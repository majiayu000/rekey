//! Authenticated template declarations and their closed, offline schema resources.
//! This module performs no IO or installation. Built-ins inherit the released
//! binary's trust; constructing one does not verify that binary's code signature.

use std::collections::BTreeMap;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use data_encoding::BASE64URL_NOPAD;
use jsonschema::{Draft, Validator};
use rekey_domain::action::{ExactPath, FixedMethod, HttpsOrigin};
use rekey_domain::ids::PolicySignerId;
use rekey_domain::template::{self, ProviderTemplate};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{ValidatedPolicyTrust, json::parse_unique_json};

pub const TEMPLATE_PACKAGE_MAX_BYTES: usize = 64 * 1024;
pub const TEMPLATE_SIGN_PREFIX: &[u8] = b"RKTEMPLATE\0\x01";
pub const GITHUB_CREATE_ISSUE_SCHEMA: &str = "schemas/github-create-issue.json";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplatePackageError {
    #[error("template package is too large")]
    TooLarge,
    #[error("template package is malformed")]
    Malformed,
    #[error("template package format is unsupported")]
    UnsupportedFormat,
    #[error("template package signature verification failed")]
    InvalidSignature,
    #[error("template declaration is invalid")]
    InvalidTemplate,
    #[error("template schema is unavailable or invalid")]
    InvalidSchema,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format_version: u32,
    signer_id: PolicySignerId,
    template: Value,
    schemas: BTreeMap<String, Value>,
    signature: String,
}

/// A schema compiled without external retrieval. The definition and validator
/// cannot be replaced separately, and lookup never interprets a filesystem path.
pub struct ValidatedTemplateSchema {
    definition: Value,
    validator: Validator,
}

impl ValidatedTemplateSchema {
    pub fn definition(&self) -> &Value {
        &self.definition
    }

    pub fn is_valid(&self, instance: &Value) -> bool {
        self.validator.is_valid(instance)
    }
}

/// Immutable authenticated source snapshot. Bind/materialize only after obtaining
/// this value. No vault persistence or upstream request occurs in this module.
pub struct ValidatedTemplatePackage {
    template: ProviderTemplate,
    schemas: BTreeMap<String, ValidatedTemplateSchema>,
    signer_id: Option<PolicySignerId>,
    canonical: Vec<u8>,
    digest: [u8; 32],
}

impl ValidatedTemplatePackage {
    pub fn template(&self) -> &ProviderTemplate {
        &self.template
    }

    /// None means a built-in construction, whose trust comes from the release
    /// artifact. It is not evidence that code signing was checked by this API.
    pub fn signer_id(&self) -> Option<PolicySignerId> {
        self.signer_id
    }

    pub fn schema(
        &self,
        reference: &str,
    ) -> Result<&ValidatedTemplateSchema, TemplatePackageError> {
        self.schemas
            .get(reference)
            .ok_or(TemplatePackageError::InvalidSchema)
    }

    /// JCS of {template, schemas}: the original declaration plus all embedded
    /// schemas and any referenced built-in schemas resolved by this binary.
    /// This source snapshot is NOT the unsigned envelope used for Ed25519.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// SHA-256 of canonical_bytes(), including resolved built-in schema content.
    /// This is a source digest, not a signature payload or installed Action hash.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub fn parse_and_verify_template_package(
    bytes: &[u8],
    trust: &ValidatedPolicyTrust,
) -> Result<ValidatedTemplatePackage, TemplatePackageError> {
    if bytes.len() > TEMPLATE_PACKAGE_MAX_BYTES {
        return Err(TemplatePackageError::TooLarge);
    }
    let mut value = parse_unique_json(bytes).map_err(|_| TemplatePackageError::Malformed)?;
    let envelope: Envelope =
        serde_json::from_value(value.clone()).map_err(|_| TemplatePackageError::Malformed)?;
    if envelope.format_version != 1 {
        return Err(TemplatePackageError::UnsupportedFormat);
    }
    if envelope.signer_id != trust.signer_id() {
        return Err(TemplatePackageError::InvalidSignature);
    }
    let signature = BASE64URL_NOPAD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| TemplatePackageError::InvalidSignature)?;
    if signature.len() != 64 || BASE64URL_NOPAD.encode(&signature) != envelope.signature {
        return Err(TemplatePackageError::InvalidSignature);
    }
    value
        .as_object_mut()
        .ok_or(TemplatePackageError::Malformed)?
        .remove("signature")
        .ok_or(TemplatePackageError::Malformed)?;
    let mut message = TEMPLATE_SIGN_PREFIX.to_vec();
    message.extend_from_slice(
        &serde_jcs::to_vec(&value).map_err(|_| TemplatePackageError::Malformed)?,
    );
    UnparsedPublicKey::new(&ED25519, trust.public_key())
        .verify(&message, &signature)
        .map_err(|_| TemplatePackageError::InvalidSignature)?;
    let template: ProviderTemplate = serde_json::from_value(envelope.template.clone())
        .map_err(|_| TemplatePackageError::InvalidTemplate)?;
    validate_source(
        envelope.template,
        template,
        envelope.schemas,
        Some(envelope.signer_id),
    )
}

/// Closed built-in entry points: arbitrary caller declarations cannot acquire
/// built-in provenance. Generic Bearer's typed targets still need the later A2
/// installation authorization; the release does not endorse user-chosen origins.
pub enum BuiltinTemplate {
    Anthropic,
    OpenAi,
    GitHubPat,
    GenericBearer {
        origin: HttpsOrigin,
        actions: Vec<(FixedMethod, ExactPath)>,
    },
}

pub fn builtin_template(
    builtin: BuiltinTemplate,
) -> Result<ValidatedTemplatePackage, TemplatePackageError> {
    let template = match builtin {
        BuiltinTemplate::Anthropic => template::anthropic(),
        BuiltinTemplate::OpenAi => template::openai(),
        BuiltinTemplate::GitHubPat => template::github_pat(),
        BuiltinTemplate::GenericBearer { origin, actions } => {
            template::generic_bearer(origin, actions)
        }
    }
    .map_err(|_| TemplatePackageError::InvalidTemplate)?;
    let declaration =
        serde_json::to_value(&template).map_err(|_| TemplatePackageError::Malformed)?;
    validate_source(declaration, template, BTreeMap::new(), None)
}

fn validate_source(
    declaration: Value,
    template: ProviderTemplate,
    mut schemas: BTreeMap<String, Value>,
    signer_id: Option<PolicySignerId>,
) -> Result<ValidatedTemplatePackage, TemplatePackageError> {
    for action in template
        .definition()
        .capabilities
        .iter()
        .flat_map(|c| &c.actions)
    {
        if let Some(reference) = &action.body_schema {
            // These are exact package resource names, not retrievable URLs.
            if !resource_name(reference) {
                return Err(TemplatePackageError::InvalidSchema);
            }
            if !schemas.contains_key(reference) {
                let schema =
                    builtin_schema(reference).ok_or(TemplatePackageError::InvalidSchema)?;
                schemas.insert(reference.clone(), schema);
            }
        }
    }
    let canonical = serde_jcs::to_vec(&json!({"template": declaration, "schemas": schemas}))
        .map_err(|_| TemplatePackageError::Malformed)?;
    let digest = Sha256::digest(&canonical).into();
    let schemas = schemas
        .into_iter()
        .map(|(reference, definition)| {
            if !resource_name(&reference) {
                return Err(TemplatePackageError::InvalidSchema);
            }
            Ok((reference, compile_template_schema(definition)?))
        })
        .collect::<Result<_, _>>()?;
    Ok(ValidatedTemplatePackage {
        template,
        schemas,
        signer_id,
        canonical,
        digest,
    })
}

/// Compile an already resolved local schema without filesystem or network IO.
/// Used for the authenticated schema stored in a template Action.
pub fn compile_template_schema(
    definition: Value,
) -> Result<ValidatedTemplateSchema, TemplatePackageError> {
    reject_external_references(&definition)?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .offline()
        .build(&definition)
        .map_err(|_| TemplatePackageError::InvalidSchema)?;
    Ok(ValidatedTemplateSchema {
        definition,
        validator,
    })
}

// A resource name is an exact relative ASCII path within the signed map. There
// is no decoding, traversal, filesystem access, URI resolution, or aliasing.
fn resource_name(reference: &str) -> bool {
    reference.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    })
}

// Keep the policy module's conservative local-fragment-only convention, also
// covering newer reference keywords. offline() independently forbids retrieval.
fn reject_external_references(value: &Value) -> Result<(), TemplatePackageError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef")
                    && !value
                        .as_str()
                        .is_some_and(|reference| reference.starts_with('#'))
                {
                    return Err(TemplatePackageError::InvalidSchema);
                }
                if key == "$schema"
                    && value.as_str() != Some("https://json-schema.org/draft/2020-12/schema")
                {
                    return Err(TemplatePackageError::InvalidSchema);
                }
                reject_external_references(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_external_references(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn builtin_schema(reference: &str) -> Option<Value> {
    match reference {
        // Deliberately the title/body subset of GitHub's create-issue body:
        // https://docs.github.com/en/rest/issues/issues#create-an-issue
        GITHUB_CREATE_ISSUE_SCHEMA => Some(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["title"],
            "properties": {
                "title": {"type": ["string", "integer"]},
                "body": {"type": "string"}
            },
            "additionalProperties": false
        })),
        _ => None,
    }
}
