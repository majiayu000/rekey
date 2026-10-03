//! Pure full-replacement drafts from Actions authenticated by the Authority.
//! This module neither authenticates stored Action rows nor performs signing.

use rekey_domain::Timestamp;
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::authorization::{PolicyTrustAlgorithm, PolicyVersion, ResourceRef, SchemaId};
use rekey_domain::ids::{PolicyRuleId, PrincipalId};
use rekey_domain::template::DefaultRule;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ActionBinding, ParameterScope, PolicyError, PolicyRule, PolicySnapshot, RuleEffect,
    SNAPSHOT_FORMAT_VERSION, SNAPSHOT_MAX_BYTES, ValidatedPolicyBundle, ValidatedPolicyTrust,
    parse_and_validate_snapshot,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyFieldChange {
    pub field: &'static str,
    pub before: Value,
    pub after: Value,
}

pub struct PersonalPolicyDraft {
    canonical_snapshot: Vec<u8>,
    sign_bytes: Vec<u8>,
    diff: Vec<PolicyFieldChange>,
}

impl PersonalPolicyDraft {
    pub fn canonical_snapshot(&self) -> &[u8] {
        &self.canonical_snapshot
    }

    pub fn sign_bytes(&self) -> &[u8] {
        &self.sign_bytes
    }

    pub fn diff(&self) -> &[PolicyFieldChange] {
        &self.diff
    }
}

/// `previous` is the current verified bundle under the installed `trust`.
/// Empty selection deliberately removes all previous authorizations. Action
/// targets remain in their authenticated rows; only their schema is copied here.
pub fn generate_personal_draft(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    actions: &[FixedHttpAction],
    principal_id: PrincipalId,
    expires_at_ms: i64,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    if trust.key().algorithm() != PolicyTrustAlgorithm::SecureEnclaveP256 {
        return Err(PolicyError::Invalid);
    }
    if previous.is_some_and(|bundle| bundle.signer_id() != trust.signer_id()) {
        return Err(PolicyError::InvalidSignature);
    }
    let next = previous
        .map_or(0, |bundle| bundle.snapshot().version().get())
        .checked_add(1)
        .ok_or(PolicyError::Invalid)?;
    let version = PolicyVersion::new(next).map_err(|_| PolicyError::Invalid)?;
    let mut selected: Vec<_> = actions.iter().collect();
    selected.sort_by_key(|action| (action.id, action.version));
    if selected
        .windows(2)
        .any(|pair| (pair[0].id, pair[0].version) == (pair[1].id, pair[1].version))
    {
        return Err(PolicyError::Invalid);
    }
    let mut bindings = Vec::with_capacity(selected.len());
    let mut rules = Vec::with_capacity(selected.len());
    for action in selected {
        action.validate().map_err(|_| PolicyError::Invalid)?;
        if !action.enabled {
            return Err(PolicyError::Invalid);
        }
        let ActionTarget::Template {
            body_schema,
            default_policy,
            ..
        } = &action.target
        else {
            return Err(PolicyError::Invalid);
        };
        let effect = match default_policy.rule {
            DefaultRule::Allow => RuleEffect::Permit,
            // local-presence approval is not implemented by this generator.
            DefaultRule::RequireApproval => return Err(PolicyError::Invalid),
        };
        let resource = ResourceRef::new("action".to_owned(), action.id.to_string())
            .map_err(|_| PolicyError::Invalid)?;
        bindings.push(ActionBinding {
            action_id: action.id,
            version: action.version,
            resource: resource.clone(),
            parameter_schema_id: SchemaId::new(format!("action/{}/{}", action.id, action.version))
                .map_err(|_| PolicyError::Invalid)?,
            parameter_schema: body_schema.clone().unwrap_or(Value::Bool(true)),
        });
        let mut id = Sha256::new();
        id.update(b"RKPERSONALRULE\0\x01");
        id.update(principal_id.as_bytes());
        id.update(action.id.as_bytes());
        id.update(action.version.to_be_bytes());
        let mut id_bytes = [0; 16];
        id_bytes.copy_from_slice(&id.finalize()[..16]);
        rules.push(PolicyRule {
            id: PolicyRuleId::from_random_bytes(id_bytes),
            effect,
            principal_id,
            action_id: action.id,
            version: action.version,
            resource,
            parameters: ParameterScope::AnyValidated {},
            approver: None,
            approval: None,
        });
    }
    let snapshot = PolicySnapshot {
        format_version: SNAPSHOT_FORMAT_VERSION,
        version,
        expires_at_ms,
        approvers: Vec::new(),
        workload_identities: Vec::new(),
        bindings,
        rules,
    };
    let canonical_snapshot = serde_jcs::to_vec(&snapshot).map_err(|_| PolicyError::Malformed)?;
    parse_and_validate_snapshot(&canonical_snapshot, now)?;
    let after: Value =
        serde_json::from_slice(&canonical_snapshot).map_err(|_| PolicyError::Malformed)?;
    // JCS uses IEEE-754 number formatting. Never silently round an authority
    // version or expiry while producing the bytes the user will actually sign.
    if after["version"].as_u64() != Some(next)
        || after["expires_at_ms"].as_i64() != Some(expires_at_ms)
        || after["bindings"]
            .as_array()
            .ok_or(PolicyError::Malformed)?
            .iter()
            .zip(&snapshot.bindings)
            .any(|(encoded, binding)| encoded["version"].as_u64() != Some(binding.version))
    {
        return Err(PolicyError::Invalid);
    }
    let unsigned = json!({"format_version": 1, "signer_id": trust.signer_id(), "snapshot": after});
    let canonical_envelope = serde_jcs::to_vec(&unsigned).map_err(|_| PolicyError::Malformed)?;
    // P-256 DER is at most 72 bytes, or 96 base64url characters. Reserve the
    // entire signature field so a valid signature cannot exceed the bundle cap.
    if canonical_envelope.len() > SNAPSHOT_MAX_BYTES - b",\"signature\":\"\"".len() - 96 {
        return Err(PolicyError::TooLarge);
    }
    let mut sign_bytes = b"RKPOLICY\0\x01".to_vec();
    sign_bytes.extend_from_slice(&canonical_envelope);
    let before = match previous {
        Some(bundle) => {
            let envelope: Value = serde_json::from_slice(bundle.canonical_bytes())
                .map_err(|_| PolicyError::Malformed)?;
            envelope
                .get("snapshot")
                .cloned()
                .ok_or(PolicyError::Malformed)?
        }
        None => Value::Null,
    };
    let mut diff = Vec::new();
    for field in [
        "version",
        "expires_at_ms",
        "approvers",
        "workload_identities",
        "bindings",
        "rules",
    ] {
        let old = before.get(field).cloned().unwrap_or(Value::Null);
        let new = after.get(field).cloned().ok_or(PolicyError::Malformed)?;
        if old != new {
            diff.push(PolicyFieldChange {
                field,
                before: old,
                after: new,
            });
        }
    }
    if serde_json::to_vec(&diff)
        .map_err(|_| PolicyError::Malformed)?
        .len()
        > SNAPSHOT_MAX_BYTES
    {
        return Err(PolicyError::TooLarge);
    }
    Ok(PersonalPolicyDraft {
        canonical_snapshot,
        sign_bytes,
        diff,
    })
}
