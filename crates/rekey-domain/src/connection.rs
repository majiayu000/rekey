//! Signed local Connection policy and public provider operation declarations.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::action::{FixedMethod, HeaderCredentialUse, HeaderName, HttpsOrigin};
use crate::ids::{CredentialId, PolicyRuleId};
use crate::{DomainError, template::slug};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MethodClass {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MethodSelector {
    Class(MethodClass),
    Methods(Vec<FixedMethod>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleEffect {
    Allow,
    Approve,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialGrade {
    T0,
    T1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    GitHub,
    Slack,
    Notion,
}

/// Public signed ceiling, never client secrets or tokens. Notion entries are
/// Developer Portal capabilities rather than OAuth request scope strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthBinding {
    pub provider: OAuthProvider,
    pub client_id: String,
    pub scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRule {
    pub id: PolicyRuleId,
    pub methods: MethodSelector,
    pub path: String,
    pub effect: RuleEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLimits {
    pub requests_per_hour: u32,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
}
impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            requests_per_hour: 600,
            max_request_bytes: 1_048_576,
            max_response_bytes: 4_194_304,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadSemantics {
    Fixed,
    GraphqlQuery,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetOperation {
    pub name: String,
    pub description: String,
    pub method: FixedMethod,
    pub path: String,
    /// Parameter schema for named operations, never credential material.
    pub parameters: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_semantics: Option<ReadSemantics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLlmLimits {
    pub models: BTreeSet<String>,
    pub max_tokens: u32,
    pub max_requests_per_day: u32,
    pub max_output_tokens_per_day: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub name: String,
    pub preset: String,
    pub credential_id: CredentialId,
    pub origin: HttpsOrigin,
    pub auth: HeaderCredentialUse,
    pub enabled: bool,
    pub grade: CredentialGrade,
    pub rules: Vec<ConnectionRule>,
    pub bindings: BTreeMap<String, Vec<String>>,
    pub caller_overrides: BTreeMap<String, Vec<ConnectionRule>>,
    pub limits: ConnectionLimits,
    pub allowed_headers: BTreeSet<HeaderName>,
    pub fixed_headers: BTreeMap<HeaderName, String>,
    pub allowed_response_headers: BTreeSet<HeaderName>,
    pub query_allowlist: Option<BTreeSet<String>>,
    pub operations: Vec<PresetOperation>,
    pub llm: Option<ConnectionLlmLimits>,
    pub oauth: Option<OAuthBinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub name: String,
    pub origin: HttpsOrigin,
    pub auth: HeaderCredentialUse,
    pub rules: Vec<ConnectionRule>,
    pub allowed_headers: BTreeSet<HeaderName>,
    pub fixed_headers: BTreeMap<HeaderName, String>,
    pub allowed_response_headers: BTreeSet<HeaderName>,
    pub query_allowlist: Option<BTreeSet<String>>,
    pub operations: Vec<PresetOperation>,
}
impl Preset {
    pub fn connection(&self, name: String, credential_id: CredentialId) -> Connection {
        Connection {
            name,
            preset: self.name.clone(),
            credential_id,
            origin: self.origin.clone(),
            auth: self.auth.clone(),
            enabled: true,
            grade: CredentialGrade::T0,
            rules: self.rules.clone(),
            bindings: if self.name == "github-git" {
                BTreeMap::from([("owner".into(), Vec::new()), ("repo".into(), Vec::new())])
            } else {
                BTreeMap::new()
            },
            caller_overrides: BTreeMap::new(),
            limits: ConnectionLimits::default(),
            allowed_headers: self.allowed_headers.clone(),
            fixed_headers: self.fixed_headers.clone(),
            allowed_response_headers: self.allowed_response_headers.clone(),
            query_allowlist: self.query_allowlist.clone(),
            operations: self.operations.clone(),
            llm: None,
            oauth: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRequestAuditContext {
    pub connection: String,
    pub caller: String,
    pub method_class: MethodClass,
    pub normalized_path: String,
    pub rule_id: Option<PolicyRuleId>,
}

fn invalid(message: &str) -> DomainError {
    DomainError::InvalidActionDefinition(message.to_owned())
}

/// Shared trusted-boundary path grammar. No decoding, normalization, or aliases.
pub fn validate_request_path(path: &str) -> Result<(), DomainError> {
    if !path.starts_with('/')
        || path.len() > 2048
        || (path != "/" && path[1..].split('/').any(|part| !slug(part, 100)))
    {
        return Err(invalid("path must contain only safe ASCII slug segments"));
    }
    Ok(())
}

pub fn validate_path_pattern(path: &str) -> Result<(), DomainError> {
    if !path.starts_with('/') || path.len() > 2048 {
        return Err(invalid("invalid rule path"));
    }
    if path == "/" {
        return Ok(());
    }
    let parts: Vec<_> = path[1..].split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "**" && i + 1 == parts.len() || *part == "*" || slug(part, 100) {
            continue;
        }
        if let Some(name) = part.strip_prefix('{').and_then(|v| v.strip_suffix('}'))
            && slug(name, 64)
        {
            continue;
        }
        return Err(invalid("invalid rule path segment"));
    }
    Ok(())
}

pub fn query_key_valid(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl Connection {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !slug(&self.name, 100)
            || !slug(&self.preset, 100)
            || self.limits.requests_per_hour == 0
            || self.limits.max_request_bytes == 0
            || self.limits.max_request_bytes > 1_048_576
            || self.limits.max_response_bytes == 0
            || self.limits.max_response_bytes > 4_194_304
        {
            return Err(invalid("invalid connection or limits"));
        }
        if matches!(
            self.preset.as_str(),
            "anthropic" | "openai" | "glm" | "glm-responses"
        ) && self.llm.is_none()
        {
            return Err(invalid(
                "LLM connections require signed model and budget limits",
            ));
        }
        if self.oauth.as_ref().is_some_and(|v| {
            v.client_id.is_empty()
                || v.client_id.len() > 256
                || !v.client_id.bytes().all(|b| (33..=126).contains(&b))
                || v.scopes.len() > 32
                || v.scopes.iter().any(|s| {
                    s.is_empty() || s.len() > 256 || !s.bytes().all(|b| (33..=126).contains(&b))
                })
                || self.grade != CredentialGrade::T0
        }) {
            return Err(invalid("invalid OAuth binding"));
        }
        HeaderCredentialUse::new(self.auth.header_name.clone(), self.auth.prefix.clone())?;
        let mut ids = BTreeSet::new();
        for rule in self
            .rules
            .iter()
            .chain(self.caller_overrides.values().flatten())
        {
            validate_path_pattern(&rule.path)?;
            if !ids.insert(rule.id) {
                return Err(invalid("duplicate rule id"));
            }
            if let MethodSelector::Methods(methods) = &rule.methods
                && (methods.is_empty()
                    || methods
                        .iter()
                        .enumerate()
                        .any(|(i, m)| methods[..i].contains(m)))
            {
                return Err(invalid("invalid rule methods"));
            }
            for segment in rule.path.split('/') {
                if let Some(name) = segment.strip_prefix('{').and_then(|v| v.strip_suffix('}'))
                    && !self.bindings.contains_key(name)
                {
                    return Err(invalid("named rule segment needs a binding"));
                }
            }
        }
        for (key, values) in &self.bindings {
            if !slug(key, 64)
                || values.is_empty()
                || values.iter().any(|v| v != "*" && !slug(v, 100))
            {
                return Err(invalid("invalid path bindings"));
            }
        }
        if self
            .caller_overrides
            .keys()
            .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
        {
            return Err(invalid("invalid caller label"));
        }
        for name in self.allowed_headers.iter().chain(self.fixed_headers.keys()) {
            if name.is_forbidden()
                || matches!(name.as_str(), "authorization" | "x-api-key")
                || name.as_str().starts_with("proxy-")
                || name == &self.auth.header_name
            {
                return Err(invalid("protected caller header"));
            }
        }
        if self.fixed_headers.iter().any(|(k, v)| {
            self.allowed_headers.contains(k)
                || v.len() > 8192
                || !v.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        }) {
            return Err(invalid("invalid fixed header"));
        }
        if self
            .query_allowlist
            .as_ref()
            .is_some_and(|keys| keys.iter().any(|v| !query_key_valid(v)))
        {
            return Err(invalid("invalid query allowlist"));
        }
        crate::action::ResponsePolicy {
            max_body_bytes: self.limits.max_response_bytes,
            allowed_headers: self.allowed_response_headers.clone(),
        }
        .validate()?;
        let mut operations = BTreeSet::new();
        for operation in &self.operations {
            if operation.name.is_empty()
                || operation.name.len() > 128
                || !operation.name.split('.').all(|s| slug(s, 100))
                || !operations.insert(&operation.name)
            {
                return Err(invalid("invalid operation name"));
            }
            validate_path_pattern(&operation.path)?;
            if operation.path.contains('*')
                || !operation.parameters.is_object()
                || operation.read_semantics.is_some() && operation.method != FixedMethod::Post
            {
                return Err(invalid("invalid operation declaration"));
            }
        }
        if self.llm.as_ref().is_some_and(|v| {
            v.models.is_empty()
                || v.max_tokens == 0
                || v.max_requests_per_day == 0
                || v.max_output_tokens_per_day == 0
                || v.max_output_tokens_per_day > 9_007_199_254_740_991
                || v.models
                    .iter()
                    .any(|m| m.is_empty() || m.len() > 256 || m.chars().any(char::is_control))
        }) {
            return Err(invalid("invalid LLM limits"));
        }
        Ok(())
    }
}

/// Signed host-key authorization for a non-exportable SSH signing credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshHostRule {
    pub host: String,
    /// Standard base64 SSH public-key wire blob, never a private key.
    pub host_key: String,
    pub rule_id: PolicyRuleId,
    pub effect: RuleEffect,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeyConnection {
    pub name: String,
    pub credential_id: CredentialId,
    pub user_public_key: String,
    pub hosts: Vec<SshHostRule>,
    pub git_signing: RuleEffect,
}

/// Explicitly signed T1 permission: the caller receives the issued temporary
/// value, but cannot supply or change its upstream target or permission ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedCredentialConnection {
    pub name: String,
    pub credential_id: CredentialId,
    pub effect: RuleEffect,
    pub max_ttl_seconds: u32,
    pub target: DerivedCredentialTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DerivedCredentialTarget {
    AwsAssumeRole {
        role_arn: String,
        region: String,
        session_policy: serde_json::Value,
    },
    KubernetesEks {
        cluster_id: String,
        region: String,
    },
    #[serde(rename = "github-app")]
    GitHubApp {
        installation_id: u64,
        repository_ids: Vec<u64>,
        permissions: BTreeMap<String, String>,
    },
}

impl DerivedCredentialConnection {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !slug(&self.name, 100) {
            return Err(invalid("invalid derived connection name"));
        }
        self.target.validate_ttl(self.max_ttl_seconds)
    }
}

impl DerivedCredentialTarget {
    pub fn lifetime_ceiling_seconds(&self) -> u32 {
        match self {
            Self::KubernetesEks { .. } => 900,
            _ => 3600,
        }
    }
    pub fn validate_ttl(&self, ttl: u32) -> Result<(), DomainError> {
        fn region_valid(region: &str) -> bool {
            slug(region, 63)
                && region
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }
        let valid = match self {
            DerivedCredentialTarget::AwsAssumeRole {
                role_arn,
                region,
                session_policy,
            } => {
                (900..=3600).contains(&ttl)
                    && role_arn.starts_with("arn:")
                    && role_arn.contains(":role/")
                    && (20..=2048).contains(&role_arn.len())
                    && role_arn
                        .bytes()
                        .all(|b| (33..=126).contains(&b) && !matches!(b, b'*' | b'?'))
                    && region_valid(region)
                    && session_policy.is_object()
                    && serde_json::to_vec(session_policy).is_ok_and(|bytes| bytes.len() <= 2048)
            }
            DerivedCredentialTarget::KubernetesEks { cluster_id, region } => {
                ttl == 900
                    && slug(cluster_id, 100)
                    && cluster_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                    && region_valid(region)
            }
            DerivedCredentialTarget::GitHubApp {
                installation_id,
                repository_ids,
                permissions,
            } => {
                const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
                ttl == 3600
                    && (1..=MAX_SAFE_INTEGER).contains(installation_id)
                    && !repository_ids.is_empty()
                    && repository_ids.len() <= 500
                    && repository_ids
                        .iter()
                        .all(|id| (1..=MAX_SAFE_INTEGER).contains(id))
                    && repository_ids
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len()
                        == repository_ids.len()
                    && !permissions.is_empty()
                    && permissions.len() <= 64
                    && permissions.iter().all(|(name, value)| {
                        !name.is_empty()
                            && name.len() <= 64
                            && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                            && matches!(value.as_str(), "read" | "write")
                    })
            }
        };
        if !valid {
            return Err(invalid("invalid derived credential target or lifetime"));
        }
        Ok(())
    }
}
