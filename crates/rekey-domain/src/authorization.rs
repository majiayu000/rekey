use serde::{Deserialize, Deserializer, Serialize};

use crate::capability::ActionVersionRef;
use crate::error::DomainError;
use crate::ids::{PolicyRuleId, PrincipalId, SessionId, TenantId};

fn invalid(message: &str) -> DomainError {
    DomainError::InvalidAuthorization(message.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub session_id: SessionId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ResourceRef {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

impl ResourceRef {
    pub fn new(resource_type: String, id: String) -> Result<Self, DomainError> {
        validate_label(&resource_type, "resource type")?;
        validate_label(&id, "resource id")?;
        Ok(Self { resource_type, id })
    }
}

impl<'de> Deserialize<'de> for ResourceRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "type")]
            resource_type: String,
            id: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.resource_type, raw.id).map_err(serde::de::Error::custom)
    }
}

fn validate_label(value: &str, field: &str) -> Result<(), DomainError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid(&format!("{field} is invalid")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SchemaId(String);

impl SchemaId {
    pub fn new(value: String) -> Result<Self, DomainError> {
        validate_label(&value, "schema id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SchemaId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    pub fn new(value: u64) -> Result<Self, DomainError> {
        if value == 0 {
            return Err(invalid("policy version must be nonzero"));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for PolicyVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalParameters {
    pub schema_id: SchemaId,
    pub canonical_hash: [u8; 32],
}

impl std::fmt::Debug for CanonicalParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalParameters")
            .field("schema_id", &self.schema_id)
            .field("canonical_hash", &"[SHA256]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub principal: Principal,
    pub action: ActionVersionRef,
    pub resource: ResourceRef,
    pub parameters: CanonicalParameters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    NoActiveSnapshot,
    SnapshotExpired,
    ActionNotBound,
    InvalidParameters,
    NoMatchingPermit,
    ExplicitForbid,
    EvaluationFailed,
}

impl DenyReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::NoActiveSnapshot => "policy-missing",
            Self::SnapshotExpired => "policy-expired",
            Self::ActionNotBound => "policy-action-unbound",
            Self::InvalidParameters => "invalid-parameters",
            Self::NoMatchingPermit => "policy-no-permit",
            Self::ExplicitForbid => "policy-forbid",
            Self::EvaluationFailed => "policy-evaluation-failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow {
        policy_version: PolicyVersion,
        snapshot_digest: [u8; 32],
        determining_rule: PolicyRuleId,
    },
    Deny {
        policy_version: Option<PolicyVersion>,
        snapshot_digest: Option<[u8; 32]>,
        reason: DenyReason,
        determining_rule: Option<PolicyRuleId>,
    },
}
