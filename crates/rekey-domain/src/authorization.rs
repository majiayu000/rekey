use serde::{Deserialize, Deserializer, Serialize};

use crate::capability::ActionVersionRef;
use crate::error::DomainError;
use crate::ids::{PolicyRuleId, PrincipalId, SessionId, TenantId};

fn invalid(message: &str) -> DomainError {
    DomainError::InvalidAuthorization(message.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    Personal,
    Team,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyTrustAlgorithm {
    Ed25519,
    SecureEnclaveP256,
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
        #[serde(deny_unknown_fields)]
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
        if value == 0 || value >= i64::MAX as u64 {
            return Err(invalid(
                "policy version must fit the durable range below the reserved terminal value",
            ));
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
    /// Exact JCS request bytes used for the hash; never included in Debug.
    pub canonical_json: Vec<u8>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    OneTime,
    TimeWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ApproverSpec {
    LocalPresence {},
    Ed25519 {
        keys: Vec<String>,
        threshold: u8,
    },
    #[cfg(feature = "lab")]
    Remote {},
}

/// Usage limits only. The rule's separate `approver` is the sole authority source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequirement {
    pub mode: ApprovalMode,
    pub max_uses: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_window_ms: Option<i64>,
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
    RequireApproval {
        policy_version: PolicyVersion,
        snapshot_digest: [u8; 32],
        determining_rule: PolicyRuleId,
        approver: ApproverSpec,
        requirement: ApprovalRequirement,
    },
    Deny {
        policy_version: Option<PolicyVersion>,
        snapshot_digest: Option<[u8; 32]>,
        reason: DenyReason,
        determining_rule: Option<PolicyRuleId>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approver_wire_has_one_closed_authority_source() {
        let local: ApproverSpec = serde_json::from_str(r#"{"kind":"local-presence"}"#).unwrap();
        assert_eq!(local, ApproverSpec::LocalPresence {});
        for invalid in [
            r#"{"kind":"local-presence","threshold":1}"#,
            r#"{"kind":"local-presence","keys":[]}"#,
            r#"{"kind":"ed25519","keys":[],"threshold":1,"quorum":1}"#,
            r#"{"kind":"ed25519","keys":[],"threshold":1,"approver_ids":[]}"#,
        ] {
            assert!(serde_json::from_str::<ApproverSpec>(invalid).is_err());
        }
        assert!(
            serde_json::from_str::<ApprovalRequirement>(
                r#"{"mode":"one-time","max_uses":1,"approver_ids":[],"quorum":1}"#
            )
            .is_err()
        );
        #[cfg(not(feature = "lab"))]
        assert!(serde_json::from_str::<ApproverSpec>(r#"{"kind":"remote"}"#).is_err());
        #[cfg(feature = "lab")]
        assert_eq!(
            serde_json::from_str::<ApproverSpec>(r#"{"kind":"remote"}"#).unwrap(),
            ApproverSpec::Remote {}
        );
    }

    #[test]
    fn policy_mode_and_trust_algorithm_have_closed_wire_names() {
        for (value, name) in [
            (PolicyMode::Personal, "personal"),
            (PolicyMode::Team, "team"),
        ] {
            let encoded = format!("\"{name}\"");
            assert_eq!(serde_json::to_string(&value).unwrap(), encoded);
            assert_eq!(serde_json::from_str::<PolicyMode>(&encoded).unwrap(), value);
        }
        for (value, name) in [
            (PolicyTrustAlgorithm::Ed25519, "ed25519"),
            (
                PolicyTrustAlgorithm::SecureEnclaveP256,
                "secure-enclave-p256",
            ),
        ] {
            let encoded = format!("\"{name}\"");
            assert_eq!(serde_json::to_string(&value).unwrap(), encoded);
            assert_eq!(
                serde_json::from_str::<PolicyTrustAlgorithm>(&encoded).unwrap(),
                value
            );
        }
        for invalid in ["\"Personal\"", "\"auto\"", "null"] {
            assert!(serde_json::from_str::<PolicyMode>(invalid).is_err());
        }
        for invalid in ["\"p256\"", "\"SecureEnclaveP256\"", "\"rsa\"", "null"] {
            assert!(serde_json::from_str::<PolicyTrustAlgorithm>(invalid).is_err());
        }
    }

    #[test]
    fn policy_versions_fit_the_durable_signed_range() {
        assert!(PolicyVersion::new(i64::MAX as u64 - 1).is_ok());
        assert!(PolicyVersion::new(i64::MAX as u64).is_err());
    }
}
