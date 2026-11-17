//! Public Agent discovery and access-request DTOs: JSON metadata only, never
//! secret material or credential identifiers. Newer fields stay optional.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ApprovalRequired, ErrorEnvelope};
use crate::action::HttpsOrigin;
use crate::connection::{
    ConnectionLimits, ConnectionLlmLimits, ConnectionRule, CredentialGrade,
    DerivedCredentialTarget, MethodClass, PresetOperation, RuleEffect,
};
use crate::ids::{PolicyRuleId, RequestId};

/// Loopback HTTP header linking a resend to its approval challenge. A public
/// correlation value: never a credential, a token, or part of the request hash.
pub const APPROVAL_CHALLENGE_HEADER: &str = "x-rekey-approval-challenge";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeMeta {
    pub operation: String,
    /// Selects one Connection when several declare the operation name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
}
/// The signed decision for a named operation called with its example
/// arguments. Discovery only: every call is decided again at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDecision {
    pub operation: String,
    pub method_class: MethodClass,
    pub effect: RuleEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<PolicyRuleId>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionCapability {
    pub connection: String,
    pub preset: String,
    pub origin: HttpsOrigin,
    pub grade: CredentialGrade,
    pub read: RuleEffect,
    pub write: RuleEffect,
    pub operations: Vec<PresetOperation>,
    /// Signed LLM model allow-list and budgets, when the Connection has them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<ConnectionLlmLimits>,
    /// One per named operation; `read` / `write` judge only the root path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<OperationDecision>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCapabilitiesResponse {
    pub connections: Vec<ConnectionCapability>,
    pub derived_credentials: Vec<DerivedCredentialCapability>,
    pub service_url: Option<String>,
    /// When the active signed rules stop authorizing calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_expires_at_ms: Option<i64>,
}
/// Public signed T1 authority. The source credential identifier is not part of
/// agent discovery, and this record contains no issued credential values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedCredentialCapability {
    pub connection: String,
    pub kind: String,
    pub target: DerivedCredentialTarget,
    pub max_ttl_seconds: u32,
    pub effect: RuleEffect,
    pub grade: CredentialGrade,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeResponse {
    pub connection: String,
    pub operation: PresetOperation,
    /// The Connection's public signed rules (never credential identifiers).
    #[serde(default)]
    pub rules: Vec<ConnectionRule>,
    /// Signed overrides for this caller; omitted when there are none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caller_rules: Vec<ConnectionRule>,
    #[serde(default)]
    pub limits: ConnectionLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<ConnectionLlmLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_expires_at_ms: Option<i64>,
    /// Required arguments satisfying the schema and signed bindings. The
    /// values are placeholders, never an authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_args: Option<BTreeMap<String, serde_json::Value>>,
    /// The decision for a call with `example_args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<OperationDecision>,
    /// The signed rule that decision matched; absent when none matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<ConnectionRule>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAccessMeta {
    pub provider: Option<String>,
    pub connection: Option<String>,
    pub operation: Option<String>,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAccessResponse {
    pub request_id: RequestId,
    pub expires_at_ms: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessRequestStatus {
    Pending,
    Granted,
    Rejected,
    Expired,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitAccessMeta {
    pub request_id: RequestId,
    pub timeout_s: u16,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwaitAccessResponse {
    pub status: AccessRequestStatus,
}

impl ErrorEnvelope {
    /// Loopback HTTP approvals belong to the HTTP caller label, so CLI/MCP
    /// waits cannot observe them: the program resends with the header.
    pub fn http_approval_required(request_id: RequestId, approval: ApprovalRequired) -> Self {
        let next = format!(
            "Ask the user to approve this request in Rekey, then resend the identical request (same method, path, query, headers and body) once with header {APPROVAL_CHALLENGE_HEADER}: {}. The header is not a token; before approval it returns this challenge again, and a resend without it never uses the approval.",
            approval.challenge_id
        );
        let mut envelope = Self::approval_required(request_id, approval);
        envelope.next = Some(next);
        envelope
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ApprovalRequestId;

    #[test]
    fn discovery_additions_are_optional_and_http_retry_names_its_header() {
        let described: DescribeMeta =
            serde_json::from_value(serde_json::json!({"operation":"qwen.chat"})).unwrap();
        assert!(described.connection.is_none());
        assert_eq!(
            serde_json::to_value(&described).unwrap(),
            serde_json::json!({"operation":"qwen.chat"})
        );
        let challenge = ApprovalRequestId::new_random();
        let envelope = ErrorEnvelope::http_approval_required(
            RequestId::new_random(),
            ApprovalRequired {
                challenge_id: challenge,
                expires_at_ms: 1,
            },
        );
        let next = envelope.next.clone().unwrap();
        assert!(next.contains(&format!("{APPROVAL_CHALLENGE_HEADER}: {challenge}")));
        assert!(!next.contains("await_approval"));
        // The wire contract for APPROVAL_REQUIRED still validates.
        let wire = serde_json::to_vec(&envelope).unwrap();
        let parsed: ErrorEnvelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(parsed.approval.unwrap().challenge_id, challenge);
    }
}
