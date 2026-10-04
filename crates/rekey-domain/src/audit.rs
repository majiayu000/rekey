use serde::{Deserialize, Serialize};

use crate::DomainError;
use crate::ids::{
    ActionId, ApprovalId, ApprovalRequestId, ApproverId, CredentialId, PolicyRuleId, PrincipalId,
    RequestId, SessionId,
};

pub const AUDIT_SCHEMA_V2: &str = "rekey.audit.v2";
pub const AUDIT_PAGE_DEFAULT_LIMIT: u32 = 50;
pub const AUDIT_PAGE_MAX_LIMIT: u32 = 100;
pub const AUDIT_SCAN_MAX_ROWS: u32 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRetentionSet {
    #[serde(deserialize_with = "required_days")]
    pub days: Option<u64>,
}
fn required_days<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}
impl AuditRetentionSet {
    pub fn validate_at(&self, now_ms: i64) -> Result<(), DomainError> {
        self.cutoff_at(now_ms).map(|_| ())
    }
    pub fn cutoff_at(&self, now_ms: i64) -> Result<Option<i64>, DomainError> {
        let Some(days) = self.days else {
            return Ok(None);
        };
        let age = days
            .checked_mul(86_400_000)
            .filter(|age| days > 0 && *age <= i64::MAX as u64)
            .ok_or_else(|| invalid("retention days exceed the supported range"))?;
        now_ms
            .checked_sub(age as i64)
            .filter(|cutoff| *cutoff >= 0)
            .map(Some)
            .ok_or_else(|| invalid("retention age exceeds the current epoch"))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRetentionStatus {
    #[serde(deserialize_with = "required_days")]
    pub days: Option<u64>,
    pub updated_at_ms: i64,
}
impl AuditRetentionStatus {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.updated_at_ms < 0
            || self.days.is_some_and(|days| {
                days == 0
                    || days
                        .checked_mul(86_400_000)
                        .is_none_or(|age| age > i64::MAX as u64)
            })
        {
            return Err(invalid("invalid audit retention status"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPruneRequest {
    pub before_ms: i64,
}

impl AuditPruneRequest {
    pub fn validate_at(&self, now_ms: i64) -> Result<(), DomainError> {
        if self.before_ms < 0 || self.before_ms > now_ms {
            return Err(invalid(
                "prune cutoff must be non-negative and not in the future",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPruneReceipt {
    pub before_ms: i64,
    pub deleted_rows: u64,
    pub deleted_groups: u64,
    pub prune_sequence: Option<u64>,
}

impl AuditPruneReceipt {
    pub fn validate_for(&self, request: &AuditPruneRequest) -> Result<(), DomainError> {
        let empty =
            self.deleted_rows == 0 && self.deleted_groups == 0 && self.prune_sequence.is_none();
        let deleted = self.deleted_groups > 0
            && self
                .deleted_groups
                .checked_mul(2)
                .is_some_and(|minimum| self.deleted_rows >= minimum)
            && self.deleted_rows <= i64::MAX as u64
            && self.prune_sequence.is_some_and(|sequence| {
                sequence > self.deleted_rows && sequence <= i64::MAX as u64
            });
        if self.before_ms < 0 || self.before_ms != request.before_ms || !(empty || deleted) {
            return Err(invalid("invalid audit prune receipt"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub request_id: Option<RequestId>,
    pub session_id: Option<SessionId>,
    pub action_id: Option<ActionId>,
    pub credential_id: Option<CredentialId>,
    pub outcome: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub snapshot_max_sequence: Option<u64>,
    pub before_sequence: Option<u64>,
    pub limit: u32,
}

impl AuditQuery {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !(1..=AUDIT_PAGE_MAX_LIMIT).contains(&self.limit) {
            return Err(invalid("limit must be between 1 and 100"));
        }
        if self.since_ms.is_some_and(|value| value < 0)
            || self.until_ms.is_some_and(|value| value < 0)
        {
            return Err(invalid("time bounds must be non-negative"));
        }
        if matches!((self.since_ms, self.until_ms), (Some(since), Some(until)) if since > until) {
            return Err(invalid("since_ms must not exceed until_ms"));
        }
        if self
            .outcome
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 64)
        {
            return Err(invalid("outcome must be between 1 and 64 bytes"));
        }
        if self.snapshot_max_sequence == Some(0) || self.before_sequence == Some(0) {
            return Err(invalid("sequence cursors must be positive"));
        }
        if self.before_sequence.is_some() && self.snapshot_max_sequence.is_none() {
            return Err(invalid("before_sequence requires snapshot_max_sequence"));
        }
        if matches!(
            (self.snapshot_max_sequence, self.before_sequence),
            (Some(snapshot), Some(before)) if before > snapshot
        ) {
            return Err(invalid(
                "before_sequence must not exceed snapshot_max_sequence",
            ));
        }
        if self
            .snapshot_max_sequence
            .is_some_and(|value| value > i64::MAX as u64)
            || self
                .before_sequence
                .is_some_and(|value| value > i64::MAX as u64)
        {
            return Err(invalid("sequence cursor exceeds the storage range"));
        }
        Ok(())
    }

    pub fn matches(&self, event: &AuditRecord) -> bool {
        self.request_id
            .is_none_or(|id| event.request_id == Some(id))
            && self
                .session_id
                .is_none_or(|id| event.session_id == Some(id))
            && self.action_id.is_none_or(|id| event.action_id == Some(id))
            && self
                .credential_id
                .is_none_or(|id| event.credential_id == Some(id))
            && self
                .outcome
                .as_ref()
                .is_none_or(|value| event.outcome == *value)
            && self
                .since_ms
                .is_none_or(|since| event.created_at_ms >= since)
            && self
                .until_ms
                .is_none_or(|until| event.created_at_ms <= until)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsageSource {
    Measured,
    Indeterminate,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageEvidence {
    pub instance_slug: String,
    pub utc_day: i64,
    pub output_tokens: u64,
    pub source: UsageSource,
}

impl UsageEvidence {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.instance_slug.is_empty()
            || self.instance_slug.len() > 64
            || !self
                .instance_slug
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .instance_slug
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .instance_slug
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || self.utc_day < 0
            || self.output_tokens > i64::MAX as u64
            || (self.source == UsageSource::NotApplicable && self.output_tokens != 0)
        {
            return Err(invalid("invalid usage evidence"));
        }
        Ok(())
    }
}

/// Public metadata copied from the authenticated Profile scope at admission.
/// Never reconstructed from current Profiles or caller-supplied request fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRequestAuditContext {
    pub profile_name: String,
    pub policy_sha256: String,
    pub instance_slug: String,
    pub capability: String,
    pub model: Option<String>,
}

impl ProfileRequestAuditContext {
    pub fn validate(&self) -> Result<(), DomainError> {
        for name in [&self.profile_name, &self.instance_slug] {
            if !(1..=64).contains(&name.len())
                || !name.as_bytes()[0].is_ascii_alphanumeric()
                || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            {
                return Err(invalid("invalid profile audit context"));
            }
        }
        if !is_lower_hex(&self.policy_sha256, 64)
            || !crate::template::slug(&self.capability, 64)
            || self.model.as_ref().is_some_and(|model| {
                model.is_empty() || model.trim() != model || model.chars().any(char::is_control)
            })
        {
            return Err(invalid("invalid profile audit context"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub record_type: String,
    pub sequence: u64,
    pub event_id: String,
    pub request_id: Option<RequestId>,
    pub session_id: Option<SessionId>,
    pub action_id: Option<ActionId>,
    pub action_version: Option<u64>,
    pub credential_id: Option<CredentialId>,
    pub credential_version: Option<u64>,
    pub principal_id: Option<PrincipalId>,
    pub policy_version: Option<u64>,
    pub policy_digest_hex: Option<String>,
    pub policy_rule_id: Option<PolicyRuleId>,
    pub approval_request_id: Option<ApprovalRequestId>,
    pub approval_id: Option<ApprovalId>,
    pub approver_id: Option<ApproverId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_context: Option<ProfileRequestAuditContext>,
    pub event_type: String,
    pub outcome: String,
    pub reason_code: String,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPage {
    pub schema: String,
    pub snapshot_max_sequence: u64,
    pub events: Vec<AuditRecord>,
    pub next_before_sequence: Option<u64>,
}

impl AuditPage {
    pub fn validate_for(&self, query: &AuditQuery) -> Result<(), DomainError> {
        query.validate()?;
        if self.schema != AUDIT_SCHEMA_V2 || self.snapshot_max_sequence == 0 {
            return Err(invalid("invalid audit page schema or snapshot"));
        }
        if query
            .snapshot_max_sequence
            .is_some_and(|expected| expected != self.snapshot_max_sequence)
        {
            return Err(invalid("audit snapshot changed between pages"));
        }
        if self.events.len() > query.limit as usize {
            return Err(invalid("audit page exceeds requested limit"));
        }

        let mut previous = None;
        for event in &self.events {
            if event.record_type != AUDIT_SCHEMA_V2
                || event.sequence == 0
                || event.sequence > self.snapshot_max_sequence
                || !is_lower_hex(&event.event_id, 32)
                || event.action_version == Some(0)
                || event.credential_version == Some(0)
                || event.policy_version == Some(0)
                || event
                    .policy_digest_hex
                    .as_ref()
                    .is_some_and(|value| !is_lower_hex(value, 64))
                || event.policy_version.is_some() != event.principal_id.is_some()
                || event.policy_digest_hex.is_some() != event.principal_id.is_some()
                || (event.policy_rule_id.is_some() && event.principal_id.is_none())
                || (event.approval_id.is_some() && event.approval_request_id.is_none())
                || (event.approver_id.is_some() && event.approval_request_id.is_none())
                || !approval_fields_match_event(event)
                || event.usage.as_ref().is_some_and(|usage| {
                    usage.validate().is_err()
                        || event.request_id.is_none()
                        || event.principal_id.is_none()
                        || !matches!(
                            event.event_type.as_str(),
                            "execution.finished" | "execution.blocked" | "execution.indeterminate"
                        )
                })
                || event.request_context.as_ref().is_some_and(|context| {
                    context.validate().is_err()
                        || event.session_id.is_none()
                        || event.action_id.is_none()
                        || event.action_version.is_none()
                        || event
                            .policy_digest_hex
                            .as_ref()
                            .is_some_and(|digest| digest != &context.policy_sha256)
                        || event
                            .usage
                            .as_ref()
                            .is_some_and(|usage| usage.instance_slug != context.instance_slug)
                })
                || event.event_type.is_empty()
                || event.outcome.is_empty()
                || event.reason_code.is_empty()
                || event.created_at_ms < 0
                || event.latency_ms.is_some_and(|value| value < 0)
                || query
                    .before_sequence
                    .is_some_and(|before| event.sequence >= before)
                || previous.is_some_and(|older| event.sequence >= older)
                || !query.matches(event)
            {
                return Err(invalid("audit page violates query bounds"));
            }
            previous = Some(event.sequence);
        }

        match self.next_before_sequence {
            Some(next)
                if next > 0
                    && next <= self.snapshot_max_sequence
                    && query.before_sequence.is_none_or(|before| next < before)
                    && self.events.iter().all(|event| event.sequence >= next)
                    && (!self.events.is_empty() || next < self.snapshot_max_sequence) => {}
            None => {}
            Some(_) => return Err(invalid("invalid audit page cursor")),
        }
        Ok(())
    }
}

fn approval_fields_match_event(event: &AuditRecord) -> bool {
    let has_authorization = event.principal_id.is_some()
        && event.policy_version.is_some()
        && event.policy_digest_hex.is_some()
        && event.policy_rule_id.is_some();
    if event.reason_code == "local-presence" {
        return has_authorization
            && event.outcome == "success"
            && event.session_id.is_some()
            && event.action_id.is_some()
            && event.action_version.is_some()
            && event.approval_request_id.is_some()
            && event.approver_id.is_none()
            && match event.event_type.as_str() {
                "approval.approved" | "approval.accepted" => event.approval_id.is_some(),
                "approval.rejected" => event.approval_id.is_none(),
                _ => false,
            };
    }
    match event.event_type.as_str() {
        "approval.requested" => {
            has_authorization
                && event.approval_request_id.is_some()
                && event.approval_id.is_none()
                && event.approver_id.is_none()
        }
        "approval.accepted" => {
            has_authorization
                && event.approval_request_id.is_some()
                && event.approval_id.is_some()
                && event.approver_id.is_some()
        }
        "approval.rejected" => {
            let identifiers_are_complete = event.approval_request_id.is_some()
                && event.approval_id.is_some()
                && event.approver_id.is_some();
            let identifiers_are_absent = event.approval_request_id.is_none()
                && event.approval_id.is_none()
                && event.approver_id.is_none();
            has_authorization && (identifiers_are_complete || identifiers_are_absent)
        }
        _ => {
            event.approval_request_id.is_none()
                && event.approval_id.is_none()
                && event.approver_id.is_none()
        }
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(message: &str) -> DomainError {
    DomainError::InvalidAuditQuery(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> AuditQuery {
        AuditQuery {
            request_id: None,
            session_id: None,
            action_id: None,
            credential_id: None,
            outcome: None,
            since_ms: None,
            until_ms: None,
            snapshot_max_sequence: None,
            before_sequence: None,
            limit: 2,
        }
    }

    fn record(sequence: u64) -> AuditRecord {
        AuditRecord {
            record_type: AUDIT_SCHEMA_V2.to_owned(),
            sequence,
            event_id: format!("{sequence:032x}"),
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            principal_id: None,
            policy_version: None,
            policy_digest_hex: None,
            policy_rule_id: None,
            approval_request_id: None,
            approval_id: None,
            approver_id: None,
            usage: None,
            request_context: None,
            event_type: "test.event".to_owned(),
            outcome: "success".to_owned(),
            reason_code: "test".to_owned(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: sequence as i64,
        }
    }

    fn local_page(event_type: &str, approved: bool) -> AuditPage {
        let mut event = record(1);
        event.event_type = event_type.into();
        event.reason_code = "local-presence".into();
        event.session_id = Some(SessionId::new_random());
        event.action_id = Some(ActionId::new_random());
        event.action_version = Some(1);
        event.principal_id = Some(PrincipalId::new_random());
        event.policy_version = Some(1);
        event.policy_digest_hex = Some("01".repeat(32));
        event.policy_rule_id = Some(PolicyRuleId::new_random());
        event.approval_request_id = Some(ApprovalRequestId::new_random());
        event.approval_id = approved.then(ApprovalId::new_random);
        AuditPage {
            schema: AUDIT_SCHEMA_V2.into(),
            snapshot_max_sequence: 1,
            events: vec![event],
            next_before_sequence: None,
        }
    }

    #[test]
    fn local_presence_approved_audit_page_is_valid() {
        local_page("approval.approved", true)
            .validate_for(&query())
            .unwrap();
    }

    #[test]
    fn local_presence_accepted_audit_page_is_valid() {
        local_page("approval.accepted", true)
            .validate_for(&query())
            .unwrap();
    }

    #[test]
    fn local_audit_shapes_do_not_relax_external_approvers_or_other_events() {
        local_page("approval.rejected", false)
            .validate_for(&query())
            .unwrap();
        for (kind, approved) in [
            ("approval.approved", false),
            ("approval.accepted", false),
            ("approval.rejected", true),
            ("execution.finished", true),
        ] {
            assert!(local_page(kind, approved).validate_for(&query()).is_err());
        }
        let valid = local_page("approval.accepted", true);
        for change in 0..6 {
            let mut page = valid.clone();
            let event = &mut page.events[0];
            match change {
                0 => event.reason_code = "accepted".into(),
                1 => event.approver_id = Some(ApproverId::new_random()),
                2 => event.outcome = "failure".into(),
                3 => event.approval_request_id = None,
                4 => event.session_id = None,
                5 => event.policy_rule_id = None,
                _ => unreachable!(),
            }
            assert!(page.validate_for(&query()).is_err());
        }
        let mut external = valid;
        external.events[0].reason_code = "accepted".into();
        external.events[0].approver_id = Some(ApproverId::new_random());
        external.validate_for(&query()).unwrap();
    }

    #[test]
    fn profile_audit_context_roundtrip_rejects_unknown_fields_and_invalid_dimensions() {
        let context = ProfileRequestAuditContext {
            profile_name: "writer".into(),
            policy_sha256: "ab".repeat(32),
            instance_slug: "provider".into(),
            capability: "messages".into(),
            model: Some("allowed".into()),
        };
        let value = serde_json::to_value(&context).unwrap();
        let decoded: ProfileRequestAuditContext = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded, context);
        decoded.validate().unwrap();
        let mut extra = value;
        extra["prompt"] = serde_json::json!("not metadata");
        assert!(serde_json::from_value::<ProfileRequestAuditContext>(extra).is_err());
        for field in 0..5 {
            let mut bad = context.clone();
            match field {
                0 => bad.profile_name = "../writer".into(),
                1 => bad.policy_sha256 = "AB".repeat(32),
                2 => bad.instance_slug = "_hidden".into(),
                3 => bad.capability = "../target".into(),
                4 => bad.model = Some("allowed\n".into()),
                _ => unreachable!(),
            }
            assert!(bad.validate().is_err());
        }
    }

    #[test]
    fn query_rejects_invalid_bounds() {
        let mut value = query();
        value.limit = 0;
        assert!(value.validate().is_err());
        value.limit = 1;
        value.since_ms = Some(2);
        value.until_ms = Some(1);
        assert!(value.validate().is_err());
        value.since_ms = None;
        value.until_ms = None;
        value.before_sequence = Some(0);
        assert!(value.validate().is_err());
        value.before_sequence = Some(2);
        value.snapshot_max_sequence = Some(1);
        assert!(value.validate().is_err());
    }

    #[test]
    fn page_rejects_order_cursor_and_filter_violations() {
        let value = query();
        let valid = AuditPage {
            schema: AUDIT_SCHEMA_V2.to_owned(),
            snapshot_max_sequence: 3,
            events: vec![record(3), record(2)],
            next_before_sequence: Some(2),
        };
        assert!(valid.validate_for(&value).is_ok());

        let mut bad = valid.clone();
        bad.events.swap(0, 1);
        assert!(bad.validate_for(&value).is_err());

        let mut filtered = value;
        filtered.outcome = Some("denied".to_owned());
        assert!(valid.validate_for(&filtered).is_err());
        let empty_scan_window = AuditPage {
            schema: AUDIT_SCHEMA_V2.to_owned(),
            snapshot_max_sequence: 3,
            events: Vec::new(),
            next_before_sequence: Some(2),
        };
        assert!(empty_scan_window.validate_for(&filtered).is_ok());

        let mut malformed = valid;
        malformed.events[0].event_id = "ABC".to_owned();
        assert!(malformed.validate_for(&query()).is_err());
    }

    #[test]
    fn approval_events_require_complete_authorization_evidence() {
        for event_type in [
            "approval.requested",
            "approval.accepted",
            "approval.rejected",
        ] {
            let mut event = record(1);
            event.event_type = event_type.to_owned();
            event.approval_request_id = Some(ApprovalRequestId::new_random());
            if event_type == "approval.accepted" {
                event.approval_id = Some(ApprovalId::new_random());
                event.approver_id = Some(ApproverId::new_random());
            }
            let page = AuditPage {
                schema: AUDIT_SCHEMA_V2.to_owned(),
                snapshot_max_sequence: 1,
                events: vec![event],
                next_before_sequence: None,
            };
            assert!(page.validate_for(&query()).is_err());
        }
    }

    #[test]
    fn rejected_approval_identifiers_are_complete_or_absent() {
        let mut event = record(1);
        event.event_type = "approval.rejected".to_owned();
        event.principal_id = Some(PrincipalId::new_random());
        event.policy_version = Some(1);
        event.policy_digest_hex = Some("00".repeat(32));
        event.policy_rule_id = Some(PolicyRuleId::new_random());
        event.approval_request_id = Some(ApprovalRequestId::new_random());
        let mut page = AuditPage {
            schema: AUDIT_SCHEMA_V2.to_owned(),
            snapshot_max_sequence: 1,
            events: vec![event],
            next_before_sequence: None,
        };
        assert!(page.validate_for(&query()).is_err());
        page.events[0].approval_id = Some(ApprovalId::new_random());
        page.events[0].approver_id = Some(ApproverId::new_random());
        assert!(page.validate_for(&query()).is_ok());
    }
}

#[cfg(test)]
mod retention_contract_tests {
    use super::*;
    #[test]
    fn retention_requires_explicit_days_and_rejects_bad_fields() {
        for input in [
            r#"{}"#,
            r#"{"days":0}"#,
            r#"{"days":-1}"#,
            r#"{"days":1,"extra":true}"#,
        ] {
            let parsed = serde_json::from_str::<AuditRetentionSet>(input);
            assert!(
                parsed.is_err() || parsed.unwrap().validate_at(172800000).is_err(),
                "{input}"
            );
        }
        assert_eq!(
            serde_json::from_str::<AuditRetentionSet>(r#"{"days":null}"#)
                .unwrap()
                .days,
            None
        );
        assert_eq!(
            serde_json::from_str::<AuditRetentionSet>(r#"{"days":1}"#)
                .unwrap()
                .cutoff_at(172800000)
                .unwrap(),
            Some(86400000)
        );
    }
    #[test]
    fn retention_age_and_receipt_bounds_are_checked_without_clamping() {
        for days in [0, u64::MAX] {
            assert!(
                AuditRetentionSet { days: Some(days) }
                    .validate_at(i64::MAX)
                    .is_err()
            );
        }
        assert!(AuditRetentionSet { days: Some(1) }.cutoff_at(1).is_err());
        assert!(
            AuditRetentionStatus {
                days: Some(0),
                updated_at_ms: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            AuditRetentionStatus {
                days: None,
                updated_at_ms: -1
            }
            .validate()
            .is_err()
        );
    }
}

#[cfg(test)]
mod usage_tests {
    use super::*;
    #[test]
    fn usage_evidence_retains_audit_v2_and_rejects_invalid_storage_values() {
        let value = UsageEvidence {
            instance_slug: "llm_Main-1".into(),
            utc_day: 1,
            output_tokens: 7,
            source: UsageSource::Measured,
        };
        value.validate().unwrap();
        assert_eq!(
            serde_json::from_slice::<UsageEvidence>(&serde_json::to_vec(&value).unwrap()).unwrap(),
            value
        );
        for slug in ["", "_main", "main_", "main.dot", "main/path", "名"] {
            let mut changed = value.clone();
            changed.instance_slug = slug.into();
            assert!(changed.validate().is_err());
        }
        let mut changed = value.clone();
        changed.output_tokens = u64::MAX;
        assert!(changed.validate().is_err());
        changed = value.clone();
        changed.utc_day = -1;
        assert!(changed.validate().is_err());
        changed = value;
        changed.source = UsageSource::NotApplicable;
        assert!(changed.validate().is_err());
        assert!(serde_json::from_str::<UsageEvidence>(r#"{"instance_slug":"llm","utc_day":1,"output_tokens":0,"source":"measured","extra":true}"#).is_err());
        assert_eq!(AUDIT_SCHEMA_V2, "rekey.audit.v2");
    }
}
