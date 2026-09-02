use serde::{Deserialize, Serialize};

use crate::DomainError;
use crate::ids::{ActionId, CredentialId, PolicyRuleId, PrincipalId, RequestId, SessionId};

pub const AUDIT_SCHEMA_V1: &str = "rekey.audit.v1";
pub const AUDIT_PAGE_DEFAULT_LIMIT: u32 = 50;
pub const AUDIT_PAGE_MAX_LIMIT: u32 = 100;
pub const AUDIT_SCAN_MAX_ROWS: u32 = 1_000;

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
        if self.schema != AUDIT_SCHEMA_V1 || self.snapshot_max_sequence == 0 {
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
            if event.record_type != AUDIT_SCHEMA_V1
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
            record_type: AUDIT_SCHEMA_V1.to_owned(),
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
            event_type: "test.event".to_owned(),
            outcome: "success".to_owned(),
            reason_code: "test".to_owned(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: sequence as i64,
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
            schema: AUDIT_SCHEMA_V1.to_owned(),
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
            schema: AUDIT_SCHEMA_V1.to_owned(),
            snapshot_max_sequence: 3,
            events: Vec::new(),
            next_before_sequence: Some(2),
        };
        assert!(empty_scan_window.validate_for(&filtered).is_ok());

        let mut malformed = valid;
        malformed.events[0].event_id = "ABC".to_owned();
        assert!(malformed.validate_for(&query()).is_err());
    }
}
