use rusqlite::{Transaction, params};

use crate::error::AuthorityError;
use crate::model::AuditEvent;

pub(super) fn insert(tx: &Transaction<'_>, event: &AuditEvent) -> Result<(), AuthorityError> {
    let authorization = event.authorization.as_ref();
    tx.execute(
        "INSERT INTO audit_events (event_id, request_id, session_id, action_id, action_version, credential_id, credential_version, principal_id, policy_version, policy_digest, policy_rule_id, resource_type, resource_id, parameter_hash, approval_request_id, approval_id, approver_id, event_type, outcome, reason_code, upstream_status, latency_ms, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        params![
            event.event_id.as_slice(),
            event.request_id.as_ref().map(|v| v.as_bytes().as_slice()),
            event.session_id.as_ref().map(|v| v.as_bytes().as_slice()),
            event.action_id.as_ref().map(|v| v.as_bytes().as_slice()),
            event.action_version.map(|v| v as i64),
            event.credential_id.as_ref().map(|v| v.as_bytes().as_slice()),
            event.credential_version.map(|v| v as i64),
            authorization.map(|v| v.principal_id.as_bytes().as_slice()),
            authorization.map(|v| v.policy_version as i64),
            authorization.map(|v| v.policy_digest.as_slice()),
            authorization.and_then(|v| v.policy_rule_id.as_ref().map(|id| id.as_bytes().as_slice())),
            authorization.map(|v| v.resource_type.as_str()),
            authorization.map(|v| v.resource_id.as_str()),
            authorization.map(|v| v.parameter_hash.as_slice()),
            event.approval.as_ref().map(|v| v.approval_request_id.as_bytes().as_slice()),
            event.approval.as_ref().and_then(|v| v.approval_id.as_ref().map(|id| id.as_bytes().as_slice())),
            event.approval.as_ref().and_then(|v| v.approver_id.as_ref().map(|id| id.as_bytes().as_slice())),
            event.event_type,
            event.outcome,
            event.reason_code,
            event.upstream_status,
            event.latency_ms,
            event.created_at_ms,
        ],
    )
    .map_err(|_| AuthorityError::AuditCommitFailed)?;
    Ok(())
}
