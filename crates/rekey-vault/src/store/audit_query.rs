use data_encoding::HEXLOWER;
use rekey_domain::audit::{AUDIT_SCHEMA_V1, AuditPage, AuditQuery, AuditRecord};
use rekey_domain::ids::{ActionId, CredentialId, RequestId, SessionId};
use rusqlite::types::Value;

use super::recovery::{authorization_from_columns, optional_id};
use super::sqlite::{SqliteRecordStore, blob16, storage};
use crate::error::AuthorityError;

struct RawAuditRow {
    sequence: i64,
    event_id: Vec<u8>,
    request_id: Option<Vec<u8>>,
    session_id: Option<Vec<u8>>,
    action_id: Option<Vec<u8>>,
    action_version: Option<i64>,
    credential_id: Option<Vec<u8>>,
    credential_version: Option<i64>,
    principal_id: Option<Vec<u8>>,
    policy_version: Option<i64>,
    policy_digest: Option<Vec<u8>>,
    policy_rule_id: Option<Vec<u8>>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    parameter_hash: Option<Vec<u8>>,
    event_type: String,
    outcome: String,
    reason_code: String,
    upstream_status: Option<i64>,
    latency_ms: Option<i64>,
    created_at_ms: i64,
}

impl SqliteRecordStore {
    pub fn audit_query(&self, query: &AuditQuery) -> Result<AuditPage, AuthorityError> {
        query.validate().map_err(AuthorityError::Domain)?;
        let snapshot_max_sequence = match query.snapshot_max_sequence {
            Some(value) => value,
            None => {
                let value: Option<i64> = self
                    .conn
                    .query_row("SELECT MAX(sequence) FROM audit_events", [], |row| {
                        row.get(0)
                    })
                    .map_err(storage)?;
                positive_u64(value.ok_or(AuthorityError::StorageIntegrityFailed)?)?
            }
        };

        let mut sql = String::from(
            "SELECT sequence, event_id, request_id, session_id, action_id, action_version,
                    credential_id, credential_version, principal_id, policy_version,
                    policy_digest, policy_rule_id, resource_type, resource_id, parameter_hash,
                    event_type, outcome, reason_code, upstream_status, latency_ms, created_at_ms
             FROM audit_events WHERE sequence <= ?",
        );
        let mut params = vec![Value::Integer(snapshot_max_sequence as i64)];
        push_id_filter(
            &mut sql,
            &mut params,
            "request_id",
            query.request_id.as_ref().map(|id| id.as_bytes()),
        );
        push_id_filter(
            &mut sql,
            &mut params,
            "session_id",
            query.session_id.as_ref().map(|id| id.as_bytes()),
        );
        push_id_filter(
            &mut sql,
            &mut params,
            "action_id",
            query.action_id.as_ref().map(|id| id.as_bytes()),
        );
        push_id_filter(
            &mut sql,
            &mut params,
            "credential_id",
            query.credential_id.as_ref().map(|id| id.as_bytes()),
        );
        if let Some(outcome) = &query.outcome {
            sql.push_str(" AND outcome = ?");
            params.push(Value::Text(outcome.clone()));
        }
        if let Some(since_ms) = query.since_ms {
            sql.push_str(" AND created_at_ms >= ?");
            params.push(Value::Integer(since_ms));
        }
        if let Some(until_ms) = query.until_ms {
            sql.push_str(" AND created_at_ms <= ?");
            params.push(Value::Integer(until_ms));
        }
        if let Some(before) = query.before_sequence {
            sql.push_str(" AND sequence < ?");
            params.push(Value::Integer(before as i64));
        }
        sql.push_str(" ORDER BY sequence DESC LIMIT ?");
        params.push(Value::Integer(i64::from(query.limit) + 1));

        let mut statement = self.conn.prepare(&sql).map_err(storage)?;
        let raw = statement
            .query_map(rusqlite::params_from_iter(params.iter()), raw_row)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut events = raw
            .into_iter()
            .map(record_from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > query.limit as usize;
        if has_more {
            events.pop();
        }
        let next_before_sequence = has_more.then(|| {
            events
                .last()
                .expect("limit validation guarantees a retained event")
                .sequence
        });
        let page = AuditPage {
            schema: AUDIT_SCHEMA_V1.to_owned(),
            snapshot_max_sequence,
            events,
            next_before_sequence,
        };
        page.validate_for(query)
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        Ok(page)
    }
}

fn push_id_filter(sql: &mut String, params: &mut Vec<Value>, column: &str, id: Option<&[u8; 16]>) {
    if let Some(id) = id {
        sql.push_str(" AND ");
        sql.push_str(column);
        sql.push_str(" = ?");
        params.push(Value::Blob(id.to_vec()));
    }
}

fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAuditRow> {
    Ok(RawAuditRow {
        sequence: row.get(0)?,
        event_id: row.get(1)?,
        request_id: row.get(2)?,
        session_id: row.get(3)?,
        action_id: row.get(4)?,
        action_version: row.get(5)?,
        credential_id: row.get(6)?,
        credential_version: row.get(7)?,
        principal_id: row.get(8)?,
        policy_version: row.get(9)?,
        policy_digest: row.get(10)?,
        policy_rule_id: row.get(11)?,
        resource_type: row.get(12)?,
        resource_id: row.get(13)?,
        parameter_hash: row.get(14)?,
        event_type: row.get(15)?,
        outcome: row.get(16)?,
        reason_code: row.get(17)?,
        upstream_status: row.get(18)?,
        latency_ms: row.get(19)?,
        created_at_ms: row.get(20)?,
    })
}

fn record_from_raw(raw: RawAuditRow) -> Result<AuditRecord, AuthorityError> {
    let authorization = authorization_from_columns(
        raw.principal_id,
        raw.policy_version,
        raw.policy_digest,
        raw.policy_rule_id,
        raw.resource_type,
        raw.resource_id,
        raw.parameter_hash,
    )?;
    let event_id = blob16(raw.event_id)?;
    if raw.event_type.is_empty()
        || raw.outcome.is_empty()
        || raw.reason_code.is_empty()
        || raw.created_at_ms < 0
        || raw.latency_ms.is_some_and(|value| value < 0)
    {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    let upstream_status = raw
        .upstream_status
        .map(|value| u16::try_from(value).map_err(|_| AuthorityError::StorageIntegrityFailed))
        .transpose()?;
    Ok(AuditRecord {
        record_type: AUDIT_SCHEMA_V1.to_owned(),
        sequence: positive_u64(raw.sequence)?,
        event_id: HEXLOWER.encode(&event_id),
        request_id: optional_id(raw.request_id, RequestId::from_bytes)?,
        session_id: optional_id(raw.session_id, SessionId::from_bytes)?,
        action_id: optional_id(raw.action_id, ActionId::from_bytes)?,
        action_version: optional_version(raw.action_version)?,
        credential_id: optional_id(raw.credential_id, CredentialId::from_bytes)?,
        credential_version: optional_version(raw.credential_version)?,
        principal_id: authorization.as_ref().map(|value| value.principal_id),
        policy_version: authorization.as_ref().map(|value| value.policy_version),
        policy_digest_hex: authorization
            .as_ref()
            .map(|value| HEXLOWER.encode(&value.policy_digest)),
        policy_rule_id: authorization.and_then(|value| value.policy_rule_id),
        event_type: raw.event_type,
        outcome: raw.outcome,
        reason_code: raw.reason_code,
        upstream_status,
        latency_ms: raw.latency_ms,
        created_at_ms: raw.created_at_ms,
    })
}

fn positive_u64(value: i64) -> Result<u64, AuthorityError> {
    let value = u64::try_from(value).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if value == 0 {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(value)
}

fn optional_version(value: Option<i64>) -> Result<Option<u64>, AuthorityError> {
    value.map(positive_u64).transpose()
}
