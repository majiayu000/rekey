use std::collections::BTreeMap;
use std::time::Instant;

use rekey_domain::audit::{AuditPruneReceipt, AuditPruneRequest};
use rekey_domain::ids::RequestId;

use super::audit_query::{AUDIT_COLUMNS, raw_row, record_from_raw};
use super::sqlite::{SqliteRecordStore, commit_audited, storage};
use crate::error::AuthorityError;
use crate::model::{AuditEvent, event_type};

#[derive(Default)]
struct ExecutionGroup {
    sequences: Vec<u64>,
    start: Option<u64>,
    terminal: Option<u64>,
    retained: bool,
}

impl SqliteRecordStore {
    pub(crate) fn audit_prune(
        &mut self,
        request: &AuditPruneRequest,
        marker: AuditEvent,
        not_after: Option<Instant>,
    ) -> Result<AuditPruneReceipt, AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        let mut groups: BTreeMap<RequestId, ExecutionGroup> = BTreeMap::new();
        {
            let mut statement = tx
                .prepare(&format!(
                    "SELECT {AUDIT_COLUMNS} FROM audit_events ORDER BY sequence"
                ))
                .map_err(storage)?;
            let rows = statement.query_map([], raw_row).map_err(storage)?;
            for raw in rows {
                // Parse even retained/ungrouped records: pruning must not erase
                // structural corruption and make the audit appear healthy.
                ensure_current(not_after)?;
                let event = record_from_raw(raw.map_err(storage)?)?;
                let Some(request_id) = event.request_id else {
                    continue;
                };
                let group = groups.entry(request_id).or_default();
                group.sequences.push(event.sequence);
                group.retained |= event.created_at_ms >= request.before_ms
                    || event.approval_request_id.is_some()
                    || event.approval_id.is_some()
                    || event.approver_id.is_some();
                match event.event_type.as_str() {
                    event_type::EXECUTION_STARTED => {
                        group.retained |= group.start.replace(event.sequence).is_some();
                    }
                    event_type::EXECUTION_FINISHED
                    | event_type::EXECUTION_BLOCKED
                    | event_type::EXECUTION_INDETERMINATE => {
                        group.retained |= group.terminal.replace(event.sequence).is_some();
                    }
                    event_type::GITHUB_CONNECTOR_AUTHORIZED
                    | event_type::GITHUB_TOKEN_REVOKED
                    | event_type::VAULT_LEASE_ISSUED
                    | event_type::VAULT_LEASE_REVOKED => {}
                    _ => group.retained = true,
                }
            }
        }
        let mut receipt = AuditPruneReceipt {
            before_ms: request.before_ms,
            deleted_rows: 0,
            deleted_groups: 0,
            prune_sequence: None,
        };
        for group in groups.into_values() {
            if group.retained
                || !matches!((group.start, group.terminal), (Some(start), Some(terminal)) if start < terminal)
            {
                continue;
            }
            for sequence in group.sequences {
                ensure_current(not_after)?;
                // sequence is the existing INTEGER PRIMARY KEY. Deleting by
                // request_id would scan the complete table for every group.
                let removed = tx
                    .execute(
                        "DELETE FROM audit_events WHERE sequence = ?1",
                        [sequence as i64],
                    )
                    .map_err(storage)?;
                if removed != 1 {
                    return Err(AuthorityError::StorageIntegrityFailed);
                }
                receipt.deleted_rows += 1;
            }
            receipt.deleted_groups += 1;
        }
        if receipt.deleted_rows > 0 {
            super::audit::insert(&tx, &marker)?;
            receipt.prune_sequence = Some(
                u64::try_from(tx.last_insert_rowid())
                    .ok()
                    .filter(|sequence| *sequence > 0)
                    .ok_or(AuthorityError::StorageIntegrityFailed)?,
            );
        }
        ensure_current(not_after)?;
        if receipt.deleted_rows > 0 {
            commit_audited(tx)?;
        }
        Ok(receipt)
    }
}

fn ensure_current(not_after: Option<Instant>) -> Result<(), AuthorityError> {
    if not_after.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(AuthorityError::AuthorityBusy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(request: Option<RequestId>, kind: &'static str) -> AuditEvent {
        AuditEvent {
            event_id: crate::crypto::random_array().unwrap(),
            request_id: request,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            event_type: kind,
            outcome: "success",
            reason_code: "test".into(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: 10,
        }
    }

    #[test]
    fn prune_precommit_expiry_restores_deleted_rows_and_discards_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteRecordStore::create(&dir.path().join("vault.sqlite3")).unwrap();
        let request = RequestId::from_bytes([7; 16]).unwrap();
        store
            .append_audit(&audit(Some(request), event_type::EXECUTION_STARTED))
            .unwrap();
        store
            .append_audit(&audit(Some(request), event_type::EXECUTION_FINISHED))
            .unwrap();
        let before = store.audit_event_types().unwrap();
        // Test-only SQL work runs after the marker was inserted, confirms the
        // group is already deleted inside this transaction, and crosses the
        // deadline. No production timing hook or connection behavior is changed.
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER delay_prune_commit AFTER INSERT ON audit_events
            WHEN NEW.event_type = 'audit.pruned' BEGIN
              SELECT CASE WHEN (SELECT count(*) FROM audit_events WHERE request_id IS NOT NULL) = 0
                THEN 1 ELSE RAISE(ABORT, 'delete not reached') END;
              SELECT sum(value) FROM (WITH RECURSIVE counter(value) AS (
                VALUES(0) UNION ALL SELECT value + 1 FROM counter WHERE value < 10000000
              ) SELECT value FROM counter);
            END;",
            )
            .unwrap();
        let started = Instant::now();
        let result = store.audit_prune(
            &AuditPruneRequest { before_ms: 100 },
            audit(None, event_type::AUDIT_PRUNED),
            Some(started + std::time::Duration::from_millis(100)),
        );
        assert!(matches!(result, Err(AuthorityError::AuthorityBusy)));
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(100),
            "must reach the delayed marker insertion"
        );
        assert_eq!(store.audit_event_types().unwrap(), before);
    }
}
