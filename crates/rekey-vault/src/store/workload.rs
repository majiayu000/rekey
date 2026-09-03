use rusqlite::params;

use super::SqliteRecordStore;
use super::sqlite::commit_audited;
use crate::error::AuthorityError;
use crate::model::AuditEvent;

pub const WORKLOAD_REPLAY_MAX_ROWS: i64 = 65_536;

impl SqliteRecordStore {
    pub fn consume_workload_token(
        &mut self,
        replay_digest: [u8; 32],
        expires_at_ms: i64,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        if audit.created_at_ms < 0 || expires_at_ms <= audit.created_at_ms {
            return Err(AuthorityError::WorkloadIdentityInvalid);
        }
        let tx = self.conn.transaction().map_err(AuthorityError::storage)?;
        let rows: i64 = tx
            .query_row("SELECT count(*) FROM workload_token_uses", [], |row| {
                row.get(0)
            })
            .map_err(AuthorityError::storage)?;
        if rows >= WORKLOAD_REPLAY_MAX_ROWS {
            return Err(AuthorityError::WorkloadIdentityInvalid);
        }
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO workload_token_uses
                 (replay_digest, expires_at_ms, created_at_ms) VALUES (?1, ?2, ?3)",
                params![replay_digest.as_slice(), expires_at_ms, audit.created_at_ms],
            )
            .map_err(AuthorityError::storage)?;
        if inserted != 1 {
            return Err(AuthorityError::WorkloadIdentityInvalid);
        }
        super::audit::insert(&tx, &audit).map_err(|_| AuthorityError::AuditCommitFailed)?;
        commit_audited(tx)
    }
}

#[cfg(test)]
mod tests {
    use rekey_domain::ids::RequestId;

    use super::*;
    use crate::model::{event_type, outcome};

    fn audit(created_at_ms: i64, event_id: [u8; 16]) -> AuditEvent {
        AuditEvent {
            event_id,
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            event_type: event_type::SESSION_CREATED,
            outcome: outcome::SUCCESS,
            reason_code: "workload-attested".to_owned(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms,
        }
    }

    fn store() -> (tempfile::TempDir, SqliteRecordStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteRecordStore::create(&dir.path().join("vault.sqlite3")).unwrap();
        (dir, store)
    }

    fn id() -> [u8; 16] {
        *RequestId::new_random().as_bytes()
    }

    #[test]
    fn replay_insert_and_audit_are_atomic() {
        let (_dir, mut store) = store();
        let first_event = id();
        store.append_audit(&audit(100, first_event)).unwrap();
        assert!(matches!(
            store.consume_workload_token([7; 32], 200, audit(100, first_event)),
            Err(AuthorityError::AuditCommitFailed)
        ));
        store
            .consume_workload_token([7; 32], 200, audit(100, id()))
            .unwrap();
        assert!(matches!(
            store.consume_workload_token([7; 32], 200, audit(100, id())),
            Err(AuthorityError::WorkloadIdentityInvalid)
        ));
        let count: i64 = store
            .conn
            .query_row("SELECT count(*) FROM workload_token_uses", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn expired_rows_survive_wall_clock_rollback() {
        let (_dir, mut store) = store();
        store
            .consume_workload_token([1; 32], 150, audit(100, id()))
            .unwrap();
        store
            .consume_workload_token([2; 32], 250, audit(200, id()))
            .unwrap();
        assert!(matches!(
            store.consume_workload_token([1; 32], 150, audit(100, id())),
            Err(AuthorityError::WorkloadIdentityInvalid)
        ));
        let digests = store
            .conn
            .prepare("SELECT replay_digest FROM workload_token_uses ORDER BY replay_digest")
            .unwrap()
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(digests, vec![vec![1; 32], vec![2; 32]]);
    }

    #[test]
    fn invalid_times_fail_before_mutation() {
        let (_dir, mut store) = store();
        assert!(matches!(
            store.consume_workload_token([1; 32], 100, audit(100, id())),
            Err(AuthorityError::WorkloadIdentityInvalid)
        ));
        assert!(matches!(
            store.consume_workload_token([1; 32], 100, audit(-1, id())),
            Err(AuthorityError::WorkloadIdentityInvalid)
        ));
    }

    #[test]
    fn replay_table_cap_fails_closed_even_after_wall_clock_advances() {
        let (_dir, mut store) = store();
        let tx = store.conn.transaction().unwrap();
        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO workload_token_uses
                     (replay_digest, expires_at_ms, created_at_ms) VALUES (?1, 1000, 0)",
                )
                .unwrap();
            for index in 0..WORKLOAD_REPLAY_MAX_ROWS as u64 {
                let mut digest = [0u8; 32];
                digest[24..].copy_from_slice(&index.to_be_bytes());
                insert.execute(params![digest.as_slice()]).unwrap();
            }
        }
        tx.commit().unwrap();
        assert!(matches!(
            store.consume_workload_token([0xff; 32], 2000, audit(500, id())),
            Err(AuthorityError::WorkloadIdentityInvalid)
        ));
        assert!(matches!(
            store.consume_workload_token([0xff; 32], 3000, audit(2000, id())),
            Err(AuthorityError::WorkloadIdentityInvalid)
        ));
        let count: i64 = store
            .conn
            .query_row("SELECT count(*) FROM workload_token_uses", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, WORKLOAD_REPLAY_MAX_ROWS);
    }
}
