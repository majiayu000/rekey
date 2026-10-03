use rekey_domain::audit::{AuditPruneReceipt, AuditPruneRequest};

use crate::command::{AuditDraft, UnlockProof};
use crate::crypto::random_array;
use crate::error::AuthorityError;
use crate::model::{AuditEvent, event_type, outcome};
use crate::now_ms;

use super::{VaultState, Worker, ensure_mutation_current, unlock_audit};

impl Worker {
    pub(super) fn audit_prune(
        &mut self,
        request: AuditPruneRequest,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<AuditPruneReceipt, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        request.validate_at(now_ms()?)?;
        ensure_mutation_current(not_after)?;
        let marker = self.audit_event_or_fault(unlock_audit(
            event_type::AUDIT_PRUNED,
            outcome::SUCCESS,
            "explicit-execution-prune",
        ))?;
        let result = self.store.audit_prune(&request, marker, not_after);
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }

    pub(super) fn retention_record(
        &mut self,
    ) -> Result<crate::model::AuditRetentionRecord, AuthorityError> {
        let key = self.require_unlocked()?;
        let result = self
            .store
            .verified_audit_retention(key.bytes(), self.header.vault_id);
        self.fault_on_integrity(result)
    }
    pub(super) fn audit_retention_status(
        &mut self,
    ) -> Result<rekey_domain::audit::AuditRetentionStatus, AuthorityError> {
        let record = self.retention_record()?;
        Ok(rekey_domain::audit::AuditRetentionStatus {
            days: record.days,
            updated_at_ms: record.updated_at_ms,
        })
    }
    fn observe_retention_clock(
        &mut self,
        updated_at_ms: i64,
        now: i64,
    ) -> Result<(), AuthorityError> {
        if now < updated_at_ms || self.retention_last_clock_ms.is_some_and(|last| now < last) {
            return Err(AuthorityError::ClockUnavailable);
        }
        self.retention_last_clock_ms = Some(now);
        Ok(())
    }
    pub(super) fn audit_retention_set(
        &mut self,
        request: rekey_domain::audit::AuditRetentionSet,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<rekey_domain::audit::AuditRetentionStatus, AuthorityError> {
        self.require_unlocked()?;
        let verified = self.verify_proof(&proof);
        drop(proof);
        verified?;
        let prior = self.retention_record()?;
        let now = now_ms()?;
        self.observe_retention_clock(prior.updated_at_ms, now)?;
        request.validate_at(now)?;
        ensure_mutation_current(not_after)?;
        let mut record = crate::model::AuditRetentionRecord {
            days: request.days,
            updated_at_ms: now,
            seal_nonce: [0; 12],
            seal_ciphertext: [0; 16],
        };
        let seal = crate::crypto::policy_state::seal_retention(
            self.require_unlocked()?.bytes(),
            self.header.vault_id,
            &record,
        )?;
        record.seal_nonce = seal.nonce;
        record.seal_ciphertext = seal.ciphertext;
        let marker = self.audit_event_at(
            unlock_audit(
                event_type::AUDIT_RETENTION_CHANGED,
                outcome::SUCCESS,
                "retention-policy",
            ),
            now,
        )?;
        let result = self.store.set_audit_retention(&record, marker, not_after);
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)?;
        Ok(rekey_domain::audit::AuditRetentionStatus {
            days: record.days,
            updated_at_ms: record.updated_at_ms,
        })
    }
    pub(super) fn audit_retention_maintenance(
        &mut self,
        not_after: std::time::Instant,
    ) -> Result<Option<AuditPruneReceipt>, AuthorityError> {
        ensure_mutation_current(Some(not_after))?;
        match self.state {
            VaultState::Locked => return Ok(None),
            VaultState::Faulted => return Err(AuthorityError::Faulted),
            VaultState::Unlocked { .. } => {}
        }
        let record = self.retention_record()?;
        if record.days.is_none() {
            return Ok(None);
        }
        self.retention_maintenance_at(record, now_ms()?, not_after)
    }
    fn retention_maintenance_at(
        &mut self,
        record: crate::model::AuditRetentionRecord,
        now: i64,
        not_after: std::time::Instant,
    ) -> Result<Option<AuditPruneReceipt>, AuthorityError> {
        self.observe_retention_clock(record.updated_at_ms, now)?;
        let before_ms = rekey_domain::audit::AuditRetentionSet { days: record.days }
            .cutoff_at(now)
            .map_err(|_| AuthorityError::ClockUnavailable)?
            .ok_or(AuthorityError::StorageIntegrityFailed)?;
        let request = AuditPruneRequest { before_ms };
        let marker = self.audit_event_at(
            unlock_audit(
                event_type::AUDIT_PRUNED,
                outcome::SUCCESS,
                "retention-policy",
            ),
            now,
        )?;
        let result = self.store.audit_prune(&request, marker, Some(not_after));
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result).map(Some)
    }

    pub(super) fn fault(&mut self, reason: &'static str) {
        self.presence_grant = None;
        self.state = VaultState::Faulted;
        if let Err(error) = self.forget_desktop() {
            tracing::error!(event = "desktop.revocation_failed", code = error.code());
        }
        if let (Ok(event_id), Ok(created_at_ms)) = (random_array(), now_ms()) {
            drop(self.store.append_audit(&AuditEvent {
                event_id,
                request_id: None,
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                approval: None,
                event_type: event_type::RUNTIME_FAULTED,
                outcome: outcome::FAILURE,
                reason_code: reason.to_owned(),
                upstream_status: None,
                latency_ms: None,
                created_at_ms,
            }));
        }
    }

    fn audit_event(&self, draft: AuditDraft) -> Result<AuditEvent, AuthorityError> {
        self.audit_event_at(draft, now_ms()?)
    }

    fn audit_event_at(
        &self,
        draft: AuditDraft,
        created_at_ms: i64,
    ) -> Result<AuditEvent, AuthorityError> {
        Ok(AuditEvent {
            event_id: random_array()?,
            request_id: draft.request_id,
            session_id: draft.session_id,
            action_id: draft.action_id,
            action_version: draft.action_version,
            credential_id: draft.credential_id,
            credential_version: draft.credential_version,
            authorization: draft.authorization.map(|evidence| *evidence),
            approval: draft.approval,
            event_type: draft.event_type,
            outcome: draft.outcome,
            reason_code: draft.reason_code,
            upstream_status: draft.upstream_status,
            latency_ms: draft.latency_ms,
            created_at_ms,
        })
    }

    pub(super) fn audit_event_or_fault(
        &mut self,
        draft: AuditDraft,
    ) -> Result<AuditEvent, AuthorityError> {
        match self.audit_event(draft) {
            Ok(event) => Ok(event),
            Err(err) => {
                self.fault("audit-event-construction-failed");
                Err(err)
            }
        }
    }

    pub(super) fn fault_on_audit_failure<T>(
        &mut self,
        result: Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        if matches!(result, Err(AuthorityError::AuditCommitFailed)) {
            self.fault("audit-commit-failed");
        }
        result
    }

    /// Audit failure is fail-closed: the worker faults instead of continuing
    /// without evidence.
    pub(super) fn append_audit(&mut self, draft: AuditDraft) -> Result<(), AuthorityError> {
        let event = self.audit_event_or_fault(draft)?;
        match self.store.append_audit(&event) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.fault("audit-commit-failed");
                Err(err)
            }
        }
    }

    pub(super) fn append_audits(&mut self, drafts: Vec<AuditDraft>) -> Result<(), AuthorityError> {
        let events = drafts
            .into_iter()
            .map(|draft| self.audit_event_or_fault(draft))
            .collect::<Result<Vec<_>, _>>()?;
        match self.store.append_audits(&events) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.fault("audit-commit-failed");
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use crate::handle::AuthorityConfig;
    use crate::secret::SecretInput;
    use std::time::{Duration, Instant};

    fn worker() -> (tempfile::TempDir, Worker) {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        crate::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(b"synthetic-proof"),
            crate::crypto::kdf::Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        crate::bootstrap::confirm_vault_init(&state).unwrap();
        let store = crate::store::SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
        let header = store.load_header().unwrap();
        let mut worker = Worker {
            #[cfg(feature = "lab")]
            keychain_fixture: None,
            desktop_resume_expiry: None,
            presence_grant: None,
            desktop_session: None,
            store,
            header,
            state: VaultState::Locked,
            failed_unlocks: 0,
            next_unlock_at: Instant::now(),
            last_activity: Instant::now(),
            retention_last_clock_ms: None,
            config: AuthorityConfig::new(state),
        };
        worker
            .unlock(UnlockProof::Password(SecretInput::from_slice(
                b"synthetic-proof",
            )))
            .unwrap();
        worker
            .audit_retention_set(
                rekey_domain::audit::AuditRetentionSet { days: Some(1) },
                UnlockProof::Password(SecretInput::from_slice(b"synthetic-proof")),
                None,
            )
            .unwrap();
        (dir, worker)
    }

    #[test]
    fn retention_clock_rollback_epoch_overflow_and_lock_preserve_highwater() {
        let (_dir, mut worker) = worker();
        let record = worker.retention_record().unwrap();
        let base = record.updated_at_ms;
        let deadline = || Instant::now() + Duration::from_secs(1);
        assert!(
            worker
                .retention_maintenance_at(record.clone(), base + 86_400_000, deadline())
                .unwrap()
                .is_some()
        );
        let before = worker
            .store
            .audit_query(&rekey_domain::audit::AuditQuery {
                request_id: None,
                session_id: None,
                action_id: None,
                credential_id: None,
                outcome: None,
                since_ms: None,
                until_ms: None,
                snapshot_max_sequence: None,
                before_sequence: None,
                limit: 100,
            })
            .unwrap()
            .snapshot_max_sequence;
        assert!(matches!(
            worker.retention_maintenance_at(record.clone(), base + 86_399_999, deadline()),
            Err(AuthorityError::ClockUnavailable)
        ));
        worker.lock("test").unwrap();
        assert_eq!(worker.retention_last_clock_ms, Some(base + 86_400_000));
        worker
            .unlock(UnlockProof::Password(SecretInput::from_slice(
                b"synthetic-proof",
            )))
            .unwrap();
        assert!(matches!(
            worker.retention_maintenance_at(record.clone(), base, deadline()),
            Err(AuthorityError::ClockUnavailable)
        ));
        worker.retention_last_clock_ms = None;
        let mut epoch_record = record.clone();
        epoch_record.updated_at_ms = 0;
        assert!(matches!(
            worker.retention_maintenance_at(epoch_record, 1, deadline()),
            Err(AuthorityError::ClockUnavailable)
        ));
        assert!(matches!(
            worker.retention_maintenance_at(record.clone(), base - 1, deadline()),
            Err(AuthorityError::ClockUnavailable)
        ));
        let mut overflow = record;
        overflow.days = Some(u64::MAX);
        assert!(matches!(
            worker.retention_maintenance_at(overflow, i64::MAX, deadline()),
            Err(AuthorityError::ClockUnavailable)
        ));
        let db = rusqlite::Connection::open(worker.store.path()).unwrap();
        let markers: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='audit.pruned'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(markers, 0);
        assert!(before > 0);
    }

    #[test]
    fn retention_seal_is_bound_to_root_vault_days_and_timestamp() {
        let (_dir, worker) = worker();
        let key = worker.require_unlocked().unwrap();
        let record = worker.store.load_audit_retention().unwrap();
        crate::crypto::policy_state::verify_retention(key.bytes(), worker.header.vault_id, &record)
            .unwrap();
        let mut changed = record.clone();
        changed.days = None;
        assert!(matches!(
            crate::crypto::policy_state::verify_retention(
                key.bytes(),
                worker.header.vault_id,
                &changed
            ),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        changed = record.clone();
        changed.updated_at_ms += 1;
        assert!(
            crate::crypto::policy_state::verify_retention(
                key.bytes(),
                worker.header.vault_id,
                &changed
            )
            .is_err()
        );
        assert!(
            crate::crypto::policy_state::verify_retention(
                key.bytes(),
                rekey_domain::ids::VaultId::new_random(),
                &record
            )
            .is_err()
        );
        let next = crate::crypto::keys::RootKey::generate().unwrap();
        assert!(
            crate::crypto::policy_state::verify_retention(
                next.bytes(),
                worker.header.vault_id,
                &record
            )
            .is_err()
        );
        let seal = crate::crypto::policy_state::seal_retention(
            next.bytes(),
            worker.header.vault_id,
            &record,
        )
        .unwrap();
        changed = record;
        changed.seal_nonce = seal.nonce;
        changed.seal_ciphertext = seal.ciphertext;
        crate::crypto::policy_state::verify_retention(
            next.bytes(),
            worker.header.vault_id,
            &changed,
        )
        .unwrap();
    }
    #[tokio::test]
    async fn retention_bounded_queue_full_and_late_dequeue_are_known_busy_without_prune() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        for late_dequeue in [false, true] {
            let (_dir, worker) = worker();
            let db = rusqlite::Connection::open(worker.store.path()).unwrap();
            let request = rekey_domain::ids::RequestId::new_random();
            for kind in ["execution.started", "execution.finished"] {
                db.execute("INSERT INTO audit_events(event_id,request_id,event_type,outcome,reason_code,created_at_ms) VALUES (?1,?2,?3,'success','queue-test',10)", rusqlite::params![rekey_domain::ids::RequestId::new_random().as_bytes().as_slice(), request.as_bytes().as_slice(), kind]).unwrap();
            }
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let handle = crate::handle::AuthorityHandle { tx };
            let join = std::thread::spawn(move || worker.run(rx));
            db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let mut blocked = Box::pin(handle.append_audit(unlock_audit(
                "fixture.blocked",
                outcome::SUCCESS,
                "queue-test",
            )));
            poll_fn(|cx| {
                assert!(blocked.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::time::timeout(Duration::from_secs(1), async {
                while handle.tx.capacity() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            if late_dequeue {
                let mut maintenance = Box::pin(handle.audit_retention_maintenance(deadline));
                poll_fn(|cx| {
                    assert!(maintenance.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                tokio::time::sleep(Duration::from_millis(1100)).await;
                db.execute_batch("COMMIT").unwrap();
                blocked.await.unwrap();
                assert!(matches!(
                    maintenance.await,
                    Err(AuthorityError::AuthorityBusy)
                ));
            } else {
                let mut status = Box::pin(handle.audit_retention_status());
                poll_fn(|cx| {
                    assert!(status.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(handle.tx.capacity(), 0);
                assert!(matches!(
                    handle.audit_retention_maintenance(deadline).await,
                    Err(AuthorityError::AuthorityBusy)
                ));
                db.execute_batch("COMMIT").unwrap();
                blocked.await.unwrap();
                status.await.unwrap();
            }
            assert_eq!(handle.status().await.unwrap().state, "unlocked");
            let rows: i64 = db
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE request_id=?1",
                    [request.as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            let markers: i64 = db
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='audit.pruned'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!((rows, markers), (2, 0));
            handle
                .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
                    b"synthetic-proof",
                ))))
                .await
                .unwrap();
            join.join().unwrap();
        }
    }
}
