use super::{
    SqliteRecordStore,
    sqlite::{blob12, blob16, blob32, commit_audited, storage},
};
use crate::{
    error::AuthorityError,
    model::{
        AuditEvent, LeaseCleanupOutcome, LeaseExecutionContext, LeaseJournalCounts,
        LeaseJournalRecord, LeaseJournalState, LeasePhase,
    },
};
use rekey_domain::ids::{ActionId, CredentialId, LeaseRegistrationId, RequestId, SessionId};
use rusqlite::{OptionalExtension, Transaction, params};
use std::time::Instant;

const COLUMNS: &str = "registration_id,execution_request_id,session_id,action_id,action_version,credential_id,credential_version,source_ref_hash,revision,phase,created_at_ms,updated_at_ms,issued_at_ms,last_confirmed_expires_at_ms,renewable,cleanup_outcome,completed_at_ms,last_audit_event_id,aad_version,crypto_suite,dek_nonce,wrapped_dek,payload_nonce,encrypted_payload";
fn corrupt<T>() -> Result<T, AuthorityError> {
    Err(AuthorityError::StorageIntegrityFailed)
}
fn blob<const N: usize>(r: &rusqlite::Row<'_>, index: usize) -> Result<[u8; N], AuthorityError> {
    r.get::<_, Vec<u8>>(index)
        .map_err(storage)?
        .try_into()
        .map_err(|_| AuthorityError::StorageIntegrityFailed)
}
fn one(changed: usize) -> Result<(), AuthorityError> {
    if changed != 1 { corrupt() } else { Ok(()) }
}
pub(super) fn initial_state(
    tx: &Transaction<'_>,
    state: &LeaseJournalState,
) -> Result<(), AuthorityError> {
    one(tx
        .execute(
            "INSERT INTO vault_lease_journal_state(singleton,revision,record_count,records_digest,seal_nonce,seal_ciphertext,last_audit_event_id) VALUES(1,?1,?2,?3,?4,?5,?6)",
            params![
                state.revision as i64,
                state.record_count as i64,
                state.records_digest.as_slice(),
                state.seal_nonce.as_slice(),
                state.seal_ciphertext.as_slice(),
                state.last_audit_event_id.as_ref().map(|id|id.as_slice())
            ],
        )
        .map_err(storage)?)
}
pub(super) fn replace_state(
    tx: &Transaction<'_>,
    state: &LeaseJournalState,
) -> Result<(), AuthorityError> {
    one(tx.execute("UPDATE vault_lease_journal_state SET revision=?1,record_count=?2,records_digest=?3,seal_nonce=?4,seal_ciphertext=?5,last_audit_event_id=?6 WHERE singleton=1",params![state.revision as i64,state.record_count as i64,state.records_digest.as_slice(),state.seal_nonce.as_slice(),state.seal_ciphertext.as_slice(),state.last_audit_event_id.as_ref().map(|id|id.as_slice())]).map_err(storage)?)
}
fn write(tx: &Transaction<'_>, r: &LeaseJournalRecord, insert: bool) -> Result<(), AuthorityError> {
    let query = if insert {
        format!(
            "INSERT INTO vault_lease_journal({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)"
        )
    } else {
        "UPDATE vault_lease_journal SET execution_request_id=?2,session_id=?3,action_id=?4,action_version=?5,credential_id=?6,credential_version=?7,source_ref_hash=?8,revision=?9,phase=?10,created_at_ms=?11,updated_at_ms=?12,issued_at_ms=?13,last_confirmed_expires_at_ms=?14,renewable=?15,cleanup_outcome=?16,completed_at_ms=?17,last_audit_event_id=?18,aad_version=?19,crypto_suite=?20,dek_nonce=?21,wrapped_dek=?22,payload_nonce=?23,encrypted_payload=?24 WHERE registration_id=?1".to_owned()
    };
    let c = &r.context;
    one(tx
        .execute(
            &query,
            params![
                r.registration_id.as_bytes().as_slice(),
                c.request_id.as_bytes().as_slice(),
                c.session_id.as_bytes().as_slice(),
                c.action_id.as_bytes().as_slice(),
                c.action_version as i64,
                c.credential_id.as_bytes().as_slice(),
                c.credential_version as i64,
                r.source_ref_hash.as_slice(),
                r.revision as i64,
                r.phase.as_str(),
                r.created_at_ms,
                r.updated_at_ms,
                r.issued_at_ms,
                r.last_confirmed_expires_at_ms,
                r.renewable.map(i64::from),
                r.cleanup_outcome.as_str(),
                r.completed_at_ms,
                r.last_audit_event_id.as_slice(),
                r.aad_version,
                r.crypto_suite,
                r.dek_nonce.as_slice(),
                r.wrapped_dek,
                r.payload_nonce.as_slice(),
                r.encrypted_payload
            ],
        )
        .map_err(storage)?)
}
pub(super) fn replace_ciphertexts(
    tx: &Transaction<'_>,
    rows: &[LeaseJournalRecord],
    state: &LeaseJournalState,
) -> Result<(), AuthorityError> {
    for row in rows {
        write(tx, row, false)?;
    }
    replace_state(tx, state)
}
impl SqliteRecordStore {
    pub fn list_lease_records(&self) -> Result<Vec<LeaseJournalRecord>, AuthorityError> {
        let mut statement = self
            .conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM vault_lease_journal ORDER BY registration_id"
            ))
            .map_err(storage)?;
        let mut rows = statement.query([]).map_err(storage)?;
        let mut result = Vec::new();
        while let Some(r) = rows.next().map_err(storage)? {
            let id_error = |_| AuthorityError::StorageIntegrityFailed;
            let positive = |index| -> Result<u64, AuthorityError> {
                let n = r.get::<_, i64>(index).map_err(storage)?;
                if n <= 0 {
                    return corrupt();
                }
                Ok(n as u64)
            };
            let phase = LeasePhase::parse(&r.get::<_, String>(9).map_err(storage)?)
                .ok_or(AuthorityError::StorageIntegrityFailed)?;
            let cleanup_outcome =
                LeaseCleanupOutcome::parse(&r.get::<_, String>(15).map_err(storage)?)
                    .ok_or(AuthorityError::StorageIntegrityFailed)?;
            let renewable = match r.get::<_, Option<i64>>(14).map_err(storage)? {
                None => None,
                Some(0) => Some(false),
                Some(1) => Some(true),
                _ => return corrupt(),
            };
            let record = LeaseJournalRecord {
                registration_id: LeaseRegistrationId::from_bytes(blob(r, 0)?).map_err(id_error)?,
                context: LeaseExecutionContext {
                    request_id: RequestId::from_bytes(blob(r, 1)?).map_err(id_error)?,
                    session_id: SessionId::from_bytes(blob(r, 2)?).map_err(id_error)?,
                    action_id: ActionId::from_bytes(blob(r, 3)?).map_err(id_error)?,
                    action_version: positive(4)?,
                    credential_id: CredentialId::from_bytes(blob(r, 5)?).map_err(id_error)?,
                    credential_version: positive(6)?,
                },
                source_ref_hash: blob(r, 7)?,
                revision: positive(8)?,
                phase,
                created_at_ms: r.get(10).map_err(storage)?,
                updated_at_ms: r.get(11).map_err(storage)?,
                issued_at_ms: r.get(12).map_err(storage)?,
                last_confirmed_expires_at_ms: r.get(13).map_err(storage)?,
                renewable,
                cleanup_outcome,
                completed_at_ms: r.get(16).map_err(storage)?,
                last_audit_event_id: blob(r, 17)?,
                aad_version: r.get(18).map_err(storage)?,
                crypto_suite: r.get(19).map_err(storage)?,
                dek_nonce: blob(r, 20)?,
                wrapped_dek: r.get(21).map_err(storage)?,
                payload_nonce: blob(r, 22)?,
                encrypted_payload: r.get(23).map_err(storage)?,
            };
            crate::crypto::lease_journal::metadata(&record)?;
            if record.wrapped_dek.len() != 48
                || !(16..=8192).contains(&record.encrypted_payload.len())
            {
                return corrupt();
            }
            result.push(record);
        }
        Ok(result)
    }
    pub fn load_lease_state(&self) -> Result<LeaseJournalState, AuthorityError> {
        let (revision, count, digest, nonce, cipher, anchor) = self.conn.query_row(
            "SELECT revision,record_count,records_digest,seal_nonce,seal_ciphertext,last_audit_event_id FROM vault_lease_journal_state WHERE singleton=1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?, r.get::<_, Vec<u8>>(4)?, r.get::<_, Option<Vec<u8>>>(5)?)),
        ).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if revision < 0 || count < 0 {
            return corrupt();
        }
        Ok(LeaseJournalState {
            revision: revision as u64,
            record_count: count as u64,
            records_digest: blob32(digest)?,
            seal_nonce: blob12(nonce)?,
            seal_ciphertext: blob16(cipher)?,
            last_audit_event_id: anchor.map(blob16).transpose()?,
        })
    }
    pub(crate) fn latest_lease_audit_id(&self) -> Result<Option<[u8; 16]>, AuthorityError> {
        self.conn.query_row("SELECT event_id FROM audit_events WHERE event_type GLOB 'vault.lease.*' ORDER BY sequence DESC LIMIT 1",[],|r|r.get::<_,Vec<u8>>(0)).optional().map_err(storage)?.map(blob16).transpose()
    }
    pub(crate) fn lease_counts_unverified(&self) -> Result<LeaseJournalCounts, AuthorityError> {
        let (pending,unknown,complete):(i64,i64,i64)=self.conn.query_row("SELECT coalesce(sum(phase!='complete'),0),coalesce(sum(phase='acquire_intent'),0),coalesce(sum(phase='complete'),0) FROM vault_lease_journal",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(storage)?;
        Ok(LeaseJournalCounts {
            verified: false,
            pending: pending as u64,
            unknown: unknown as u64,
            complete: complete as u64,
        })
    }
    pub(crate) fn commit_lease(
        &mut self,
        row: &LeaseJournalRecord,
        state: &LeaseJournalState,
        audit: &AuditEvent,
        insert: bool,
        not_after: Option<Instant>,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        if insert {
            let c = &row.context;
            let started: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM audit_events WHERE request_id=?1 AND session_id=?2 AND action_id=?3 AND action_version=?4 AND credential_id=?5 AND (credential_version IS NULL OR credential_version=?6) AND event_type='execution.started' AND outcome='success')", params![c.request_id.as_bytes().as_slice(), c.session_id.as_bytes().as_slice(), c.action_id.as_bytes().as_slice(), c.action_version as i64, c.credential_id.as_bytes().as_slice(), c.credential_version as i64], |r| r.get(0)).map_err(storage)?;
            if !started {
                return Err(AuthorityError::Domain(
                    rekey_domain::DomainError::InvalidActionDefinition(
                        "lease acquire requires committed execution.started".into(),
                    ),
                ));
            }
            let pending:i64=tx.query_row("SELECT count(*) FROM vault_lease_journal WHERE source_ref_hash=?1 AND phase!='complete'",params![row.source_ref_hash.as_slice()],|r|r.get(0)).map_err(storage)?;
            if pending != 0 {
                return Err(AuthorityError::AuthorityBusy);
            }
        }
        super::audit::insert(&tx, audit)?;
        write(&tx, row, insert)?;
        replace_state(&tx, state)?;
        if not_after.is_some_and(|v| Instant::now() >= v) {
            return Err(AuthorityError::AuthorityBusy);
        }
        commit_audited(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn journal_expiry_at_commit_rolls_back_row_audit_and_manifest_after_all_writes() {
        use crate::{
            bootstrap::{confirm_vault_init, init_vault},
            command::UnlockProof,
            crypto::kdf::Argon2Params,
            handle::AuthorityConfig,
            secret::SecretInput,
        };
        use rekey_domain::credential::{CredentialKind, CredentialLabel};
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let proof = || UnlockProof::Password(SecretInput::from_slice(b"fixture-password"));
        init_vault(
            &state_dir,
            &SecretInput::from_slice(b"fixture-password"),
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        confirm_vault_init(&state_dir).unwrap();
        let (handle, join) =
            crate::authority::spawn_authority(AuthorityConfig::new(state_dir.clone())).unwrap();
        handle.unlock(proof()).await.unwrap();
        let credential = handle
            .credential_add(
                CredentialLabel::new("commit-boundary").unwrap(),
                CredentialKind::VaultDynamicSource,
                SecretInput::from_slice(b"fixture-only-ciphertext"),
                proof(),
            )
            .await
            .unwrap();
        handle.shutdown(Some(proof())).await.unwrap();
        join.join().unwrap();
        let mut store = SqliteRecordStore::open(&crate::paths::vault_db(&state_dir)).unwrap();
        let before = store.load_lease_state().unwrap();
        let context = LeaseExecutionContext {
            request_id: RequestId::new_random(),
            session_id: SessionId::new_random(),
            action_id: ActionId::new_random(),
            action_version: 1,
            credential_id: credential.id,
            credential_version: 1,
        };
        let mut audit = AuditEvent {
            event_id: crate::crypto::random_array().unwrap(),
            request_id: Some(context.request_id),
            session_id: Some(context.session_id),
            action_id: Some(context.action_id),
            action_version: Some(1),
            credential_id: Some(credential.id),
            credential_version: None,
            authorization: None,
            approval: None,
            request_context: None,
            usage: None,
            event_type: "execution.started",
            outcome: "success",
            reason_code: "fixture".into(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: crate::now_ms().unwrap(),
        };
        store.append_audit(&audit).unwrap();
        audit.event_id = crate::crypto::random_array().unwrap();
        audit.credential_version = Some(1);
        audit.event_type = "vault.lease.acquire_intent";
        // Deliberately target the SQL commit boundary with structurally valid,
        // opaque ciphertext. Cryptographic admission is exercised by Authority tests.
        let row = LeaseJournalRecord {
            registration_id: LeaseRegistrationId::new_random(),
            context,
            source_ref_hash: [1; 32],
            revision: 1,
            phase: LeasePhase::AcquireIntent,
            created_at_ms: audit.created_at_ms,
            updated_at_ms: audit.created_at_ms,
            issued_at_ms: None,
            last_confirmed_expires_at_ms: None,
            renewable: None,
            cleanup_outcome: LeaseCleanupOutcome::None,
            completed_at_ms: None,
            last_audit_event_id: audit.event_id,
            aad_version: 1,
            crypto_suite: crate::crypto::CRYPTO_SUITE_V1.into(),
            dek_nonce: [1; 12],
            wrapped_dek: vec![1; 48],
            payload_nonce: [1; 12],
            encrypted_payload: vec![1; 16],
        };
        let mut manifest = before.clone();
        manifest.revision += 1;
        manifest.record_count = 1;
        manifest.last_audit_event_id = Some(audit.event_id);
        manifest.records_digest = [2; 32];
        store.conn.execute_batch("CREATE TRIGGER assert_every_journal_write BEFORE UPDATE ON vault_lease_journal_state BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM vault_lease_journal j JOIN audit_events a ON a.event_id=j.last_audit_event_id WHERE a.event_type='vault.lease.acquire_intent') AND NEW.record_count=1 THEN 1 ELSE RAISE(ABORT,'writes not reached') END; END;").unwrap();
        assert!(matches!(
            store.commit_lease(&row, &manifest, &audit, true, Some(Instant::now())),
            Err(AuthorityError::AuthorityBusy)
        ));
        assert!(store.list_lease_records().unwrap().is_empty());
        let after = store.load_lease_state().unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.record_count, before.record_count);
        assert_eq!(after.records_digest, before.records_digest);
        assert_eq!(after.seal_ciphertext, before.seal_ciphertext);
        assert_eq!(after.last_audit_event_id, before.last_audit_event_id);
        assert!(
            !store
                .audit_event_types()
                .unwrap()
                .iter()
                .any(|event| event == "vault.lease.acquire_intent")
        );
    }
}
