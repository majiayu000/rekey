//! Single-owner concrete journal commands. HTTP remains exclusively in Broker.
use super::{VaultState, Worker, ensure_mutation_current};
use crate::{
    command::AuditDraft,
    crypto::{
        aad::{AadPurpose, AadV1},
        aead, credential_state, lease_journal as crypto, random_array,
    },
    error::AuthorityError,
    model::{
        CredentialRecord, CredentialVersionRecord, LeaseCleanupOutcome, LeaseExecutionContext,
        LeaseJournalCounts, LeaseJournalRecord, LeaseJournalState, LeasePhase, LeaseReceipt,
        LeaseRecoveryBatch, LeaseSourceRef,
    },
    secret::{PreparedLeaseCleanup, SecretInput},
    store::SqliteRecordStore,
};
use rekey_domain::{
    credential::{CredentialKind, CredentialState, VersionState},
    ids::{LeaseRegistrationId, VaultId},
};
use serde::Deserialize;
use std::time::Instant;
use zeroize::Zeroizing;

fn invalid<T>() -> Result<T, AuthorityError> {
    Err(AuthorityError::StorageIntegrityFailed)
}
fn profile_source(bytes: &[u8]) -> Result<LeaseSourceRef, AuthorityError> {
    #[derive(Deserialize)]
    struct Source<'a> {
        credential_type: &'a str,
        origin: &'a str,
        mount: &'a str,
        role: &'a str,
    }
    let value: Source<'_> =
        serde_json::from_slice(bytes).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if value.credential_type != "vault-dynamic-source-v2" {
        return invalid();
    }
    let source = LeaseSourceRef {
        origin: rekey_domain::action::HttpsOrigin::parse(value.origin)
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
        mount: value.mount.to_owned(),
        role: value.role.to_owned(),
    };
    crypto::validate_source(&source)?;
    Ok(source)
}
fn historical(
    store: &SqliteRecordStore,
    root: &[u8; 32],
    vault: VaultId,
    row: &LeaseJournalRecord,
) -> Result<
    (
        CredentialRecord,
        CredentialVersionRecord,
        Zeroizing<Vec<u8>>,
    ),
    AuthorityError,
> {
    let credential =
        store
            .get_credential(row.context.credential_id)
            .map_err(|error| match error {
                AuthorityError::CredentialNotFound => AuthorityError::StorageIntegrityFailed,
                other => other,
            })?;
    credential_state::verify(root, vault, &credential)?;
    if credential.kind != CredentialKind::VaultDynamicSource {
        return invalid();
    }
    let version = store
        .get_version(credential.credential_id, row.context.credential_version)
        .map_err(|error| match error {
            AuthorityError::CredentialNotFound => AuthorityError::StorageIntegrityFailed,
            other => other,
        })?;
    if version.aad_version != crate::crypto::AAD_VERSION_V1
        || version.crypto_suite != crate::crypto::CRYPTO_SUITE_V1
    {
        return invalid();
    }
    let wrap = AadV1 {
        purpose: AadPurpose::WrapDek,
        vault_id: vault,
        object_id: *credential.credential_id.as_bytes(),
        object_version: version.version,
        credential_kind: 0,
        constraints_hash: [0; 32],
    }
    .encode();
    let dek = aead::open(root, &wrap, &version.dek_nonce, &version.wrapped_dek)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let key = Zeroizing::new(
        <[u8; 32]>::try_from(dek.as_slice()).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
    );
    let payload = AadV1 {
        purpose: AadPurpose::CredentialPayload,
        vault_id: vault,
        object_id: *credential.credential_id.as_bytes(),
        object_version: version.version,
        credential_kind: credential.kind.aad_code(),
        constraints_hash: [0; 32],
    }
    .encode();
    let bytes = aead::open(
        &key,
        &payload,
        &version.payload_nonce,
        &version.encrypted_payload,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if crypto::source_hash(&profile_source(&bytes)?)? != row.source_ref_hash {
        return invalid();
    }
    Ok((credential, version, bytes))
}
pub(crate) fn verify_store(
    store: &SqliteRecordStore,
    root: &[u8; 32],
    vault: VaultId,
) -> Result<Vec<LeaseJournalRecord>, AuthorityError> {
    store.validate_credential_version_invariants()?;
    store.foreign_key_check()?;
    let records = store.list_lease_records()?;
    let state = store.load_lease_state()?;
    crypto::verify_state(root, vault, &records, &state)?;
    if state.last_audit_event_id != store.latest_lease_audit_id()? {
        return invalid();
    }
    for row in &records {
        crypto::open(root, vault, row)?;
        historical(store, root, vault, row)?;
    }
    Ok(records)
}
impl Worker {
    fn journal_result<T>(
        &mut self,
        result: Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }
    fn verified_journal(&self) -> Result<Vec<LeaseJournalRecord>, AuthorityError> {
        verify_store(
            &self.store,
            self.require_unlocked()?.bytes(),
            self.header.vault_id,
        )
    }
    fn journal_audit(
        &mut self,
        row: &LeaseJournalRecord,
        event_type: &'static str,
        success: bool,
    ) -> Result<crate::model::AuditEvent, AuthorityError> {
        let c = &row.context;
        self.audit_event_or_fault(AuditDraft {
            request_id: Some(c.request_id),
            session_id: Some(c.session_id),
            action_id: Some(c.action_id),
            action_version: Some(c.action_version),
            credential_id: Some(c.credential_id),
            credential_version: Some(c.credential_version),
            authorization: None,
            approval: None,
            event_type,
            outcome: if success { "success" } else { "unconfirmed" },
            reason_code: "lease-journal".to_owned(),
            upstream_status: None,
            latency_ms: None,
        })
    }
    pub(super) fn lease_begin(
        &mut self,
        context: LeaseExecutionContext,
        source: LeaseSourceRef,
        not_after: Option<Instant>,
    ) -> Result<LeaseReceipt, AuthorityError> {
        let result = (|| {
            ensure_mutation_current(not_after)?;
            let mut records = self.verified_journal()?;
            let now = crate::now_ms()?;
            let mut row = LeaseJournalRecord {
                registration_id: LeaseRegistrationId::from_random_bytes(random_array()?),
                context,
                source_ref_hash: crypto::source_hash(&source)?,
                revision: 1,
                phase: LeasePhase::AcquireIntent,
                created_at_ms: now,
                updated_at_ms: now,
                issued_at_ms: None,
                last_confirmed_expires_at_ms: None,
                renewable: None,
                cleanup_outcome: LeaseCleanupOutcome::None,
                completed_at_ms: None,
                last_audit_event_id: [0; 16],
                aad_version: crate::crypto::AAD_VERSION_V1,
                crypto_suite: crate::crypto::CRYPTO_SUITE_V1.to_owned(),
                dek_nonce: [0; 12],
                wrapped_dek: Vec::new(),
                payload_nonce: [0; 12],
                encrypted_payload: Vec::new(),
            };
            if records.iter().any(|existing| {
                existing.source_ref_hash == row.source_ref_hash
                    && existing.phase != LeasePhase::Complete
            }) {
                return Err(AuthorityError::AuthorityBusy);
            }
            let (credential, version, _) = historical(
                &self.store,
                self.require_unlocked()?.bytes(),
                self.header.vault_id,
                &row,
            )?;
            if credential.state != CredentialState::Active
                || credential.current_version != row.context.credential_version
                || version.state != VersionState::Active
            {
                return Err(AuthorityError::CredentialRevoked);
            }
            let audit = self.journal_audit(&row, "vault.lease.acquire_intent", true)?;
            row.last_audit_event_id = audit.event_id;
            crypto::seal_new(
                self.require_unlocked()?.bytes(),
                self.header.vault_id,
                &mut row,
                &crypto::LeasePayload {
                    source,
                    lease_id: None,
                },
            )?;
            records.push(row.clone());
            let state = crypto::seal_state(
                self.require_unlocked()?.bytes(),
                self.header.vault_id,
                &records,
                self.store
                    .load_lease_state()?
                    .revision
                    .checked_add(1)
                    .ok_or(AuthorityError::StorageIntegrityFailed)?,
                Some(audit.event_id),
            )?;
            self.store
                .commit_lease(&row, &state, &audit, true, not_after)?;
            Ok(row.receipt())
        })();
        self.journal_result(result)
    }
    fn lease_change(
        &mut self,
        id: LeaseRegistrationId,
        change: LeaseChange,
        not_after: Option<Instant>,
    ) -> Result<LeaseReceipt, AuthorityError> {
        ensure_mutation_current(not_after)?;
        let mut rows = self.verified_journal()?;
        let index = rows
            .iter()
            .position(|r| r.registration_id == id)
            .ok_or(AuthorityError::CredentialNotFound)?;
        let old = rows[index].clone();
        let mut payload =
            crypto::open(self.require_unlocked()?.bytes(), self.header.vault_id, &old)?;
        let mut row = old.clone();
        row.revision = row
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::StorageIntegrityFailed)?;
        row.updated_at_ms = crate::now_ms()?;
        let (event, success) = match change {
            LeaseChange::Issued {
                lease_id,
                request_started_at_ms,
                actual_ttl_seconds,
                renewable,
            } => {
                if row.phase != LeasePhase::AcquireIntent
                    || request_started_at_ms < row.created_at_ms
                    || request_started_at_ms > row.updated_at_ms
                    || !(5..=300).contains(&actual_ttl_seconds)
                {
                    return Err(AuthorityError::Domain(
                        rekey_domain::DomainError::InvalidActionDefinition(
                            "invalid lease issuance".into(),
                        ),
                    ));
                }
                row.phase = LeasePhase::Issued;
                row.issued_at_ms = Some(request_started_at_ms);
                row.last_confirmed_expires_at_ms = Some(
                    request_started_at_ms
                        .checked_add((actual_ttl_seconds * 1000) as i64)
                        .ok_or(AuthorityError::ClockUnavailable)?,
                );
                row.renewable = Some(renewable);
                payload.lease_id = Some(Zeroizing::new(lease_id.expose().to_vec()));
                ("vault.lease.issued", true)
            }
            LeaseChange::AbortDefinite => {
                if row.phase != LeasePhase::AcquireIntent {
                    return invalid();
                }
                row.phase = LeasePhase::Complete;
                row.completed_at_ms = Some(row.updated_at_ms);
                ("vault.lease.acquire_aborted", true)
            }
            LeaseChange::RenewBegin => {
                if row.phase != LeasePhase::Issued || row.renewable != Some(true) {
                    return invalid();
                }
                row.phase = LeasePhase::Renewing;
                ("vault.lease.renewal_started", true)
            }
            LeaseChange::RenewResult {
                request_started_at_ms,
                actual_ttl_seconds,
                renewable,
            } => {
                if row.phase != LeasePhase::Renewing {
                    return invalid();
                }
                row.phase = LeasePhase::Issued;
                if let Some(ttl) = actual_ttl_seconds {
                    if !(5..=300).contains(&ttl)
                        || request_started_at_ms < old.updated_at_ms
                        || request_started_at_ms > row.updated_at_ms
                    {
                        return invalid();
                    }
                    row.last_confirmed_expires_at_ms = Some(
                        request_started_at_ms
                            .checked_add((ttl * 1000) as i64)
                            .ok_or(AuthorityError::ClockUnavailable)?,
                    );
                    row.renewable = Some(renewable);
                    ("vault.lease.renewed", true)
                } else {
                    row.cleanup_outcome = LeaseCleanupOutcome::Unconfirmed;
                    ("vault.lease.renewal_unconfirmed", false)
                }
            }
            LeaseChange::CleanupBegin => {
                if !matches!(
                    row.phase,
                    LeasePhase::Issued | LeasePhase::Renewing | LeasePhase::CleanupStarted
                ) {
                    return invalid();
                }
                row.phase = LeasePhase::CleanupStarted;
                row.cleanup_outcome = LeaseCleanupOutcome::Unconfirmed;
                ("vault.lease.cleanup_started", true)
            }
            LeaseChange::CleanupFinish { confirmed } => {
                if row.phase != LeasePhase::CleanupStarted {
                    return invalid();
                }
                if confirmed {
                    row.phase = LeasePhase::Complete;
                    row.cleanup_outcome = LeaseCleanupOutcome::Confirmed;
                    row.completed_at_ms = Some(row.updated_at_ms);
                    payload.lease_id = None;
                    ("vault.lease.revoked", true)
                } else {
                    row.cleanup_outcome = LeaseCleanupOutcome::Unconfirmed;
                    ("vault.lease.revoke_unconfirmed", false)
                }
            }
        };
        let audit = self.journal_audit(&row, event, success)?;
        row.last_audit_event_id = audit.event_id;
        crypto::update(
            self.require_unlocked()?.bytes(),
            self.header.vault_id,
            &old,
            &mut row,
            &payload,
        )?;
        rows[index] = row.clone();
        let state = crypto::seal_state(
            self.require_unlocked()?.bytes(),
            self.header.vault_id,
            &rows,
            self.store
                .load_lease_state()?
                .revision
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            Some(audit.event_id),
        )?;
        self.store
            .commit_lease(&row, &state, &audit, false, not_after)?;
        Ok(row.receipt())
    }
    pub(super) fn lease_update(
        &mut self,
        id: LeaseRegistrationId,
        change: LeaseChange,
        not_after: Option<Instant>,
    ) -> Result<LeaseReceipt, AuthorityError> {
        let result = self.lease_change(id, change, not_after);
        self.journal_result(result)
    }
    pub(super) fn lease_cleanup_prepare(
        &mut self,
        id: LeaseRegistrationId,
        not_after: Option<Instant>,
    ) -> Result<PreparedLeaseCleanup, AuthorityError> {
        let result = (|| {
            ensure_mutation_current(not_after)?;
            let rows = self.verified_journal()?;
            let row = rows
                .iter()
                .find(|r| r.registration_id == id)
                .ok_or(AuthorityError::CredentialNotFound)?;
            if !matches!(
                row.phase,
                LeasePhase::Issued | LeasePhase::Renewing | LeasePhase::CleanupStarted
            ) {
                return Err(AuthorityError::AuthorityBusy);
            }
            let payload =
                crypto::open(self.require_unlocked()?.bytes(), self.header.vault_id, row)?;
            let (_, _, profile) = historical(
                &self.store,
                self.require_unlocked()?.bytes(),
                self.header.vault_id,
                row,
            )?;
            let lease_id = payload
                .lease_id
                .ok_or(AuthorityError::StorageIntegrityFailed)?;
            let receipt = self.lease_change(id, LeaseChange::CleanupBegin, not_after)?;
            Ok(PreparedLeaseCleanup::new(profile, lease_id, receipt))
        })();
        self.journal_result(result)
    }
    pub(super) fn lease_batch(&mut self) -> Result<LeaseRecoveryBatch, AuthorityError> {
        let result = (|| {
            if let Some(unavailable) = match self.state {
                VaultState::Locked => Some(AuthorityError::Locked),
                VaultState::Faulted => Some(AuthorityError::Faulted),
                VaultState::Unlocked { .. } => None,
            } {
                return Ok(LeaseRecoveryBatch {
                    unavailable: Some(unavailable),
                    counts: self.store.lease_counts_unverified()?,
                    known: Vec::new(),
                });
            }
            let mut rows = self.verified_journal()?;
            rows.sort_by_key(|r| (r.updated_at_ms, *r.registration_id.as_bytes()));
            let counts = LeaseJournalCounts {
                verified: true,
                pending: rows
                    .iter()
                    .filter(|r| r.phase != LeasePhase::Complete)
                    .count() as u64,
                unknown: rows
                    .iter()
                    .filter(|r| r.phase == LeasePhase::AcquireIntent)
                    .count() as u64,
                complete: rows
                    .iter()
                    .filter(|r| r.phase == LeasePhase::Complete)
                    .count() as u64,
            };
            let known = rows
                .iter()
                .filter(|r| {
                    matches!(
                        r.phase,
                        LeasePhase::Issued | LeasePhase::Renewing | LeasePhase::CleanupStarted
                    )
                })
                .take(8)
                .map(|r| r.receipt())
                .collect();
            Ok(LeaseRecoveryBatch {
                unavailable: None,
                counts,
                known,
            })
        })();
        self.journal_result(result)
    }
    pub(super) fn rotated_journal(
        &self,
        old_root: &[u8; 32],
        new_root: &[u8; 32],
        not_after: Option<Instant>,
    ) -> Result<(Vec<LeaseJournalRecord>, LeaseJournalState), AuthorityError> {
        let mut rows = verify_store(&self.store, old_root, self.header.vault_id)?;
        for row in &mut rows {
            ensure_mutation_current(not_after)?;
            let payload = crypto::open(old_root, self.header.vault_id, row)?;
            crypto::seal_new(new_root, self.header.vault_id, row, &payload)?;
        }
        let state = crypto::seal_state(
            new_root,
            self.header.vault_id,
            &rows,
            self.store
                .load_lease_state()?
                .revision
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            self.store.load_lease_state()?.last_audit_event_id,
        )?;
        Ok((rows, state))
    }
}
pub(crate) enum LeaseChange {
    Issued {
        lease_id: SecretInput,
        request_started_at_ms: i64,
        actual_ttl_seconds: u64,
        renewable: bool,
    },
    AbortDefinite,
    RenewBegin,
    RenewResult {
        request_started_at_ms: i64,
        actual_ttl_seconds: Option<u64>,
        renewable: bool,
    },
    CleanupBegin,
    CleanupFinish {
        confirmed: bool,
    },
}
