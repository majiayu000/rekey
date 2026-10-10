//! The one generation commit boundary for administrative business transactions.
use std::time::Instant;

use rekey_domain::{ids::VaultId, ipc::RollbackContext};
use rusqlite::{Transaction, params};

use super::{
    SqliteRecordStore,
    sqlite::{commit_audited, storage},
};
use crate::{
    AuthorityError,
    generation_anchor::{AnchorObservation, GenerationAnchors},
    model::{AuditEvent, VaultHeaderRecord},
};

pub fn rollback_context(
    header: &VaultHeaderRecord,
    observed: AnchorObservation,
) -> RollbackContext {
    RollbackContext {
        vault_id: header.vault_id,
        source_generation: header.generation,
        high_water: observed.file.into_iter().chain(observed.protected).max(),
        history_missing: observed.file.is_none()
            || (observed.protected_required && observed.protected.is_none()),
    }
}

pub(crate) fn current(header: &VaultHeaderRecord, observed: AnchorObservation) -> bool {
    observed.file == Some(header.generation)
        && (!observed.protected_required || observed.protected == Some(header.generation))
}

/// Trusted store input: the caller has authenticated `header` and its existing
/// material. The next root is used only to derive a MAC and is never retained.
pub struct GenerationAttempt<'a> {
    pub(crate) anchors: &'a GenerationAnchors,
    pub(crate) observed: AnchorObservation,
    pub(crate) vault_id: VaultId,
    pub(crate) format_version: u32,
    pub(crate) prior_generation: u64,
    pub(crate) prior_mac: [u8; 32],
    pub(crate) prior_pki_digest: [u8; 32],
    pub(crate) pki_digest: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) mac: [u8; 32],
    pub(crate) not_after: Option<Instant>,
    pub(crate) wall_not_after_ms: Option<i64>,
    pub(crate) may_have_reserved: bool,
}
impl<'a> GenerationAttempt<'a> {
    pub fn new(
        anchors: &'a GenerationAnchors,
        header: &VaultHeaderRecord,
        observed: AnchorObservation,
        next_key: &[u8; 32],
        generation: u64,
        not_after: Option<Instant>,
        wall_not_after_ms: Option<i64>,
    ) -> Result<Self, AuthorityError> {
        if generation <= header.generation
            || observed
                .file
                .into_iter()
                .chain(observed.protected)
                .any(|g| generation <= g)
        {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(Self {
            anchors,
            observed,
            vault_id: header.vault_id,
            format_version: header.format_version,
            prior_generation: header.generation,
            prior_mac: header.generation_mac,
            prior_pki_digest: header.pki_digest,
            pki_digest: header.pki_digest,
            generation,
            mac: crate::crypto::generation::seal(
                next_key,
                header.vault_id,
                header.format_version,
                generation,
                &header.pki_digest,
            )?,
            not_after,
            wall_not_after_ms,
            may_have_reserved: false,
        })
    }

    /// Consumes the borrow before the Worker handles a result or changes state.
    pub(crate) fn finish(self) -> (u64, [u8; 32], bool, [u8; 32]) {
        (
            self.generation,
            self.mac,
            self.may_have_reserved,
            self.pki_digest,
        )
    }

    pub(crate) fn bind_pki_digest(
        &mut self,
        key: &[u8; 32],
        digest: [u8; 32],
    ) -> Result<(), AuthorityError> {
        self.mac = crate::crypto::generation::seal(
            key,
            self.vault_id,
            self.format_version,
            self.generation,
            &digest,
        )?;
        self.pki_digest = digest;
        Ok(())
    }

    fn check_deadline(&self) -> Result<(), AuthorityError> {
        crate::authority::ensure_mutation_current(self.not_after)?;
        if let Some(end) = self.wall_not_after_ms
            && crate::now_ms()? >= end
        {
            return Err(AuthorityError::PolicyVersionConflict);
        }
        Ok(())
    }
}

pub(super) fn commit_generation(
    tx: Transaction<'_>,
    attempt: &mut GenerationAttempt<'_>,
) -> Result<(), AuthorityError> {
    let changed = tx.execute(
        "UPDATE vault_header SET generation=?1,generation_mac=?2,pki_digest=?7 WHERE singleton=1 AND vault_id=?3 AND format_version=?4 AND generation=?5 AND generation_mac=?6 AND pki_digest=?8",
        params![attempt.generation.to_be_bytes().as_slice(), attempt.mac.as_slice(), attempt.vault_id.as_bytes().as_slice(), attempt.format_version, attempt.prior_generation.to_be_bytes().as_slice(), attempt.prior_mac.as_slice(), attempt.pki_digest.as_slice(), attempt.prior_pki_digest.as_slice()],
    ).map_err(storage)?;
    if changed != 1 {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    // Check after header UPDATE as well: a trigger must not alter either the
    // collection or the authenticated header between hashing and commit.
    let header_matches: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM vault_header WHERE singleton=1 AND vault_id=?1 AND format_version=?2 AND generation=?3 AND generation_mac=?4 AND pki_digest=?5)",
        params![attempt.vault_id.as_bytes().as_slice(), attempt.format_version, attempt.generation.to_be_bytes().as_slice(), attempt.mac.as_slice(), attempt.pki_digest.as_slice()],
        |r| r.get(0),
    ).map_err(storage)?;
    if !header_matches {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    super::pki::verified(&tx, &attempt.pki_digest)?;
    attempt.check_deadline()?;
    attempt.anchors.reserve(
        attempt.observed,
        attempt.generation,
        &mut attempt.may_have_reserved,
    )?;
    attempt.check_deadline()?;
    commit_audited(tx)
}

impl SqliteRecordStore {
    pub(crate) fn confirm_generation(
        &mut self,
        audit: AuditEvent,
        attempt: &mut GenerationAttempt<'_>,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        super::audit::insert(&tx, &audit)?;
        commit_generation(tx, attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap,
        crypto::{kdf::Argon2Params, keys::RootKey},
        model::{WrapperKind, event_type, outcome},
        secret::SecretInput,
    };

    fn fixture() -> (
        tempfile::TempDir,
        SqliteRecordStore,
        VaultHeaderRecord,
        RootKey,
        GenerationAnchors,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("source");
        let password = SecretInput::from_slice(b"generation-store-fixture");
        bootstrap::init_vault(
            &state,
            &password,
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        bootstrap::confirm_vault_init(&state).unwrap();
        let store = SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
        let header = store.load_header().unwrap();
        let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
        let root = bootstrap::unwrap_vrk(
            header.vault_id,
            &wrapper,
            &bootstrap::kek_for_wrapper(&wrapper, &password).unwrap(),
        )
        .unwrap();
        let anchors = GenerationAnchors::open(&state, header.vault_id).unwrap();
        (dir, store, header, root, anchors)
    }
    fn event() -> AuditEvent {
        AuditEvent {
            event_id: [0x78; 16],
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            request_context: None,
            usage: None,
            event_type: event_type::RESTORE_COMPLETED,
            outcome: outcome::SUCCESS,
            reason_code: "synthetic".into(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: 1,
        }
    }
    #[test]
    fn sql_header_work_expires_before_reservation_and_rolls_back_header_and_audit() {
        let (_dir, mut store, header, root, anchors) = fixture();
        let before = store.audit_event_types().unwrap();
        store.conn.execute_batch("CREATE TRIGGER slow_generation_header AFTER UPDATE OF generation ON vault_header BEGIN SELECT sum(value) FROM (WITH RECURSIVE counter(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM counter WHERE value<10000000) SELECT value FROM counter); END;").unwrap();
        let start = Instant::now();
        let mut attempt = GenerationAttempt::new(
            &anchors,
            &header,
            anchors.read().unwrap(),
            root.bytes(),
            2,
            Some(start + std::time::Duration::from_millis(100)),
            None,
        )
        .unwrap();
        assert!(matches!(
            store.confirm_generation(event(), &mut attempt),
            Err(AuthorityError::AuthorityBusy)
        ));
        assert!(start.elapsed() >= std::time::Duration::from_millis(100));
        assert!(!attempt.may_have_reserved);
        assert_eq!(store.load_header().unwrap().generation, 1);
        assert_eq!(anchors.read().unwrap().file, Some(1));
        assert_eq!(store.audit_event_types().unwrap(), before);
    }
    #[test]
    fn stale_observation_cannot_advance_or_commit_and_never_retries() {
        let (_dir, mut store, header, root, anchors) = fixture();
        let before = store.audit_event_types().unwrap();
        let mut attempt = GenerationAttempt::new(
            &anchors,
            &header,
            anchors.read().unwrap(),
            root.bytes(),
            2,
            None,
            None,
        )
        .unwrap();
        anchors
            .reserve(anchors.read().unwrap(), 3, &mut false)
            .unwrap();
        assert!(matches!(
            store.confirm_generation(event(), &mut attempt),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert!(!attempt.may_have_reserved);
        assert_eq!(anchors.read().unwrap().file, Some(3));
        assert_eq!(store.load_header().unwrap().generation, 1);
        assert_eq!(store.audit_event_types().unwrap(), before);
    }
    #[test]
    fn initial_commit_failure_reports_reserved_and_preserves_marker_and_anchor() {
        let (dir, source, header, root, _anchors) = fixture();
        let target = dir.path().join("initialization");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(
            crate::paths::init_incomplete(&target),
            b"rekey-init-incomplete-v1\n",
        )
        .unwrap();
        let mut store = SqliteRecordStore::create(&crate::paths::vault_db(&target)).unwrap();
        store.conn.execute_batch("CREATE TABLE deferred_failure (id BLOB REFERENCES credentials(credential_id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_initial_commit AFTER INSERT ON vault_header BEGIN INSERT INTO deferred_failure VALUES(zeroblob(16)); END;").unwrap();
        let anchors = GenerationAnchors::open(&target, header.vault_id).unwrap();
        let mut reserved = false;
        let wrappers = [
            source.active_wrapper(WrapperKind::Password).unwrap(),
            source.active_wrapper(WrapperKind::Recovery).unwrap(),
        ];
        let result = store.initialize(
            &header,
            &wrappers,
            &source
                .verified_policy_material(root.bytes(), header.vault_id)
                .unwrap()
                .state,
            &source
                .verified_audit_retention(root.bytes(), header.vault_id)
                .unwrap(),
            &crate::crypto::lease_journal::seal_state(root.bytes(), header.vault_id, &[], 0, None)
                .unwrap(),
            &crate::crypto::usage::seal(root.bytes(), header.vault_id, &[], 0).unwrap(),
            event(),
            &anchors,
            &mut reserved,
        );
        assert!(matches!(result, Err(AuthorityError::AuditCommitFailed)));
        assert!(reserved);
        assert_eq!(anchors.read().unwrap().file, Some(1));
        assert!(store.load_header().is_err());
        assert!(crate::paths::init_incomplete(&target).exists());
        assert!(matches!(
            bootstrap::discard_vault_files(&target),
            Err(AuthorityError::UnsupportedVaultLayout)
        ));
        assert!(matches!(
            bootstrap::init_vault(
                &target,
                &SecretInput::from_slice(b"other"),
                Argon2Params {
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1
                },
                rekey_domain::authorization::PolicyMode::Team
            ),
            Err(AuthorityError::StateDirectoryNotEmpty)
        ));
    }
}
