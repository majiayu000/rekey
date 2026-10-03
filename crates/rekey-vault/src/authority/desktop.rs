use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{VaultState, Worker, ensure_mutation_current, unlock_audit};
use crate::command::UnlockProof;
use crate::crypto::{aead, keys::RootKey, random_array};
use crate::error::AuthorityError;
use crate::model::outcome;
use crate::secret::SecretInput;

const FILE: &str = "desktop-unlock.bin";
const ACTIVE: &str = ".desktop-runtime-active";

pub(super) fn begin_runtime(state: &std::path::Path) -> Result<(), AuthorityError> {
    let marker = state.join(ACTIVE);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            match fs::remove_file(state.join(FILE)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(AuthorityError::storage(e)),
            }
            // Keep the existing crash marker throughout recovery. The ticket
            // deletion must be durable before any later clean stop clears it.
            return crate::durable::fsync(state).map_err(AuthorityError::storage);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(AuthorityError::storage(e)),
    }
    crate::durable::create_new_file(&marker)
        .map_err(AuthorityError::storage)?
        .sync_all()
        .map_err(AuthorityError::storage)?;
    crate::durable::fsync(state).map_err(AuthorityError::storage)
}

pub fn finish_runtime(state: &std::path::Path) -> Result<(), AuthorityError> {
    fs::remove_file(state.join(ACTIVE)).map_err(AuthorityError::storage)?;
    if let Err(error) = crate::durable::fsync(state) {
        match fs::remove_file(state.join(FILE)) {
            Ok(()) => crate::durable::fsync(state).map_err(AuthorityError::storage)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AuthorityError::storage(e)),
        }
        return Err(AuthorityError::storage(error));
    }
    Ok(())
}
const MAGIC: &[u8; 8] = b"RKDSK001";
const LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1000;

// The verifier is authority material, even though the original bearer key is not retained.
// Do not derive Debug or persist this value.
pub(super) struct PresenceGrant {
    key_hash: Zeroizing<[u8; 32]>,
    issued_at_ms: i64,
    expires_at_ms: i64,
    monotonic_deadline: Instant,
}

// DeadlineOnly retains only a same-ticket lifetime constraint, never proof authority.
// Both states own the same single grant record; there is no second verifier ledger.
pub(super) enum PresenceState {
    Active(PresenceGrant),
    DeadlineOnly(PresenceGrant),
}

impl PresenceState {
    fn grant(&self) -> &PresenceGrant {
        match self {
            Self::Active(grant) | Self::DeadlineOnly(grant) => grant,
        }
    }

    fn into_grant(self) -> PresenceGrant {
        match self {
            Self::Active(grant) | Self::DeadlineOnly(grant) => grant,
        }
    }
}

fn decode_presence_key(input: &[u8]) -> Result<Zeroizing<[u8; 32]>, AuthorityError> {
    if input.len() != 64
        || !input
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AuthorityError::InvalidUnlockCredential);
    }
    let mut key = Zeroizing::new([0; 32]);
    data_encoding::HEXLOWER
        .decode_mut(input, key.as_mut())
        .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
    Ok(key)
}

impl PresenceGrant {
    fn new(key: &[u8; 32], issued: i64, expires: i64) -> Result<Self, AuthorityError> {
        let now = crate::now_ms()?;
        if expires.checked_sub(issued) != Some(LIFETIME_MS) || now < issued || now >= expires {
            return Err(AuthorityError::InvalidUnlockCredential);
        }
        let monotonic_deadline = Instant::now()
            .checked_add(Duration::from_millis((expires - now) as u64))
            .ok_or(AuthorityError::ClockUnavailable)?;
        Ok(Self {
            key_hash: Zeroizing::new(Sha256::digest(key).into()),
            issued_at_ms: issued,
            expires_at_ms: expires,
            monotonic_deadline,
        })
    }

    fn cap_to_same_ticket(&mut self, previous: &Self) {
        if self.issued_at_ms == previous.issued_at_ms
            && self.expires_at_ms == previous.expires_at_ms
            && bool::from(self.key_hash.as_ref().ct_eq(previous.key_hash.as_ref()))
        {
            self.monotonic_deadline = self.monotonic_deadline.min(previous.monotonic_deadline);
        }
    }

    fn verify_at(
        &self,
        key: &[u8; 32],
        wall: i64,
        monotonic: Instant,
    ) -> Result<(), AuthorityError> {
        let candidate: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(key).into());
        if wall < self.issued_at_ms
            || wall >= self.expires_at_ms
            || monotonic >= self.monotonic_deadline
            || !bool::from(candidate.as_ref().ct_eq(self.key_hash.as_ref()))
        {
            return Err(AuthorityError::InvalidUnlockCredential);
        }
        Ok(())
    }
}

impl Worker {
    pub(super) fn verify_presence(&self, proof: &SecretInput) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        let key = decode_presence_key(proof.expose())?;
        match &self.presence_grant {
            Some(PresenceState::Active(grant)) => {
                grant.verify_at(&key, crate::now_ms()?, Instant::now())
            }
            _ => Err(AuthorityError::InvalidUnlockCredential),
        }
    }

    pub(super) fn suspend_presence(&mut self) {
        self.presence_grant = self
            .presence_grant
            .take()
            .map(|state| PresenceState::DeadlineOnly(state.into_grant()));
    }

    pub(super) fn forget_desktop(&mut self) -> Result<(), AuthorityError> {
        // Revoke in memory first, including when durable deletion fails.
        self.presence_grant = None;
        match fs::remove_file(self.config.state_dir.join(FILE)) {
            Ok(()) => {
                crate::durable::fsync(&self.config.state_dir).map_err(AuthorityError::storage)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AuthorityError::storage(e)),
        }
    }

    pub(super) fn remember_desktop(
        &mut self,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<(Zeroizing<Vec<u8>>, i64), AuthorityError> {
        ensure_mutation_current(not_after)?;
        self.verify_proof(&proof)?;
        // Once the caller has proved authority, replacement is one-way: failures
        // must not silently leave the old bearer authorized.
        if let Err(error) = self.forget_desktop() {
            self.fault("desktop-revocation-failed");
            return Err(error);
        }
        let result = (|| {
            let issued = crate::now_ms()?;
            let expires = issued
                .checked_add(LIFETIME_MS)
                .ok_or(AuthorityError::ClockUnavailable)?;
            let key = Zeroizing::new(random_array::<32>()?);
            let grant = PresenceGrant::new(&key, issued, expires)?;
            let mut header = Vec::with_capacity(24);
            header.extend_from_slice(MAGIC);
            header.extend_from_slice(&issued.to_be_bytes());
            header.extend_from_slice(&expires.to_be_bytes());
            let mut aad = header.clone();
            aad.extend_from_slice(self.header.vault_id.as_bytes());
            let sealed = aead::seal(&key, &aad, self.require_unlocked()?.bytes())?;
            ensure_mutation_current(not_after)?;
            let path = self.config.state_dir.join(FILE);
            let mut file =
                crate::durable::create_new_file(&path).map_err(AuthorityError::storage)?;
            file.write_all(&header)
                .and_then(|_| file.write_all(&sealed.nonce))
                .and_then(|_| file.write_all(&sealed.ciphertext))
                .and_then(|_| file.sync_all())
                .and_then(|_| crate::durable::fsync(&self.config.state_dir))
                .map_err(AuthorityError::storage)?;
            ensure_mutation_current(not_after)?;
            self.append_audit(unlock_audit(
                "desktop.remembered",
                outcome::SUCCESS,
                "seven-days",
            ))?;
            ensure_mutation_current(not_after)?;
            grant.verify_at(&key, crate::now_ms()?, Instant::now())?;
            Ok((
                Zeroizing::new(data_encoding::HEXLOWER.encode(&*key).into_bytes()),
                expires,
                grant,
            ))
        })();
        match result {
            Ok((key, expires, grant)) => {
                self.presence_grant = Some(PresenceState::Active(grant));
                Ok((key, expires))
            }
            Err(error) => {
                if let Err(cleanup) = self.forget_desktop() {
                    self.fault("desktop-revocation-failed");
                    return Err(cleanup);
                }
                Err(error)
            }
        }
    }

    pub(super) fn resume_desktop(
        &mut self,
        token: SecretInput,
        not_after: Option<Instant>,
    ) -> Result<i64, AuthorityError> {
        if matches!(self.state, VaultState::Faulted) {
            return Err(AuthorityError::Locked);
        }
        self.suspend_presence();
        let result = (|| {
            ensure_mutation_current(not_after)?;
            let key = decode_presence_key(token.expose())?;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.config.state_dir.join(FILE))
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        AuthorityError::InvalidUnlockCredential
                    } else {
                        AuthorityError::storage(e)
                    }
                })?;
            let metadata = file.metadata().map_err(AuthorityError::storage)?;
            if !metadata.is_file()
                || metadata.mode() & 0o777 != 0o600
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(AuthorityError::InsecureStatePermissions);
            }
            let mut record = Vec::with_capacity(85);
            file.take(85)
                .read_to_end(&mut record)
                .map_err(AuthorityError::storage)?;
            if record.len() != 84 || &record[..8] != MAGIC {
                return Err(AuthorityError::InvalidUnlockCredential);
            }
            let issued = i64::from_be_bytes(record[8..16].try_into().unwrap());
            let expires = i64::from_be_bytes(record[16..24].try_into().unwrap());
            let mut grant = PresenceGrant::new(&key, issued, expires)?;
            if let Some(previous) = &self.presence_grant {
                grant.cap_to_same_ticket(previous.grant());
            }
            grant.verify_at(&key, crate::now_ms()?, Instant::now())?;
            let mut aad = record[..24].to_vec();
            aad.extend_from_slice(self.header.vault_id.as_bytes());
            ensure_mutation_current(not_after)?;
            let raw = aead::open(
                &key,
                &aad,
                record[24..36].try_into().unwrap(),
                &record[36..],
            )
            .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
            let mut bytes = Zeroizing::new(
                <[u8; 32]>::try_from(raw.as_slice())
                    .map_err(|_| AuthorityError::InvalidUnlockCredential)?,
            );
            let vrk = RootKey::from_bytes(&mut bytes);
            drop(raw);
            // Authenticate with the candidate without publishing it into worker state.
            if let Err(error) = self
                .store
                .verified_policy_material(vrk.bytes(), self.header.vault_id)
            {
                self.fault("desktop-resume-integrity-failed");
                return Err(error);
            }
            let retention = self
                .store
                .verified_audit_retention(vrk.bytes(), self.header.vault_id);
            self.fault_on_integrity(retention)?;
            if let Err(error) =
                super::lease_journal::verify_store(&self.store, vrk.bytes(), self.header.vault_id)
            {
                self.fault("desktop-resume-journal-integrity-failed");
                return Err(error);
            }
            // A verified ticket may constrain future retries before it authorizes A2.
            // Preserve that cap even if the audit/deadline below prevents publication.
            self.presence_grant = Some(PresenceState::DeadlineOnly(grant));
            ensure_mutation_current(not_after)?;
            self.append_audit(unlock_audit(
                "desktop.resumed",
                outcome::SUCCESS,
                "keychain",
            ))?;
            ensure_mutation_current(not_after)?;
            let state = self
                .presence_grant
                .as_ref()
                .ok_or(AuthorityError::InvalidUnlockCredential)?;
            state
                .grant()
                .verify_at(&key, crate::now_ms()?, Instant::now())?;
            let grant = self
                .presence_grant
                .take()
                .ok_or(AuthorityError::InvalidUnlockCredential)?
                .into_grant();
            Ok((expires, vrk, grant))
        })();
        match result {
            Ok((expires, vrk, grant)) => {
                self.state = VaultState::Unlocked { vrk };
                self.desktop_session = None;
                self.desktop_resume_expiry = Some(expires);
                self.presence_grant = Some(PresenceState::Active(grant));
                self.last_activity = Instant::now();
                Ok(expires)
            }
            Err(error) => {
                self.append_audit(unlock_audit(
                    "desktop.resume_failed",
                    outcome::DENIED,
                    error.code(),
                ))?;
                Err(error)
            }
        }
    }

    pub(super) fn desktop_session_duration(&self) -> Result<Duration, AuthorityError> {
        let millis = match self.desktop_resume_expiry {
            Some(expires) => expires
                .checked_sub(crate::now_ms()?)
                .filter(|v| *v > 0)
                .ok_or(AuthorityError::InvalidUnlockCredential)?,
            None => LIFETIME_MS,
        };
        Ok(Duration::from_millis(millis as u64))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const PASSWORD: &[u8] = b"synthetic-presence-proof";

    fn password() -> UnlockProof {
        UnlockProof::Password(SecretInput::from_slice(PASSWORD))
    }

    fn presence(key: &[u8]) -> UnlockProof {
        UnlockProof::Presence(SecretInput::from_slice(key))
    }

    fn fixture() -> (tempfile::TempDir, Worker, crate::bootstrap::InitOutcome) {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let initialized = crate::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(PASSWORD),
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
            store,
            header,
            state: VaultState::Locked,
            desktop_session: None,
            desktop_resume_expiry: None,
            presence_grant: None,
            failed_unlocks: 0,
            next_unlock_at: Instant::now(),
            last_activity: Instant::now(),
            retention_last_clock_ms: None,
            config: crate::handle::AuthorityConfig::new(state),
        };
        worker.unlock(password()).unwrap();
        (dir, worker, initialized)
    }

    fn assert_revoked(worker: &Worker, key: &[u8]) {
        assert!(worker.presence_grant.is_none());
        assert!(!worker.config.state_dir.join(FILE).exists());
        assert!(worker.verify_proof(&presence(key)).is_err());
    }

    #[test]
    fn presence_strict_key_and_independent_wall_monotonic_expiry() {
        let key = [0xab; 32];
        let encoded = data_encoding::HEXLOWER.encode(&key);
        assert_eq!(&*decode_presence_key(encoded.as_bytes()).unwrap(), &key);
        for input in [
            encoded.to_uppercase(),
            "0".repeat(63),
            "0".repeat(65),
            "g".repeat(64),
        ] {
            assert!(matches!(
                decode_presence_key(input.as_bytes()),
                Err(AuthorityError::InvalidUnlockCredential)
            ));
        }
        let now = crate::now_ms().unwrap();
        let grant = PresenceGrant::new(&key, now - 1000, now - 1000 + LIFETIME_MS).unwrap();
        grant.verify_at(&key, now, Instant::now()).unwrap();
        assert!(grant.verify_at(&[0xcd; 32], now, Instant::now()).is_err());
        assert!(
            grant
                .verify_at(&key, grant.issued_at_ms - 1, Instant::now())
                .is_err()
        );
        assert!(
            grant
                .verify_at(&key, grant.expires_at_ms, Instant::now())
                .is_err()
        );
        assert!(
            grant
                .verify_at(&key, now, grant.monotonic_deadline)
                .is_err()
        );
        assert!(PresenceGrant::new(&key, now, now + LIFETIME_MS + 1).is_err());
    }

    #[test]
    fn presence_reissue_replaces_hash_and_failed_resume_preserves_existing_root_only() {
        let (_dir, mut worker, _) = fixture();
        let (old, _) = worker.remember_desktop(password(), None).unwrap();
        worker.verify_proof(&presence(&old)).unwrap();
        let (new, expires) = worker.remember_desktop(presence(&old), None).unwrap();
        assert!(worker.verify_proof(&presence(&old)).is_err());
        worker.verify_proof(&presence(&new)).unwrap();
        let original_root = Zeroizing::new(*worker.require_unlocked().unwrap().bytes());
        assert!(matches!(
            worker.resume_desktop(SecretInput::from_slice(&old), None),
            Err(AuthorityError::InvalidUnlockCredential)
        ));
        assert_eq!(worker.require_unlocked().unwrap().bytes(), &*original_root);
        assert!(matches!(
            worker.presence_grant,
            Some(PresenceState::DeadlineOnly(_))
        ));
        assert_eq!(
            worker
                .resume_desktop(SecretInput::from_slice(&new), None)
                .unwrap(),
            expires
        );
        let deadline = worker
            .presence_grant
            .as_ref()
            .unwrap()
            .grant()
            .monotonic_deadline;
        worker.verify_proof(&presence(&new)).unwrap();
        assert_eq!(
            worker
                .presence_grant
                .as_ref()
                .unwrap()
                .grant()
                .monotonic_deadline,
            deadline
        );
        assert!(matches!(
            worker.unlock(presence(&new)),
            Err(AuthorityError::InvalidUnlockCredential)
        ));
        worker.set_locked("test-restart", true).unwrap();
        assert!(matches!(
            worker.verify_shutdown_proof(&presence(&new)),
            Err(AuthorityError::InvalidUnlockCredential)
        ));
        assert!(matches!(
            worker.resume_desktop(SecretInput::from_slice(&old), None),
            Err(AuthorityError::InvalidUnlockCredential)
        ));
        assert!(matches!(worker.state, VaultState::Locked));
        worker.unlock(password()).unwrap();
        assert!(matches!(
            worker.presence_grant,
            Some(PresenceState::DeadlineOnly(_))
        ));
        assert!(worker.verify_proof(&presence(&new)).is_err());
        assert!(worker.config.state_dir.join(FILE).exists());
    }

    #[test]
    fn presence_all_revocation_paths_clear_hash_and_persisted_wrap() {
        for operation in ["lock", "idle", "fault", "password", "recovery", "vrk"] {
            let (_dir, mut worker, initialized) = fixture();
            let (key, _) = worker.remember_desktop(password(), None).unwrap();
            match operation {
                "lock" => worker.lock("presence-test").unwrap(),
                "idle" => {
                    worker.last_activity = Instant::now() - worker.config.idle_lock;
                    assert!(!worker.handle(crate::command::AuthorityCommand::CheckIdle));
                }
                "fault" => worker.fault("presence-test"),
                "password" => worker
                    .password_change(
                        presence(&key),
                        SecretInput::from_slice(b"synthetic-new-password"),
                        None,
                    )
                    .unwrap(),
                "recovery" => {
                    worker.recovery_rotate(presence(&key), None).unwrap();
                }
                "vrk" => {
                    worker.set_locked("restart-test", true).unwrap();
                    assert!(worker.config.state_dir.join(FILE).exists());
                    worker
                        .rotate_vrk(
                            SecretInput::from_slice(PASSWORD),
                            SecretInput::from_slice(initialized.recovery_key_display.as_bytes()),
                            None,
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_revoked(&worker, &key);
            if operation == "fault" {
                assert!(matches!(
                    worker.verify_shutdown_proof(&presence(&key)),
                    Err(AuthorityError::Faulted)
                ));
            }
        }
    }

    #[test]
    fn presence_reissue_deletion_failure_is_visible_and_old_hash_is_revoked() {
        let (_dir, mut worker, _) = fixture();
        let (key, _) = worker.remember_desktop(password(), None).unwrap();
        let path = worker.config.state_dir.join(FILE);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            worker.remember_desktop(presence(&key), None),
            Err(AuthorityError::StorageUnavailable(_))
        ));
        assert!(worker.presence_grant.is_none());
        assert!(worker.verify_proof(&presence(&key)).is_err());
    }

    #[test]
    fn presence_readable_ticket_deletion_failure_faults_before_it_can_resume() {
        let (_dir, mut worker, _) = fixture();
        let (key, _) = worker.remember_desktop(password(), None).unwrap();
        let state = worker.config.state_dir.clone();
        let path = state.join(FILE);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o500)).unwrap();
        let readable = fs::read(&path);
        let deletion = fs::remove_file(&path);
        let result = worker.remember_desktop(presence(&key), None);
        // Restore the temporary directory before assertions or TempDir cleanup.
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(readable.unwrap(), original);
        assert_eq!(
            deletion.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(matches!(result, Err(AuthorityError::StorageUnavailable(_))));
        assert_eq!(fs::read(path).unwrap(), original);
        assert!(matches!(worker.state, VaultState::Faulted));
        assert!(worker.presence_grant.is_none());
        assert!(matches!(
            worker.verify_proof(&presence(&key)),
            Err(AuthorityError::Faulted)
        ));
        assert!(matches!(
            worker.resume_desktop(SecretInput::from_slice(&key), None),
            Err(AuthorityError::Locked)
        ));
        assert!(worker.presence_grant.is_none());
    }

    #[test]
    fn presence_resume_cannot_extend_the_same_ticket_cap_after_wall_rollback_or_failure() {
        let (_dir, mut worker, _) = fixture();
        let (key, _) = worker.remember_desktop(password(), None).unwrap();
        let original_root = Zeroizing::new(*worker.require_unlocked().unwrap().bytes());
        // Model a cap established when the wall clock was further ahead. The current
        // wall is still within issued/expires, but recomputing remaining time is longer.
        let cap = Instant::now() + Duration::from_secs(60);
        let Some(PresenceState::Active(grant)) = worker.presence_grant.as_mut() else {
            panic!("remember must publish an active grant");
        };
        grant.monotonic_deadline = cap;
        for _ in 0..2 {
            worker
                .resume_desktop(SecretInput::from_slice(&key), None)
                .unwrap();
            assert_eq!(
                worker
                    .presence_grant
                    .as_ref()
                    .unwrap()
                    .grant()
                    .monotonic_deadline,
                cap
            );
            worker.verify_proof(&presence(&key)).unwrap();
        }
        worker.unlock(password()).unwrap();
        assert!(matches!(
            worker.presence_grant,
            Some(PresenceState::DeadlineOnly(_))
        ));
        assert!(worker.verify_proof(&presence(&key)).is_err());
        worker.set_locked("preserve-ticket-test", true).unwrap();
        worker
            .resume_desktop(SecretInput::from_slice(&key), None)
            .unwrap();
        assert_eq!(
            worker
                .presence_grant
                .as_ref()
                .unwrap()
                .grant()
                .monotonic_deadline,
            cap
        );

        let expired_cap = Instant::now() - Duration::from_millis(1);
        let Some(PresenceState::Active(grant)) = worker.presence_grant.as_mut() else {
            panic!("resume must publish an active grant");
        };
        grant.monotonic_deadline = expired_cap;
        let mut wrong_key = Zeroizing::new(key.to_vec());
        wrong_key[0] = if key[0] == b'0' { b'1' } else { b'0' };
        for attempt in [wrong_key.as_slice(), key.as_slice()] {
            assert!(matches!(
                worker.resume_desktop(SecretInput::from_slice(attempt), None),
                Err(AuthorityError::InvalidUnlockCredential)
            ));
            assert!(matches!(
                worker.presence_grant,
                Some(PresenceState::DeadlineOnly(_))
            ));
            assert_eq!(
                worker
                    .presence_grant
                    .as_ref()
                    .unwrap()
                    .grant()
                    .monotonic_deadline,
                expired_cap
            );
            assert!(worker.verify_proof(&presence(&key)).is_err());
            assert_eq!(worker.require_unlocked().unwrap().bytes(), &*original_root);
        }
    }

    #[test]
    fn presence_audit_failure_never_publishes_remember_or_resume() {
        for operation in ["remember", "resume-locked", "resume-unlocked"] {
            let (_dir, mut worker, _) = fixture();
            let (key, _) = worker.remember_desktop(password(), None).unwrap();
            if operation == "resume-locked" {
                worker.set_locked("test", true).unwrap();
                // Model the first explicit resume after a clean process restart.
                worker.presence_grant = None;
            }
            let db = rusqlite::Connection::open(crate::paths::vault_db(&worker.config.state_dir))
                .unwrap();
            db.execute_batch("CREATE TRIGGER fail_presence_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'synthetic'); END;").unwrap();
            let result = if operation == "remember" {
                worker.remember_desktop(presence(&key), None).map(|_| ())
            } else {
                worker
                    .resume_desktop(SecretInput::from_slice(&key), None)
                    .map(|_| ())
            };
            assert!(matches!(result, Err(AuthorityError::AuditCommitFailed)));
            assert!(matches!(worker.state, VaultState::Faulted));
            assert_revoked(&worker, &key);
        }
    }

    #[test]
    fn presence_deadline_after_audit_does_not_publish_a_new_grant_or_root() {
        for operation in ["remember", "resume-locked", "resume-unlocked"] {
            let (_dir, mut worker, _) = fixture();
            let (key, _) = worker.remember_desktop(password(), None).unwrap();
            let original_root = Zeroizing::new(*worker.require_unlocked().unwrap().bytes());
            if operation == "resume-locked" {
                worker.set_locked("test", true).unwrap();
                // This process has not yet established a cap for the saved ticket.
                worker.presence_grant = None;
            }
            let path = crate::paths::vault_db(&worker.config.state_dir);
            let db = rusqlite::Connection::open(&path).unwrap();
            db.execute_batch("BEGIN IMMEDIATE").unwrap();
            // Hold the audit writer past the operation deadline without changing any clock.
            let release = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(800));
                db.execute_batch("COMMIT").unwrap();
            });
            let deadline = Some(Instant::now() + Duration::from_millis(500));
            let result = if operation == "remember" {
                worker
                    .remember_desktop(presence(&key), deadline)
                    .map(|_| ())
            } else {
                worker
                    .resume_desktop(SecretInput::from_slice(&key), deadline)
                    .map(|_| ())
            };
            release.join().unwrap();
            assert!(matches!(result, Err(AuthorityError::AuthorityBusy)));
            if operation == "remember" {
                assert!(worker.presence_grant.is_none());
            } else {
                assert!(matches!(
                    worker.presence_grant,
                    Some(PresenceState::DeadlineOnly(_))
                ));
            }
            if operation == "resume-locked" {
                assert!(matches!(worker.state, VaultState::Locked));
            } else {
                assert_eq!(worker.require_unlocked().unwrap().bytes(), &*original_root);
            }
            if operation == "remember" {
                assert_revoked(&worker, &key);
            }
            let db = rusqlite::Connection::open(path).unwrap();
            let event = if operation == "remember" {
                "desktop.remembered"
            } else {
                "desktop.resumed"
            };
            let count: i64 = db
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type=?1",
                    [event],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, if operation == "remember" { 2 } else { 1 });
            if operation != "remember" {
                let cap = worker
                    .presence_grant
                    .as_ref()
                    .unwrap()
                    .grant()
                    .monotonic_deadline;
                worker
                    .resume_desktop(SecretInput::from_slice(&key), None)
                    .unwrap();
                assert!(
                    worker
                        .presence_grant
                        .as_ref()
                        .unwrap()
                        .grant()
                        .monotonic_deadline
                        <= cap
                );
            }
        }
    }

    #[test]
    fn wall_clock_expiry_rejects_a_still_live_monotonic_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        crate::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(b"synthetic-expiry-test"),
            crate::crypto::kdf::Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        let store = crate::store::SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
        let header = store.load_header().unwrap();
        let token = SecretInput::from_slice(b"synthetic-session");
        let mut worker = Worker {
            #[cfg(feature = "lab")]
            keychain_fixture: None,
            store,
            header,
            state: VaultState::Unlocked {
                vrk: RootKey::generate().unwrap(),
            },
            desktop_session: Some((
                Zeroizing::new(token.expose().to_vec()),
                Instant::now() + Duration::from_secs(60),
            )),
            desktop_resume_expiry: Some(crate::now_ms().unwrap() + 60_000),
            presence_grant: None,
            failed_unlocks: 0,
            next_unlock_at: Instant::now(),
            last_activity: Instant::now(),
            retention_last_clock_ms: None,
            config: crate::handle::AuthorityConfig::new(state),
        };
        worker.verify_desktop(&token).unwrap();
        worker.desktop_resume_expiry = Some(crate::now_ms().unwrap() - 1);
        assert!(matches!(
            worker.verify_desktop(&token),
            Err(AuthorityError::InvalidUnlockCredential)
        ));
    }
    #[test]
    fn exact3_desktop_resume_authenticates_retention_before_success() {
        let mut outcomes = Vec::new();
        for tamper in [
            None,
            Some("UPDATE audit_retention SET seal_nonce=zeroblob(12)"),
            Some("UPDATE audit_retention SET seal_ciphertext=zeroblob(16)"),
            Some("DELETE FROM audit_retention"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = dir.path().join("state");
            crate::bootstrap::init_vault(
                &state,
                &SecretInput::from_slice(b"synthetic-resume"),
                crate::crypto::kdf::Argon2Params {
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1,
                },
                rekey_domain::authorization::PolicyMode::Team,
            )
            .unwrap();
            crate::bootstrap::confirm_vault_init(&state).unwrap();
            let store =
                crate::store::SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
            let header = store.load_header().unwrap();
            let mut worker = Worker {
                #[cfg(feature = "lab")]
                keychain_fixture: None,
                store,
                header,
                state: VaultState::Locked,
                desktop_session: None,
                desktop_resume_expiry: None,
                presence_grant: None,
                failed_unlocks: 0,
                next_unlock_at: Instant::now(),
                last_activity: Instant::now(),
                retention_last_clock_ms: None,
                config: crate::handle::AuthorityConfig::new(state.clone()),
            };
            worker
                .unlock(UnlockProof::Password(SecretInput::from_slice(
                    b"synthetic-resume",
                )))
                .unwrap();
            let (ticket, _) = worker
                .remember_desktop(
                    UnlockProof::Password(SecretInput::from_slice(b"synthetic-resume")),
                    None,
                )
                .unwrap();
            worker.set_locked("synthetic-resume", true).unwrap();
            let db = rusqlite::Connection::open(crate::paths::vault_db(&state)).unwrap();
            if let Some(sql) = tamper {
                db.execute_batch(sql).unwrap();
            }
            let result = worker.resume_desktop(SecretInput::from_slice(&ticket), None);
            let successes: i64 = db
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='desktop.resumed'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            outcomes.push(if tamper.is_some() {
                matches!(result, Err(AuthorityError::StorageIntegrityFailed))
                    && matches!(worker.state, VaultState::Faulted)
                    && matches!(worker.require_unlocked(), Err(AuthorityError::Faulted))
                    && successes == 0
            } else {
                result.is_ok()
                    && matches!(worker.state, VaultState::Unlocked { .. })
                    && successes == 1
            });
        }
        assert_eq!(outcomes, vec![true, true, true, true]);
    }
}
