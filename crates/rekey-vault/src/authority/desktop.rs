use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};

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
const MAX_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1000;

impl Worker {
    pub(super) fn forget_desktop(&self) -> Result<(), AuthorityError> {
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
        lifetime_ms: i64,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<(Zeroizing<Vec<u8>>, i64), AuthorityError> {
        ensure_mutation_current(not_after)?;
        if !(1_000..=MAX_LIFETIME_MS).contains(&lifetime_ms) {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidActionDefinition(
                    "desktop remembered lifetime must be 1 second to 30 days".into(),
                ),
            ));
        }
        self.verify_proof(&proof)?;
        let issued = crate::now_ms()?;
        let expires = issued
            .checked_add(lifetime_ms)
            .ok_or(AuthorityError::ClockUnavailable)?;
        let key = Zeroizing::new(random_array::<32>()?);
        let mut header = Vec::with_capacity(24);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&issued.to_be_bytes());
        header.extend_from_slice(&expires.to_be_bytes());
        let mut aad = header.clone();
        aad.extend_from_slice(self.header.vault_id.as_bytes());
        let sealed = aead::seal(&key, &aad, self.require_unlocked()?.bytes())?;
        ensure_mutation_current(not_after)?;
        self.forget_desktop()?;
        let path = self.config.state_dir.join(FILE);
        let mut file = crate::durable::create_new_file(&path).map_err(AuthorityError::storage)?;
        let persisted = file
            .write_all(&header)
            .and_then(|_| file.write_all(&sealed.nonce))
            .and_then(|_| file.write_all(&sealed.ciphertext))
            .and_then(|_| file.sync_all())
            .and_then(|_| crate::durable::fsync(&self.config.state_dir));
        if let Err(error) = persisted {
            drop(file);
            self.forget_desktop()?;
            return Err(AuthorityError::storage(error));
        }
        self.append_audit(unlock_audit(
            "desktop.remembered",
            outcome::SUCCESS,
            "configured-expiry",
        ))?;
        self.desktop_resume_expiry = Some(expires);
        Ok((
            Zeroizing::new(data_encoding::HEXLOWER.encode(&*key).into_bytes()),
            expires,
        ))
    }

    pub(super) fn resume_desktop(
        &mut self,
        token: SecretInput,
        not_after: Option<Instant>,
    ) -> Result<i64, AuthorityError> {
        if matches!(self.state, VaultState::Faulted) {
            return Err(AuthorityError::Locked);
        }
        let was_locked = matches!(self.state, VaultState::Locked);
        let result = (|| {
            ensure_mutation_current(not_after)?;
            let key = Zeroizing::new(
                data_encoding::HEXLOWER
                    .decode(token.expose())
                    .map_err(|_| AuthorityError::InvalidUnlockCredential)?,
            );
            let key: &[u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
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
            let now = crate::now_ms()?;
            if !expires
                .checked_sub(issued)
                .is_some_and(|duration| (1_000..=MAX_LIFETIME_MS).contains(&duration))
                || now < issued
                || now >= expires
            {
                return Err(AuthorityError::InvalidUnlockCredential);
            }
            let mut aad = record[..24].to_vec();
            aad.extend_from_slice(self.header.vault_id.as_bytes());
            ensure_mutation_current(not_after)?;
            let raw = aead::open(key, &aad, record[24..36].try_into().unwrap(), &record[36..])
                .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
            let mut bytes = Zeroizing::new(
                <[u8; 32]>::try_from(raw.as_slice())
                    .map_err(|_| AuthorityError::InvalidUnlockCredential)?,
            );
            let vrk = RootKey::from_bytes(&mut bytes);
            self.state = VaultState::Unlocked { vrk };
            self.desktop_session = None;
            self.desktop_resume_expiry = Some(expires);
            self.last_activity = Instant::now();
            if let Err(error) = self.policy_material() {
                self.fault("desktop-resume-integrity-failed");
                return Err(error);
            }
            self.retention_record()?;
            if let Err(error) = super::lease_journal::verify_store(
                &self.store,
                self.require_unlocked()?.bytes(),
                self.header.vault_id,
            ) {
                self.fault("desktop-resume-journal-integrity-failed");
                return Err(error);
            }
            self.append_audit(unlock_audit(
                "desktop.resumed",
                outcome::SUCCESS,
                "keychain",
            ))?;
            ensure_mutation_current(not_after)?;
            Ok(expires)
        })();
        if let Err(error) = &result {
            if was_locked && !matches!(self.state, VaultState::Faulted) {
                self.state = VaultState::Locked;
                self.desktop_session = None;
                self.desktop_resume_expiry = None;
            }
            self.append_audit(unlock_audit(
                "desktop.resume_failed",
                outcome::DENIED,
                error.code(),
            ))?;
        }
        result
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

    pub(super) fn lock_desktop(
        &mut self,
        token: SecretInput,
        forget_remembered: bool,
    ) -> Result<(), AuthorityError> {
        use subtle::ConstantTimeEq;
        // An expired matching session may still be revoked; an unrelated token
        // must not revoke a newer desktop session.
        let matches = self
            .desktop_session
            .as_ref()
            .is_some_and(|(expected, _)| bool::from(expected.as_slice().ct_eq(token.expose())));
        if !matches {
            return Err(AuthorityError::InvalidUnlockCredential);
        }
        if forget_remembered {
            self.forget_desktop()?;
        }
        self.desktop_session = None;
        self.append_audit(unlock_audit(
            "desktop.locked",
            outcome::SUCCESS,
            if forget_remembered {
                "grant-revoked"
            } else {
                "session-revoked"
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        )
        .unwrap();
        let store = crate::store::SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
        let header = store.load_header().unwrap();
        let token = SecretInput::from_slice(b"synthetic-session");
        let mut worker = Worker {
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
            )
            .unwrap();
            crate::bootstrap::confirm_vault_init(&state).unwrap();
            let store =
                crate::store::SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
            let header = store.load_header().unwrap();
            let mut worker = Worker {
                keychain_fixture: None,
                store,
                header,
                state: VaultState::Locked,
                desktop_session: None,
                desktop_resume_expiry: None,
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
                    604_800_000,
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
