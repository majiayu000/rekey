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
const MAGIC: &[u8; 8] = b"RKDSK001";
const LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1000;

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
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<(Zeroizing<Vec<u8>>, i64), AuthorityError> {
        ensure_mutation_current(not_after)?;
        self.verify_proof(&proof)?;
        let issued = crate::now_ms()?;
        let expires = issued
            .checked_add(LIFETIME_MS)
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
        file.write_all(&header)
            .and_then(|_| file.write_all(&sealed.nonce))
            .and_then(|_| file.write_all(&sealed.ciphertext))
            .and_then(|_| file.sync_all())
            .map_err(AuthorityError::storage)?;
        crate::durable::fsync(&self.config.state_dir).map_err(AuthorityError::storage)?;
        self.append_audit(unlock_audit(
            "desktop.remembered",
            outcome::SUCCESS,
            "seven-days",
        ))?;
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
            if expires.checked_sub(issued) != Some(LIFETIME_MS) || now < issued || now >= expires {
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
            self.append_audit(unlock_audit(
                "desktop.resumed",
                outcome::SUCCESS,
                "keychain",
            ))?;
            Ok(expires)
        })();
        if let Err(error) = &result {
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
}
