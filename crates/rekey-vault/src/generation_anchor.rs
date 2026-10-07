//! External generation high-water foundation. The file alone is L1-dev: its
//! cooperative same-path lock is not protection against same-user disk rollback.
//! Production transaction/unlock integration is a separate caller contract.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rand::TryRngCore;
use rekey_domain::ids::VaultId;

use crate::{AuthorityError, durable};

#[cfg(target_os = "macos")]
mod macos;

/// Best-effort caller attribution only. Failed/unsigned/ad-hoc code queries
/// cannot establish the matching non-empty, trusted macOS signing team.
#[cfg(target_os = "macos")]
pub fn peer_has_own_team(kernel_audit_token: [u32; 8]) -> bool {
    macos::peer_has_own_team(kernel_audit_token).unwrap_or(false)
}

const MAGIC: &[u8; 8] = b"RKGEN\0\x01\0";
const RECORD_LEN: usize = 8 + 16 + 8;

/// Actual observations, including missing history. Only an authenticated caller
/// may decide whether an incomplete observation can establish a new baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorObservation {
    pub file: Option<u64>,
    pub protected: Option<u64>,
    pub protected_required: bool,
}

/// Backend selection has no environment override. Opening never creates history.
pub struct GenerationAnchors {
    path: PathBuf,
    vault_id: VaultId,
    protected: Protected,
    #[cfg(test)]
    fail_file_install: bool,
}

enum Protected {
    FileOnly,
    #[cfg(target_os = "macos")]
    Keychain(macos::ProtectedAnchor),
    #[cfg(test)]
    Mock(std::sync::Arc<std::sync::Mutex<MockAnchor>>),
}

fn integrity() -> AuthorityError {
    AuthorityError::StorageIntegrityFailed
}

fn storage(operation: &'static str, error: io::Error) -> AuthorityError {
    AuthorityError::storage(io::Error::new(
        error.kind(),
        format!("generation anchor {operation}: {error}"),
    ))
}

impl GenerationAnchors {
    pub fn open(state_dir: &Path, vault_id: VaultId) -> Result<Self, AuthorityError> {
        #[cfg(target_os = "macos")]
        let protected = match macos::own_team()? {
            Some(team) => Protected::Keychain(macos::ProtectedAnchor::new(vault_id, &team)),
            None => Protected::FileOnly,
        };
        #[cfg(not(target_os = "macos"))]
        let protected = Protected::FileOnly;
        Ok(Self {
            path: state_dir.join("generation"),
            vault_id,
            protected,
            #[cfg(test)]
            fail_file_install: false,
        })
    }

    pub fn read(&self) -> Result<AnchorObservation, AuthorityError> {
        self.observe()
    }

    /// Before the first possible anchor mutation, sets the irreversible phase.
    /// Errors never reset that flag or compensate by deleting/lowering history.
    pub fn create_new(
        &self,
        generation: u64,
        may_have_reserved: &mut bool,
    ) -> Result<(), AuthorityError> {
        if generation == 0 {
            return Err(integrity());
        }
        let _lock = self.lock()?;
        let observed = self.observe()?;
        if observed.file.is_some() || observed.protected.is_some() {
            return Err(integrity());
        }
        self.advance(observed, generation, may_have_reserved)
    }

    pub fn reserve(
        &self,
        expected: AnchorObservation,
        next: u64,
        may_have_reserved: &mut bool,
    ) -> Result<(), AuthorityError> {
        let _lock = self.lock()?;
        let observed = self.observe()?;
        if observed != expected
            || next == 0
            || observed
                .file
                .into_iter()
                .chain(observed.protected)
                .any(|seen| next <= seen)
        {
            return Err(integrity());
        }
        self.advance(observed, next, may_have_reserved)
    }

    fn observe(&self) -> Result<AnchorObservation, AuthorityError> {
        Ok(AnchorObservation {
            file: self.read_file()?,
            protected: self.protected.read()?,
            protected_required: !matches!(self.protected, Protected::FileOnly),
        })
    }

    fn advance(
        &self,
        observed: AnchorObservation,
        next: u64,
        may_have_reserved: &mut bool,
    ) -> Result<(), AuthorityError> {
        // The flag is conservative even if a unique add/CAS returns an error.
        *may_have_reserved = true;
        self.protected.advance(observed.protected, next)?;
        #[cfg(test)]
        if self.fail_file_install {
            return Err(storage(
                "test file install",
                io::Error::other("injected failure"),
            ));
        }
        self.install_file(next, observed.file.is_none())
    }

    fn lock(&self) -> Result<File, AuthorityError> {
        let path = self.path.with_file_name("generation.lock");
        let file = match durable::create_new_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
                .map_err(|e| storage("open lock", e))?,
            Err(error) => return Err(storage("create lock", error)),
        };
        validate_file(&file)?;
        loop {
            // SAFETY: the owned file remains open until the complete operation
            // ends. Closing releases flock on all success/error paths.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err(AuthorityError::AuthorityBusy);
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(storage("flock", error));
            }
        }
        if !durable::same_file(&file, &path).map_err(|e| storage("lock identity", e))? {
            return Err(integrity());
        }
        Ok(file)
    }

    fn read_file(&self) -> Result<Option<u64>, AuthorityError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage("open file", error)),
        };
        validate_file(&file)?;
        let mut bytes = Vec::with_capacity(RECORD_LEN + 1);
        file.take((RECORD_LEN + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| storage("read file", e))?;
        if bytes.len() != RECORD_LEN
            || &bytes[..8] != MAGIC
            || &bytes[8..24] != self.vault_id.as_bytes()
        {
            return Err(integrity());
        }
        let generation = u64::from_be_bytes(bytes[24..].try_into().map_err(|_| integrity())?);
        if generation == 0 {
            return Err(integrity());
        }
        Ok(Some(generation))
    }

    fn install_file(&self, generation: u64, missing: bool) -> Result<(), AuthorityError> {
        let mut random = [0_u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| AuthorityError::EntropyUnavailable)?;
        let temporary = self.path.with_file_name(format!(
            ".generation-{}.tmp",
            data_encoding::HEXLOWER.encode(&random)
        ));
        let mut file =
            durable::create_new_file(&temporary).map_err(|e| storage("create temporary", e))?;
        let result = (|| {
            file.write_all(MAGIC)
                .and_then(|_| file.write_all(self.vault_id.as_bytes()))
                .and_then(|_| file.write_all(&generation.to_be_bytes()))
                .and_then(|_| file.sync_all())
                .map_err(|e| storage("write and sync temporary", e))?;
            if missing {
                // link is atomic and never replaces an existing target. Both
                // names are in this directory, so no cross-device fallback.
                fs::hard_link(&temporary, &self.path).map_err(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        integrity()
                    } else {
                        storage("create unique file", e)
                    }
                })?;
                fs::remove_file(&temporary).map_err(|e| storage("unlink temporary", e))?;
            } else {
                fs::rename(&temporary, &self.path).map_err(|e| storage("replace file", e))?;
            }
            durable::fsync_parent(&self.path).map_err(|e| storage("sync directory", e))
        })();
        if result.is_err() {
            // Only the uninstalled temporary is eligible for cleanup. Preserve
            // the original error; no anchor compensation is permitted.
            if let Err(error) = fs::remove_file(&temporary)
                && error.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!(event = "generation.temporary_cleanup_failed", %error);
            }
        }
        result
    }
}

fn validate_file(file: &File) -> Result<(), AuthorityError> {
    let metadata = file.metadata().map_err(|e| storage("file metadata", e))?;
    if !metadata.is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(integrity());
    }
    Ok(())
}

impl Protected {
    fn read(&self) -> Result<Option<u64>, AuthorityError> {
        match self {
            Self::FileOnly => Ok(None),
            #[cfg(target_os = "macos")]
            Self::Keychain(anchor) => anchor.read(),
            #[cfg(test)]
            Self::Mock(anchor) => anchor.lock().unwrap().read(),
        }
    }
    fn advance(&self, expected: Option<u64>, next: u64) -> Result<(), AuthorityError> {
        #[cfg(not(any(target_os = "macos", test)))]
        let _ = (expected, next);
        match self {
            Self::FileOnly => Ok(()),
            #[cfg(target_os = "macos")]
            Self::Keychain(anchor) => anchor.advance(expected, next),
            #[cfg(test)]
            Self::Mock(anchor) => anchor.lock().unwrap().advance(expected, next),
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct MockAnchor {
    value: Option<u64>,
    fail_read: bool,
    fail_write: bool,
    race_value: Option<u64>,
}

#[cfg(test)]
impl MockAnchor {
    fn read(&self) -> Result<Option<u64>, AuthorityError> {
        if self.fail_read {
            Err(storage(
                "mock read",
                io::Error::new(io::ErrorKind::PermissionDenied, "injected denial"),
            ))
        } else {
            Ok(self.value)
        }
    }

    fn advance(&mut self, expected: Option<u64>, next: u64) -> Result<(), AuthorityError> {
        if self.fail_write {
            return Err(storage("mock write", io::Error::other("injected failure")));
        }
        if let Some(raced) = self.race_value.take() {
            self.value = Some(raced);
        }
        if self.value != expected {
            return Err(integrity());
        }
        self.value = Some(next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier, Mutex};

    fn file_anchor(directory: &Path) -> GenerationAnchors {
        GenerationAnchors {
            path: directory.join("generation"),
            vault_id: VaultId::from_bytes([7; 16]).unwrap(),
            protected: Protected::FileOnly,
            fail_file_install: false,
        }
    }

    fn protected_anchor(directory: &Path) -> (GenerationAnchors, Arc<Mutex<MockAnchor>>) {
        let mock = Arc::new(Mutex::new(MockAnchor::default()));
        let mut anchor = file_anchor(directory);
        anchor.protected = Protected::Mock(mock.clone());
        (anchor, mock)
    }

    fn assert_integrity(result: Result<impl Sized, AuthorityError>) {
        assert!(matches!(
            result,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }

    fn write_record(anchor: &GenerationAnchors, generation: u64) {
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.extend(anchor.vault_id.as_bytes());
        bytes.extend(generation.to_be_bytes());
        fs::write(&anchor.path, bytes).unwrap();
        fs::set_permissions(&anchor.path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn open_only_selects_backend_and_does_not_create_history() {
        let dir = tempfile::tempdir().unwrap();
        let anchor =
            GenerationAnchors::open(dir.path(), VaultId::from_bytes([7; 16]).unwrap()).unwrap();
        // This test never reads or changes a protected item, even if a future
        // signed test runner legitimately selects the mandatory DPK backend.
        assert!(!anchor.path.exists());
        assert!(!dir.path().join("generation.lock").exists());
    }

    #[test]
    fn read_missing_history_never_creates_a_lock_or_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-created");
        assert_eq!(file_anchor(&missing).read().unwrap().file, None);
        assert!(!missing.exists());
        assert_eq!(file_anchor(dir.path()).read().unwrap().file, None);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn file_creation_and_reservation_are_durable_and_monotonic() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        assert_eq!(
            anchor.read().unwrap(),
            AnchorObservation {
                file: None,
                protected: None,
                protected_required: false
            }
        );
        let mut phase = false;
        anchor.create_new(3, &mut phase).unwrap();
        assert!(phase);
        assert_eq!(fs::metadata(&anchor.path).unwrap().mode() & 0o7777, 0o600);
        let previous = anchor.read().unwrap();
        assert_eq!(previous.file, Some(3));
        phase = false;
        anchor.reserve(previous, 8, &mut phase).unwrap();
        assert!(phase);
        assert_eq!(file_anchor(dir.path()).read().unwrap().file, Some(8));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn precondition_errors_never_overwrite_or_clear_phase() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        let mut phase = false;
        assert_integrity(anchor.create_new(0, &mut phase));
        assert!(!phase);
        anchor.create_new(1, &mut phase).unwrap();
        let original = fs::read(&anchor.path).unwrap();
        phase = false;
        assert_integrity(anchor.create_new(2, &mut phase));
        assert!(!phase);
        let observed = anchor.read().unwrap();
        for next in [0, 1] {
            assert_integrity(anchor.reserve(observed, next, &mut phase));
        }
        let mut wrong = observed;
        wrong.protected_required = true;
        assert_integrity(anchor.reserve(wrong, 2, &mut phase));
        wrong = observed;
        wrong.file = None;
        assert_integrity(anchor.reserve(wrong, 2, &mut phase));
        assert!(!phase);
        phase = true;
        assert_integrity(anchor.reserve(wrong, 2, &mut phase));
        assert!(phase);
        assert_eq!(fs::read(&anchor.path).unwrap(), original);
    }

    #[test]
    fn malformed_wrong_vault_zero_and_oversize_are_integrity_errors() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        for variant in 0..6 {
            write_record(&anchor, 1);
            let mut bytes = fs::read(&anchor.path).unwrap();
            match variant {
                0 => bytes[0] ^= 1,
                1 => bytes[8] ^= 1,
                2 => bytes[24..].fill(0),
                3 => {
                    bytes.pop();
                }
                4 => bytes.push(0),
                5 => bytes.resize(1_000_000, 0),
                _ => unreachable!(),
            }
            fs::write(&anchor.path, &bytes).unwrap();
            assert_integrity(anchor.read());
            let mut phase = false;
            assert_integrity(anchor.create_new(2, &mut phase));
            assert!(!phase);
            assert_eq!(fs::read(&anchor.path).unwrap(), bytes);
        }
    }

    #[test]
    fn symlink_wrong_mode_and_nonregular_are_not_missing() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        let target = dir.path().join("target");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &anchor.path).unwrap();
        assert!(matches!(
            anchor.read(),
            Err(AuthorityError::StorageUnavailable(_))
        ));
        fs::remove_file(&anchor.path).unwrap();
        fs::create_dir(&anchor.path).unwrap();
        assert_integrity(anchor.read());
        fs::remove_dir(&anchor.path).unwrap();
        write_record(&anchor, 1);
        fs::set_permissions(&anchor.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_integrity(anchor.read());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
    }

    #[test]
    fn protected_errors_are_not_missing_and_never_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        let (anchor, mock) = protected_anchor(dir.path());
        mock.lock().unwrap().fail_read = true;
        assert!(matches!(
            anchor.read(),
            Err(AuthorityError::StorageUnavailable(_))
        ));
        let mut phase = false;
        assert!(anchor.create_new(1, &mut phase).is_err());
        assert!(!phase);
        mock.lock().unwrap().fail_read = false;
        mock.lock().unwrap().fail_write = true;
        assert!(anchor.create_new(1, &mut phase).is_err());
        assert!(phase);
        assert!(!anchor.path.exists());
    }

    #[test]
    fn protected_cas_race_never_adds_or_lowers_existing_history() {
        let dir = tempfile::tempdir().unwrap();
        let (anchor, mock) = protected_anchor(dir.path());
        anchor.create_new(2, &mut false).unwrap();
        let old = anchor.read().unwrap();
        mock.lock().unwrap().race_value = Some(9);
        let mut phase = false;
        assert_integrity(anchor.reserve(old, 3, &mut phase));
        assert!(phase);
        assert_eq!(mock.lock().unwrap().value, Some(9));
        assert_eq!(anchor.read_file().unwrap(), Some(2));
    }

    #[test]
    fn unique_protected_creation_conflict_does_not_write_file() {
        let dir = tempfile::tempdir().unwrap();
        let (anchor, mock) = protected_anchor(dir.path());
        mock.lock().unwrap().race_value = Some(4);
        let mut phase = false;
        assert_integrity(anchor.create_new(1, &mut phase));
        assert!(phase);
        assert_eq!(mock.lock().unwrap().value, Some(4));
        assert!(!anchor.path.exists());
    }

    #[test]
    fn file_failure_preserves_advanced_protected_value_and_phase() {
        let dir = tempfile::tempdir().unwrap();
        let (mut anchor, mock) = protected_anchor(dir.path());
        anchor.create_new(1, &mut false).unwrap();
        let old = anchor.read().unwrap();
        anchor.fail_file_install = true;
        let mut phase = false;
        assert!(matches!(
            anchor.reserve(old, 2, &mut phase),
            Err(AuthorityError::StorageUnavailable(_))
        ));
        assert!(phase);
        assert_eq!(mock.lock().unwrap().value, Some(2));
        assert_eq!(
            anchor.read().unwrap(),
            AnchorObservation {
                file: Some(1),
                protected: Some(2),
                protected_required: true
            }
        );
        assert_integrity(anchor.reserve(old, 3, &mut phase));
    }

    #[test]
    fn incomplete_history_is_observed_and_explicit_reserve_never_lowers() {
        let dir = tempfile::tempdir().unwrap();
        let (anchor, mock) = protected_anchor(dir.path());
        mock.lock().unwrap().value = Some(7);
        let observed = anchor.read().unwrap();
        assert_eq!(
            observed,
            AnchorObservation {
                file: None,
                protected: Some(7),
                protected_required: true
            }
        );
        assert_integrity(anchor.create_new(8, &mut false));
        assert_integrity(anchor.reserve(observed, 7, &mut false));
        anchor.reserve(observed, 8, &mut false).unwrap();
        assert_eq!(anchor.read().unwrap().file, Some(8));
        mock.lock().unwrap().value = None;
        let observed = anchor.read().unwrap();
        assert_eq!(observed.file, Some(8));
        assert_eq!(observed.protected, None);
        anchor.reserve(observed, 9, &mut false).unwrap();
        assert_eq!(mock.lock().unwrap().value, Some(9));
    }

    #[test]
    fn exclusive_file_install_preserves_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        write_record(&anchor, 8);
        assert_integrity(anchor.install_file(9, true));
        assert_eq!(anchor.read_file().unwrap(), Some(8));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn held_lock_returns_busy_without_advancing_or_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        let lock = anchor.lock().unwrap();
        let start = std::time::Instant::now();
        let mut phase = false;
        assert!(matches!(
            anchor.create_new(1, &mut phase),
            Err(AuthorityError::AuthorityBusy)
        ));
        assert!(!phase);
        assert!(!anchor.path.exists());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        drop(lock);
        anchor.create_new(1, &mut phase).unwrap();
        let observed = anchor.read().unwrap();
        let lock = anchor.lock().unwrap();
        let start = std::time::Instant::now();
        phase = false;
        assert!(matches!(
            anchor.reserve(observed, 2, &mut phase),
            Err(AuthorityError::AuthorityBusy)
        ));
        assert!(!phase);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(anchor.read().unwrap(), observed);
        drop(lock);
    }

    #[test]
    fn same_path_concurrent_reservation_has_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let anchor = file_anchor(dir.path());
        anchor.create_new(1, &mut false).unwrap();
        let observed = anchor.read().unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let path = dir.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let anchor = file_anchor(&path);
                    barrier.wait();
                    let mut phase = false;
                    let result = anchor.reserve(observed, 2, &mut phase);
                    assert_eq!(result.is_ok(), phase);
                    result.is_ok()
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        assert_eq!(anchor.read().unwrap().file, Some(2));
    }
}
