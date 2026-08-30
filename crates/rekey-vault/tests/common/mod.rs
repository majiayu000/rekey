#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_vault::bootstrap::{InitOutcome, init_vault};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::handle::{AuthorityConfig, AuthorityHandle};
use rekey_vault::secret::SecretInput;

pub const TEST_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};

pub const PASSWORD: &[u8] = b"correct horse battery staple";

pub struct TestVault {
    pub dir: tempfile::TempDir,
    pub state_dir: PathBuf,
    pub outcome: InitOutcome,
}

pub fn init_test_vault() -> TestVault {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let outcome = init_vault(&state_dir, &SecretInput::from_slice(PASSWORD), TEST_PARAMS)
        .expect("init vault");
    TestVault {
        dir,
        state_dir,
        outcome,
    }
}

pub fn test_config(state_dir: &Path) -> AuthorityConfig {
    let mut config = AuthorityConfig::new(state_dir.to_owned());
    config.unlock_backoff_base = Duration::from_millis(20);
    config
}

pub fn spawn(state_dir: &Path) -> (AuthorityHandle, std::thread::JoinHandle<()>) {
    rekey_vault::authority::spawn_authority(test_config(state_dir)).expect("spawn authority")
}

pub fn password_input() -> SecretInput {
    SecretInput::from_slice(PASSWORD)
}

pub fn password_proof() -> rekey_vault::command::UnlockProof {
    rekey_vault::command::UnlockProof::Password(password_input())
}

/// `unwrap_err` needs `T: Debug`; secret-bearing types deliberately are not.
pub fn expect_err<T>(
    result: Result<T, rekey_vault::error::AuthorityError>,
) -> rekey_vault::error::AuthorityError {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(err) => err,
    }
}
