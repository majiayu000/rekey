//! Clean-bootstrap contract: fresh v2 init succeeds with correct permissions;
//! non-empty and v1-looking directories are rejected without modification.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use rekey_vault::bootstrap::{confirm_vault_init, discard_vault_files, init_vault};
use rekey_vault::error::AuthorityError;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;

#[test]
fn fresh_init_creates_secure_layout() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    assert!(db.exists());

    let dir_mode = fs::metadata(&vault.state_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "state dir must be 0700");
    let db_mode = fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    assert_eq!(db_mode, 0o600, "vault db must be 0600");

    assert!(vault.outcome.recovery_key_display.starts_with("RKREC1-"));
}

#[test]
fn discard_after_init_leaves_no_servable_vault() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    assert!(db.exists());
    discard_vault_files(&vault.state_dir).unwrap();
    assert!(!db.exists());
}

#[tokio::test]
async fn init_is_not_servable_until_recovery_confirmation_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let _outcome = init_vault(
        &state_dir,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
    )
    .unwrap();

    assert!(paths::init_incomplete(&state_dir).exists());
    let err = common::expect_err(rekey_vault::authority::spawn_authority(
        common::test_config(&state_dir),
    ));
    assert!(matches!(err, AuthorityError::UnsupportedVaultLayout));

    confirm_vault_init(&state_dir).unwrap();
    assert!(!paths::init_incomplete(&state_dir).exists());
    let (handle, join) = common::spawn(&state_dir);
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[test]
fn failed_discard_keeps_init_marker_and_blocks_serve() {
    let vault = common::init_test_vault();
    let runtime = paths::runtime_dir(&vault.state_dir);
    fs::create_dir(&runtime).unwrap();
    fs::write(
        runtime.join("unexpected"),
        b"must not be recursively deleted",
    )
    .unwrap();

    let err = discard_vault_files(&vault.state_dir).unwrap_err();
    assert!(matches!(err, AuthorityError::StorageUnavailable(_)));
    assert!(paths::init_incomplete(&vault.state_dir).exists());
    assert!(runtime.join("unexpected").exists());
    let err = common::expect_err(rekey_vault::authority::spawn_authority(
        common::test_config(&vault.state_dir),
    ));
    assert!(matches!(err, AuthorityError::UnsupportedVaultLayout));

    fs::remove_file(runtime.join("unexpected")).unwrap();
    discard_vault_files(&vault.state_dir).unwrap();
    assert!(!vault.state_dir.exists());
}

#[test]
fn second_init_rejected() {
    let vault = common::init_test_vault();
    let err = common::expect_err(init_vault(
        &vault.state_dir,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
    ));
    assert!(matches!(err, AuthorityError::StateDirectoryNotEmpty));
}

#[test]
fn legacy_vault_rejected() {
    // A v1-era directory: contains vault.db, no v2 layout.
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let legacy = state_dir.join("vault.db");
    fs::write(&legacy, b"legacy v1 bytes").unwrap();

    let err = common::expect_err(init_vault(
        &state_dir,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
    ));
    assert!(matches!(err, AuthorityError::StateDirectoryNotEmpty));
    // Existing data must be untouched.
    assert_eq!(fs::read(&legacy).unwrap(), b"legacy v1 bytes");

    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let err = common::expect_err(rekey_vault::authority::spawn_authority(
        common::test_config(&state_dir),
    ));
    assert!(matches!(err, AuthorityError::UnsupportedVaultLayout));
    assert_eq!(fs::read(&legacy).unwrap(), b"legacy v1 bytes");
}

#[test]
fn empty_dir_serve_reports_not_initialized() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let err = common::expect_err(rekey_vault::authority::spawn_authority(
        common::test_config(&state_dir),
    ));
    assert!(matches!(err, AuthorityError::NotInitialized));
}

#[test]
fn incomplete_restore_marker_blocks_authority_startup() {
    let vault = common::init_test_vault();
    fs::write(
        paths::restore_incomplete(&vault.state_dir),
        b"rekey-restore-incomplete-v1\n",
    )
    .unwrap();
    let err = common::expect_err(rekey_vault::authority::spawn_authority(
        common::test_config(&vault.state_dir),
    ));
    assert!(matches!(err, AuthorityError::UnsupportedVaultLayout));
}

#[test]
fn insecure_permissions_rejected() {
    let vault = common::init_test_vault();
    fs::set_permissions(&vault.state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let err = common::expect_err(rekey_vault::authority::spawn_authority(
        common::test_config(&vault.state_dir),
    ));
    assert!(matches!(err, AuthorityError::InsecureStatePermissions));
}

#[test]
fn empty_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let err = common::expect_err(init_vault(
        &state_dir,
        &SecretInput::new(vec![]),
        common::TEST_PARAMS,
    ));
    assert!(matches!(err, AuthorityError::InvalidUnlockCredential));
    // Failed init must not leave a usable-looking directory behind.
    assert!(!state_dir.exists());
}
