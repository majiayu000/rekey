//! Upgrade migration contract. The v25 / v26 fixtures were created by the
//! released 0.3.0-alpha.2 / 0.4.0-alpha.1 binaries with synthetic data
//! (`scripts/make-migration-fixtures.sh`); their password is public test data.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialState};
use rekey_domain::ipc::PersonalPolicyDraftMeta;
use rekey_vault::bootstrap::confirm_vault_init;
use rekey_vault::command::UnlockProof;
use rekey_vault::error::AuthorityError;
use rekey_vault::migrate::{MIGRATED_POLICY_REQUEST_FILE, MigrateOutcome, migrate_vault};
use rekey_vault::secret::SecretInput;

const FIXTURE_PASSWORD: &[u8] = b"migration-fixture-password";

fn fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("source");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/migrate")
        .join(name);
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = state.join(entry.file_name());
        fs::copy(entry.path(), &to).unwrap();
        fs::set_permissions(&to, fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, state)
}

fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn migrate(
    source: &Path,
    target: &Path,
    password: &[u8],
) -> Result<MigrateOutcome, AuthorityError> {
    migrate_vault(
        source,
        target,
        &SecretInput::from_slice(password),
        common::TEST_PARAMS,
    )
}

fn proof() -> UnlockProof {
    UnlockProof::Password(SecretInput::from_slice(FIXTURE_PASSWORD))
}

fn audit_types(state: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    let mut stmt = conn
        .prepare("SELECT event_type FROM audit_events ORDER BY sequence")
        .unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

async fn payload(
    handle: &rekey_vault::handle::AuthorityHandle,
    label: &str,
) -> Result<Vec<u8>, AuthorityError> {
    let id = handle
        .credential_list()
        .await?
        .into_iter()
        .find(|c| c.label.as_str() == label)
        .expect("migrated label")
        .id;
    Ok(handle
        .prepare_credential(id)
        .await?
        .consume(|bytes| bytes.to_vec()))
}

#[tokio::test]
async fn v25_fixture_migrates_all_versions_without_touching_the_source() {
    let (dir, source) = fixture("v25");
    let target = dir.path().join("target");
    let before = snapshot(&source);

    let outcome = migrate(&source, &target, FIXTURE_PASSWORD).unwrap();
    assert_eq!(outcome.source_format, 25);
    assert_eq!((outcome.credentials, outcome.versions), (3, 4));
    assert!(!outcome.trust_carried);
    assert!(outcome.policy_request.is_none());
    assert_ne!(outcome.vault_id, outcome.source_vault_id);
    assert_eq!(
        snapshot(&source),
        before,
        "source directory must not change"
    );

    // Unconfirmed until the caller shows the new recovery key.
    assert!(target.join(".init-incomplete").exists());
    confirm_vault_init(&target).unwrap();
    assert_eq!(
        audit_types(&target),
        ["vault.initialized", "migration.completed"]
    );

    let (handle, join) = common::spawn(&target);
    handle.unlock(proof()).await.unwrap();
    let list = handle.credential_list().await.unwrap();
    let states: BTreeMap<_, _> = list
        .iter()
        .map(|c| (c.label.as_str().to_owned(), (c.state, c.current_version)))
        .collect();
    assert_eq!(states["openai-fixture"], (CredentialState::Active, 2));
    assert_eq!(states["revoked-fixture"], (CredentialState::Revoked, 1));
    assert_eq!(states["github-fixture"], (CredentialState::Active, 1));
    assert_eq!(
        payload(&handle, "openai-fixture").await.unwrap(),
        b"sk-fixture-openai-0002"
    );
    assert_eq!(
        payload(&handle, "github-fixture").await.unwrap(),
        b"ghp_fixture_github_token"
    );
    assert!(payload(&handle, "revoked-fixture").await.is_err());
    handle.shutdown(Some(proof())).await.unwrap();
    join.join().unwrap();
    assert_eq!(snapshot(&source), before);
}

#[tokio::test]
async fn v26_fixture_carries_trust_and_leaves_connections_as_a_draft() {
    let (dir, source) = fixture("v26");
    let target = dir.path().join("target");
    let before = snapshot(&source);

    let outcome = migrate(&source, &target, FIXTURE_PASSWORD).unwrap();
    assert_eq!(outcome.source_format, 26);
    assert_eq!((outcome.credentials, outcome.versions), (4, 5));
    assert!(outcome.trust_carried);
    assert_eq!((outcome.connections, outcome.ssh_keys), (1, 1));
    assert!(
        outcome
            .review
            .iter()
            .any(|item| item.contains("fixture-ssh"))
    );
    assert_eq!(snapshot(&source), before);

    let request_path = outcome.policy_request.clone().unwrap();
    assert_eq!(request_path, target.join(MIGRATED_POLICY_REQUEST_FILE));
    assert_eq!(
        fs::metadata(&request_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let request: PersonalPolicyDraftMeta =
        serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
    assert_eq!(request.connections[0].name, "github");
    let ssh = &request.ssh_keys.unwrap()[0];
    assert_eq!(
        ssh.approver,
        rekey_domain::authorization::ApproverSpec::LocalPresence {}
    );
    assert_eq!(
        (
            ssh.session_budget.max_signatures,
            ssh.session_budget.max_seconds
        ),
        (100, 600)
    );
    for connection in &request.connections {
        connection.validate().unwrap();
    }

    confirm_vault_init(&target).unwrap();
    let (handle, join) = common::spawn(&target);
    handle.unlock(proof()).await.unwrap();
    let policy = handle.policy_material().await.unwrap();
    assert!(policy.trust.is_some());
    assert!(policy.bundle.is_none(), "old signature must be re-signed");
    let ssh_kind = handle
        .credential_list()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.label.as_str() == "fixture-ssh")
        .unwrap()
        .kind;
    assert_eq!(ssh_kind, CredentialKind::SshEd25519);
    assert_eq!(
        payload(&handle, "github-fixture").await.unwrap(),
        b"ghp_fixture_github_token"
    );
    handle.shutdown(Some(proof())).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn current_format_vault_copies_into_a_new_vault_id() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .credential_add(
            CredentialLabel::new("current").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"current-format-secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let target = vault.dir.path().join("target");
    let outcome = migrate(&vault.state_dir, &target, common::PASSWORD).unwrap();
    assert_eq!(outcome.source_format, rekey_vault::model::FORMAT_VERSION);
    assert_eq!(outcome.source_vault_id, vault.outcome.vault_id);
    assert_ne!(outcome.vault_id, vault.outcome.vault_id);
    confirm_vault_init(&target).unwrap();
    let (handle, join) = common::spawn(&target);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(
        payload(&handle, "current").await.unwrap(),
        b"current-format-secret"
    );
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[test]
fn wrong_password_fails_before_creating_the_target() {
    let (dir, source) = fixture("v26");
    let target = dir.path().join("target");
    assert!(matches!(
        migrate(&source, &target, b"not the password"),
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert!(!target.exists());
}

#[test]
fn refuses_a_non_empty_target_and_a_source_in_use() {
    let (dir, source) = fixture("v25");
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("keep"), b"x").unwrap();
    assert!(matches!(
        migrate(&source, &target, FIXTURE_PASSWORD),
        Err(AuthorityError::StateDirectoryNotEmpty)
    ));
    assert_eq!(fs::read(target.join("keep")).unwrap(), b"x");

    let nested = source.join("nested");
    assert!(matches!(
        migrate(&source, &nested, FIXTURE_PASSWORD),
        Err(AuthorityError::MigrationRefused(_))
    ));
    assert!(!nested.exists());

    let lock = fs::File::create(source.join("broker.lock")).unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let fresh = dir.path().join("fresh");
    assert!(matches!(
        migrate(&source, &fresh, FIXTURE_PASSWORD),
        Err(AuthorityError::MigrationRefused(_))
    ));
    assert!(!fresh.exists());
}

#[test]
fn refuses_a_rolled_back_source() {
    let (dir, source) = fixture("v26");
    // RKGEN anchor: magic(8) || vault id(16) || generation(8, big endian).
    let anchor = source.join("generation");
    let mut bytes = fs::read(&anchor).unwrap();
    let generation = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    bytes[24..32].copy_from_slice(&(generation + 1).to_be_bytes());
    fs::write(&anchor, bytes).unwrap();
    let target = dir.path().join("target");
    assert!(matches!(
        migrate(&source, &target, FIXTURE_PASSWORD),
        Err(AuthorityError::RollbackSuspected)
    ));
    assert!(!target.exists());
}

#[test]
fn formats_older_than_25_stay_rejected() {
    let (dir, source) = fixture("v25");
    let conn = rusqlite::Connection::open(source.join("vault.sqlite3")).unwrap();
    conn.execute_batch(
        "PRAGMA ignore_check_constraints=ON; UPDATE vault_header SET format_version=24;",
    )
    .unwrap();
    drop(conn);
    let target = dir.path().join("target");
    assert!(matches!(
        migrate(&source, &target, FIXTURE_PASSWORD),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!target.exists());
}
