//! Fail-closed behavior under storage corruption and audit failure.

mod common;

use std::fs;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_vault::error::AuthorityError;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;

#[test]
fn corrupted_database_fails_integrity_check() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    // Ensure WAL content is folded into the main file before corrupting.
    drop(SqliteRecordStore::open(&db).unwrap());

    // Truncate to a partial page: quick_check / open must fail closed.
    // (Byte flips inside free pages are invisible to quick_check because
    // SQLite pages carry no checksums; record-level tampering is caught by
    // AEAD instead.)
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&db)
        .unwrap();
    let len = file.metadata().unwrap().len();
    file.set_len(len * 2 / 3).unwrap();
    drop(file);

    let err = common::expect_err(SqliteRecordStore::open(&db));
    assert!(
        matches!(
            err,
            AuthorityError::StorageIntegrityFailed
                | AuthorityError::UnsupportedVaultLayout
                | AuthorityError::StorageUnavailable(_)
        ),
        "corruption must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn audit_commit_failure_faults_the_worker() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .credential_add(
            CredentialLabel::new("pre-fault").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"v"),
            common::password_proof(),
        )
        .await
        .unwrap();

    // Fault injection: break the audit table from a second in-process
    // connection (the single-writer contract applies across processes; this
    // simulates on-disk damage while the broker runs).
    let db = paths::vault_db(&vault.state_dir);
    let tamper = rusqlite_open(&db);
    tamper.execute_batch("DROP TABLE audit_events;").unwrap();
    drop(tamper);

    // Lock writes a vault.locked audit event; that commit now fails and the
    // worker must fault instead of continuing without evidence.
    let err = handle.lock("test").await.unwrap_err();
    assert!(matches!(err, AuthorityError::AuditCommitFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");

    // Faulted rejects everything except status/shutdown.
    let err = handle.unlock(common::password_proof()).await.unwrap_err();
    assert!(matches!(err, AuthorityError::Faulted));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn transactional_mutation_audit_failure_faults_the_worker() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let db = paths::vault_db(&vault.state_dir);
    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch(
            "CREATE TRIGGER fail_credential_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'credential.created'
             BEGIN SELECT RAISE(ABORT, 'injected mutation audit fault'); END;",
        )
        .unwrap();
    drop(tamper);

    let err = handle
        .credential_add(
            CredentialLabel::new("faulted mutation").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"v"),
            common::password_proof(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::AuditCommitFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn wrapper_insert_failure_rolls_back_to_the_old_password() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let db = paths::vault_db(&vault.state_dir);
    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch(
            "CREATE TRIGGER fail_password_wrapper_insert
             BEFORE INSERT ON key_wrappers
             WHEN NEW.wrapper_kind = 'password' AND NEW.state = 'active'
             BEGIN SELECT RAISE(ABORT, 'injected wrapper insert fault'); END;",
        )
        .unwrap();
    drop(tamper);

    let error = handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(b"replacement password"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::StorageUnavailable(_)));
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    handle.verify_proof(common::password_proof()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let connection = rusqlite_open(&db);
    let counts: (i64, i64) = connection
        .query_row(
            "SELECT
                SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 'disabled' THEN 1 ELSE 0 END)
             FROM key_wrappers WHERE wrapper_kind = 'password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 0));
}

#[tokio::test]
async fn wrapper_success_audit_failure_rolls_back_and_faults() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let db = paths::vault_db(&vault.state_dir);
    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch(
            "CREATE TRIGGER fail_password_change_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'vault.password_changed'
             BEGIN SELECT RAISE(ABORT, 'injected password audit fault'); END;",
        )
        .unwrap();
    drop(tamper);

    let error = handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(b"replacement password"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::AuditCommitFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch("DROP TRIGGER fail_password_change_audit;")
        .unwrap();
    drop(tamper);
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn wrapper_commit_failure_rolls_back_and_faults() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let db = paths::vault_db(&vault.state_dir);
    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch(
            "CREATE TABLE wrapper_commit_parent (id INTEGER PRIMARY KEY);
             CREATE TABLE wrapper_commit_child (
               parent_id INTEGER REFERENCES wrapper_commit_parent(id)
                 DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TRIGGER fail_wrapper_commit
             AFTER INSERT ON audit_events
             WHEN NEW.event_type = 'vault.password_changed'
             BEGIN INSERT INTO wrapper_commit_child(parent_id) VALUES (1); END;",
        )
        .unwrap();
    drop(tamper);

    let error = handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(b"replacement password"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::AuditCommitFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch(
            "DROP TRIGGER fail_wrapper_commit;
             DROP TABLE wrapper_commit_child;
             DROP TABLE wrapper_commit_parent;",
        )
        .unwrap();
    drop(tamper);
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn wrapper_denial_audit_failure_faults_without_mutation() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let db = paths::vault_db(&vault.state_dir);
    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch(
            "CREATE TRIGGER fail_password_denial_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'vault.password_change_failed'
             BEGIN SELECT RAISE(ABORT, 'injected password denial audit fault'); END;",
        )
        .unwrap();
    drop(tamper);

    let error = handle
        .password_change_before(
            rekey_vault::command::UnlockProof::Password(SecretInput::from_slice(b"wrong")),
            SecretInput::from_slice(b"replacement password"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::AuditCommitFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    let tamper = rusqlite_open(&db);
    tamper
        .execute_batch("DROP TRIGGER fail_password_denial_audit;")
        .unwrap();
    drop(tamper);
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn wrapper_change_crash_child() {
    let Some(mode) = std::env::var_os("REKEY_WRAPPER_CRASH_MODE") else {
        return;
    };
    let state = std::env::var_os("REKEY_WRAPPER_CRASH_STATE").unwrap();
    let marker = std::env::var_os("REKEY_WRAPPER_CRASH_MARKER").unwrap();
    let (handle, _join) = common::spawn(std::path::Path::new(&state));
    handle.unlock(common::password_proof()).await.unwrap();
    fs::write(&marker, b"ready").unwrap();
    wait_for_marker(std::path::Path::new(&marker), b"go");
    handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(b"replacement password"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(mode, "postcommit");
    fs::write(&marker, b"committed").unwrap();
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn real_process_crash_reopens_either_complete_wrapper_generation() {
    let old = common::init_test_vault();
    let old_db = paths::vault_db(&old.state_dir);
    let marker = old.dir.path().join("precommit.marker");
    let mut child = spawn_wrapper_crash_child("precommit", &old.state_dir, &marker);
    wait_for_marker(&marker, b"ready");
    let connection = rusqlite_open(&old_db);
    connection
        .execute_batch(
            "CREATE TRIGGER hold_password_change_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'vault.password_changed'
             BEGIN
               SELECT sum(value) FROM (
                 WITH RECURSIVE counter(value) AS (
                   VALUES(0) UNION ALL
                   SELECT value + 1 FROM counter WHERE value < 100000000
                 ) SELECT value FROM counter
               );
             END;",
        )
        .unwrap();
    drop(connection);
    fs::write(&marker, b"go").unwrap();
    wait_for_write_lock(&old_db);
    kill_child(&mut child);
    let connection = rusqlite_open(&old_db);
    connection
        .execute_batch("DROP TRIGGER hold_password_change_audit;")
        .unwrap();
    drop(connection);
    assert_password_generation(&old.state_dir, common::PASSWORD, 0);

    let committed = common::init_test_vault();
    let marker = committed.dir.path().join("postcommit.marker");
    let mut child = spawn_wrapper_crash_child("postcommit", &committed.state_dir, &marker);
    wait_for_marker(&marker, b"ready");
    fs::write(&marker, b"go").unwrap();
    wait_for_marker(&marker, b"committed");
    kill_child(&mut child);
    assert_password_generation(&committed.state_dir, b"replacement password", 1);
}

fn spawn_wrapper_crash_child(
    mode: &str,
    state: &std::path::Path,
    marker: &std::path::Path,
) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "wrapper_change_crash_child", "--nocapture"])
        .env("REKEY_WRAPPER_CRASH_MODE", mode)
        .env("REKEY_WRAPPER_CRASH_STATE", state)
        .env("REKEY_WRAPPER_CRASH_MARKER", marker)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn wait_for_marker(path: &std::path::Path, expected: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if matches!(fs::read(path), Ok(bytes) if bytes == expected) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("child did not reach wrapper crash marker");
}

fn wait_for_write_lock(db: &std::path::Path) {
    let connection = rusqlite_open(db);
    connection.busy_timeout(Duration::ZERO).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match connection.execute_batch("BEGIN IMMEDIATE; ROLLBACK;") {
            Ok(()) => thread::sleep(Duration::from_millis(5)),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if matches!(
                    error.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                return;
            }
            Err(error) => panic!("write-lock probe failed: {error}"),
        }
    }
    panic!("wrapper transaction never held the SQLite write lock");
}

fn kill_child(child: &mut Child) {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-KILL", pid.as_str()])
        .status()
        .unwrap();
    assert!(status.success(), "failed to SIGKILL crash child");
    assert!(!child.wait().unwrap().success());
}

fn assert_password_generation(state: &std::path::Path, password: &[u8], disabled: i64) {
    let (handle, join) = common::spawn(state);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        handle
            .unlock(rekey_vault::command::UnlockProof::Password(
                SecretInput::from_slice(password),
            ))
            .await
            .unwrap();
        handle
            .shutdown(Some(rekey_vault::command::UnlockProof::Password(
                SecretInput::from_slice(password),
            )))
            .await
            .unwrap();
    });
    join.join().unwrap();
    let connection = rusqlite_open(&paths::vault_db(state));
    let counts: (i64, i64) = connection
        .query_row(
            "SELECT
                SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 'disabled' THEN 1 ELSE 0 END)
             FROM key_wrappers WHERE wrapper_kind = 'password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, disabled));
}

fn rusqlite_open(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}
