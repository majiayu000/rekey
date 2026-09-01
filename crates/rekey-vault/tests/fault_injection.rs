//! Fail-closed behavior under storage corruption and audit failure.

mod common;

use std::fs;

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

fn rusqlite_open(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}
