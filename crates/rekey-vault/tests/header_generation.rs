//! Stage A authenticates the header; no external rollback anchor is claimed.
mod common;

use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::error::AuthorityError;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use rusqlite::Connection;

#[test]
fn initial_header_is_nonzero_fixed_width_blob_and_schema_rejects_malformed_values() {
    let vault = common::init_test_vault();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let (generation, mac): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT generation,generation_mac FROM vault_header",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(generation, 1u64.to_be_bytes());
    assert_eq!(mac.len(), 32);
    for sql in [
        "generation=zeroblob(8)",
        "generation=x'01'",
        "generation=zeroblob(9)",
        "generation=1",
        "generation_mac=x'01'",
    ] {
        assert!(
            db.execute(&format!("UPDATE vault_header SET {sql}"), [])
                .is_err(),
            "{sql}"
        );
    }
}

#[test]
fn bypassed_blob_constraints_are_integrity_failures_not_truncated_integers() {
    for sql in [
        "generation=zeroblob(8)",
        "generation=x'01'",
        "generation=zeroblob(9)",
        "generation_mac=x'01'",
    ] {
        let vault = common::init_test_vault();
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        db.execute(&format!("UPDATE vault_header SET {sql}"), [])
            .unwrap();
        assert!(
            matches!(
                SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)),
                Err(AuthorityError::StorageIntegrityFailed)
            ),
            "{sql}"
        );
    }
}

#[tokio::test]
async fn tampered_generation_or_mac_never_unlocks_cached_worker_or_reopened_worker() {
    for sql in [
        "generation=x'0000000000000002'",
        "generation_mac=zeroblob(32)",
    ] {
        for reopen in [false, true] {
            let vault = common::init_test_vault();
            let mut worker = (!reopen).then(|| common::spawn(&vault.state_dir));
            let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
            db.execute(&format!("UPDATE vault_header SET {sql}"), [])
                .unwrap();
            let (handle, join) = worker
                .take()
                .unwrap_or_else(|| common::spawn(&vault.state_dir));
            assert!(matches!(
                handle.unlock(common::password_proof()).await,
                Err(AuthorityError::StorageIntegrityFailed)
            ));
            assert_eq!(handle.status().await.unwrap().state, "faulted");
            let successes: i64 = db
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='vault.unlocked'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(successes, 0);
            handle.shutdown(None).await.unwrap();
            join.join().unwrap();
        }
    }
}

#[tokio::test]
async fn desktop_resume_authenticates_header_before_candidate_publication() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    handle.lock_for_restart("test-preserve-wrap").await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    db.execute("UPDATE vault_header SET generation=x'0000000000000002'", [])
        .unwrap();
    assert!(matches!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    let successes: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='desktop.resumed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(successes, 0);
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn backup_checks_actual_snapshot_header_and_cleans_failed_output() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    db.execute("UPDATE vault_header SET generation=x'0000000000000002'", [])
        .unwrap();
    let output = vault.dir.path().join("bad-backup");
    assert!(matches!(
        handle
            .backup(output.clone(), common::password_proof())
            .await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert!(!output.exists());
    assert!(!paths::backup_snapshot(&vault.state_dir).exists());
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn restore_rejects_authenticated_header_change_even_with_correct_file_digest() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("backup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET generation=x'0000000000000002'", [])
        .unwrap();
    drop(db);
    let digest = rekey_vault::durable::sha256_file(&backup).unwrap();
    let destination = vault.dir.path().join("restored");
    assert!(matches!(
        restore_vault(
            &backup,
            &destination,
            RestoreProof::Password(common::password_input()),
            &digest,
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert!(!paths::vault_db(&destination).exists());
}

#[test]
fn earlier_unreleased_v25_header_layout_is_rejected_without_backfill() {
    let vault = common::init_test_vault();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("ALTER TABLE vault_header DROP COLUMN generation; ALTER TABLE vault_header DROP COLUMN generation_mac;").unwrap();
    assert!(matches!(
        SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)),
        Err(AuthorityError::UnsupportedVaultLayout)
    ));
    let remaining: i64 = db.query_row("SELECT count(*) FROM pragma_table_info('vault_header') WHERE name IN ('generation','generation_mac')", [], |r| r.get(0)).unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn candidate_marker_failure_faults_locked_and_unlocked_without_reclassifying_error() {
    for method in ["password", "desktop"] {
        for unlocked in [true, false] {
            let vault = common::init_test_vault();
            let (handle, join) = common::spawn(&vault.state_dir);
            let mut presence = None;
            if unlocked || method == "desktop" {
                handle.unlock(common::password_proof()).await.unwrap();
            }
            if method == "desktop" {
                presence = Some(
                    handle
                        .desktop_remember(common::password_proof(), None)
                        .await
                        .unwrap()
                        .0,
                );
                if !unlocked {
                    handle.lock_for_restart("test-preserve-wrap").await.unwrap();
                }
            }
            let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
            db.execute("UPDATE vault_header SET integrity_ciphertext=zeroblob(length(integrity_ciphertext))", []).unwrap();
            let error = match &presence {
                Some(key) => handle
                    .desktop_resume(SecretInput::from_slice(key), None)
                    .await
                    .map(|_| ())
                    .unwrap_err(),
                None => handle.unlock(common::password_proof()).await.unwrap_err(),
            };
            assert!(
                matches!(error, AuthorityError::CryptoFailure),
                "{method}/{unlocked}: {error}"
            );
            assert_eq!(
                handle.status().await.unwrap().state,
                "faulted",
                "{method}/{unlocked}"
            );
            assert!(matches!(
                handle.verify_proof(common::password_proof()).await,
                Err(AuthorityError::Faulted)
            ));
            if let Some(key) = presence {
                assert!(matches!(
                    handle
                        .verify_proof(rekey_vault::command::UnlockProof::Presence(
                            SecretInput::from_slice(&key)
                        ))
                        .await,
                    Err(AuthorityError::Faulted)
                ));
                // Desktop resume intentionally preserves its existing Locked
                // error for a faulted worker; it must not reinstall the old key.
                assert!(matches!(
                    handle
                        .desktop_resume(SecretInput::from_slice(&key), None)
                        .await,
                    Err(AuthorityError::Locked)
                ));
                assert_eq!(handle.status().await.unwrap().state, "faulted");
            }
            handle.shutdown(None).await.unwrap();
            join.join().unwrap();
        }
    }
}

#[tokio::test]
async fn backup_marker_failure_faults_and_keeps_original_crypto_error() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    db.execute(
        "UPDATE vault_header SET integrity_ciphertext=zeroblob(length(integrity_ciphertext))",
        [],
    )
    .unwrap();
    let output = vault.dir.path().join("bad-backup");
    assert!(matches!(
        handle
            .backup(output.clone(), common::password_proof())
            .await,
        Err(AuthorityError::CryptoFailure)
    ));
    assert!(!output.exists());
    assert!(!paths::backup_snapshot(&vault.state_dir).exists());
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn wrong_password_remains_denied_without_faulting_either_state() {
    for unlocked in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        if unlocked {
            handle.unlock(common::password_proof()).await.unwrap();
        }
        assert!(matches!(
            handle
                .unlock(rekey_vault::command::UnlockProof::Password(
                    SecretInput::from_slice(b"synthetic-wrong-password")
                ))
                .await,
            Err(AuthorityError::InvalidUnlockCredential)
        ));
        assert_eq!(
            handle.status().await.unwrap().state,
            if unlocked { "unlocked" } else { "locked" }
        );
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn unavailable_header_revokes_password_and_desktop_permissions_in_both_states() {
    for sql in [
        "DELETE FROM vault_header",
        "ALTER TABLE vault_header DROP COLUMN generation_mac",
    ] {
        for desktop in [false, true] {
            for unlocked in [false, true] {
                let vault = common::init_test_vault();
                let (handle, join) = common::spawn(&vault.state_dir);
                handle.unlock(common::password_proof()).await.unwrap();
                let (key, _) = handle
                    .desktop_remember(common::password_proof(), None)
                    .await
                    .unwrap();
                if !unlocked {
                    handle.lock_for_restart("test-preserve-wrap").await.unwrap();
                }
                let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
                db.execute_batch(sql).unwrap();
                // The header gate must not run before the wrapper proves the key.
                assert!(matches!(
                    handle
                        .unlock(rekey_vault::command::UnlockProof::Password(
                            SecretInput::from_slice(b"synthetic-wrong-password")
                        ))
                        .await,
                    Err(AuthorityError::InvalidUnlockCredential)
                ));
                assert_eq!(
                    handle.status().await.unwrap().state,
                    if unlocked { "unlocked" } else { "locked" }
                );
                let error = if desktop {
                    handle
                        .desktop_resume(SecretInput::from_slice(&key), None)
                        .await
                        .map(|_| ())
                        .unwrap_err()
                } else {
                    handle.unlock(common::password_proof()).await.unwrap_err()
                };
                assert!(
                    matches!(error, AuthorityError::UnsupportedVaultLayout),
                    "{sql}/{desktop}/{unlocked}: {error}"
                );
                assert_eq!(
                    handle.status().await.unwrap().state,
                    "faulted",
                    "{sql}/{desktop}/{unlocked}"
                );
                assert!(matches!(
                    handle
                        .verify_proof(rekey_vault::command::UnlockProof::Presence(
                            SecretInput::from_slice(&key)
                        ))
                        .await,
                    Err(AuthorityError::Faulted)
                ));
                handle.shutdown(None).await.unwrap();
                join.join().unwrap();
            }
        }
    }
}

#[tokio::test]
async fn unavailable_snapshot_header_faults_but_backup_destination_failure_does_not() {
    for sql in [
        "DELETE FROM vault_header",
        "ALTER TABLE vault_header DROP COLUMN generation_mac",
    ] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let output = vault.dir.path().join("existing-backup");
        std::fs::write(&output, b"synthetic existing output").unwrap();
        assert!(matches!(
            handle
                .backup(output.clone(), common::password_proof())
                .await,
            Err(AuthorityError::BackupFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "unlocked");
        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"synthetic existing output"
        );
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch(sql).unwrap();
        let output = vault.dir.path().join("unavailable-header-backup");
        assert!(matches!(
            handle
                .backup(output.clone(), common::password_proof())
                .await,
            Err(AuthorityError::UnsupportedVaultLayout)
        ));
        assert!(!output.exists());
        assert!(!paths::backup_snapshot(&vault.state_dir).exists());
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}
