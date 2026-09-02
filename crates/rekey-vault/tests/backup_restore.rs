//! Backup/restore contract: online snapshot only, ciphertext-only output,
//! restore verifies unlock material before installing.

mod common;

use std::fs;
use std::path::Path;

use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::error::AuthorityError;
use rekey_vault::secret::SecretInput;

const SECRET_CANARY: &[u8] = b"backup-canary-secret-0xDEADBEEF";
const NEW_PASSWORD: &[u8] = b"replacement horse battery staple";

fn file_sha256(path: &Path) -> String {
    rekey_vault::durable::sha256_file(path).unwrap()
}

#[tokio::test]
async fn backup_roundtrip_and_restore() {
    use std::os::unix::fs::PermissionsExt;

    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let meta = handle
        .credential_add(
            CredentialLabel::new("backed-up").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(SECRET_CANARY),
            common::password_proof(),
        )
        .await
        .unwrap();

    let backup_path = vault.dir.path().join("out.rkbackup");
    let receipt = handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    assert_eq!(receipt.format_version, 6);
    assert_eq!(receipt.vault_id, vault.outcome.vault_id);
    assert_eq!(receipt.sha256_hex.len(), 64);
    assert_eq!(
        fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let audit = rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(
        &vault.state_dir,
    ))
    .unwrap()
    .audit_event_types()
    .unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|kind| *kind == "backup.created")
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|kind| *kind == "backup.release_authorized")
            .count(),
        1
    );

    // Ciphertext-only: the backup bytes never contain the plaintext secret.
    let bytes = fs::read(&backup_path).unwrap();
    assert!(
        !bytes
            .windows(SECRET_CANARY.len())
            .any(|w| w == SECRET_CANARY),
        "backup must not contain plaintext secrets"
    );

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    // Restore into a fresh directory with the password proof.
    let target = vault.dir.path().join("restored");
    let vault_id = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    assert_eq!(vault_id, vault.outcome.vault_id);

    // Restored vault serves the same credential.
    let (handle, join) = common::spawn(&target);
    handle.unlock(common::password_proof()).await.unwrap();
    let prepared = handle.prepare_credential(meta.id).await.unwrap();
    prepared.consume(|bytes| assert_eq!(bytes, SECRET_CANARY));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn backups_keep_the_wrapper_generation_captured_at_snapshot_time() {
    use rekey_vault::command::UnlockProof;

    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("wrapper-generation").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(SECRET_CANARY),
            common::password_proof(),
        )
        .await
        .unwrap();

    let old_backup = vault.dir.path().join("before-wrapper-change.rkbackup");
    let old_receipt = handle
        .backup(old_backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(NEW_PASSWORD),
            None,
        )
        .await
        .unwrap();
    let new_recovery = handle
        .recovery_rotate_before(SecretInput::from_slice(NEW_PASSWORD), None)
        .await
        .unwrap();
    let new_password_proof = || UnlockProof::Password(SecretInput::from_slice(NEW_PASSWORD));
    let new_backup = vault.dir.path().join("after-wrapper-change.rkbackup");
    let new_receipt = handle
        .backup(new_backup.clone(), new_password_proof())
        .await
        .unwrap();
    handle.shutdown(Some(new_password_proof())).await.unwrap();
    join.join().unwrap();

    let old_target = vault.dir.path().join("restore-old-generation");
    restore_vault(
        &old_backup,
        &old_target,
        RestoreProof::RecoveryKey(SecretInput::from_slice(
            vault.outcome.recovery_key_display.as_bytes(),
        )),
        &old_receipt.sha256_hex,
    )
    .unwrap();
    let wrong_old_target = vault.dir.path().join("restore-old-with-new-password");
    let error = restore_vault(
        &old_backup,
        &wrong_old_target,
        RestoreProof::Password(SecretInput::from_slice(NEW_PASSWORD)),
        &old_receipt.sha256_hex,
    )
    .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));

    let wrong_new_target = vault.dir.path().join("restore-new-with-old-recovery");
    let error = restore_vault(
        &new_backup,
        &wrong_new_target,
        RestoreProof::RecoveryKey(SecretInput::from_slice(
            vault.outcome.recovery_key_display.as_bytes(),
        )),
        &new_receipt.sha256_hex,
    )
    .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));

    let new_target = vault.dir.path().join("restore-new-generation");
    restore_vault(
        &new_backup,
        &new_target,
        RestoreProof::RecoveryKey(SecretInput::from_slice(new_recovery.as_bytes())),
        &new_receipt.sha256_hex,
    )
    .unwrap();
    let (handle, join) = common::spawn(&new_target);
    handle.unlock(new_password_proof()).await.unwrap();
    handle
        .prepare_credential(credential.id)
        .await
        .unwrap()
        .consume(|bytes| assert_eq!(bytes, SECRET_CANARY));
    handle.shutdown(Some(new_password_proof())).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn restore_rejects_wrong_proof_and_nonempty_target() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup_path = vault.dir.path().join("out.rkbackup");
    handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    // Wrong password: restore refuses and leaves no usable target.
    let target = vault.dir.path().join("restored-bad");
    let err = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(SecretInput::from_slice(b"wrong")),
        &file_sha256(&backup_path),
    )
    .unwrap_err();
    assert!(matches!(err, AuthorityError::InvalidUnlockCredential));
    assert!(!rekey_vault::paths::vault_db(&target).exists());

    // Non-empty target: refused without touching existing data.
    let occupied = vault.dir.path().join("occupied");
    fs::create_dir_all(&occupied).unwrap();
    fs::write(occupied.join("keep.txt"), b"keep").unwrap();
    let err = restore_vault(
        &backup_path,
        &occupied,
        RestoreProof::Password(common::password_input()),
        &file_sha256(&backup_path),
    )
    .unwrap_err();
    assert!(matches!(err, AuthorityError::StateDirectoryNotEmpty));
    assert_eq!(fs::read(occupied.join("keep.txt")).unwrap(), b"keep");

    // Truncated backup: integrity failure. (Byte flips in free pages are
    // undetectable to quick_check — SQLite pages carry no checksums — but any
    // ciphertext tamper is caught later by AEAD; truncation exercises the
    // storage-level check.)
    let mut bytes = fs::read(&backup_path).unwrap();
    bytes.truncate(bytes.len() * 2 / 3);
    let tampered = vault.dir.path().join("tampered.rkbackup");
    fs::write(&tampered, &bytes).unwrap();
    let target = vault.dir.path().join("restored-tampered");
    let err = restore_vault(
        &tampered,
        &target,
        RestoreProof::Password(common::password_input()),
        &file_sha256(&tampered),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            AuthorityError::StorageIntegrityFailed
                | AuthorityError::RestoreFailed
                | AuthorityError::UnsupportedVaultLayout
        ),
        "tampered backup must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn restore_rejects_wrong_sha256_without_installing() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup_path = vault.dir.path().join("out.rkbackup");
    handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let target = vault.dir.path().join("restored-bad-hash");
    let err = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        &"0".repeat(64),
    )
    .unwrap_err();
    assert!(matches!(err, AuthorityError::RestoreFailed));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
    assert!(!target.join(".incoming-vault.sqlite3").exists());
    assert!(!rekey_vault::paths::restore_incomplete(&target).exists());
}

#[tokio::test]
async fn restore_rejects_invalid_sha256_format() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup_path = vault.dir.path().join("out.rkbackup");
    handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let target = vault.dir.path().join("restored-bad-format");
    let err = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        "not-a-hash",
    )
    .unwrap_err();
    assert!(matches!(err, AuthorityError::RestoreFailed));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn restore_empty_vault_still_proves_integrity_record() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup_path = vault.dir.path().join("empty.rkbackup");
    let receipt = handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let target = vault.dir.path().join("restored-empty");
    restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    let (handle, join) = common::spawn(&target);
    handle.unlock(common::password_proof()).await.unwrap();
    assert!(handle.credential_list().await.unwrap().is_empty());
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn restore_rejects_corrupt_later_credential() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .credential_add(
            CredentialLabel::new("first").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret-one"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let second = handle
        .credential_add(
            CredentialLabel::new("second").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret-two"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let backup_path = vault.dir.path().join("two.rkbackup");
    handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let conn = rusqlite::Connection::open(&backup_path).unwrap();
    conn.execute(
        "UPDATE credential_versions SET encrypted_payload = x'00'
         WHERE credential_id = ?1",
        [second.id.as_bytes().as_slice()],
    )
    .unwrap();
    drop(conn);

    let target = vault.dir.path().join("restored-corrupt");
    let err = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        &file_sha256(&backup_path),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            AuthorityError::CryptoFailure | AuthorityError::RestoreFailed
        ),
        "corrupt later credential must fail, got {err:?}"
    );
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn restore_rejects_orphan_credential_version() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let source = handle
        .credential_add(
            CredentialLabel::new("orphan-source").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let backup_path = vault.dir.path().join("orphan.rkbackup");
    handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let orphan = rekey_domain::ids::CredentialId::new_random();
    let connection = rusqlite::Connection::open(&backup_path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_versions (
                credential_id, version, state, aad_version, crypto_suite,
                dek_nonce, wrapped_dek, payload_nonce, encrypted_payload,
                created_at_ms, retired_at_ms
             )
             SELECT ?1, 1, state, aad_version, crypto_suite, dek_nonce,
                    wrapped_dek, payload_nonce, encrypted_payload,
                    created_at_ms, retired_at_ms
             FROM credential_versions WHERE credential_id = ?2 AND version = 1",
            rusqlite::params![
                orphan.as_bytes().as_slice(),
                source.id.as_bytes().as_slice()
            ],
        )
        .unwrap();
    drop(connection);

    let target = vault.dir.path().join("restored-orphan");
    let err = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        &file_sha256(&backup_path),
    )
    .unwrap_err();
    assert!(matches!(err, AuthorityError::StorageIntegrityFailed));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn backup_fails_when_parent_directory_cannot_be_fsynced() {
    use std::os::unix::fs::PermissionsExt;

    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let dest = vault.dir.path().join("noread");
    fs::create_dir(&dest).unwrap();
    let output = dest.join("out.rkbackup");
    let mut perms = fs::metadata(&dest).unwrap().permissions();
    perms.set_mode(0o300);
    fs::set_permissions(&dest, perms).unwrap();

    let err = handle
        .backup(output.clone(), common::password_proof())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthorityError::BackupFailed),
        "parent fsync/open failure must be BackupFailed, got {err:?}"
    );

    let mut perms = fs::metadata(&dest).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&dest, perms).unwrap();
    assert!(
        output.exists(),
        "an authorized external artifact is never pathname-unlinked after creation"
    );
    assert!(!rekey_vault::paths::backup_snapshot(&vault.state_dir).exists());
    let audit = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(
        audit
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type = 'backup.release_authorized'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        audit
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type = 'backup.created'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn backup_audit_failure_leaves_authorized_artifact_without_receipt() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let db = rekey_vault::paths::vault_db(&vault.state_dir);
    let tamper = rusqlite::Connection::open(&db).unwrap();
    tamper
        .execute_batch(
            "CREATE TRIGGER fail_backup_created
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'backup.created'
             BEGIN SELECT RAISE(ABORT, 'injected final backup audit failure'); END;",
        )
        .unwrap();
    drop(tamper);

    let output = vault.dir.path().join("audit-failure.rkbackup");
    let err = handle
        .backup(output.clone(), common::password_proof())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::AuditCommitFailed));
    assert!(
        output.exists(),
        "authorized artifact must not be pathname-unlinked after creation"
    );
    let artifact = rusqlite::Connection::open(&output).unwrap();
    assert_eq!(
        artifact
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(artifact);
    assert!(!rekey_vault::paths::backup_snapshot(&vault.state_dir).exists());
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    let audit = rusqlite::Connection::open(&db).unwrap();
    assert_eq!(
        audit
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type = 'backup.release_authorized'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        audit
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type = 'backup.created'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );

    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn backup_refuses_to_overwrite_an_existing_artifact() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let output = vault.dir.path().join("existing.rkbackup");
    fs::write(&output, b"keep-existing-backup").unwrap();
    let err = handle
        .backup(output.clone(), common::password_proof())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::BackupFailed));
    assert_eq!(fs::read(&output).unwrap(), b"keep-existing-backup");

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn backup_never_touches_external_sibling_or_symlink_target() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let output = vault.dir.path().join("owned-output.rkbackup");
    let old_style_sibling = output.with_extension("rkbackup.tmp");
    let victim = vault.dir.path().join("victim");
    fs::write(&old_style_sibling, b"unowned-sibling").unwrap();
    fs::write(&victim, b"unowned-victim").unwrap();
    std::os::unix::fs::symlink(&victim, &output).unwrap();

    let err = handle
        .backup(output.clone(), common::password_proof())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::BackupFailed));
    assert_eq!(fs::read(&victim).unwrap(), b"unowned-victim");
    assert_eq!(fs::read(&old_style_sibling).unwrap(), b"unowned-sibling");
    fs::remove_file(&output).unwrap();

    let internal = rekey_vault::paths::backup_snapshot(&vault.state_dir);
    std::os::unix::fs::symlink(&victim, &internal).unwrap();
    handle
        .backup(output.clone(), common::password_proof())
        .await
        .unwrap();
    assert_eq!(fs::read(&victim).unwrap(), b"unowned-victim");
    assert_eq!(fs::read(&old_style_sibling).unwrap(), b"unowned-sibling");
    assert!(!internal.exists());

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn internal_snapshot_cleanup_failure_faults_authority() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let internal = rekey_vault::paths::backup_snapshot(&vault.state_dir);
    fs::create_dir(&internal).unwrap();
    let output = vault.dir.path().join("must-not-exist.rkbackup");
    let err = handle
        .backup(output.clone(), common::password_proof())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::BackupFailed));
    assert!(!output.exists());
    assert_eq!(handle.status().await.unwrap().state, "faulted");

    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn restore_recovers_only_marked_internal_artifacts_before_retry() {
    use std::os::unix::fs::PermissionsExt;

    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup_path = vault.dir.path().join("retry-source.rkbackup");
    let receipt = handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let target = vault.dir.path().join("interrupted-restore");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(&backup_path, rekey_vault::paths::vault_db(&target)).unwrap();
    fs::copy(&backup_path, target.join(".incoming-vault.sqlite3")).unwrap();
    fs::write(
        rekey_vault::paths::restore_incomplete(&target),
        b"rekey-restore-incomplete-v1\n",
    )
    .unwrap();

    let restored_id = restore_vault(
        &backup_path,
        &target,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    assert_eq!(restored_id, vault.outcome.vault_id);
    assert!(!rekey_vault::paths::restore_incomplete(&target).exists());
    assert!(!target.join(".incoming-vault.sqlite3").exists());

    let (handle, join) = common::spawn(&target);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
