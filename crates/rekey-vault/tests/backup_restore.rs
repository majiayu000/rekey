//! Backup/restore contract: online snapshot only, ciphertext-only output,
//! restore verifies unlock material before installing.

mod common;

use std::fs;
use std::path::Path;

use rekey_domain::credential::CredentialLabel;
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::error::AuthorityError;
use rekey_vault::secret::SecretInput;
use sha2::{Digest, Sha256};

const SECRET_CANARY: &[u8] = b"backup-canary-secret-0xDEADBEEF";

fn file_sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    Sha256::digest(&bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[tokio::test]
async fn backup_roundtrip_and_restore() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let meta = handle
        .credential_add(
            CredentialLabel::new("backed-up").unwrap(),
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
    assert_eq!(receipt.format_version, 3);
    assert_eq!(receipt.vault_id, vault.outcome.vault_id);
    assert_eq!(receipt.sha256_hex.len(), 64);

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
            SecretInput::from_slice(b"secret-one"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let second = handle
        .credential_add(
            CredentialLabel::new("second").unwrap(),
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
        .backup(output, common::password_proof())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthorityError::BackupFailed),
        "parent fsync/open failure must be BackupFailed, got {err:?}"
    );

    let mut perms = fs::metadata(&dest).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&dest, perms).unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
