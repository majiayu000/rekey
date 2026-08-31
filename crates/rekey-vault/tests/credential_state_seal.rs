//! Credential lifecycle metadata is authenticated under the VRK. Runtime
//! tampering must fault the authority before metadata can influence behavior.

mod common;

use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialState};
use rekey_domain::ids::CredentialId;
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::error::AuthorityError;
use rekey_vault::secret::SecretInput;

async fn add_credential(
    handle: &rekey_vault::handle::AuthorityHandle,
    label: &str,
) -> CredentialId {
    handle
        .credential_add(
            CredentialLabel::new(label).unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret"),
            common::password_proof(),
        )
        .await
        .unwrap()
        .id
}

async fn assert_list_faults(
    handle: &rekey_vault::handle::AuthorityHandle,
    join: std::thread::JoinHandle<()>,
) {
    let err = handle.credential_list().await.unwrap_err();
    assert!(matches!(err, AuthorityError::StorageIntegrityFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    let err = handle.credential_list().await.unwrap_err();
    assert!(matches!(err, AuthorityError::Faulted));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn metadata_tamper_matrix_faults_runtime() {
    for tamper in [
        "label",
        "kind",
        "state",
        "current-version",
        "created-at",
        "updated-at",
        "revoked-at",
    ] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let id = add_credential(&handle, tamper).await;
        let connection =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        match tamper {
            "label" => {
                connection
                    .execute(
                        "UPDATE credentials SET label = 'tampered' WHERE credential_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            "kind" => {
                connection
                    .execute(
                        "UPDATE credentials SET kind = 'github-app-installation' WHERE credential_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            "state" => {
                let tx = connection.unchecked_transaction().unwrap();
                tx.execute(
                    "UPDATE credential_versions SET state = 'revoked', retired_at_ms = 1
                     WHERE credential_id = ?1 AND version = 1",
                    [id.as_bytes().as_slice()],
                )
                .unwrap();
                tx.execute(
                    "UPDATE credentials SET state = 'revoked', updated_at_ms = 1, revoked_at_ms = 1
                     WHERE credential_id = ?1",
                    [id.as_bytes().as_slice()],
                )
                .unwrap();
                tx.commit().unwrap();
            }
            "current-version" => {
                connection
                    .execute(
                        "UPDATE credentials SET current_version = 2 WHERE credential_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            "created-at" => {
                connection
                    .execute(
                        "UPDATE credentials SET created_at_ms = created_at_ms + 1 WHERE credential_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            "updated-at" => {
                connection
                    .execute(
                        "UPDATE credentials SET updated_at_ms = updated_at_ms + 1 WHERE credential_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            "revoked-at" => {
                connection
                    .execute(
                        "UPDATE credentials SET revoked_at_ms = 1 WHERE credential_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        assert_list_faults(&handle, join).await;
    }
}

async fn rotated_vault() -> (
    common::TestVault,
    rekey_vault::handle::AuthorityHandle,
    std::thread::JoinHandle<()>,
    CredentialId,
) {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let id = add_credential(&handle, "rotated").await;
    handle
        .credential_rotate(
            id,
            SecretInput::from_slice(b"secret-v2"),
            common::password_proof(),
        )
        .await
        .unwrap();
    (vault, handle, join, id)
}

#[tokio::test]
async fn retired_version_reactivation_faults_runtime() {
    let (vault, handle, join, id) = rotated_vault().await;
    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let tx = connection.unchecked_transaction().unwrap();
    tx.execute(
        "UPDATE credential_versions SET state = 'retired' WHERE credential_id = ?1 AND version = 2",
        [id.as_bytes().as_slice()],
    )
    .unwrap();
    tx.execute(
        "UPDATE credential_versions SET state = 'active', retired_at_ms = NULL
         WHERE credential_id = ?1 AND version = 1",
        [id.as_bytes().as_slice()],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(connection);
    assert_list_faults(&handle, join).await;
}

#[tokio::test]
async fn unsealed_current_version_rewrite_faults_even_when_rows_are_consistent() {
    let (vault, handle, join, id) = rotated_vault().await;
    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let tx = connection.unchecked_transaction().unwrap();
    tx.execute(
        "UPDATE credential_versions SET state = 'retired' WHERE credential_id = ?1 AND version = 2",
        [id.as_bytes().as_slice()],
    )
    .unwrap();
    tx.execute(
        "UPDATE credential_versions SET state = 'active', retired_at_ms = NULL
         WHERE credential_id = ?1 AND version = 1",
        [id.as_bytes().as_slice()],
    )
    .unwrap();
    tx.execute(
        "UPDATE credentials SET current_version = 1 WHERE credential_id = ?1",
        [id.as_bytes().as_slice()],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(connection);
    assert_list_faults(&handle, join).await;
}

#[tokio::test]
async fn cross_credential_seal_swap_faults_runtime() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let source = add_credential(&handle, "source").await;
    let target = add_credential(&handle, "target").await;
    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute(
            "UPDATE credentials
             SET state_nonce = (SELECT state_nonce FROM credentials WHERE credential_id = ?1),
                 state_ciphertext = (SELECT state_ciphertext FROM credentials WHERE credential_id = ?1)
             WHERE credential_id = ?2",
            rusqlite::params![source.as_bytes().as_slice(), target.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);
    assert_list_faults(&handle, join).await;
}

#[tokio::test]
async fn prepare_and_mutation_verify_state_before_use() {
    for operation in ["prepare", "mutation"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let id = add_credential(&handle, operation).await;
        let connection =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        connection
            .execute(
                "UPDATE credentials SET updated_at_ms = updated_at_ms + 1 WHERE credential_id = ?1",
                [id.as_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);

        let err = if operation == "prepare" {
            handle.prepare_credential(id).await.unwrap_err()
        } else {
            handle
                .credential_revoke(id, common::password_proof())
                .await
                .unwrap_err()
        };
        assert!(matches!(err, AuthorityError::StorageIntegrityFailed));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn restore_rejects_tampered_lifecycle_metadata() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    add_credential(&handle, "restore-tamper").await;
    let backup = vault.dir.path().join("tampered-state.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let connection = rusqlite::Connection::open(&backup).unwrap();
    connection
        .execute("UPDATE credentials SET label = 'tampered'", [])
        .unwrap();
    drop(connection);
    let sha256 = rekey_vault::durable::sha256_file(&backup).unwrap();
    let target = vault.dir.path().join("restore-rejected");
    let err = restore_vault(
        &backup,
        &target,
        RestoreProof::Password(common::password_input()),
        &sha256,
    )
    .unwrap_err();
    assert!(matches!(err, AuthorityError::StorageIntegrityFailed));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn lifecycle_seal_survives_rotate_revoke_backup_restore() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let id = add_credential(&handle, "lifecycle").await;
    handle
        .credential_rotate(
            id,
            SecretInput::from_slice(b"secret-v2"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let revoked = handle
        .credential_revoke(id, common::password_proof())
        .await
        .unwrap();
    assert_eq!(revoked.state, CredentialState::Revoked);
    assert_eq!(revoked.current_version, 2);

    let backup = vault.dir.path().join("lifecycle.rkbackup");
    let receipt = handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let restored = vault.dir.path().join("restored-lifecycle");
    restore_vault(
        &backup,
        &restored,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    let (handle, join) = common::spawn(&restored);
    handle.unlock(common::password_proof()).await.unwrap();
    let listed = handle.credential_list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, CredentialState::Revoked);
    assert_eq!(listed[0].current_version, 2);
    let err = handle.prepare_credential(id).await.unwrap_err();
    assert!(matches!(err, AuthorityError::CredentialRevoked));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
