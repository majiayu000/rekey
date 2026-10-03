mod common;

use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_vault::command::UnlockProof;
use rekey_vault::error::AuthorityError;
use rekey_vault::secret::SecretInput;

fn presence(bytes: &[u8]) -> UnlockProof {
    UnlockProof::Presence(SecretInput::from_slice(bytes))
}

#[tokio::test]
async fn presence_authorizes_atomic_reveal_but_desktop_session_never_does() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("synthetic presence").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic-credential-value"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let desktop = handle.desktop_issue().await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    // The existing A1 session remains valid for write-only addition after remember.
    handle
        .desktop_add(
            SecretInput::from_slice(&desktop),
            CredentialLabel::new("synthetic A1").unwrap(),
            SecretInput::from_slice(b"synthetic-write-only"),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        handle
            .desktop_reveal(presence(&desktop), credential.id, None)
            .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    let value = handle
        .desktop_reveal(presence(&key), credential.id, None)
        .await
        .unwrap();
    assert_eq!(&*value, b"synthetic-credential-value");
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let reason: String = db
        .query_row(
            "SELECT reason_code FROM audit_events WHERE event_type='credential.revealed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason, "step-up-presence");
    drop(db);
    handle.shutdown(Some(presence(&key))).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn clean_restart_needs_explicit_resume_and_preserves_original_expiry() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, expiry) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    handle.shutdown(Some(presence(&key))).await.unwrap();
    join.join().unwrap();
    rekey_vault::authority::finish_runtime(&vault.state_dir).unwrap();
    assert!(vault.state_dir.join("desktop-unlock.bin").exists());
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(matches!(
        handle.unlock(presence(&key)).await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert!(matches!(
        handle.verify_shutdown_proof(presence(&key)).await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle.unlock(common::password_proof()).await.unwrap();
    assert!(matches!(
        handle.verify_proof(presence(&key)).await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert_eq!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .unwrap(),
        expiry
    );
    handle.verify_proof(presence(&key)).await.unwrap();
    handle.lock("presence-test").await.unwrap();
    assert!(!vault.state_dir.join("desktop-unlock.bin").exists());
    assert!(matches!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn recovery_rotation_accepts_presence_and_rejects_recovery_self_rotation() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    assert!(matches!(
        handle
            .recovery_rotate_before(
                UnlockProof::Recovery(SecretInput::from_slice(
                    vault.outcome.recovery_key_display.as_bytes()
                )),
                None
            )
            .await,
        Err(AuthorityError::Domain(_))
    ));
    handle.verify_proof(presence(&key)).await.unwrap();
    let new_recovery = handle
        .recovery_rotate_before(presence(&key), None)
        .await
        .unwrap();
    assert!(matches!(
        handle.verify_proof(presence(&key)).await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert!(!vault.state_dir.join("desktop-unlock.bin").exists());
    handle
        .verify_proof(UnlockProof::Recovery(SecretInput::from_slice(
            new_recovery.as_bytes(),
        )))
        .await
        .unwrap();
    assert!(matches!(
        handle
            .verify_proof(UnlockProof::Recovery(SecretInput::from_slice(
                vault.outcome.recovery_key_display.as_bytes()
            )))
            .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let reason: String = db
        .query_row(
            "SELECT reason_code FROM audit_events WHERE event_type='vault.recovery_rotated'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason, "step-up-presence");
    drop(db);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
