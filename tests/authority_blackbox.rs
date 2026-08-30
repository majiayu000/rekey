//! Authority blackbox: everything through public API only — no direct table
//! access, no crypto internals — proving the lifecycle holds end to end.

use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_integration::harness as h;
use rekey_vault::authority::spawn_authority;
use rekey_vault::bootstrap::init_vault;
use rekey_vault::command::UnlockProof;
use rekey_vault::handle::AuthorityConfig;
use rekey_vault::secret::SecretInput;

#[tokio::test]
async fn full_lifecycle_via_public_api() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let outcome = init_vault(
        &state_dir,
        &SecretInput::from_slice(h::PASSWORD),
        h::TEST_PARAMS,
    )
    .unwrap();

    let mut config = AuthorityConfig::new(state_dir.clone());
    config.unlock_backoff_base = std::time::Duration::from_millis(10);
    let (handle, join) = spawn_authority(config).unwrap();

    // Recovery key unlocks; password unlocks; both reach the same vault.
    handle
        .unlock(UnlockProof::Recovery(SecretInput::from_slice(
            outcome.recovery_key_display.as_bytes(),
        )))
        .await
        .unwrap();
    handle.lock("test").await.unwrap();
    handle
        .unlock(UnlockProof::Password(SecretInput::from_slice(h::PASSWORD)))
        .await
        .unwrap();

    let meta = handle
        .credential_add(
            CredentialLabel::new("blackbox").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"blackbox-secret"),
            UnlockProof::Password(SecretInput::from_slice(h::PASSWORD)),
        )
        .await
        .unwrap();
    let prepared = handle.prepare_credential(meta.id).await.unwrap();
    prepared.consume(|bytes| assert_eq!(bytes, b"blackbox-secret"));

    handle
        .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
            h::PASSWORD,
        ))))
        .await
        .unwrap();
    join.join().unwrap();

    // Reopen: the vault survives a clean shutdown and stays locked.
    let (handle, join) = spawn_authority(AuthorityConfig::new(state_dir)).unwrap();
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}
