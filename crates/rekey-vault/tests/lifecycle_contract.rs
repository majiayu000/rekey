//! AuthorityWorker state-machine contract: lock/unlock transitions, unlock
//! rate limiting, idle lock, and shutdown proof requirements.

mod common;

use std::time::Duration;

use rekey_domain::credential::CredentialLabel;
use rekey_vault::command::UnlockProof;
use rekey_vault::error::AuthorityError;
use rekey_vault::secret::SecretInput;

fn wrong_password() -> UnlockProof {
    UnlockProof::Password(SecretInput::from_slice(b"wrong-password"))
}

#[tokio::test]
async fn lock_clears_lease_ability() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let meta = handle
        .credential_add(
            CredentialLabel::new("t").unwrap(),
            SecretInput::from_slice(b"v"),
            common::password_proof(),
        )
        .await
        .unwrap();
    handle.lock("explicit").await.unwrap();
    assert_eq!(handle.status().await.unwrap().state, "locked");
    let err = handle.prepare_credential(meta.id).await.unwrap_err();
    assert!(matches!(err, AuthorityError::Locked));

    // Unlock again works; state machine is Locked -> Unlocked, not Faulted.
    handle.unlock(common::password_proof()).await.unwrap();
    handle.prepare_credential(meta.id).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn unlock_backoff_rate_limits() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);

    // First three failures carry no delay.
    for _ in 0..3 {
        let err = handle.unlock(wrong_password()).await.unwrap_err();
        assert!(matches!(err, AuthorityError::InvalidUnlockCredential));
    }
    // Fourth attempt inside the backoff window is rate limited before any
    // KDF work happens.
    let err = handle.unlock(common::password_proof()).await.unwrap_err();
    assert!(matches!(err, AuthorityError::UnlockRateLimited));

    // After the window passes, a correct unlock succeeds and resets counters.
    tokio::time::sleep(Duration::from_millis(60)).await;
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(handle.status().await.unwrap().state, "unlocked");

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn idle_timeout_locks() {
    let vault = common::init_test_vault();
    let mut config = common::test_config(&vault.state_dir);
    config.idle_lock = Duration::from_millis(50);
    let (handle, join) = rekey_vault::authority::spawn_authority(config).unwrap();
    handle.unlock(common::password_proof()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    handle.check_idle();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn shutdown_requires_proof_only_when_unlocked() {
    let vault = common::init_test_vault();

    // Locked: shutdown needs no proof.
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    // Unlocked: shutdown without proof is refused, with proof succeeds.
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let err = handle.shutdown(None).await.unwrap_err();
    assert!(matches!(err, AuthorityError::AuthenticationFailed));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn startup_reconciles_unterminated_started() {
    use rekey_domain::ids::RequestId;
    use rekey_vault::model::{AuditEvent, event_type, outcome};
    use rekey_vault::paths;
    use rekey_vault::store::SqliteRecordStore;

    let vault = common::init_test_vault();
    let request_id = RequestId::new_random();
    {
        let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
        store
            .append_audit(&AuditEvent {
                event_id: *request_id.as_bytes(),
                request_id: Some(request_id),
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                event_type: event_type::EXECUTION_STARTED,
                outcome: outcome::SUCCESS,
                reason_code: "started".to_owned(),
                upstream_status: None,
                latency_ms: None,
                created_at_ms: 1,
            })
            .unwrap();
    }

    let (handle, join) = common::spawn(&vault.state_dir);
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    let store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let log = store.audit_execution_log().unwrap();
    let started = log
        .iter()
        .filter(|(id, ty)| {
            id.as_slice() == request_id.as_bytes().as_slice() && ty == "execution.started"
        })
        .count();
    let blocked = log
        .iter()
        .filter(|(id, ty)| {
            id.as_slice() == request_id.as_bytes().as_slice() && ty == "execution.blocked"
        })
        .count();
    assert_eq!(started, 1);
    assert_eq!(blocked, 1);
}
