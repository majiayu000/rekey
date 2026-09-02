//! AuthorityWorker state-machine contract: lock/unlock transitions, unlock
//! rate limiting, idle lock, and shutdown proof requirements.

mod common;

use std::time::Duration;

use rekey_domain::credential::{CredentialKind, CredentialLabel};
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
            CredentialKind::OpaqueToken,
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
    let mut config = common::test_config(&vault.state_dir);
    config.unlock_backoff_base = Duration::from_millis(250);
    let (handle, join) = rekey_vault::authority::spawn_authority(config).unwrap();

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
    tokio::time::sleep(Duration::from_millis(300)).await;
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
async fn successful_activity_audits_reset_idle_activity() {
    use rekey_domain::ids::RequestId;
    use rekey_vault::command::AuditDraft;
    use rekey_vault::model::{event_type, outcome};

    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    for (kind, audit_outcome) in [
        (event_type::EXECUTION_BLOCKED, outcome::DENIED),
        (event_type::SESSION_REVOKED, outcome::SUCCESS),
        (event_type::POLICY_ACTIVATED, outcome::SUCCESS),
    ] {
        tokio::time::sleep(Duration::from_millis(30)).await;
        let before = handle.status().await.unwrap().idle_for_ms;
        handle
            .append_audit(AuditDraft {
                request_id: Some(RequestId::new_random()),
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                approval: None,
                event_type: kind,
                outcome: audit_outcome,
                reason_code: "test-complete".to_owned(),
                upstream_status: None,
                latency_ms: None,
            })
            .await
            .unwrap();
        let after = handle.status().await.unwrap().idle_for_ms;
        assert!(after < before, "{kind} audit did not reset activity");
    }
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn successful_admin_lists_reset_idle_activity() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(30)).await;
    let before_credentials = handle.status().await.unwrap().idle_for_ms;
    handle.credential_list().await.unwrap();
    let after_credentials = handle.status().await.unwrap().idle_for_ms;
    assert!(after_credentials < before_credentials);

    tokio::time::sleep(Duration::from_millis(30)).await;
    let before_actions = handle.status().await.unwrap().idle_for_ms;
    handle.action_list().await.unwrap();
    let after_actions = handle.status().await.unwrap().idle_for_ms;
    assert!(after_actions < before_actions);

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn only_admin_status_refreshes_idle_activity() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(25)).await;
    let first_internal = handle.status().await.unwrap().idle_for_ms;
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second_internal = handle.status().await.unwrap().idle_for_ms;
    assert!(second_internal > first_internal);

    let refreshed = handle.admin_status().await.unwrap().idle_for_ms;
    assert!(refreshed < second_internal);

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
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
    use rekey_domain::ids::{PolicyRuleId, PrincipalId, RequestId};
    use rekey_vault::model::{AuditEvent, AuthorizationEvidence, event_type, outcome};
    use rekey_vault::paths;
    use rekey_vault::store::SqliteRecordStore;

    let vault = common::init_test_vault();
    let request_id = RequestId::new_random();
    let authorization = AuthorizationEvidence {
        principal_id: PrincipalId::new_random(),
        policy_version: 7,
        policy_digest: [3; 32],
        policy_rule_id: Some(PolicyRuleId::new_random()),
        resource_type: "fixed-http-action".to_owned(),
        resource_id: "test-action".to_owned(),
        parameter_hash: [5; 32],
    };
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
                authorization: Some(authorization.clone()),
                approval: None,
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
    let indeterminate = log
        .iter()
        .filter(|(id, ty)| {
            id.as_slice() == request_id.as_bytes().as_slice() && ty == "execution.indeterminate"
        })
        .count();
    assert_eq!(started, 1);
    assert_eq!(indeterminate, 1);

    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT principal_id, policy_version, policy_digest, policy_rule_id,
                    resource_type, resource_id, parameter_hash
             FROM audit_events
             WHERE request_id = ?1 AND event_type LIKE 'execution.%'
             ORDER BY sequence",
        )
        .unwrap();
    let evidence_rows = statement
        .query_map(
            [request_id.as_bytes().as_slice()],
            |row| -> rusqlite::Result<_> {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            },
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(evidence_rows.len(), 2);
    assert_eq!(evidence_rows[0], evidence_rows[1]);
    assert_eq!(
        evidence_rows[0].0.as_deref(),
        Some(authorization.principal_id.as_bytes().as_slice())
    );
    assert_eq!(
        evidence_rows[0].1,
        Some(authorization.policy_version as i64)
    );
    assert_eq!(
        evidence_rows[0].2.as_deref(),
        Some(authorization.policy_digest.as_slice())
    );
}
