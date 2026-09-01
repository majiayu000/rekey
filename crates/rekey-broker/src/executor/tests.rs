use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rekey_domain::Timestamp;
use rekey_domain::authorization::Principal;
use rekey_domain::capability::SessionGrant;
use rekey_domain::ids::{ActionId, CredentialId, PrincipalId, SessionId, TenantId};
use tokio::sync::Notify;

use super::*;
use crate::audit::spawn_terminal_worker_with;

fn execution_context() -> ExecutionAuditContext {
    ExecutionAuditContext {
        request_id: RequestId::new_random(),
        session_id: SessionId::new_random(),
        action: ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        },
        credential_id: CredentialId::new_random(),
        authorization: None,
    }
}

#[tokio::test]
async fn drain_linearizes_before_started() {
    let commits = Arc::new(AtomicUsize::new(0));
    let (tracker, worker) = spawn_terminal_worker_with({
        let commits = Arc::clone(&commits);
        move |_| {
            commits.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        }
    });
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running();
    let _coordinator = lifecycle.coordinate().await;
    lifecycle.enter_draining();
    let err = match commit_started_while_running(&lifecycle, &tracker, execution_context()).await {
        Ok(_) => panic!("draining admission unexpectedly committed started"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "DRAINING");
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    drop(tracker);
    worker.await.unwrap();
}

#[tokio::test]
async fn running_coordinator_contention_fails_without_waiting() {
    let (tracker, worker) = spawn_terminal_worker_with(|_| async { Ok(()) });
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running();
    let sessions = Arc::new(SessionRegistry::new());
    sessions.open_for_admission();
    let action = ActionVersionRef {
        action_id: ActionId::new_random(),
        version: 1,
    };
    let session_id = SessionId::new_random();
    let token = sessions
        .admit(
            SessionGrant::new(
                session_id,
                Principal {
                    tenant_id: TenantId::new_random(),
                    principal_id: PrincipalId::new_random(),
                    session_id,
                },
                vec![action],
                Timestamp::from_unix_ms(0),
                60_000,
                1,
            )
            .unwrap(),
        )
        .unwrap();
    let permit = sessions
        .acquire(&token, action, Timestamp::from_unix_ms(1))
        .unwrap();
    assert_eq!(sessions.in_flight_total(), 1);
    let _coordinator = lifecycle.coordinate().await;

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        commit_started_while_running(&lifecycle, &tracker, execution_context()),
    )
    .await
    .expect("final admission gate must not wait behind the drain coordinator");
    let err = match result {
        Ok(_) => panic!("contended admission unexpectedly committed started"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "AUTHORITY_BUSY");
    drop(permit);
    assert_eq!(sessions.in_flight_total(), 0);
    drop(tracker);
    worker.await.unwrap();
}

#[test]
fn sealing_detects_direct_and_encoded_secret() {
    let secret = b"ghp_super_secret_token_value";
    let auth = b"Bearer ghp_super_secret_token_value";
    let needles = sealing_needles(secret, auth);

    assert!(contains_secret(
        b"before ghp_super_secret_token_value after",
        &needles
    ));
    let b64 = BASE64.encode(secret);
    assert!(contains_secret(format!("x{b64}y").as_bytes(), &needles));
    let url = BASE64URL_NOPAD.encode(auth);
    assert!(contains_secret(url.as_bytes(), &needles));
    let pct = percent_encode(auth, true);
    assert!(contains_secret(pct.as_bytes(), &needles));
    assert!(!contains_secret(b"clean response body", &needles));

    let leak = vec![("content-type".to_owned(), format!("text/plain; {b64}"))];
    assert!(headers_contain_secret(&leak, &needles));
    let clean = vec![("content-type".to_owned(), "application/json".to_owned())];
    assert!(!headers_contain_secret(&clean, &needles));
}

#[tokio::test]
async fn cancellation_after_terminal_submission_does_not_submit_fallback() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let commits = Arc::new(AtomicUsize::new(0));
    let (tracker, worker) = spawn_terminal_worker_with({
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        let commits = Arc::clone(&commits);
        move |_| {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let commits = Arc::clone(&commits);
            async move {
                commits.fetch_add(1, Ordering::SeqCst);
                entered.notify_one();
                release.notified().await;
                Ok(())
            }
        }
    });
    let guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
    let commit = tokio::spawn(async move {
        let mut guard = guard;
        guard.blocked("test-cancel").await
    });
    entered.notified().await;
    commit.abort();
    drop(commit.await);
    release.notify_one();
    tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
    assert_eq!(commits.load(Ordering::SeqCst), 1);
    drop(tracker);
    worker.await.unwrap();
}

#[tokio::test]
async fn closed_remote_effect_gate_commits_one_blocked_terminal() {
    let commits = Arc::new(Mutex::new(Vec::new()));
    let (tracker, worker) = spawn_terminal_worker_with({
        let commits = Arc::clone(&commits);
        move |draft| {
            commits.lock().unwrap().push(draft);
            async { Ok(()) }
        }
    });
    let mut guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
    let lifecycle = Lifecycle::new();
    let error = try_begin_remote_effect(&lifecycle, &mut guard)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "DRAINING");
    tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
    {
        let commits = commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(
            commits[0].event_type,
            rekey_vault::model::event_type::EXECUTION_BLOCKED
        );
        assert_eq!(commits[0].reason_code, "remote-effect-admission-closed");
    }
    drop(guard);
    drop(tracker);
    worker.await.unwrap();
}
