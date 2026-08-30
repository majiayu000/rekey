use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rekey_domain::ids::{ActionId, CredentialId, SessionId};
use tokio::sync::Notify;

use super::*;
use crate::audit::spawn_terminal_worker_with;

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
    let guard = StartedGuard::new(
        Arc::clone(&tracker),
        ExecutionAuditContext {
            request_id: RequestId::new_random(),
            session_id: SessionId::new_random(),
            action: ActionVersionRef {
                action_id: ActionId::new_random(),
                version: 1,
            },
            credential_id: CredentialId::new_random(),
            authorization: None,
        },
    );
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
    let mut guard = StartedGuard::new(
        Arc::clone(&tracker),
        ExecutionAuditContext {
            request_id: RequestId::new_random(),
            session_id: SessionId::new_random(),
            action: ActionVersionRef {
                action_id: ActionId::new_random(),
                version: 1,
            },
            credential_id: CredentialId::new_random(),
            authorization: None,
        },
    );
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
