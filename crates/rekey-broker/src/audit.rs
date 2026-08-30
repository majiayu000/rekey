//! Execution audit event construction. Events are built here in the broker
//! pipeline but persisted only through the AuthorityWorker's transaction.
//! Field discipline: identifiers, codes, and counters — never secrets,
//! bodies, or raw errors.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{CredentialId, RequestId, SessionId};
use rekey_vault::AuthorityError;
use rekey_vault::command::AuditDraft;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::{event_type, outcome};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Accepts terminal audits from Drop/panic paths and waits them to commit
/// before Authority shutdown. Commit errors and timeouts are never ignored.
pub struct TerminalAuditTracker {
    tx: mpsc::UnboundedSender<TerminalSubmission>,
    pending: Arc<AtomicUsize>,
    failed: Arc<AtomicBool>,
}

struct TerminalSubmission {
    draft: AuditDraft,
    reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
}

impl TerminalAuditTracker {
    pub fn submit(&self, draft: AuditDraft) {
        self.enqueue(draft, None);
    }

    fn enqueue(
        &self,
        draft: AuditDraft,
        reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
    ) {
        self.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(TerminalSubmission { draft, reply }).is_err() {
            self.failed.store(true, Ordering::SeqCst);
            self.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Transfers ownership of a terminal commit to the tracker before the
    /// first await. Cancelling the caller cannot cancel the durable commit.
    pub async fn commit(&self, draft: AuditDraft) -> Result<(), AuthorityError> {
        let (reply, result) = oneshot::channel();
        self.enqueue(draft, Some(reply));
        match result.await {
            Ok(result) => result,
            Err(_) => Err(AuthorityError::AuditCommitFailed),
        }
    }

    pub fn has_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst) > 0
    }

    /// Returns `Err(AuditCommitFailed)` if a terminal is still queued after
    /// `timeout`, or if any commit/submit failed. Callers must not treat
    /// lock/shutdown as success when this errors.
    pub async fn wait_idle(&self, timeout: Duration) -> Result<(), AuthorityError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.pending.load(Ordering::SeqCst) == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AuthorityError::AuditCommitFailed);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if self.failed.load(Ordering::SeqCst) {
            return Err(AuthorityError::AuditCommitFailed);
        }
        Ok(())
    }
}

pub fn spawn_terminal_worker(
    authority: AuthorityHandle,
) -> (Arc<TerminalAuditTracker>, JoinHandle<()>) {
    spawn_terminal_worker_with(move |draft| {
        let authority = authority.clone();
        async move { authority.commit_audit(draft).await }
    })
}

pub(crate) fn spawn_terminal_worker_with<F, Fut>(
    commit: F,
) -> (Arc<TerminalAuditTracker>, JoinHandle<()>)
where
    F: Fn(AuditDraft) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AuthorityError>> + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<TerminalSubmission>();
    let pending = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let pending_worker = Arc::clone(&pending);
    let failed_worker = Arc::clone(&failed);
    let join = tokio::spawn(async move {
        while let Some(submission) = rx.recv().await {
            let result = commit(submission.draft).await;
            if result.is_err() {
                failed_worker.store(true, Ordering::SeqCst);
            }
            if let Some(reply) = submission.reply {
                drop(reply.send(result));
            }
            pending_worker.fetch_sub(1, Ordering::SeqCst);
        }
    });
    (
        Arc::new(TerminalAuditTracker {
            tx,
            pending,
            failed,
        }),
        join,
    )
}

pub struct ExecutionAuditContext {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub action: ActionVersionRef,
    pub credential_id: CredentialId,
}

fn base(ctx: &ExecutionAuditContext) -> AuditDraft {
    AuditDraft {
        request_id: Some(ctx.request_id),
        session_id: Some(ctx.session_id),
        action_id: Some(ctx.action.action_id),
        action_version: Some(ctx.action.version),
        credential_id: Some(ctx.credential_id),
        credential_version: None,
        event_type: event_type::EXECUTION_STARTED,
        outcome: outcome::SUCCESS,
        reason_code: String::new(),
        upstream_status: None,
        latency_ms: None,
    }
}

pub fn execution_started(ctx: &ExecutionAuditContext) -> AuditDraft {
    let mut draft = base(ctx);
    draft.reason_code = "started".to_owned();
    draft
}

pub fn execution_finished(
    ctx: &ExecutionAuditContext,
    credential_version: u64,
    upstream_status: u16,
    latency_ms: i64,
) -> AuditDraft {
    let mut draft = base(ctx);
    draft.event_type = event_type::EXECUTION_FINISHED;
    draft.credential_version = Some(credential_version);
    draft.reason_code = "finished".to_owned();
    draft.upstream_status = Some(upstream_status);
    draft.latency_ms = Some(latency_ms);
    draft
}

pub fn execution_blocked(ctx: &ExecutionAuditContext, reason_code: &str) -> AuditDraft {
    let mut draft = base(ctx);
    draft.event_type = event_type::EXECUTION_BLOCKED;
    draft.outcome = outcome::DENIED;
    draft.reason_code = reason_code.to_owned();
    draft
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> AuditDraft {
        AuditDraft {
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            event_type: event_type::EXECUTION_BLOCKED,
            outcome: outcome::DENIED,
            reason_code: "abandoned".to_owned(),
            upstream_status: None,
            latency_ms: None,
        }
    }

    #[tokio::test]
    async fn wait_idle_errors_when_pending_times_out() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tracker = TerminalAuditTracker {
            tx,
            pending: Arc::new(AtomicUsize::new(1)),
            failed: Arc::new(AtomicBool::new(false)),
        };
        let err = tracker
            .wait_idle(Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthorityError::AuditCommitFailed));
        assert!(tracker.has_pending());
    }

    #[tokio::test]
    async fn wait_idle_errors_when_submit_channel_is_closed() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        let tracker = TerminalAuditTracker {
            tx,
            pending: Arc::new(AtomicUsize::new(0)),
            failed: Arc::new(AtomicBool::new(false)),
        };
        tracker.submit(draft());
        let err = tracker
            .wait_idle(Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthorityError::AuditCommitFailed));
        assert!(!tracker.has_pending());
    }

    #[tokio::test]
    async fn wait_idle_propagates_commit_error() {
        let (tracker, join) =
            spawn_terminal_worker_with(|_| async { Err(AuthorityError::AuditCommitFailed) });
        tracker.submit(draft());
        let err = tracker.wait_idle(Duration::from_secs(1)).await.unwrap_err();
        assert!(matches!(err, AuthorityError::AuditCommitFailed));
        drop(tracker);
        let _ = join.await;
    }

    #[tokio::test]
    async fn wait_idle_ok_when_commit_succeeds() {
        let (tracker, join) = spawn_terminal_worker_with(|_| async { Ok(()) });
        tracker.submit(draft());
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
        drop(tracker);
        let _ = join.await;
    }
}
