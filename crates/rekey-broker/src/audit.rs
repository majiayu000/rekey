//! Execution audit event construction. Events are built here in the broker
//! pipeline but persisted only through the AuthorityWorker's transaction.
//! Field discipline: identifiers, codes, and counters — never secrets,
//! bodies, or raw errors.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{CredentialId, RequestId, SessionId};
use rekey_vault::AuthorityError;
use rekey_vault::command::AuditDraft;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::AuthorizationEvidence;
use rekey_vault::model::{event_type, outcome};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::error::BrokerError;

/// Accepts terminal audits from Drop/panic paths and waits them to commit
/// before Authority shutdown. Commit errors and timeouts are never ignored.
pub struct TerminalAuditTracker {
    queue: AuditSubmissionQueue,
}

#[derive(Clone)]
struct AuditSubmissionQueue {
    tx: mpsc::UnboundedSender<AuditSubmission>,
    pending: Arc<AtomicUsize>,
    failed: Arc<AtomicBool>,
}

enum AuditSubmission {
    Terminal(TerminalSubmission),
    Started(Box<StartedSubmission>),
}

struct TerminalSubmission {
    draft: AuditDraft,
    reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
}

struct StartedSubmission {
    draft: AuditDraft,
    ctx: ExecutionAuditContext,
    queue: AuditSubmissionQueue,
    reply: oneshot::Sender<Result<StartedAuditGuard, AuthorityError>>,
}

/// Unique ownership of the terminal event paired with a committed
/// `execution.started`. The owner itself crosses the worker reply channel, so
/// cancellation anywhere in that handoff drops the guard and durably queues
/// the fallback terminal.
pub(crate) struct StartedAuditGuard {
    queue: AuditSubmissionQueue,
    ctx: ExecutionAuditContext,
    terminal_submitted: bool,
    remote_effect_started: bool,
}

impl StartedAuditGuard {
    #[cfg(test)]
    pub(crate) fn new_for_test(tracker: &TerminalAuditTracker, ctx: ExecutionAuditContext) -> Self {
        Self::new(tracker.queue.clone(), ctx)
    }

    fn new(queue: AuditSubmissionQueue, ctx: ExecutionAuditContext) -> Self {
        Self {
            queue,
            ctx,
            terminal_submitted: false,
            remote_effect_started: false,
        }
    }

    pub(crate) fn context(&self) -> &ExecutionAuditContext {
        &self.ctx
    }

    pub(crate) fn is_completed(&self) -> bool {
        self.terminal_submitted
    }

    pub(crate) fn mark_remote_effect_started(&mut self) {
        self.remote_effect_started = true;
    }

    pub(crate) fn submit_blocked(&mut self, reason: &'static str) {
        self.terminal_submitted = true;
        self.queue
            .enqueue_terminal(execution_blocked(&self.ctx, reason), None);
    }

    pub(crate) fn submit_indeterminate(&mut self, reason: &'static str) {
        self.terminal_submitted = true;
        self.queue
            .enqueue_terminal(execution_indeterminate(&self.ctx, reason), None);
    }

    pub(crate) async fn blocked_until(
        &mut self,
        deadline: Instant,
        reason: &'static str,
    ) -> Result<(), BrokerError> {
        self.commit_terminal_until(execution_blocked(&self.ctx, reason), deadline)
            .await
    }

    pub(crate) async fn indeterminate_until(
        &mut self,
        deadline: Instant,
        reason: &'static str,
    ) -> Result<(), BrokerError> {
        self.commit_terminal_until(execution_indeterminate(&self.ctx, reason), deadline)
            .await
    }

    pub(crate) async fn finished_until(
        &mut self,
        deadline: Instant,
        credential_version: u64,
        upstream_status: u16,
        latency_ms: i64,
    ) -> Result<(), BrokerError> {
        self.commit_terminal_until(
            execution_finished(&self.ctx, credential_version, upstream_status, latency_ms),
            deadline,
        )
        .await
        .map_err(|err| match err {
            BrokerError::Authority(AuthorityError::AuditCommitFailed) => {
                BrokerError::Authority(AuthorityError::AuditCommitFailedAfterExecution)
            }
            other => other,
        })
    }

    async fn commit_terminal_until(
        &mut self,
        draft: AuditDraft,
        deadline: Instant,
    ) -> Result<(), BrokerError> {
        self.terminal_submitted = true;
        let (reply, result) = oneshot::channel();
        self.queue.enqueue_terminal(draft, Some(reply));
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), result).await {
            Ok(Ok(result)) => result.map_err(BrokerError::Authority),
            Ok(Err(_)) => Err(BrokerError::Authority(AuthorityError::AuditCommitFailed)),
            Err(_) => Err(BrokerError::Upstream("upstream-timeout")),
        }
    }
}

impl Drop for StartedAuditGuard {
    fn drop(&mut self) {
        if !self.terminal_submitted {
            let draft = if self.remote_effect_started {
                execution_indeterminate(&self.ctx, "abandoned-after-remote-effect")
            } else {
                execution_blocked(&self.ctx, "abandoned")
            };
            self.queue.enqueue_terminal(draft, None);
        }
    }
}

impl AuditSubmissionQueue {
    fn enqueue_terminal(
        &self,
        draft: AuditDraft,
        reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
    ) {
        self.enqueue(AuditSubmission::Terminal(TerminalSubmission {
            draft,
            reply,
        }));
    }

    fn enqueue(&self, submission: AuditSubmission) {
        self.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(submission).is_err() {
            self.failed.store(true, Ordering::SeqCst);
            self.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl TerminalAuditTracker {
    pub fn submit(&self, draft: AuditDraft) {
        self.queue.enqueue_terminal(draft, None);
    }

    /// Transfers ownership of a terminal commit to the tracker before the
    /// first await. Cancelling the caller cannot cancel the durable commit.
    pub async fn commit(&self, draft: AuditDraft) -> Result<(), AuthorityError> {
        let (reply, result) = oneshot::channel();
        self.queue.enqueue_terminal(draft, Some(reply));
        match result.await {
            Ok(result) => result,
            Err(_) => Err(AuthorityError::AuditCommitFailed),
        }
    }

    /// Transfers an audit commit to the tracker before applying the caller's
    /// absolute deadline. Timeout cannot cancel the queued durable write.
    pub(crate) async fn commit_until(
        &self,
        deadline: Instant,
        draft: AuditDraft,
    ) -> Result<(), BrokerError> {
        let (reply, result) = oneshot::channel();
        self.queue.enqueue_terminal(draft, Some(reply));
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), result).await {
            Ok(Ok(result)) => result.map_err(BrokerError::Authority),
            Ok(Err(_)) => Err(BrokerError::Authority(AuthorityError::AuditCommitFailed)),
            Err(_) => Err(BrokerError::Upstream("upstream-timeout")),
        }
    }

    /// Transfers `execution.started` commit and its future terminal ownership
    /// to the worker before awaiting Authority capacity or a reply.
    pub(crate) async fn commit_started(
        &self,
        ctx: ExecutionAuditContext,
    ) -> Result<StartedAuditGuard, AuthorityError> {
        let draft = execution_started(&ctx);
        let (reply, result) = oneshot::channel();
        self.queue
            .enqueue(AuditSubmission::Started(Box::new(StartedSubmission {
                draft,
                ctx,
                queue: self.queue.clone(),
                reply,
            })));
        match result.await {
            Ok(result) => result,
            Err(_) => Err(AuthorityError::AuditCommitFailed),
        }
    }

    pub fn has_pending(&self) -> bool {
        self.queue.pending.load(Ordering::SeqCst) > 0
    }

    pub fn has_failed(&self) -> bool {
        self.queue.failed.load(Ordering::SeqCst)
    }

    /// Returns `Err(AuditCommitFailed)` if a terminal is still queued after
    /// `timeout`, or if any commit/submit failed. Callers must not treat
    /// lock/shutdown as success when this errors.
    pub async fn wait_idle(&self, timeout: Duration) -> Result<(), AuthorityError> {
        self.wait_idle_until(tokio::time::Instant::now() + timeout)
            .await
    }

    /// Same contract using the central stop's absolute deadline. Callers must
    /// not create a fresh relative timeout at each shutdown layer.
    pub async fn wait_idle_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), AuthorityError> {
        loop {
            if self.queue.pending.load(Ordering::SeqCst) == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AuthorityError::AuditCommitFailed);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if self.queue.failed.load(Ordering::SeqCst) {
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
    let (tx, mut rx) = mpsc::unbounded_channel::<AuditSubmission>();
    let pending = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let queue = AuditSubmissionQueue {
        tx,
        pending: Arc::clone(&pending),
        failed: Arc::clone(&failed),
    };
    let join = tokio::spawn(async move {
        while let Some(submission) = rx.recv().await {
            match submission {
                AuditSubmission::Terminal(submission) => {
                    let result = commit(submission.draft).await;
                    if result.is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                    if let Some(reply) = submission.reply {
                        drop(reply.send(result));
                    }
                }
                AuditSubmission::Started(submission) => {
                    let StartedSubmission {
                        draft,
                        ctx,
                        queue,
                        reply,
                    } = *submission;
                    let result = commit(draft)
                        .await
                        .map(|()| StartedAuditGuard::new(queue, ctx));
                    if result.is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                    // If the caller was cancelled before receiving the
                    // committed ownership, send returns the armed guard and
                    // dropping it queues the fallback terminal synchronously.
                    drop(reply.send(result));
                }
            }
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    (Arc::new(TerminalAuditTracker { queue }), join)
}

pub struct ExecutionAuditContext {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub action: ActionVersionRef,
    pub credential_id: CredentialId,
    pub authorization: Option<AuthorizationEvidence>,
}

fn base(ctx: &ExecutionAuditContext) -> AuditDraft {
    AuditDraft {
        request_id: Some(ctx.request_id),
        session_id: Some(ctx.session_id),
        action_id: Some(ctx.action.action_id),
        action_version: Some(ctx.action.version),
        credential_id: Some(ctx.credential_id),
        credential_version: None,
        authorization: ctx.authorization.clone().map(Box::new),
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

pub fn execution_indeterminate(ctx: &ExecutionAuditContext, reason_code: &str) -> AuditDraft {
    let mut draft = base(ctx);
    draft.event_type = event_type::EXECUTION_INDETERMINATE;
    draft.outcome = outcome::UNKNOWN;
    draft.reason_code = reason_code.to_owned();
    draft
}

pub fn connector_event(
    ctx: &ExecutionAuditContext,
    event_type: &'static str,
    event_outcome: &'static str,
    reason_code: String,
) -> AuditDraft {
    let mut draft = base(ctx);
    draft.event_type = event_type;
    draft.outcome = event_outcome;
    draft.reason_code = reason_code;
    draft
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rekey_domain::ids::ActionId;
    use tokio::sync::{Barrier, Notify};

    use super::*;

    fn draft() -> AuditDraft {
        AuditDraft {
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            event_type: event_type::EXECUTION_BLOCKED,
            outcome: outcome::DENIED,
            reason_code: "abandoned".to_owned(),
            upstream_status: None,
            latency_ms: None,
        }
    }

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
    async fn started_commit_reply_cancellation_still_has_terminal() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let committed = Arc::new(Mutex::new(Vec::new()));
        let (tracker, worker) = spawn_terminal_worker_with({
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let committed = Arc::clone(&committed);
            move |draft| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                committed.lock().unwrap().push((
                    draft.event_type,
                    draft.outcome,
                    draft.reason_code.clone(),
                ));
                async move {
                    if draft.event_type == event_type::EXECUTION_STARTED {
                        entered.wait().await;
                        release.wait().await;
                    }
                    Ok(())
                }
            }
        });
        let caller = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.commit_started(execution_context()).await }
        });
        entered.wait().await;
        caller.abort();
        drop(caller.await);
        release.wait().await;
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();

        {
            let committed = committed.lock().unwrap();
            assert_eq!(committed.len(), 2, "expected started plus one terminal");
            assert_eq!(
                committed[0],
                ("execution.started", "success", "started".into())
            );
            assert_eq!(
                committed[1],
                ("execution.blocked", "denied", "abandoned".into())
            );
        }
        drop(tracker);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn deferred_blocked_terminal_is_queued_exactly_once() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let (tracker, worker) = spawn_terminal_worker_with({
            let committed = Arc::clone(&committed);
            move |draft| {
                committed.lock().unwrap().push((
                    draft.event_type,
                    draft.outcome,
                    draft.reason_code.clone(),
                ));
                async { Ok(()) }
            }
        });
        let mut guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
        guard.submit_blocked("upstream-timeout");
        drop(guard);
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();

        assert_eq!(
            committed.lock().unwrap().as_slice(),
            &[("execution.blocked", "denied", "upstream-timeout".to_owned())]
        );
        drop(tracker);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn timed_out_connector_audit_stays_ordered_before_terminal() {
        let release = Arc::new(Notify::new());
        let committed = Arc::new(Mutex::new(Vec::new()));
        let (tracker, worker) = spawn_terminal_worker_with({
            let release = Arc::clone(&release);
            let committed = Arc::clone(&committed);
            move |draft| {
                let release = Arc::clone(&release);
                committed.lock().unwrap().push(draft.event_type);
                async move {
                    if draft.event_type == event_type::GITHUB_TOKEN_REVOKED {
                        release.notified().await;
                    }
                    Ok(())
                }
            }
        });
        let mut connector = draft();
        connector.event_type = event_type::GITHUB_TOKEN_REVOKED;
        let error = tracker
            .commit_until(Instant::now() + Duration::from_millis(20), connector)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "UPSTREAM_FAILED");

        let mut guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
        guard.mark_remote_effect_started();
        guard.submit_indeterminate("upstream-timeout");
        drop(guard);
        release.notify_one();
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();

        assert_eq!(
            committed.lock().unwrap().as_slice(),
            &[
                event_type::GITHUB_TOKEN_REVOKED,
                event_type::EXECUTION_INDETERMINATE
            ]
        );
        drop(tracker);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn wait_idle_errors_when_pending_times_out() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tracker = TerminalAuditTracker {
            queue: AuditSubmissionQueue {
                tx,
                pending: Arc::new(AtomicUsize::new(1)),
                failed: Arc::new(AtomicBool::new(false)),
            },
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
            queue: AuditSubmissionQueue {
                tx,
                pending: Arc::new(AtomicUsize::new(0)),
                failed: Arc::new(AtomicBool::new(false)),
            },
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
