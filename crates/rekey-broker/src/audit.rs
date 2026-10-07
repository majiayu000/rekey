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
use rekey_vault::command::{AuditDraft, ProfileUsageStart};
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::{AuthorizationEvidence, UsageAdmission};
use rekey_vault::model::{event_type, outcome};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::error::BrokerError;
use crate::lifecycle::ConnectionExecutionPermit;
use crate::runtime::local_calls::ConnectionAdmission;

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
    Terminal(Box<TerminalSubmission>),
    Started(Box<StartedSubmission>),
}

struct TerminalSubmission {
    draft: AuditDraft,
    profile_usage: bool,
    measured_output_tokens: Option<u64>,
    reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
    connection_permit: Option<ConnectionExecutionPermit>,
}

struct StartedSubmission {
    drafts: Vec<AuditDraft>,
    profile_usage: Option<ProfileUsageStart>,
    not_after: Option<Instant>,
    wall_not_after_ms: Option<i64>,
    ctx: ExecutionAuditContext,
    queue: AuditSubmissionQueue,
    connection_admission: Option<ConnectionAdmission>,
    reply: oneshot::Sender<Result<Option<StartedAuditGuard>, AuthorityError>>,
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
    profile_usage: bool,
    measured_output_tokens: Option<u64>,
    connection_permit: Option<ConnectionExecutionPermit>,
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
            profile_usage: false,
            measured_output_tokens: None,
            connection_permit: None,
        }
    }

    pub(crate) fn record_profile_output(&mut self, measured: Option<u64>) {
        self.measured_output_tokens = measured;
    }

    fn enqueue_terminal(
        &mut self,
        draft: AuditDraft,
        reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
    ) {
        self.queue.enqueue_terminal_with_usage(
            draft,
            reply,
            self.profile_usage,
            self.measured_output_tokens,
            self.connection_permit.take(),
        );
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

    /// A transport refusal can prove that this target sent nothing. Retain
    /// any effect recorded before its handoff, such as an OAuth refresh.
    pub(crate) fn record_target_no_effect(&mut self, prior_remote_effect: bool) {
        self.remote_effect_started = prior_remote_effect;
    }

    pub(crate) fn remote_effect_started(&self) -> bool {
        self.remote_effect_started
    }

    pub(crate) fn submit_blocked(&mut self, reason: &'static str) {
        self.terminal_submitted = true;
        self.enqueue_terminal(execution_blocked(&self.ctx, reason), None);
    }

    pub(crate) fn submit_indeterminate(&mut self, reason: &'static str) {
        self.terminal_submitted = true;
        self.enqueue_terminal(execution_indeterminate(&self.ctx, reason), None);
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
        self.enqueue_terminal(draft, Some(reply));
        let result =
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), result).await {
                Ok(Ok(result)) => result.map_err(BrokerError::Authority),
                Ok(Err(_)) => Err(BrokerError::Authority(AuthorityError::AuditCommitFailed)),
                Err(_) => Err(BrokerError::Upstream("upstream-timeout")),
            };
        result.map_err(|error| {
            if self.remote_effect_started && error.retryable() {
                let reason = match error {
                    BrokerError::Upstream(reason) => reason,
                    _ => "terminal-audit-failed",
                };
                BrokerError::UpstreamUnconfirmed(reason)
            } else {
                error
            }
        })
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
            self.enqueue_terminal(draft, None);
        }
    }
}

impl AuditSubmissionQueue {
    fn enqueue_terminal(
        &self,
        draft: AuditDraft,
        reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
    ) {
        self.enqueue_terminal_with_usage(draft, reply, false, None, None);
    }

    fn enqueue_terminal_with_usage(
        &self,
        draft: AuditDraft,
        reply: Option<oneshot::Sender<Result<(), AuthorityError>>>,
        profile_usage: bool,
        measured_output_tokens: Option<u64>,
        connection_permit: Option<ConnectionExecutionPermit>,
    ) {
        self.enqueue(AuditSubmission::Terminal(Box::new(TerminalSubmission {
            draft,
            reply,
            profile_usage,
            measured_output_tokens,
            connection_permit,
        })));
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
        mut preceding: Vec<AuditDraft>,
        not_after: Option<Instant>,
        wall_not_after_ms: Option<i64>,
    ) -> Result<StartedAuditGuard, AuthorityError> {
        preceding.push(execution_started(&ctx));
        let (reply, result) = oneshot::channel();
        self.queue
            .enqueue(AuditSubmission::Started(Box::new(StartedSubmission {
                drafts: preceding,
                profile_usage: None,
                not_after,
                wall_not_after_ms,
                ctx,
                queue: self.queue.clone(),
                connection_admission: None,
                reply,
            })));
        match result.await {
            Ok(result) => result?.ok_or(AuthorityError::AuditCommitFailed),
            Err(_) => Err(AuthorityError::AuditCommitFailed),
        }
    }

    /// None is a normal budget denial: no started row and no terminal owner.
    pub(crate) async fn commit_profile_started(
        &self,
        ctx: ExecutionAuditContext,
        mut preceding: Vec<AuditDraft>,
        usage: ProfileUsageStart,
        not_after: Instant,
        wall_not_after_ms: Option<i64>,
    ) -> Result<Option<StartedAuditGuard>, AuthorityError> {
        preceding.push(execution_started(&ctx));
        let (reply, result) = oneshot::channel();
        self.queue
            .enqueue(AuditSubmission::Started(Box::new(StartedSubmission {
                drafts: preceding,
                profile_usage: Some(usage),
                not_after: Some(not_after),
                wall_not_after_ms,
                ctx,
                queue: self.queue.clone(),
                connection_admission: None,
                reply,
            })));
        result
            .await
            .map_err(|_| AuthorityError::AuditCommitFailed)?
    }

    pub fn has_pending(&self) -> bool {
        self.queue.pending.load(Ordering::SeqCst) > 0
    }

    /// Reservations belong to the durable worker before any await. A lost
    /// receiver cannot roll back an approval after started actually commits.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_connection_started(
        &self,
        ctx: ExecutionAuditContext,
        mut preceding: Vec<AuditDraft>,
        usage: Option<ProfileUsageStart>,
        not_after: Instant,
        wall_not_after_ms: i64,
        admission: ConnectionAdmission,
    ) -> Result<Option<StartedAuditGuard>, AuthorityError> {
        preceding.push(execution_started(&ctx));
        let (reply, result) = oneshot::channel();
        self.queue
            .enqueue(AuditSubmission::Started(Box::new(StartedSubmission {
                drafts: preceding,
                profile_usage: usage,
                not_after: Some(not_after),
                wall_not_after_ms: Some(wall_not_after_ms),
                ctx,
                queue: self.queue.clone(),
                connection_admission: Some(admission),
                reply,
            })));
        result
            .await
            .map_err(|_| AuthorityError::AuditCommitFailed)?
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
    spawn_terminal_worker_inner(
        Some(authority.clone()),
        move |drafts, not_after, wall_not_after_ms| {
            let authority = authority.clone();
            async move {
                authority
                    .commit_audits_before(drafts, not_after, wall_not_after_ms)
                    .await
            }
        },
    )
}

#[cfg(test)]
pub(crate) fn spawn_terminal_worker_with<F, Fut>(
    commit: F,
) -> (Arc<TerminalAuditTracker>, JoinHandle<()>)
where
    F: Fn(AuditDraft) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), AuthorityError>> + Send + 'static,
{
    let commit = Arc::new(commit);
    spawn_terminal_worker_with_batch(move |drafts, _, _| {
        let commit = Arc::clone(&commit);
        async move {
            for draft in drafts {
                commit(draft).await?;
            }
            Ok(())
        }
    })
}

#[cfg(test)]
fn spawn_terminal_worker_with_batch<F, Fut>(
    commit: F,
) -> (Arc<TerminalAuditTracker>, JoinHandle<()>)
where
    F: Fn(Vec<AuditDraft>, Option<Instant>, Option<i64>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AuthorityError>> + Send + 'static,
{
    spawn_terminal_worker_inner(None, commit)
}

fn spawn_terminal_worker_inner<F, Fut>(
    authority: Option<AuthorityHandle>,
    commit: F,
) -> (Arc<TerminalAuditTracker>, JoinHandle<()>)
where
    F: Fn(Vec<AuditDraft>, Option<Instant>, Option<i64>) -> Fut + Send + 'static,
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
                    let submission = *submission;
                    let result = if submission.profile_usage {
                        match (&authority, submission.draft.request_id) {
                            (Some(authority), Some(request_id)) => {
                                authority
                                    .settle_profile_execution(
                                        request_id,
                                        submission.measured_output_tokens,
                                        submission.draft,
                                    )
                                    .await
                            }
                            _ => Err(AuthorityError::AuditCommitFailed),
                        }
                    } else {
                        commit(vec![submission.draft], None, None).await
                    };
                    if result.is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                    // An uncommitted terminal drops an armed permit and
                    // closes remote admission before capacity is reused.
                    if let Some(permit) = submission.connection_permit
                        && result.is_ok()
                    {
                        permit.complete();
                    }
                    if let Some(reply) = submission.reply {
                        drop(reply.send(result));
                    }
                }
                AuditSubmission::Started(submission) => {
                    let StartedSubmission {
                        mut drafts,
                        profile_usage,
                        not_after,
                        wall_not_after_ms,
                        ctx,
                        queue,
                        mut connection_admission,
                        reply,
                    } = *submission;
                    let mut result = if let Some(usage) = profile_usage {
                        match (&authority, drafts.pop(), not_after) {
                            (Some(authority), Some(started), Some(not_after)) => authority
                                .begin_profile_execution(
                                    usage,
                                    drafts,
                                    started,
                                    not_after,
                                    wall_not_after_ms,
                                )
                                .await
                                .map(|admission| match admission {
                                    UsageAdmission::BudgetDenied => None,
                                    UsageAdmission::Started => {
                                        let mut guard = StartedAuditGuard::new(queue, ctx);
                                        guard.profile_usage = true;
                                        Some(guard)
                                    }
                                }),
                            _ => Err(AuthorityError::AuditCommitFailed),
                        }
                    } else {
                        commit(drafts, not_after, wall_not_after_ms)
                            .await
                            .map(|()| Some(StartedAuditGuard::new(queue, ctx)))
                    };
                    if let Ok(Some(guard)) = &mut result {
                        guard.connection_permit =
                            connection_admission.take().map(ConnectionAdmission::commit);
                    }
                    // Roll back rejected admission before publishing its
                    // error or budget denial to the requester.
                    drop(connection_admission);
                    if matches!(&result, Err(error) if !matches!(error, AuthorityError::AuthorityBusy))
                    {
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
    pub request_context: Option<rekey_domain::audit::RequestAuditContext>,
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
        approval: None,
        request_context: ctx.request_context.clone(),
        usage: None,
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
            approval: None,
            request_context: None,
            usage: None,
            event_type: event_type::EXECUTION_BLOCKED,
            outcome: outcome::DENIED,
            reason_code: "abandoned".to_owned(),
            upstream_status: None,
            latency_ms: None,
        }
    }

    fn execution_context() -> ExecutionAuditContext {
        ExecutionAuditContext {
            request_context: None,
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

    fn connection_admission(
        lifecycle: &Arc<crate::lifecycle::Lifecycle>,
        calls: &Arc<crate::runtime::local_calls::LocalCalls>,
        approval: &crate::runtime::local_calls::LocalCallApproval,
    ) -> ConnectionAdmission {
        ConnectionAdmission {
            approval: Some(crate::runtime::local_calls::tests::reserve(calls, approval).unwrap()),
            rate: calls
                .reserve_rate("fixture", 1, Duration::from_secs(3600))
                .unwrap(),
            permit: lifecycle.connection_permit("fixture").unwrap(),
        }
    }

    #[tokio::test]
    async fn connection_admission_survives_cancelled_reply_through_terminal_commit() {
        use crate::runtime::local_calls::{LocalCalls, tests::approved};
        let lifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let calls = Arc::new(LocalCalls::default());
        let approval = approved(&calls);
        let entered = Arc::new(Notify::new());
        let start_release = Arc::new(Notify::new());
        let terminal_entered = Arc::new(Notify::new());
        let terminal_release = Arc::new(Notify::new());
        let committed = Arc::new(Mutex::new(Vec::new()));
        let (tracker, worker) = spawn_terminal_worker_with({
            let entered = entered.clone();
            let start_release = start_release.clone();
            let terminal_entered = terminal_entered.clone();
            let terminal_release = terminal_release.clone();
            let committed = committed.clone();
            move |draft| {
                let entered = entered.clone();
                let start_release = start_release.clone();
                let terminal_entered = terminal_entered.clone();
                let terminal_release = terminal_release.clone();
                let committed = committed.clone();
                async move {
                    if draft.event_type == event_type::EXECUTION_STARTED {
                        entered.notify_one();
                        start_release.notified().await;
                    } else {
                        terminal_entered.notify_one();
                        terminal_release.notified().await;
                    }
                    committed.lock().unwrap().push(draft.event_type);
                    Ok(())
                }
            }
        });
        let admission = connection_admission(&lifecycle, &calls, &approval);
        let caller = tokio::spawn({
            let tracker = tracker.clone();
            async move {
                tracker
                    .commit_connection_started(
                        execution_context(),
                        Vec::new(),
                        None,
                        Instant::now() + Duration::from_secs(10),
                        crate::now_ts().unwrap().as_unix_ms() + 10_000,
                        admission,
                    )
                    .await
            }
        });
        entered.notified().await;
        caller.abort();
        drop(caller.await);
        assert_eq!(lifecycle.local_in_flight(), 1);
        assert!(crate::runtime::local_calls::tests::reserve(&calls, &approval).is_err());
        start_release.notify_one();
        terminal_entered.notified().await;
        assert_eq!(
            calls
                .get(
                    approval.challenge.approval_request_id,
                    crate::now_ts().unwrap().as_unix_ms()
                )
                .unwrap()
                .state,
            rekey_domain::ipc::LocalApprovalState::Consumed
        );
        assert_eq!(
            lifecycle.local_in_flight(),
            1,
            "queued terminal still owns capacity"
        );
        terminal_release.notify_one();
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
        assert_eq!(lifecycle.local_in_flight(), 0);
        assert!(lifecycle.try_begin_remote_effect());
        assert_eq!(
            *committed.lock().unwrap(),
            [event_type::EXECUTION_STARTED, event_type::EXECUTION_BLOCKED]
        );
        drop(tracker);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_connection_started_returns_approval_rate_and_capacity_before_reply() {
        use crate::runtime::local_calls::{
            LocalCalls,
            tests::{approved, reserve},
        };
        for fault in [false, true] {
            let lifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
            lifecycle.enter_running().unwrap();
            let calls = Arc::new(LocalCalls::default());
            let approval = approved(&calls);
            let (tracker, worker) = spawn_terminal_worker_with(move |_| async move {
                Err(if fault {
                    AuthorityError::AuditCommitFailed
                } else {
                    AuthorityError::AuthorityBusy
                })
            });
            let result = tracker
                .commit_connection_started(
                    execution_context(),
                    Vec::new(),
                    None,
                    Instant::now() + Duration::from_secs(10),
                    crate::now_ts().unwrap().as_unix_ms() + 10_000,
                    connection_admission(&lifecycle, &calls, &approval),
                )
                .await;
            assert!(result.is_err());
            assert_eq!(lifecycle.local_in_flight(), 0);
            assert_eq!(tracker.has_failed(), fault);
            drop(reserve(&calls, &approval).unwrap());
            drop(
                calls
                    .reserve_rate("fixture", 1, Duration::from_secs(3600))
                    .unwrap(),
            );
            drop(tracker);
            worker.await.unwrap();
        }
    }

    #[tokio::test]
    async fn connection_terminal_failure_closes_remote_admission() {
        use crate::runtime::local_calls::{LocalCalls, tests::approved};
        let lifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let calls = Arc::new(LocalCalls::default());
        let approval = approved(&calls);
        let (tracker, worker) = spawn_terminal_worker_with(|draft| async move {
            if draft.event_type == event_type::EXECUTION_STARTED {
                Ok(())
            } else {
                Err(AuthorityError::AuditCommitFailed)
            }
        });
        let guard = tracker
            .commit_connection_started(
                execution_context(),
                Vec::new(),
                None,
                Instant::now() + Duration::from_secs(10),
                crate::now_ts().unwrap().as_unix_ms() + 10_000,
                connection_admission(&lifecycle, &calls, &approval),
            )
            .await
            .unwrap()
            .unwrap();
        drop(guard);
        assert!(tracker.wait_idle(Duration::from_secs(1)).await.is_err());
        assert_eq!(lifecycle.local_in_flight(), 0);
        assert!(!lifecycle.try_begin_remote_effect());
        drop(tracker);
        worker.await.unwrap();
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
            async move {
                tracker
                    .commit_started(execution_context(), Vec::new(), None, None)
                    .await
            }
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
    async fn started_commit_carries_approval_deadline() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let (tracker, worker) = spawn_terminal_worker_with_batch({
            let observed = Arc::clone(&observed);
            move |_, not_after, wall_not_after_ms| {
                observed
                    .lock()
                    .unwrap()
                    .push((not_after, wall_not_after_ms));
                async { Ok(()) }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let wall_deadline_ms = 1_900_000_000_000;
        let mut guard = tracker
            .commit_started(
                execution_context(),
                Vec::new(),
                Some(deadline),
                Some(wall_deadline_ms),
            )
            .await
            .unwrap();
        guard.submit_blocked("test-complete");
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            observed.lock().unwrap()[0],
            (Some(deadline), Some(wall_deadline_ms))
        );
        drop(guard);
        drop(tracker);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn expired_started_admission_does_not_poison_tracker() {
        let (tracker, worker) = spawn_terminal_worker_with_batch(|_, _, _| async {
            Err(AuthorityError::AuthorityBusy)
        });
        let error = match tracker
            .commit_started(
                execution_context(),
                Vec::new(),
                Some(Instant::now()),
                Some(0),
            )
            .await
        {
            Ok(_) => panic!("expired admission unexpectedly committed"),
            Err(error) => error,
        };
        assert!(matches!(error, AuthorityError::AuthorityBusy));
        tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
        assert!(!tracker.has_failed());
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
