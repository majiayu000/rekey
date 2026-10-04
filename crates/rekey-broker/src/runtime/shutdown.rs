//! The single irreversible BrokerRuntime stop path.

use std::time::Duration;

use rekey_vault::AuthorityError;
use rekey_vault::command::UnlockProof;
use tokio::task::{JoinError, JoinHandle};

use super::BrokerCtx;
use crate::error::BrokerError;
use crate::lifecycle::BrokerPhase;

const FINALIZE_GRACE: Duration = Duration::from_secs(5);

pub(super) enum StopCommand {
    Admin {
        proof: UnlockProof,
        reply: tokio::sync::oneshot::Sender<Result<(), BrokerError>>,
    },
    Fault,
}

pub(super) enum StopCause {
    Admin(UnlockProof),
    Signal,
    Fault,
}

pub(super) enum StopDisposition {
    Rejected(BrokerError),
    Stopped(Option<BrokerError>),
}

pub(super) type ExecutionTaskResult = Result<Result<(), BrokerError>, JoinError>;

pub(super) fn deadline(drain_timeout: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + drain_timeout + FINALIZE_GRACE
}

fn remember(first: &mut Option<BrokerError>, error: BrokerError) {
    if first.is_none() {
        *first = Some(error);
    }
}

async fn wait_in_flight_until(ctx: &BrokerCtx, deadline: tokio::time::Instant) {
    while ctx.sessions.in_flight_total() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

impl BrokerCtx {
    pub(super) async fn central_stop(
        &self,
        cause: StopCause,
        stop_deadline: tokio::time::Instant,
        execution_task: &mut JoinHandle<Result<(), BrokerError>>,
        completed_execution: Option<ExecutionTaskResult>,
    ) -> StopDisposition {
        let preserve_desktop = !matches!(&cause, StopCause::Fault);
        let lock_reason = match &cause {
            StopCause::Admin(_) => "admin-shutdown",
            StopCause::Signal => "service-manager-signal",
            StopCause::Fault => "runtime-fault",
        };
        let must_record_signal_lock = matches!(&cause, StopCause::Signal);
        let owner = match tokio::time::timeout_at(stop_deadline, self.lifecycle.coordinate()).await
        {
            Ok(owner) => owner,
            Err(_) if matches!(&cause, StopCause::Admin(_)) => {
                return StopDisposition::Rejected(BrokerError::Admission(
                    AuthorityError::AuthorityBusy,
                ));
            }
            Err(_) => {
                self.publish_shutdown();
                if completed_execution.is_none() {
                    execution_task.abort();
                }
                return StopDisposition::Stopped(Some(BrokerError::Authority(
                    AuthorityError::Faulted,
                )));
            }
        };

        let terminal_audit_failed = self.terminals.has_failed();
        let mut first_error = if terminal_audit_failed {
            Some(BrokerError::Authority(AuthorityError::AuditCommitFailed))
        } else {
            matches!(cause, StopCause::Fault)
                .then_some(BrokerError::Authority(AuthorityError::Faulted))
        };
        let status = match tokio::time::timeout_at(stop_deadline, self.authority.status()).await {
            Ok(Ok(status)) => Some(status),
            Ok(Err(err)) => {
                remember(&mut first_error, BrokerError::Authority(err));
                None
            }
            Err(_) => {
                remember(
                    &mut first_error,
                    BrokerError::Authority(AuthorityError::Faulted),
                );
                None
            }
        };

        if let StopCause::Admin(proof) = cause {
            match tokio::time::timeout_at(
                stop_deadline,
                self.authority.verify_shutdown_proof(proof),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    // Authentication failure never authorizes stopping. A worker
                    // fault is routed separately through the internal fault path.
                    if matches!(
                        err,
                        AuthorityError::Faulted
                            | AuthorityError::AuditCommitFailed
                            | AuthorityError::StorageIntegrityFailed
                    ) {
                        self.request_fault();
                    }
                    drop(owner);
                    return StopDisposition::Rejected(BrokerError::Authority(err));
                }
                Err(_) => {
                    drop(owner);
                    return StopDisposition::Rejected(BrokerError::Authority(
                        AuthorityError::AuthorityBusy,
                    ));
                }
            }
            self.lifecycle.mark_stop_pending();
        }

        if self.lifecycle.phase() == BrokerPhase::Running {
            self.lifecycle.enter_draining();
        }
        #[cfg(feature = "lab")]
        if let Some(manager) = &self.oidc_admin {
            manager.clear();
        }
        self.sessions.close_and_revoke_all();
        self.publish_shutdown();

        let natural_deadline = stop_deadline
            .checked_sub(FINALIZE_GRACE)
            .unwrap_or(stop_deadline);
        wait_in_flight_until(self, natural_deadline).await;
        if self.sessions.in_flight_total() > 0 {
            self.lifecycle.signal_cancel();
            wait_in_flight_until(self, stop_deadline).await;
        }
        if self.sessions.in_flight_total() > 0 {
            remember(
                &mut first_error,
                BrokerError::Authority(AuthorityError::AuthorityBusy),
            );
        }

        let execution_result = match completed_execution {
            Some(result) => Some(result),
            None => tokio::time::timeout_at(stop_deadline, &mut *execution_task)
                .await
                .ok(),
        };
        match execution_result {
            Some(Ok(Ok(()))) => {}
            Some(Ok(Err(err))) => remember(&mut first_error, err),
            Some(Err(_)) => remember(
                &mut first_error,
                BrokerError::Authority(AuthorityError::Faulted),
            ),
            None => {
                execution_task.abort();
                remember(
                    &mut first_error,
                    BrokerError::Authority(AuthorityError::Faulted),
                );
            }
        }

        if let Err(err) = self.terminals.wait_idle_until(stop_deadline).await {
            remember(&mut first_error, BrokerError::Authority(err));
        }
        if self.terminals.has_pending() {
            // Never enqueue Authority lock/shutdown behind terminal work that
            // still belongs to the independent tracker. The bounded runtime
            // exits non-zero; restart reconciliation closes durable started
            // rows, but this stop must not claim or reorder a clean shutdown.
            self.lifecycle.enter_shutting_down();
            self.publish_shutdown();
            drop(owner);
            return StopDisposition::Stopped(first_error.or(Some(BrokerError::Authority(
                AuthorityError::AuditCommitFailed,
            ))));
        }

        if !preserve_desktop
            || must_record_signal_lock
            || status
                .as_ref()
                .is_some_and(|status| status.state == "unlocked")
        {
            let lock = async {
                if !preserve_desktop || first_error.is_some() {
                    self.authority.lock(lock_reason).await
                } else {
                    self.authority.lock_for_restart(lock_reason).await
                }
            };
            match tokio::time::timeout_at(stop_deadline, lock).await {
                Ok(Ok(())) => {
                    *self.policy.write().await = None;
                    self.lifecycle.enter_locked();
                    tracing::info!(
                        event = "authority.state",
                        state = "locked",
                        reason = lock_reason
                    );
                }
                Ok(Err(err)) => remember(&mut first_error, BrokerError::Authority(err)),
                Err(_) => remember(
                    &mut first_error,
                    BrokerError::Authority(AuthorityError::Faulted),
                ),
            }
        }

        self.lifecycle.enter_shutting_down();
        match tokio::time::timeout_at(stop_deadline, self.authority.shutdown(None)).await {
            Ok(Ok(())) => {
                *self.policy.write().await = None;
                tracing::info!(event = "authority.state", state = "shutting_down");
            }
            Ok(Err(err)) => remember(&mut first_error, BrokerError::Authority(err)),
            Err(_) => remember(
                &mut first_error,
                BrokerError::Authority(AuthorityError::Faulted),
            ),
        }
        self.publish_shutdown();
        drop(owner);
        StopDisposition::Stopped(first_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_vault::secret::SecretInput;

    #[tokio::test]
    async fn rejected_admin_stop_never_publishes_aborts_or_reopens_another_drain() {
        for blocked in [false, true] {
            for draining in [false, true] {
                let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
                if draining {
                    ctx.lifecycle.enter_draining();
                }
                let owner = if blocked {
                    Some(ctx.lifecycle.coordinate().await)
                } else {
                    None
                };
                let mut execution = tokio::spawn(std::future::pending::<Result<(), BrokerError>>());
                let outcome = ctx
                    .central_stop(
                        StopCause::Admin(UnlockProof::Password(SecretInput::from_slice(b"wrong"))),
                        tokio::time::Instant::now() + Duration::from_millis(40),
                        &mut execution,
                        None,
                    )
                    .await;
                let StopDisposition::Rejected(error) = outcome else {
                    panic!("Admin must be rejected")
                };
                assert_eq!(
                    error.code(),
                    if blocked {
                        "AUTHORITY_BUSY"
                    } else {
                        "INVALID_UNLOCK_CREDENTIAL"
                    }
                );
                assert!(!ctx.shutdown_requested());
                assert!(!execution.is_finished());
                assert_eq!(
                    ctx.lifecycle.phase(),
                    if draining {
                        BrokerPhase::Draining
                    } else {
                        BrokerPhase::Running
                    }
                );
                assert_eq!(ctx.lifecycle.try_begin_remote_effect(), !draining);
                drop(owner);
                ctx.authority.lock("test-cleanup").await.unwrap();
                ctx.authority.shutdown(None).await.unwrap();
                execution.abort();
                let _ = execution.await;
                drop(ctx);
                terminal.await.unwrap();
                join.join().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn signal_and_fault_coordinator_timeouts_still_stop() {
        for cause in [StopCause::Signal, StopCause::Fault] {
            let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
            let owner = ctx.lifecycle.coordinate().await;
            let mut execution = tokio::spawn(std::future::pending::<Result<(), BrokerError>>());
            let outcome = ctx
                .central_stop(
                    cause,
                    tokio::time::Instant::now() + Duration::from_millis(20),
                    &mut execution,
                    None,
                )
                .await;
            assert!(matches!(outcome, StopDisposition::Stopped(Some(_))));
            assert!(ctx.shutdown_requested());
            assert!(execution.await.unwrap_err().is_cancelled());
            drop(owner);
            ctx.authority.lock("test-cleanup").await.unwrap();
            ctx.authority.shutdown(None).await.unwrap();
            drop(ctx);
            terminal.await.unwrap();
            join.join().unwrap();
        }
    }
}
