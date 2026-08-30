//! The single irreversible BrokerRuntime stop path.

use std::time::Duration;

use rekey_vault::AuthorityError;
use rekey_vault::command::UnlockProof;
use tokio::task::JoinHandle;

use super::BrokerCtx;
use crate::error::BrokerError;
use crate::lifecycle::BrokerPhase;

const FINALIZE_GRACE: Duration = Duration::from_secs(5);

pub(super) enum StopCommand {
    Admin {
        proof: Option<UnlockProof>,
        reply: tokio::sync::oneshot::Sender<Result<(), BrokerError>>,
    },
    Fault,
}

pub(super) enum StopCause {
    Admin(Option<UnlockProof>),
    Signal,
    Fault,
}

pub(super) enum StopDisposition {
    Rejected(BrokerError),
    Stopped(Option<BrokerError>),
}

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
    ) -> StopDisposition {
        let lock_reason = match &cause {
            StopCause::Admin(_) => "admin-shutdown",
            StopCause::Signal => "service-manager-signal",
            StopCause::Fault => "runtime-fault",
        };
        let owner = match tokio::time::timeout_at(stop_deadline, self.lifecycle.coordinate()).await
        {
            Ok(owner) => owner,
            Err(_) => {
                self.publish_shutdown();
                execution_task.abort();
                return StopDisposition::Stopped(Some(BrokerError::Authority(
                    AuthorityError::Faulted,
                )));
            }
        };

        let mut first_error = matches!(cause, StopCause::Fault)
            .then_some(BrokerError::Authority(AuthorityError::Faulted));
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

        if let StopCause::Admin(proof) = cause
            && status
                .as_ref()
                .is_some_and(|status| status.state == "unlocked")
        {
            let Some(proof) = proof else {
                drop(owner);
                return StopDisposition::Rejected(BrokerError::Authority(
                    AuthorityError::AuthenticationFailed,
                ));
            };
            match tokio::time::timeout_at(stop_deadline, self.authority.verify_proof(proof)).await {
                Ok(Ok(())) => {}
                Ok(Err(
                    err @ (AuthorityError::AuthenticationFailed
                    | AuthorityError::InvalidUnlockCredential
                    | AuthorityError::UnlockRateLimited),
                )) => {
                    drop(owner);
                    return StopDisposition::Rejected(BrokerError::Authority(err));
                }
                Ok(Err(err)) => remember(&mut first_error, BrokerError::Authority(err)),
                Err(_) => {
                    remember(
                        &mut first_error,
                        BrokerError::Authority(AuthorityError::Faulted),
                    );
                }
            }
        }

        if self.lifecycle.phase() == BrokerPhase::Running {
            self.lifecycle.enter_draining();
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

        match tokio::time::timeout_at(stop_deadline, &mut *execution_task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => remember(&mut first_error, err),
            Ok(Err(_)) => remember(
                &mut first_error,
                BrokerError::Authority(AuthorityError::Faulted),
            ),
            Err(_) => {
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

        if status
            .as_ref()
            .is_some_and(|status| status.state == "unlocked")
        {
            match tokio::time::timeout_at(stop_deadline, self.authority.lock(lock_reason)).await {
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
