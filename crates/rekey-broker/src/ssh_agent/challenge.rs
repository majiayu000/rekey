//! One pending SSH challenge: wait for its local decision, and cancel it on
//! every exit that does not consume it.
use std::sync::Arc;
use std::time::Instant;

use rekey_domain::ids::ApprovalRequestId;
use rekey_domain::ipc::LocalApprovalState;
use tokio::sync::watch;

use crate::error::BrokerError;
use crate::lifecycle::Lifecycle;
use crate::runtime::local_calls::LocalCalls;

/// Cancels a registered challenge unless signing clears `id` after the Worker reply.
pub(super) struct PendingApproval {
    pub(super) calls: Arc<LocalCalls>,
    pub(super) id: Option<ApprovalRequestId>,
}
impl Drop for PendingApproval {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.calls.cancel_unconfirmed(id);
        }
    }
}

/// Peer EOF, lifecycle cancellation and the signed deadline each end the wait
/// before any execution is admitted; only an approval returns `Ok`.
pub(super) async fn await_decision(
    calls: &LocalCalls,
    lifecycle: &Lifecycle,
    id: ApprovalRequestId,
    caller: &str,
    deadline: Instant,
    cancel: watch::Receiver<bool>,
) -> Result<(), BrokerError> {
    loop {
        let response = tokio::select! {
            biased;
            _ = crate::executor::wait_for_cancel(cancel.clone()) => return Err(BrokerError::Denied("ssh-peer-closed")),
            _ = crate::executor::wait_for_cancel(lifecycle.subscribe_cancel()) => return Err(BrokerError::Denied("ssh-draining")),
            _ = tokio::time::sleep_until(deadline.into()) => return Err(BrokerError::Denied("ssh-approval-expired")),
            response = calls.await_state(id, caller, 120) => response?,
        };
        match response.state {
            LocalApprovalState::Pending if Instant::now() < deadline => continue,
            LocalApprovalState::Approved => return Ok(()),
            _ => return Err(BrokerError::Denied("ssh-approval-not-granted")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::runtime::local_calls::tests::approved;

    const CALLER: &str = "ssh-agent";

    /// A registered SSH challenge that is still waiting for its decision.
    fn pending(calls: &Arc<LocalCalls>) -> ApprovalRequestId {
        let mut challenge = approved(calls);
        challenge.challenge.approval_request_id = ApprovalRequestId::new_random();
        challenge.challenge.parameter_sha256 = "44".repeat(32);
        challenge.caller = CALLER.into();
        challenge.state = LocalApprovalState::Pending;
        challenge.approval_id = None;
        let now = crate::now_ts().unwrap().as_unix_ms();
        calls
            .register(challenge, now)
            .unwrap()
            .challenge
            .approval_request_id
    }

    fn state(calls: &LocalCalls, id: ApprovalRequestId) -> LocalApprovalState {
        calls
            .get(id, crate::now_ts().unwrap().as_unix_ms())
            .unwrap()
            .state
    }

    #[tokio::test]
    async fn lifecycle_cancel_and_signed_deadline_cancel_the_pending_challenge() {
        for reason in ["ssh-draining", "ssh-approval-expired"] {
            let calls = Arc::new(LocalCalls::default());
            let lifecycle = Lifecycle::new();
            lifecycle.enter_running().unwrap();
            let id = pending(&calls);
            let guard = PendingApproval {
                calls: Arc::clone(&calls),
                id: Some(id),
            };
            let (_peer, cancel) = watch::channel(false);
            // The registry entry outlives the wait deadline, so only the
            // signing owner's own deadline can end an expiry case.
            let deadline = if reason == "ssh-approval-expired" {
                Instant::now() + Duration::from_millis(50)
            } else {
                Instant::now() + Duration::from_secs(60)
            };
            let wait = await_decision(&calls, &lifecycle, id, CALLER, deadline, cancel);
            tokio::pin!(wait);
            if reason == "ssh-draining" {
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut wait)
                        .await
                        .is_err(),
                    "a pending challenge must keep waiting"
                );
                lifecycle.signal_cancel();
            }
            let result = tokio::time::timeout(Duration::from_secs(5), wait)
                .await
                .expect("pending SSH challenge wait is bounded");
            assert!(
                matches!(result, Err(BrokerError::Denied(code)) if code == reason),
                "{reason}: {result:?}"
            );
            assert_eq!(state(&calls, id), LocalApprovalState::Pending);
            drop(guard);
            assert_eq!(state(&calls, id), LocalApprovalState::Cancelled, "{reason}");
            let now = crate::now_ts().unwrap().as_unix_ms();
            assert!(
                calls
                    .consume(id, CALLER, &"44".repeat(32), &"22".repeat(32), now)
                    .is_err(),
                "{reason}: a cancelled challenge can never be consumed"
            );
        }
    }

    #[tokio::test]
    async fn only_an_approval_ends_the_wait_successfully() {
        let calls = Arc::new(LocalCalls::default());
        let lifecycle = Lifecycle::new();
        lifecycle.enter_running().unwrap();
        let id = pending(&calls);
        let (_peer, cancel) = watch::channel(false);
        let review = calls
            .get(id, crate::now_ts().unwrap().as_unix_ms())
            .unwrap()
            .review_sha256;
        let wait = await_decision(
            &calls,
            &lifecycle,
            id,
            CALLER,
            Instant::now() + Duration::from_secs(60),
            cancel,
        );
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut wait)
                .await
                .is_err()
        );
        calls
            .decide(
                id,
                &review,
                Some(rekey_domain::ids::ApprovalId::new_random()),
                crate::now_ts().unwrap().as_unix_ms(),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .unwrap()
            .unwrap();
    }
}
