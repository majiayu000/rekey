//! Agent SCAN (agent 15). Whole files are matched inside the Authority, which
//! returns only positions and signed connection names. One byte budget per
//! kernel-verified system user bounds how much candidate text can be tested;
//! caller labels never select or reset it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rekey_domain::ipc;
use tokio::net::UnixStream;

use crate::error::BrokerError;
use crate::ipc::frame::IncomingFrame;
use crate::runtime::BrokerCtx;

const WINDOW: Duration = Duration::from_secs(60);

/// Daemon-wide scan budget, owned by the Agent listener: a fixed window per
/// UID that starts with the first admitted frame.
pub struct ScanBudget {
    limit: u64,
    window: Duration,
    users: Mutex<BTreeMap<u32, (Instant, u64)>>,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self::new(ipc::SCAN_USER_BYTES_PER_MINUTE, WINDOW)
    }
}

impl ScanBudget {
    fn new(limit: u64, window: Duration) -> Self {
        Self {
            limit,
            window,
            users: Mutex::new(BTreeMap::new()),
        }
    }

    /// Admits a whole frame or refuses it; a refused frame consumes nothing.
    fn charge(&self, uid: u32, bytes: u64) -> Result<(), BrokerError> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rekey_vault::AuthorityError::ClockUnavailable)?;
        let now = Instant::now();
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        users.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        let (start, used) = users.entry(uid).or_insert((now, 0));
        if let Some(total) = used.checked_add(bytes).filter(|total| *total <= self.limit) {
            *used = total;
            return Ok(());
        }
        // The monotonic window decides; the wall clock only names its end.
        let reset = wall + self.window.saturating_sub(now.duration_since(*start));
        Err(BrokerError::ScanBudgetExhausted {
            reset_at_ms: i64::try_from(reset.as_nanos().div_ceil(1_000_000)).unwrap_or(i64::MAX),
        })
    }
}

/// One Agent connection's handle on the budget, bound to its peer UID.
pub(crate) struct ScanPeer {
    budget: Arc<ScanBudget>,
    uid: Option<u32>,
}

impl ScanPeer {
    pub(crate) fn new(stream: &UnixStream, budget: Arc<ScanBudget>) -> Self {
        Self {
            budget,
            uid: crate::ipc::peer::peer_uid(stream).ok(),
        }
    }
}

pub(crate) async fn dispatch(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    peer: &ScanPeer,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let meta: ipc::ScanMeta =
        serde_json::from_slice(&frame.metadata).map_err(|_| ipc::FrameError::InvalidField)?;
    ctx.lifecycle.reject_if_not_running()?;
    let active = ctx
        .policy
        .read()
        .await
        .clone()
        .filter(|p| p.signer_id().is_some())
        .ok_or(BrokerError::LocalCall(
            "NOT_CONFIGURED",
            "no active signed policy; nothing was scanned",
            "Ask the user to sign Connection rules in Rekey, then scan again.",
        ))?;
    if active.is_expired(crate::now_ts()?) {
        return Err(BrokerError::LocalCall(
            "NOT_CONFIGURED",
            "the signed policy expired; nothing was scanned",
            "Ask the user to renew the signed Connection rules in Rekey, then scan again.",
        ));
    }
    // Without a kernel-verified UID there is no budget to charge.
    let uid = peer
        .uid
        .ok_or(BrokerError::Denied("scan-peer-unverified"))?;
    peer.budget.charge(uid, frame.body.len() as u64)?;
    let snapshot = active.snapshot();
    let credentials = snapshot
        .connections()
        .iter()
        .filter(|c| c.enabled)
        .map(|c| (&c.name, c.credential_id))
        .chain(
            snapshot
                .ssh_keys()
                .iter()
                .map(|c| (&c.name, c.credential_id)),
        )
        .chain(
            snapshot
                .derived_credentials()
                .iter()
                .map(|c| (&c.name, c.credential_id)),
        )
        .map(
            |(connection, credential_id)| rekey_vault::hygiene::ScanCredential {
                connection: connection.clone(),
                credential_id,
            },
        )
        .collect();
    let report = ctx
        .authority
        .scan_credentials(
            vec![rekey_vault::hygiene::ScanInput::new(
                meta.path,
                frame.body.to_vec(),
            )],
            credentials,
        )
        .await?;
    Ok((
        b"{}".to_vec(),
        serde_json::to_vec(&ipc::ScanResponse {
            findings: report.findings,
            unavailable_credentials: report.unavailable_credentials,
        })
        .map_err(|_| ipc::FrameError::InvalidField)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_at(error: BrokerError) -> i64 {
        assert_eq!(error.code(), "RATE_LIMITED");
        assert_eq!(crate::ipc::agent::local_agent_code(&error), "RATE_LIMITED");
        assert!(error.agent_next().starts_with("Retry after "));
        match error {
            BrokerError::ScanBudgetExhausted { reset_at_ms } => reset_at_ms,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn bytes_are_shared_per_uid_and_refusal_reports_the_window_reset() {
        let budget = ScanBudget::new(100, WINDOW);
        let before = crate::now_ts().unwrap().as_unix_ms();
        budget.charge(501, 60).unwrap();
        // A refused frame is not charged: 40 more bytes still fit exactly.
        let reset = reset_at(budget.charge(501, 41).unwrap_err());
        budget.charge(501, 40).unwrap();
        let after = crate::now_ts().unwrap().as_unix_ms();
        assert!(
            reset >= before + 59_000 && reset <= after + 60_001,
            "{before} {reset} {after}"
        );
        // Later refusals in the same window name the same reset instant.
        assert!((reset_at(budget.charge(501, 1).unwrap_err()) - reset).abs() <= 1);
        // The key is the system user: another UID has its own window.
        budget.charge(502, 100).unwrap();
    }

    #[test]
    fn a_new_window_starts_after_the_previous_one_expires() {
        let budget = ScanBudget::new(10, Duration::from_millis(50));
        budget.charge(501, 10).unwrap();
        assert!(budget.charge(501, 1).is_err());
        std::thread::sleep(Duration::from_millis(60));
        budget.charge(501, 10).unwrap();
        assert!(budget.charge(501, 1).is_err());
    }

    #[test]
    fn the_default_budget_is_six_hundred_mib_per_minute() {
        let budget = ScanBudget::default();
        let frame = 10 * 1024 * 1024;
        for _ in 0..60 {
            budget.charge(501, frame).unwrap();
        }
        let reset = reset_at(budget.charge(501, frame).unwrap_err());
        let now = crate::now_ts().unwrap().as_unix_ms();
        assert!(reset > now + 55_000 && reset <= now + 60_001, "{reset}");
    }
}
