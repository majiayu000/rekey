use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rekey_domain::Timestamp;
use rekey_policy::{PolicyError, ValidatedSnapshot};

pub(crate) struct ActivePolicy {
    snapshot: Arc<ValidatedSnapshot>,
    monotonic_deadline: tokio::time::Instant,
    expired: AtomicBool,
}

impl ActivePolicy {
    pub(crate) fn activate(
        snapshot: ValidatedSnapshot,
        now: Timestamp,
    ) -> Result<Self, PolicyError> {
        let remaining_ms = snapshot
            .expires_at_ms()
            .checked_sub(now.as_unix_ms())
            .filter(|remaining| *remaining > 0)
            .ok_or(PolicyError::Expired)?;
        let monotonic_deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(remaining_ms as u64))
            .ok_or(PolicyError::Invalid)?;
        Ok(Self {
            snapshot: Arc::new(snapshot),
            monotonic_deadline,
            expired: AtomicBool::new(false),
        })
    }

    pub(crate) fn snapshot(&self) -> &ValidatedSnapshot {
        &self.snapshot
    }

    /// Expiry is irreversible for an activated snapshot. A forward wall-clock
    /// jump may expire it early, but a later rollback can never revive it.
    pub(crate) fn is_expired(&self, now: Timestamp) -> bool {
        if self.expired.load(Ordering::Acquire) {
            return true;
        }
        let expired = self.snapshot.expires_at_ms() <= now.as_unix_ms()
            || tokio::time::Instant::now() >= self.monotonic_deadline;
        if expired {
            self.expired.store(true, Ordering::Release);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::authorization::PolicyVersion;
    use serde_json::json;

    fn snapshot(expires_at_ms: i64) -> ValidatedSnapshot {
        rekey_policy::parse_and_validate_snapshot(
            &serde_json::to_vec(&json!({
                "format_version": 1,
                "version": PolicyVersion::new(1).unwrap(),
                "expires_at_ms": expires_at_ms,
                "bindings": [],
                "rules": []
            }))
            .unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .unwrap()
    }

    #[test]
    fn wall_clock_expiry_cannot_be_revived_by_rollback() {
        let active = ActivePolicy::activate(snapshot(10_000), Timestamp::from_unix_ms(1)).unwrap();
        assert!(active.is_expired(Timestamp::from_unix_ms(10_000)));
        assert!(active.is_expired(Timestamp::from_unix_ms(2)));
    }

    #[test]
    fn monotonic_deadline_expires_snapshot() {
        let mut active =
            ActivePolicy::activate(snapshot(10_000), Timestamp::from_unix_ms(1)).unwrap();
        active.monotonic_deadline = tokio::time::Instant::now();
        assert!(active.is_expired(Timestamp::from_unix_ms(2)));
    }
}
