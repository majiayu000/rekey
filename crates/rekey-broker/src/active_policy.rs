use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rekey_domain::Timestamp;
use rekey_domain::ids::PolicySignerId;
use rekey_policy::{PolicyError, ValidatedPolicyBundle, ValidatedSnapshot};

pub(crate) struct ActivePolicy {
    snapshot: Arc<ValidatedSnapshot>,
    monotonic_deadline: tokio::time::Instant,
    expired: AtomicBool,
    signer_id: Option<PolicySignerId>,
    bundle_digest: Option<[u8; 32]>,
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
            signer_id: None,
            bundle_digest: None,
        })
    }

    pub(crate) fn activate_bundle(
        bundle: ValidatedPolicyBundle,
        now: Timestamp,
    ) -> Result<Self, PolicyError> {
        let signer_id = bundle.signer_id();
        let bundle_digest = bundle.bundle_digest();
        let mut active = Self::activate(bundle.into_snapshot(), now)?;
        active.signer_id = Some(signer_id);
        active.bundle_digest = Some(bundle_digest);
        Ok(active)
    }

    pub(crate) fn load_bundle(bundle: ValidatedPolicyBundle, now: Timestamp) -> Self {
        let signer_id = bundle.signer_id();
        let bundle_digest = bundle.bundle_digest();
        let snapshot = bundle.into_snapshot();
        let remaining_ms = snapshot.expires_at_ms().saturating_sub(now.as_unix_ms());
        let expired = remaining_ms <= 0;
        let monotonic_deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(remaining_ms.max(0) as u64))
            .unwrap_or_else(tokio::time::Instant::now);
        Self {
            snapshot: Arc::new(snapshot),
            monotonic_deadline,
            expired: AtomicBool::new(expired),
            signer_id: Some(signer_id),
            bundle_digest: Some(bundle_digest),
        }
    }

    pub(crate) fn snapshot(&self) -> &ValidatedSnapshot {
        &self.snapshot
    }

    pub(crate) fn signer_id(&self) -> Option<PolicySignerId> {
        self.signer_id
    }

    pub(crate) fn bundle_digest(&self) -> Option<[u8; 32]> {
        self.bundle_digest
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
                "format_version": 3,
                "version": PolicyVersion::new(1).unwrap(),
                "expires_at_ms": expires_at_ms,
                "approvers": [],
                "workload_identities": [],
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
