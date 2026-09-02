//! Capability session registry. Tokens are 32 random bytes; only their
//! SHA-256 is stored. Sessions live in memory only: restart, lock, idle
//! drain, and shutdown revoke everything.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
use rekey_domain::authorization::Principal;
use rekey_domain::capability::{
    ActionVersionRef, CAPABILITY_TOKEN_BYTES, SESSION_MAX_CONCURRENT_EXECUTIONS, SessionGrant,
    SessionProvenance,
};
use rekey_domain::ids::{ActionId, SessionId};
use rekey_domain::{DomainError, Timestamp};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

mod approval;
pub(crate) use approval::ApprovalContext;

#[derive(Debug)]
pub enum CreateSessionError {
    Closed,
    Domain(DomainError),
}

struct Entry {
    token_hash: [u8; 32],
    grant: SessionGrant,
    provenance: SessionProvenance,
    action_timeouts: Vec<(ActionVersionRef, u32)>,
    uses_left: u32,
    in_flight: u32,
    revoked: bool,
    exhausted: bool,
    monotonic_deadline: Instant,
    approval_challenges: Vec<approval::StoredChallenge>,
    approval_uses: Vec<approval::ApprovalUsage>,
    expired_approvals: Vec<approval::ExpiredApproval>,
}

pub struct SessionTicket {
    pub session_id: SessionId,
    pub principal: Principal,
    pub action: ActionVersionRef,
    pub timeout_ms: u32,
    pub expires_at_ms: i64,
}

/// RAII permit for one execution. Drop always releases the concurrency slot,
/// including cancellation and panic unwinds.
pub struct ExecutionPermit {
    registry: Arc<SessionRegistry>,
    pub session_id: SessionId,
    pub principal: Principal,
    pub action: ActionVersionRef,
    pub timeout_ms: u32,
    pub expires_at_ms: i64,
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.registry.finish(self.session_id);
    }
}

struct Inner {
    closed: bool,
    entries: Vec<Entry>,
}

fn compact_entries(entries: &mut Vec<Entry>) {
    let now = Instant::now();
    entries.retain(|entry| {
        entry.in_flight > 0
            || (!entry.revoked && !entry.exhausted && now < entry.monotonic_deadline)
    });
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            closed: true,
            entries: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct SessionRegistry {
    inner: Mutex<Inner>,
}

fn entropy_token() -> Result<(Zeroizing<[u8; CAPABILITY_TOKEN_BYTES]>, String), DomainError> {
    use rand::TryRngCore;
    let mut raw = Zeroizing::new([0u8; CAPABILITY_TOKEN_BYTES]);
    rand::rngs::OsRng
        .try_fill_bytes(raw.as_mut())
        .map_err(|_| DomainError::InvalidCapability)?;
    let encoded = BASE64URL_NOPAD.encode(raw.as_ref());
    Ok((raw, encoded))
}

fn hash_token(raw: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(raw);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => std::process::abort(),
        }
    }

    /// Creates a session and returns the capability token exactly once.
    #[cfg(test)]
    pub fn create(&self, grant: SessionGrant) -> Result<String, DomainError> {
        let action_timeouts = grant
            .allowed_actions
            .iter()
            .copied()
            .map(|action| (action, rekey_domain::action::ACTION_TIMEOUT_HARD_MAX_MS))
            .collect();
        match self.admit(grant, action_timeouts) {
            Ok(token) => Ok(token),
            Err(CreateSessionError::Closed) => Err(DomainError::InvalidCapability),
            Err(CreateSessionError::Domain(err)) => Err(err),
        }
    }

    /// Same as `create`, but distinguishes a closed (draining/locked) registry
    /// from a domain error so Admin can return `DRAINING` rather than
    /// `INVALID_CAPABILITY`.
    pub fn admit(
        &self,
        grant: SessionGrant,
        action_timeouts: Vec<(ActionVersionRef, u32)>,
    ) -> Result<String, CreateSessionError> {
        self.admit_with_provenance(grant, action_timeouts, SessionProvenance::Admin)
    }

    pub fn admit_with_provenance(
        &self,
        grant: SessionGrant,
        action_timeouts: Vec<(ActionVersionRef, u32)>,
        provenance: SessionProvenance,
    ) -> Result<String, CreateSessionError> {
        let (raw, encoded) = entropy_token().map_err(CreateSessionError::Domain)?;
        let ttl_ms = grant
            .expires_at
            .as_unix_ms()
            .saturating_sub(grant.issued_at.as_unix_ms());
        let monotonic_deadline = Instant::now()
            .checked_add(Duration::from_millis(ttl_ms as u64))
            .ok_or(CreateSessionError::Domain(DomainError::InvalidCapability))?;
        let entry = Entry {
            token_hash: hash_token(raw.as_ref()),
            action_timeouts,
            uses_left: grant.max_uses,
            in_flight: 0,
            revoked: false,
            exhausted: false,
            monotonic_deadline,
            approval_challenges: Vec::new(),
            approval_uses: Vec::new(),
            expired_approvals: Vec::new(),
            grant,
            provenance,
        };
        let mut inner = self.lock_inner();
        if inner.closed {
            return Err(CreateSessionError::Closed);
        }
        compact_entries(&mut inner.entries);
        inner.entries.push(entry);
        Ok(encoded)
    }

    /// Authenticates a token for one execution and reserves one use.
    /// Reserving up front is deliberately stricter than post-execution
    /// accounting: failed executions still consume a use.
    pub fn begin(
        &self,
        token: &str,
        wanted: ActionVersionRef,
        now: Timestamp,
    ) -> Result<SessionTicket, DomainError> {
        let raw = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(token.as_bytes())
                .map_err(|_| DomainError::InvalidCapability)?,
        );
        if raw.len() != CAPABILITY_TOKEN_BYTES {
            return Err(DomainError::InvalidCapability);
        }
        let wanted_hash = hash_token(&raw);

        let mut inner = self.lock_inner();
        // Constant-time scan over all entries; no early exit on hash match
        // position.
        let mut found: Option<usize> = None;
        for (i, entry) in inner.entries.iter().enumerate() {
            if bool::from(entry.token_hash.ct_eq(&wanted_hash)) {
                found = Some(i);
            }
        }
        let entry = found
            .map(|i| &mut inner.entries[i])
            .ok_or(DomainError::InvalidCapability)?;
        if entry.revoked {
            return Err(DomainError::InvalidCapability);
        }
        if entry.grant.expired_at(now) || Instant::now() >= entry.monotonic_deadline {
            entry.revoked = true;
            return Err(DomainError::CapabilityExpired);
        }
        if !entry.grant.allows(wanted) {
            return Err(DomainError::ActionNotAllowed);
        }
        let timeout_ms = entry
            .action_timeouts
            .iter()
            .find_map(|(action, timeout_ms)| (*action == wanted).then_some(*timeout_ms))
            .ok_or(DomainError::InvalidCapability)?;
        if entry.uses_left == 0 {
            entry.exhausted = true;
            return Err(DomainError::CapabilityExhausted);
        }
        if entry.in_flight >= SESSION_MAX_CONCURRENT_EXECUTIONS {
            return Err(DomainError::InvalidCapability);
        }
        entry.uses_left -= 1;
        entry.in_flight += 1;
        if entry.uses_left == 0 {
            // Exhausted after this reservation: no further executions.
            entry.exhausted = true;
        }
        Ok(SessionTicket {
            session_id: entry.grant.id,
            principal: entry.grant.principal,
            action: wanted,
            timeout_ms,
            expires_at_ms: entry.grant.expires_at.as_unix_ms(),
        })
    }

    /// Authenticate and hold a concurrency slot until the permit is dropped.
    pub fn acquire(
        self: &Arc<Self>,
        token: &str,
        wanted: ActionVersionRef,
        now: Timestamp,
    ) -> Result<ExecutionPermit, DomainError> {
        let ticket = self.begin(token, wanted, now)?;
        Ok(ExecutionPermit {
            registry: Arc::clone(self),
            session_id: ticket.session_id,
            principal: ticket.principal,
            action: ticket.action,
            timeout_ms: ticket.timeout_ms,
            expires_at_ms: ticket.expires_at_ms,
        })
    }

    /// Releases the concurrency slot reserved by `begin`.
    pub fn finish(&self, session_id: SessionId) {
        let mut inner = self.lock_inner();
        if let Some(entry) = inner.entries.iter_mut().find(|e| e.grant.id == session_id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
        compact_entries(&mut inner.entries);
    }

    pub fn revoke(&self, session_id: SessionId) -> bool {
        let mut inner = self.lock_inner();
        match inner.entries.iter_mut().find(|e| e.grant.id == session_id) {
            Some(entry) => {
                entry.revoked = true;
                compact_entries(&mut inner.entries);
                true
            }
            None => false,
        }
    }

    pub fn revoke_all(&self) {
        let mut inner = self.lock_inner();
        for entry in &mut inner.entries {
            entry.revoked = true;
        }
        compact_entries(&mut inner.entries);
    }

    pub fn revoke_workload(&self) {
        let mut inner = self.lock_inner();
        for entry in &mut inner.entries {
            if entry.provenance == SessionProvenance::Workload {
                entry.revoked = true;
            }
        }
        compact_entries(&mut inner.entries);
    }

    /// Close admission and revoke every session under the same lock so a
    /// SessionCreate that already passed proof verification cannot mint a
    /// token after revoke_all.
    pub fn close_and_revoke_all(&self) {
        let mut inner = self.lock_inner();
        inner.closed = true;
        for entry in inner.entries.iter_mut() {
            entry.revoked = true;
        }
        compact_entries(&mut inner.entries);
    }

    pub fn open_for_admission(&self) {
        self.lock_inner().closed = false;
    }

    /// Revokes every session that can reach any version of the given actions.
    pub fn revoke_by_actions(&self, action_ids: &[ActionId]) {
        let mut inner = self.lock_inner();
        for entry in inner.entries.iter_mut() {
            if entry
                .grant
                .allowed_actions
                .iter()
                .any(|r| action_ids.contains(&r.action_id))
            {
                entry.revoked = true;
            }
        }
        compact_entries(&mut inner.entries);
    }

    pub fn active_count(&self, now: Timestamp) -> u32 {
        self.lock_inner()
            .entries
            .iter()
            .filter(|e| {
                !e.revoked
                    && !e.exhausted
                    && !e.grant.expired_at(now)
                    && Instant::now() < e.monotonic_deadline
            })
            .count() as u32
    }

    pub fn in_flight_total(&self) -> u32 {
        self.lock_inner().entries.iter().map(|e| e.in_flight).sum()
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.lock_inner().entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::authorization::Principal;
    use rekey_domain::ids::{ActionId, PrincipalId, TenantId};

    fn now(ms: i64) -> Timestamp {
        Timestamp::from_unix_ms(ms)
    }

    fn grant(max_uses: u32) -> (SessionGrant, ActionVersionRef) {
        let r = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let session_id = SessionId::new_random();
        let g = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::new_random(),
                principal_id: PrincipalId::new_random(),
                session_id,
            },
            vec![r],
            now(0),
            10_000,
            max_uses,
        )
        .unwrap();
        (g, r)
    }

    fn open_registry() -> SessionRegistry {
        let registry = SessionRegistry::new();
        registry.open_for_admission();
        registry
    }

    fn timeouts(grant: &SessionGrant) -> Vec<(ActionVersionRef, u32)> {
        grant
            .allowed_actions
            .iter()
            .copied()
            .map(|action| (action, 1_000))
            .collect()
    }

    #[test]
    fn token_lifecycle() {
        let registry = open_registry();
        let (g, r) = grant(2);
        let session_id = g.id;
        let token = registry.create(g).unwrap();

        let ticket = registry.begin(&token, r, now(1)).unwrap();
        assert_eq!(ticket.session_id, session_id);
        registry.finish(session_id);
        registry.begin(&token, r, now(1)).unwrap();
        registry.finish(session_id);
        // max_uses = 2: third use denied.
        assert!(matches!(
            registry.begin(&token, r, now(1)),
            Err(DomainError::CapabilityExhausted) | Err(DomainError::InvalidCapability)
        ));
    }

    #[test]
    fn expiry_wrong_action_and_revocation() {
        let registry = open_registry();
        let (g, r) = grant(10);
        let session_id = g.id;
        let token = registry.create(g).unwrap();

        let other = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        assert!(matches!(
            registry.begin(&token, other, now(1)),
            Err(DomainError::ActionNotAllowed)
        ));
        // Wrong version of the allowed action is also denied.
        let wrong_version = ActionVersionRef {
            action_id: r.action_id,
            version: 2,
        };
        assert!(matches!(
            registry.begin(&token, wrong_version, now(1)),
            Err(DomainError::ActionNotAllowed)
        ));

        assert!(matches!(
            registry.begin(&token, r, now(10_000)),
            Err(DomainError::CapabilityExpired)
        ));

        let (g2, r2) = grant(10);
        let token2 = registry.create(g2).unwrap();
        registry.revoke(session_id);
        registry.revoke_all();
        assert!(registry.begin(&token2, r2, now(1)).is_err());
    }

    #[test]
    fn monotonic_deadline_survives_wall_clock_rollback() {
        let registry = open_registry();
        let r = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let session_id = SessionId::new_random();
        let grant = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::new_random(),
                principal_id: PrincipalId::new_random(),
                session_id,
            },
            vec![r],
            now(0),
            1,
            1,
        )
        .unwrap();
        let token = registry.create(grant).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(
            registry.begin(&token, r, now(0)),
            Err(DomainError::CapabilityExpired)
        ));
    }

    #[test]
    fn garbage_tokens_rejected() {
        let registry = open_registry();
        let (g, r) = grant(1);
        let _token = registry.create(g).unwrap();
        for bad in ["", "not-base64!!", "AAAA", &"A".repeat(43)] {
            assert!(registry.begin(bad, r, now(1)).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn concurrency_cap_enforced() {
        let registry = open_registry();
        let (g, r) = grant(100);
        let token = registry.create(g).unwrap();
        for _ in 0..SESSION_MAX_CONCURRENT_EXECUTIONS {
            registry.begin(&token, r, now(1)).unwrap();
        }
        assert!(registry.begin(&token, r, now(1)).is_err());
    }

    #[test]
    fn permit_drop_releases_concurrency_slot() {
        let registry = Arc::new(open_registry());
        let (g, r) = grant(100);
        let token = registry.create(g).unwrap();
        {
            let _held: Vec<_> = (0..SESSION_MAX_CONCURRENT_EXECUTIONS)
                .map(|_| registry.acquire(&token, r, now(1)).unwrap())
                .collect();
            assert_eq!(
                registry.in_flight_total(),
                SESSION_MAX_CONCURRENT_EXECUTIONS
            );
            assert!(registry.acquire(&token, r, now(1)).is_err());
        }
        assert_eq!(registry.in_flight_total(), 0);
        let _again = registry.acquire(&token, r, now(1)).unwrap();
        assert_eq!(registry.in_flight_total(), 1);
    }

    #[test]
    fn close_and_revoke_refuses_new_sessions() {
        let registry = open_registry();
        let (g, r) = grant(10);
        let token = registry.create(g).unwrap();
        registry.close_and_revoke_all();
        let (g2, _) = grant(10);
        let g2_timeouts = timeouts(&g2);
        assert!(matches!(
            registry.admit(g2, g2_timeouts),
            Err(CreateSessionError::Closed)
        ));
        assert!(registry.begin(&token, r, now(1)).is_err());
        registry.open_for_admission();
        let (g3, r3) = grant(10);
        let g3_timeouts = timeouts(&g3);
        let token3 = registry.admit(g3, g3_timeouts).unwrap();
        registry.begin(&token3, r3, now(1)).unwrap();
    }

    #[test]
    fn revoked_history_is_compacted_without_dropping_in_flight_entries() {
        let registry = Arc::new(open_registry());
        for _ in 0..1_000 {
            let (grant, _) = grant(1);
            let id = grant.id;
            let action_timeouts = timeouts(&grant);
            registry.admit(grant, action_timeouts).unwrap();
            assert!(registry.revoke(id));
        }
        assert_eq!(registry.entry_count(), 0);

        let (grant, action) = grant(10);
        let id = grant.id;
        let action_timeouts = timeouts(&grant);
        let token = registry.admit(grant, action_timeouts).unwrap();
        let permit = registry.acquire(&token, action, now(1)).unwrap();
        assert_eq!(permit.timeout_ms, 1_000);
        assert!(registry.revoke(id));
        assert_eq!(registry.entry_count(), 1);
        drop(permit);
        assert_eq!(registry.entry_count(), 0);
    }

    #[test]
    fn expired_unused_history_is_compacted_on_next_admission() {
        let registry = open_registry();
        let action = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let session_id = SessionId::new_random();
        let expiring = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::new_random(),
                principal_id: PrincipalId::new_random(),
                session_id,
            },
            vec![action],
            now(0),
            1,
            1,
        )
        .unwrap();
        let expiring_timeouts = timeouts(&expiring);
        registry.admit(expiring, expiring_timeouts).unwrap();
        std::thread::sleep(Duration::from_millis(5));

        let (live, _) = grant(1);
        let live_timeouts = timeouts(&live);
        registry.admit(live, live_timeouts).unwrap();
        assert_eq!(registry.entry_count(), 1);
    }
}
