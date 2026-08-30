//! Capability session registry. Tokens are 32 random bytes; only their
//! SHA-256 is stored. Sessions live in memory only: restart, lock, idle
//! drain, and shutdown revoke everything.

use std::sync::Arc;
use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use rekey_domain::capability::{
    ActionVersionRef, CAPABILITY_TOKEN_BYTES, SESSION_MAX_CONCURRENT_EXECUTIONS, SessionGrant,
};
use rekey_domain::ids::{ActionId, SessionId};
use rekey_domain::{DomainError, Timestamp};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum CreateSessionError {
    Closed,
    Domain(DomainError),
}

struct Entry {
    token_hash: [u8; 32],
    grant: SessionGrant,
    uses_left: u32,
    in_flight: u32,
    revoked: bool,
}

pub struct SessionTicket {
    pub session_id: SessionId,
    pub action: ActionVersionRef,
}

/// RAII permit for one execution. Drop always releases the concurrency slot,
/// including cancellation and panic unwinds.
pub struct ExecutionPermit {
    registry: Arc<SessionRegistry>,
    pub session_id: SessionId,
    pub action: ActionVersionRef,
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
    entries.retain(|entry| !entry.revoked || entry.in_flight > 0);
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
    pub fn create(&self, grant: SessionGrant) -> Result<String, DomainError> {
        match self.admit(grant) {
            Ok(token) => Ok(token),
            Err(CreateSessionError::Closed) => Err(DomainError::InvalidCapability),
            Err(CreateSessionError::Domain(err)) => Err(err),
        }
    }

    /// Same as `create`, but distinguishes a closed (draining/locked) registry
    /// from a domain error so Admin can return `DRAINING` rather than
    /// `INVALID_CAPABILITY`.
    pub fn admit(&self, grant: SessionGrant) -> Result<String, CreateSessionError> {
        let (raw, encoded) = entropy_token().map_err(CreateSessionError::Domain)?;
        let entry = Entry {
            token_hash: hash_token(raw.as_ref()),
            uses_left: grant.max_uses,
            in_flight: 0,
            revoked: false,
            grant,
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
        if entry.grant.expired_at(now) {
            entry.revoked = true;
            return Err(DomainError::CapabilityExpired);
        }
        if !entry.grant.allows(wanted) {
            return Err(DomainError::ActionNotAllowed);
        }
        if entry.uses_left == 0 {
            entry.revoked = true;
            return Err(DomainError::CapabilityExhausted);
        }
        if entry.in_flight >= SESSION_MAX_CONCURRENT_EXECUTIONS {
            return Err(DomainError::InvalidCapability);
        }
        entry.uses_left -= 1;
        entry.in_flight += 1;
        if entry.uses_left == 0 {
            // Exhausted after this reservation: no further executions.
            entry.revoked = true;
        }
        Ok(SessionTicket {
            session_id: entry.grant.id,
            action: wanted,
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
            action: ticket.action,
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
            .filter(|e| !e.revoked && !e.grant.expired_at(now))
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
    use rekey_domain::ids::ActionId;

    fn now(ms: i64) -> Timestamp {
        Timestamp::from_unix_ms(ms)
    }

    fn grant(max_uses: u32) -> (SessionGrant, ActionVersionRef) {
        let r = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let g =
            SessionGrant::new(SessionId::new_random(), vec![r], now(0), 10_000, max_uses).unwrap();
        (g, r)
    }

    fn open_registry() -> SessionRegistry {
        let registry = SessionRegistry::new();
        registry.open_for_admission();
        registry
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
        assert!(matches!(
            registry.admit(g2),
            Err(CreateSessionError::Closed)
        ));
        assert!(registry.begin(&token, r, now(1)).is_err());
        registry.open_for_admission();
        let (g3, r3) = grant(10);
        let token3 = registry.admit(g3).unwrap();
        registry.begin(&token3, r3, now(1)).unwrap();
    }

    #[test]
    fn revoked_history_is_compacted_without_dropping_in_flight_entries() {
        let registry = Arc::new(open_registry());
        for _ in 0..1_000 {
            let (grant, _) = grant(1);
            let id = grant.id;
            registry.admit(grant).unwrap();
            assert!(registry.revoke(id));
        }
        assert_eq!(registry.entry_count(), 0);

        let (grant, action) = grant(10);
        let id = grant.id;
        let token = registry.admit(grant).unwrap();
        let permit = registry.acquire(&token, action, now(1)).unwrap();
        assert!(registry.revoke(id));
        assert_eq!(registry.entry_count(), 1);
        drop(permit);
        assert_eq!(registry.entry_count(), 0);
    }
}
