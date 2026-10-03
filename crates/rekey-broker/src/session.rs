//! Capability session registry. Tokens are 32 random bytes; only their
//! SHA-256 is stored. Sessions live in memory only: restart, lock, idle
//! drain, and shutdown revoke everything.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::BrokerError;
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::authorization::Principal;
use rekey_domain::capability::{
    ActionVersionRef, CAPABILITY_TOKEN_BYTES, SESSION_MAX_CONCURRENT_EXECUTIONS, SessionGrant,
    SessionProvenance,
};
use rekey_domain::ids::{ActionId, SessionId};
use rekey_domain::profile::{AgentProfile, ProfileLlmLimit};
use rekey_domain::{DomainError, Timestamp};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use zeroize::Zeroizing;

mod approval;
pub(crate) use approval::{ApprovalContext, LocalApproval};

#[derive(Debug)]
pub enum CreateSessionError {
    Closed,
    Domain(DomainError),
}

struct Entry {
    token_hash: [u8; 32],
    grant: SessionGrant,
    provenance: SessionProvenance,
    profile_scope: Option<Arc<ProfileSessionScope>>,
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

/// Immutable signed scope stored on the existing registry entry, never a second token map.
#[derive(Debug)]
pub(crate) struct ProfileSessionScope {
    profile: AgentProfile,
    policy_sha256: [u8; 32],
}

impl ProfileSessionScope {
    pub(crate) fn profile(&self) -> &AgentProfile {
        &self.profile
    }

    pub(crate) fn policy_sha256(&self) -> &[u8; 32] {
        &self.policy_sha256
    }

    pub(crate) fn new(profile: AgentProfile, policy_sha256: [u8; 32]) -> Self {
        Self {
            profile,
            policy_sha256,
        }
    }

    fn action(&self, wanted: ActionVersionRef) -> Result<ProfileActionScope, DomainError> {
        for grant in &self.profile.grants {
            for capability in &grant.capabilities {
                if capability.actions.contains(&wanted) {
                    return Ok(ProfileActionScope {
                        profile_name: self.profile.name.clone(),
                        instance_slug: grant.instance.clone(),
                        capability: capability.capability.clone(),
                        llm_limits: self
                            .profile
                            .llm_limits
                            .iter()
                            .find(|limit| limit.instance == grant.instance)
                            .cloned(),
                        policy_sha256: self.policy_sha256,
                    });
                }
            }
        }
        Err(DomainError::InvalidCapability)
    }
}

/// Authenticated per-action projection for the shared executor. No caller fields.
// The executor lane consumes these fields after this foundation is integrated.
#[derive(Debug, Clone)]
pub(crate) struct ProfileActionScope {
    pub(crate) profile_name: String,
    pub(crate) instance_slug: String,
    pub(crate) capability: String,
    pub(crate) llm_limits: Option<ProfileLlmLimit>,
    pub(crate) policy_sha256: [u8; 32],
}

/// Synchronous revocation on every cancellation path, before any audit await.
pub(crate) struct ProfileSessionGuard {
    registry: Arc<SessionRegistry>,
    session_id: SessionId,
}
impl Drop for ProfileSessionGuard {
    fn drop(&mut self) {
        self.registry.revoke(self.session_id);
    }
}
impl ProfileSessionGuard {
    pub(crate) fn session_id(&self) -> SessionId {
        self.session_id
    }
}

pub struct SessionTicket {
    pub session_id: SessionId,
    pub principal: Principal,
    pub action: ActionVersionRef,
    pub timeout_ms: u32,
    pub expires_at_ms: i64,
    profile_scope: Option<ProfileActionScope>,
}

/// RAII permit for one execution. Drop always releases the concurrency slot,
/// including cancellation and panic unwinds.
pub struct ExecutionPermit {
    use_refunded: bool,
    registry: Arc<SessionRegistry>,
    pub session_id: SessionId,
    pub principal: Principal,
    pub action: ActionVersionRef,
    pub timeout_ms: u32,
    pub expires_at_ms: i64,
    profile_scope: Option<ProfileActionScope>,
}

impl ExecutionPermit {
    pub(crate) fn profile_scope(&self) -> Option<&ProfileActionScope> {
        self.profile_scope.as_ref()
    }
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
            || (!entry.revoked
                && now < entry.monotonic_deadline
                // A Profile control connection outlives its final execution response.
                // Exhaustion rejects new work; only revocation/expiry ends ownership.
                && (!entry.exhausted
                    || entry.profile_scope.is_some()
                    || entry.approval_challenges.iter().any(approval::is_local)))
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
    pub(crate) approval_changed: Notify,
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
    /// Authenticate once without reserving an execution or refreshing lifetime.
    pub(crate) fn profile_inventory(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<(SessionId, Arc<ProfileSessionScope>, i64), BrokerError> {
        let raw = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(token.as_bytes())
                .map_err(|_| DomainError::InvalidCapability)?,
        );
        if raw.len() != CAPABILITY_TOKEN_BYTES {
            return Err(DomainError::InvalidCapability.into());
        }
        let wanted = hash_token(&raw);
        let mut inner = self.lock_inner();
        if inner.closed {
            return Err(DomainError::InvalidCapability.into());
        }
        let mut found = None;
        for (index, entry) in inner.entries.iter().enumerate() {
            if bool::from(entry.token_hash.ct_eq(&wanted)) {
                found = Some(index);
            }
        }
        let entry = found
            .map(|index| &mut inner.entries[index])
            .ok_or(DomainError::InvalidCapability)?;
        inventory_live(entry, now)?;
        let scope = entry
            .profile_scope
            .as_ref()
            .ok_or(DomainError::InvalidCapability)?;
        Ok((
            entry.grant.id,
            Arc::clone(scope),
            entry.grant.expires_at.as_unix_ms(),
        ))
    }

    /// Recheck liveness after Authority IO, without authenticating a token twice.
    pub(crate) fn ensure_inventory_live(
        &self,
        id: SessionId,
        now: Timestamp,
    ) -> Result<(), BrokerError> {
        let mut inner = self.lock_inner();
        if inner.closed {
            return Err(DomainError::InvalidCapability.into());
        }
        let entry = inner
            .entries
            .iter_mut()
            .find(|entry| entry.grant.id == id)
            .ok_or(DomainError::InvalidCapability)?;
        inventory_live(entry, now)
    }

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
        self.admit_inner(grant, action_timeouts, provenance, None, None)
    }

    pub(crate) fn admit_profile(
        self: &Arc<Self>,
        grant: SessionGrant,
        action_timeouts: Vec<(ActionVersionRef, u32)>,
        scope: ProfileSessionScope,
        deadline: Instant,
    ) -> Result<(Zeroizing<String>, ProfileSessionGuard), CreateSessionError> {
        let session_id = grant.id;
        let token = self.admit_inner(
            grant,
            action_timeouts,
            SessionProvenance::Admin,
            Some(Arc::new(scope)),
            Some(deadline),
        )?;
        // No await or fallible work may separate insertion from ownership.
        Ok((
            Zeroizing::new(token),
            ProfileSessionGuard {
                registry: Arc::clone(self),
                session_id,
            },
        ))
    }

    fn admit_inner(
        &self,
        grant: SessionGrant,
        action_timeouts: Vec<(ActionVersionRef, u32)>,
        provenance: SessionProvenance,
        profile_scope: Option<Arc<ProfileSessionScope>>,
        deadline: Option<Instant>,
    ) -> Result<String, CreateSessionError> {
        let (raw, encoded) = entropy_token().map_err(CreateSessionError::Domain)?;
        let ttl_ms = grant
            .expires_at
            .as_unix_ms()
            .saturating_sub(grant.issued_at.as_unix_ms());
        let monotonic_deadline = Instant::now()
            .checked_add(Duration::from_millis(ttl_ms as u64))
            .ok_or(CreateSessionError::Domain(DomainError::InvalidCapability))?;
        let monotonic_deadline =
            deadline.map_or(monotonic_deadline, |cap| cap.min(monotonic_deadline));
        let entry = Entry {
            profile_scope,
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
        self.approval_changed.notify_waiters();
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
    ) -> Result<SessionTicket, BrokerError> {
        let raw = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(token.as_bytes())
                .map_err(|_| DomainError::InvalidCapability)?,
        );
        if raw.len() != CAPABILITY_TOKEN_BYTES {
            return Err(DomainError::InvalidCapability.into());
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
            return Err(DomainError::InvalidCapability.into());
        }
        if entry.grant.expired_at(now) || Instant::now() >= entry.monotonic_deadline {
            entry.revoked = true;
            return Err(DomainError::CapabilityExpired.into());
        }
        if !entry.grant.allows(wanted) {
            return Err(DomainError::ActionNotAllowed.into());
        }
        let timeout_ms = entry
            .action_timeouts
            .iter()
            .find_map(|(action, timeout_ms)| (*action == wanted).then_some(*timeout_ms))
            .ok_or(DomainError::InvalidCapability)?;
        if entry.uses_left == 0 {
            if entry.in_flight > 0 {
                return Err(rekey_vault::AuthorityError::AuthorityBusy.into());
            }
            entry.exhausted = true;
            return Err(DomainError::CapabilityExhausted.into());
        }
        if entry.in_flight >= SESSION_MAX_CONCURRENT_EXECUTIONS {
            return Err(DomainError::InvalidCapability.into());
        }
        let profile_scope = entry
            .profile_scope
            .as_ref()
            .map(|scope| scope.action(wanted))
            .transpose()?;
        entry.uses_left -= 1;
        entry.in_flight += 1;
        if entry.uses_left == 0 {
            // Exhausted after this reservation: no further executions.
            entry.exhausted = true;
        }
        Ok(SessionTicket {
            profile_scope,
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
    ) -> Result<ExecutionPermit, BrokerError> {
        let ticket = self.begin(token, wanted, now)?;
        Ok(ExecutionPermit {
            profile_scope: ticket.profile_scope,
            use_refunded: false,
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
        self.approval_changed.notify_waiters();
    }

    /// Clamp an unpublished human capability to the owning management lease.
    #[cfg(feature = "lab")]
    pub(crate) fn bound_management_deadline(&self, session: SessionId, deadline: Instant) -> bool {
        let mut inner = self.lock_inner();
        let Some(entry) = inner
            .entries
            .iter_mut()
            .find(|entry| entry.grant.id == session && !entry.revoked)
        else {
            return false;
        };
        entry.monotonic_deadline = entry.monotonic_deadline.min(deadline);
        true
    }

    pub fn revoke(&self, session_id: SessionId) -> bool {
        let mut inner = self.lock_inner();
        match inner.entries.iter_mut().find(|e| e.grant.id == session_id) {
            Some(entry) => {
                entry.revoked = true;
                compact_entries(&mut inner.entries);
                self.approval_changed.notify_waiters();
                true
            }
            None => false,
        }
    }

    /// Wait without holding the registry lock. Notify is armed before checking
    /// state; a bounded local wall-clock check also notices forward jumps.
    pub(crate) async fn wait_revoked(&self, session_id: SessionId) {
        loop {
            let changed = self.approval_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let deadline = {
                let mut inner = self.lock_inner();
                let Some(entry) = inner.entries.iter_mut().find(|e| e.grant.id == session_id)
                else {
                    return;
                };
                let now = crate::now_ts();
                if entry.revoked
                    || now.is_err()
                    || now.is_ok_and(|now| entry.grant.expired_at(now))
                    || Instant::now() >= entry.monotonic_deadline
                {
                    entry.revoked = true;
                    self.approval_changed.notify_waiters();
                    return;
                }
                entry
                    .monotonic_deadline
                    .min(Instant::now() + Duration::from_secs(1))
            };
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(deadline.into()) => {},
            }
        }
    }

    /// Revoke only the explicit principal; count live capabilities and pending challenges.
    #[cfg(feature = "lab")]
    pub(crate) fn revoke_principal(
        &self,
        principal: rekey_domain::ids::PrincipalId,
    ) -> (usize, usize) {
        let mut inner = self.lock_inner();
        let now = crate::now_ts().unwrap_or(Timestamp::from_unix_ms(i64::MAX));
        let mono = Instant::now();
        let mut capabilities = 0;
        let mut pending = 0;
        for entry in &mut inner.entries {
            if entry.grant.principal.principal_id == principal && !entry.revoked {
                if !entry.exhausted
                    && entry.monotonic_deadline > mono
                    && entry.grant.expires_at > now
                {
                    capabilities += 1;
                }
                pending += entry
                    .approval_challenges
                    .iter_mut()
                    .map(|stored| usize::from(approval::challenge_is_pending(stored, now, mono)))
                    .sum::<usize>();
                entry.revoked = true;
            }
        }
        compact_entries(&mut inner.entries);
        self.approval_changed.notify_waiters();
        (capabilities, pending)
    }

    pub fn revoke_all(&self) {
        let mut inner = self.lock_inner();
        for entry in &mut inner.entries {
            entry.revoked = true;
        }
        compact_entries(&mut inner.entries);
        self.approval_changed.notify_waiters();
    }

    pub fn revoke_workload(&self) {
        let mut inner = self.lock_inner();
        for entry in &mut inner.entries {
            if entry.provenance == SessionProvenance::Workload {
                entry.revoked = true;
            }
        }
        compact_entries(&mut inner.entries);
        self.approval_changed.notify_waiters();
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
        self.approval_changed.notify_waiters();
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
        self.approval_changed.notify_waiters();
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

fn inventory_live(entry: &mut Entry, now: Timestamp) -> Result<(), BrokerError> {
    if entry.revoked {
        return Err(DomainError::InvalidCapability.into());
    }
    if entry.grant.expired_at(now) || Instant::now() >= entry.monotonic_deadline {
        entry.revoked = true;
        return Err(DomainError::CapabilityExpired.into());
    }
    if entry.uses_left == 0 {
        return Err(if entry.in_flight > 0 {
            rekey_vault::AuthorityError::AuthorityBusy.into()
        } else {
            DomainError::CapabilityExhausted.into()
        });
    }
    Ok(())
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
    #[cfg(feature = "lab")]
    fn oidc_principal_revocation_counts_live_pending_and_preserves_other_principals() {
        use rekey_domain::authorization::{ApprovalMode, ResourceRef, SchemaId};
        use rekey_domain::ids::{ApprovalRequestId, PolicyRuleId};
        let registry = open_registry();
        let (mut first, action) = grant(10);
        let now = crate::now_ts().unwrap();
        first.issued_at = now;
        first.expires_at = now.saturating_add_ms(60_000);
        let principal = first.principal.principal_id;
        let token = registry.create(first.clone()).unwrap();
        registry.begin(&token, action, now).unwrap();
        for offset in [10_000, -1] {
            let challenge = rekey_domain::ipc::ApprovalChallenge {
                record_type: "rekey.approval.challenge.v2".into(),
                approval_request_id: ApprovalRequestId::new_random(),
                tenant_id: first.principal.tenant_id,
                principal_id: principal,
                session_id: first.id,
                action_id: action.action_id,
                action_version: 1,
                resource: ResourceRef::new("test.resource".into(), "one".into()).unwrap(),
                schema_id: SchemaId::new("test/v1".into()).unwrap(),
                parameter_sha256: "a".repeat(64),
                policy_version: 1,
                policy_sha256: "b".repeat(64),
                policy_rule_id: PolicyRuleId::new_random(),
                mode: ApprovalMode::OneTime,
                approver: rekey_domain::authorization::ApproverSpec::Ed25519 {
                    keys: vec!["11".repeat(32)],
                    threshold: 1,
                },
                max_uses: 1,
                created_at_ms: now.as_unix_ms() - 1000,
                max_expires_at_ms: now.as_unix_ms() + offset,
            };
            registry
                .store_approval_challenge(
                    challenge,
                    Instant::now(),
                    Instant::now() + Duration::from_secs(60),
                    now,
                )
                .unwrap();
        }
        let (mut other, other_action) = grant(10);
        other.issued_at = now;
        other.expires_at = now.saturating_add_ms(60_000);
        let other_token = registry.create(other).unwrap();
        assert_eq!(registry.revoke_principal(principal), (1, 1));
        assert_eq!(registry.revoke_principal(principal), (0, 0));
        assert!(registry.begin(&token, action, now).is_err());
        assert!(registry.begin(&other_token, other_action, now).is_ok());
        registry.finish(first.id);
    }

    #[test]
    #[cfg(feature = "lab")]
    fn oidc_management_monotonic_deadline_bounds_human_capability() {
        let registry = open_registry();
        let (mut grant, action) = grant(10);
        let now = crate::now_ts().unwrap();
        grant.issued_at = now;
        grant.expires_at = now.saturating_add_ms(60_000);
        let id = grant.id;
        let token = registry.create(grant).unwrap();
        assert!(registry.bound_management_deadline(id, Instant::now() - Duration::from_millis(1)));
        assert!(registry.begin(&token, action, now).is_err());
        registry.revoke(id);
        assert!(!registry.bound_management_deadline(id, Instant::now() + Duration::from_secs(60)));
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
            Err(BrokerError::Domain(DomainError::CapabilityExhausted))
                | Err(BrokerError::Domain(DomainError::InvalidCapability))
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
            Err(BrokerError::Domain(DomainError::ActionNotAllowed))
        ));
        // Wrong version of the allowed action is also denied.
        let wrong_version = ActionVersionRef {
            action_id: r.action_id,
            version: 2,
        };
        assert!(matches!(
            registry.begin(&token, wrong_version, now(1)),
            Err(BrokerError::Domain(DomainError::ActionNotAllowed))
        ));

        assert!(matches!(
            registry.begin(&token, r, now(10_000)),
            Err(BrokerError::Domain(DomainError::CapabilityExpired))
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
            Err(BrokerError::Domain(DomainError::CapabilityExpired))
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

#[cfg(test)]
mod profile_tests {
    use super::*;
    use rekey_domain::ids::{ActionId, PrincipalId, TenantId};
    use serde_json::json;

    fn grant_scope() -> (SessionGrant, ProfileSessionScope, ActionVersionRef) {
        let now = crate::now_ts().unwrap();
        let id = SessionId::new_random();
        let principal = Principal {
            tenant_id: TenantId::new_random(),
            principal_id: PrincipalId::new_random(),
            session_id: id,
        };
        let action = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let grant = SessionGrant::new(id, principal, vec![action], now, 60_000, 1).unwrap();
        let profile:AgentProfile = serde_json::from_value(json!({"name":"test","principal_id":principal.principal_id,"grants":[{"instance":"one","capabilities":[{"rule":"template-default","capability":"read","actions":[action]}]}],"session":{"ttl_ms":60000,"max_uses":1},"confirm_each_run":false,"isolation":"none","egress":"allow","llm_limits":[]})).unwrap();
        (grant, ProfileSessionScope::new(profile, [1; 32]), action)
    }

    #[test]
    fn inventory_never_reserves_uses_and_distinguishes_inflight_last_use() {
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        let (grant, scope, action) = grant_scope();
        let (token, _guard) = registry
            .admit_profile(
                grant,
                vec![(action, 100)],
                scope,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        for _ in 0..10 {
            let (id, scope, _) = registry
                .profile_inventory(&token, crate::now_ts().unwrap())
                .unwrap();
            assert_eq!(scope.profile().name, "test");
            registry
                .ensure_inventory_live(id, crate::now_ts().unwrap())
                .unwrap();
        }
        assert_eq!(registry.in_flight_total(), 0);
        let permit = registry
            .acquire(&token, action, crate::now_ts().unwrap())
            .unwrap();
        assert_eq!(
            registry
                .profile_inventory(&token, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "AUTHORITY_BUSY"
        );
        drop(permit);
        assert_eq!(
            registry
                .profile_inventory(&token, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "CAPABILITY_EXHAUSTED"
        );
    }

    #[tokio::test]
    async fn exhausted_profile_lives_until_owner_drop_revoke_or_deadline() {
        for termination in ["owner", "revoke", "expiry"] {
            let registry = Arc::new(SessionRegistry::new());
            registry.open_for_admission();
            let (grant, scope, action) = grant_scope();
            let (token, guard) = registry
                .admit_profile(
                    grant,
                    vec![(action, 100)],
                    scope,
                    Instant::now() + Duration::from_secs(60),
                )
                .unwrap();
            let id = guard.session_id();
            drop(
                registry
                    .acquire(&token, action, crate::now_ts().unwrap())
                    .unwrap(),
            );
            assert_eq!(registry.lock_inner().entries.len(), 1);
            assert!(
                tokio::time::timeout(Duration::from_millis(5), registry.wait_revoked(id))
                    .await
                    .is_err()
            );
            assert_eq!(
                registry
                    .acquire(&token, action, crate::now_ts().unwrap())
                    .err()
                    .unwrap()
                    .code(),
                "CAPABILITY_EXHAUSTED"
            );
            assert_eq!(
                registry
                    .profile_inventory(&token, crate::now_ts().unwrap())
                    .unwrap_err()
                    .code(),
                "CAPABILITY_EXHAUSTED"
            );
            match termination {
                "owner" => drop(guard),
                "revoke" => {
                    assert!(registry.revoke(id));
                    drop(guard);
                }
                "expiry" => {
                    registry.lock_inner().entries[0].monotonic_deadline = Instant::now();
                    tokio::time::timeout(Duration::from_millis(100), registry.wait_revoked(id))
                        .await
                        .unwrap();
                    drop(guard);
                }
                _ => unreachable!(),
            }
            tokio::time::timeout(Duration::from_millis(100), registry.wait_revoked(id))
                .await
                .unwrap();
            assert!(registry.lock_inner().entries.is_empty());
        }
        // Ordinary manual sessions retain their existing exhausted-entry cleanup.
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        let (grant, _, action) = grant_scope();
        let token = registry.admit(grant, vec![(action, 100)]).unwrap();
        drop(
            registry
                .acquire(&token, action, crate::now_ts().unwrap())
                .unwrap(),
        );
        assert!(registry.lock_inner().entries.is_empty());
    }

    #[test]
    fn inventory_rechecks_revocation_expiry_and_requires_profile_scope() {
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        let (grant, scope, action) = grant_scope();
        let (token, guard) = registry
            .admit_profile(
                grant,
                vec![(action, 100)],
                scope,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        let (id, _, _) = registry
            .profile_inventory(&token, crate::now_ts().unwrap())
            .unwrap();
        drop(guard);
        assert_eq!(
            registry
                .ensure_inventory_live(id, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "INVALID_CAPABILITY"
        );
        assert_eq!(
            registry
                .profile_inventory(&token, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "INVALID_CAPABILITY"
        );
        let (grant, scope, action) = grant_scope();
        let (token, guard) = registry
            .admit_profile(
                grant,
                vec![(action, 100)],
                scope,
                Instant::now() - Duration::from_millis(1),
            )
            .unwrap();
        assert_eq!(
            registry
                .ensure_inventory_live(guard.session_id(), crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "CAPABILITY_EXPIRED"
        );
        assert_eq!(
            registry
                .profile_inventory(&token, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "INVALID_CAPABILITY"
        );
        let (grant, _, _) = grant_scope();
        let legacy = registry.create(grant).unwrap();
        assert_eq!(
            registry
                .profile_inventory(&legacy, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "INVALID_CAPABILITY"
        );
    }

    #[tokio::test]
    async fn profile_scope_is_derived_once_and_drop_revokes_without_await() {
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        let (grant, scope, action) = grant_scope();
        let (token, guard) = registry
            .admit_profile(
                grant,
                vec![(action, 100)],
                scope,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        let permit = registry
            .acquire(&token, action, crate::now_ts().unwrap())
            .unwrap();
        let scope = permit.profile_scope().unwrap();
        assert_eq!(scope.instance_slug, "one");
        assert_eq!(scope.capability, "read");
        assert!(scope.llm_limits.is_none());
        assert_eq!(scope.policy_sha256, [1; 32]);
        // The last reserved use must not terminate an in-flight/local-waiting session.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                registry.wait_revoked(guard.session_id())
            )
            .await
            .is_err()
        );
        let id = guard.session_id();
        drop(guard);
        tokio::time::timeout(Duration::from_millis(100), registry.wait_revoked(id))
            .await
            .unwrap();
        assert_eq!(registry.active_count(crate::now_ts().unwrap()), 0);
        drop(permit);
    }

    #[tokio::test]
    async fn profile_scope_missing_mapping_is_error_and_legacy_remains_none() {
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        let (grant, mut scope, action) = grant_scope();
        scope.profile.grants.clear();
        let (token, _guard) = registry
            .admit_profile(
                grant.clone(),
                vec![(action, 100)],
                scope,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        assert!(matches!(
            registry.acquire(&token, action, crate::now_ts().unwrap()),
            Err(BrokerError::Domain(DomainError::InvalidCapability))
        ));
        let token = registry.admit(grant, vec![(action, 100)]).unwrap();
        assert!(
            registry
                .acquire(&token, action, crate::now_ts().unwrap())
                .unwrap()
                .profile_scope()
                .is_none()
        );
    }

    #[tokio::test]
    async fn profile_monotonic_cap_and_wait_cancellation_do_not_extend_lifetime() {
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        let (grant, scope, action) = grant_scope();
        let (token, guard) = registry
            .admit_profile(
                grant,
                vec![(action, 100)],
                scope,
                Instant::now() + Duration::from_millis(40),
            )
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                registry.wait_revoked(guard.session_id())
            )
            .await
            .is_err()
        );
        tokio::time::timeout(
            Duration::from_millis(150),
            registry.wait_revoked(guard.session_id()),
        )
        .await
        .unwrap();
        assert!(
            registry
                .acquire(&token, action, crate::now_ts().unwrap())
                .is_err()
        );
    }
    #[tokio::test]
    async fn profile_failed_or_cancelled_frame_write_drops_unpublished_guard() {
        use rekey_domain::ids::RequestId;
        use rekey_domain::ipc::Channel;
        let registry = Arc::new(SessionRegistry::new());
        registry.open_for_admission();
        for cancel in [false, true] {
            let (grant, scope, action) = grant_scope();
            let (token, guard) = registry
                .admit_profile(
                    grant,
                    vec![(action, 100)],
                    scope,
                    Instant::now() + Duration::from_secs(60),
                )
                .unwrap();
            let (mut writer, reader) = tokio::io::duplex(1);
            let mut write = tokio::spawn(async move {
                let _guard = guard;
                crate::ipc::frame::write_ok(
                    &mut writer,
                    Channel::Admin,
                    RequestId::new_random(),
                    b"{}",
                    b"synthetic-response",
                )
                .await
            });
            if cancel {
                assert!(
                    tokio::time::timeout(Duration::from_millis(10), &mut write)
                        .await
                        .is_err()
                );
                write.abort();
                assert!(matches!(write.await, Err(error) if error.is_cancelled()));
                drop(reader);
            } else {
                drop(reader);
                assert!(write.await.unwrap().is_err());
            }
            assert!(matches!(
                registry.acquire(&token, action, crate::now_ts().unwrap()),
                Err(BrokerError::Domain(DomainError::InvalidCapability))
            ));
        }
    }
}
