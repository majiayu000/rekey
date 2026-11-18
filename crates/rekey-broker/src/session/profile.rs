//! Lab-only signed Profile sessions: control-owned admission and the read-only
//! inventory lookup. The default build never mints or inspects one.
use super::*;

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
}

/// Synchronous revocation on every cancellation path, before any audit await.
pub(crate) struct ProfileSessionGuard {
    registry: Arc<SessionRegistry>,
    session_id: SessionId,
    _control_owner: Arc<OwnedSemaphorePermit>,
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

    pub(crate) fn admit_profile(
        self: &Arc<Self>,
        grant: SessionGrant,
        action_timeouts: Vec<(ActionVersionRef, u32)>,
        scope: ProfileSessionScope,
        deadline: Instant,
        control_owner: Arc<OwnedSemaphorePermit>,
    ) -> Result<(Zeroizing<String>, ProfileSessionGuard), CreateSessionError> {
        let session_id = grant.id;
        let token = self.admit_inner(
            grant,
            action_timeouts,
            SessionProvenance::Admin,
            Some(Arc::new(scope)),
            Some(deadline),
            Some(Arc::downgrade(&control_owner)),
        )?;
        // No await or fallible work may separate insertion from ownership.
        Ok((
            Zeroizing::new(token),
            ProfileSessionGuard {
                registry: Arc::clone(self),
                session_id,
                _control_owner: control_owner,
            },
        ))
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
