use serde::{Deserialize, Serialize};

use crate::authorization::Principal;
use crate::error::DomainError;
use crate::ids::{ActionId, SessionId};
use crate::time::Timestamp;

pub const SESSION_TTL_MAX_MS: i64 = 24 * 60 * 60 * 1000;
pub const SESSION_TTL_DEFAULT_MS: i64 = 60 * 60 * 1000;
pub const SESSION_MAX_USES_MAX: u32 = 10_000;
pub const SESSION_MAX_USES_DEFAULT: u32 = 100;
pub const SESSION_MAX_CONCURRENT_EXECUTIONS: u32 = 4;
pub const CAPABILITY_TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProvenance {
    Admin,
    Workload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActionVersionRef {
    pub action_id: ActionId,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrant {
    pub id: SessionId,
    pub principal: Principal,
    pub allowed_actions: Vec<ActionVersionRef>,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub max_uses: u32,
}

impl SessionGrant {
    pub fn new(
        id: SessionId,
        principal: Principal,
        allowed_actions: Vec<ActionVersionRef>,
        issued_at: Timestamp,
        ttl_ms: i64,
        max_uses: u32,
    ) -> Result<Self, DomainError> {
        if allowed_actions.is_empty() {
            return Err(DomainError::InvalidCapability);
        }
        if allowed_actions.iter().any(|r| r.version == 0) {
            return Err(DomainError::InvalidCapability);
        }
        if ttl_ms <= 0 || ttl_ms > SESSION_TTL_MAX_MS {
            return Err(DomainError::InvalidCapability);
        }
        if max_uses == 0 || max_uses > SESSION_MAX_USES_MAX {
            return Err(DomainError::InvalidCapability);
        }
        Ok(Self {
            id,
            principal,
            allowed_actions,
            issued_at,
            expires_at: issued_at.saturating_add_ms(ttl_ms),
            max_uses,
        })
    }

    pub fn allows(&self, wanted: ActionVersionRef) -> bool {
        self.allowed_actions.contains(&wanted)
    }

    pub fn expired_at(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{PrincipalId, TenantId};

    fn principal(session_id: SessionId) -> Principal {
        Principal {
            tenant_id: TenantId::new_random(),
            principal_id: PrincipalId::new_random(),
            session_id,
        }
    }

    fn any_ref() -> ActionVersionRef {
        ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        }
    }

    #[test]
    fn grant_bounds() {
        let now = Timestamp::from_unix_ms(1_000);
        let id = SessionId::new_random();
        let principal = principal(id);
        assert!(SessionGrant::new(id, principal, vec![], now, 1000, 1).is_err());
        assert!(SessionGrant::new(id, principal, vec![any_ref()], now, 0, 1).is_err());
        assert!(
            SessionGrant::new(
                id,
                principal,
                vec![any_ref()],
                now,
                SESSION_TTL_MAX_MS + 1,
                1,
            )
            .is_err()
        );
        assert!(SessionGrant::new(id, principal, vec![any_ref()], now, 1000, 0).is_err());
        assert!(
            SessionGrant::new(
                id,
                principal,
                vec![any_ref()],
                now,
                1000,
                SESSION_MAX_USES_MAX + 1,
            )
            .is_err()
        );

        let grant = SessionGrant::new(id, principal, vec![any_ref()], now, 1000, 5).unwrap();
        assert!(!grant.expired_at(Timestamp::from_unix_ms(1_999)));
        assert!(grant.expired_at(Timestamp::from_unix_ms(2_000)));
    }

    #[test]
    fn allows_only_exact_action_version() {
        let now = Timestamp::from_unix_ms(0);
        let r = any_ref();
        let id = SessionId::new_random();
        let grant = SessionGrant::new(id, principal(id), vec![r], now, 1000, 1).unwrap();
        assert!(grant.allows(r));
        assert!(!grant.allows(ActionVersionRef {
            action_id: r.action_id,
            version: 2
        }));
        assert!(!grant.allows(any_ref()));
    }
}
