use std::collections::BTreeSet;
use std::time::Duration;

use rekey_domain::authorization::Principal;
use rekey_domain::capability::{SESSION_TTL_MAX_MS, SessionGrant, SessionProvenance};
use rekey_domain::ids::{SessionId, TenantId};
use rekey_domain::ipc::{SessionCreateMeta, SessionCreatedResponse};
use rekey_vault::AuthorityError;
use rekey_vault::command::AuditDraft;
use rekey_vault::model::{ActionState, event_type, outcome};
use zeroize::Zeroizing;

use super::BrokerCtx;
use crate::error::BrokerError;
use crate::session::CreateSessionError;

const WORKLOAD_ADMISSION_TIMEOUT: Duration = Duration::from_secs(25);

impl BrokerCtx {
    pub(crate) async fn create_workload_session(
        &self,
        create: SessionCreateMeta,
        token_body: Vec<u8>,
    ) -> Result<SessionCreatedResponse, BrokerError> {
        let deadline = tokio::time::Instant::now() + WORKLOAD_ADMISSION_TIMEOUT;
        self.lifecycle.reject_if_not_running()?;
        let token = normalize_token(token_body)?;
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        let now = crate::now_ts()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .ok_or(BrokerError::Authority(AuthorityError::PolicyUnavailable))?;
        if active.is_expired(now) {
            return Err(BrokerError::Authority(AuthorityError::PolicyUnavailable));
        }
        let verified = active
            .snapshot()
            .verify_workload_token(&token, now)
            .map_err(|_| BrokerError::Authority(AuthorityError::WorkloadIdentityInvalid))?;

        let distinct_actions = create.actions.iter().copied().collect::<BTreeSet<_>>();
        if create.actions.is_empty()
            || create.ttl_ms <= 0
            || create.max_uses == 0
            || distinct_actions.len() != create.actions.len()
        {
            return Err(BrokerError::Domain(
                rekey_domain::DomainError::InvalidCapability,
            ));
        }
        let mut action_timeouts = Vec::with_capacity(create.actions.len());
        for action in &create.actions {
            if !active
                .snapshot()
                .workload_principal_may_request(verified.principal_id, *action)
            {
                return Err(BrokerError::Denied("workload action is not authorized"));
            }
            let pinned = tokio::time::timeout_at(
                deadline,
                self.authority.action_get(action.action_id, action.version),
            )
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))??;
            if pinned.state != ActionState::Active {
                return Err(BrokerError::Domain(
                    rekey_domain::DomainError::ActionDisabled,
                ));
            }
            action_timeouts.push((*action, pinned.action.timeout_ms));
        }

        let requested_expiry = now.saturating_add_ms(create.ttl_ms.min(SESSION_TTL_MAX_MS));
        let expires_at_ms = requested_expiry
            .as_unix_ms()
            .min(verified.expires_at_ms)
            .min(active.snapshot().expires_at_ms());
        let effective_ttl_ms = expires_at_ms
            .checked_sub(now.as_unix_ms())
            .filter(|ttl| *ttl > 0)
            .ok_or(BrokerError::Authority(
                AuthorityError::WorkloadIdentityInvalid,
            ))?;
        let session_id = crate::random_id(SessionId::from_random_bytes)?;
        let vault_id = tokio::time::timeout_at(deadline, self.authority.status())
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))??
            .vault_id;
        let principal = Principal {
            tenant_id: TenantId::from_bytes(*vault_id.as_bytes()).map_err(BrokerError::Domain)?,
            principal_id: verified.principal_id,
            session_id,
        };
        let grant = SessionGrant::new(
            session_id,
            principal,
            create.actions,
            now,
            effective_ttl_ms,
            create.max_uses,
        )
        .map_err(BrokerError::Domain)?;
        reject_if_elapsed(deadline)?;
        let max_uses = grant.max_uses;
        let capability_token = self
            .sessions
            .admit_with_provenance(grant, action_timeouts, SessionProvenance::Workload)
            .map_err(|error| match error {
                CreateSessionError::Closed => BrokerError::Authority(AuthorityError::Draining),
                CreateSessionError::Domain(error) => BrokerError::Domain(error),
            })?;
        let consume = tokio::time::timeout_at(
            deadline,
            self.authority.consume_workload_token_before(
                verified.replay_digest,
                verified.expires_at_ms,
                workload_session_audit(session_id),
                Some(deadline.into_std()),
            ),
        )
        .await;
        let consume = match consume {
            Ok(result) => result,
            Err(_) => {
                self.sessions.revoke(session_id);
                self.request_fault();
                return Err(BrokerError::Authority(AuthorityError::Faulted));
            }
        };
        if let Err(error) = consume {
            self.sessions.revoke(session_id);
            if consume_error_requires_fault(&error) {
                self.request_fault();
            }
            return Err(BrokerError::Authority(error));
        }
        // Once replay and audit are durable, response loss intentionally leaves
        // this bounded session live until its normal revocation or expiry.
        reject_if_elapsed(deadline)?;
        Ok(SessionCreatedResponse {
            session_id,
            principal_id: verified.principal_id,
            capability_token,
            expires_at_ms,
            max_uses,
        })
    }
}

fn normalize_token(body: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let mut body = Zeroizing::new(body);
    if body.last() == Some(&b'\n') {
        body.pop();
    }
    if body.is_empty()
        || body
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || *byte == 0)
        || std::str::from_utf8(&body).is_err()
    {
        return Err(BrokerError::Authority(
            AuthorityError::WorkloadIdentityInvalid,
        ));
    }
    Ok(body)
}

fn consume_error_requires_fault(error: &AuthorityError) -> bool {
    !matches!(
        error,
        AuthorityError::WorkloadIdentityInvalid | AuthorityError::AuthorityBusy
    )
}

fn reject_if_elapsed(deadline: tokio::time::Instant) -> Result<(), BrokerError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
    }
    Ok(())
}

fn workload_session_audit(session_id: SessionId) -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: Some(session_id),
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: event_type::SESSION_CREATED,
        outcome: outcome::SUCCESS,
        reason_code: "workload-attested".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_pre_mutation_rejections_do_not_fault_the_broker() {
        assert!(!consume_error_requires_fault(
            &AuthorityError::WorkloadIdentityInvalid
        ));
        assert!(!consume_error_requires_fault(
            &AuthorityError::AuthorityBusy
        ));
        assert!(consume_error_requires_fault(
            &AuthorityError::AuditCommitFailed
        ));
        assert!(consume_error_requires_fault(&AuthorityError::Faulted));
    }
}
