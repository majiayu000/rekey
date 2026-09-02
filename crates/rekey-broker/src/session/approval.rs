use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rekey_domain::Timestamp;
use rekey_domain::authorization::{ApprovalRequirement, Principal, ResourceRef, SchemaId};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ApprovalId, PolicyRuleId};
use rekey_domain::ipc::ApprovalChallenge;
use rekey_policy::VerifiedApprovalGrant;
use rekey_vault::model::ApprovalEvidence;

use super::SessionRegistry;

#[derive(Clone)]
pub(crate) struct ApprovalContext {
    pub principal: Principal,
    pub action: ActionVersionRef,
    pub resource: ResourceRef,
    pub schema_id: SchemaId,
    pub parameter_hash: [u8; 32],
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub policy_rule_id: PolicyRuleId,
    pub requirement: ApprovalRequirement,
}

pub(super) struct StoredChallenge {
    challenge: ApprovalChallenge,
    monotonic_anchor: Instant,
    monotonic_deadline: Instant,
    expired: bool,
}

pub(super) struct ApprovalUsage {
    approval_id: ApprovalId,
    grant_digest: [u8; 32],
    uses: u32,
}

pub(super) struct ExpiredApproval {
    approval_id: ApprovalId,
    grant_digest: [u8; 32],
}

pub(crate) struct ApprovalReservation {
    pub(crate) evidence: Vec<ApprovalEvidence>,
    pub(crate) not_after: Instant,
    pub(crate) wall_not_after_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApprovalRejection(&'static str);

impl ApprovalRejection {
    pub(crate) fn code(self) -> &'static str {
        self.0
    }
}

fn reject(code: &'static str) -> ApprovalRejection {
    ApprovalRejection(code)
}

impl SessionRegistry {
    pub(crate) fn store_approval_challenge(
        &self,
        challenge: ApprovalChallenge,
        monotonic_anchor: Instant,
        monotonic_deadline: Instant,
    ) -> Result<(), ApprovalRejection> {
        let mut inner = self.lock_inner();
        let entry = inner
            .entries
            .iter_mut()
            .find(|entry| {
                entry.grant.id == challenge.session_id && entry.in_flight > 0 && !entry.revoked
            })
            .ok_or_else(|| reject("approval-session-unavailable"))?;
        if entry
            .approval_challenges
            .iter()
            .any(|stored| stored.challenge.approval_request_id == challenge.approval_request_id)
        {
            return Err(reject("approval-state-conflict"));
        }
        entry.approval_challenges.push(StoredChallenge {
            challenge,
            monotonic_anchor,
            monotonic_deadline,
            expired: false,
        });
        Ok(())
    }

    pub(crate) fn reserve_approvals(
        &self,
        context: &ApprovalContext,
        grants: &[VerifiedApprovalGrant],
        now: Timestamp,
    ) -> Result<ApprovalReservation, ApprovalRejection> {
        if grants.is_empty() || grants.len() > 2 {
            return Err(reject("approval-insufficient-quorum"));
        }
        let request_id = grants[0].grant().approval_request_id;
        if grants
            .iter()
            .any(|grant| grant.grant().approval_request_id != request_id)
        {
            return Err(reject("approval-request-mismatch"));
        }

        let monotonic_now = Instant::now();
        let mut inner = self.lock_inner();
        let entry = inner
            .entries
            .iter_mut()
            .find(|entry| {
                entry.grant.id == context.principal.session_id
                    && entry.in_flight > 0
                    && !entry.revoked
            })
            .ok_or_else(|| reject("approval-session-unavailable"))?;
        let stored = entry
            .approval_challenges
            .iter_mut()
            .find(|stored| stored.challenge.approval_request_id == request_id)
            .ok_or_else(|| reject("approval-challenge-unknown"))?;
        validate_challenge(stored, context, now, monotonic_now)?;

        let challenge = &stored.challenge;
        let mut approval_ids = BTreeSet::new();
        let mut approver_ids = BTreeSet::new();
        let mut not_after = stored.monotonic_deadline;
        let mut wall_not_after_ms = challenge.max_expires_at_ms;
        for verified in grants {
            let grant = verified.grant();
            if !approval_ids.insert(grant.approval_id) {
                return Err(reject("approval-id-duplicate"));
            }
            if !approver_ids.insert(grant.approver_id) {
                return Err(reject("approval-approver-duplicate"));
            }
            if let Some(expired) = entry
                .expired_approvals
                .iter()
                .find(|expired| expired.approval_id == grant.approval_id)
            {
                return if expired.grant_digest == verified.grant_digest() {
                    Err(reject("approval-expired"))
                } else {
                    Err(reject("approval-id-conflict"))
                };
            }
            if now.as_unix_ms() >= grant.expires_at_ms {
                entry.expired_approvals.push(ExpiredApproval {
                    approval_id: grant.approval_id,
                    grant_digest: verified.grant_digest(),
                });
                return Err(reject("approval-expired"));
            }
            not_after = not_after.min(validate_grant(
                verified,
                challenge,
                context,
                now,
                stored,
                monotonic_now,
            )?);
            wall_not_after_ms = wall_not_after_ms.min(grant.expires_at_ms);
            if let Some(usage) = entry
                .approval_uses
                .iter()
                .find(|usage| usage.approval_id == grant.approval_id)
            {
                if usage.grant_digest != verified.grant_digest() {
                    return Err(reject("approval-id-conflict"));
                }
                if usage.uses >= grant.max_uses {
                    return Err(reject("approval-use-exhausted"));
                }
            }
        }
        if approver_ids.len() < usize::from(context.requirement.quorum) {
            return Err(reject("approval-insufficient-quorum"));
        }

        let mut evidence = Vec::with_capacity(grants.len());
        for verified in grants {
            let grant = verified.grant();
            match entry
                .approval_uses
                .iter_mut()
                .find(|usage| usage.approval_id == grant.approval_id)
            {
                Some(usage) => usage.uses += 1,
                None => entry.approval_uses.push(ApprovalUsage {
                    approval_id: grant.approval_id,
                    grant_digest: verified.grant_digest(),
                    uses: 1,
                }),
            }
            evidence.push(ApprovalEvidence {
                approval_request_id: request_id,
                approval_id: Some(grant.approval_id),
                approver_id: Some(grant.approver_id),
            });
        }
        Ok(ApprovalReservation {
            evidence,
            not_after,
            wall_not_after_ms,
        })
    }
}

fn validate_challenge(
    stored: &mut StoredChallenge,
    context: &ApprovalContext,
    now: Timestamp,
    monotonic_now: Instant,
) -> Result<(), ApprovalRejection> {
    let challenge = &stored.challenge;
    if challenge.tenant_id != context.principal.tenant_id
        || challenge.principal_id != context.principal.principal_id
        || challenge.session_id != context.principal.session_id
        || challenge.action_id != context.action.action_id
        || challenge.action_version != context.action.version
        || challenge.resource != context.resource
        || challenge.schema_id != context.schema_id
        || challenge.parameter_sha256 != data_encoding::HEXLOWER.encode(&context.parameter_hash)
        || challenge.policy_version != context.policy_version
        || challenge.policy_sha256 != data_encoding::HEXLOWER.encode(&context.policy_digest)
        || challenge.policy_rule_id != context.policy_rule_id
        || challenge.mode != context.requirement.mode
        || challenge.quorum != context.requirement.quorum
        || challenge.approver_ids != context.requirement.approver_ids
        || challenge.max_uses != context.requirement.max_uses
    {
        return Err(reject("approval-tuple-mismatch"));
    }
    if stored.expired {
        return Err(reject("approval-challenge-expired"));
    }
    if now.as_unix_ms() >= challenge.max_expires_at_ms || monotonic_now >= stored.monotonic_deadline
    {
        stored.expired = true;
        return Err(reject("approval-challenge-expired"));
    }
    Ok(())
}

fn validate_grant(
    verified: &VerifiedApprovalGrant,
    challenge: &ApprovalChallenge,
    context: &ApprovalContext,
    now: Timestamp,
    stored: &StoredChallenge,
    monotonic_now: Instant,
) -> Result<Instant, ApprovalRejection> {
    let grant = verified.grant();
    if grant.tenant_id != challenge.tenant_id
        || grant.principal_id != challenge.principal_id
        || grant.session_id != challenge.session_id
        || grant.action_id != challenge.action_id
        || grant.action_version != challenge.action_version
        || grant.resource != challenge.resource
        || grant.schema_id != challenge.schema_id
        || verified.parameter_hash() != context.parameter_hash
        || grant.policy_version.get() != challenge.policy_version
        || verified.policy_digest() != context.policy_digest
        || grant.policy_rule_id != challenge.policy_rule_id
        || grant.mode != challenge.mode
    {
        return Err(reject("approval-tuple-mismatch"));
    }
    if !challenge.approver_ids.contains(&grant.approver_id) {
        return Err(reject("approval-approver-not-allowed"));
    }
    if grant.max_uses > challenge.max_uses {
        return Err(reject("approval-use-limit-invalid"));
    }
    let now_ms = now.as_unix_ms();
    if now_ms < grant.not_before_ms {
        return Err(reject("approval-not-yet-valid"));
    }
    if grant.expires_at_ms > challenge.max_expires_at_ms {
        return Err(reject("approval-expired"));
    }
    if grant.mode == rekey_domain::authorization::ApprovalMode::OneTime
        && grant.expires_at_ms.saturating_sub(grant.not_before_ms) > 10 * 60 * 1_000
    {
        return Err(reject("approval-window-invalid"));
    }
    let derived_deadline = stored
        .monotonic_anchor
        .checked_add(monotonic_expiry_offset(
            grant.expires_at_ms,
            challenge.created_at_ms,
        )?)
        .ok_or_else(|| reject("approval-window-invalid"))?
        .min(stored.monotonic_deadline);
    if monotonic_now >= derived_deadline {
        return Err(reject("approval-expired"));
    }
    Ok(derived_deadline)
}

fn monotonic_expiry_offset(
    expires_at_ms: i64,
    challenge_created_at_ms: i64,
) -> Result<Duration, ApprovalRejection> {
    let duration_ms = expires_at_ms
        .checked_sub(challenge_created_at_ms)
        .filter(|duration| *duration > 0)
        .ok_or_else(|| reject("approval-window-invalid"))?;
    Ok(Duration::from_millis(duration_ms as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_expiry_requires_time_after_challenge_creation() {
        assert_eq!(
            monotonic_expiry_offset(101, 100).unwrap(),
            Duration::from_millis(1)
        );
        assert!(monotonic_expiry_offset(100, 100).is_err());
        assert!(monotonic_expiry_offset(99, 100).is_err());
        assert!(monotonic_expiry_offset(i64::MAX, -1).is_err());
    }
}
