#[cfg(test)]
use rekey_domain::ipc::LocalApprovalReviewResponse;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::error::BrokerError;
use rekey_domain::Timestamp;
use rekey_domain::authorization::{
    ApprovalRequirement, ApproverSpec, Principal, ResourceRef, SchemaId,
};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ApprovalId, ApprovalRequestId, ApproverId, PolicyRuleId};
use rekey_domain::ipc::{
    APPROVAL_PENDING_MAX, ApprovalChallenge, LocalApprovalState, LocalApprovalStateResponse,
};
use rekey_policy::VerifiedApprovalGrant;
use rekey_vault::model::ApprovalEvidence;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

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
    pub approver: ApproverSpec,
    // Derived once from the same authenticated snapshot; never a wire source.
    pub allowed_approver_ids: Vec<ApproverId>,
    pub requirement: ApprovalRequirement,
}

pub(super) struct StoredChallenge {
    challenge: ApprovalChallenge,
    monotonic_anchor: Instant,
    monotonic_deadline: Instant,
    state: ChallengeState,
    review: Option<LocalReview>,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChallengeState {
    Pending,
    Approved(ApprovalId),
    Consumed,
    Cancelled,
    Expired,
}

struct LocalReview {
    request_context: Option<rekey_domain::audit::RequestAuditContext>,
    hash: String,
    body: Zeroizing<Vec<u8>>,
}

pub(crate) struct LocalApproval {
    #[cfg_attr(not(feature = "lab"), allow(dead_code))]
    pub request_context: Option<rekey_domain::audit::RequestAuditContext>,
    pub challenge: ApprovalChallenge,
    pub state: LocalApprovalState,
    pub review_sha256: String,
    pub deadline: Instant,
}
impl LocalApproval {
    pub(crate) fn response(&self) -> LocalApprovalStateResponse {
        LocalApprovalStateResponse {
            approval_request_id: self.challenge.approval_request_id,
            state: self.state,
            expires_at_ms: self.challenge.max_expires_at_ms,
        }
    }
}

pub(super) fn is_local(stored: &StoredChallenge) -> bool {
    stored.review.is_some()
}

fn refresh_local(stored: &mut StoredChallenge, now: Timestamp) {
    if matches!(
        stored.state,
        ChallengeState::Pending | ChallengeState::Approved(_)
    ) && (now.as_unix_ms() < stored.challenge.created_at_ms
        || now.as_unix_ms() >= stored.challenge.max_expires_at_ms
        || Instant::now() >= stored.monotonic_deadline)
    {
        stored.state = ChallengeState::Expired;
        if let Some(review) = &mut stored.review {
            review.body.zeroize();
        }
    }
}
fn local_snapshot(stored: &StoredChallenge) -> LocalApproval {
    LocalApproval {
        request_context: stored
            .review
            .as_ref()
            .expect("local review")
            .request_context
            .clone(),
        challenge: stored.challenge.clone(),
        state: match stored.state {
            ChallengeState::Pending => LocalApprovalState::Pending,
            ChallengeState::Approved(_) => LocalApprovalState::Approved,
            ChallengeState::Consumed => LocalApprovalState::Consumed,
            ChallengeState::Cancelled => LocalApprovalState::Cancelled,
            ChallengeState::Expired => LocalApprovalState::Expired,
        },
        review_sha256: stored.review.as_ref().expect("local review").hash.clone(),
        deadline: stored.monotonic_deadline,
    }
}

pub(super) fn challenge_is_pending(
    stored: &mut StoredChallenge,
    now: Timestamp,
    monotonic_now: Instant,
) -> bool {
    if stored.state != ChallengeState::Pending {
        return false;
    }
    if (is_local(stored) && now.as_unix_ms() < stored.challenge.created_at_ms)
        || now.as_unix_ms() >= stored.challenge.max_expires_at_ms
        || monotonic_now >= stored.monotonic_deadline
    {
        stored.state = ChallengeState::Expired;
        if let Some(review) = &mut stored.review {
            review.body.zeroize();
        }
        return false;
    }
    true
}

fn pending_count(entries: &mut [super::Entry], now: Timestamp, monotonic_now: Instant) -> usize {
    let mut count = 0;
    for entry in entries.iter_mut() {
        if entry.revoked {
            continue;
        }
        for stored in &mut entry.approval_challenges {
            if is_local(stored) || challenge_is_pending(stored, now, monotonic_now) {
                count += 1;
            }
        }
    }
    count
}

impl SessionRegistry {
    pub(crate) fn store_approval_challenge(
        &self,
        challenge: ApprovalChallenge,
        monotonic_anchor: Instant,
        monotonic_deadline: Instant,
        now: Timestamp,
    ) -> Result<(), ApprovalRejection> {
        let monotonic_now = Instant::now();
        let mut inner = self.lock_inner();
        super::compact_entries(&mut inner.entries);
        let index = inner
            .entries
            .iter()
            .position(|entry| {
                entry.grant.id == challenge.session_id && entry.in_flight > 0 && !entry.revoked
            })
            .ok_or_else(|| reject("approval-session-unavailable"))?;
        if inner.entries[index]
            .approval_challenges
            .iter()
            .any(|stored| stored.challenge.approval_request_id == challenge.approval_request_id)
        {
            return Err(reject("approval-state-conflict"));
        }
        if pending_count(&mut inner.entries, now, monotonic_now) >= APPROVAL_PENDING_MAX {
            return Err(reject("approval-inbox-overflow"));
        }
        inner.entries[index]
            .approval_challenges
            .push(StoredChallenge {
                challenge,
                monotonic_anchor,
                monotonic_deadline,
                state: ChallengeState::Pending,
                review: None,
            });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pending_approval_challenges(
        &self,
        now: Timestamp,
    ) -> Result<Vec<ApprovalChallenge>, ApprovalRejection> {
        let monotonic_now = Instant::now();
        let mut inner = self.lock_inner();
        super::compact_entries(&mut inner.entries);
        let mut out = Vec::new();
        for entry in inner.entries.iter_mut() {
            if entry.revoked {
                continue;
            }
            for stored in &mut entry.approval_challenges {
                if !challenge_is_pending(stored, now, monotonic_now) {
                    continue;
                }
                out.push(stored.challenge.clone());
                if out.len() > APPROVAL_PENDING_MAX {
                    return Err(reject("approval-inbox-overflow"));
                }
            }
        }
        out.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.approval_request_id.cmp(&right.approval_request_id))
        });
        Ok(out)
    }

    #[cfg(any(feature = "lab", test))]
    pub(crate) fn approval_challenge(
        &self,
        approval_request_id: ApprovalRequestId,
        now: Timestamp,
    ) -> Result<ApprovalChallenge, ApprovalRejection> {
        let monotonic_now = Instant::now();
        let mut inner = self.lock_inner();
        super::compact_entries(&mut inner.entries);
        for entry in inner.entries.iter_mut() {
            if entry.revoked {
                continue;
            }
            for stored in &mut entry.approval_challenges {
                if stored.challenge.approval_request_id != approval_request_id {
                    continue;
                }
                if !challenge_is_pending(stored, now, monotonic_now) {
                    return Err(reject("approval-challenge-unknown"));
                }
                return Ok(stored.challenge.clone());
            }
        }
        Err(reject("approval-challenge-unknown"))
    }

    // Every caller that mutates a local decision holds the lifecycle coordinator.
    pub(crate) fn local_for_execution(
        &self,
        permit: &super::ExecutionPermit,
        context: &ApprovalContext,
        wanted: Option<ApprovalRequestId>,
        now: Timestamp,
    ) -> Result<Option<LocalApproval>, BrokerError> {
        let mut inner = self.lock_inner();
        let entry = inner
            .entries
            .iter_mut()
            .find(|entry| entry.grant.id == permit.session_id && !entry.revoked)
            .ok_or(BrokerError::Denied("approval-session-unavailable"))?;
        for stored in &mut entry.approval_challenges {
            if !is_local(stored)
                || wanted.is_some_and(|id| id != stored.challenge.approval_request_id)
            {
                continue;
            }
            refresh_local(stored, now);
            let validation = validate_challenge(stored, context, now, Instant::now());
            if wanted.is_some() {
                validation.map_err(|e| BrokerError::Denied(e.code()))?;
                return Ok(Some(local_snapshot(stored)));
            }
            if validation.is_ok()
                && matches!(
                    stored.state,
                    ChallengeState::Pending | ChallengeState::Approved(_)
                )
            {
                return Ok(Some(local_snapshot(stored)));
            }
        }
        if wanted.is_some() {
            Err(BrokerError::Denied("approval-challenge-unknown"))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn local_capacity(&self) -> Result<(), BrokerError> {
        let mut inner = self.lock_inner();
        super::compact_entries(&mut inner.entries);
        if pending_count(&mut inner.entries, crate::now_ts()?, Instant::now())
            >= APPROVAL_PENDING_MAX
        {
            return Err(BrokerError::Denied("approval-inbox-overflow"));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_local_pending(
        &self,
        permit: &mut super::ExecutionPermit,
        challenge: ApprovalChallenge,
        body: Vec<u8>,
        hash: String,
        anchor: Instant,
        deadline: Instant,
        request_context: Option<rekey_domain::audit::RequestAuditContext>,
    ) -> Result<LocalApproval, BrokerError> {
        let mut inner = self.lock_inner();
        if inner.closed
            || pending_count(&mut inner.entries, crate::now_ts()?, Instant::now())
                >= APPROVAL_PENDING_MAX
        {
            return Err(BrokerError::Denied("approval-inbox-overflow"));
        }
        let entry = inner
            .entries
            .iter_mut()
            .find(|e| e.grant.id == permit.session_id && !e.revoked && e.in_flight > 0)
            .ok_or(BrokerError::Denied("approval-session-unavailable"))?;
        let stored = StoredChallenge {
            challenge,
            monotonic_anchor: anchor,
            monotonic_deadline: deadline.min(entry.monotonic_deadline),
            state: ChallengeState::Pending,
            review: Some(LocalReview {
                request_context,
                hash,
                body: Zeroizing::new(body),
            }),
        };
        let result = local_snapshot(&stored);
        entry.approval_challenges.push(stored);
        refund_local_wait(entry, permit)?;
        self.approval_changed.notify_waiters();
        Ok(result)
    }

    pub(crate) fn refund_local_wait(
        &self,
        permit: &mut super::ExecutionPermit,
        id: ApprovalRequestId,
    ) -> Result<(), BrokerError> {
        let mut inner = self.lock_inner();
        let entry = inner
            .entries
            .iter_mut()
            .find(|e| e.grant.id == permit.session_id && !e.revoked && e.in_flight > 0)
            .ok_or(BrokerError::Denied("approval-session-unavailable"))?;
        if !entry.approval_challenges.iter().any(|c| {
            c.challenge.approval_request_id == id
                && is_local(c)
                && matches!(
                    c.state,
                    ChallengeState::Pending | ChallengeState::Approved(_)
                )
        }) {
            return Err(BrokerError::Denied("approval-challenge-unavailable"));
        }
        refund_local_wait(entry, permit)
    }

    #[cfg(any(test, feature = "lab"))]
    pub(crate) fn local_approval(
        &self,
        id: ApprovalRequestId,
        now: Timestamp,
    ) -> Result<LocalApproval, BrokerError> {
        let mut inner = self.lock_inner();
        let stored = local_stored(&mut inner, id)?;
        refresh_local(stored, now);
        Ok(local_snapshot(stored))
    }

    #[cfg(test)]
    pub(crate) fn local_review(
        &self,
        id: ApprovalRequestId,
        now: Timestamp,
    ) -> Result<(LocalApprovalReviewResponse, Zeroizing<Vec<u8>>), BrokerError> {
        let mut inner = self.lock_inner();
        let stored = local_stored(&mut inner, id)?;
        refresh_local(stored, now);
        let snapshot = local_snapshot(stored);
        let review = stored.review.as_ref().expect("local review");
        Ok((
            LocalApprovalReviewResponse {
                record_type: "rekey.approval.local-review.v1".into(),
                approval_request_id: id,
                review_sha256: snapshot.review_sha256,
                state: snapshot.state,
                body_len: review.body.len() as u32,
            },
            review.body.clone(),
        ))
    }

    pub(crate) fn local_state_for_owner(
        &self,
        token: &str,
        id: ApprovalRequestId,
        now: Timestamp,
    ) -> Result<LocalApproval, BrokerError> {
        let raw = Zeroizing::new(
            data_encoding::BASE64URL_NOPAD
                .decode(token.as_bytes())
                .map_err(|_| rekey_domain::DomainError::InvalidCapability)?,
        );
        if raw.len() != rekey_domain::capability::CAPABILITY_TOKEN_BYTES {
            return Err(rekey_domain::DomainError::InvalidCapability.into());
        }
        let hash = super::hash_token(&raw);
        let mut inner = self.lock_inner();
        if inner.closed {
            return Err(rekey_domain::DomainError::InvalidCapability.into());
        }
        let mut found = None;
        for (i, e) in inner.entries.iter().enumerate() {
            if bool::from(e.token_hash.ct_eq(&hash)) {
                found = Some(i);
            }
        }
        let entry = found
            .map(|i| &mut inner.entries[i])
            .ok_or(rekey_domain::DomainError::InvalidCapability)?;
        if entry.revoked {
            return Err(rekey_domain::DomainError::InvalidCapability.into());
        }
        if entry.grant.expired_at(now) || Instant::now() >= entry.monotonic_deadline {
            entry.revoked = true;
            return Err(rekey_domain::DomainError::CapabilityExpired.into());
        }
        let stored = entry
            .approval_challenges
            .iter_mut()
            .find(|c| is_local(c) && c.challenge.approval_request_id == id)
            .ok_or(BrokerError::Denied("approval-challenge-unknown"))?;
        refresh_local(stored, now);
        let mut snapshot = local_snapshot(stored);
        snapshot.deadline = snapshot.deadline.min(entry.monotonic_deadline);
        Ok(snapshot)
    }

    pub(crate) fn decide_local(
        &self,
        id: ApprovalRequestId,
        hash: &str,
        approval_id: Option<ApprovalId>,
        now: Timestamp,
    ) -> Result<LocalApprovalStateResponse, BrokerError> {
        let mut inner = self.lock_inner();
        let stored = local_stored(&mut inner, id)?;
        refresh_local(stored, now);
        if stored.review.as_ref().expect("local review").hash != hash {
            return Err(BrokerError::Denied("approval-review-mismatch"));
        }
        if approval_id.is_some() && stored.state != ChallengeState::Pending {
            return Err(BrokerError::Denied("approval-challenge-unavailable"));
        }
        if !matches!(
            stored.state,
            ChallengeState::Pending | ChallengeState::Approved(_)
        ) {
            return Ok(local_snapshot(stored).response());
        }
        stored.state = match approval_id {
            Some(id) => ChallengeState::Approved(id),
            None => ChallengeState::Cancelled,
        };
        if approval_id.is_none() {
            stored.review.as_mut().expect("local review").body.zeroize();
        }
        self.approval_changed.notify_waiters();
        Ok(local_snapshot(stored).response())
    }

    // A queued decision whose result is unknown cannot be retried. Missing state
    // is already revoked; this cleanup never restores an entry or a grant.
    #[cfg(any(test, feature = "lab"))]
    pub(crate) fn cancel_local_unconfirmed(&self, id: ApprovalRequestId) {
        let mut inner = self.lock_inner();
        for stored in inner
            .entries
            .iter_mut()
            .flat_map(|e| &mut e.approval_challenges)
        {
            if is_local(stored)
                && stored.challenge.approval_request_id == id
                && matches!(
                    stored.state,
                    ChallengeState::Pending | ChallengeState::Approved(_)
                )
            {
                stored.state = ChallengeState::Cancelled;
                stored.review.as_mut().expect("local review").body.zeroize();
            }
        }
        self.approval_changed.notify_waiters();
    }

    pub(crate) fn consume_local(
        &self,
        permit: &super::ExecutionPermit,
        context: &ApprovalContext,
        id: ApprovalRequestId,
        now: Timestamp,
    ) -> Result<ApprovalReservation, BrokerError> {
        let mut inner = self.lock_inner();
        let entry = inner
            .entries
            .iter_mut()
            .find(|e| e.grant.id == permit.session_id && !e.revoked && e.in_flight > 0)
            .ok_or(BrokerError::Denied("approval-session-unavailable"))?;
        let stored = entry
            .approval_challenges
            .iter_mut()
            .find(|c| is_local(c) && c.challenge.approval_request_id == id)
            .ok_or(BrokerError::Denied("approval-challenge-unknown"))?;
        refresh_local(stored, now);
        validate_challenge(stored, context, now, Instant::now())
            .map_err(|e| BrokerError::Denied(e.code()))?;
        let ChallengeState::Approved(approval_id) = stored.state else {
            return Err(BrokerError::Denied("approval-challenge-unavailable"));
        };
        stored.state = ChallengeState::Consumed;
        stored.review.as_mut().expect("local review").body.zeroize();
        self.approval_changed.notify_waiters();
        Ok(ApprovalReservation {
            evidence: vec![ApprovalEvidence {
                approval_request_id: id,
                approval_id: Some(approval_id),
                approver_id: None,
            }],
            not_after: stored.monotonic_deadline,
            wall_not_after_ms: stored.challenge.max_expires_at_ms,
        })
    }

    pub(crate) fn reserve_approvals(
        &self,
        context: &ApprovalContext,
        grants: &[VerifiedApprovalGrant],
        now: Timestamp,
    ) -> Result<ApprovalReservation, ApprovalRejection> {
        let threshold = match &context.approver {
            ApproverSpec::Ed25519 { threshold, .. } => *threshold,
            _ => return Err(reject("approval-approver-unsupported")),
        };
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
        if approver_ids.len() < usize::from(threshold) {
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
        stored.state = ChallengeState::Consumed;
        Ok(ApprovalReservation {
            evidence,
            not_after,
            wall_not_after_ms,
        })
    }
}

fn refund_local_wait(
    entry: &mut super::Entry,
    permit: &mut super::ExecutionPermit,
) -> Result<(), BrokerError> {
    if permit.use_refunded {
        return Err(BrokerError::Denied("approval-state-conflict"));
    }
    entry.uses_left = entry
        .uses_left
        .checked_add(1)
        .ok_or(BrokerError::Denied("approval-state-conflict"))?;
    entry.exhausted = false;
    permit.use_refunded = true;
    Ok(())
}
fn local_stored(
    inner: &mut super::Inner,
    id: ApprovalRequestId,
) -> Result<&mut StoredChallenge, BrokerError> {
    if inner.closed {
        return Err(BrokerError::Denied("approval-session-unavailable"));
    }
    inner
        .entries
        .iter_mut()
        .filter(|e| !e.revoked && Instant::now() < e.monotonic_deadline)
        .flat_map(|e| &mut e.approval_challenges)
        .find(|c| is_local(c) && c.challenge.approval_request_id == id)
        .ok_or(BrokerError::Denied("approval-challenge-unknown"))
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
        || challenge.approver != context.approver
        || challenge.max_uses != context.requirement.max_uses
    {
        return Err(reject("approval-tuple-mismatch"));
    }
    if stored.state == ChallengeState::Expired {
        return Err(reject("approval-challenge-expired"));
    }
    if now.as_unix_ms() >= challenge.max_expires_at_ms || monotonic_now >= stored.monotonic_deadline
    {
        stored.state = ChallengeState::Expired;
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
    if !context.allowed_approver_ids.contains(&grant.approver_id) {
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
    use rekey_domain::authorization::{ApprovalMode, Principal, ResourceRef, SchemaId};
    use rekey_domain::capability::{ActionVersionRef, SessionGrant};
    use rekey_domain::ids::{ActionId, PolicyRuleId, PrincipalId, SessionId, TenantId};

    fn now(ms: i64) -> Timestamp {
        Timestamp::from_unix_ms(ms)
    }

    fn open_registry() -> SessionRegistry {
        let registry = SessionRegistry::new();
        registry.open_for_admission();
        registry
    }

    fn grant(max_uses: u32) -> (SessionGrant, ActionVersionRef) {
        let action = ActionVersionRef {
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
            vec![action],
            now(0),
            10_000,
            max_uses,
        )
        .unwrap();
        (grant, action)
    }

    fn challenge(
        grant: &SessionGrant,
        action: ActionVersionRef,
        created_at_ms: i64,
        max_expires_at_ms: i64,
    ) -> ApprovalChallenge {
        ApprovalChallenge {
            record_type: "rekey.approval.challenge.v2".to_owned(),
            approval_request_id: ApprovalRequestId::new_random(),
            tenant_id: grant.principal.tenant_id,
            principal_id: grant.principal.principal_id,
            session_id: grant.id,
            action_id: action.action_id,
            action_version: action.version,
            resource: ResourceRef::new("test.resource".to_owned(), "one".to_owned()).unwrap(),
            schema_id: SchemaId::new("test/v1".to_owned()).unwrap(),
            parameter_sha256: "00".repeat(32),
            policy_version: 1,
            policy_sha256: "11".repeat(32),
            policy_rule_id: PolicyRuleId::new_random(),
            mode: ApprovalMode::OneTime,
            approver: ApproverSpec::Ed25519 {
                keys: vec!["11".repeat(32)],
                threshold: 1,
            },
            max_uses: 1,
            created_at_ms,
            max_expires_at_ms,
        }
    }

    fn store(
        registry: &SessionRegistry,
        challenge: ApprovalChallenge,
        now: Timestamp,
    ) -> Result<(), ApprovalRejection> {
        registry.store_approval_challenge(
            challenge,
            Instant::now(),
            Instant::now() + Duration::from_secs(60),
            now,
        )
    }

    #[test]
    fn changed_approver_kind_keys_or_threshold_cannot_reuse_challenge() {
        let (grant, action) = grant(1);
        let challenge = challenge(&grant, action, 0, 10_000);
        let context = ApprovalContext {
            principal: grant.principal,
            action,
            resource: challenge.resource.clone(),
            schema_id: challenge.schema_id.clone(),
            parameter_hash: [0; 32],
            policy_version: 1,
            policy_digest: [0x11; 32],
            policy_rule_id: challenge.policy_rule_id,
            approver: challenge.approver.clone(),
            allowed_approver_ids: vec![],
            requirement: ApprovalRequirement {
                mode: ApprovalMode::OneTime,
                max_uses: 1,
                max_window_ms: None,
            },
        };
        let instant = Instant::now();
        let mut stored = StoredChallenge {
            challenge,
            monotonic_anchor: instant,
            monotonic_deadline: instant + Duration::from_secs(10),
            state: ChallengeState::Pending,
            review: None,
        };
        validate_challenge(&mut stored, &context, now(1), instant).unwrap();
        for approver in [
            ApproverSpec::LocalPresence {},
            ApproverSpec::Ed25519 {
                keys: vec!["22".repeat(32)],
                threshold: 1,
            },
            ApproverSpec::Ed25519 {
                keys: vec!["11".repeat(32)],
                threshold: 2,
            },
        ] {
            let changed = ApprovalContext {
                approver,
                ..context.clone()
            };
            assert_eq!(
                validate_challenge(&mut stored, &changed, now(1), instant),
                Err(reject("approval-tuple-mismatch"))
            );
        }
    }

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

    #[test]
    fn pending_lists_live_challenges_and_hides_expired_or_revoked() {
        let registry = open_registry();
        let (grant, action) = grant(4);
        let session_id = grant.id;
        let token = registry.create(grant.clone()).unwrap();
        registry.begin(&token, action, now(1)).unwrap();
        let live = challenge(&grant, action, 1, 9_000);
        let expired = challenge(&grant, action, 0, 1);
        let live_id = live.approval_request_id;
        store(&registry, live, now(1)).unwrap();
        store(&registry, expired, now(1)).unwrap();
        registry.finish(session_id);

        let pending = registry.pending_approval_challenges(now(2)).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].approval_request_id, live_id);
        assert_eq!(
            registry
                .approval_challenge(live_id, now(2))
                .unwrap()
                .approval_request_id,
            live_id
        );
        assert_eq!(
            registry
                .approval_challenge(ApprovalRequestId::new_random(), now(2))
                .unwrap_err()
                .code(),
            "approval-challenge-unknown"
        );

        registry.revoke(session_id);
        assert!(
            registry
                .pending_approval_challenges(now(2))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            registry
                .approval_challenge(live_id, now(2))
                .unwrap_err()
                .code(),
            "approval-challenge-unknown"
        );
    }

    #[test]
    fn inbox_overflow_fails_closed() {
        let registry = open_registry();
        let (grant, action) = grant(1);
        let token = registry.create(grant.clone()).unwrap();
        registry.begin(&token, action, now(1)).unwrap();
        for _ in 0..APPROVAL_PENDING_MAX {
            store(&registry, challenge(&grant, action, 1, 9_000), now(1)).unwrap();
        }
        assert_eq!(
            store(&registry, challenge(&grant, action, 1, 9_000), now(1))
                .unwrap_err()
                .code(),
            "approval-inbox-overflow"
        );
        assert_eq!(
            registry.pending_approval_challenges(now(1)).unwrap().len(),
            APPROVAL_PENDING_MAX
        );
    }
    fn local_fixture() -> (
        std::sync::Arc<SessionRegistry>,
        String,
        super::super::ExecutionPermit,
        ApprovalChallenge,
        ApprovalContext,
    ) {
        let registry = std::sync::Arc::new(open_registry());
        let (grant, action) = grant(1);
        let token = registry.create(grant.clone()).unwrap();
        let permit = registry.acquire(&token, action, now(1)).unwrap();
        let mut challenge = challenge(&grant, action, 1, 9_000);
        challenge.approver = ApproverSpec::LocalPresence {};
        let context = ApprovalContext {
            principal: grant.principal,
            action,
            resource: challenge.resource.clone(),
            schema_id: challenge.schema_id.clone(),
            parameter_hash: [0; 32],
            policy_version: 1,
            policy_digest: [0x11; 32],
            policy_rule_id: challenge.policy_rule_id,
            approver: challenge.approver.clone(),
            allowed_approver_ids: vec![],
            requirement: ApprovalRequirement {
                mode: ApprovalMode::OneTime,
                max_uses: 1,
                max_window_ms: None,
            },
        };
        (registry, token, permit, challenge, context)
    }

    #[test]
    fn local_refund_is_once_and_consumption_compares_full_context() {
        let (registry, token, mut permit, challenge, context) = local_fixture();
        assert!(matches!(
            registry.acquire(&token, context.action, now(1)),
            Err(BrokerError::Authority(
                rekey_vault::AuthorityError::AuthorityBusy
            ))
        ));
        let id = challenge.approval_request_id;
        registry
            .publish_local_pending(
                &mut permit,
                challenge,
                b"review".to_vec(),
                "hash".into(),
                Instant::now(),
                Instant::now() + Duration::from_secs(60),
                None,
            )
            .unwrap();
        assert!(registry.refund_local_wait(&mut permit, id).is_err());
        assert_eq!(registry.lock_inner().entries[0].uses_left, 1);
        drop(permit);
        registry
            .decide_local(id, "hash", Some(ApprovalId::new_random()), now(2))
            .unwrap();
        let permit = registry.acquire(&token, context.action, now(2)).unwrap();
        for altered in [
            ApprovalContext {
                parameter_hash: [2; 32],
                ..context.clone()
            },
            ApprovalContext {
                policy_digest: [2; 32],
                ..context.clone()
            },
            ApprovalContext {
                schema_id: SchemaId::new("other/v1".into()).unwrap(),
                ..context.clone()
            },
        ] {
            assert!(
                registry
                    .consume_local(&permit, &altered, id, now(2))
                    .is_err()
            );
        }
        assert!(
            registry
                .consume_local(&permit, &context, id, now(2))
                .is_ok()
        );
        assert!(
            registry
                .consume_local(&permit, &context, id, now(2))
                .is_err()
        );
        drop(permit);
        assert_eq!(
            registry
                .local_state_for_owner(&token, id, now(3))
                .unwrap()
                .state,
            LocalApprovalState::Consumed
        );
        assert!(registry.local_review(id, now(3)).unwrap().1.is_empty());
        assert_eq!(registry.lock_inner().entries[0].uses_left, 0);
    }

    #[test]
    fn local_dual_clock_expiry_latches_and_cannot_renew_session_deadline() {
        for backwards in [false, true] {
            let (registry, token, mut permit, challenge, _context) = local_fixture();
            let id = challenge.approval_request_id;
            let session_deadline = registry.lock_inner().entries[0].monotonic_deadline;
            let published = registry
                .publish_local_pending(
                    &mut permit,
                    challenge,
                    b"review".to_vec(),
                    "hash".into(),
                    Instant::now(),
                    Instant::now() + Duration::from_secs(60),
                    None,
                )
                .unwrap();
            assert_eq!(published.deadline, session_deadline);
            if !backwards {
                registry.lock_inner().entries[0].approval_challenges[0].monotonic_deadline =
                    Instant::now() - Duration::from_millis(1);
            }
            if backwards {
                assert!(
                    registry
                        .pending_approval_challenges(now(0))
                        .unwrap()
                        .is_empty()
                );
            }
            assert_eq!(
                registry
                    .local_state_for_owner(&token, id, now(if backwards { 0 } else { 2 }))
                    .unwrap()
                    .state,
                LocalApprovalState::Expired
            );
            assert_eq!(
                registry.local_approval(id, now(2)).unwrap().state,
                LocalApprovalState::Expired
            );
            assert!(
                registry
                    .decide_local(id, "hash", Some(ApprovalId::new_random()), now(2))
                    .is_err()
            );
            assert!(registry.local_review(id, now(2)).unwrap().1.is_empty());
        }
    }

    #[test]
    fn cancelled_local_records_share_the_existing_128_limit_with_external_pending() {
        let (registry, token, mut permit, challenge, context) = local_fixture();
        for _ in 0..APPROVAL_PENDING_MAX {
            let mut next = challenge.clone();
            next.approval_request_id = ApprovalRequestId::new_random();
            let id = next.approval_request_id;
            registry
                .publish_local_pending(
                    &mut permit,
                    next,
                    b"review".to_vec(),
                    "hash".into(),
                    Instant::now(),
                    Instant::now() + Duration::from_secs(60),
                    None,
                )
                .unwrap();
            registry.decide_local(id, "hash", None, now(2)).unwrap();
            drop(permit);
            permit = registry.acquire(&token, context.action, now(2)).unwrap();
        }
        assert!(registry.local_capacity().is_err());
        assert!(
            registry
                .publish_local_pending(
                    &mut permit,
                    challenge.clone(),
                    b"review".to_vec(),
                    "hash".into(),
                    Instant::now(),
                    Instant::now() + Duration::from_secs(60),
                    None,
                )
                .is_err()
        );
        let mut external = challenge;
        external.approver = ApproverSpec::Ed25519 {
            keys: vec!["11".repeat(32)],
            threshold: 1,
        };
        assert_eq!(
            registry
                .store_approval_challenge(
                    external,
                    Instant::now(),
                    Instant::now() + Duration::from_secs(60),
                    now(2)
                )
                .unwrap_err()
                .code(),
            "approval-inbox-overflow"
        );
        assert_eq!(registry.lock_inner().entries[0].uses_left, 0);
    }

    #[tokio::test]
    async fn unknown_decision_cancellation_and_registry_close_notify_waiters() {
        let (registry, token, mut permit, challenge, _) = local_fixture();
        let id = challenge.approval_request_id;
        registry
            .publish_local_pending(
                &mut permit,
                challenge,
                b"review".to_vec(),
                "hash".into(),
                Instant::now(),
                Instant::now() + Duration::from_secs(60),
                None,
            )
            .unwrap();
        let wake = registry.approval_changed.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        registry.cancel_local_unconfirmed(id);
        tokio::time::timeout(Duration::from_millis(100), wake)
            .await
            .unwrap();
        assert_eq!(
            registry
                .local_state_for_owner(&token, id, now(2))
                .unwrap()
                .state,
            LocalApprovalState::Cancelled
        );
        let wake = registry.approval_changed.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        registry.close_and_revoke_all();
        tokio::time::timeout(Duration::from_millis(100), wake)
            .await
            .unwrap();
        assert!(registry.local_state_for_owner(&token, id, now(2)).is_err());
        registry.open_for_admission();
        assert!(registry.local_state_for_owner(&token, id, now(2)).is_err());
    }
}
