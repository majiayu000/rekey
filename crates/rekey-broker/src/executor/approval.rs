use std::sync::Arc;
use std::time::{Duration, Instant};

use rekey_domain::DomainError;
use rekey_domain::authorization::{AuthorizationRequest, Decision, DenyReason, Principal};
use rekey_domain::ids::ApprovalRequestId;
use rekey_domain::ipc::ApprovalChallenge;
use rekey_policy::VerifiedApprovalGrant;
use rekey_vault::command::AuditDraft;
use rekey_vault::model::{
    ActionState, ApprovalEvidence, AuthorizationEvidence, event_type, outcome,
};

use crate::active_policy::ActivePolicy;
use crate::audit::{ExecutionAuditContext, execution_blocked};
use crate::error::BrokerError;
use crate::session::{ApprovalContext, ExecutionPermit};

use super::{ActionExecutor, ExecuteRequest, deadline, validate_request};

pub(super) struct EvaluatedAuthorization {
    pub action: rekey_domain::action::FixedHttpAction,
    pub ctx: ExecutionAuditContext,
    pub decision: Decision,
    pub approval_context: Option<ApprovalContext>,
    pub snapshot: Arc<ActivePolicy>,
}

impl ActionExecutor {
    pub(super) async fn evaluate_request(
        &self,
        request: &ExecuteRequest,
        principal: Principal,
        effect_deadline: Instant,
    ) -> Result<EvaluatedAuthorization, BrokerError> {
        let pinned = deadline::await_authority(
            effect_deadline,
            self.authority
                .action_get(request.action.action_id, request.action.version),
        )
        .await?;
        let action = pinned.action;
        let mut ctx = ExecutionAuditContext {
            request_id: request.request_id,
            session_id: principal.session_id,
            action: request.action,
            credential_id: action.credential_id,
            authorization: None,
        };
        if pinned.state == ActionState::Disabled || !action.enabled {
            self.audit_denial(effect_deadline, &ctx, "action-disabled")
                .await?;
            return Err(BrokerError::Domain(DomainError::ActionDisabled));
        }
        if let Err(reason) = validate_request(&action, request) {
            self.audit_denial(effect_deadline, &ctx, reason).await?;
            return Err(BrokerError::Denied(reason));
        }

        let Some(snapshot) = self.lifecycle_policy(effect_deadline).await? else {
            let reason = DenyReason::NoActiveSnapshot.code();
            self.audit_denial(effect_deadline, &ctx, reason).await?;
            return Err(BrokerError::Denied(reason));
        };
        if snapshot.snapshot().binding(request.action).is_none() {
            let reason = DenyReason::ActionNotBound.code();
            self.audit_denial(effect_deadline, &ctx, reason).await?;
            return Err(BrokerError::Denied(reason));
        }
        let (resource, parameters) = match snapshot.snapshot().canonicalize(
            request.action,
            request.content_type.as_deref(),
            &request.extra_headers,
            &request.body,
        ) {
            Ok(value) => value,
            Err(_) => {
                let reason = DenyReason::InvalidParameters.code();
                self.audit_denial(effect_deadline, &ctx, reason).await?;
                return Err(BrokerError::Denied(reason));
            }
        };
        let authorization_request = AuthorizationRequest {
            principal,
            action: request.action,
            resource: resource.clone(),
            parameters: parameters.clone(),
        };
        let now = crate::now_ts()?;
        let decision = rekey_policy::evaluate(
            snapshot.snapshot(),
            &authorization_request,
            now,
            snapshot.is_expired(now),
        );
        let (policy_version, policy_digest, policy_rule_id, requirement) = match &decision {
            Decision::Allow {
                policy_version,
                snapshot_digest,
                determining_rule,
            } => (
                *policy_version,
                *snapshot_digest,
                Some(*determining_rule),
                None,
            ),
            Decision::RequireApproval {
                policy_version,
                snapshot_digest,
                determining_rule,
                requirement,
            } => (
                *policy_version,
                *snapshot_digest,
                Some(*determining_rule),
                Some(requirement.clone()),
            ),
            Decision::Deny {
                policy_version: Some(policy_version),
                snapshot_digest: Some(snapshot_digest),
                determining_rule,
                ..
            } => (*policy_version, *snapshot_digest, *determining_rule, None),
            Decision::Deny { reason, .. } => {
                self.audit_denial(effect_deadline, &ctx, reason.code())
                    .await?;
                return Err(BrokerError::Denied(reason.code()));
            }
        };
        ctx.authorization = Some(AuthorizationEvidence {
            principal_id: principal.principal_id,
            policy_version: policy_version.get(),
            policy_digest,
            policy_rule_id,
            resource_type: resource.resource_type.clone(),
            resource_id: resource.id.clone(),
            parameter_hash: parameters.canonical_hash,
        });
        if let Decision::Deny { reason, .. } = decision {
            self.audit_denial(effect_deadline, &ctx, reason.code())
                .await?;
            return Err(BrokerError::Denied(reason.code()));
        }
        let approval_context = match (requirement, policy_rule_id) {
            (Some(mut requirement), Some(policy_rule_id)) => {
                requirement.approver_ids.sort_unstable();
                Some(ApprovalContext {
                    principal,
                    action: request.action,
                    resource,
                    schema_id: parameters.schema_id,
                    parameter_hash: parameters.canonical_hash,
                    policy_version: policy_version.get(),
                    policy_digest,
                    policy_rule_id,
                    requirement,
                })
            }
            (None, _) => None,
            (Some(_), None) => return Err(BrokerError::Denied("policy-evaluation-failed")),
        };
        Ok(EvaluatedAuthorization {
            action,
            ctx,
            approval_context,
            decision,
            snapshot,
        })
    }

    async fn audit_denial(
        &self,
        deadline_at: Instant,
        ctx: &ExecutionAuditContext,
        reason: &'static str,
    ) -> Result<(), BrokerError> {
        deadline::await_authority(
            deadline_at,
            self.authority.append_audit(execution_blocked(ctx, reason)),
        )
        .await
    }

    pub(crate) async fn prepare_approval(
        self: &Arc<Self>,
        request: ExecuteRequest,
    ) -> Result<ApprovalChallenge, BrokerError> {
        let started = Instant::now();
        self.refuse_unless_running()?;
        let permit =
            self.sessions
                .acquire(&request.capability_token, request.action, crate::now_ts()?)?;
        let deadline_at = started + Duration::from_millis(permit.timeout_ms as u64);
        self.refuse_unless_running()?;
        let evaluated = self
            .evaluate_request(&request, permit.principal, deadline_at)
            .await?;
        let Decision::RequireApproval { .. } = evaluated.decision else {
            return Err(BrokerError::Denied("approval-not-required"));
        };
        self.create_approval_challenge(evaluated, &permit, deadline_at)
            .await
    }

    async fn create_approval_challenge(
        &self,
        evaluated: EvaluatedAuthorization,
        permit: &ExecutionPermit,
        deadline_at: Instant,
    ) -> Result<ApprovalChallenge, BrokerError> {
        let context = evaluated
            .approval_context
            .as_ref()
            .ok_or(BrokerError::Denied("policy-evaluation-failed"))?;
        let created = crate::now_ts()?.as_unix_ms();
        let window_ms = match context.requirement.mode {
            rekey_domain::authorization::ApprovalMode::OneTime => 10 * 60 * 1_000,
            rekey_domain::authorization::ApprovalMode::TimeWindow => context
                .requirement
                .max_window_ms
                .ok_or(BrokerError::Denied("policy-evaluation-failed"))?,
        };
        let max_expires_at_ms = evaluated
            .snapshot
            .snapshot()
            .expires_at_ms()
            .min(permit.expires_at_ms)
            .min(created.saturating_add(window_ms));
        let remaining_ms = max_expires_at_ms
            .checked_sub(created)
            .filter(|remaining| *remaining > 0)
            .ok_or(BrokerError::Denied("approval-window-expired"))?;
        let monotonic_anchor = Instant::now();
        let monotonic_deadline = monotonic_anchor
            .checked_add(Duration::from_millis(remaining_ms as u64))
            .ok_or(BrokerError::Denied("approval-window-invalid"))?;
        let challenge = ApprovalChallenge {
            record_type: "rekey.approval.challenge.v1".to_owned(),
            approval_request_id: crate::random_id(ApprovalRequestId::from_random_bytes)?,
            tenant_id: context.principal.tenant_id,
            principal_id: context.principal.principal_id,
            session_id: context.principal.session_id,
            action_id: context.action.action_id,
            action_version: context.action.version,
            resource: context.resource.clone(),
            schema_id: context.schema_id.clone(),
            parameter_sha256: data_encoding::HEXLOWER.encode(&context.parameter_hash),
            policy_version: context.policy_version,
            policy_sha256: data_encoding::HEXLOWER.encode(&context.policy_digest),
            policy_rule_id: context.policy_rule_id,
            mode: context.requirement.mode,
            quorum: context.requirement.quorum,
            approver_ids: context.requirement.approver_ids.clone(),
            max_uses: context.requirement.max_uses,
            created_at_ms: created,
            max_expires_at_ms,
        };
        self.sessions
            .store_approval_challenge(challenge.clone(), monotonic_anchor, monotonic_deadline)
            .map_err(|error| BrokerError::Denied(error.code()))?;
        let draft = approval_audit(
            &evaluated.ctx,
            event_type::APPROVAL_REQUESTED,
            outcome::SUCCESS,
            "requested",
            Some(ApprovalEvidence {
                approval_request_id: challenge.approval_request_id,
                approval_id: None,
                approver_id: None,
            }),
        );
        deadline::await_authority(deadline_at, self.authority.append_audit(draft)).await?;
        Ok(challenge)
    }

    pub(super) async fn verify_and_reserve_approvals(
        &self,
        evaluated: &EvaluatedAuthorization,
        raw_grants: &[String],
        deadline_at: Instant,
    ) -> Result<(Vec<AuditDraft>, Instant, i64), BrokerError> {
        if raw_grants.len() > 2 {
            self.reject_approval(
                &evaluated.ctx,
                "approval-insufficient-quorum",
                None,
                deadline_at,
            )
            .await?;
            return Err(BrokerError::Denied("approval-insufficient-quorum"));
        }
        let verified = match raw_grants
            .iter()
            .map(|grant| {
                rekey_policy::parse_and_verify_approval_grant(
                    grant.as_bytes(),
                    evaluated.snapshot.snapshot(),
                )
            })
            .collect::<Result<Vec<VerifiedApprovalGrant>, _>>()
        {
            Ok(grants) => grants,
            Err(_) => {
                self.reject_approval(&evaluated.ctx, "approval-grant-invalid", None, deadline_at)
                    .await?;
                return Err(BrokerError::Denied("approval-grant-invalid"));
            }
        };
        let now = crate::now_ts()?;
        let evidence = match self.sessions.reserve_approvals(
            evaluated
                .approval_context
                .as_ref()
                .ok_or(BrokerError::Denied("policy-evaluation-failed"))?,
            &verified,
            now,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let audit_evidence = match verified.as_slice() {
                    [verified] => {
                        let grant = verified.grant();
                        Some(ApprovalEvidence {
                            approval_request_id: grant.approval_request_id,
                            approval_id: Some(grant.approval_id),
                            approver_id: Some(grant.approver_id),
                        })
                    }
                    _ => None,
                };
                self.reject_approval(&evaluated.ctx, error.code(), audit_evidence, deadline_at)
                    .await?;
                return Err(BrokerError::Denied(error.code()));
            }
        };
        let not_after = evidence.not_after;
        let wall_not_after_ms = evidence.wall_not_after_ms;
        Ok((
            evidence
                .evidence
                .into_iter()
                .map(|evidence| {
                    approval_audit(
                        &evaluated.ctx,
                        event_type::APPROVAL_ACCEPTED,
                        outcome::SUCCESS,
                        "accepted",
                        Some(evidence),
                    )
                })
                .collect(),
            not_after,
            wall_not_after_ms,
        ))
    }

    async fn reject_approval(
        &self,
        ctx: &ExecutionAuditContext,
        reason: &'static str,
        evidence: Option<ApprovalEvidence>,
        deadline_at: Instant,
    ) -> Result<(), BrokerError> {
        let draft = approval_audit(
            ctx,
            event_type::APPROVAL_REJECTED,
            outcome::DENIED,
            reason,
            evidence,
        );
        deadline::await_authority(deadline_at, self.authority.append_audit(draft)).await
    }
}

fn approval_audit(
    ctx: &ExecutionAuditContext,
    event: &'static str,
    result: &'static str,
    reason: &'static str,
    approval: Option<ApprovalEvidence>,
) -> AuditDraft {
    AuditDraft {
        request_id: Some(ctx.request_id),
        session_id: Some(ctx.session_id),
        action_id: Some(ctx.action.action_id),
        action_version: Some(ctx.action.version),
        credential_id: Some(ctx.credential_id),
        credential_version: None,
        authorization: ctx.authorization.clone().map(Box::new),
        approval,
        event_type: event,
        outcome: result,
        reason_code: reason.to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}
