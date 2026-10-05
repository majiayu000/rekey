use std::sync::Arc;
use std::time::{Duration, Instant};

use rekey_domain::DomainError;
use rekey_domain::authorization::{ApproverSpec, AuthorizationRequest, Decision, DenyReason};
use rekey_domain::ids::ApprovalRequestId;
use rekey_domain::ipc::{ApprovalChallenge, SignedApprovalChallenge};
use rekey_domain::ipc::{
    LOCAL_APPROVAL_REVIEW_HASH_PREFIX, LocalApprovalReview, LocalApprovalState,
};
use rekey_policy::VerifiedApprovalGrant;
use rekey_vault::command::AuditDraft;
use rekey_vault::model::{
    ActionState, ApprovalEvidence, AuthorizationEvidence, event_type, outcome,
};
use sha2::{Digest, Sha256};

use crate::active_policy::ActivePolicy;
use crate::audit::{ExecutionAuditContext, execution_blocked};
use crate::error::BrokerError;
use crate::session::{ApprovalContext, ExecutionPermit};

use super::{ActionExecutor, ExecuteRequest, deadline, validate_request};

pub(super) struct EvaluatedAuthorization {
    pub action: rekey_domain::action::FixedHttpAction,
    pub target: rekey_domain::template::RenderedTarget,
    pub ctx: ExecutionAuditContext,
    pub decision: Decision,
    pub approval_context: Option<ApprovalContext>,
    pub snapshot: Arc<ActivePolicy>,
    pub canonical_json: Vec<u8>,
    pub effective_body: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub llm: Option<super::llm::LlmExecution>,
}

impl ActionExecutor {
    pub(super) async fn evaluate_request(
        &self,
        request: &ExecuteRequest,
        permit: &ExecutionPermit,
        effect_deadline: Instant,
    ) -> Result<EvaluatedAuthorization, BrokerError> {
        let principal = permit.principal;
        let pinned = deadline::await_authority(
            effect_deadline,
            self.authority
                .action_get(request.action.action_id, request.action.version),
        )
        .await?;
        let action = pinned.action;
        let mut ctx = ExecutionAuditContext {
            request_context: permit.profile_scope().map(|scope| {
                rekey_domain::audit::ProfileRequestAuditContext {
                    profile_name: scope.profile_name.clone(),
                    policy_sha256: data_encoding::HEXLOWER.encode(&scope.policy_sha256),
                    instance_slug: scope.instance_slug.clone(),
                    capability: scope.capability.clone(),
                    model: None,
                }
                .into()
            }),
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
        let scoped = permit.profile_scope();
        if scoped.is_some_and(|scope| scope.policy_sha256 != snapshot.snapshot().digest()) {
            self.audit_denial(effect_deadline, &ctx, "profile-policy-changed")
                .await?;
            return Err(BrokerError::Denied("profile-policy-changed"));
        }
        let protocol = match scoped
            .map(|scope| super::llm::protocol(&action, scope))
            .transpose()
        {
            Ok(protocol) => protocol.flatten(),
            Err(error) => {
                self.audit_denial(effect_deadline, &ctx, "profile-llm-source-unsupported")
                    .await?;
                return Err(error);
            }
        };
        let input = rekey_policy::ActionRequest {
            params: &request.params,
            query: &request.query,
            content_type: request.content_type.as_deref(),
            headers: &request.extra_headers,
            body: &request.body,
        };
        let canonical = if let Some(protocol) = protocol {
            let scope = scoped.ok_or(BrokerError::Denied("profile-llm-limits-missing"))?;
            let limits = scope
                .llm_limits
                .as_ref()
                .ok_or(BrokerError::Denied("profile-llm-limits-missing"))?;
            snapshot
                .snapshot()
                .canonicalize_profile_llm(&action, input, protocol, limits)
                .map(|result| {
                    if let Some(rekey_domain::audit::RequestAuditContext::Profile(context)) =
                        ctx.request_context.as_mut()
                    {
                        context.model = result.model;
                    }
                    (
                        result.resource,
                        result.parameters,
                        result.target,
                        Some(zeroize::Zeroizing::new(result.body)),
                        Some(super::llm::LlmExecution {
                            protocol,
                            streaming: result.streaming,
                            usage: rekey_vault::command::ProfileUsageStart {
                                instance_slug: scope.instance_slug.clone(),
                                max_requests_per_day: limits.max_requests_per_day,
                                max_output_tokens_per_day: limits.max_output_tokens_per_day,
                                generation_max_output: result.generation_max_output,
                            },
                        }),
                    )
                })
        } else {
            snapshot
                .snapshot()
                .canonicalize(&action, input)
                .map(|(resource, parameters, target)| (resource, parameters, target, None, None))
        };
        let (resource, parameters, target, effective_body, llm) = match canonical {
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
                approver,
                requirement,
            } => (
                *policy_version,
                *snapshot_digest,
                Some(*determining_rule),
                Some((approver.clone(), requirement.clone())),
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
            (Some((approver, requirement)), Some(policy_rule_id)) => {
                let allowed_approver_ids = match &approver {
                    ApproverSpec::Ed25519 { keys, .. } => snapshot
                        .snapshot()
                        .ed25519_approver_ids(keys)
                        .ok_or(BrokerError::Denied("policy-evaluation-failed"))?,
                    ApproverSpec::LocalPresence {} => Vec::new(),
                    #[cfg(feature = "lab")]
                    ApproverSpec::Remote {} => {
                        self.audit_denial(effect_deadline, &ctx, "approval-remote-unavailable")
                            .await?;
                        return Err(BrokerError::Denied("approval-remote-unavailable"));
                    }
                };
                Some(ApprovalContext {
                    principal,
                    action: request.action,
                    resource,
                    schema_id: parameters.schema_id,
                    parameter_hash: parameters.canonical_hash,
                    policy_version: policy_version.get(),
                    policy_digest,
                    policy_rule_id,
                    approver,
                    allowed_approver_ids,
                    requirement,
                })
            }
            (None, _) => None,
            (Some(_), None) => return Err(BrokerError::Denied("policy-evaluation-failed")),
        };
        Ok(EvaluatedAuthorization {
            action,
            target,
            ctx,
            approval_context,
            decision,
            snapshot,
            canonical_json: parameters.canonical_json,
            effective_body,
            llm,
        })
    }

    pub(super) async fn audit_denial(
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
    ) -> Result<SignedApprovalChallenge, BrokerError> {
        let started = Instant::now();
        self.refuse_unless_running()?;
        let mut permit =
            self.sessions
                .acquire(&request.capability_token, request.action, crate::now_ts()?)?;
        let deadline_at = started + Duration::from_millis(permit.timeout_ms as u64);
        self.refuse_unless_running()?;
        let evaluated = self
            .evaluate_request(&request, &permit, deadline_at)
            .await?;
        let Decision::RequireApproval { .. } = evaluated.decision else {
            return Err(BrokerError::Denied("approval-not-required"));
        };
        if matches!(
            evaluated.approval_context.as_ref().map(|c| &c.approver),
            Some(ApproverSpec::LocalPresence {})
        ) {
            let local = self
                .ensure_local_approval(&evaluated, &mut permit, None, true, deadline_at)
                .await?;
            return tokio::time::timeout_at(
                deadline_at.into(),
                self.sign_challenge_envelope(local.challenge),
            )
            .await
            .map_err(|_| BrokerError::Upstream("upstream-timeout"))?;
        }
        self.create_approval_challenge(evaluated, &permit, deadline_at)
            .await
    }

    async fn create_approval_challenge(
        &self,
        evaluated: EvaluatedAuthorization,
        permit: &ExecutionPermit,
        deadline_at: Instant,
    ) -> Result<SignedApprovalChallenge, BrokerError> {
        let (challenge, monotonic_anchor, monotonic_deadline) =
            Self::new_challenge(&evaluated, permit)?;
        let now = crate::now_ts()?;
        let payload = rekey_policy::approval_challenge_sign_payload(&challenge)?;
        let signature =
            deadline::await_authority(deadline_at, self.authority.sign_approval_origin(payload))
                .await?;
        let envelope = SignedApprovalChallenge {
            record_type: "rekey.approval.challenge.envelope.v2".to_owned(),
            challenge: challenge.clone(),
            signature: data_encoding::BASE64URL_NOPAD.encode(&signature),
        };
        self.sessions
            .store_approval_challenge(challenge.clone(), monotonic_anchor, monotonic_deadline, now)
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
        Ok(envelope)
    }

    fn new_challenge(
        evaluated: &EvaluatedAuthorization,
        permit: &ExecutionPermit,
    ) -> Result<(ApprovalChallenge, Instant, Instant), BrokerError> {
        let context = evaluated
            .approval_context
            .as_ref()
            .ok_or(BrokerError::Denied("policy-evaluation-failed"))?;
        let now = crate::now_ts()?;
        let created = now.as_unix_ms();
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
            record_type: "rekey.approval.challenge.v2".to_owned(),
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
            approver: context.approver.clone(),
            max_uses: context.requirement.max_uses,
            created_at_ms: created,
            max_expires_at_ms,
        };
        Ok((challenge, monotonic_anchor, monotonic_deadline))
    }

    pub(super) async fn ensure_local_approval(
        &self,
        evaluated: &EvaluatedAuthorization,
        permit: &mut ExecutionPermit,
        wanted: Option<ApprovalRequestId>,
        prepare_only: bool,
        deadline_at: Instant,
    ) -> Result<crate::session::LocalApproval, BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline_at.into()).await?;
        self.lifecycle.reject_if_not_running()?;
        tokio::time::timeout_at(
            deadline_at.into(),
            super::check_started_policy(
                &self.policy,
                Some(super::PolicyIdentity::of(&evaluated.snapshot)),
                &self.terminals,
                &evaluated.ctx,
            ),
        )
        .await
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))??;
        if Instant::now() >= deadline_at {
            return Err(BrokerError::Upstream("upstream-timeout"));
        }
        if evaluated.snapshot.is_expired(crate::now_ts()?) {
            return Err(BrokerError::Denied("policy-expired"));
        }
        let context = evaluated
            .approval_context
            .as_ref()
            .ok_or(BrokerError::Denied("policy-evaluation-failed"))?;
        if let Some(local) =
            self.sessions
                .local_for_execution(permit, context, wanted, crate::now_ts()?)?
        {
            if !matches!(
                local.state,
                LocalApprovalState::Pending | LocalApprovalState::Approved
            ) {
                return Err(BrokerError::Denied("approval-challenge-unavailable"));
            }
            if prepare_only || wanted.is_none() || local.state == LocalApprovalState::Pending {
                self.sessions
                    .refund_local_wait(permit, local.challenge.approval_request_id)?;
            }
            return Ok(local);
        }
        self.sessions.local_capacity()?;
        let (challenge, anchor, expires) = Self::new_challenge(evaluated, permit)?;
        let review = LocalApprovalReview {
            record_type: "rekey.approval.review.v1".into(),
            challenge: challenge.clone(),
            action_name: evaluated.action.name.clone(),
            origin: evaluated.action.origin.clone(),
            method: evaluated.action.method,
            canonical_request: serde_json::value::RawValue::from_string(
                String::from_utf8(evaluated.canonical_json.clone())
                    .map_err(|_| BrokerError::Denied("policy-evaluation-failed"))?,
            )
            .map_err(|_| BrokerError::Denied("policy-evaluation-failed"))?,
        };
        let body = serde_jcs::to_vec(&review)
            .map_err(|_| BrokerError::Denied("policy-evaluation-failed"))?;
        if body.len() > rekey_domain::ipc::RESPONSE_BODY_MAX_BYTES as usize {
            return Err(rekey_domain::DomainError::RequestTooLarge.into());
        }
        let mut hash = Sha256::new();
        hash.update(LOCAL_APPROVAL_REVIEW_HASH_PREFIX);
        hash.update(&body);
        let hash = data_encoding::HEXLOWER.encode(&hash.finalize());
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
        deadline::await_authority(
            deadline_at,
            self.authority
                .commit_audit_before(draft, Some(deadline_at.min(expires))),
        )
        .await?;
        if Instant::now() >= deadline_at.min(expires)
            || crate::now_ts()?.as_unix_ms() >= challenge.max_expires_at_ms
        {
            return Err(rekey_vault::AuthorityError::AuthorityBusy.into());
        }
        self.sessions.publish_local_pending(
            permit,
            challenge,
            body,
            hash,
            anchor,
            expires,
            evaluated.ctx.request_context.clone(),
        )
    }

    pub(super) async fn commit_local_started(
        &self,
        evaluated: &EvaluatedAuthorization,
        permit: &ExecutionPermit,
        id: ApprovalRequestId,
        deadline_at: Instant,
    ) -> Result<crate::audit::StartedAuditGuard, BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline_at.into()).await?;
        self.lifecycle.reject_if_not_running()?;
        tokio::time::timeout_at(
            deadline_at.into(),
            super::check_started_policy(
                &self.policy,
                Some(super::PolicyIdentity::of(&evaluated.snapshot)),
                &self.terminals,
                &evaluated.ctx,
            ),
        )
        .await
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))??;
        if Instant::now() >= deadline_at {
            return Err(BrokerError::Upstream("upstream-timeout"));
        }
        if evaluated.snapshot.is_expired(crate::now_ts()?) {
            return Err(BrokerError::Denied("policy-expired"));
        }
        let context = evaluated
            .approval_context
            .as_ref()
            .ok_or(BrokerError::Denied("policy-evaluation-failed"))?;
        let reserved = self
            .sessions
            .consume_local(permit, context, id, crate::now_ts()?)?;
        let accepted = reserved
            .evidence
            .into_iter()
            .map(|evidence| {
                approval_audit(
                    &evaluated.ctx,
                    event_type::APPROVAL_ACCEPTED,
                    outcome::SUCCESS,
                    "local-presence",
                    Some(evidence),
                )
            })
            .collect();
        tokio::time::timeout_at(
            deadline_at.min(reserved.not_after).into(),
            super::commit_evaluated_started(
                &self.terminals,
                ExecutionAuditContext {
                    request_context: evaluated.ctx.request_context.clone(),
                    request_id: evaluated.ctx.request_id,
                    session_id: evaluated.ctx.session_id,
                    action: evaluated.ctx.action,
                    credential_id: evaluated.ctx.credential_id,
                    authorization: evaluated.ctx.authorization.clone(),
                },
                accepted,
                Some(
                    deadline_at
                        .min(reserved.not_after)
                        .min(evaluated.snapshot.monotonic_deadline().into_std()),
                ),
                Some(
                    reserved
                        .wall_not_after_ms
                        .min(evaluated.snapshot.snapshot().expires_at_ms()),
                ),
                evaluated.llm.as_ref().map(|llm| llm.usage.clone()),
            ),
        )
        .await
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))?
    }

    pub(crate) async fn sign_challenge_envelope(
        &self,
        challenge: ApprovalChallenge,
    ) -> Result<SignedApprovalChallenge, BrokerError> {
        let payload = rekey_policy::approval_challenge_sign_payload(&challenge)?;
        let signature = self.authority.sign_approval_origin(payload).await?;
        Ok(SignedApprovalChallenge {
            record_type: "rekey.approval.challenge.envelope.v2".to_owned(),
            challenge,
            signature: data_encoding::BASE64URL_NOPAD.encode(&signature),
        })
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
        request_context: ctx.request_context.clone(),
        usage: None,
        event_type: event,
        outcome: result,
        reason_code: reason.to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use rekey_domain::authorization::{
        ApprovalMode, ApprovalRequirement, Principal, ResourceRef, SchemaId,
    };
    use rekey_domain::capability::{ActionVersionRef, SessionGrant};
    use rekey_domain::ids::{
        ActionId, CredentialId, PolicyRuleId, PrincipalId, RequestId, SessionId, TenantId,
    };

    #[tokio::test]
    async fn local_review_budget_and_final_policy_expiry_precede_publication_and_consumption() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let now = crate::now_ts().unwrap();
        let snapshot=rekey_policy::parse_and_validate_snapshot(&serde_json::to_vec(&serde_json::json!({
            "format_version":7,"version":1,"expires_at_ms":now.as_unix_ms()+60000,"approvers":[],"connections":[], "ssh_keys":[], "derived_credentials":[], "profiles": [], "workload_identities":[],"bindings":[],"rules":[]
        })).unwrap(),now).unwrap();
        let snapshot = Arc::new(ActivePolicy::activate(snapshot, now).unwrap());
        *ctx.executor.policy.write().await = Some(snapshot.clone());
        let action:rekey_domain::action::FixedHttpAction=serde_json::from_value(serde_json::json!({
            "id":ActionId::new_random(),"name":"review-budget","version":1,"enabled":true,"credential_id":CredentialId::new_random(),
            "origin":"https://api.example.com","method":"POST","target":{"kind":"fixed","path":"/fixed"},
            "auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":1000,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":1024,"allowed_headers":[]}
        })).unwrap();
        let action_ref = ActionVersionRef {
            action_id: action.id,
            version: 1,
        };
        let session_id = SessionId::new_random();
        let principal = Principal {
            tenant_id: TenantId::new_random(),
            principal_id: PrincipalId::new_random(),
            session_id,
        };
        let grant =
            SessionGrant::new(session_id, principal, vec![action_ref], now, 60000, 1).unwrap();
        let token = ctx.sessions.create(grant).unwrap();
        let mut permit = ctx.sessions.acquire(&token, action_ref, now).unwrap();
        let rule = PolicyRuleId::new_random();
        let requirement = ApprovalRequirement {
            mode: ApprovalMode::OneTime,
            max_uses: 1,
            max_window_ms: None,
        };
        let evaluated=EvaluatedAuthorization {
            target:rekey_domain::template::RenderedTarget {path:rekey_domain::action::ExactPath::parse("/fixed").unwrap(),params:Default::default(),query:Default::default()},
            ctx:ExecutionAuditContext { request_context: None,request_id:RequestId::new_random(),session_id,action:action_ref,credential_id:action.credential_id,authorization:None},
            decision:Decision::RequireApproval {policy_version:snapshot.snapshot().version(),snapshot_digest:snapshot.snapshot().digest(),determining_rule:rule,approver:ApproverSpec::LocalPresence {},requirement:requirement.clone()},
            approval_context:Some(ApprovalContext {principal,action:action_ref,resource:ResourceRef::new("test-action".into(),action.id.to_string()).unwrap(),schema_id:SchemaId::new("test/v1".into()).unwrap(),parameter_hash:[0;32],policy_version:1,policy_digest:snapshot.snapshot().digest(),policy_rule_id:rule,approver:ApproverSpec::LocalPresence {},allowed_approver_ids:vec![],requirement}),
            action,snapshot,effective_body:None,llm:None,
            canonical_json:serde_json::to_vec(&serde_json::json!({"body":"x".repeat(rekey_domain::ipc::RESPONSE_BODY_MAX_BYTES as usize)})).unwrap(),
        };
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        let count = || {
            db.query_row("SELECT count(*) FROM audit_events", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
        };
        let before = count();
        let error = ctx
            .executor
            .ensure_local_approval(
                &evaluated,
                &mut permit,
                None,
                false,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "REQUEST_TOO_LARGE");
        assert_eq!(count(), before);
        assert!(
            ctx.sessions
                .pending_approval_challenges(now)
                .unwrap()
                .is_empty()
        );
        // The oversized attempt did not refund the reserved use.
        assert!(ctx.sessions.acquire(&token, action_ref, now).is_err());
        // A policy expiry observed while a request waits for the final
        // coordinator must also precede grant consumption, even after wall rollback.
        let (challenge, anchor, expires) =
            ActionExecutor::new_challenge(&evaluated, &permit).unwrap();
        let id = challenge.approval_request_id;
        ctx.sessions
            .publish_local_pending(
                &mut permit,
                challenge,
                b"{}".to_vec(),
                "hash".into(),
                anchor,
                expires,
                None,
            )
            .unwrap();
        drop(permit);
        ctx.sessions
            .decide_local(
                id,
                "hash",
                Some(rekey_domain::ids::ApprovalId::new_random()),
                crate::now_ts().unwrap(),
            )
            .unwrap();
        let permit = ctx.sessions.acquire(&token, action_ref, now).unwrap();
        assert!(
            evaluated
                .snapshot
                .is_expired(rekey_domain::Timestamp::from_unix_ms(
                    now.as_unix_ms() + 60000
                ))
        );
        let error = ctx
            .executor
            .commit_local_started(
                &evaluated,
                &permit,
                id,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "request denied: policy-expired");
        assert_eq!(
            ctx.sessions
                .local_approval(id, crate::now_ts().unwrap())
                .unwrap()
                .state,
            LocalApprovalState::Approved
        );
        assert_eq!(count(), before);
        drop(permit);
        ctx.authority
            .shutdown(Some(rekey_vault::command::UnlockProof::Password(
                rekey_vault::secret::SecretInput::from_slice(b"fixture-proof"),
            )))
            .await
            .unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }
}
