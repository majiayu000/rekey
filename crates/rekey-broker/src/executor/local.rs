//! Signed Connection admission reuses the existing supervised effect and sealing path.
use std::sync::Arc;
use std::time::{Duration, Instant};

use rekey_domain::audit::RequestAuditContext;
use rekey_domain::authorization::{ApprovalMode, ApproverSpec};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::connection::{ConnectionRequestAuditContext, RuleEffect};
use rekey_domain::ids::{ApprovalRequestId, PrincipalId, RequestId, SessionId, TenantId};
use rekey_domain::ipc::{self, CallMeta};
use rekey_policy::connections::evaluate_connection;
use rekey_vault::model::{ApprovalEvidence, AuthorizationEvidence, event_type, outcome};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{ActionExecutor, AdmittedExecution, ExecuteRequest, PolicyIdentity};
use crate::audit::{ExecutionAuditContext, execution_blocked};
use crate::error::BrokerError;
use crate::runtime::local_calls::LocalCallApproval;

pub(crate) struct LocalExecuteRequest {
    pub(crate) request_id: RequestId,
    pub(crate) meta: CallMeta,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) caller: String,
}

fn principal(connection: &str) -> PrincipalId {
    // Caller labels are advisory. Changing one must never mint another budget.
    let mut hash = Sha256::new();
    hash.update(b"rekey.connection-budget.v1\0");
    hash.update(connection.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    PrincipalId::from_random_bytes(bytes)
}

impl ActionExecutor {
    pub(crate) async fn admit_connection(
        self: &Arc<Self>,
        input: LocalExecuteRequest,
    ) -> Result<AdmittedExecution, BrokerError> {
        let started_at = Instant::now();
        self.refuse_unless_running()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some())
            .ok_or(BrokerError::LocalCall(
                "NOT_CONFIGURED",
                "no active signed connection policy",
                "Use request_access; do not ask for a key.",
            ))?;
        let now = crate::now_ts()?;
        if active.is_expired(now) {
            return Err(BrokerError::Denied("policy-expired"));
        }
        let authorized = evaluate_connection(
            active.snapshot(),
            &input.meta,
            &input.body,
            &input.caller,
            now,
        )?;
        if input.meta.dry_run {
            return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
        }
        let policy_hash = data_encoding::HEXLOWER.encode(&active.snapshot().digest());
        let parameter_hash = data_encoding::HEXLOWER.encode(&authorized.parameters.canonical_hash);
        let deadline = (started_at + Duration::from_millis(authorized.action.timeout_ms as u64))
            .min(active.monotonic_deadline().into_std());
        let ctx = ExecutionAuditContext {
            request_context: Some(RequestAuditContext::Connection(
                ConnectionRequestAuditContext {
                    connection: authorized.connection.name.clone(),
                    caller: input.caller.clone(),
                    method_class: authorized.method_class,
                    normalized_path: authorized.normalized_path.clone(),
                    rule_id: authorized.rule_id,
                },
            )),
            request_id: input.request_id,
            // This is an audit correlation ID only, never a session or token.
            session_id: SessionId::from_random_bytes(*input.request_id.as_bytes()),
            action: ActionVersionRef {
                action_id: authorized.action.id,
                version: authorized.action.version,
            },
            credential_id: authorized.action.credential_id,
            authorization: Some(AuthorizationEvidence {
                principal_id: principal(&authorized.connection.name),
                policy_version: active.snapshot().version().get(),
                policy_digest: active.snapshot().digest(),
                policy_rule_id: authorized.rule_id,
                resource_type: "connection".into(),
                resource_id: authorized.connection.name.clone(),
                parameter_hash: authorized.parameters.canonical_hash,
            }),
        };
        let mut preceding = Vec::new();
        match authorized.effect {
            RuleEffect::Deny => {
                self.authority
                    .append_audit(execution_blocked(&ctx, "connection-rule-denied"))
                    .await?;
                return Err(BrokerError::LocalCall(
                    "DENIED",
                    "connection rule denied this request",
                    "Use request_access to explain the required operation.",
                ));
            }
            RuleEffect::Approve => {
                if let Some(id) = input.meta.approval_request_id {
                    let approval = self.local_calls.consume(
                        id,
                        &input.caller,
                        &parameter_hash,
                        &policy_hash,
                        now.as_unix_ms(),
                    )?;
                    let mut accepted = crate::audit::execution_started(&ctx);
                    accepted.event_type = event_type::APPROVAL_ACCEPTED;
                    accepted.reason_code = "local-presence".into();
                    accepted.approval = Some(ApprovalEvidence {
                        approval_request_id: id,
                        approval_id: approval.approval_id,
                        approver_id: None,
                    });
                    preceding.push(accepted);
                } else if let Some(window) = self.local_calls.window(
                    &policy_hash,
                    &authorized.connection.name,
                    authorized.rule_id,
                    &input.caller,
                    now.as_unix_ms(),
                ) {
                    let mut accepted = crate::audit::execution_started(&ctx);
                    accepted.event_type = event_type::APPROVAL_ACCEPTED;
                    accepted.reason_code = "local-presence-window".into();
                    accepted.approval = Some(ApprovalEvidence {
                        approval_request_id: window.request_id,
                        approval_id: Some(window.approval_id),
                        approver_id: None,
                    });
                    preceding.push(accepted);
                } else {
                    let id = crate::random_id(ApprovalRequestId::from_random_bytes)?;
                    let rule = authorized
                        .rule_id
                        .ok_or(BrokerError::Denied("approval-rule-missing"))?;
                    let status = self.authority.status().await?;
                    let challenge = ipc::ApprovalChallenge {
                        record_type: "rekey.approval.challenge.v2".into(),
                        approval_request_id: id,
                        tenant_id: TenantId::from_random_bytes(*status.vault_id.as_bytes()),
                        principal_id: principal(&authorized.connection.name),
                        session_id: ctx.session_id,
                        action_id: authorized.action.id,
                        action_version: authorized.action.version,
                        resource: authorized.resource.clone(),
                        schema_id: authorized.parameters.schema_id.clone(),
                        parameter_sha256: parameter_hash,
                        policy_version: active.snapshot().version().get(),
                        policy_sha256: policy_hash,
                        policy_rule_id: rule,
                        mode: ApprovalMode::OneTime,
                        approver: ApproverSpec::LocalPresence {},
                        max_uses: 1,
                        created_at_ms: now.as_unix_ms(),
                        max_expires_at_ms: (now.as_unix_ms() + 600_000)
                            .min(active.snapshot().expires_at_ms()),
                    };
                    let review = ipc::LocalApprovalReview {
                        record_type: "rekey.approval.local-review.v1".into(),
                        challenge: challenge.clone(),
                        action_name: authorized.action.name.clone(),
                        origin: authorized.action.origin.clone(),
                        method: authorized.action.method,
                        canonical_request: serde_json::value::RawValue::from_string(
                            String::from_utf8(authorized.parameters.canonical_json.clone())
                                .map_err(|_| ipc::FrameError::InvalidField)?,
                        )
                        .map_err(|_| ipc::FrameError::InvalidField)?,
                    };
                    let bytes = Zeroizing::new(
                        serde_jcs::to_vec(&review).map_err(|_| ipc::FrameError::InvalidField)?,
                    );
                    let mut hash = Sha256::new();
                    hash.update(ipc::LOCAL_APPROVAL_REVIEW_HASH_PREFIX);
                    hash.update(&*bytes);
                    let local = LocalCallApproval {
                        challenge: challenge.clone(),
                        caller: input.caller,
                        request_context: ctx.request_context.clone(),
                        review_sha256: data_encoding::HEXLOWER.encode(&hash.finalize()),
                        review: bytes,
                        deadline: (Instant::now() + Duration::from_secs(600))
                            .min(active.monotonic_deadline().into_std()),
                        state: ipc::LocalApprovalState::Pending,
                        approval_id: None,
                    };
                    let local = self.local_calls.register(local, now.as_unix_ms())?;
                    if local.challenge.approval_request_id == id {
                        let mut audit = crate::audit::execution_started(&ctx);
                        audit.event_type = event_type::APPROVAL_REQUESTED;
                        audit.reason_code = "local-presence".into();
                        audit.outcome = outcome::SUCCESS;
                        audit.approval = Some(ApprovalEvidence {
                            approval_request_id: id,
                            approval_id: None,
                            approver_id: None,
                        });
                        self.authority.append_audit(audit).await?;
                    }
                    return Err(BrokerError::ApprovalRequired(ipc::ApprovalRequired {
                        challenge_id: local.challenge.approval_request_id,
                        expires_at_ms: local.challenge.max_expires_at_ms,
                    }));
                }
            }
            RuleEffect::Allow => {
                if input.meta.approval_request_id.is_some() {
                    return Err(BrokerError::Denied("approval-not-required"));
                }
            }
        }
        let llm = connection_llm(
            &authorized.connection,
            &authorized.action,
            authorized.streaming,
            authorized.generation_max_output,
        )?;
        let request = ExecuteRequest {
            request_id: input.request_id,
            capability_token: String::new(),
            action: ctx.action,
            content_type: authorized
                .headers
                .iter()
                .find(|(n, _)| n == "content-type")
                .map(|(_, v)| v.clone()),
            extra_headers: authorized
                .headers
                .iter()
                .filter(|(n, _)| n != "content-type")
                .cloned()
                .collect(),
            params: Default::default(),
            query: authorized.target.query.clone(),
            body: authorized.request_body,
            approval_grants: Vec::new(),
            local_approval_request_id: None,
        };
        let _owner = self
            .lifecycle
            .coordinate_until(tokio::time::Instant::from_std(deadline))
            .await?;
        self.lifecycle.reject_if_not_running()?;
        super::check_started_policy(
            &self.policy,
            Some(PolicyIdentity::of(&active)),
            &self.terminals,
            &ctx,
        )
        .await?;
        if active.is_expired(crate::now_ts()?) {
            return Err(BrokerError::Denied("policy-expired"));
        }
        self.local_calls.admit_rate(
            &authorized.connection.name,
            authorized.connection.limits.requests_per_hour,
            Duration::from_secs(3600),
        )?;
        let permit = self.lifecycle.local_permit();
        let started = super::commit_evaluated_started(
            &self.terminals,
            ctx,
            preceding,
            Some(deadline),
            Some(active.snapshot().expires_at_ms()),
            llm.as_ref().map(|l| l.usage.clone()),
        )
        .await
        .map_err(|error| match error {
            BrokerError::Denied("profile-budget-exceeded") => BrokerError::BudgetExceeded {
                reset_at_ms: (now.as_unix_ms().div_euclid(86_400_000) + 1) * 86_400_000,
            },
            other => other,
        })?;
        Ok(AdmittedExecution {
            executor: Arc::clone(self),
            request,
            action: authorized.action,
            target: authorized.target,
            llm,
            effect_deadline: deadline,
            started,
            _permit: None,
            _local_permit: Some(permit),
        })
    }
}

fn connection_llm(
    connection: &rekey_domain::connection::Connection,
    action: &rekey_domain::action::FixedHttpAction,
    streaming: bool,
    maximum: Option<u64>,
) -> Result<Option<super::llm::LlmExecution>, BrokerError> {
    let Some(limits) = &connection.llm else {
        return Ok(None);
    };
    use rekey_policy::ProfileLlmProtocol::*;
    let path = action.target.fixed_path().map(|p| p.as_str()).unwrap_or("");
    let protocol = match path {
        "/v1/messages" | "/api/anthropic/v1/messages" => AnthropicMessages,
        "/v1/messages/count_tokens" => CountTokens,
        "/v1/chat/completions" => OpenAiChat,
        "/v1/responses" | "/api/v1/responses" => OpenAiResponses,
        "/v1/embeddings" => Embeddings,
        "/v1/models" => Models,
        _ => return Err(BrokerError::Denied("llm-operation-unsupported")),
    };
    Ok(Some(super::llm::LlmExecution {
        protocol,
        streaming,
        usage: rekey_vault::command::ProfileUsageStart {
            instance_slug: connection.name.clone(),
            max_requests_per_day: limits.max_requests_per_day as u64,
            max_output_tokens_per_day: limits.max_output_tokens_per_day,
            generation_max_output: maximum,
        },
    }))
}
