//! Fixed signed T1 targets share local presence reviews and terminal audit ownership.
use super::{BrokerCtx, local_calls::LocalCallApproval};
use crate::{audit::ExecutionAuditContext, error::BrokerError};
use rekey_domain::audit::{DerivedRequestAuditContext, RequestAuditContext};
use rekey_domain::authorization::{ApprovalMode, ApproverSpec, ResourceRef, SchemaId};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::connection::{DerivedCredentialTarget, RuleEffect};
use rekey_domain::ids::{
    ActionId, ApprovalRequestId, PolicyRuleId, PrincipalId, RequestId, SessionId, TenantId,
};
use rekey_domain::ipc;
use rekey_vault::model::{ApprovalEvidence, AuthorizationEvidence, event_type};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn id_bytes(value: &[u8]) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&Sha256::digest(value)[..16]);
    id
}
impl BrokerCtx {
    pub(crate) async fn derive_credential(
        &self,
        meta: ipc::DeriveCredentialMeta,
        caller: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
        self.lifecycle.reject_if_not_running()?;
        let now = crate::now_ts()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some() && !p.is_expired(now))
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        let grant = active
            .snapshot()
            .derived_credentials()
            .iter()
            .find(|g| g.name == meta.connection)
            .cloned()
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        let request_id = crate::random_id(RequestId::from_random_bytes)?;
        let canonical = serde_jcs::to_vec(&serde_json::json!({"connection":grant.name,"target":grant.target,"max_ttl_seconds":grant.max_ttl_seconds,"grade":"T1","agent_receives_temporary_credential":true})).map_err(|_| ipc::FrameError::InvalidField)?;
        let hash: [u8; 32] = Sha256::digest(&canonical).into();
        let policy_hash = data_encoding::HEXLOWER.encode(&active.snapshot().digest());
        let parameter_hash = data_encoding::HEXLOWER.encode(&hash);
        let rule =
            PolicyRuleId::from_random_bytes(id_bytes(format!("derive:{}", grant.name).as_bytes()));
        let principal =
            PrincipalId::from_random_bytes(id_bytes(format!("derive:{}", grant.name).as_bytes()));
        let ctx = ExecutionAuditContext {
            request_id,
            session_id: SessionId::from_random_bytes(*request_id.as_bytes()),
            action: ActionVersionRef {
                action_id: ActionId::from_random_bytes(id_bytes(
                    format!("derive:{}", grant.name).as_bytes(),
                )),
                version: 1,
            },
            credential_id: grant.credential_id,
            request_context: Some(RequestAuditContext::Derived(DerivedRequestAuditContext {
                connection: grant.name.clone(),
                caller: caller.into(),
                target: grant.target.clone(),
                expires_at_ms: None,
            })),
            authorization: Some(AuthorizationEvidence {
                principal_id: principal,
                policy_version: active.snapshot().version().get(),
                policy_digest: active.snapshot().digest(),
                policy_rule_id: Some(rule),
                resource_type: "connection".into(),
                resource_id: grant.name.clone(),
                parameter_hash: hash,
            }),
        };
        let mut preceding = Vec::new();
        match grant.effect {
            RuleEffect::Deny => {
                self.authority
                    .append_audit(crate::audit::execution_blocked(&ctx, "derived-rule-denied"))
                    .await?;
                return Err(BrokerError::LocalCall(
                    "DENIED",
                    "temporary credential issuance is denied",
                    "Use request_access and review the signed T1 permission in Rekey App.",
                ));
            }
            RuleEffect::Allow if meta.approval_request_id.is_some() => {
                return Err(BrokerError::Denied("approval-not-required"));
            }
            RuleEffect::Allow => {}
            RuleEffect::Approve => {
                if let Some(id) = meta.approval_request_id {
                    let approval = self.local_calls.consume(
                        id,
                        caller,
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
                } else {
                    let id = crate::random_id(ApprovalRequestId::from_random_bytes)?;
                    let status = self.authority.status().await?;
                    let challenge = ipc::ApprovalChallenge {
                        record_type: "rekey.approval.challenge.v2".into(),
                        approval_request_id: id,
                        tenant_id: TenantId::from_random_bytes(*status.vault_id.as_bytes()),
                        principal_id: principal,
                        session_id: ctx.session_id,
                        action_id: ctx.action.action_id,
                        action_version: 1,
                        resource: ResourceRef::new("connection".into(), grant.name.clone())?,
                        schema_id: SchemaId::new("rekey.derived.v1".into())?,
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
                    let origin = match &grant.target {
                        DerivedCredentialTarget::AwsAssumeRole { region, .. }
                        | DerivedCredentialTarget::KubernetesEks { region, .. } => {
                            format!("https://sts.{region}.amazonaws.com")
                        }
                        DerivedCredentialTarget::GitHubApp { .. } => {
                            "https://api.github.com".into()
                        }
                    };
                    let review = ipc::LocalApprovalReview {
                        record_type: "rekey.approval.local-review.v1".into(),
                        challenge: challenge.clone(),
                        action_name: rekey_domain::action::ActionName::new(&format!(
                            "T1 {}: Agent receives temporary credentials",
                            grant.name
                        ))?,
                        origin: rekey_domain::action::HttpsOrigin::parse(&origin)?,
                        method: rekey_domain::action::FixedMethod::Post,
                        canonical_request: serde_json::value::RawValue::from_string(
                            String::from_utf8(canonical)
                                .map_err(|_| ipc::FrameError::InvalidField)?,
                        )
                        .map_err(|_| ipc::FrameError::InvalidField)?,
                    };
                    let bytes = Zeroizing::new(
                        serde_jcs::to_vec(&review).map_err(|_| ipc::FrameError::InvalidField)?,
                    );
                    let mut h = Sha256::new();
                    h.update(ipc::LOCAL_APPROVAL_REVIEW_HASH_PREFIX);
                    h.update(&*bytes);
                    let approval = self.local_calls.register(
                        LocalCallApproval {
                            challenge: challenge.clone(),
                            caller: caller.into(),
                            request_context: ctx.request_context.clone(),
                            review_sha256: data_encoding::HEXLOWER.encode(&h.finalize()),
                            review: bytes,
                            deadline: (Instant::now() + Duration::from_secs(600))
                                .min(active.monotonic_deadline().into_std()),
                            state: ipc::LocalApprovalState::Pending,
                            approval_id: None,
                        },
                        now.as_unix_ms(),
                    )?;
                    if approval.challenge.approval_request_id == id {
                        let mut audit = crate::audit::execution_started(&ctx);
                        audit.event_type = event_type::APPROVAL_REQUESTED;
                        audit.reason_code = "local-presence".into();
                        audit.approval = Some(ApprovalEvidence {
                            approval_request_id: id,
                            approval_id: None,
                            approver_id: None,
                        });
                        self.authority.append_audit(audit).await?;
                    }
                    return Err(BrokerError::ApprovalRequired(ipc::ApprovalRequired {
                        challenge_id: approval.challenge.approval_request_id,
                        expires_at_ms: approval.challenge.max_expires_at_ms,
                    }));
                }
            }
        }
        let start = Instant::now();
        let deadline =
            (start + Duration::from_secs(30)).min(active.monotonic_deadline().into_std());
        let permit;
        let mut started;
        {
            let _owner = self.lifecycle.coordinate_until(deadline.into()).await?;
            self.lifecycle.reject_if_not_running()?;
            let current = self.policy.read().await;
            let current_time = crate::now_ts()?;
            if !current.as_ref().is_some_and(|p| {
                p.snapshot().digest() == active.snapshot().digest() && !p.is_expired(current_time)
            }) {
                return Err(BrokerError::Denied("policy-changed"));
            }
            permit = self.lifecycle.local_permit();
            started = self
                .terminals
                .commit_started(
                    ctx,
                    preceding,
                    Some(deadline),
                    Some(active.snapshot().expires_at_ms()),
                )
                .await?;
        }
        let cancel = self.lifecycle.subscribe_cancel();
        if *cancel.borrow() {
            started.submit_blocked("abandoned");
            return Err(BrokerError::Admission(
                rekey_vault::AuthorityError::Draining,
            ));
        }
        crate::executor::try_begin_remote_effect(&self.lifecycle, &mut started, deadline).await?;
        // Once admitted, cancellation queues an indeterminate terminal instead of inventing success.
        started.mark_remote_effect_started();
        let issue = tokio::time::timeout_at(
            deadline.into(),
            crate::derived::issue(
                &self.authority,
                self.executor.transport.as_ref(),
                &self.lifecycle,
                grant.credential_id,
                &grant.target,
                grant.max_ttl_seconds,
                deadline,
            ),
        );
        let issued = tokio::select! {
            biased;
            _ = crate::executor::wait_for_cancel(cancel.clone()) => {
                started.submit_indeterminate("derived-issuance-cancelled");
                return Err(BrokerError::Admission(rekey_vault::AuthorityError::Draining));
            }
            issued = issue => issued,
        };
        let issued = match issued {
            Ok(Ok(issued)) => issued,
            other => {
                started
                    .indeterminate_until(deadline, "derived-issuance-failed")
                    .await?;
                return Err(match other {
                    Ok(Err(error)) => error,
                    _ => BrokerError::Upstream("derived-issuance-timeout"),
                });
            }
        };
        let _owner = tokio::select! {
            biased;
            _ = crate::executor::wait_for_cancel(cancel) => {
                started.submit_indeterminate("derived-issuance-cancelled");
                return Err(BrokerError::Admission(rekey_vault::AuthorityError::Draining));
            }
            owner = self.lifecycle.coordinate_until(deadline.into()) => owner?,
        };
        self.lifecycle.reject_if_not_running()?;
        if self
            .policy
            .read()
            .await
            .as_ref()
            .is_none_or(|p| p.snapshot().digest() != active.snapshot().digest())
        {
            return Err(BrokerError::Denied("policy-changed"));
        }
        let mut audit = crate::audit::execution_started(started.context());
        audit.event_type = "credential.derived_issued";
        audit.reason_code = "temporary-credential".into();
        audit.credential_version = Some(issued.credential_version);
        audit.request_context = Some(RequestAuditContext::Derived(DerivedRequestAuditContext {
            connection: grant.name.clone(),
            caller: caller.into(),
            target: grant.target,
            expires_at_ms: Some(issued.expires_at_ms),
        }));
        self.authority.append_audit(audit).await?;
        started
            .finished_until(
                deadline,
                issued.credential_version,
                200,
                start.elapsed().as_millis() as i64,
            )
            .await?;
        drop(permit);
        Ok((serde_json::to_vec(&serde_json::json!({"connection":grant.name,"kind":issued.kind,"expires_at_ms":issued.expires_at_ms})).map_err(|_| ipc::FrameError::InvalidField)?,issued.body.to_vec()))
    }
}
