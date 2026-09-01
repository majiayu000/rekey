//! Fixed HTTP action execution pipeline. Step order is a contract
//! (spec §14) and must not be rearranged: capability, pinning, validation,
//! started-audit, credential, upstream, sealing, filtering, finished-audit,
//! accounting, cleanup.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use rekey_domain::DomainError;
use rekey_domain::action::FixedHttpAction;
use rekey_domain::authorization::{AuthorizationRequest, Decision, DenyReason, Principal};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::RequestId;
use rekey_vault::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::ActionState;
use rekey_vault::model::AuthorizationEvidence;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::audit::{
    ExecutionAuditContext, StartedAuditGuard, TerminalAuditTracker, connector_event,
    execution_blocked,
};
use crate::error::BrokerError;
use crate::github_app::{GitHubAppCredential, GitHubEffect, GitHubError};
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::{ExecutionPermit, SessionRegistry};
use crate::upstream::{UpstreamRequest, UpstreamTransport};

mod deadline;
mod http;
mod sealing;
use http::{
    build_upstream, filter_response_headers, reason_static, response_metadata_fits,
    upstream_failure_is_indeterminate, validate_request,
};
#[cfg(test)]
use sealing::percent_encode;
use sealing::{contains_secret, headers_contain_secret, sealing_needles};

pub struct ExecuteRequest {
    pub request_id: RequestId,
    pub capability_token: String,
    pub action: ActionVersionRef,
    pub content_type: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct ExecuteOutcome {
    pub upstream_status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Runtime-owned after `execution.started` commits. Dropping a client response
/// receiver cannot drop this object; the ExecutionSupervisor owns `run`.
pub struct AdmittedExecution {
    executor: Arc<ActionExecutor>,
    request: ExecuteRequest,
    action: FixedHttpAction,
    effect_deadline: Instant,
    started: StartedAuditGuard,
    _permit: ExecutionPermit,
}

pub struct ActionExecutor {
    authority: AuthorityHandle,
    sessions: Arc<SessionRegistry>,
    transport: Arc<dyn UpstreamTransport>,
    lifecycle: Arc<Lifecycle>,
    terminals: Arc<TerminalAuditTracker>,
    policy: Arc<RwLock<Option<Arc<rekey_policy::ValidatedSnapshot>>>>,
}

const EFFECT_NOT_STARTED: u8 = 0;
const EFFECT_ORDINARY_HTTP: u8 = 1;
const EFFECT_GITHUB_CONNECTOR: u8 = 2;

impl ActionExecutor {
    pub fn new(
        authority: AuthorityHandle,
        sessions: Arc<SessionRegistry>,
        transport: Arc<dyn UpstreamTransport>,
        lifecycle: Arc<Lifecycle>,
        terminals: Arc<TerminalAuditTracker>,
        policy: Arc<RwLock<Option<Arc<rekey_policy::ValidatedSnapshot>>>>,
    ) -> Self {
        Self {
            authority,
            sessions,
            transport,
            lifecycle,
            terminals,
            policy,
        }
    }

    fn refuse_unless_running(&self) -> Result<(), BrokerError> {
        match self.lifecycle.phase() {
            BrokerPhase::Running => Ok(()),
            BrokerPhase::Locked => Err(BrokerError::Authority(AuthorityError::Locked)),
            BrokerPhase::Draining | BrokerPhase::ShuttingDown => {
                Err(BrokerError::Authority(AuthorityError::Draining))
            }
        }
    }

    pub async fn admit(
        self: &Arc<Self>,
        request: ExecuteRequest,
    ) -> Result<AdmittedExecution, BrokerError> {
        let admission_started = Instant::now();
        self.refuse_unless_running()?;
        // Step 3: capability authentication reserves one use and one
        // concurrency slot; the permit releases the slot on every path.
        let permit =
            self.sessions
                .acquire(&request.capability_token, request.action, crate::now_ts()?)?;
        let effect_deadline = admission_started + Duration::from_millis(permit.timeout_ms as u64);
        self.refuse_unless_running()?;
        let principal = permit.principal;
        self.admit_authorized(request, principal, permit, effect_deadline)
            .await
    }

    async fn admit_authorized(
        self: &Arc<Self>,
        request: ExecuteRequest,
        principal: Principal,
        permit: ExecutionPermit,
        effect_deadline: Instant,
    ) -> Result<AdmittedExecution, BrokerError> {
        // Step 4: pin the immutable action version.
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
            deadline::await_authority(
                effect_deadline,
                self.authority
                    .append_audit(execution_blocked(&ctx, "action-disabled")),
            )
            .await?;
            return Err(BrokerError::Domain(DomainError::ActionDisabled));
        }

        // Step 5: request validation against the pinned policy.
        if let Err(reason) = validate_request(&action, &request) {
            deadline::await_authority(
                effect_deadline,
                self.authority.append_audit(execution_blocked(&ctx, reason)),
            )
            .await?;
            return Err(BrokerError::Denied(reason));
        }

        let Some(snapshot) = self.lifecycle_policy(effect_deadline).await? else {
            deadline::await_authority(
                effect_deadline,
                self.authority
                    .append_audit(execution_blocked(&ctx, DenyReason::NoActiveSnapshot.code())),
            )
            .await?;
            return Err(BrokerError::Denied(DenyReason::NoActiveSnapshot.code()));
        };
        if snapshot.binding(request.action).is_none() {
            deadline::await_authority(
                effect_deadline,
                self.authority
                    .append_audit(execution_blocked(&ctx, DenyReason::ActionNotBound.code())),
            )
            .await?;
            return Err(BrokerError::Denied(DenyReason::ActionNotBound.code()));
        }
        let (resource, parameters) = match snapshot.canonicalize(
            request.action,
            request.content_type.as_deref(),
            &request.extra_headers,
            &request.body,
        ) {
            Ok(value) => value,
            Err(_) => {
                deadline::await_authority(
                    effect_deadline,
                    self.authority.append_audit(execution_blocked(
                        &ctx,
                        DenyReason::InvalidParameters.code(),
                    )),
                )
                .await?;
                return Err(BrokerError::Denied(DenyReason::InvalidParameters.code()));
            }
        };
        let authorization_request = AuthorizationRequest {
            principal,
            action: request.action,
            resource: resource.clone(),
            parameters: parameters.clone(),
        };
        let decision = rekey_policy::evaluate(&snapshot, &authorization_request, crate::now_ts()?);
        let (policy_version, policy_digest, policy_rule_id) = match &decision {
            Decision::Allow {
                policy_version,
                snapshot_digest,
                determining_rule,
            } => (*policy_version, *snapshot_digest, Some(*determining_rule)),
            Decision::Deny {
                policy_version: Some(policy_version),
                snapshot_digest: Some(snapshot_digest),
                determining_rule,
                ..
            } => (*policy_version, *snapshot_digest, *determining_rule),
            Decision::Deny { reason, .. } => {
                deadline::await_authority(
                    effect_deadline,
                    self.authority
                        .append_audit(execution_blocked(&ctx, reason.code())),
                )
                .await?;
                return Err(BrokerError::Denied(reason.code()));
            }
        };
        ctx.authorization = Some(AuthorizationEvidence {
            principal_id: principal.principal_id,
            policy_version: policy_version.get(),
            policy_digest,
            policy_rule_id,
            resource_type: resource.resource_type,
            resource_id: resource.id,
            parameter_hash: parameters.canonical_hash,
        });
        if let Decision::Deny { reason, .. } = decision {
            deadline::await_authority(
                effect_deadline,
                self.authority
                    .append_audit(execution_blocked(&ctx, reason.code())),
            )
            .await?;
            return Err(BrokerError::Denied(reason.code()));
        }

        // Step 6: this final point linearizes with drain. Earlier Running
        // checks are advisory; no drain may transition between this re-check
        // and transfer of durable started/terminal ownership.
        let started = tokio::time::timeout_at(
            tokio::time::Instant::from_std(effect_deadline),
            commit_started_while_running(&self.lifecycle, &self.terminals, ctx),
        )
        .await
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))??;
        Ok(AdmittedExecution {
            executor: Arc::clone(self),
            request,
            effect_deadline,
            action,
            started,
            _permit: permit,
        })
    }

    async fn lifecycle_policy(
        &self,
        effect_deadline: Instant,
    ) -> Result<Option<Arc<rekey_policy::ValidatedSnapshot>>, BrokerError> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(effect_deadline),
            self.policy.read(),
        )
        .await
        .map(|guard| guard.clone())
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))
    }

    async fn run_started(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<ExecuteOutcome, BrokerError> {
        // Steps 7-8: credential eligibility and preparation (single owner).
        let prepared = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(effect_deadline),
            self.authority.prepare_credential(action.credential_id),
        )
        .await
        {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(err)) => {
                started.blocked(prepare_block_reason(&err)).await?;
                return Err(BrokerError::Authority(err));
            }
            Err(_) => {
                started.blocked("upstream-timeout").await?;
                return Err(BrokerError::Upstream("upstream-timeout"));
            }
        };
        let credential_version = prepared.version();
        let credential_kind = prepared.kind();

        // Step 9: select the closed credential effect. Ordinary credentials
        // retain the fixed-header path. A marked GitHub App payload may only
        // enter its one built-in profile; malformed marked payloads never
        // fall back to bearer-token behavior.
        let prepared = prepared.consume(|secret| match credential_kind {
            rekey_domain::credential::CredentialKind::OpaqueToken
                if !GitHubAppCredential::action_is_reserved(action) =>
            {
                let mut auth_value = Zeroizing::new(Vec::with_capacity(
                    action.auth.prefix.as_str().len() + secret.len(),
                ));
                auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
                auth_value.extend_from_slice(secret);
                let needles = sealing_needles(secret, &auth_value);
                PreparedExecution::Opaque {
                    upstream: build_upstream(action, request, auth_value),
                    needles,
                }
            }
            rekey_domain::credential::CredentialKind::OpaqueToken => {
                PreparedExecution::GitHub(GitHubPrepared {
                    credential_version,
                    needles: Vec::new(),
                    profile: Err(GitHubError::InvalidCredential),
                })
            }
            rekey_domain::credential::CredentialKind::GitHubAppInstallation => {
                let profile = GitHubAppCredential::parse_profile(secret);
                PreparedExecution::GitHub(GitHubPrepared {
                    credential_version,
                    needles: profile
                        .as_ref()
                        .map(|profile| sealing_needles(secret, profile.private_key_bytes()))
                        .unwrap_or_default(),
                    profile,
                })
            }
        });

        if let PreparedExecution::GitHub(prepared) = prepared {
            return self
                .run_github(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await;
        }
        let PreparedExecution::Opaque {
            upstream: mut upstream_request,
            needles,
        } = prepared
        else {
            unreachable!("credential execution variant was matched above")
        };

        // Steps 10-11: fixed HTTPS send with bounded response. Credential
        // preparation consumes the same action deadline as DNS and HTTP.
        upstream_request.timeout = effect_deadline.saturating_duration_since(Instant::now());
        if upstream_request.timeout.is_zero() {
            started.blocked("upstream-timeout").await?;
            return Err(BrokerError::Upstream("upstream-timeout"));
        }
        try_begin_remote_effect(&self.lifecycle, started).await?;
        // No await separates the gate from this marker. Cancellation after
        // this point cannot truthfully claim the upstream saw no effect.
        started.mark_remote_effect_started();
        effect_kind.store(EFFECT_ORDINARY_HTTP, Ordering::SeqCst);
        let send_started = Instant::now();
        let response = self.transport.send(upstream_request).await;
        let latency_ms = send_started.elapsed().as_millis() as i64;
        let mut response = match response {
            Ok(response) => response,
            Err(err) => {
                let reason = match &err {
                    crate::upstream::UpstreamError::Blocked(r) => r,
                    crate::upstream::UpstreamError::ResponseTooLarge => "response-too-large",
                    crate::upstream::UpstreamError::Timeout => "upstream-timeout",
                    crate::upstream::UpstreamError::Transport => "upstream-transport",
                };
                if upstream_failure_is_indeterminate(&err) {
                    started.indeterminate(reason).await?;
                } else {
                    started.blocked(reason).await?;
                }
                return Err(match err {
                    crate::upstream::UpstreamError::ResponseTooLarge => {
                        BrokerError::Domain(DomainError::ResponseTooLarge)
                    }
                    _ => BrokerError::Upstream(reason_static(reason)),
                });
            }
        };

        // Step 12: secret sealing over the buffered body and every header
        // the upstream sent (name and value), before any allowlist copy.
        if contains_secret(&response.body, &needles)
            || headers_contain_secret(&response.headers, &needles)
        {
            started.indeterminate("reflected-secret").await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }

        // Step 13: response header filtering (allowlist only).
        let headers = filter_response_headers(action, &response.headers);
        if !response_metadata_fits(response.status, &headers, response.body.len()) {
            started.indeterminate("response-metadata-too-large").await?;
            return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
        }

        // Step 14: ExecutionFinished must commit; upstream success without
        // evidence is not success.
        started
            .finished(credential_version, response.status, latency_ms)
            .await?;
        let body = std::mem::take(&mut *response.body);

        // Steps 15-16 (accounting + cleanup) happen in Drop of permit and secrets.
        Ok(ExecuteOutcome {
            upstream_status: response.status,
            headers,
            body,
        })
    }

    async fn run_github(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: GitHubPrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let profile = match prepared.profile {
            Ok(profile) => profile,
            Err(err) => {
                started.blocked(err.reason()).await?;
                return Err(BrokerError::Denied(err.reason()));
            }
        };
        if let Err(err) = profile.validate_action(action, request) {
            started.blocked(err.reason()).await?;
            return Err(BrokerError::Denied(err.reason()));
        }
        // This durable event proves the exact non-secret connector binding
        // was authorized before JWT signing or token exchange.
        self.authority
            .append_audit(connector_event(
                started.context(),
                rekey_vault::model::event_type::GITHUB_CONNECTOR_AUTHORIZED,
                rekey_vault::model::outcome::SUCCESS,
                profile.commitment(),
            ))
            .await?;

        try_begin_remote_effect(&self.lifecycle, started).await?;
        // No await separates the gate's linearization point from this flag.
        // Once begun, lifecycle cancellation must not strand a remote token.
        started.mark_remote_effect_started();
        effect_kind.store(EFFECT_GITHUB_CONNECTOR, Ordering::SeqCst);

        let send_started = Instant::now();
        let effect = profile
            .execute_effect(
                self.transport.as_ref(),
                effect_deadline,
                action.response_policy.max_body_bytes,
            )
            .await;
        let latency_ms = send_started.elapsed().as_millis() as i64;
        let GitHubEffect::WithToken {
            resource,
            revoke,
            sealing_sources,
        } = effect
        else {
            let GitHubEffect::WithoutToken {
                error,
                remote_effect_possible,
            } = effect
            else {
                unreachable!("GitHub effect variant was matched above")
            };
            if remote_effect_possible {
                started.indeterminate(error.reason()).await?;
            } else {
                started.blocked(error.reason()).await?;
            }
            return Err(BrokerError::Upstream(error.reason()));
        };
        let mut needles = prepared.needles;
        for source in sealing_sources {
            needles.extend(sealing_needles(&source, &source));
        }
        let (revoke_outcome, revoke_reason) = match revoke {
            Ok(()) => (
                rekey_vault::model::outcome::SUCCESS,
                format!("success;{}", profile.commitment()),
            ),
            Err(err) => (
                rekey_vault::model::outcome::FAILURE,
                format!("{};{}", err.reason(), profile.commitment()),
            ),
        };
        self.authority
            .append_audit(connector_event(
                started.context(),
                rekey_vault::model::event_type::GITHUB_TOKEN_REVOKED,
                revoke_outcome,
                revoke_reason,
            ))
            .await?;
        if let Err(err) = revoke {
            started.indeterminate(err.reason()).await?;
            return Err(BrokerError::Upstream(err.reason()));
        }

        let mut response = match resource {
            Ok(response) => response,
            Err(err) => {
                started.indeterminate(err.reason()).await?;
                return Err(BrokerError::Upstream(err.reason()));
            }
        };
        if contains_secret(&response.body, &needles)
            || headers_contain_secret(&response.headers, &needles)
        {
            started.indeterminate("reflected-secret").await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let headers = filter_response_headers(action, &response.headers);
        if !response_metadata_fits(response.status, &headers, response.body.len()) {
            started.indeterminate("response-metadata-too-large").await?;
            return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
        }
        started
            .finished(prepared.credential_version, response.status, latency_ms)
            .await?;
        let body = std::mem::take(&mut *response.body);
        Ok(ExecuteOutcome {
            upstream_status: response.status,
            headers,
            body,
        })
    }
}

enum PreparedExecution {
    Opaque {
        upstream: UpstreamRequest,
        needles: Vec<Zeroizing<Vec<u8>>>,
    },
    GitHub(GitHubPrepared),
}

struct GitHubPrepared {
    credential_version: u64,
    profile: Result<GitHubAppCredential, GitHubError>,
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl AdmittedExecution {
    pub async fn run(mut self) -> Result<ExecuteOutcome, BrokerError> {
        let cancel = self.executor.lifecycle.subscribe_cancel();
        if *cancel.borrow() {
            self.started.blocked("abandoned").await?;
            return Err(BrokerError::Authority(AuthorityError::Draining));
        }

        let executor = Arc::clone(&self.executor);
        let effect_kind = AtomicU8::new(EFFECT_NOT_STARTED);
        let mut cancelled_after_ordinary_effect = false;
        {
            let run = executor.run_started(
                &mut self.started,
                &self.request,
                &self.action,
                self.effect_deadline,
                &effect_kind,
            );
            tokio::pin!(run);
            tokio::select! {
                biased;
                _ = wait_for_cancel(cancel) => {
                    match effect_kind.load(Ordering::SeqCst) {
                        EFFECT_GITHUB_CONNECTOR => return run.await,
                        EFFECT_ORDINARY_HTTP => cancelled_after_ordinary_effect = true,
                        _ => {}
                    }
                }
                result = &mut run => return result,
            }
        }
        if !self.started.is_completed() {
            if cancelled_after_ordinary_effect {
                self.started
                    .indeterminate("cancelled-after-remote-effect")
                    .await?;
            } else {
                self.started.blocked("abandoned").await?;
            }
        }
        Err(BrokerError::Authority(AuthorityError::Draining))
    }
}

async fn wait_for_cancel(mut cancel: tokio::sync::watch::Receiver<bool>) {
    while !*cancel.borrow_and_update() {
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

async fn try_begin_remote_effect(
    lifecycle: &Lifecycle,
    started: &mut StartedAuditGuard,
) -> Result<(), BrokerError> {
    if lifecycle.try_begin_remote_effect() {
        return Ok(());
    }
    started.blocked("remote-effect-admission-closed").await?;
    Err(BrokerError::Authority(AuthorityError::Draining))
}

async fn commit_started_while_running(
    lifecycle: &Lifecycle,
    terminals: &TerminalAuditTracker,
    ctx: ExecutionAuditContext,
) -> Result<StartedAuditGuard, BrokerError> {
    let _coordinator = match lifecycle.try_coordinate() {
        Ok(owner) => owner,
        Err(_) if lifecycle.phase() == BrokerPhase::Running => {
            return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
        }
        Err(_) => return Err(BrokerError::Authority(AuthorityError::Draining)),
    };
    lifecycle.reject_if_not_running()?;
    terminals
        .commit_started(ctx)
        .await
        .map_err(BrokerError::Authority)
}

fn prepare_block_reason(err: &AuthorityError) -> &'static str {
    match err {
        AuthorityError::Locked => "locked",
        AuthorityError::Draining => "draining",
        AuthorityError::Faulted => "faulted",
        AuthorityError::CredentialRevoked => "credential-revoked",
        AuthorityError::CryptoFailure => "crypto-failure",
        _ => "credential-unavailable",
    }
}

#[cfg(test)]
mod tests;
