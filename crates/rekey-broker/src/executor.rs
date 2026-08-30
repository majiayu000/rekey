//! Fixed HTTP action execution pipeline. Step order is a contract
//! (spec §14) and must not be rearranged: capability, pinning, validation,
//! started-audit, credential, upstream, sealing, filtering, finished-audit,
//! accounting, cleanup.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use rekey_domain::action::FixedHttpAction;
use rekey_domain::authorization::{AuthorizationRequest, Decision, DenyReason, Principal};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::RequestId;
use rekey_domain::{DomainError, Timestamp};
use rekey_vault::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::ActionState;
use rekey_vault::model::AuthorizationEvidence;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::audit::{
    ExecutionAuditContext, TerminalAuditTracker, connector_event, execution_blocked,
    execution_finished, execution_started,
};
use crate::error::BrokerError;
use crate::github_app::{GitHubAppCredential, GitHubEffect, GitHubError};
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::{ExecutionPermit, SessionRegistry};
use crate::upstream::{UpstreamRequest, UpstreamTransport};

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
    started: StartedGuard,
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

struct StartedGuard {
    terminals: Arc<TerminalAuditTracker>,
    ctx: ExecutionAuditContext,
    terminal_submitted: bool,
}

impl StartedGuard {
    fn new(terminals: Arc<TerminalAuditTracker>, ctx: ExecutionAuditContext) -> Self {
        Self {
            terminals,
            ctx,
            terminal_submitted: false,
        }
    }

    fn is_completed(&self) -> bool {
        self.terminal_submitted
    }

    async fn blocked(&mut self, reason: &'static str) -> Result<(), BrokerError> {
        self.terminal_submitted = true;
        self.terminals
            .commit(execution_blocked(&self.ctx, reason))
            .await
            .map_err(BrokerError::Authority)
    }

    async fn finished(
        &mut self,
        credential_version: u64,
        upstream_status: u16,
        latency_ms: i64,
    ) -> Result<(), BrokerError> {
        self.terminal_submitted = true;
        self.terminals
            .commit(execution_finished(
                &self.ctx,
                credential_version,
                upstream_status,
                latency_ms,
            ))
            .await
            .map_err(|err| match err {
                AuthorityError::AuditCommitFailed => {
                    BrokerError::Authority(AuthorityError::AuditCommitFailedAfterExecution)
                }
                other => BrokerError::Authority(other),
            })?;
        Ok(())
    }
}

impl Drop for StartedGuard {
    fn drop(&mut self) {
        if !self.terminal_submitted {
            self.terminals
                .submit(execution_blocked(&self.ctx, "abandoned"));
        }
    }
}

/// Response headers stripped unconditionally, before the allowlist applies.
const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &[
    "authentication-info",
    "authorization",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "www-authenticate",
];

fn now_ts() -> Timestamp {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Timestamp::from_unix_ms(ms)
}

fn header_value_is_safe(value: &str) -> bool {
    value.len() <= 8 * 1024 && !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

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
        let permit = self
            .sessions
            .acquire(&request.capability_token, request.action, now_ts())?;
        self.refuse_unless_running()?;
        let principal = permit.principal;
        self.admit_authorized(request, principal, permit, admission_started)
            .await
    }

    async fn admit_authorized(
        self: &Arc<Self>,
        request: ExecuteRequest,
        principal: Principal,
        permit: ExecutionPermit,
        admission_started: Instant,
    ) -> Result<AdmittedExecution, BrokerError> {
        // Step 4: pin the immutable action version.
        let pinned = self
            .authority
            .action_get(request.action.action_id, request.action.version)
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
            self.authority
                .append_audit(execution_blocked(&ctx, "action-disabled"))
                .await?;
            return Err(BrokerError::Domain(DomainError::ActionDisabled));
        }

        // Step 5: request validation against the pinned policy.
        if let Err(reason) = validate_request(&action, &request) {
            self.authority
                .append_audit(execution_blocked(&ctx, reason))
                .await?;
            return Err(BrokerError::Denied(reason));
        }

        let Some(snapshot) = self.lifecycle_policy().await else {
            self.authority
                .append_audit(execution_blocked(&ctx, DenyReason::NoActiveSnapshot.code()))
                .await?;
            return Err(BrokerError::Denied(DenyReason::NoActiveSnapshot.code()));
        };
        if snapshot.binding(request.action).is_none() {
            self.authority
                .append_audit(execution_blocked(&ctx, DenyReason::ActionNotBound.code()))
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
                self.authority
                    .append_audit(execution_blocked(
                        &ctx,
                        DenyReason::InvalidParameters.code(),
                    ))
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
        let decision = rekey_policy::evaluate(&snapshot, &authorization_request, now_ts());
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
                self.authority
                    .append_audit(execution_blocked(&ctx, reason.code()))
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
            self.authority
                .append_audit(execution_blocked(&ctx, reason.code()))
                .await?;
            return Err(BrokerError::Denied(reason.code()));
        }

        // Step 6: ExecutionStarted must commit before any credential effect.
        self.authority.append_audit(execution_started(&ctx)).await?;
        Ok(AdmittedExecution {
            executor: Arc::clone(self),
            request,
            effect_deadline: admission_started + Duration::from_millis(action.timeout_ms as u64),
            action,
            started: StartedGuard::new(Arc::clone(&self.terminals), ctx),
            _permit: permit,
        })
    }

    async fn lifecycle_policy(&self) -> Option<Arc<rekey_policy::ValidatedSnapshot>> {
        self.policy.read().await.clone()
    }

    async fn run_started(
        &self,
        started: &mut StartedGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        effect_deadline: Instant,
        connector_effect_started: &AtomicBool,
    ) -> Result<ExecuteOutcome, BrokerError> {
        // Steps 7-8: credential eligibility and preparation (single owner).
        let prepared = match self
            .authority
            .prepare_credential(action.credential_id)
            .await
        {
            Ok(prepared) => prepared,
            Err(err) => {
                started.blocked(prepare_block_reason(&err)).await?;
                return Err(BrokerError::Authority(err));
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
                    connector_effect_started,
                )
                .await;
        }
        let PreparedExecution::Opaque {
            upstream: upstream_request,
            needles,
        } = prepared
        else {
            unreachable!("credential execution variant was matched above")
        };

        // Steps 10-11: fixed HTTPS send with bounded response.
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
                started.blocked(reason).await?;
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
            started.blocked("reflected-secret").await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }

        // Step 13: response header filtering (allowlist only).
        let headers = filter_response_headers(action, &response.headers);

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
        started: &mut StartedGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: GitHubPrepared,
        effect_deadline: Instant,
        connector_effect_started: &AtomicBool,
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
                &started.ctx,
                rekey_vault::model::event_type::GITHUB_CONNECTOR_AUTHORIZED,
                rekey_vault::model::outcome::SUCCESS,
                profile.commitment(),
            ))
            .await?;

        try_begin_remote_effect(&self.lifecycle, started).await?;
        // No await separates the gate's linearization point from this flag.
        // Once begun, lifecycle cancellation must not strand a remote token.
        connector_effect_started.store(true, Ordering::SeqCst);

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
            let GitHubEffect::WithoutToken(err) = effect else {
                unreachable!("GitHub effect variant was matched above")
            };
            started.blocked(err.reason()).await?;
            return Err(BrokerError::Upstream(err.reason()));
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
                &started.ctx,
                rekey_vault::model::event_type::GITHUB_TOKEN_REVOKED,
                revoke_outcome,
                revoke_reason,
            ))
            .await?;
        if let Err(err) = revoke {
            started.blocked(err.reason()).await?;
            return Err(BrokerError::Upstream(err.reason()));
        }

        let mut response = match resource {
            Ok(response) => response,
            Err(err) => {
                started.blocked(err.reason()).await?;
                return Err(BrokerError::Upstream(err.reason()));
            }
        };
        if contains_secret(&response.body, &needles)
            || headers_contain_secret(&response.headers, &needles)
        {
            started.blocked("reflected-secret").await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let headers = filter_response_headers(action, &response.headers);
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
        let connector_effect_started = AtomicBool::new(false);
        {
            let run = executor.run_started(
                &mut self.started,
                &self.request,
                &self.action,
                self.effect_deadline,
                &connector_effect_started,
            );
            tokio::pin!(run);
            tokio::select! {
                biased;
                _ = wait_for_cancel(cancel) => {
                    if connector_effect_started.load(Ordering::SeqCst) {
                        return run.await;
                    }
                }
                result = &mut run => return result,
            }
        }
        if !self.started.is_completed() {
            self.started.blocked("abandoned").await?;
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
    started: &mut StartedGuard,
) -> Result<(), BrokerError> {
    if lifecycle.try_begin_remote_effect() {
        return Ok(());
    }
    started.blocked("remote-effect-admission-closed").await?;
    Err(BrokerError::Authority(AuthorityError::Draining))
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

fn reason_static(reason: &str) -> &'static str {
    match reason {
        "private-address" => "private-address",
        "redirect" => "redirect",
        "upstream-timeout" => "upstream-timeout",
        _ => "upstream-transport",
    }
}

fn validate_request(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
) -> Result<(), &'static str> {
    if request.body.len() > action.request_policy.max_body_bytes as usize {
        return Err("request-too-large");
    }
    if let Some(ct) = &request.content_type
        && (!header_value_is_safe(ct) || ct.is_empty())
    {
        return Err("invalid-content-type");
    }
    for (name, value) in &request.extra_headers {
        let Ok(name) = rekey_domain::action::HeaderName::new(name) else {
            return Err("invalid-extra-header");
        };
        // Anything outside the allowlist rejects the whole request; nothing
        // is silently stripped.
        if name.is_forbidden()
            || name == action.auth.header_name
            || name.as_str() == "authorization"
            || name.as_str() == "content-type"
            || !action.request_policy.allowed_extra_headers.contains(&name)
        {
            return Err("extra-header-not-allowed");
        }
        if !header_value_is_safe(value) {
            return Err("invalid-extra-header");
        }
    }
    Ok(())
}

fn build_upstream(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    auth_value: Zeroizing<Vec<u8>>,
) -> UpstreamRequest {
    let mut headers = Vec::with_capacity(request.extra_headers.len() + 1);
    if let Some(ct) = &request.content_type {
        headers.push(("content-type".to_owned(), ct.clone()));
    }
    for (name, value) in &request.extra_headers {
        headers.push((name.to_ascii_lowercase(), value.clone()));
    }
    UpstreamRequest {
        host: action.origin.host().to_owned(),
        port: action.origin.port(),
        method: action.method,
        path: action.exact_path.as_str().to_owned(),
        headers,
        auth_header: (action.auth.header_name.as_str().to_owned(), auth_value),
        body: request.body.clone(),
        timeout: Duration::from_millis(action.timeout_ms as u64),
        response_max_bytes: action.response_policy.max_body_bytes,
    }
}

/// Direct encodings of the secret (and the full auth header value) that a
/// reflecting upstream could echo: raw, base64 standard/url with and without
/// padding, and full percent-encoding in both hex cases.
fn sealing_needles(secret: &[u8], auth_value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut needles = Vec::new();
    for source in [secret, auth_value] {
        if source.is_empty() {
            continue;
        }
        needles.push(Zeroizing::new(source.to_vec()));
        needles.push(Zeroizing::new(BASE64.encode(source).into_bytes()));
        needles.push(Zeroizing::new(BASE64_NOPAD.encode(source).into_bytes()));
        needles.push(Zeroizing::new(BASE64URL.encode(source).into_bytes()));
        needles.push(Zeroizing::new(BASE64URL_NOPAD.encode(source).into_bytes()));
        needles.push(Zeroizing::new(percent_encode(source, false).into_bytes()));
        needles.push(Zeroizing::new(percent_encode(source, true).into_bytes()));
    }
    needles
}

fn percent_encode(bytes: &[u8], uppercase: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else if uppercase {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn contains_secret(haystack: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> bool {
    needles.iter().any(|n| find_subslice(haystack, n))
}

fn headers_contain_secret(headers: &[(String, String)], needles: &[Zeroizing<Vec<u8>>]) -> bool {
    headers.iter().any(|(name, value)| {
        contains_secret(name.as_bytes(), needles) || contains_secret(value.as_bytes(), needles)
    })
}

fn filter_response_headers(
    action: &FixedHttpAction,
    headers: &[(String, String)],
) -> Vec<(String, String)> {
    let auth_slot = action.auth.header_name.as_str();
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            if FORBIDDEN_RESPONSE_HEADERS.contains(&lower.as_str()) || lower == auth_slot {
                return false;
            }
            rekey_domain::action::HeaderName::new(&lower)
                .map(|n| action.response_policy.allowed_headers.contains(&n))
                .unwrap_or(false)
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests;
