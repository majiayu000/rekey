//! Fixed HTTP action execution pipeline. Step order is a contract
//! (spec §14) and must not be rearranged: capability, pinning, validation,
//! started-audit, credential, upstream, sealing, filtering, finished-audit,
//! accounting, cleanup.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use rekey_domain::action::FixedHttpAction;
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::RequestId;
use rekey_domain::{DomainError, Timestamp};
use rekey_vault::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::ActionState;
use zeroize::Zeroizing;

use crate::audit::{
    ExecutionAuditContext, TerminalAuditTracker, execution_blocked, execution_finished,
    execution_started,
};
use crate::error::BrokerError;
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::SessionRegistry;
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

pub struct ActionExecutor {
    authority: AuthorityHandle,
    sessions: Arc<SessionRegistry>,
    transport: Arc<dyn UpstreamTransport>,
    lifecycle: Arc<Lifecycle>,
    terminals: Arc<TerminalAuditTracker>,
}

struct StartedGuard {
    authority: AuthorityHandle,
    terminals: Arc<TerminalAuditTracker>,
    ctx: ExecutionAuditContext,
    completed: bool,
}

impl StartedGuard {
    fn new(
        authority: AuthorityHandle,
        terminals: Arc<TerminalAuditTracker>,
        ctx: ExecutionAuditContext,
    ) -> Self {
        Self {
            authority,
            terminals,
            ctx,
            completed: false,
        }
    }

    fn is_completed(&self) -> bool {
        self.completed
    }

    async fn blocked(&mut self, reason: &'static str) -> Result<(), BrokerError> {
        self.authority
            .commit_audit(execution_blocked(&self.ctx, reason))
            .await?;
        self.completed = true;
        Ok(())
    }

    async fn finished(
        &mut self,
        credential_version: u64,
        upstream_status: u16,
        latency_ms: i64,
    ) -> Result<(), BrokerError> {
        self.authority
            .commit_audit(execution_finished(
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
        self.completed = true;
        Ok(())
    }
}

impl Drop for StartedGuard {
    fn drop(&mut self) {
        if !self.completed {
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
    ) -> Self {
        Self {
            authority,
            sessions,
            transport,
            lifecycle,
            terminals,
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

    pub async fn execute(&self, request: ExecuteRequest) -> Result<ExecuteOutcome, BrokerError> {
        self.refuse_unless_running()?;
        // Step 3: capability authentication reserves one use and one
        // concurrency slot; the permit releases the slot on every path.
        let permit = self
            .sessions
            .acquire(&request.capability_token, request.action, now_ts())?;
        self.refuse_unless_running()?;
        let session_id = permit.session_id;
        self.execute_authorized(&request, session_id).await
    }

    async fn execute_authorized(
        &self,
        request: &ExecuteRequest,
        session_id: rekey_domain::ids::SessionId,
    ) -> Result<ExecuteOutcome, BrokerError> {
        // Step 4: pin the immutable action version.
        let pinned = self
            .authority
            .action_get(request.action.action_id, request.action.version)
            .await?;
        let action = pinned.action;
        let ctx = ExecutionAuditContext {
            request_id: request.request_id,
            session_id,
            action: request.action,
            credential_id: action.credential_id,
        };
        if pinned.state == ActionState::Disabled || !action.enabled {
            self.authority
                .append_audit(execution_blocked(&ctx, "action-disabled"))
                .await?;
            return Err(BrokerError::Domain(DomainError::ActionDisabled));
        }

        // Step 5: request validation against the pinned policy.
        if let Err(reason) = validate_request(&action, request) {
            self.authority
                .append_audit(execution_blocked(&ctx, reason))
                .await?;
            return Err(BrokerError::Denied(reason));
        }

        // Step 6: ExecutionStarted must commit before any credential effect.
        self.authority.append_audit(execution_started(&ctx)).await?;
        let mut started =
            StartedGuard::new(self.authority.clone(), Arc::clone(&self.terminals), ctx);

        let mut cancel = self.lifecycle.subscribe_cancel();
        if *cancel.borrow() {
            started.blocked("abandoned").await?;
            return Err(BrokerError::Authority(AuthorityError::Draining));
        }

        tokio::select! {
            biased;
            _ = cancel.changed() => {}
            result = self.run_started(&mut started, request, &action) => return result,
        }
        if !started.is_completed() {
            started.blocked("abandoned").await?;
        }
        Err(BrokerError::Authority(AuthorityError::Draining))
    }

    async fn run_started(
        &self,
        started: &mut StartedGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
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

        // Step 9: build the upstream request; the server owns origin, method,
        // path, and the single auth header.
        let mut needles = Vec::new();
        let upstream_request = prepared.consume(|secret| {
            let mut auth_value = Zeroizing::new(Vec::with_capacity(
                action.auth.prefix.as_str().len() + secret.len(),
            ));
            auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
            auth_value.extend_from_slice(secret);
            needles = sealing_needles(secret, &auth_value);
            build_upstream(action, request, auth_value)
        });

        // Steps 10-11: fixed HTTPS send with bounded response.
        let send_started = Instant::now();
        let response = self.transport.send(upstream_request).await;
        let latency_ms = send_started.elapsed().as_millis() as i64;
        let response = match response {
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

        // Steps 15-16 (accounting + cleanup) happen in Drop of permit and secrets.
        Ok(ExecuteOutcome {
            upstream_status: response.status,
            headers,
            body: response.body,
        })
    }
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
mod tests {
    use super::*;

    #[test]
    fn sealing_detects_direct_and_encoded_secret() {
        let secret = b"ghp_super_secret_token_value";
        let auth = b"Bearer ghp_super_secret_token_value";
        let needles = sealing_needles(secret, auth);

        assert!(contains_secret(
            b"before ghp_super_secret_token_value after",
            &needles
        ));
        let b64 = BASE64.encode(secret);
        assert!(contains_secret(format!("x{b64}y").as_bytes(), &needles));
        let url = BASE64URL_NOPAD.encode(auth);
        assert!(contains_secret(url.as_bytes(), &needles));
        let pct = percent_encode(auth, true);
        assert!(contains_secret(pct.as_bytes(), &needles));
        assert!(!contains_secret(b"clean response body", &needles));

        let leak = vec![("content-type".to_owned(), format!("text/plain; {b64}"))];
        assert!(headers_contain_secret(&leak, &needles));
        let clean = vec![("content-type".to_owned(), "application/json".to_owned())];
        assert!(!headers_contain_secret(&clean, &needles));
    }
}
