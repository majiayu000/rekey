//! Loopback HTTP is only an adapter to the existing Profile execution owner.
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ApprovalRequestId, RequestId};
use rekey_domain::ipc::{
    ErrorEnvelope, ProfileGatewayEndpoint, ProfileGatewayInstance, ProfileGatewayProvider,
    TextStreamStatus,
};
use rekey_domain::profile::AgentProfile;
use rekey_domain::template::{TemplateValues, ValueRule};
use rekey_vault::AuthorityError;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::{BrokerCtx, profile};
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;
use crate::execution_supervisor::HttpExecution;
use crate::executor::ExecuteRequest;
use crate::executor::text_stream::TextStreamEvent;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTIONS: usize = 120;
const HEADER_BYTES: usize = 16 * 1024;

#[derive(Default)]
pub(super) struct Gateway {
    bound: Mutex<Option<Bound>>,
    context: OnceLock<Weak<BrokerCtx>>,
    state_dir: Option<PathBuf>,
}
struct Bound {
    port: u16,
    policy: [u8; 32],
    stop: watch::Sender<bool>,
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.close();
    }
}
impl Gateway {
    pub(super) fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir: Some(state_dir),
            bound: Mutex::new(None),
            context: OnceLock::new(),
        }
    }
    pub(super) fn attach(&self, ctx: &Arc<BrokerCtx>) {
        let _ = self.context.set(Arc::downgrade(ctx));
    }
    pub(super) fn close(&self) {
        let mut state = self.bound.lock().unwrap_or_else(|e| e.into_inner());
        state.take();
        self.remove_cache();
    }
    fn close_binding(&self, stop: &watch::Sender<bool>) {
        let mut state = self.bound.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .as_ref()
            .is_some_and(|bound| bound.stop.same_channel(stop))
        {
            state.take();
            self.remove_cache();
        }
    }
    fn remove_cache(&self) {
        if let Some(dir) = &self.state_dir
            && let Err(error) = fs::remove_file(dir.join("gateway.port"))
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(event = "gateway.cache_cleanup_failed");
        }
    }
    fn current(&self, port: u16) -> bool {
        self.bound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|bound| bound.port == port)
    }
    pub(super) fn endpoint(
        &self,
        active: &ActivePolicy,
        profile: &AgentProfile,
        actions: &[FixedHttpAction],
    ) -> Option<ProfileGatewayEndpoint> {
        if profile.llm_limits.is_empty() {
            return None;
        }
        let state = self.bound.lock().unwrap_or_else(|e| e.into_inner());
        let bound = state
            .as_ref()
            .filter(|bound| bound.policy == active.snapshot().digest())?;
        let instances = profile
            .llm_limits
            .iter()
            .map(|limit| {
                let grant = profile
                    .grants
                    .iter()
                    .find(|grant| grant.instance == limit.instance)?;
                let reference = grant.capabilities.first()?.actions.first()?;
                let action = actions.iter().find(|action| {
                    action.id == reference.action_id && action.version == reference.version
                })?;
                let ActionTarget::Template { source, .. } = &action.target else {
                    return None;
                };
                if source.signer_id.is_some() {
                    return None;
                }
                let provider = match source.template.as_str() {
                    "anthropic@1" | "glm@1" => ProfileGatewayProvider::Anthropic,
                    "openai@1" => ProfileGatewayProvider::OpenAi,
                    _ => return None,
                };
                Some(ProfileGatewayInstance {
                    instance: limit.instance.clone(),
                    provider,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(ProfileGatewayEndpoint {
            port: bound.port,
            instances,
        })
    }
    fn publish_cache(&self, port: u16) -> io::Result<()> {
        let dir = self
            .state_dir
            .as_ref()
            .ok_or_else(|| io::Error::other("gateway unavailable"))?;
        let id = crate::random_id(RequestId::from_random_bytes).map_err(io::Error::other)?;
        let temporary = dir.join(format!(".gateway-{id}.tmp"));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            writeln!(file, "{port}")?;
            file.sync_all()?;
            fs::rename(&temporary, dir.join("gateway.port"))?;
            fs::File::open(dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
impl BrokerCtx {
    /// The policy transaction has already committed. Availability is reported
    /// separately through the authenticated Profile session response.
    pub(super) async fn reconcile_gateway(&self) {
        let Some(weak) = self.gateway.context.get().cloned() else {
            return;
        };
        let active = self.policy.read().await.clone();
        let Some(active) = active.filter(|policy| {
            policy.signer_id().is_some()
                && crate::now_ts().is_ok_and(|now| !policy.is_expired(now))
                && policy
                    .snapshot()
                    .profiles()
                    .iter()
                    .any(|profile| !profile.llm_limits.is_empty())
        }) else {
            self.gateway.close();
            return;
        };
        if !self.lifecycle.is_running() {
            self.gateway.close();
            return;
        }
        if self
            .gateway
            .bound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|bound| bound.policy == active.snapshot().digest())
        {
            return;
        }
        self.gateway.close();
        let Ok(Ok(actions)) =
            tokio::time::timeout(READ_TIMEOUT, self.authority.action_list()).await
        else {
            tracing::warn!(event = "gateway.material_unavailable");
            return;
        };
        if !active.snapshot().profiles().iter().any(|profile| {
            !profile.llm_limits.is_empty()
                && profile::validate_profiles(std::slice::from_ref(profile), &actions).is_ok()
                && profile::require_supported_profile(profile, &actions).is_ok()
        }) {
            return;
        }
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(_) => {
                tracing::warn!(event = "gateway.bind_failed");
                return;
            }
        };
        let Ok(address) = listener.local_addr() else {
            tracing::warn!(event = "gateway.bind_failed");
            return;
        };
        let port = address.port();
        if self.gateway.publish_cache(port).is_err() {
            self.gateway.close();
            tracing::warn!(event = "gateway.cache_publish_failed");
            return;
        }
        if !self.lifecycle.is_running()
            || crate::now_ts().map_or(true, |now| active.is_expired(now))
        {
            self.gateway.close();
            return;
        }
        let (stop, stop_rx) = watch::channel(false);
        *self.gateway.bound.lock().unwrap_or_else(|e| e.into_inner()) = Some(Bound {
            port,
            policy: active.snapshot().digest(),
            stop: stop.clone(),
        });
        tokio::spawn(accept(weak, listener, active, stop, stop_rx));
    }
}
async fn accept(
    weak: Weak<BrokerCtx>,
    listener: TcpListener,
    active: Arc<ActivePolicy>,
    identity: watch::Sender<bool>,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(address) = listener.local_addr() else {
        return;
    };
    let mut tasks = JoinSet::new();
    let mut wall = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = tokio::time::sleep_until(active.monotonic_deadline()) => break,
            _ = wall.tick() => {
                if crate::now_ts().map_or(true, |now| active.is_expired(now)) { break; }
                if weak.upgrade().is_none_or(|ctx| !ctx.lifecycle.is_running()) { break; }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { break; };
                if !peer.ip().is_loopback() || tasks.len() >= CONNECTIONS { continue; }
                let weak = weak.clone();
                tasks.spawn(async move {
                    let service = service_fn(move |request| {
                        let weak = weak.clone();
                        async move { Ok::<_, Infallible>(handle(weak, address, request).await) }
                    });
                    let _ = http1::Builder::new().keep_alive(false).max_headers(64).max_buf_size(16*1024)
                        .timer(TokioTimer::new()).header_read_timeout(READ_TIMEOUT)
                        .serve_connection(TokioIo::new(stream), service).await;
                });
            }
        }
    }
    drop(listener);
    // These tasks own only HTTP receivers; admitted effects remain supervised.
    tasks.abort_all();
    if let Some(ctx) = weak.upgrade() {
        ctx.gateway.close_binding(&identity);
    }
}

fn bad_input() -> BrokerError {
    rekey_domain::ipc::FrameError::InvalidField.into()
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, BrokerError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(bad_input());
    }
    first
        .map(|value| value.to_str().map_err(|_| bad_input()))
        .transpose()
}
fn auth(headers: &HeaderMap) -> Result<Zeroizing<String>, BrokerError> {
    let invalid = || BrokerError::Domain(rekey_domain::DomainError::InvalidCapability);
    let bearer = single(headers, "authorization").map_err(|_| invalid())?;
    let key = single(headers, "x-api-key").map_err(|_| invalid())?;
    let wrapped = match (bearer, key) {
        (Some(value), None) => value.strip_prefix("Bearer ").ok_or_else(invalid)?,
        (None, Some(value)) => value,
        _ => return Err(invalid()),
    };
    let token = wrapped.strip_prefix("rkc_").ok_or_else(invalid)?;
    if token.len() != 43
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(invalid());
    }
    Ok(Zeroizing::new(token.to_owned()))
}
type ForwardHeaders = (Option<String>, Vec<(String, String)>);

fn headers_for(
    action: &FixedHttpAction,
    headers: &HeaderMap,
) -> Result<ForwardHeaders, BrokerError> {
    let ActionTarget::Template { fixed_headers, .. } = &action.target else {
        return Err(bad_input());
    };
    for (name, expected) in fixed_headers {
        if single(headers, name.as_str())?.is_some_and(|value| value != expected) {
            return Err(bad_input());
        }
    }
    let content_type = single(headers, "content-type")?;
    let fixed_type = fixed_headers
        .keys()
        .any(|name| name.as_str() == "content-type");
    // MIME and JSON validity belong to the existing canonicalization boundary.
    let extra = action
        .request_policy
        .allowed_extra_headers
        .iter()
        .filter(|name| {
            !matches!(
                name.as_str(),
                "authorization"
                    | "x-api-key"
                    | "x-rekey-approval-challenge"
                    | "host"
                    | "content-type"
            )
        })
        .filter_map(|name| match single(headers, name.as_str()) {
            Ok(None) => None,
            Ok(Some(value)) => Some(Ok((name.as_str().to_owned(), value.to_owned()))),
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        if fixed_type {
            None
        } else {
            content_type.map(str::to_owned)
        },
        extra,
    ))
}
async fn handle(
    weak: Weak<BrokerCtx>,
    address: SocketAddr,
    request: Request<Incoming>,
) -> Response<GatewayBody> {
    let id = match crate::random_id(RequestId::from_random_bytes) {
        Ok(id) => id,
        Err(_) => {
            // No request identity exists: reject before authorization/admission,
            // rather than synthesize a reusable ID or accept without entropy.
            let mut response = Response::new(GatewayBody::full(Vec::new()));
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            return response;
        }
    };
    let result = match weak.upgrade() {
        Some(ctx) => handle_request(&ctx, address, request, id).await,
        None => Err((503, AuthorityError::Draining.into())),
    };
    match result {
        Ok(response) => response,
        Err((status, error)) => error_response(status, id, error),
    }
}
async fn handle_request(
    ctx: &BrokerCtx,
    address: SocketAddr,
    request: Request<Incoming>,
    request_id: RequestId,
) -> Result<Response<GatewayBody>, (u16, BrokerError)> {
    let (parts, mut body) = request.into_parts();
    // Hyper's buffer cap applies when a header is still incomplete. A complete
    // parsed head also needs this fixed bound before any capability admission.
    let head_bytes = parts.method.as_str().len()
        + parts.uri.to_string().len()
        + 16
        + parts
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .sum::<usize>();
    if head_bytes > HEADER_BYTES {
        return Err((431, bad_input()));
    }
    if !ctx.gateway.current(address.port()) {
        return Err((503, AuthorityError::Draining.into()));
    }
    let host = single(&parts.headers, "host").map_err(|e| (400, e))?;
    if host != Some(format!("127.0.0.1:{}", address.port()).as_str())
        && host != Some(format!("localhost:{}", address.port()).as_str())
    {
        return Err((400, bad_input()));
    }
    if parts.headers.contains_key("origin")
        || parts.headers.contains_key("upgrade")
        || parts.method == hyper::Method::CONNECT
        || parts.uri.scheme().is_some()
        || parts.uri.authority().is_some()
        || (parts.headers.contains_key("content-length")
            && parts.headers.contains_key("transfer-encoding"))
        || single(&parts.headers, "content-encoding")
            .map_err(|e| (400, e))?
            .is_some_and(|value| value != "identity")
    {
        return Err((400, bad_input()));
    }
    let token = auth(&parts.headers).map_err(|e| (401, e))?;
    let path = parts.uri.path();
    let query = match parts.uri.query() {
        None => TemplateValues::new(),
        Some("beta=true") => TemplateValues::from([("beta".into(), "true".into())]),
        Some(_) => return Err((404, BrokerError::Denied("gateway-route"))),
    };
    if path.contains(['%', '\\', '#'])
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err((404, BrokerError::Denied("gateway-route")));
    }
    let (instance, path) = path
        .strip_prefix("/p/")
        .and_then(|value| value.split_once('/'))
        .filter(|(instance, _)| !instance.is_empty())
        .ok_or((404, BrokerError::Denied("gateway-route")))?;
    let path = format!("/{path}");
    let deadline = Instant::now() + READ_TIMEOUT;
    let material = ctx
        .profile_material_until(&token, deadline)
        .await
        .map_err(map_error)?;
    let grant = material
        .profile
        .grants
        .iter()
        .find(|grant| {
            grant.instance == instance
                && material
                    .profile
                    .llm_limits
                    .iter()
                    .any(|limit| limit.instance == instance)
        })
        .ok_or((404, BrokerError::Denied("gateway-route")))?;
    let mut matches=material.actions.iter().filter(|action| {
        grant.capabilities.iter().any(|capability|capability.actions.iter().any(|r|r.action_id==action.id&&r.version==action.version))
            && action.method.as_str()==parts.method.as_str()
            && matches!(&action.target,ActionTarget::Template{target,source,..} if source.signer_id.is_none() && matches!(source.template.as_str(),"anthropic@1"|"glm@1"|"openai@1") && target.params().is_empty()
                && (if source.template == "glm@1" { path == "/v1/messages" && target.path_pattern() == "/api/anthropic/v1/messages" } else { target.path_pattern() == path })
                && (query.is_empty() || matches!(target.query().get("beta"),Some(ValueRule::Enum(values)) if values.as_slice()==["true"])))
    });
    let action = matches
        .next()
        .ok_or((404, BrokerError::Denied("gateway-route")))?;
    if matches.next().is_some() {
        return Err((404, BrokerError::Denied("gateway-route")));
    }
    let (content_type, extra_headers) =
        headers_for(action, &parts.headers).map_err(|e| (400, e))?;
    let challenge = single(&parts.headers, "x-rekey-approval-challenge")
        .map_err(|e| (400, e))?
        .map(str::parse::<ApprovalRequestId>)
        .transpose()
        .map_err(|e| (400, e.into()))?;
    let limit = action.request_policy.max_body_bytes as usize;
    if single(&parts.headers, "content-length")
        .map_err(|e| (400, e))?
        .is_some_and(|value| value.parse::<usize>().map_or(true, |n| n > limit))
    {
        return Err((400, rekey_domain::DomainError::RequestTooLarge.into()));
    }
    let mut bytes = Vec::new();
    while let Some(frame) = tokio::time::timeout_at(deadline, body.frame())
        .await
        .map_err(|_| (400, bad_input()))?
    {
        let frame = frame.map_err(|_| (400, bad_input()))?;
        let data = frame.into_data().map_err(|_| (400, bad_input()))?;
        if data.len() > limit.saturating_sub(bytes.len()) {
            return Err((400, rekey_domain::DomainError::RequestTooLarge.into()));
        }
        bytes.extend_from_slice(&data);
    }
    if parts.method == hyper::Method::GET && !bytes.is_empty() {
        return Err((400, bad_input()));
    }
    let result = ctx
        .executions
        .submit_http(ExecuteRequest {
            request_id,
            capability_token: token.to_string(),
            action: ActionVersionRef {
                action_id: action.id,
                version: action.version,
            },
            content_type,
            extra_headers,
            params: Default::default(),
            query,
            body: bytes,
            approval_grants: Vec::new(),
            local_approval_request_id: challenge,
        })
        .await
        .map_err(map_error)?
        .await
        .map_err(|_| (503, AuthorityError::Faulted.into()))?
        .map_err(map_error)?;
    match result {
        HttpExecution::Buffered(outcome) => {
            let mut response = Response::new(GatewayBody::full(outcome.body));
            *response.status_mut() = StatusCode::from_u16(outcome.upstream_status)
                .map_err(|_| (502, BrokerError::Upstream("invalid-status")))?;
            for (name, value) in outcome.headers {
                if matches!(
                    name.as_str(),
                    "connection"
                        | "content-length"
                        | "transfer-encoding"
                        | "content-encoding"
                        | "keep-alive"
                        | "trailer"
                        | "upgrade"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "te"
                ) {
                    continue;
                }
                response.headers_mut().append(
                    HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| (502, BrokerError::Upstream("invalid-header")))?,
                    HeaderValue::from_str(&value)
                        .map_err(|_| (502, BrokerError::Upstream("invalid-header")))?,
                );
            }
            Ok(response)
        }
        HttpExecution::Stream(mut receiver) => loop {
            match receiver.recv().await {
                Some(TextStreamEvent::Admitted { .. }) => {}
                Some(TextStreamEvent::Chunk(first)) => {
                    let mut response = Response::new(GatewayBody::Stream {
                        first: Some(Bytes::from(first)),
                        receiver,
                        ended: false,
                    });
                    response.headers_mut().insert(
                        "content-type",
                        HeaderValue::from_static("text/event-stream; charset=utf-8"),
                    );
                    return Ok(response);
                }
                Some(TextStreamEvent::AdmissionError(error)) => return Err(map_error(error)),
                _ => return Err((502, BrokerError::Upstream("stream-failed"))),
            }
        },
    }
}
fn map_error(error: BrokerError) -> (u16, BrokerError) {
    let status = match &error {
        BrokerError::Domain(
            rekey_domain::DomainError::InvalidCapability
            | rekey_domain::DomainError::CapabilityExpired,
        ) => 401,
        BrokerError::Authority(AuthorityError::PolicyVersionConflict) => 403,
        BrokerError::Authority(_) | BrokerError::Io(_) => 503,
        BrokerError::Frame(_) => 400,
        BrokerError::Upstream(_)
        | BrokerError::Indeterminate(_)
        | BrokerError::ResponseSecurityViolation => 502,
        _ => 403,
    };
    (status, error)
}
fn error_response(status: u16, id: RequestId, error: BrokerError) -> Response<GatewayBody> {
    let envelope = match error {
        BrokerError::ApprovalRequired(approval) => ErrorEnvelope::approval_required(id, approval),
        other => ErrorEnvelope {
            request_id: id,
            code: other.code().to_owned(),
            message: other.agent_message(),
            retryable: other.retryable(),
            approval: None,
        },
    };
    let body = serde_json::to_vec(&envelope).unwrap_or_default();
    let mut response = Response::new(GatewayBody::full(body));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}
enum GatewayBody {
    Full(Option<Bytes>),
    Stream {
        first: Option<Bytes>,
        receiver: mpsc::Receiver<TextStreamEvent>,
        ended: bool,
    },
}
impl GatewayBody {
    fn full(bytes: Vec<u8>) -> Self {
        Self::Full(Some(Bytes::from(bytes)))
    }
}
impl Body for GatewayBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Full(value) => Poll::Ready(value.take().map(|value| Ok(Frame::data(value)))),
            Self::Stream {
                first,
                receiver,
                ended,
            } => {
                if *ended {
                    return Poll::Ready(None);
                }
                if let Some(value) = first.take() {
                    return Poll::Ready(Some(Ok(Frame::data(value))));
                }
                match receiver.poll_recv(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Some(TextStreamEvent::Chunk(value))) => {
                        Poll::Ready(Some(Ok(Frame::data(Bytes::from(value)))))
                    }
                    Poll::Ready(Some(TextStreamEvent::Terminal(
                        TextStreamStatus::Completed | TextStreamStatus::Incomplete,
                    ))) => {
                        *ended = true;
                        Poll::Ready(None)
                    }
                    Poll::Ready(_) => {
                        *ended = true;
                        Poll::Ready(Some(Err(io::Error::other("gateway stream incomplete"))))
                    }
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Full(None) | Self::Stream { ended: true, .. })
    }
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(value) => SizeHint::with_exact(value.as_ref().map_or(0, Bytes::len) as u64),
            Self::Stream { .. } => SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_listener_cleanup_cannot_close_a_reused_port_binding() {
        let gateway = Gateway::default();
        let (old, _) = watch::channel(false);
        let (current, _) = watch::channel(false);
        *gateway.bound.lock().unwrap() = Some(Bound {
            port: 12345,
            policy: [0; 32],
            stop: current.clone(),
        });
        gateway.close_binding(&old);
        assert!(gateway.current(12345));
        gateway.close_binding(&current);
        assert!(!gateway.current(12345));
    }
}
