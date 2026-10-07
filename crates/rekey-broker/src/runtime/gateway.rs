//! Loopback HTTP adapts signed Connection calls; inbound keys are placeholders.
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::future::Future;
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
use rekey_domain::ids::{ApprovalRequestId, RequestId};
use rekey_domain::ipc::{
    ErrorEnvelope, ProfileGatewayEndpoint, ProfileGatewayInstance, ProfileGatewayProvider,
    TextStreamStatus,
};
use rekey_domain::profile::AgentProfile;
use rekey_vault::AuthorityError;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::BrokerCtx;
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;
use crate::execution_supervisor::HttpExecution;
use crate::executor::text_stream::TextStreamEvent;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTIONS: usize = 120;
const HEADER_BYTES: usize = 16 * 1024;

#[derive(Default)]
pub(super) struct Gateway {
    bound: Mutex<Option<Bound>>,
    context: OnceLock<Weak<BrokerCtx>>,
    state_dir: Option<PathBuf>,
    port: Option<u16>,
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
    pub(super) fn new(state_dir: PathBuf, port: Option<u16>) -> Self {
        Self {
            state_dir: Some(state_dir),
            port,
            bound: Mutex::new(None),
            context: OnceLock::new(),
        }
    }
    pub(super) fn attach(&self, ctx: &Arc<BrokerCtx>) {
        let _ = self.context.set(Arc::downgrade(ctx));
    }
    pub(super) fn service_url(&self) -> Option<String> {
        self.bound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|b| format!("http://127.0.0.1:{}", b.port))
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
    fn remove_cache(&self) {}
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
                    "openai@1" | "glm-responses@1" => ProfileGatewayProvider::OpenAi,
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
            writeln!(file, "{{\"port\":{port}}}")?;
            file.sync_all()?;
            fs::rename(&temporary, dir.join("service.json"))?;
            fs::File::open(dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
impl BrokerCtx {
    pub(super) async fn reconcile_gateway(&self) {
        if let Err(error) = self.start_local_service().await {
            tracing::warn!(event = "service.bind_failed", code = error.code());
        }
    }
    pub(super) async fn start_local_service(&self) -> Result<(), BrokerError> {
        let Some(port) = self.gateway.port else {
            return Ok(());
        };
        if self
            .gateway
            .bound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }
        let weak = self
            .gateway
            .context
            .get()
            .cloned()
            .ok_or(BrokerError::Denied("service-context-unavailable"))?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(BrokerError::Io)?;
        let port = listener.local_addr().map_err(BrokerError::Io)?.port();
        self.gateway.publish_cache(port).map_err(BrokerError::Io)?;
        let (stop, stop_rx) = watch::channel(false);
        *self.gateway.bound.lock().unwrap_or_else(|e| e.into_inner()) = Some(Bound {
            port,
            policy: [0; 32],
            stop: stop.clone(),
        });
        tokio::spawn(accept(weak, listener, stop, stop_rx));
        Ok(())
    }
}
async fn accept(
    weak: Weak<BrokerCtx>,
    listener: TcpListener,
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
            _ = wall.tick() => {
                if weak.upgrade().is_none_or(|ctx| ctx.shutdown_requested()) { break; }
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
                        .serve_connection(TokioIo::new(WriteTimeout::new(stream, WRITE_TIMEOUT)), service).await;
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

/// The deadline starts when a socket write stalls, not while waiting for the
/// upstream. Only completed writes/flushes reset it; inbound reads do not.
struct WriteTimeout<T> {
    inner: T,
    timeout: Duration,
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl<T> WriteTimeout<T> {
    fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            stalled: None,
        }
    }
    fn check<U>(
        &mut self,
        cx: &mut Context<'_>,
        result: Poll<io::Result<U>>,
    ) -> Poll<io::Result<U>> {
        match result {
            Poll::Ready(result) => {
                self.stalled = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let timer = self
                    .stalled
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.timeout)));
                if timer.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "gateway client write stalled",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for WriteTimeout<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for WriteTimeout<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.check(cx, result)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.check(cx, result)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.check(cx, result)
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
        || parts.headers.contains_key("sec-fetch-site")
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
    let mut placeholder_present = false;
    for header in ["authorization", "x-api-key"] {
        if let Some(value) = single(&parts.headers, header).map_err(|e| (400, e))? {
            let value = if header == "authorization" {
                value.strip_prefix("Bearer ").unwrap_or(value)
            } else {
                value
            };
            if value != "rekey" {
                return Err((
                    400,
                    BrokerError::LocalCall(
                        "REAL_KEY_PRESENTED",
                        "only the rekey placeholder is accepted",
                        "Use rekey import; never give this program a real key.",
                    ),
                ));
            }
            placeholder_present = true;
        }
    }
    if !placeholder_present {
        return Err((
            400,
            BrokerError::LocalCall(
                "INVALID_INPUT",
                "the public rekey request marker is required",
                "Send Authorization: Bearer rekey or x-api-key: rekey; this is a public placeholder, not a token.",
            ),
        ));
    }
    let (connection, path) = parts
        .uri
        .path()
        .strip_prefix("/c/")
        .and_then(|v| v.split_once('/'))
        .ok_or((404, BrokerError::Denied("service-route")))?;
    let path = format!("/{path}");
    let method = rekey_domain::action::FixedMethod::parse(parts.method.as_str())
        .map_err(|e| (400, e.into()))?;
    let active = ctx
        .policy
        .read()
        .await
        .clone()
        .filter(|p| p.signer_id().is_some())
        .ok_or((
            503,
            BrokerError::Policy(rekey_policy::PolicyError::NotConfigured),
        ))?;
    ctx.lifecycle.reject_if_not_running().map_err(map_error)?;
    let declaration = active
        .snapshot()
        .connections()
        .iter()
        .find(|c| c.enabled && c.name == connection)
        .ok_or((
            404,
            BrokerError::Policy(rekey_policy::PolicyError::NotConfigured),
        ))?;
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes()) {
        if query.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err((400, bad_input()));
        }
    }
    let challenge = single(&parts.headers, "x-rekey-approval-challenge")
        .map_err(|e| (400, e))?
        .map(str::parse::<ApprovalRequestId>)
        .transpose()
        .map_err(|e| (400, e.into()))?;
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        if matches!(
            name.as_str(),
            "host"
                | "authorization"
                | "x-api-key"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "user-agent"
                | "accept"
                | "accept-encoding"
                | "accept-language"
                | "sec-fetch-mode"
                | "x-rekey-approval-challenge"
        ) || name.as_str().starts_with("x-stainless-")
        {
            continue;
        }
        let value = value.to_str().map_err(|_| (400, bad_input()))?;
        if let Some(fixed) = declaration.fixed_headers.get(
            &rekey_domain::action::HeaderName::new(name.as_str()).map_err(|e| (400, e.into()))?,
        ) {
            if fixed != value {
                return Err((400, bad_input()));
            }
            continue;
        }
        headers.push((name.as_str().to_owned(), value.to_owned()));
    }
    let deadline = Instant::now() + READ_TIMEOUT;
    let limit = declaration.limits.max_request_bytes as usize;

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
        .submit_local(crate::executor::LocalExecuteRequest {
            request_id,
            meta: rekey_domain::ipc::CallMeta {
                connection: connection.to_owned(),
                method: Some(method),
                path: Some(path),
                query,
                headers,
                dry_run: false,
                approval_request_id: challenge,
                operation: None,
                args: Default::default(),
            },
            body: Zeroizing::new(bytes),
            caller: "unknown".into(),
        })
        .await
        .map_err(map_error)?
        .await
        .map_err(|_| (503, AuthorityError::Faulted.into()))?
        .map_err(map_error)?;
    match result {
        HttpExecution::Buffered(outcome) => buffered_response(outcome),
        HttpExecution::Stream(mut receiver) => loop {
            match receiver.recv().await {
                Some(TextStreamEvent::Admitted { .. }) => {}
                Some(TextStreamEvent::Buffered(outcome)) => return buffered_response(outcome),
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
fn buffered_response(
    outcome: crate::executor::ExecuteOutcome,
) -> Result<Response<GatewayBody>, (u16, BrokerError)> {
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
            code: crate::ipc::agent::local_agent_code(&other).to_owned(),
            message: other.agent_message(),
            retryable: other.retryable(),
            approval: None,
            next: Some(other.agent_next()),
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn stalled_client_write_times_out_without_waiting_for_upstream_or_reads() {
        let (stream, mut client) = tokio::io::duplex(8);
        let (mut reader, mut writer) = tokio::io::split(WriteTimeout::new(stream, WRITE_TIMEOUT));
        writer.write_all(b"12345678").await.unwrap();
        let started = Instant::now();
        let next = writer.write_all(b"blocked");
        tokio::pin!(next);
        tokio::select! {
            result = &mut next => panic!("write unexpectedly completed: {result:?}"),
            _ = tokio::time::sleep(WRITE_TIMEOUT / 2) => {},
        }
        client.write_all(b"inbound").await.unwrap();
        reader.read_exact(&mut [0; 7]).await.unwrap();
        let error = next.await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), WRITE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn successful_write_resets_deadline_and_upstream_wait_does_not_start_one() {
        let (stream, mut client) = tokio::io::duplex(8);
        let mut writer = WriteTimeout::new(stream, WRITE_TIMEOUT);
        tokio::time::sleep(WRITE_TIMEOUT * 2).await;
        writer.write_all(b"12345678").await.unwrap();
        {
            let next = writer.write_all(b"abcdefgh");
            tokio::pin!(next);
            tokio::select! {
                result = &mut next => panic!("write unexpectedly completed: {result:?}"),
                _ = tokio::time::sleep(WRITE_TIMEOUT / 2) => {},
            }
            client.read_exact(&mut [0; 8]).await.unwrap();
            next.await.unwrap();
        }
        let started = Instant::now();
        assert_eq!(
            writer.write_all(b"blocked").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(started.elapsed(), WRITE_TIMEOUT);
    }
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
