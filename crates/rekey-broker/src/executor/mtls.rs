//! One-shot mTLS with per-poll live policy checks and explicit native ownership.
use super::{
    ActionExecutor, ExecuteOutcome, ExecuteRequest, contains_secret, filter_response_headers,
    headers_contain_secret, response_metadata_fits, sealing_needles, wait_for_cancel,
};
use crate::active_policy::ActivePolicy;
use crate::audit::StartedAuditGuard;
use crate::error::BrokerError;
use crate::lifecycle::Lifecycle;
use crate::upstream::{ResponseHeaders, ScreenedEndpoint, UpstreamError, screen_public_endpoint};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rekey_domain::action::FixedHttpAction;
use rekey_vault::AuthorityError;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use std::future::{Future, poll_fn};
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::task::Poll;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

/// The only TCP owner outlives all borrowed TLS/HTTP protocol owners. Drop
/// closes Both without polling TLS shutdown, which could flush old auth bytes.
struct OwnedTcp {
    stream: Option<TcpStream>,
    #[cfg(test)]
    probe: Option<Arc<TestProbe>>,
}
impl Drop for OwnedTcp {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take()
            && let Ok(stream) = stream.into_std()
        {
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
            #[cfg(test)]
            if let Some(probe) = &self.probe {
                probe.events.lock().unwrap().push("tcp-close");
            }
        }
    }
}

struct Gate<'a> {
    lifecycle: &'a Lifecycle,
    policy: &'a tokio::sync::RwLock<Option<Arc<ActivePolicy>>>,
    digest: [u8; 32],
    deadline: Instant,
    effect: &'a AtomicBool,
    cancel: tokio::sync::watch::Receiver<bool>,
    #[cfg(test)]
    pause: Option<&'a TestPause>,
}
impl Gate<'_> {
    #[cfg(test)]
    async fn pause(&self, stage: TestStage) {
        if let Some(pause) = self.pause
            && pause.stage == stage
        {
            pause.reached.notify_one();
            pause.release.notified().await;
        }
    }
    async fn live(
        &self,
    ) -> Result<
        (
            tokio::sync::MutexGuard<'_, ()>,
            tokio::sync::RwLockReadGuard<'_, Option<Arc<ActivePolicy>>>,
        ),
        BrokerError,
    > {
        let owner = tokio::select! {
            biased;
            _ = wait_for_cancel(self.cancel.clone()) => return Err(BrokerError::Authority(AuthorityError::Draining)),
            _ = wait_for_cancel(self.lifecycle.subscribe_cancel()) => return Err(BrokerError::Authority(AuthorityError::Draining)),
            owner = self.lifecycle.coordinate_until(self.deadline.into()) => owner?,
        };
        self.lifecycle.reject_if_not_running()?;
        if !self.lifecycle.try_begin_remote_effect() || *self.cancel.borrow() {
            return Err(BrokerError::Authority(AuthorityError::Draining));
        }
        let policy = tokio::time::timeout_at(self.deadline.into(), self.policy.read())
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?;
        let now = crate::now_ts()?;
        if policy.as_ref().is_none_or(|p| {
            p.snapshot().digest() != self.digest
                || p.is_expired(now)
                || Instant::now() >= self.deadline
        }) {
            return Err(BrokerError::Denied("policy-changed"));
        }
        Ok((owner, policy))
    }
    async fn call<T>(&self, call: impl FnOnce() -> T) -> Result<T, BrokerError> {
        let _live = self.live().await?;
        Ok(call())
    }
    async fn poll<F: Future>(&self, future: F, effect: bool) -> Result<F::Output, BrokerError> {
        tokio::pin!(future);
        let mut owner = None;
        let run = poll_fn(|cx| {
            if owner.is_none() {
                owner = Some(Box::pin(self.live()));
            }
            let live = match owner.as_mut().expect("queued live gate").as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(live)) => live,
            };
            owner = None;
            if effect {
                self.effect.store(true, Ordering::SeqCst);
            }
            let result = future.as_mut().poll(cx);
            drop(live);
            result.map(Ok)
        });
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(self.deadline.into()) => Err(BrokerError::Upstream("upstream-timeout")),
            _ = wait_for_cancel(self.cancel.clone()) => Err(BrokerError::Authority(AuthorityError::Draining)),
            _ = wait_for_cancel(self.lifecycle.subscribe_cancel()) => Err(BrokerError::Authority(AuthorityError::Draining)),
            result = run => result,
        }
    }
}
fn upstream_error(error: UpstreamError) -> BrokerError {
    match error {
        UpstreamError::Blocked(reason) => BrokerError::Upstream(reason),
        UpstreamError::ResponseTooLarge => rekey_domain::DomainError::ResponseTooLarge.into(),
        UpstreamError::Timeout => BrokerError::Upstream("upstream-timeout"),
        UpstreamError::Transport => BrokerError::Upstream("upstream-transport"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    executor: &ActionExecutor,
    request: &ExecuteRequest,
    action: &FixedHttpAction,
    target: &rekey_domain::template::RenderedTarget,
    started: &mut StartedAuditGuard,
    deadline: Instant,
    effect_kind: &AtomicU8,
    cleanup_owned: &AtomicBool,
) -> Result<ExecuteOutcome, BrokerError> {
    let context = started.context();
    let Some(rekey_domain::audit::RequestAuditContext::Connection(connection)) =
        &context.request_context
    else {
        return Err(BrokerError::Denied("private-binding-invalid"));
    };
    let digest = context
        .authorization
        .as_ref()
        .ok_or(BrokerError::Denied("private-binding-invalid"))?
        .policy_digest;
    let owner = {
        let _coordinate = executor.lifecycle.coordinate_until(deadline.into()).await?;
        executor
            .lifecycle
            .private_credential_owner(action.credential_id, request.request_id)?
    };
    cleanup_owned.store(true, Ordering::SeqCst);
    effect_kind.store(super::EFFECT_REVOCABLE_CONNECTOR, Ordering::SeqCst);
    let effect = started.remote_effect_marker();
    #[cfg(test)]
    let fixture = executor.mtls_fixture.lock().unwrap().clone();
    let gate = Gate {
        #[cfg(test)]
        pause: fixture.as_ref().and_then(|f| f.pause.as_deref()),
        lifecycle: &executor.lifecycle,
        policy: &executor.policy,
        digest,
        deadline,
        effect: &effect,
        cancel: owner.cancel.clone(),
    };
    let started_at = Instant::now();
    let mut credential_version = 0;
    let result = async {
        // Screen and connect before loading the identity; TLS never follows redirects.
        #[cfg(test)]
        let endpoint = match &fixture {
            Some(fixture) => fixture.endpoint.clone(),
            None => gate
                .poll(
                    screen_public_endpoint(action.origin.host(), action.origin.port()),
                    false,
                )
                .await?
                .map_err(upstream_error)?,
        };
        #[cfg(not(test))]
        let endpoint = gate
            .poll(
                screen_public_endpoint(action.origin.host(), action.origin.port()),
                false,
            )
            .await?
            .map_err(upstream_error)?;
        let stream = gate
            .poll(TcpStream::connect(endpoint.addr), false)
            .await?
            .map_err(|_| BrokerError::Upstream("upstream-transport"))?;
        let mut tcp = OwnedTcp {
            stream: Some(stream),
            #[cfg(test)]
            probe: fixture.as_ref().map(|f| Arc::clone(&f.probe)),
        };
        let prepared = {
            let _live = gate.live().await?;
            tokio::time::timeout_at(
                deadline.into(),
                executor.authority.prepare_mtls_connection(
                    request.request_id,
                    connection.connection.clone(),
                    digest,
                    deadline,
                ),
            )
            .await
            .map_err(|_| BrokerError::Upstream("upstream-timeout"))??
        };
        credential_version = prepared.version();
        let (config, needles) = gate
            .call(|| {
                prepared.consume_mtls(|raw, material| {
                    let needles = sealing_needles(raw, material.private_key.secret_der());
                    let signer =
                        rustls::crypto::aws_lc_rs::sign::any_supported_type(&material.private_key)
                            .map_err(|_| BrokerError::Upstream("upstream-transport"))?;
                    #[cfg(test)]
                    let signer: Arc<dyn rustls::sign::SigningKey> = match &fixture {
                        Some(fixture) => Arc::new(ObservedKey {
                            inner: signer,
                            probe: Arc::clone(&fixture.probe),
                            lifecycle: Arc::clone(&executor.lifecycle),
                        }),
                        None => signer,
                    };
                    let identity = CertifiedKey::new(material.certificates, signer);
                    let roots = rustls::RootCertStore {
                        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                    };
                    #[cfg(test)]
                    let roots = match &fixture {
                        Some(fixture) => {
                            let mut roots = rustls::RootCertStore::empty();
                            roots
                                .add(fixture.ca.clone())
                                .map_err(|_| BrokerError::Upstream("upstream-transport"))?;
                            roots
                        }
                        None => roots,
                    };
                    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .map_err(|_| BrokerError::Upstream("upstream-transport"))?
                    .with_root_certificates(roots)
                    .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(identity)));
                    config.alpn_protocols = vec![b"http/1.1".to_vec()];
                    config.resumption = Resumption::disabled();
                    config.enable_early_data = false;
                    Ok::<_, BrokerError>((config, needles))
                })
            })
            .await???;
        #[cfg(test)]
        gate.pause(TestStage::Prepared).await;
        execute(
            &gate,
            tcp.stream.as_mut().expect("owned TCP"),
            endpoint,
            config,
            &needles,
            action,
            request,
            target,
        )
        .await
        // All HTTP/TLS/signing owners drop here before OwnedTcp closes Both.
    }
    .await;
    drop(owner);
    if effect.load(Ordering::SeqCst) {
        started.mark_remote_effect_started();
    }
    match result {
        Ok(outcome) => {
            started
                .finished_until(
                    deadline,
                    credential_version,
                    outcome.upstream_status,
                    started_at.elapsed().as_millis() as i64,
                )
                .await?;
            Ok(outcome)
        }
        Err(error) => {
            if effect.load(Ordering::SeqCst) {
                started.submit_indeterminate("private-execution-failed");
            } else {
                started.submit_blocked("private-execution-failed");
            }
            Err(match error {
                BrokerError::Upstream(reason) if effect.load(Ordering::SeqCst) => {
                    BrokerError::UpstreamUnconfirmed(reason)
                }
                error => error,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    gate: &Gate<'_>,
    tcp: &mut TcpStream,
    endpoint: ScreenedEndpoint,
    config: rustls::ClientConfig,
    needles: &[Zeroizing<Vec<u8>>],
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    target: &rekey_domain::template::RenderedTarget,
) -> Result<ExecuteOutcome, BrokerError> {
    let name = ServerName::try_from(endpoint.host)
        .map_err(|_| BrokerError::Upstream("upstream-transport"))?;
    let connector = TlsConnector::from(Arc::new(config));
    // connect construction and every TLS poll/sign stay inside the live gate.
    let connect = gate.call(|| connector.connect(name, tcp)).await?;
    #[cfg(test)]
    gate.pause(TestStage::TlsConstructed).await;
    let tls = gate
        .poll(connect, true)
        .await?
        .map_err(|_| BrokerError::Upstream("upstream-transport"))?;
    let handshake = gate
        .call(|| http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls)))
        .await?;
    let (mut sender, mut connection) = gate
        .poll(handshake, false)
        .await?
        .map_err(|_| BrokerError::Upstream("upstream-transport"))?;
    let host = if action.origin.port() == 443 {
        action.origin.host().to_owned()
    } else {
        format!("{}:{}", action.origin.host(), action.origin.port())
    };
    let mut builder = hyper::Request::builder()
        .method(action.method.as_str())
        .uri(target.request_target())
        .header("host", host)
        .header("connection", "close");
    if let Some(content_type) = &request.content_type {
        builder = builder.header("content-type", content_type);
    }
    for (name, value) in &request.extra_headers {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Full::new(Bytes::copy_from_slice(&request.body)))
        .map_err(|_| BrokerError::Denied("invalid-header"))?;
    #[cfg(test)]
    gate.pause(TestStage::Enqueue).await;
    let response = gate.call(|| sender.send_request(request)).await?;
    tokio::pin!(response);
    let mut driver_done = false;
    let mut driver_failed = false;
    let response = gate
        .poll(
            poll_fn(|cx| {
                if !driver_done && let Poll::Ready(result) = connection.poll_without_shutdown(cx) {
                    driver_done = true;
                    driver_failed = result.is_err();
                }
                match response.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        Poll::Ready(result.map_err(|_| BrokerError::Upstream("upstream-transport")))
                    }
                    Poll::Pending if driver_done => {
                        Poll::Ready(Err(BrokerError::Upstream("upstream-transport")))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }),
            false,
        )
        .await??;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(BrokerError::Upstream("redirect"));
    }
    let headers = ResponseHeaders::from_header_map(response.headers());
    if headers_contain_secret(&headers, needles) {
        return Err(BrokerError::ResponseSecurityViolation);
    }
    let mut incoming = response.into_body();
    #[cfg(test)]
    gate.pause(TestStage::Body).await;
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let frame = incoming.frame();
        tokio::pin!(frame);
        let next = gate
            .poll(
                poll_fn(|cx| {
                    if !driver_done
                        && let Poll::Ready(result) = connection.poll_without_shutdown(cx)
                    {
                        driver_done = true;
                        driver_failed = result.is_err();
                    }
                    match frame.as_mut().poll(cx) {
                        Poll::Ready(result) => Poll::Ready(Ok(result)),
                        Poll::Pending if driver_done => {
                            Poll::Ready(Err(BrokerError::Upstream("upstream-transport")))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                }),
                false,
            )
            .await??;
        let Some(frame) = next else {
            break;
        };
        let frame = frame.map_err(|_| BrokerError::Upstream("upstream-transport"))?;
        if let Some(data) = frame.data_ref() {
            if body.len().saturating_add(data.len())
                > action.response_policy.max_body_bytes as usize
            {
                return Err(rekey_domain::DomainError::ResponseTooLarge.into());
            }
            body.extend_from_slice(data);
        }
        if let Some(trailers) = frame.trailers_ref()
            && trailers.iter().any(|(name, value)| {
                contains_secret(name.as_str().as_bytes(), needles)
                    || contains_secret(value.as_bytes(), needles)
            })
        {
            return Err(BrokerError::ResponseSecurityViolation);
        }
    }
    if driver_failed {
        return Err(BrokerError::Upstream("upstream-transport"));
    }
    if contains_secret(&body, needles) {
        return Err(BrokerError::ResponseSecurityViolation);
    }
    let headers = filter_response_headers(action, &headers);
    if !response_metadata_fits(status, &headers, body.len()) {
        return Err(rekey_domain::DomainError::ResponseTooLarge.into());
    }
    Ok(ExecuteOutcome {
        stream_status: None,
        upstream_status: status,
        headers,
        body: std::mem::take(&mut *body),
    })
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TestStage {
    Prepared,
    TlsConstructed,
    Enqueue,
    Body,
}
#[cfg(test)]
struct TestPause {
    stage: TestStage,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[cfg(test)]
#[derive(Default)]
struct TestProbe {
    signs: std::sync::atomic::AtomicUsize,
    panic_sign: AtomicBool,
    events: std::sync::Mutex<Vec<&'static str>>,
}
#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestFixture {
    endpoint: ScreenedEndpoint,
    ca: rustls::pki_types::CertificateDer<'static>,
    pause: Option<Arc<TestPause>>,
    probe: Arc<TestProbe>,
}
#[cfg(test)]
struct ObservedKey {
    inner: Arc<dyn rustls::sign::SigningKey>,
    probe: Arc<TestProbe>,
    lifecycle: Arc<Lifecycle>,
}
#[cfg(test)]
impl std::fmt::Debug for ObservedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservedKey([REDACTED])")
    }
}
#[cfg(test)]
impl Drop for ObservedKey {
    fn drop(&mut self) {
        self.probe.events.lock().unwrap().push("key-drop");
    }
}
#[cfg(test)]
impl rustls::sign::SigningKey for ObservedKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.inner.choose_scheme(offered).map(|inner| {
            Box::new(ObservedSigner {
                inner,
                probe: Arc::clone(&self.probe),
                lifecycle: Arc::clone(&self.lifecycle),
            }) as Box<dyn rustls::sign::Signer>
        })
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}
#[cfg(test)]
struct ObservedSigner {
    inner: Box<dyn rustls::sign::Signer>,
    probe: Arc<TestProbe>,
    lifecycle: Arc<Lifecycle>,
}
#[cfg(test)]
impl std::fmt::Debug for ObservedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservedSigner([REDACTED])")
    }
}
#[cfg(test)]
impl rustls::sign::Signer for ObservedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        assert!(
            self.lifecycle.try_coordinate().is_err(),
            "TLS signing escaped its live coordinator gate"
        );
        self.probe.signs.fetch_add(1, Ordering::SeqCst);
        if self.probe.panic_sign.load(Ordering::SeqCst) {
            panic!("synthetic TLS signing panic");
        }
        self.inner.sign(message)
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        self.inner.scheme()
    }
}

#[cfg(test)]
mod tests;
