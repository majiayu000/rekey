//! Upstream HTTPS transport. Fixed origin only, redirects disabled, proxy
//! environment ignored, DNS results screened before connecting.

use serde::{Deserialize, Deserializer};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rekey_domain::action::FixedMethod;
use zeroize::{Zeroize, Zeroizing};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct UpstreamRequest {
    pub host: String,
    pub port: u16,
    pub method: FixedMethod,
    pub path: String,
    /// Plain headers (content-type, allowlisted extra headers).
    pub headers: Vec<(String, String)>,
    /// The single credential header: name and full value bytes.
    pub auth_header: (String, Zeroizing<Vec<u8>>),
    /// Request body bytes. Lease IDs and other secret-bearing payloads stay
    /// wipe-on-drop until the transport copies them.
    pub body: Zeroizing<Vec<u8>>,
    pub timeout: Duration,
    pub response_max_bytes: u32,
}

impl Drop for UpstreamRequest {
    fn drop(&mut self) {
        for (name, value) in &mut self.headers {
            name.zeroize();
            value.zeroize();
        }
    }
}

pub struct UpstreamResponse {
    pub status: u16,
    pub headers: ResponseHeaders,
    pub body: Zeroizing<Vec<u8>>,
}

/// Rekey-owned copies of upstream headers remain wipe-on-drop until response
/// sealing has proved that an allowlisted value is safe to materialize.
pub struct ResponseHeaders {
    visible: Vec<(String, String)>,
    unsupported: Vec<(String, Zeroizing<Vec<u8>>)>,
}

impl From<Vec<(String, String)>> for ResponseHeaders {
    fn from(headers: Vec<(String, String)>) -> Self {
        Self {
            visible: headers,
            unsupported: Vec::new(),
        }
    }
}

impl ResponseHeaders {
    pub(crate) fn from_header_map(headers: &reqwest::header::HeaderMap) -> Self {
        let mut visible = Vec::with_capacity(headers.len());
        let mut unsupported = Vec::new();
        for (name, value) in headers {
            match std::str::from_utf8(value.as_bytes()) {
                Ok(value) => visible.push((name.as_str().to_owned(), value.to_owned())),
                Err(_) => unsupported.push((
                    name.as_str().to_owned(),
                    Zeroizing::new(value.as_bytes().to_vec()),
                )),
            }
        }
        Self {
            visible,
            unsupported,
        }
    }

    /// Full name/value bytes for sealing, before the String wire projection.
    pub(crate) fn name_value_bytes(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.visible
            .iter()
            .map(|(name, value)| (name.as_bytes(), value.as_bytes()))
            .chain(
                self.unsupported
                    .iter()
                    .map(|(name, value)| (name.as_bytes(), value.as_slice())),
            )
    }
}

impl std::ops::Deref for ResponseHeaders {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.visible
    }
}

impl Drop for ResponseHeaders {
    fn drop(&mut self) {
        for (name, value) in &mut self.visible {
            name.zeroize();
            value.zeroize();
        }
        for (name, _) in &mut self.unsupported {
            name.zeroize();
        }
        // Unsupported values are Zeroizing buffers and wipe on field drop.
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UpstreamError {
    #[error("upstream target blocked: {0}")]
    Blocked(&'static str),
    #[error("upstream response exceeds size limit")]
    ResponseTooLarge,
    #[error("upstream transport failure")]
    Transport,
    #[error("upstream timeout")]
    Timeout,
}

pub type UpstreamFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UpstreamResponse, UpstreamError>> + Send + 'a>>;

pub type UpstreamChunkFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Zeroizing<Vec<u8>>>, UpstreamError>> + Send + 'a>>;
pub trait UpstreamBody: Send {
    fn next_chunk(&mut self) -> UpstreamChunkFuture<'_>;
}
pub struct UpstreamStreamResponse {
    pub status: u16,
    pub headers: ResponseHeaders,
    pub body: Box<dyn UpstreamBody>,
}
pub type UpstreamStreamFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UpstreamStreamResponse, UpstreamError>> + Send + 'a>>;

/// Closed, encrypted-profile binding for this Vault source only.
#[derive(Clone)]
pub struct SourceEndpoint {
    allowed_ips: Vec<IpAddr>,
    ca_der: Vec<Vec<u8>>,
}

impl<'de> Deserialize<'de> for SourceEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            allowed_ips: Vec<String>,
            ca_der_base64: Vec<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let invalid = || serde::de::Error::custom("invalid source endpoint");
        if raw.allowed_ips.is_empty() || raw.ca_der_base64.is_empty() {
            return Err(invalid());
        }
        let mut allowed_ips = Vec::new();
        for literal in raw.allowed_ips {
            let ip: IpAddr = literal.parse().map_err(|_| invalid())?;
            if !source_ip_is_private(ip) || allowed_ips.contains(&ip) {
                return Err(invalid());
            }
            allowed_ips.push(ip);
        }
        let mut ca_der = Vec::new();
        for encoded in raw.ca_der_base64 {
            let der = data_encoding::BASE64
                .decode(encoded.as_bytes())
                .map_err(|_| invalid())?;
            let cert = reqwest::Certificate::from_der(&der).map_err(|_| invalid())?;
            // Building the fixed-root client also validates the certificate's TLS trust syntax.
            reqwest::Client::builder()
                .use_rustls_tls()
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert)
                .build()
                .map_err(|_| invalid())?;
            if ca_der.contains(&der) {
                return Err(invalid());
            }
            ca_der.push(der);
        }
        Ok(Self {
            allowed_ips,
            ca_der,
        })
    }
}

#[cfg(feature = "lab")]
pub(crate) fn optional_source_endpoint<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<SourceEndpoint>, D::Error> {
    SourceEndpoint::deserialize(d).map(Some)
}

pub fn source_ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.segments()[0] & 0xfe00 == 0xfc00,
    }
}

#[cfg(feature = "lab")]
pub(crate) fn source_hostname_valid(host: &str) -> bool {
    host.parse::<IpAddr>().is_err()
        && host.len() <= 253
        && host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub fn select_source_endpoint(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    binding: &SourceEndpoint,
) -> Result<ScreenedEndpoint, UpstreamError> {
    if addrs.is_empty() {
        return Err(UpstreamError::Transport);
    }
    if addrs
        .iter()
        .any(|addr| addr.port() != port || !binding.allowed_ips.contains(&addr.ip()))
    {
        return Err(UpstreamError::Blocked("source-address"));
    }
    Ok(ScreenedEndpoint {
        host: host.to_owned(),
        addr: addrs[0],
    })
}

#[derive(Clone, Debug)]
pub struct SourceAttempt {
    pub selected_ip: Option<IpAddr>,
    pub phase: &'static str,
    pub outcome: &'static str,
}
impl Default for SourceAttempt {
    fn default() -> Self {
        Self {
            selected_ip: None,
            phase: "resolve",
            outcome: "unknown",
        }
    }
}
pub type SourceTrace = Arc<Mutex<SourceAttempt>>;

/// Only encrypted Vault source profiles may invoke this entry.
#[cfg(feature = "lab")]
pub(crate) fn send_source<'a>(
    transport: &'a dyn UpstreamTransport,
    request: UpstreamRequest,
    binding: Option<&'a SourceEndpoint>,
    deadline: std::time::Instant,
) -> UpstreamFuture<'a> {
    Box::pin(async move {
        if std::time::Instant::now() >= deadline {
            return Err(UpstreamError::Timeout);
        }
        let result = match binding {
            Some(binding) => {
                transport
                    .send_vault_source(
                        request,
                        binding,
                        deadline,
                        Arc::new(Mutex::new(SourceAttempt::default())),
                    )
                    .await
            }
            None => transport.send(request).await,
        };
        if std::time::Instant::now() >= deadline {
            return Err(UpstreamError::Timeout);
        }
        result
    })
}

pub trait UpstreamTransport: Send + Sync {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_>;
    fn send_vault_source<'a>(
        &'a self,
        _request: UpstreamRequest,
        _binding: &'a SourceEndpoint,
        _deadline: std::time::Instant,
        trace: SourceTrace,
    ) -> UpstreamFuture<'a> {
        Box::pin(async move {
            *trace.lock().unwrap() = SourceAttempt {
                selected_ip: None,
                phase: "unsupported",
                outcome: "denied",
            };
            Err(UpstreamError::Blocked("source-transport-unsupported"))
        })
    }
    fn open_stream(&self, _request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        Box::pin(async { Err(UpstreamError::Blocked("streaming-unsupported")) })
    }
}

/// Validate the complete request, including credential bytes, before the
/// executor crosses the remote-effect admission gate.
pub fn outbound_headers_are_valid(request: &UpstreamRequest) -> bool {
    request.headers.iter().all(|(name, value)| {
        reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
            && reqwest::header::HeaderValue::from_bytes(value.as_bytes()).is_ok()
    }) && reqwest::header::HeaderName::from_bytes(request.auth_header.0.as_bytes()).is_ok()
        && reqwest::header::HeaderValue::from_bytes(&request.auth_header.1).is_ok()
}

pub use rekey_domain::action::ip_is_public;

pub struct ReqwestUpstreamTransport;

impl UpstreamTransport for ReqwestUpstreamTransport {
    fn send_vault_source<'a>(
        &'a self,
        mut request: UpstreamRequest,
        binding: &'a SourceEndpoint,
        deadline: std::time::Instant,
        trace: SourceTrace,
    ) -> UpstreamFuture<'a> {
        Box::pin(async move {
            let result = async {
                if std::time::Instant::now() >= deadline {
                    return Err(UpstreamError::Timeout);
                }
                let addrs = tokio::time::timeout_at(
                    deadline.into(),
                    tokio::net::lookup_host((request.host.as_str(), request.port)),
                )
                .await
                .map_err(|_| UpstreamError::Timeout)?
                .map_err(|_| UpstreamError::Transport)?
                .collect::<Vec<_>>();
                if std::time::Instant::now() >= deadline {
                    return Err(UpstreamError::Timeout);
                }
                let endpoint =
                    select_source_endpoint(&request.host, request.port, &addrs, binding)?;
                *trace.lock().unwrap() = SourceAttempt {
                    selected_ip: Some(endpoint.addr.ip()),
                    phase: "connect",
                    outcome: "unknown",
                };
                request.timeout = deadline.saturating_duration_since(std::time::Instant::now());
                let response = tokio::time::timeout_at(deadline.into(), async {
                    let mut stream =
                        open_stream_fixed_roots(request, endpoint, Some(&binding.ca_der), true)
                            .await?;
                    trace.lock().unwrap().phase = "response";
                    let mut body = Zeroizing::new(Vec::new());
                    while let Some(chunk) = stream.body.next_chunk().await? {
                        body.extend_from_slice(&chunk);
                    }
                    Ok(UpstreamResponse {
                        status: stream.status,
                        headers: stream.headers,
                        body,
                    })
                })
                .await
                .map_err(|_| UpstreamError::Timeout)?;
                if std::time::Instant::now() >= deadline {
                    return Err(UpstreamError::Timeout);
                }
                response
            }
            .await;
            trace.lock().unwrap().outcome = match &result {
                Ok(_) => "success",
                Err(UpstreamError::Blocked(_)) => "denied",
                Err(_) => "unknown",
            };
            result
        })
    }
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move { send_via_reqwest(request).await })
    }
    fn open_stream(&self, mut request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + request.timeout;
            let endpoint = resolve_before_deadline(
                deadline,
                screen_public_endpoint(&request.host, request.port),
            )
            .await?;
            request.timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
            if request.timeout.is_zero() {
                return Err(UpstreamError::Timeout);
            }
            open_stream_screened(request, endpoint, None).await
        })
    }
}

/// DNS result that has already passed public-IP screening.
#[derive(Clone, Debug)]
pub struct ScreenedEndpoint {
    pub host: String,
    pub addr: SocketAddr,
}

/// Layer 1: resolve and refuse any private/special address.
pub async fn screen_public_endpoint(
    host: &str,
    port: u16,
) -> Result<ScreenedEndpoint, UpstreamError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| UpstreamError::Transport)?
        .collect();
    select_public_endpoint(host, &addrs)
}

/// Screen already-resolved addresses. Fixtures may run this on a public
/// placeholder, then replace `addr` with a post-screen local inject.
pub fn select_public_endpoint(
    host: &str,
    addrs: &[SocketAddr],
) -> Result<ScreenedEndpoint, UpstreamError> {
    if addrs.is_empty() {
        return Err(UpstreamError::Transport);
    }
    // Every resolved address must be public; a mixed answer is treated as a
    // rebinding attempt and refused outright.
    if addrs.iter().any(|a| !ip_is_public(a.ip())) {
        return Err(UpstreamError::Blocked("private-address"));
    }
    Ok(ScreenedEndpoint {
        host: host.to_owned(),
        addr: addrs[0],
    })
}

async fn send_via_reqwest(mut request: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
    let deadline = tokio::time::Instant::now() + request.timeout;
    let endpoint = resolve_before_deadline(
        deadline,
        screen_public_endpoint(&request.host, request.port),
    )
    .await?;
    request.timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
    if request.timeout.is_zero() {
        return Err(UpstreamError::Timeout);
    }
    send_screened(request, endpoint, None).await
}

async fn resolve_before_deadline<F>(
    deadline: tokio::time::Instant,
    resolution: F,
) -> Result<ScreenedEndpoint, UpstreamError>
where
    F: Future<Output = Result<ScreenedEndpoint, UpstreamError>>,
{
    tokio::time::timeout_at(deadline, resolution)
        .await
        .map_err(|_| UpstreamError::Timeout)?
}

/// Layer 2: TLS, SNI, redirect-none, DNS pin, bounded body.
/// `extra_root_der` is a test-only CA; production always passes `None`.
pub async fn send_screened(
    request: UpstreamRequest,
    endpoint: ScreenedEndpoint,
    extra_root_der: Option<&[u8]>,
) -> Result<UpstreamResponse, UpstreamError> {
    let limit = request.response_max_bytes as usize;
    let mut response = open_stream_screened(request, endpoint, extra_root_der).await?;
    let mut body = Zeroizing::new(Vec::with_capacity(limit));
    while let Some(chunk) = response.body.next_chunk().await? {
        body.extend_from_slice(&chunk);
    }
    Ok(UpstreamResponse {
        status: response.status,
        headers: response.headers,
        body,
    })
}

/// Same screened TLS request as buffered transport; exposes real arriving chunks.
pub async fn open_stream_screened(
    request: UpstreamRequest,
    endpoint: ScreenedEndpoint,
    extra_root_der: Option<&[u8]>,
) -> Result<UpstreamStreamResponse, UpstreamError> {
    let roots = extra_root_der.map(|der| vec![der.to_vec()]);
    open_stream_fixed_roots(request, endpoint, roots.as_deref(), false).await
}

async fn open_stream_fixed_roots(
    request: UpstreamRequest,
    endpoint: ScreenedEndpoint,
    fixed_roots: Option<&[Vec<u8>]>,
    private_only: bool,
) -> Result<UpstreamStreamResponse, UpstreamError> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(request.timeout)
        .resolve(&endpoint.host, endpoint.addr);
    if let Some(roots) = fixed_roots {
        builder = builder.http1_only();
        if private_only {
            builder = builder
                .tls_built_in_root_certs(false)
                .retry(reqwest::retry::never());
        }
        for der in roots {
            let cert = reqwest::Certificate::from_der(der).map_err(|_| UpstreamError::Transport)?;
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build().map_err(|_| UpstreamError::Transport)?;

    let url = if request.port == 443 {
        format!("https://{}{}", request.host, request.path)
    } else {
        format!("https://{}:{}{}", request.host, request.port, request.path)
    };
    let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())
        .map_err(|_| UpstreamError::Transport)?;

    let mut req = client.request(method, url);
    for (name, value) in &request.headers {
        let mut header = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| UpstreamError::Transport)?;
        if name == "x-amz-security-token" {
            header.set_sensitive(true);
        }
        req = req.header(name, header);
    }
    let (auth_name, auth_value) = &request.auth_header;
    let mut header_value = reqwest::header::HeaderValue::from_bytes(auth_value)
        .map_err(|_| UpstreamError::Transport)?;
    header_value.set_sensitive(true);
    req = req.header(auth_name, header_value);
    if !request.body.is_empty() {
        req = req.body(request.body.to_vec());
    }

    let response = req.send().await.map_err(|err| {
        if err.is_timeout() {
            UpstreamError::Timeout
        } else if err.is_redirect() {
            UpstreamError::Blocked("redirect")
        } else {
            UpstreamError::Transport
        }
    })?;

    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(UpstreamError::Blocked("redirect"));
    }
    let headers = ResponseHeaders::from_header_map(response.headers());

    Ok(UpstreamStreamResponse {
        status,
        headers,
        body: Box::new(ReqwestBody {
            response,
            remaining: request.response_max_bytes as usize,
        }),
    })
}

struct ReqwestBody {
    response: reqwest::Response,
    remaining: usize,
}
impl UpstreamBody for ReqwestBody {
    fn next_chunk(&mut self) -> UpstreamChunkFuture<'_> {
        Box::pin(async move {
            let Some(chunk) = self.response.chunk().await.map_err(|err| {
                if err.is_timeout() {
                    UpstreamError::Timeout
                } else {
                    UpstreamError::Transport
                }
            })?
            else {
                return Ok(None);
            };
            self.remaining = self
                .remaining
                .checked_sub(chunk.len())
                .ok_or(UpstreamError::ResponseTooLarge)?;
            Ok(Some(Zeroizing::new(chunk.to_vec())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::action::FixedMethod;
    use std::net::IpAddr;

    fn loopback_request(host: &str) -> UpstreamRequest {
        UpstreamRequest {
            host: host.to_owned(),
            port: 443,
            method: FixedMethod::Get,
            path: "/".to_owned(),
            headers: vec![],
            auth_header: (
                "authorization".to_owned(),
                Zeroizing::new(b"Bearer test".to_vec()),
            ),
            body: Zeroizing::new(Vec::new()),
            timeout: Duration::from_secs(5),
            response_max_bytes: 1024,
        }
    }

    fn private_binding() -> SourceEndpoint {
        let cert = rcgen::generate_simple_self_signed(vec!["vault.example.com".into()])
            .unwrap()
            .cert;
        serde_json::from_value(serde_json::json!({"allowed_ips":["10.1.2.3","fd12::1"],"ca_der_base64":[data_encoding::BASE64.encode(cert.der())]})).unwrap()
    }

    #[test]
    fn private_dns_requires_every_exact_ip_and_port_without_fallback() {
        let binding = private_binding();
        let good = [
            "10.1.2.3:8200".parse().unwrap(),
            "[fd12::1]:8200".parse().unwrap(),
        ];
        let selected = select_source_endpoint("vault.example.com", 8200, &good, &binding).unwrap();
        assert_eq!(selected.addr, good[0]);
        assert_eq!(selected.host, "vault.example.com");
        for bad in [
            "10.1.2.4:8200",
            "10.1.2.3:443",
            "93.184.216.34:8200",
            "127.0.0.1:8200",
            "[::ffff:10.1.2.3]:8200",
            "[64:ff9b::a01:203]:8200",
            "[2002:a01:203::1]:8200",
        ] {
            assert!(
                select_source_endpoint(
                    "vault.example.com",
                    8200,
                    &[good[0], bad.parse().unwrap()],
                    &binding
                )
                .is_err(),
                "{bad}"
            );
        }
        assert!(select_source_endpoint("vault.example.com", 8200, &[], &binding).is_err());
        assert!(select_public_endpoint("vault.example.com", &good).is_err());
    }

    #[tokio::test]
    async fn private_deadline_late_first_poll_never_resolves_or_selects_an_ip() {
        let binding = private_binding();
        let trace = Arc::new(Mutex::new(SourceAttempt::default()));
        let transport = ReqwestUpstreamTransport;
        let end = std::time::Instant::now() + Duration::from_millis(5);
        let future = transport.send_vault_source(
            loopback_request("vault.example.com"),
            &binding,
            end,
            trace.clone(),
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(matches!(future.await, Err(UpstreamError::Timeout)));
        assert_eq!(trace.lock().unwrap().selected_ip, None);
        assert_eq!(trace.lock().unwrap().outcome, "unknown");
    }

    // Compiled/listed only on the current host, which rejects listeners. The
    // loopback pin is confined to this fixture, never the bound-source entry.
    #[tokio::test]
    async fn strict_tls_source_fixed_ca_hostname_redirect_and_public_target_boundary_fixture() {
        if std::env::var_os("REKEY_SOURCE_TLS_FIXTURE_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "upstream::tests::strict_tls_source_fixed_ca_hostname_redirect_and_public_target_boundary_fixture", "--nocapture"])
                .env("REKEY_SOURCE_TLS_FIXTURE_CHILD", "1")
                .env("HTTPS_PROXY", "http://127.0.0.1:1")
                .env("ALL_PROXY", "http://127.0.0.1:1")
                .env("NO_PROXY", "")
                .output().unwrap();
            assert!(
                output.status.success(),
                "strict TLS child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (wrong_ca, wrong_hostname, redirect) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let generated =
                rcgen::generate_simple_self_signed(vec!["vault.example.com".into()]).unwrap();
            let der = generated.cert.der().to_vec();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der())),
            )
            .unwrap();
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                    .accept(socket)
                    .await
                {
                    let mut buf = [0; 4096];
                    let _ = stream.read(&mut buf).await;
                    let bytes = if redirect {
                        b"HTTP/1.1 302 Found\r\nLocation: https://10.1.2.3/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            .as_slice()
                    };
                    let _ = stream.write_all(bytes).await;
                }
            });
            let roots = if wrong_ca {
                vec![
                    rcgen::generate_simple_self_signed(vec!["vault.example.com".into()])
                        .unwrap()
                        .cert
                        .der()
                        .to_vec(),
                ]
            } else {
                vec![der]
            };
            let host = if wrong_hostname {
                "other.example.com"
            } else {
                "vault.example.com"
            };
            let mut request = loopback_request(host);
            request.port = addr.port();
            let result = open_stream_fixed_roots(
                request,
                ScreenedEndpoint {
                    host: host.into(),
                    addr,
                },
                Some(&roots),
                true,
            )
            .await;
            assert_eq!(result.is_ok(), !wrong_ca && !wrong_hostname && !redirect);
            if redirect {
                assert!(matches!(result, Err(UpstreamError::Blocked("redirect"))));
            }
            server.await.unwrap();
            assert!(select_public_endpoint(host, &[addr]).is_err());
        }
    }

    #[test]
    fn response_header_map_preserves_utf8_and_unsupported_bytes_once() {
        let utf8 = "Bearer header-中文-fixture".as_bytes();
        let unsupported = [b"\xffprefix-".as_slice(), utf8, b"-suffix\xfe"].concat();
        let mut map = reqwest::header::HeaderMap::new();
        let utf8_value = reqwest::header::HeaderValue::from_bytes(utf8).unwrap();
        assert!(
            utf8_value.to_str().is_err(),
            "exercise the former ASCII-only boundary"
        );
        map.append("x-utf8", utf8_value);
        map.append(
            "x-unsupported",
            reqwest::header::HeaderValue::from_bytes(&unsupported).unwrap(),
        );
        map.append(
            "content-type",
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let headers = ResponseHeaders::from_header_map(&map);
        assert_eq!(headers.visible.len(), 2);
        assert_eq!(headers.unsupported.len(), 1);
        assert_eq!(headers.name_value_bytes().count(), map.len());
        assert!(
            headers
                .name_value_bytes()
                .any(|(name, value)| name == b"x-utf8" && value == utf8)
        );
        assert!(
            headers
                .name_value_bytes()
                .any(|(name, value)| name == b"x-unsupported" && value == unsupported)
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == "x-utf8" && value.as_bytes() == utf8)
        );
        assert!(!headers.iter().any(|(name, _)| name == "x-unsupported"));
    }
    #[test]
    fn clean_nonutf8_response_headers_are_retained_for_sealing_and_omitted_from_string_projection()
    {
        let mut map = reqwest::header::HeaderMap::new();
        map.append(
            "content-type",
            reqwest::header::HeaderValue::from_bytes(b"\xffclean\xfe").unwrap(),
        );
        let headers = ResponseHeaders::from_header_map(&map);
        assert!(headers.is_empty());
        let all: Vec<_> = headers.name_value_bytes().collect();
        assert_eq!(
            all,
            vec![(b"content-type".as_slice(), b"\xffclean\xfe".as_slice())]
        );
        let existing =
            ResponseHeaders::from(vec![("content-type".into(), "application/json".into())]);
        assert_eq!(existing.name_value_bytes().count(), 1);
        assert_eq!(existing.len(), 1);
    }
    #[test]
    fn private_and_special_addresses_rejected() {
        for bad in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "0.1.2.3",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:1::4",
            "2001:1:0:1::1",
            "2001:2::1",
            "2001:4:111::1",
            "2001:10::1",
            "2001:100::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
            "3fff:fff::1",
            "3fff:1000::1",
            "3ffe::1",
            "3f00::1",
            "3e00::1",
            "3c00::1",
            "3800::1",
            "3000::1",
            "2e00::1",
            "2d00::1",
            "2c10::1",
            "2a20::1",
            "2640::1",
            "2620:200::1",
            "2610:200::1",
            "2420::1",
            "2003:4000::1",
            "2001:4e00::1",
            "5f00::1",
            "fec0::1",
            "ff02::1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!ip_is_public(ip), "{bad} must be rejected");
        }
        for good in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:1::1",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2001:200::1",
            "2001:9ff::1",
            "2001:1fff::1",
            "2001:3fff::1",
            "2001:4dff::1",
            "2001:5fff::1",
            "2001:9fff::1",
            "2001:afff::1",
            "2001:bfff::1",
            "2003:3fff::1",
            "241f::1",
            "260f::1",
            "2610:1ff::1",
            "2620:1ff::1",
            "263f::1",
            "280f::1",
            "2a1f::1",
            "2c0f::1",
            "64:ff9b::5db8:d822",
            "2002:5db8:d822::1",
        ] {
            let ip: IpAddr = good.parse().unwrap();
            assert!(ip_is_public(ip), "{good} must be allowed");
        }
    }

    #[test]
    fn mixed_dns_answer_is_rejected_before_selection() {
        let addrs = [
            "93.184.216.34:443".parse().unwrap(),
            "[3000::1]:443".parse().unwrap(),
        ];
        assert!(matches!(
            select_public_endpoint("example.com", &addrs),
            Err(UpstreamError::Blocked("private-address"))
        ));
    }

    #[test]
    fn all_public_dns_answer_pins_one_screened_endpoint() {
        let addrs = [
            "93.184.216.34:443".parse().unwrap(),
            "[2606:4700:4700::1111]:443".parse().unwrap(),
        ];
        let endpoint = select_public_endpoint("example.com", &addrs).unwrap();
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.addr, addrs[0]);
    }

    #[tokio::test]
    async fn production_transport_blocks_loopback_dns() {
        match ReqwestUpstreamTransport
            .send(loopback_request("localhost"))
            .await
        {
            Err(UpstreamError::Blocked("private-address")) => {}
            Err(err) => panic!("expected private-address, got {err:?}"),
            Ok(_) => panic!("expected private-address, got success"),
        }
    }

    #[tokio::test]
    async fn production_dns_deadline_times_out_a_stalled_resolver() {
        let deadline = tokio::time::Instant::now();
        assert!(matches!(
            resolve_before_deadline(deadline, std::future::pending()).await,
            Err(UpstreamError::Timeout)
        ));
    }

    #[tokio::test]
    async fn production_transport_blocks_rfc1918_literal() {
        match ReqwestUpstreamTransport
            .send(loopback_request("10.0.0.1"))
            .await
        {
            Err(UpstreamError::Blocked("private-address")) => {}
            Err(err) => panic!("expected private-address, got {err:?}"),
            Ok(_) => panic!("expected private-address, got success"),
        }
    }

    #[tokio::test]
    async fn production_transport_blocks_ipv6_loopback_literal() {
        match ReqwestUpstreamTransport.send(loopback_request("::1")).await {
            Err(UpstreamError::Blocked("private-address")) => {}
            Err(err) => panic!("expected private-address, got {err:?}"),
            Ok(_) => panic!("expected private-address, got success"),
        }
    }

    #[tokio::test]
    async fn production_transport_blocks_ipv6_documentation_literal() {
        match ReqwestUpstreamTransport
            .send(loopback_request("3fff::1"))
            .await
        {
            Err(UpstreamError::Blocked("private-address")) => {}
            Err(err) => panic!("expected private-address, got {err:?}"),
            Ok(_) => panic!("expected private-address, got success"),
        }
    }
}
