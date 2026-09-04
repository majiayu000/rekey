//! Upstream HTTPS transport. Fixed origin only, redirects disabled, proxy
//! environment ignored, DNS results screened before connecting.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
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

pub struct UpstreamResponse {
    pub status: u16,
    pub headers: ResponseHeaders,
    pub body: Zeroizing<Vec<u8>>,
}

/// Rekey-owned copies of upstream headers remain wipe-on-drop until response
/// sealing has proved that an allowlisted value is safe to materialize.
pub struct ResponseHeaders(Vec<(String, String)>);

impl From<Vec<(String, String)>> for ResponseHeaders {
    fn from(headers: Vec<(String, String)>) -> Self {
        Self(headers)
    }
}

impl std::ops::Deref for ResponseHeaders {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ResponseHeaders {
    fn drop(&mut self) {
        for (name, value) in &mut self.0 {
            name.zeroize();
            value.zeroize();
        }
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

pub trait UpstreamTransport: Send + Sync {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_>;
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

fn second_segment_matches_prefix(segment: u16, network: u16, prefix_len: u8) -> bool {
    let bits = prefix_len - 16;
    let mask = u16::MAX << (16 - bits);
    segment & mask == network
}

fn allocated_public_ipv6(segments: &[u16; 8]) -> bool {
    let [first, second, ..] = *segments;
    match first {
        0x2001 => {
            let public_ietf_exception = (second == 1
                && segments[2..7] == [0, 0, 0, 0, 0]
                && (1..=3).contains(&segments[7]))
                || second == 3
                || (second == 4 && segments[2] == 0x0112)
                || (second & 0xfff0) == 0x0020
                || (second & 0xfff0) == 0x0030;
            let allocated = [
                (0x0200, 23),
                (0x0400, 23),
                (0x0600, 23),
                (0x0800, 22),
                (0x0c00, 23),
                (0x0e00, 23),
                (0x1200, 23),
                (0x1400, 22),
                (0x1800, 23),
                (0x1a00, 23),
                (0x1c00, 22),
                (0x2000, 19),
                (0x4000, 23),
                (0x4200, 23),
                (0x4400, 23),
                (0x4600, 23),
                (0x4800, 23),
                (0x4a00, 23),
                (0x4c00, 23),
                (0x5000, 20),
                (0x8000, 19),
                (0xa000, 20),
                (0xb000, 20),
            ]
            .iter()
            .any(|&(network, prefix)| second_segment_matches_prefix(second, network, prefix));
            public_ietf_exception || (allocated && second != 0x0db8)
        }
        0x2003 => second_segment_matches_prefix(second, 0, 18),
        0x2400..=0x241f => true,
        0x2600..=0x260f => true,
        0x2610 | 0x2620 => second_segment_matches_prefix(second, 0, 23),
        0x2630..=0x263f => true,
        0x2800..=0x280f => true,
        0x2a00..=0x2a1f => true,
        0x2c00..=0x2c0f => true,
        _ => false,
    }
}

/// Default-deny for anything that is not covered by the explicit public
/// unicast contract. Translation addresses are accepted only when their
/// embedded IPv4 destination independently passes the IPv4 contract.
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // RFC 6052 well-known NAT64 prefix. Screen the embedded IPv4 so
            // a public NAT64 destination remains usable but private IPv4
            // cannot be smuggled through IPv6.
            if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                let embedded = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return ip_is_public(IpAddr::V4(embedded));
            }
            // 6to4 embeds an IPv4 address in bits 16..48.
            if s[0] == 0x2002 {
                let embedded = std::net::Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                );
                return ip_is_public(IpAddr::V4(embedded));
            }
            allocated_public_ipv6(&s)
        }
    }
}

pub struct ReqwestUpstreamTransport;

impl UpstreamTransport for ReqwestUpstreamTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move { send_via_reqwest(request).await })
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

fn select_public_endpoint(
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
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(request.timeout)
        .resolve(&endpoint.host, endpoint.addr);
    if let Some(der) = extra_root_der {
        let cert = reqwest::Certificate::from_der(der).map_err(|_| UpstreamError::Transport)?;
        builder = builder.add_root_certificate(cert).http1_only();
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
        req = req.header(name, value);
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
    let headers: ResponseHeaders = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|value| (k.as_str().to_owned(), value.to_owned()))
        })
        .collect::<Vec<_>>()
        .into();

    let limit = request.response_max_bytes as usize;
    // Product actions cap this at 4 MiB. Reserving the full bounded response
    // avoids reallocations that could leave stale secret-bearing heap copies.
    let mut body = Zeroizing::new(Vec::with_capacity(limit));
    let body_capacity = body.capacity();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await.map_err(|err| {
        if err.is_timeout() {
            UpstreamError::Timeout
        } else {
            UpstreamError::Transport
        }
    })? {
        if body.len() + chunk.len() > limit {
            // Over-limit is a hard failure, never a truncated success.
            return Err(UpstreamError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
        debug_assert_eq!(body.capacity(), body_capacity);
    }

    Ok(UpstreamResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::action::FixedMethod;

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
