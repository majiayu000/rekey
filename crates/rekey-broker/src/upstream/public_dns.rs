//! Layer 1 resolution with the fake-IP DNS fallback (threat model I6). DoH is
//! consulted only when every system answer is a 198.18.0.0/15 virtual address;
//! the resolver list is injected so its selection is tested without a network.
use std::ffi::OsString;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

use super::{CONNECT_TIMEOUT, ScreenedEndpoint, UpstreamError, select_public_endpoint};

const PUBLIC_DNS_MAX_BYTES: usize = 65_536;

/// JSON DoH resolvers tried in order when system DNS returns fake IPs and
/// REKEY_DOH_URL is unset. IP hosts avoid resolving the resolver itself.
const DEFAULT_PUBLIC_DOH: [&str; 2] = ["https://223.5.5.5/resolve", "https://1.1.1.1/dns-query"];

/// Layer 1: resolve real addresses and refuse any private/special address.
pub async fn screen_public_endpoint(
    host: &str,
    port: u16,
) -> Result<ScreenedEndpoint, UpstreamError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| UpstreamError::Transport)?
        .collect();
    resolve_with(
        host,
        &addrs,
        std::env::var_os("REKEY_DOH_URL"),
        &DEFAULT_PUBLIC_DOH,
        |resolver| async move { query_resolver(host, port, &resolver).await },
    )
    .await
}

/// Chooses the answer for `system` (the system DNS result). `explicit` is the
/// REKEY_DOH_URL value and `doh` performs one screened query to a resolver.
async fn resolve_with<F, Fut>(
    host: &str,
    system: &[SocketAddr],
    explicit: Option<OsString>,
    defaults: &[&str],
    mut doh: F,
) -> Result<ScreenedEndpoint, UpstreamError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<ScreenedEndpoint, UpstreamError>>,
{
    if !needs_public_dns(host, system) {
        return select_public_endpoint(host, system);
    }
    // An explicit resolver is exclusive; otherwise fake-IP proxies (Clash/Surge
    // TUN) fall back to fixed public DoH resolvers addressed by IP, so the
    // daemon works whether it was started by the App, launchd or a terminal.
    if let Some(value) = explicit {
        let resolver = value
            .into_string()
            .map_err(|_| UpstreamError::Blocked("invalid-doh-url"))?;
        return doh(resolver).await;
    }
    let mut last = UpstreamError::Blocked("fake-ip-dns");
    for resolver in defaults {
        match doh((*resolver).to_owned()).await {
            Ok(endpoint) => return Ok(endpoint),
            Err(error) => last = error,
        }
    }
    tracing::warn!(
        event = "upstream.dns_configuration_required",
        "System DNS returned fake-IP addresses and the default public DoH resolvers failed; set REKEY_DOH_URL for the daemon"
    );
    Err(last)
}

/// One HTTPS JSON DoH query. The resolver itself must resolve to a public
/// address and is pinned; every answer must be public as well.
async fn query_resolver(
    host: &str,
    port: u16,
    resolver: &str,
) -> Result<ScreenedEndpoint, UpstreamError> {
    let url = public_dns_url(resolver)?;
    let resolver_host = match url
        .host()
        .ok_or(UpstreamError::Blocked("invalid-doh-url"))?
    {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let resolver_addrs =
        tokio::net::lookup_host((resolver_host.as_str(), url.port_or_known_default().unwrap()))
            .await
            .map_err(|_| UpstreamError::Transport)?
            .collect::<Vec<_>>();
    let endpoint = select_public_endpoint(&resolver_host, &resolver_addrs)?;
    // The chosen resolver is screened once and pinned too.
    // No provider headers or credentials enter this separate client.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .resolve_to_addrs(&resolver_host, &[endpoint.addr])
        .build()
        .map_err(|_| UpstreamError::Transport)?;
    let (mut ipv4, ipv6) = tokio::try_join!(
        query_public_dns(&client, &url, host, port, "A"),
        query_public_dns(&client, &url, host, port, "AAAA"),
    )?;
    ipv4.extend(ipv6);
    select_public_endpoint(host, &ipv4)
}

fn public_dns_url(value: &str) -> Result<url::Url, UpstreamError> {
    let url = url::Url::parse(value).map_err(|_| UpstreamError::Blocked("invalid-doh-url"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(UpstreamError::Blocked("invalid-doh-url"));
    }
    Ok(url)
}

fn needs_public_dns(host: &str, addrs: &[SocketAddr]) -> bool {
    host.parse::<IpAddr>().is_err()
        && !addrs.is_empty()
        && addrs.iter().all(|addr| match addr.ip() {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                octets[0] == 198 && matches!(octets[1], 18 | 19)
            }
            IpAddr::V6(_) => false,
        })
}

async fn query_public_dns(
    client: &reqwest::Client,
    resolver: &url::Url,
    host: &str,
    port: u16,
    record_type: &str,
) -> Result<Vec<SocketAddr>, UpstreamError> {
    // No provider headers or body enter this request. The caller's DNS deadline
    // encloses both queries; no cached answer can outlive that operation.
    let mut response = client
        .get(resolver.clone())
        .query(&[("name", host), ("type", record_type)])
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await
        .map_err(|err| {
            if err.is_timeout() {
                UpstreamError::Timeout
            } else {
                UpstreamError::Transport
            }
        })?;
    if !response.status().is_success() {
        return Err(UpstreamError::Transport);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| {
        if err.is_timeout() {
            UpstreamError::Timeout
        } else {
            UpstreamError::Transport
        }
    })? {
        if chunk.len() > PUBLIC_DNS_MAX_BYTES.saturating_sub(body.len()) {
            return Err(UpstreamError::Transport);
        }
        body.extend_from_slice(&chunk);
    }
    parse_public_dns_answer(&body, port)
}

#[derive(Deserialize)]
struct PublicDnsAnswer {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "TC")]
    truncated: bool,
    #[serde(rename = "Answer", default)]
    answers: Vec<PublicDnsRecord>,
}

#[derive(Deserialize)]
struct PublicDnsRecord {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

fn parse_public_dns_answer(body: &[u8], port: u16) -> Result<Vec<SocketAddr>, UpstreamError> {
    let answer: PublicDnsAnswer =
        serde_json::from_slice(body).map_err(|_| UpstreamError::Transport)?;
    if answer.status != 0 || answer.truncated {
        return Err(UpstreamError::Transport);
    }
    answer
        .answers
        .into_iter()
        .filter(|record| matches!(record.record_type, 1 | 28))
        .map(|record| {
            let ip: IpAddr = record.data.parse().map_err(|_| UpstreamError::Transport)?;
            if (record.record_type == 1) != ip.is_ipv4() {
                return Err(UpstreamError::Transport);
            }
            Ok(SocketAddr::new(ip, port))
        })
        .collect()
}

#[cfg(test)]
mod tests;
