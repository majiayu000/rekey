//! Layer 1 resolution with the fake-IP DNS fallback (threat model I6), moved
//! verbatim out of `upstream.rs`.
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

use super::{CONNECT_TIMEOUT, ScreenedEndpoint, UpstreamError, select_public_endpoint};

const PUBLIC_DNS_MAX_BYTES: usize = 65_536;

/// Layer 1: resolve real addresses and refuse any private/special address.
pub async fn screen_public_endpoint(
    host: &str,
    port: u16,
) -> Result<ScreenedEndpoint, UpstreamError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| UpstreamError::Transport)?
        .collect();
    if !needs_public_dns(host, &addrs) {
        return screen_dns_answer(host, port, addrs, None).await;
    }
    // An explicit resolver wins; otherwise fake-IP proxies (Clash/Surge TUN)
    // fall back to fixed public DoH resolvers addressed by IP, so the daemon
    // works whether it was started by the App, launchd or a terminal.
    if let Some(value) = std::env::var_os("REKEY_DOH_URL") {
        let resolver = value
            .into_string()
            .map_err(|_| UpstreamError::Blocked("invalid-doh-url"))?;
        return screen_dns_answer(host, port, addrs, Some(&resolver)).await;
    }
    let mut last = UpstreamError::Blocked("fake-ip-dns");
    for resolver in DEFAULT_PUBLIC_DOH {
        match screen_dns_answer(host, port, addrs.clone(), Some(resolver)).await {
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

/// JSON DoH resolvers tried in order when system DNS returns fake IPs and
/// REKEY_DOH_URL is unset. IP hosts avoid resolving the resolver itself.
const DEFAULT_PUBLIC_DOH: [&str; 2] = ["https://223.5.5.5/resolve", "https://1.1.1.1/dns-query"];

async fn screen_dns_answer(
    host: &str,
    port: u16,
    mut addrs: Vec<SocketAddr>,
    resolver: Option<&str>,
) -> Result<ScreenedEndpoint, UpstreamError> {
    if needs_public_dns(host, &addrs) {
        let Some(resolver) = resolver else {
            tracing::warn!(
                event = "upstream.dns_configuration_required",
                "System DNS returned fake-IP addresses; configure real system DNS or explicitly set REKEY_DOH_URL for the daemon"
            );
            return Err(UpstreamError::Blocked("fake-ip-dns"));
        };
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
        // The explicitly chosen resolver is screened once and pinned too.
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
        addrs = ipv4;
    }
    select_public_endpoint(host, &addrs)
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
mod tests {
    use super::*;

    #[test]
    fn only_all_virtual_system_answers_for_domains_use_public_dns() {
        let virtual_addrs = [
            "198.18.7.242:443".parse().unwrap(),
            "198.19.255.254:443".parse().unwrap(),
        ];
        for host in ["open.bigmodel.cn", "api.anthropic.com", "api.openai.com"] {
            assert!(needs_public_dns(host, &virtual_addrs));
        }
        assert!(!needs_public_dns("198.18.7.242", &virtual_addrs));
        for addrs in [
            vec![],
            vec!["93.184.216.34:443".parse().unwrap()],
            vec!["127.0.0.1:443".parse().unwrap()],
            vec!["10.0.0.1:443".parse().unwrap()],
            vec!["[::1]:443".parse().unwrap()],
            vec![virtual_addrs[0], "93.184.216.34:443".parse().unwrap()],
            vec![virtual_addrs[0], "10.0.0.1:443".parse().unwrap()],
        ] {
            assert!(!needs_public_dns("example.com", &addrs), "{addrs:?}");
        }
    }

    #[tokio::test]
    async fn fake_ip_dns_requires_explicit_resolver_and_never_overrides_other_private_answers() {
        let virtual_addrs = vec!["198.18.1.2:443".parse().unwrap()];
        assert!(matches!(
            screen_dns_answer("example.com", 443, virtual_addrs.clone(), None).await,
            Err(UpstreamError::Blocked("fake-ip-dns"))
        ));
        for resolver in [
            "https://127.0.0.1/dns-query",
            "https://198.18.1.1/dns-query",
        ] {
            assert!(matches!(
                screen_dns_answer("example.com", 443, virtual_addrs.clone(), Some(resolver)).await,
                Err(UpstreamError::Blocked("private-address"))
            ));
        }
        // An invalid resolver would fail before any query if it were used.
        // The normal/mixed system answer path must remain independent of it.
        assert_eq!(
            screen_dns_answer(
                "example.com",
                443,
                vec!["93.184.216.34:443".parse().unwrap()],
                Some("invalid")
            )
            .await
            .unwrap()
            .addr,
            "93.184.216.34:443".parse().unwrap()
        );
        assert!(matches!(
            screen_dns_answer(
                "example.com",
                443,
                vec![
                    "93.184.216.34:443".parse().unwrap(),
                    "198.18.1.2:443".parse().unwrap()
                ],
                Some("invalid")
            )
            .await,
            Err(UpstreamError::Blocked("private-address"))
        ));
    }

    #[test]
    fn explicit_doh_url_requires_https_and_never_embeds_credentials() {
        for url in [
            "http://1.1.1.1/dns-query",
            "https://user:secret@example.com/dns-query",
            "https://example.com/dns-query?token=secret",
            "https://example.com/dns-query#fragment",
            "not-a-url",
        ] {
            assert!(matches!(
                public_dns_url(url),
                Err(UpstreamError::Blocked("invalid-doh-url"))
            ));
        }
        for url in [
            "https://resolver.example.com/dns-query",
            "https://1.1.1.1/dns-query",
            "https://[2606:4700:4700::1111]/dns-query",
        ] {
            assert!(public_dns_url(url).is_ok());
        }
    }

    #[test]
    fn public_dns_cname_and_both_address_families_keep_origin_and_port() {
        let addrs = parse_public_dns_answer(
            br#"{"Status":0,"TC":false,"Answer":[
                {"type":5,"data":"cdn.example.com."},
                {"type":1,"data":"93.184.216.34"},
                {"type":28,"data":"2606:4700:4700::1111"}
            ]}"#,
            8443,
        )
        .unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(|addr| addr.port() == 8443));
        let endpoint = select_public_endpoint("example.com", &addrs).unwrap();
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.addr, "93.184.216.34:8443".parse().unwrap());
    }

    #[test]
    fn public_dns_does_not_allow_private_mixed_or_virtual_answers() {
        for ip in ["127.0.0.1", "10.0.0.1", "198.18.7.242", "::1", "fc00::1"] {
            let record_type = if ip.contains(':') { 28 } else { 1 };
            let body = serde_json::json!({
                "Status": 0, "TC": false,
                "Answer": [
                    {"type": 1, "data": "93.184.216.34"},
                    {"type": record_type, "data": ip}
                ]
            });
            let addrs = parse_public_dns_answer(&serde_json::to_vec(&body).unwrap(), 443).unwrap();
            assert!(matches!(
                select_public_endpoint("example.com", &addrs),
                Err(UpstreamError::Blocked("private-address"))
            ));
        }
    }

    #[test]
    fn public_dns_incomplete_invalid_or_empty_answers_fail_closed() {
        for body in [
            r#"{"Status":3,"TC":false}"#,
            r#"{"Status":0,"TC":true,"Answer":[{"type":1,"data":"93.184.216.34"}]}"#,
            r#"{"Status":0,"TC":false,"Answer":[{"type":1,"data":"not-an-ip"}]}"#,
            r#"{"Status":0,"TC":false,"Answer":[{"type":1,"data":"2606:4700:4700::1111"}]}"#,
            r#"{"Status":0,"TC":false,"Answer":[{"type":28,"data":"93.184.216.34"}]}"#,
            r#"{"TC":false,"Answer":[{"type":1,"data":"93.184.216.34"}]}"#,
        ] {
            assert!(
                matches!(
                    parse_public_dns_answer(body.as_bytes(), 443),
                    Err(UpstreamError::Transport)
                ),
                "{body}"
            );
        }
        let empty = parse_public_dns_answer(br#"{"Status":0,"TC":false}"#, 443).unwrap();
        assert!(matches!(
            select_public_endpoint("example.com", &empty),
            Err(UpstreamError::Transport)
        ));
    }
}
