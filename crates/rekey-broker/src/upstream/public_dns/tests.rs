use super::*;
use std::os::unix::ffi::OsStringExt;

const VIRTUAL: &str = "198.18.7.242:443";
const EXPLICIT: &str = "https://doh.example/dns-query";

fn endpoint(addr: &str) -> ScreenedEndpoint {
    ScreenedEndpoint {
        host: "example.com".into(),
        addr: addr.parse().unwrap(),
    }
}

/// Runs the production selection with scripted DoH replies and returns the
/// outcome plus every resolver queried, in order. An unscripted query panics.
async fn scripted(
    host: &str,
    system: &[&str],
    explicit: Option<OsString>,
    defaults: &[&str],
    replies: Vec<Result<ScreenedEndpoint, UpstreamError>>,
) -> (Result<ScreenedEndpoint, UpstreamError>, Vec<String>) {
    let system: Vec<SocketAddr> = system.iter().map(|addr| addr.parse().unwrap()).collect();
    let mut replies = replies.into_iter();
    let mut queried = Vec::new();
    let result = resolve_with(host, &system, explicit, defaults, |resolver| {
        queried.push(resolver);
        let reply = replies.next().expect("unscripted resolver query");
        async move { reply }
    })
    .await;
    (result, queried)
}

#[tokio::test]
async fn explicit_doh_url_is_the_only_resolver_ever_queried() {
    for reply in [
        Err(UpstreamError::Timeout),
        Err(UpstreamError::Blocked("private-address")),
    ] {
        let (result, queried) = scripted(
            "example.com",
            &[VIRTUAL],
            Some(EXPLICIT.into()),
            &DEFAULT_PUBLIC_DOH,
            vec![reply],
        )
        .await;
        // A failing explicit resolver never falls back to the defaults.
        assert!(result.is_err());
        assert_eq!(queried, [EXPLICIT]);
    }
    let (result, queried) = scripted(
        "example.com",
        &[VIRTUAL],
        Some(EXPLICIT.into()),
        &DEFAULT_PUBLIC_DOH,
        vec![Ok(endpoint("93.184.216.34:443"))],
    )
    .await;
    assert_eq!(result.unwrap().addr, "93.184.216.34:443".parse().unwrap());
    assert_eq!(queried, [EXPLICIT]);
    // A value that is not UTF-8 is refused before any query.
    let (result, queried) = scripted(
        "example.com",
        &[VIRTUAL],
        Some(OsString::from_vec(b"https://\xff/dns-query".to_vec())),
        &DEFAULT_PUBLIC_DOH,
        vec![],
    )
    .await;
    assert!(matches!(
        result,
        Err(UpstreamError::Blocked("invalid-doh-url"))
    ));
    assert!(queried.is_empty());
}

#[tokio::test]
async fn unset_doh_url_tries_the_fixed_resolvers_in_order() {
    assert_eq!(
        DEFAULT_PUBLIC_DOH,
        ["https://223.5.5.5/resolve", "https://1.1.1.1/dns-query"]
    );
    let (result, queried) = scripted(
        "example.com",
        &[VIRTUAL, "198.19.255.254:443"],
        None,
        &DEFAULT_PUBLIC_DOH,
        vec![
            Err(UpstreamError::Transport),
            Ok(endpoint("93.184.216.34:443")),
        ],
    )
    .await;
    assert_eq!(result.unwrap().addr, "93.184.216.34:443".parse().unwrap());
    assert_eq!(queried, DEFAULT_PUBLIC_DOH);
    // The first answer that passes screening ends the search.
    let (result, queried) = scripted(
        "example.com",
        &[VIRTUAL],
        None,
        &DEFAULT_PUBLIC_DOH,
        vec![Ok(endpoint("93.184.216.34:443"))],
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(queried, [DEFAULT_PUBLIC_DOH[0]]);
}

#[tokio::test]
async fn every_resolver_failing_refuses_instead_of_using_the_virtual_answer() {
    let (result, queried) = scripted(
        "example.com",
        &[VIRTUAL],
        None,
        &DEFAULT_PUBLIC_DOH,
        vec![
            Err(UpstreamError::Timeout),
            Err(UpstreamError::Blocked("private-address")),
        ],
    )
    .await;
    // The last resolver's refusal is reported; nothing connects to 198.18/15.
    assert!(matches!(
        result,
        Err(UpstreamError::Blocked("private-address"))
    ));
    assert_eq!(queried, DEFAULT_PUBLIC_DOH);
    let (result, queried) = scripted("example.com", &[VIRTUAL], None, &[], vec![]).await;
    assert!(matches!(result, Err(UpstreamError::Blocked("fake-ip-dns"))));
    assert!(queried.is_empty());
}

#[tokio::test]
async fn only_an_all_virtual_answer_for_a_domain_consults_any_resolver() {
    for (system, expected) in [
        (vec!["93.184.216.34:443"], None),
        (vec!["[2606:4700:4700::1111]:443"], None),
        (vec!["198.17.255.255:443"], None),
        (vec!["198.20.0.1:443"], None),
        (vec!["127.0.0.1:443"], Some("private-address")),
        (vec!["10.0.0.1:443"], Some("private-address")),
        (vec!["[::1]:443"], Some("private-address")),
        (vec![VIRTUAL, "93.184.216.34:443"], Some("private-address")),
        (vec![VIRTUAL, "10.0.0.1:443"], Some("private-address")),
    ] {
        // Even a configured resolver cannot override another kind of answer.
        let (result, queried) = scripted(
            "example.com",
            &system,
            Some(EXPLICIT.into()),
            &DEFAULT_PUBLIC_DOH,
            vec![],
        )
        .await;
        assert!(queried.is_empty(), "{system:?}");
        match expected {
            None => assert_eq!(result.unwrap().addr, system[0].parse().unwrap()),
            Some(reason) => assert!(
                matches!(result, Err(UpstreamError::Blocked(r)) if r == reason),
                "{system:?}"
            ),
        }
    }
    let (result, queried) = scripted("example.com", &[], None, &DEFAULT_PUBLIC_DOH, vec![]).await;
    assert!(matches!(result, Err(UpstreamError::Transport)));
    assert!(queried.is_empty());
    // An IP-literal target is never re-resolved, even inside 198.18/15.
    let (result, queried) = scripted(
        "198.18.7.242",
        &[VIRTUAL],
        None,
        &DEFAULT_PUBLIC_DOH,
        vec![],
    )
    .await;
    assert!(matches!(
        result,
        Err(UpstreamError::Blocked("private-address"))
    ));
    assert!(queried.is_empty());
}

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

/// Formerly the 0.4 "explicit resolver required" test. Since 0.5 the defaults
/// are used when REKEY_DOH_URL is unset; each resolver must still be public.
#[tokio::test]
async fn fake_ip_fallback_queries_only_public_https_resolvers() {
    for resolver in [
        "https://127.0.0.1/dns-query",
        "https://198.18.1.1/dns-query",
    ] {
        assert!(matches!(
            query_resolver("example.com", 443, resolver).await,
            Err(UpstreamError::Blocked("private-address"))
        ));
    }
    for resolver in ["http://1.1.1.1/dns-query", "invalid"] {
        assert!(matches!(
            query_resolver("example.com", 443, resolver).await,
            Err(UpstreamError::Blocked("invalid-doh-url"))
        ));
    }
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
