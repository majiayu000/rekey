//! Local HTTP service and SSH agent surfaces. The HTTP check covers the
//! status line, every response header and the body.
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{CANARY, Fixture, SSH_KEY_NAME, Sweep, common, reflections, ssh_blob};

async fn exchange(sweep: &mut Sweep, what: &str, request: reqwest::RequestBuilder) -> (u16, Value) {
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let mut output = format!("HTTP {status}\n").into_bytes();
    for (name, value) in response.headers() {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.push(b'\n');
    }
    let body = response.bytes().await.unwrap();
    output.extend_from_slice(&body);
    sweep.check("http", what, &output);
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

pub(super) async fn http_sweep(f: &Fixture, sweep: &mut Sweep) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = |path: &str| format!("{}{path}", f.service_url);
    let issue = url("/c/fixture/repos/octo/widgets/issues/7");
    let canary = std::str::from_utf8(CANARY).unwrap();
    // Calls that succeed with either public marker.
    let (status, body) = exchange(sweep, "GET", client.get(&issue).bearer_auth("rekey")).await;
    assert_eq!((status, body), (200, json!({"ok":true})));
    let marked = client.get(&issue).header("x-api-key", "rekey");
    assert_eq!(exchange(sweep, "GET x-api-key", marked).await.0, 200);
    assert_eq!(f.upstream_requests(), 2);
    // Every reflection is sealed before a status, header or body byte leaves.
    for (name, response) in reflections() {
        f.fake.push_response(Ok(response));
        let (status, body) = exchange(sweep, name, client.get(&issue).bearer_auth("rekey")).await;
        assert_eq!(
            (status, &body["code"]),
            (502, &json!("RESPONSE_BLOCKED")),
            "{name}"
        );
        assert_eq!(f.upstream_requests(), 1, "{name}");
    }
    // Refusals; a presented canary is never echoed back.
    let bearer = || client.get(&issue).bearer_auth("rekey");
    let refusals = [
        (
            "canary as bearer",
            client.get(&issue).bearer_auth(canary),
            Some("REAL_KEY_PRESENTED"),
        ),
        (
            "canary as x-api-key",
            client.get(&issue).header("x-api-key", canary),
            Some("REAL_KEY_PRESENTED"),
        ),
        ("no marker", client.get(&issue), Some("INVALID_INPUT")),
        (
            "foreign host",
            bearer().header("host", "evil.example"),
            None,
        ),
        (
            "browser origin",
            bearer().header("origin", "https://evil.example"),
            None,
        ),
        (
            "cross-site fetch",
            bearer().header("sec-fetch-site", "cross-site"),
            None,
        ),
        ("GET with body", bearer().body("{}"), None),
        (
            "repeated query key",
            client
                .get(format!("{issue}?state=open&state=closed"))
                .bearer_auth("rekey"),
            None,
        ),
    ];
    for (name, request, code) in refusals {
        let (status, body) = exchange(sweep, name, request).await;
        assert_eq!(status, 400, "{name}: {body}");
        if let Some(code) = code {
            assert_eq!(body["code"], code, "{name}");
        }
    }
    // Errors: rules, approvals and routes.
    let errors = [
        (
            "denied method",
            client
                .delete(url("/c/fixture/repos/octo/widgets"))
                .bearer_auth("rekey"),
            403,
        ),
        (
            "approval required",
            client
                .post(url("/c/fixture/repos/octo/widgets/issues"))
                .bearer_auth("rekey")
                .header("content-type", "application/json")
                .body(r#"{"title":"sweep"}"#),
            403,
        ),
        (
            "unknown connection",
            client.get(url("/c/nowhere/x")).bearer_auth("rekey"),
            404,
        ),
        (
            "unknown route",
            client.get(url("/v1/models")).bearer_auth("rekey"),
            404,
        ),
        // The HTTP client itself resolves dot segments; these reach the rules.
        (
            "empty segment",
            client
                .get(url("/c/fixture/repos//widgets"))
                .bearer_auth("rekey"),
            403,
        ),
        (
            "encoded slash",
            client
                .get(url("/c/fixture/repos/octo%2Fwidgets/issues/7"))
                .bearer_auth("rekey"),
            403,
        ),
    ];
    for (name, request, expected) in errors {
        let (status, body) = exchange(sweep, name, request).await;
        assert_eq!(status, expected, "{name}: {body}");
    }
    assert_eq!(f.upstream_requests(), 0);
}

async fn ssh_exchange(
    agent: &mut UnixStream,
    sweep: &mut Sweep,
    what: &str,
    packet: &[u8],
) -> Vec<u8> {
    agent.write_u32(packet.len() as u32).await.unwrap();
    agent.write_all(packet).await.unwrap();
    let limit = common::test_timeout(Duration::from_secs(30));
    let reply = tokio::time::timeout(limit, async {
        let length = agent.read_u32().await.unwrap() as usize;
        assert!(length < 256 * 1024);
        let mut reply = vec![0; length];
        agent.read_exact(&mut reply).await.unwrap();
        reply
    })
    .await
    .unwrap_or_else(|_| panic!("SSH agent did not answer `{what}`"));
    sweep.check("ssh", what, &reply);
    reply
}

pub(super) async fn ssh_sweep(f: &Fixture, sweep: &mut Sweep) {
    let mut agent = UnixStream::connect(f.state.join("ssh-agent.sock"))
        .await
        .unwrap();
    // Identities carry only the registered public key and the signed key name.
    let identities = ssh_exchange(&mut agent, sweep, "request identities", &[11]).await;
    assert_eq!(identities[..5], [12, 0, 0, 0, 1]);
    assert!(
        identities
            .windows(SSH_KEY_NAME.len())
            .any(|window| window == SSH_KEY_NAME.as_bytes())
    );
    // An unknown key, a mutation request and a malformed bind all fail closed.
    let unknown = ssh_blob(b"ssh-ed25519", &[&[7; 32]]);
    let mut sign = vec![13];
    sign.extend(ssh_blob(&unknown, &[b"data"]));
    sign.extend_from_slice(&0_u32.to_be_bytes());
    let failed = ssh_exchange(&mut agent, sweep, "sign with unknown key", &sign).await;
    assert_eq!(failed, [5]);
    let failed = ssh_exchange(&mut agent, sweep, "add identity", &[17, 0, 0, 0, 0]).await;
    assert_eq!(failed, [5]);
    let mut bind = vec![27];
    bind.extend(ssh_blob(b"session-bind@openssh.com", &[b"garbage"]));
    let failed = ssh_exchange(&mut agent, sweep, "malformed session bind", &bind).await;
    assert_eq!(failed, [5]);
}
