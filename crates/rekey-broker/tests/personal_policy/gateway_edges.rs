//! Raw-socket and edge contracts of the default Connection HTTP service.
//! Upstream is synthetic; nothing here claims real provider behavior.
use super::gateway::{SECRET, activate, finished, post, sse, transport};
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

const BODY: &str =
    r#"{"model":"synthetic-model","messages":[{"role":"user","content":"test"}],"max_tokens":16}"#;

fn port(url: &str) -> u16 {
    let rest = url.strip_prefix("http://127.0.0.1:").unwrap();
    rest.split_once('/').unwrap().0.parse().unwrap()
}

fn started(f: &Fixture) -> i64 {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='execution.started'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// Sends exact bytes and returns the status code plus the whole response.
async fn raw_http(port: u16, raw: &[u8]) -> (u16, String) {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(raw).await.unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), socket.read_to_end(&mut output))
        .await
        .expect("the service must answer and close within its read deadline")
        .ok();
    let text = String::from_utf8_lossy(&output).into_owned();
    let status = text
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP/1.1 response: {text:?}"));
    (status, text)
}

async fn envelope(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

fn ok_message() -> rekey_broker::upstream::UpstreamResponse {
    rekey_broker::upstream::UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#
            .to_vec()
            .into(),
    }
}

#[tokio::test]
async fn raw_socket_ambiguous_headers_and_paths_never_reach_upstream() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "anthropic").await;
    let port = port(&url);
    let normal = format!(
        "Host: 127.0.0.1:{port}\r\nAuthorization: Bearer rekey\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        BODY.len()
    );
    let route = "/c/fixture/v1/messages";
    let mut cases: Vec<(String, String, u16)> = vec![
        (
            normal.replace(&format!("127.0.0.1:{port}"), "evil.example"),
            route.into(),
            400,
        ),
        // DNS rebinding keeps the real port behind an attacker name that
        // resolves to loopback. Another case, no port or another port is not
        // this service either: Host is compared byte for byte.
        (
            normal.replace("127.0.0.1", "rebind.example"),
            route.into(),
            400,
        ),
        (normal.replace("127.0.0.1", "LOCALHOST"), route.into(), 400),
        (
            normal.replace(&format!("127.0.0.1:{port}"), "127.0.0.1"),
            route.into(),
            400,
        ),
        (
            normal.replace(
                &format!("127.0.0.1:{port}"),
                &format!("localhost:{}", port ^ 1),
            ),
            route.into(),
            400,
        ),
        (
            format!("{normal}Host: localhost:{port}\r\n"),
            route.into(),
            400,
        ),
        (format!("{normal}Origin:\r\n"), route.into(), 400),
        (
            format!("{normal}Origin: http://127.0.0.1:{port}\r\n"),
            route.into(),
            400,
        ),
        (
            format!("{normal}Sec-Fetch-Site: same-origin\r\n"),
            route.into(),
            400,
        ),
        (
            format!("{normal}Authorization: Bearer rekey\r\n"),
            route.into(),
            400,
        ),
        (
            format!("{normal}x-api-key: sk-real-key-must-never-forward\r\n"),
            route.into(),
            400,
        ),
        (
            normal.replace("Bearer rekey", "Bearer sk-real-key-must-never-forward"),
            route.into(),
            400,
        ),
        (
            normal.replace("Authorization: Bearer rekey\r\n", ""),
            route.into(),
            400,
        ),
        (
            format!("{normal}Content-Encoding: gzip\r\n"),
            route.into(),
            400,
        ),
        (format!("{normal}Upgrade: websocket\r\n"), route.into(), 400),
        (
            format!("{normal}anthropic-version: wrong\r\n"),
            route.into(),
            400,
        ),
        (
            format!("{normal}x-rekey-approval-challenge: not-a-uuid\r\n"),
            route.into(),
            400,
        ),
        (
            format!("{normal}Transfer-Encoding: chunked\r\n"),
            route.into(),
            400,
        ),
        // An undeclared pass-through header and a repeated one are both refused.
        (format!("{normal}x-unsigned: 1\r\n"), route.into(), 403),
        (
            format!("{normal}Content-Type: application/json\r\n"),
            route.into(),
            403,
        ),
        // Absolute-form targets would let the request line disagree with Host.
        (
            normal.clone(),
            format!("http://127.0.0.1:{port}{route}"),
            400,
        ),
    ];
    for (path, status) in [
        ("/v1/messages", 404),
        ("/p/fixture/v1/messages", 404),
        ("/c/fixture", 404),
        ("/c/nope/v1/messages", 404),
        ("/c/fixture/v1/%6dessages", 403),
        ("/c/fixture//v1/messages", 403),
        ("/c/fixture/v1/../v1/messages", 403),
        ("/c/fixture/v1/messages/", 403),
        ("/c/fixture/v1/complete", 403),
        ("/c/fixture/v1/messages?x=1", 403),
        ("/c/fixture/v1/messages?beta=true&beta=true", 400),
    ] {
        cases.push((normal.clone(), path.into(), status));
    }
    let before = f.counts().0;
    for (headers, path, status) in cases {
        let raw = format!("POST {path} HTTP/1.1\r\n{headers}\r\n{BODY}");
        let (seen, response) = raw_http(port, raw.as_bytes()).await;
        assert_eq!(seen, status, "path={path} headers={headers:?} {response}");
        assert!(
            !response.contains(std::str::from_utf8(SECRET).unwrap()),
            "{response}"
        );
    }
    assert!(f.fake.take_requests().is_empty());
    assert_eq!(started(&f), 0);
    assert_eq!(f.counts().0, before, "a refusal must not write audit rows");

    // Refusals consumed nothing: the same socket path still serves a request
    // whose declared fixed header agrees with the signed value.
    f.fake.push_response(Ok(ok_message()));
    let raw =
        format!("POST {route} HTTP/1.1\r\n{normal}anthropic-version: 2023-06-01\r\n\r\n{BODY}");
    let (status, response) = raw_http(port, raw.as_bytes()).await;
    assert_eq!(status, 200, "{response}");
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].path, "/v1/messages");
    assert_eq!(sent[0].auth_value, SECRET);
    assert_eq!(
        sent[0]
            .headers
            .iter()
            .filter(|(name, _)| name == "anthropic-version")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>(),
        ["2023-06-01"]
    );
    assert_eq!((started(&f), finished(&f)), (1, 1));
    f.finish().await;
}

#[tokio::test]
async fn raw_auth_octets_size_limits_and_body_deadline_fail_before_execution() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "openai").await;
    let port = port(&url);
    let prefix =
        format!("POST /c/fixture/v1/chat/completions HTTP/1.1\r\nHost: localhost:{port}\r\n");
    for value in [
        b"Bearer rekey,other".to_vec(),
        b"Bearer rekey other".to_vec(),
        b"bearer rekey".to_vec(),
        [b"Bearer ".as_slice(), &[0xff]].concat(),
    ] {
        let mut raw = prefix.as_bytes().to_vec();
        raw.extend_from_slice(b"Authorization: ");
        raw.extend(value);
        raw.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (status, response) = raw_http(port, &raw).await;
        assert_eq!(status, 400, "{response}");
    }
    let auth = "Authorization: Bearer rekey\r\nContent-Type: application/json\r\n";
    // Declared and chunked bodies above the signed 1 MiB request bound.
    let over = 1_048_577;
    let raw = format!("{prefix}{auth}Content-Length: {over}\r\n\r\n{{");
    assert_eq!(raw_http(port, raw.as_bytes()).await.0, 400);
    let raw = format!(
        "{prefix}{auth}Transfer-Encoding: chunked\r\n\r\n{over:x}\r\n{}\r\n0\r\n\r\n",
        "x".repeat(over)
    );
    assert_eq!(raw_http(port, raw.as_bytes()).await.0, 400);
    // A complete head above 16 KiB is refused before admission.
    let raw = format!(
        "{prefix}{auth}X-large: {}\r\nContent-Length: {}\r\n\r\n{BODY}",
        "x".repeat(17_000),
        BODY.len()
    );
    assert_eq!(raw_http(port, raw.as_bytes()).await.0, 431);
    // A body that never arrives is bounded by the read deadline; neither a
    // permit nor a durable request exists yet.
    let raw = format!("{prefix}{auth}Content-Length: 2\r\n\r\n{{");
    let begun = std::time::Instant::now();
    assert_eq!(raw_http(port, raw.as_bytes()).await.0, 400);
    assert!(begun.elapsed() >= Duration::from_secs(4));
    assert!(f.fake.take_requests().is_empty());
    assert_eq!(started(&f), 0);
    f.finish().await;
}

#[tokio::test]
async fn get_models_sends_an_empty_body_and_mime_parameters_stay_accepted() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "openai").await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let models = br#"{"data":[]}"#;
    f.fake
        .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())].into(),
            body: models.to_vec().into(),
        }));
    let out = client
        .get(format!("{url}/v1/models"))
        .header("x-api-key", "rekey")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 200);
    assert_eq!(out.bytes().await.unwrap().as_ref(), models);
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].method.as_str(), sent[0].path.as_str()),
        ("GET", "/v1/models")
    );
    assert!(sent[0].body.is_empty());
    assert!(
        sent[0]
            .headers
            .iter()
            .all(|(name, _)| name != "content-type")
    );
    assert_eq!(sent[0].auth_value, [b"Bearer ".as_slice(), SECRET].concat());

    // A GET carrying a body is a different request shape and is refused.
    let out = client
        .get(format!("{url}/v1/models"))
        .bearer_auth("rekey")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 400);
    assert!(f.fake.take_requests().is_empty());

    // SDKs commonly append a charset; the signed JSON contract still applies.
    f.fake.push_response(Ok(rekey_broker::upstream::UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: br#"{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#.to_vec().into(),
    }));
    let out = client
        .post(format!("{url}/v1/chat/completions"))
        .bearer_auth("rekey")
        .header("content-type", "application/json; charset=utf-8")
        .body(BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 200);
    assert_eq!(f.fake.take_requests().len(), 1);
    assert_eq!((started(&f), finished(&f)), (2, 2));
    f.finish().await;
}

#[tokio::test]
async fn anthropic_beta_query_reaches_only_signed_endpoints() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "anthropic").await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (path, reply) in [
        (
            "/v1/messages",
            br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#
                .as_slice(),
        ),
        (
            "/v1/messages/count_tokens",
            br#"{"input_tokens":1}"#.as_slice(),
        ),
    ] {
        for query in ["", "?beta=true"] {
            f.fake
                .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
                    status: 200,
                    headers: vec![("content-type".into(), "application/json".into())].into(),
                    body: reply.to_vec().into(),
                }));
            let out = client
                .post(format!("{url}{path}{query}"))
                .bearer_auth("rekey")
                .header("content-type", "application/json")
                .body(BODY)
                .send()
                .await
                .unwrap();
            assert_eq!(out.status(), 200, "{path}{query}");
            assert_eq!(out.bytes().await.unwrap().as_ref(), reply);
            let sent = f.fake.take_requests();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].path, format!("{path}{query}"));
        }
    }
    // Any other key, and the same key on an undeclared endpoint, is refused.
    for target in [
        "/v1/messages?beta=true&x=1",
        "/v1/messages?debug=true",
        "/v1/complete?beta=true",
    ] {
        let out = client
            .post(format!("{url}{target}"))
            .bearer_auth("rekey")
            .header("content-type", "application/json")
            .body(BODY)
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 403, "{target}");
        assert!(f.fake.take_requests().is_empty());
    }
    assert_eq!((started(&f), finished(&f)), (4, 4));
    f.finish().await;
}

#[tokio::test]
async fn failed_terminal_audit_never_releases_http_completion() {
    let (prefix, tail) = sse("chat");
    let (release, wait) = oneshot::channel();
    let (upstream, _) = transport(
        200,
        vec![format!("{prefix}{prefix}").into_bytes(), tail.into_bytes()],
        Some(wait),
        false,
    );
    let f = Fixture::with_transport(PolicyMode::Personal, true, Some(upstream)).await;
    let url = activate(&f, "openai").await;
    let mut response = tokio::time::timeout(
        Duration::from_secs(30),
        post(&format!("{url}/v1/chat/completions"), true).send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), 200);
    let mut bytes = response.chunk().await.unwrap().unwrap().to_vec();
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_terminal BEFORE INSERT ON audit_events \
             WHEN NEW.event_type='execution.finished' \
             BEGIN SELECT RAISE(ABORT,'synthetic'); END",
        )
        .unwrap();
    release.send(()).unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(30), response.chunk())
            .await
            .expect("a failed terminal audit must end the HTTP response")
        {
            Ok(Some(chunk)) => bytes.extend(chunk),
            Err(_) => break,
            Ok(None) => panic!("a failed terminal audit became a clean HTTP EOF"),
        }
    }
    assert!(!String::from_utf8_lossy(&bytes).contains("[DONE]"));
    assert_eq!((started(&f), finished(&f)), (1, 0));
    // The spec closes later remote-effect admission instead of serving on.
    // 503 keeps SDK clients from reading the refusal as a permission error.
    let refused = post(&format!("{url}/v1/chat/completions"), false)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 503);
    let error = envelope(refused).await;
    assert_eq!(
        (&error["code"], &error["retryable"]),
        (&json!("FAULTED"), &json!(false))
    );
    assert!(
        error["next"].as_str().unwrap().contains("restart"),
        "{error}"
    );
    assert_eq!((started(&f), finished(&f)), (1, 0));
    // A faulted runtime makes no clean shutdown claim.
    f.task.abort();
}

#[tokio::test]
async fn unpublishable_service_file_refuses_startup_instead_of_serving_unannounced() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    rekey_vault::bootstrap::init_vault(
        &state,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
        PolicyMode::Personal,
    )
    .unwrap();
    rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
    // A non-empty directory cannot be replaced by the atomic rename.
    std::fs::create_dir_all(state.join("service.json/occupied")).unwrap();
    let mut config = BrokerConfig::new(state.clone());
    config.transport = Some(Arc::new(FakeUpstreamTransport::new()));
    config.service_port = Some(0);
    let result = tokio::time::timeout(Duration::from_secs(30), serve(config))
        .await
        .expect("startup must fail promptly");
    assert!(result.is_err());
    // A failed start leaves no endpoint behind for a client to wait on.
    for socket in ["runtime/admin.sock", "runtime/agent.sock", "ssh-agent.sock"] {
        assert!(!state.join(socket).exists(), "{socket}");
    }
    assert!(
        std::fs::read_dir(&state).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")),
        "the temporary service file must be removed"
    );
}

#[tokio::test]
async fn locked_vault_answers_locked_not_a_missing_connection() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "openai").await;
    f.call(admin_msg::LOCK, json!({}), &[]).await.ok();
    let before = f.counts().0;
    for request in [
        post(&format!("{url}/v1/chat/completions"), false),
        post(&format!("{url}/v1/chat/completions"), true),
        post(
            &url.replace("/c/fixture", "/c/unknown/v1/chat/completions"),
            false,
        ),
    ] {
        let out = request.send().await.unwrap();
        assert_eq!(out.status(), 503);
        let error = envelope(out).await;
        assert_eq!(error["code"], "LOCKED", "{error}");
        assert!(
            error["next"].as_str().unwrap().contains("await_unlock"),
            "{error}"
        );
    }
    assert!(f.fake.take_requests().is_empty());
    assert_eq!(f.counts().0, before);
    // Unlocking restores the same signed Connection without another activation.
    f.unlock().await;
    f.fake.push_response(Ok(ok_message()));
    let out = post(&format!("{url}/v1/chat/completions"), false)
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 200);
    f.finish().await;
}

#[tokio::test]
async fn fifth_concurrent_call_is_a_retryable_busy_not_a_permission_error() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "openai").await;
    let target = format!("{url}/v1/chat/completions");
    let gates: Vec<_> = (0..4)
        .map(|_| f.fake.push_response_gated(Ok(ok_message())))
        .collect();
    let held: Vec<_> = (0..4)
        .map(|_| tokio::spawn(post(&target, false).send()))
        .collect();
    for _ in 0..3000 {
        if started(&f) == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        started(&f),
        4,
        "four calls must hold the Connection's permits"
    );
    let out = post(&target, false).send().await.unwrap();
    assert_eq!(out.status(), 503);
    let error = envelope(out).await;
    assert_eq!(
        (&error["code"], &error["retryable"]),
        (&json!("AUTHORITY_BUSY"), &json!(true))
    );
    assert!(error["next"].as_str().unwrap().contains("Retry"), "{error}");
    assert_eq!(started(&f), 4, "a busy refusal starts nothing");
    for gate in gates {
        gate.notify_one();
    }
    for call in held {
        assert_eq!(call.await.unwrap().unwrap().status(), 200);
    }
    assert_eq!(f.fake.take_requests().len(), 4);
    // Capacity returns with the terminal audit, so the next call is admitted.
    f.fake.push_response(Ok(ok_message()));
    assert_eq!(post(&target, false).send().await.unwrap().status(), 200);
    assert_eq!((started(&f), finished(&f)), (5, 5));
    f.finish().await;
}

#[tokio::test]
async fn occupied_service_port_names_the_conflict_and_the_fix() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    rekey_vault::bootstrap::init_vault(
        &state,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
        PolicyMode::Personal,
    )
    .unwrap();
    rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
    let occupant = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut config = BrokerConfig::new(state.clone());
    config.transport = Some(Arc::new(FakeUpstreamTransport::new()));
    config.service_port = Some(occupant.local_addr().unwrap().port());
    let error = tokio::time::timeout(Duration::from_secs(30), serve(config))
        .await
        .expect("startup must fail promptly")
        .unwrap_err();
    assert_eq!(error.code(), "SERVICE_PORT_IN_USE");
    assert!(
        error.to_string().contains("port is already in use"),
        "{error}"
    );
    assert!(!state.join("runtime/admin.sock").exists());
    assert!(
        !state.join("service.json").exists(),
        "a refused port is not published"
    );
}
