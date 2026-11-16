//! Default Connection HTTP contracts. No Profile session or real provider is used.
use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rekey_broker::upstream::{
    UpstreamBody, UpstreamChunkFuture, UpstreamError, UpstreamFuture, UpstreamRequest,
    UpstreamStreamFuture, UpstreamStreamResponse, UpstreamTransport,
};
use rekey_domain::connection::ConnectionLlmLimits;
use tokio::sync::oneshot;

const SECRET: &[u8] = b"synthetic-connection-token";

async fn activate(f: &Fixture, preset: &str) -> String {
    let mut connection = rekey_policy::presets::builtin_preset(preset)
        .unwrap()
        .connection("fixture".into(), f.seed().await.credential_id);
    connection.llm = Some(ConnectionLlmLimits {
        models: ["synthetic-model".into()].into_iter().collect(),
        max_tokens: 32,
        max_requests_per_day: 20,
        max_output_tokens_per_day: 1000,
    });
    let draft = f.draft(vec![connection]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    format!("{}/c/fixture", list.service_url.unwrap())
}

fn post(url: &str, stream: bool) -> reqwest::RequestBuilder {
    let body = if url.ends_with("/responses") {
        json!({"model":"synthetic-model","input":"test","max_output_tokens":16,"stream":stream})
    } else {
        json!({"model":"synthetic-model","messages":[{"role":"user","content":"test"}],"max_tokens":16,"stream":stream})
    };
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(url)
        .bearer_auth("rekey")
        .header("content-type", "application/json")
        .body(body.to_string())
}

fn finished(f: &Fixture) -> i64 {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='execution.finished'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn buffered_errors_preserve_safe_headers_and_inject_one_provider_authentication() {
    for (preset, path, auth, prefix) in [
        ("anthropic", "/v1/messages", "x-api-key", ""),
        ("openai", "/v1/chat/completions", "authorization", "Bearer "),
    ] {
        let f = Fixture::new(PolicyMode::Personal, true).await;
        let url = activate(&f, preset).await;
        let body = br#"{"error":{"message":"try later"}}"#;
        f.fake
            .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
                status: 429,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("retry-after".into(), "30".into()),
                    ("set-cookie".into(), "private-session".into()),
                ]
                .into(),
                body: body.to_vec().into(),
            }));
        let response = post(&format!("{url}{path}"), false).send().await.unwrap();
        assert_eq!(response.status(), 429);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(response.headers()["retry-after"], "30");
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.bytes().await.unwrap().as_ref(), body);
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].auth_name, auth);
        assert_eq!(requests[0].auth_value, [prefix.as_bytes(), SECRET].concat());
        assert!(
            requests[0]
                .headers
                .iter()
                .all(|(name, _)| name != "authorization" && name != "x-api-key")
        );
        assert_eq!(finished(&f), 1);
        f.finish().await;
    }
}

struct StreamBody {
    chunks: VecDeque<Vec<u8>>,
    release: Option<oneshot::Receiver<()>>,
    ended: Arc<AtomicBool>,
    fail: bool,
}
impl UpstreamBody for StreamBody {
    fn next_chunk(&mut self) -> UpstreamChunkFuture<'_> {
        Box::pin(async {
            if self.chunks.len() <= 1
                && let Some(release) = self.release.take()
            {
                release.await.unwrap();
            }
            if let Some(chunk) = self.chunks.pop_front() {
                return Ok(Some(chunk.into()));
            }
            self.ended.store(true, Ordering::SeqCst);
            if self.fail {
                Err(UpstreamError::Transport)
            } else {
                Ok(None)
            }
        })
    }
}
struct StreamTransport {
    response: Mutex<Option<UpstreamStreamResponse>>,
    auth_names: Mutex<Vec<String>>,
}
impl UpstreamTransport for StreamTransport {
    fn send(&self, _: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async { panic!("streaming requests must not use buffered transport") })
    }
    fn open_stream(&self, request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        Box::pin(async move {
            assert!(
                request
                    .headers
                    .iter()
                    .all(|(name, _)| name != "authorization" && name != "x-api-key")
            );
            let expected = if request.auth_header.0 == "x-api-key" {
                SECRET.to_vec()
            } else {
                [b"Bearer ".as_slice(), SECRET].concat()
            };
            assert_eq!(request.auth_header.1.as_slice(), expected);
            self.auth_names
                .lock()
                .unwrap()
                .push(request.auth_header.0.clone());
            Ok(self
                .response
                .lock()
                .unwrap()
                .take()
                .expect("exactly one upstream call"))
        })
    }
}
fn transport(
    status: u16,
    chunks: Vec<Vec<u8>>,
    release: Option<oneshot::Receiver<()>>,
    fail: bool,
) -> (Arc<StreamTransport>, Arc<AtomicBool>) {
    let ended = Arc::new(AtomicBool::new(false));
    (
        Arc::new(StreamTransport {
            response: Mutex::new(Some(UpstreamStreamResponse {
                status,
                headers: vec![
                    (
                        "content-type".into(),
                        if status == 200 {
                            "text/event-stream"
                        } else {
                            "application/json"
                        }
                        .into(),
                    ),
                    ("retry-after".into(), "30".into()),
                ]
                .into(),
                body: Box::new(StreamBody {
                    chunks: chunks.into(),
                    release,
                    ended: ended.clone(),
                    fail,
                }),
            })),
            auth_names: Mutex::new(Vec::new()),
        }),
        ended,
    )
}

fn sse(protocol: &str) -> (String, String) {
    let text = "safe output ".repeat(1024);
    let event = |v: Value| format!("data: {v}\n\n");
    match protocol {
        "messages" => (
            event(
                json!({"type":"message_start","message":{"id":"m","type":"message","content":[],"usage":{"output_tokens":0}}}),
            ) + &event(
                json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            ) + &event(
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}}),
            ),
            event(json!({"type":"content_block_stop","index":0}))
                + &event(
                    json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}),
                )
                + &event(json!({"type":"message_stop"})),
        ),
        "responses" => (
            event(json!({"type":"response.created","response":{"id":"r","output":[]}}))
                + &event(
                    json!({"type":"response.output_text.delta","item_id":"i","output_index":0,"content_index":0,"delta":text}),
                ),
            event(
                json!({"type":"response.completed","response":{"id":"r","status":"completed","usage":{"output_tokens":7}}}),
            ),
        ),
        _ => (
            event(
                json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":text},"finish_reason":null}]}),
            ),
            event(
                json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
            ) + &event(
                json!({"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"completion_tokens":7}}),
            ) + "data: [DONE]\n\n",
        ),
    }
}

#[tokio::test]
async fn three_protocols_stream_before_upstream_finishes_and_settle_before_http_eof() {
    for (preset, path, protocol) in [
        ("anthropic", "/v1/messages", "messages"),
        ("openai", "/v1/chat/completions", "chat"),
        ("openai", "/v1/responses", "responses"),
        ("glm", "/api/anthropic/v1/messages", "messages"),
        ("glm-responses", "/api/v1/responses", "responses"),
    ] {
        let (mut prefix, tail) = sse(protocol);
        let more = "more safe ".repeat(200);
        let delta = match protocol {
            "messages" => {
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":more}})
            }
            "responses" => {
                json!({"type":"response.output_text.delta","item_id":"i","output_index":0,"content_index":0,"delta":more})
            }
            _ => {
                json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":more},"finish_reason":null}]})
            }
        };
        prefix += &format!("data: {delta}\n\n");
        let expected = format!("{prefix}{tail}");
        let (release, wait) = oneshot::channel();
        let (upstream, ended) = transport(
            200,
            vec![prefix.into_bytes(), tail.into_bytes()],
            Some(wait),
            false,
        );
        let f = Fixture::with_transport(PolicyMode::Personal, true, Some(upstream.clone())).await;
        let url = activate(&f, preset).await;
        let mut response = tokio::time::timeout(
            Duration::from_secs(3),
            post(&format!("{url}{path}"), true).send(),
        )
        .await
        .unwrap_or_else(|_| panic!("{preset}/{path}: response must start before upstream release"))
        .unwrap();
        assert_eq!(response.status(), 200, "{preset}/{path}");
        assert_eq!(
            response.headers()["content-type"],
            "text/event-stream; charset=utf-8"
        );
        let mut bytes = tokio::time::timeout(Duration::from_secs(3), response.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .to_vec();
        assert!(!bytes.is_empty());
        assert!(!ended.load(Ordering::SeqCst));
        assert_eq!(finished(&f), 0);
        let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        release.send(()).unwrap();
        loop {
            match tokio::time::timeout(Duration::from_millis(100), response.chunk()).await {
                Ok(Ok(Some(chunk))) => bytes.extend(chunk),
                Err(_) => break,
                other => panic!("HTTP must wait for durable terminal audit: {other:?}"),
            }
        }
        assert_eq!(finished(&f), 0);
        let visible = String::from_utf8_lossy(&bytes);
        for terminal in ["[DONE]", "message_stop", "response.completed"] {
            assert!(!visible.contains(terminal));
        }
        db.execute_batch("COMMIT").unwrap();
        while let Some(chunk) = response.chunk().await.unwrap() {
            bytes.extend(chunk);
        }
        assert_eq!(bytes, expected.as_bytes());
        assert!(ended.load(Ordering::SeqCst));
        assert_eq!(finished(&f), 1);
        assert_eq!(upstream.auth_names.lock().unwrap().len(), 1);
        f.finish().await;
    }
}

#[tokio::test]
async fn upstream_cut_after_prefix_aborts_http_without_a_success_terminal() {
    let (prefix, _) = sse("chat");
    let (release, wait) = oneshot::channel();
    let (upstream, _) = transport(
        200,
        vec![format!("{prefix}{prefix}").into_bytes(), Vec::new()],
        Some(wait),
        true,
    );
    let f = Fixture::with_transport(PolicyMode::Personal, true, Some(upstream)).await;
    let url = activate(&f, "openai").await;
    let mut response = tokio::time::timeout(
        Duration::from_secs(3),
        post(&format!("{url}/v1/chat/completions"), true).send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), 200);
    let mut bytes = response.chunk().await.unwrap().unwrap().to_vec();
    release.send(()).unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(3), response.chunk())
            .await
            .unwrap()
        {
            Ok(Some(chunk)) => bytes.extend(chunk),
            Err(_) => break,
            Ok(None) => panic!("truncated upstream must not become a successful HTTP EOF"),
        }
    }
    assert!(!String::from_utf8_lossy(&bytes).contains("[DONE]"));
    assert_eq!(finished(&f), 0);
    f.finish().await;
}

#[tokio::test]
async fn streaming_errors_keep_status_headers_and_seal_reflected_credentials() {
    for reflected in [false, true] {
        let body = if reflected {
            SECRET.to_vec()
        } else {
            br#"{"error":{"message":"try later"}}"#.to_vec()
        };
        let (upstream, _) = transport(429, vec![body.clone()], None, false);
        let f = Fixture::with_transport(PolicyMode::Personal, true, Some(upstream)).await;
        let url = activate(&f, "openai").await;
        let response = post(&format!("{url}/v1/chat/completions"), true)
            .send()
            .await
            .unwrap();
        if reflected {
            assert_eq!(response.status(), 502);
            let body = response.bytes().await.unwrap();
            assert!(!body.windows(SECRET.len()).any(|v| v == SECRET));
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["code"], "RESPONSE_BLOCKED");
            assert_eq!(error["retryable"], false);
        } else {
            assert_eq!(response.status(), 429);
            assert_eq!(response.headers()["retry-after"], "30");
            assert_eq!(response.headers()["content-type"], "application/json");
            assert_eq!(response.bytes().await.unwrap().as_ref(), body);
            assert_eq!(finished(&f), 1);
        }
        f.finish().await;
    }
}

#[tokio::test]
async fn legacy_route_duplicate_auth_and_unsigned_model_never_reach_upstream() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "openai").await;
    for (request, status) in [
        (
            post(
                &url.replace("/c/fixture", "/p/work/v1/chat/completions"),
                true,
            ),
            404,
        ),
        (
            post(&format!("{url}/v1/chat/completions"), true)
                .header("authorization", "Bearer rekey"),
            400,
        ),
        (
            reqwest::Client::new()
                .post(format!("{url}/v1/chat/completions"))
                .bearer_auth("rekey")
                .header("content-type", "application/json")
                .body(json!({"model":"unsigned-model","messages":[],"stream":true}).to_string()),
            403,
        ),
    ] {
        assert_eq!(request.send().await.unwrap().status().as_u16(), status);
        assert!(f.fake.take_requests().is_empty());
    }
    f.finish().await;
}
