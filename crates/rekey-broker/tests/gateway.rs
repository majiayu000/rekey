#![cfg(feature = "lab")]
//! Real loopback HTTP and UDS control, real Authority, synthetic upstream only.
mod common;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    UpstreamBody, UpstreamChunkFuture, UpstreamError, UpstreamFuture, UpstreamRequest,
    UpstreamResponse, UpstreamStreamFuture, UpstreamStreamResponse, UpstreamTransport,
};
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::ids::{PolicyRuleId, PrincipalId, RequestId};
use rekey_domain::ipc::{
    self, Channel, FrameHeader, ProfileSessionCreatedResponse, admin_msg, agent_msg,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Notify;

const SECRET: &[u8] = b"SYNTHETIC-GATEWAY-CREDENTIAL";
const BODY: &[u8] =
    br#"{"model":"allowed","tools":[{"name":"tool"}],"thinking":{"type":"enabled"}}"#;
const CHAT:&[u8]=br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#;
struct StreamReply {
    status: u16,
    headers: Vec<(String, String)>,
    chunks: VecDeque<Vec<u8>>,
    eof: Option<Arc<Notify>>,
    fail: bool,
}
impl UpstreamBody for StreamReply {
    fn next_chunk(&mut self) -> UpstreamChunkFuture<'_> {
        Box::pin(async {
            if let Some(chunk) = self.chunks.pop_front() {
                return Ok(Some(chunk.into()));
            }
            if let Some(gate) = self.eof.take() {
                gate.notified().await;
            }
            if self.fail {
                Err(UpstreamError::Transport)
            } else {
                Ok(None)
            }
        })
    }
}
struct Transport {
    fake: Arc<FakeUpstreamTransport>,
    streams: Mutex<VecDeque<StreamReply>>,
    raw_sent: Mutex<Vec<Vec<u8>>>,
    raw_paths: Mutex<Vec<String>>,
}
impl Transport {
    fn push(&self, raw: &[u8], eof: Option<Arc<Notify>>, fail: bool) {
        self.streams.lock().unwrap().push_back(StreamReply {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            chunks: raw.chunks(7).map(<[u8]>::to_vec).collect(),
            eof,
            fail,
        });
    }
}
impl UpstreamTransport for Transport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        self.fake.send(request)
    }
    fn open_stream(&self, request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        Box::pin(async move {
            self.raw_sent.lock().unwrap().push(request.body.to_vec());
            self.raw_paths.lock().unwrap().push(request.path.clone());
            assert_eq!(
                request.auth_header.1.as_slice(),
                if request.auth_header.0 == "x-api-key" {
                    SECRET.to_vec()
                } else {
                    [b"Bearer ".as_slice(), SECRET].concat()
                }
            );
            let mut body = self
                .streams
                .lock()
                .unwrap()
                .pop_front()
                .expect("queued synthetic stream");
            Ok(UpstreamStreamResponse {
                status: body.status,
                headers: std::mem::take(&mut body.headers).into(),
                body: Box::new(body),
            })
        })
    }
}
struct Fixture {
    broker: common::TestBroker,
    transport: Arc<Transport>,
    actions: Vec<FixedHttpAction>,
    snapshot: Value,
}
impl Fixture {
    async fn new(
        provider: &str,
        capability: &str,
        max_uses: u32,
        budget: u64,
        approval: bool,
    ) -> Self {
        let fake = Arc::new(FakeUpstreamTransport::new());
        let transport = Arc::new(Transport {
            fake: fake.clone(),
            streams: Mutex::new(VecDeque::new()),
            raw_sent: Mutex::new(Vec::new()),
            raw_paths: Mutex::new(Vec::new()),
        });
        let broker = common::start_broker_with_transport(
            Duration::from_secs(300),
            Duration::from_secs(2),
            fake,
            transport.clone(),
        )
        .await;
        assert!(!broker.state_dir.join("gateway.port").exists());
        common::unlock(&broker).await;
        assert!(!broker.state_dir.join("gateway.port").exists());
        let credential = common::add_credential(&broker, "gateway-fixture", SECRET).await;
        let install = json!({"source":{"kind":provider},"credential_id":credential,"bindings":[{}],"capabilities":[capability],"name_prefix":"gateway","timeout_ms":2000,"request_max_bytes":4096,"allowed_extra_headers":["x-test","anthropic-beta"],"response_max_bytes":65536,"allowed_response_headers":["content-type","retry-after"]});
        let response = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::TEMPLATE_INSTALL,
            &serde_json::to_vec(&install).unwrap(),
            &common::proof_and_secret_body(common::PASSWORD, b""),
        )
        .await;
        let actions = response.ok()["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| serde_json::from_value(a["action"].clone()).unwrap())
            .collect::<Vec<FixedHttpAction>>();
        let principal = PrincipalId::new_random();
        let refs: Vec<_> = actions
            .iter()
            .map(|a| json!({"action_id":a.id,"version":a.version}))
            .collect();
        let mut rules:Vec<_>=actions.iter().map(|a|json!({"id":PolicyRuleId::new_random(),"effect":"permit","principal_id":principal,"action_id":a.id,"version":a.version,"resource":{"type":"gateway","id":a.id},"parameters":{"kind":"any_validated"}})).collect();
        if approval {
            for rule in &mut rules {
                rule["effect"] = json!("require-approval");
                rule["approver"] = json!({"kind":"local-presence"});
                rule["approval"] = json!({"mode":"one-time","max_uses":1});
            }
        }
        let snapshot = json!({"format_version":8,"version":1,"expires_at_ms":4_102_444_800_000_i64,"approvers":[],"workload_identities":[],
            "connections":[], "ssh_keys":[], "profiles":[{"name":"test","principal_id":principal,"grants":[{"instance":"work","capabilities":[{"rule":"template-default","capability":capability,"actions":refs}]}],"session":{"ttl_ms":60000,"max_uses":max_uses},"confirm_each_run":false,"isolation":"none","egress":"allow","llm_limits":[{"instance":"work","models":["allowed"],"max_output_tokens_per_request":20,"max_requests_per_day":100,"max_output_tokens_per_day":budget}]}],
            "bindings":actions.iter().map(|a|json!({"action_id":a.id,"version":a.version,"resource":{"type":"gateway","id":a.id},"parameter_schema_id":"any/v1","parameter_schema":{}})).collect::<Vec<_>>(),"rules":rules});
        common::policy::activate_snapshot(&broker, snapshot.clone()).await;
        Self {
            broker,
            transport,
            actions,
            snapshot,
        }
    }
    async fn mint(&self) -> (UnixStream, ProfileSessionCreatedResponse) {
        let mut stream = UnixStream::connect(self.broker.admin_sock()).await.unwrap();
        let metadata = br#"{"profile":"test"}"#;
        let h = FrameHeader {
            channel: Channel::Admin,
            flags: 0,
            message_type: admin_msg::PROFILE_SESSION_CREATE,
            request_id: RequestId::new_random(),
            metadata_len: metadata.len() as u32,
            body_len: 0,
        };
        stream.write_all(&h.encode()).await.unwrap();
        stream.write_all(metadata).await.unwrap();
        let mut h = [0; ipc::FRAME_HEADER_LEN];
        stream.read_exact(&mut h).await.unwrap();
        let h = FrameHeader::decode(&h).unwrap();
        let mut meta = vec![0; h.metadata_len as usize];
        let mut body = vec![0; h.body_len as usize];
        stream.read_exact(&mut meta).await.unwrap();
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(
            h.message_type,
            ipc::resp_msg::OK,
            "{}",
            String::from_utf8_lossy(&meta)
        );
        (stream, serde_json::from_slice(&body).unwrap())
    }
    fn url(&self, s: &ProfileSessionCreatedResponse) -> String {
        let ActionTarget::Template { target, .. } = &self.actions[0].target else {
            panic!()
        };
        format!(
            "http://127.0.0.1:{}/p/work{}",
            s.gateway.as_ref().unwrap().port,
            target
                .path_pattern()
                .strip_prefix("/api/anthropic")
                .or_else(|| target.path_pattern().strip_prefix("/api"))
                .unwrap_or(target.path_pattern())
        )
    }
    fn post(&self, s: &ProfileSessionCreatedResponse, body: &[u8]) -> reqwest::RequestBuilder {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(self.url(s))
            .bearer_auth(format!("rkc_{}", s.session.capability_token))
            .header("content-type", "application/json")
            .body(body.to_vec())
    }
    fn response(&self, body: &[u8]) {
        self.broker.fake.push_response(Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())].into(),
            body: body.to_vec().into(),
        }));
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.broker.state_dir)).unwrap()
    }
    fn totals(&self) -> (u64, u64, u64) {
        self.db().query_row("SELECT count(*),coalesce(sum(output_tokens),0),sum(CASE WHEN output_tokens IS NULL THEN 1 ELSE 0 END) FROM profile_usage",[],|r|Ok((r.get(0)?,r.get(1)?,r.get::<_,Option<u64>>(2)?.unwrap_or(0)))).unwrap()
    }
    async fn settled(&self, n: u64) {
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let (count, _, pending) = self.totals();
                if count == n && pending == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn buffered_three_protocols_use_actual_profile_and_one_effective_body() {
    for (provider, capability, response, bound) in [
        ("openai", "chat-completions", CHAT, "max_completion_tokens"),
        (
            "openai",
            "responses",
            br#"{"status":"completed","usage":{"output_tokens":7}}"#.as_slice(),
            "max_output_tokens",
        ),
        (
            "anthropic",
            "messages",
            br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#
                .as_slice(),
            "max_tokens",
        ),
        (
            "glm",
            "messages",
            br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#
                .as_slice(),
            "max_tokens",
        ),
    ] {
        let f = Fixture::new(provider, capability, 1, 100, false).await;
        let (owner, s) = f.mint().await;
        assert_eq!(s.gateway.as_ref().unwrap().instances[0].instance, "work");
        // The public discovery cache cannot redirect the authenticated endpoint.
        std::fs::write(f.broker.state_dir.join("gateway.port"), "1\n").unwrap();
        f.response(response);
        let out = f
            .post(&s, BODY)
            .header("x-test", "allowed")
            .header("anthropic-beta", "declared-only")
            .header("x-ignored", "not-forwarded")
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 200);
        assert_eq!(out.bytes().await.unwrap().as_ref(), response);
        assert_eq!(f.totals(), (1, 7, 0));
        let sent = f.broker.fake.take_requests();
        assert_eq!(sent.len(), 1);
        if provider == "glm" {
            assert_eq!(sent[0].host, "open.bigmodel.cn");
            assert_eq!(sent[0].path, "/api/anthropic/v1/messages");
            assert_eq!(sent[0].auth_name, "x-api-key");
            assert_eq!(sent[0].auth_value, SECRET);
        }
        let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(body[bound], 20);
        assert_eq!(body["tools"][0]["name"], "tool");
        assert!(
            sent[0]
                .headers
                .contains(&("x-test".into(), "allowed".into()))
        );
        assert!(
            sent[0]
                .headers
                .contains(&("anthropic-beta".into(), "declared-only".into()))
        );
        assert!(
            !sent[0]
                .headers
                .iter()
                .any(|(k, _)| k == "authorization" || k == "x-api-key" || k == "x-ignored")
        );
        assert_eq!(f.post(&s, BODY).send().await.unwrap().status(), 403);
        assert!(f.broker.fake.take_requests().is_empty());
        drop(owner);
        f.broker.shutdown().await;
    }
}
fn raw(provider: &str) -> String {
    match provider {
        "chat-completions" => format!(
            "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
            json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"safe tools output"},"finish_reason":"stop"}]}),
            json!({"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"completion_tokens":7}})
        ),
        "responses" => format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\n",
            json!({"type":"response.created","response":{"id":"r","output":[]}}),
            json!({"type":"response.custom_tool_call_input.delta","output_index":0,"item_id":"tool","delta":"safe apply_patch"}),
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}})
        ),
        _ => format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\ndata: {}\n\ndata: {}\n\ndata: {}\n\n",
            json!({"type":"message_start","message":{"id":"m","type":"message","content":[],"usage":{"output_tokens":0}}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"safe thinking"}}),
            json!({"type":"content_block_stop","index":0}),
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}),
            json!({"type":"message_stop"})
        ),
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn streaming_http_errors_preserve_status_headers_and_body_only_after_sealing() {
    let f = Fixture::new("anthropic", "messages", 10, 1000, false).await;
    let (owner, session) = f.mint().await;
    let request =
        br#"{"model":"allowed","stream":true,"messages":[{"role":"user","content":"test"}]}"#;
    let error = br#"{"type":"error","error":{"type":"rate_limit_error","message":"try later"}}"#;
    for status in [429, 529] {
        f.transport.streams.lock().unwrap().push_back(StreamReply {
            status,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("retry-after".into(), "30".into()),
                ("set-cookie".into(), "must-not-forward".into()),
            ],
            chunks: error.chunks(7).map(<[u8]>::to_vec).collect(),
            eof: None,
            fail: false,
        });
        let response = f.post(&session, request).send().await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["retry-after"], "30");
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.bytes().await.unwrap().as_ref(), error);
    }
    f.settled(2).await;
    assert_eq!(f.totals(), (2, 40, 0));
    assert_eq!(f.db().query_row("SELECT count(*) FROM audit_events WHERE event_type='execution.finished' AND upstream_status IN (429,529)", [], |r|r.get::<_,u64>(0)).unwrap(), 2);
    for (body, header, fail, status, code, retryable) in [
        (
            SECRET.to_vec(),
            ("x-not-allowlisted", "safe"),
            false,
            502,
            "RESPONSE_SECURITY_VIOLATION",
            false,
        ),
        (
            error.to_vec(),
            ("x-not-allowlisted", std::str::from_utf8(SECRET).unwrap()),
            false,
            502,
            "RESPONSE_SECURITY_VIOLATION",
            false,
        ),
        (
            error.to_vec(),
            ("retry-after", std::str::from_utf8(SECRET).unwrap()),
            false,
            502,
            "RESPONSE_SECURITY_VIOLATION",
            false,
        ),
        (
            vec![b'x'; 65537],
            ("retry-after", "30"),
            false,
            403,
            "RESPONSE_TOO_LARGE",
            false,
        ),
        (
            error.to_vec(),
            ("retry-after", "30"),
            true,
            502,
            "UPSTREAM_FAILED",
            true,
        ),
    ] {
        f.transport.streams.lock().unwrap().push_back(StreamReply {
            status: 429,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                (header.0.into(), header.1.into()),
            ],
            chunks: body.chunks(7).map(<[u8]>::to_vec).collect(),
            eof: None,
            fail,
        });
        let response = f.post(&session, request).send().await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert!(!response.headers().contains_key("retry-after"));
        let body = response.bytes().await.unwrap();
        assert!(!body.windows(SECRET.len()).any(|s| s == SECRET));
        assert!(!body.windows(error.len()).any(|s| s == error));
        let envelope: ipc::ErrorEnvelope = serde_json::from_slice(&body).unwrap();
        assert_eq!(envelope.code, code);
        assert_eq!(envelope.retryable, retryable);
    }
    f.settled(7).await;
    assert_eq!(f.totals(), (7, 140, 0));
    assert_eq!(f.transport.raw_sent.lock().unwrap().len(), 7);
    drop(owner);
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn stream_security_failure_before_first_chunk_preserves_nonretryable_error() {
    let f = Fixture::new("anthropic", "messages", 3, 1000, false).await;
    let (owner, session) = f.mint().await;
    let request =
        br#"{"model":"allowed","stream":true,"messages":[{"role":"user","content":"test"}]}"#;
    let raw = format!(
        "data: {}\n\n",
        json!({"type":"message_start","message":{"id":std::str::from_utf8(SECRET).unwrap(),"content":[]}})
    );
    for (body, header) in [
        (raw.as_bytes(), "safe"),
        (b"".as_slice(), std::str::from_utf8(SECRET).unwrap()),
    ] {
        f.transport.streams.lock().unwrap().push_back(StreamReply {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/event-stream".into()),
                ("x-unlisted".into(), header.into()),
            ],
            chunks: body.chunks(7).map(<[u8]>::to_vec).collect(),
            eof: None,
            fail: false,
        });
        let response = f.post(&session, request).send().await.unwrap();
        assert_eq!(response.status(), 502);
        let bytes = response.bytes().await.unwrap();
        assert!(!bytes.windows(SECRET.len()).any(|value| value == SECRET));
        let envelope: ipc::ErrorEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.code, "RESPONSE_SECURITY_VIOLATION");
        assert!(!envelope.retryable);
    }
    f.settled(2).await;
    assert_eq!(f.totals(), (2, 40, 0));
    assert_eq!(f.transport.raw_sent.lock().unwrap().len(), 2);
    drop(owner);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn glm_gateway_rejects_undeclared_paths_and_models_before_upstream() {
    let f = Fixture::new("glm", "messages", 10, 100, false).await;
    let (owner, s) = f.mint().await;
    assert_eq!(
        s.gateway.as_ref().unwrap().instances[0].provider,
        rekey_domain::ipc::ProfileGatewayProvider::Anthropic
    );
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for path in [
        "/api/anthropic/v1/messages",
        "/v1/models",
        "/v1/messages/count_tokens",
        "/v1/messages?beta=false",
    ] {
        let response = client
            .post(format!(
                "http://127.0.0.1:{}/p/work{path}",
                s.gateway.as_ref().unwrap().port
            ))
            .bearer_auth(format!("rkc_{}", s.session.capability_token))
            .header("content-type", "application/json")
            .body(BODY.to_vec())
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success(), "{path}");
    }
    let mut wrong_model: Value = serde_json::from_slice(BODY).unwrap();
    wrong_model["model"] = json!("unapproved");
    assert_eq!(
        f.post(&s, &serde_json::to_vec(&wrong_model).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(f.totals(), (0, 0, 0));
    drop(owner);
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn glm_responses_uses_only_fixed_bearer_route_and_shared_limits() {
    let f = Fixture::new("glm-responses", "responses", 10, 100, false).await;
    let (owner, session) = f.mint().await;
    assert_eq!(
        session.gateway.as_ref().unwrap().instances[0].provider,
        rekey_domain::ipc::ProfileGatewayProvider::OpenAi
    );
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for path in [
        "/api/v1/responses",
        "/v1/messages",
        "/v1/models",
        "/v1/responses/other",
        "/v1/responses?beta=true",
    ] {
        let response = client
            .post(format!(
                "http://127.0.0.1:{}/p/work{path}",
                session.gateway.as_ref().unwrap().port
            ))
            .bearer_auth(format!("rkc_{}", session.session.capability_token))
            .header("content-type", "application/json")
            .body(BODY.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{path}");
    }
    for body in [
        br#"{"model":"unapproved","input":"test"}"#.as_slice(),
        br#"{"model":"allowed","max_output_tokens":21,"input":"test"}"#.as_slice(),
    ] {
        assert_eq!(f.post(&session, body).send().await.unwrap().status(), 403);
    }
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(f.totals(), (0, 0, 0));
    f.response(br#"{"status":"completed","usage":{"output_tokens":7}}"#);
    assert_eq!(
        f.post(&session, br#"{"model":"allowed","input":"test"}"#)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let sent = f.broker.fake.take_requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].host, "open.bigmodel.cn");
    assert_eq!(sent[0].path, "/api/v1/responses");
    assert_eq!(sent[0].auth_name, "authorization");
    assert_eq!(sent[0].auth_value, [b"Bearer ".as_slice(), SECRET].concat());
    assert_eq!(
        serde_json::from_slice::<Value>(&sent[0].body).unwrap()["max_output_tokens"],
        20
    );
    assert_eq!(f.totals(), (1, 7, 0));
    drop(owner);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_three_protocols_preserve_exact_bytes_and_settle_before_http_eof() {
    for (provider, capability, query) in [
        ("openai", "chat-completions", ""),
        ("openai", "responses", ""),
        ("glm-responses", "responses", ""),
        ("anthropic", "messages", ""),
        ("anthropic", "messages", "?beta=true"),
        ("glm", "messages", ""),
        ("glm", "messages", "?beta=true"),
    ] {
        let f = Fixture::new(provider, capability, 2, 100, false).await;
        let (owner, s) = f.mint().await;
        let raw = raw(capability);
        f.transport.push(raw.as_bytes(), None, false);
        let mut body: Value = serde_json::from_slice(BODY).unwrap();
        body["stream"] = json!(true);
        let request = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}{query}", f.url(&s)))
            .bearer_auth(format!("rkc_{}", s.session.capability_token))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap());
        let out = request.send().await.unwrap();
        assert_eq!(out.status(), 200, "{provider}/{capability}");
        assert_eq!(
            out.headers()["content-type"],
            "text/event-stream; charset=utf-8"
        );
        assert_eq!(out.bytes().await.unwrap().as_ref(), raw.as_bytes());
        assert_eq!(f.totals(), (1, 7, 0));
        assert_eq!(f.transport.raw_sent.lock().unwrap().len(), 1);
        let ActionTarget::Template { target, .. } = &f.actions[0].target else {
            panic!()
        };
        assert_eq!(
            *f.transport.raw_paths.lock().unwrap(),
            vec![format!("{}{query}", target.path_pattern())]
        );
        drop(owner);
        f.broker.shutdown().await;
    }
}
async fn raw_http(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(raw).await.unwrap();
    let mut output = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(7), socket.read_to_end(&mut output))
        .await
        .unwrap();
    output
}
#[tokio::test(flavor = "multi_thread")]
async fn raw_socket_ambiguous_headers_paths_and_bodies_never_reach_upstream() {
    let f = Fixture::new("anthropic", "messages", 100, 1000, false).await;
    let (owner, s) = f.mint().await;
    let port = s.gateway.as_ref().unwrap().port;
    let token = format!("rkc_{}", s.session.capability_token);
    let normal = format!(
        "Host: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
    );
    let mut cases = vec![
        (
            normal.replace(&format!("127.0.0.1:{port}"), "evil.example"),
            "/p/work/v1/messages".to_owned(),
            400,
        ),
        (
            format!("{normal}Host: localhost:{port}\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}Origin:\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}x-api-key: {token}\r\n"),
            "/p/work/v1/messages".into(),
            401,
        ),
        (
            format!("{normal}Authorization: Bearer {token}\r\n"),
            "/p/work/v1/messages".into(),
            401,
        ),
        (
            normal.replace(&token, "actual-real-key-must-never-forward"),
            "/p/work/v1/messages".into(),
            401,
        ),
        (
            format!("{normal}Content-Type: application/json\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}Content-Encoding: gzip\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}Upgrade: websocket\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}anthropic-version: wrong\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}x-rekey-approval-challenge: not-a-uuid\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            format!("{normal}Transfer-Encoding: chunked\r\n"),
            "/p/work/v1/messages".into(),
            400,
        ),
        (
            normal.replace("Content-Length: 2", "Content-Length: 5000"),
            "/p/work/v1/messages".into(),
            400,
        ),
    ];
    for path in [
        "/v1/messages",
        "/p/nope/v1/messages",
        "/p/work/v1/%6dessages",
        "/p/work//v1/messages",
        "/p/work/v1/../v1/messages",
        "/p/work/v1/messages?",
        "/p/work/v1/messages?x=1",
        "/p/work/v1/messages?beta=false",
        "/p/work/v1/messages?beta=TRUE",
        "/p/work/v1/messages?beta=true&beta=true",
        "/p/work/v1/messages?beta=true&x=1",
        "/p/work/v1/messages?%62eta=true",
        "/p/work/v1/messages?beta=%74rue",
        "/p/work/v1/messages?beta=true&",
    ] {
        cases.push((normal.clone(), path.to_owned(), 404));
    }
    cases.push((
        normal.clone(),
        format!("http://127.0.0.1:{port}/p/work/v1/messages"),
        400,
    ));
    for (headers, path, status) in cases {
        let raw = format!("POST {path} HTTP/1.1\r\n{headers}\r\n{{}}");
        let response = raw_http(port, raw.as_bytes()).await;
        assert!(
            String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status}")),
            "path={path} expected={status} response={}",
            String::from_utf8_lossy(&response)
        );
    }
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(f.totals(), (0, 0, 0));
    // Rejections did not consume a capability use; a declared fixed header agrees.
    f.response(br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#);
    assert_eq!(
        f.post(&s, BODY)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    drop(owner);
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn agent_and_http_share_daily_budget_across_reissued_capabilities() {
    let f = Fixture::new("openai", "chat-completions", 10, 14, false).await;
    let (owner, s) = f.mint().await;
    f.response(CHAT);
    assert_eq!(f.post(&s, BODY).send().await.unwrap().status(), 200);
    let (owner2, s2) = f.mint().await;
    f.response(CHAT);
    let meta = json!({"capability_token":s2.session.capability_token,"action_id":f.actions[0].id,"action_version":f.actions[0].version,"content_type":"application/json","extra_headers":[],"params":{},"query":{},"approval_grants":[]});
    common::call(
        &f.broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        &serde_json::to_vec(&meta).unwrap(),
        BODY,
    )
    .await
    .ok();
    assert_eq!(f.totals(), (2, 14, 0));
    assert_eq!(f.post(&s2, BODY).send().await.unwrap().status(), 403);
    assert_eq!(f.broker.fake.take_requests().len(), 2);
    assert_eq!(f.totals(), (2, 14, 0));
    assert_eq!(
        common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::STATUS,
            b"{}",
            &[]
        )
        .await
        .ok()["state"],
        "unlocked"
    );
    drop((owner, owner2));
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn approval_required_waits_for_explicit_same_body_retry_with_one_use() {
    let f = Fixture::new("openai", "chat-completions", 1, 100, true).await;
    let (owner, s) = f.mint().await;
    let required = f.post(&s, BODY).send().await.unwrap();
    assert_eq!(required.status(), 403);
    let required: ipc::ErrorEnvelope =
        serde_json::from_slice(&required.bytes().await.unwrap()).unwrap();
    assert_eq!(required.code, "APPROVAL_REQUIRED");
    assert!(!required.retryable);
    let id = required.approval.unwrap().challenge_id;
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(f.totals(), (0, 0, 0));
    let review = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        &serde_json::to_vec(&json!({"approval_request_id":id})).unwrap(),
        &[],
    )
    .await;
    let value: Value = serde_json::from_slice(&review.body).unwrap();
    assert!(
        serde_json::to_string(&value)
            .unwrap()
            .contains("max_completion_tokens")
    );
    let key = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::DESKTOP_REMEMBER,
        br#"{"lifetime_ms":604800000}"#,
        &common::proof_body(common::PASSWORD),
    )
    .await
    .body;
    let mut proof = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &key, &mut proof);
    common::call(&f.broker.admin_sock(),Channel::Admin,admin_msg::APPROVAL_LOCAL_APPROVE,&serde_json::to_vec(&json!({"approval_request_id":id,"expected_review_sha256":review.ok()["review_sha256"]})).unwrap(),&proof).await.ok();
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(f.totals(), (0, 0, 0));
    f.response(CHAT);
    let result = f
        .post(&s, BODY)
        .header("x-rekey-approval-challenge", id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), 200);
    assert_eq!(f.totals(), (1, 7, 0));
    let sent = f.broker.fake.take_requests();
    assert_eq!(sent.len(), 1);
    assert!(
        !sent[0]
            .headers
            .iter()
            .any(|(name, _)| name == "x-rekey-approval-challenge")
    );
    assert_eq!(
        f.post(&s, BODY)
            .header("x-rekey-approval-challenge", id.to_string())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert!(f.broker.fake.take_requests().is_empty());
    drop(owner);
    f.broker.shutdown().await;
}
async fn wait_no_listener(f: &Fixture, port: u16) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!f.broker.state_dir.join("gateway.port").exists());
}
#[tokio::test(flavor = "multi_thread")]
async fn lock_retraction_expiry_and_owner_eof_close_authority_for_new_http() {
    let mut f = Fixture::new("openai", "chat-completions", 100, 1000, false).await;
    let (owner, s) = f.mint().await;
    let port = s.gateway.as_ref().unwrap().port;
    drop(owner);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let r = common::call(
                &f.broker.agent_sock(),
                Channel::Agent,
                agent_msg::PROFILE_INVENTORY,
                &serde_json::to_vec(&json!({"capability_token":s.session.capability_token}))
                    .unwrap(),
                &[],
            )
            .await;
            if r.err_code() == "INVALID_CAPABILITY" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.post(&s, BODY).send().await.unwrap().status(), 401);
    common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    wait_no_listener(&f, port).await;
    common::unlock(&f.broker).await;
    let (owner, s) = f.mint().await;
    let port = s.gateway.as_ref().unwrap().port;
    let mut withdrawn = f.snapshot.clone();
    withdrawn["version"] = json!(2);
    withdrawn["profiles"] = json!([]);
    common::policy::activate_snapshot(&f.broker, withdrawn).await;
    wait_no_listener(&f, port).await;
    drop(owner);
    f.snapshot["version"] = json!(3);
    f.snapshot["expires_at_ms"] = json!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 5_000
    );
    common::policy::activate_snapshot(&f.broker, f.snapshot.clone()).await;
    // This checks listener expiry, so observe its public binding directly.
    // A second session mint can correctly lose the race to this short policy.
    let port = std::fs::read_to_string(f.broker.state_dir.join("gateway.port"))
        .unwrap()
        .trim()
        .parse::<u16>()
        .unwrap();
    // Preparation/signing must fit before expiry even under the full workspace load.
    tokio::time::sleep(Duration::from_secs(4)).await;
    wait_no_listener(&f, port).await;
    assert!(f.broker.fake.take_requests().is_empty());
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn cache_publication_failure_keeps_committed_policy_but_no_trusted_endpoint() {
    let mut f = Fixture::new("openai", "chat-completions", 10, 100, false).await;
    common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    let cache = f.broker.state_dir.join("gateway.port");
    std::fs::create_dir(&cache).unwrap();
    common::unlock(&f.broker).await;
    let (owner, s) = f.mint().await;
    assert!(s.gateway.is_none());
    assert_eq!(
        common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::POLICY_STATUS,
            b"{}",
            &[]
        )
        .await
        .ok()["version"],
        1
    );
    drop(owner);
    std::fs::remove_dir(cache).unwrap();
    f.snapshot["version"] = json!(2);
    common::policy::activate_snapshot(&f.broker, f.snapshot.clone()).await;
    let (owner, s) = f.mint().await;
    assert!(s.gateway.is_some());
    drop(owner);
    f.broker.shutdown().await;
}
fn long_chat() -> String {
    format!(
        "data: {}\n\ndata: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"safe ".repeat(200)},"finish_reason":null}]}),
        json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"more ".repeat(200)},"finish_reason":"stop"}]}),
        json!({"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"completion_tokens":7}})
    )
}
fn raw_body() -> Vec<u8> {
    let mut body: Value = serde_json::from_slice(BODY).unwrap();
    body["stream"] = json!(true);
    serde_json::to_vec(&body).unwrap()
}
#[tokio::test(flavor = "multi_thread")]
async fn raw_eof_and_durable_settlement_gate_completion_and_disconnect_keeps_owner() {
    let f = Fixture::new("openai", "chat-completions", 10, 1000, false).await;
    let (owner, s) = f.mint().await;
    let raw = long_chat();
    let gate = Arc::new(Notify::new());
    f.transport.push(raw.as_bytes(), Some(gate.clone()), false);
    let mut out = f.post(&s, &raw_body()).send().await.unwrap();
    assert_eq!(out.status(), 200);
    let mut emitted = out.chunk().await.unwrap().unwrap().to_vec();
    assert!(!String::from_utf8_lossy(&emitted).contains("[DONE]"));
    assert_eq!(f.totals(), (1, 0, 1));
    let db = f.db();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    gate.notify_one();
    // Upstream EOF alone cannot release completion while terminal SQL is blocked.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), out.chunk())
            .await
            .is_err()
    );
    assert_eq!(f.totals(), (1, 0, 1));
    db.execute_batch("COMMIT").unwrap();
    while let Some(chunk) = out.chunk().await.unwrap() {
        emitted.extend(chunk);
    }
    assert_eq!(emitted, raw.as_bytes());
    assert_eq!(f.totals(), (1, 7, 0));
    let gate = Arc::new(Notify::new());
    f.transport.push(raw.as_bytes(), Some(gate.clone()), false);
    let out = f.post(&s, &raw_body()).send().await.unwrap();
    assert_eq!(out.status(), 200);
    drop(out);
    gate.notify_one();
    f.settled(2).await;
    assert_eq!(f.totals(), (2, 14, 0));
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.finished'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        2
    );
    drop(owner);
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn stream_transport_cut_aborts_http_and_uses_saved_max_once() {
    let f = Fixture::new("openai", "chat-completions", 10, 1000, false).await;
    let (owner, s) = f.mint().await;
    let gate = Arc::new(Notify::new());
    f.transport
        .push(long_chat().as_bytes(), Some(gate.clone()), true);
    let mut out = f.post(&s, &raw_body()).send().await.unwrap();
    assert_eq!(out.status(), 200);
    let mut emitted = out.chunk().await.unwrap().unwrap().to_vec();
    gate.notify_one();
    loop {
        match out.chunk().await {
            Ok(Some(bytes)) => emitted.extend(bytes),
            Err(_) => break,
            Ok(None) => panic!("cut stream became a clean HTTP EOF"),
        }
    }
    assert!(!String::from_utf8_lossy(&emitted).contains("[DONE]"));
    f.settled(1).await;
    assert_eq!(f.totals(), (1, 20, 0));
    assert_eq!(
        f.db()
            .query_row("SELECT source FROM profile_usage", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "indeterminate"
    );
    drop(owner);
    f.broker.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn failed_terminal_audit_never_releases_http_completion() {
    let f = Fixture::new("openai", "chat-completions", 10, 1000, false).await;
    let (owner, s) = f.mint().await;
    let gate = Arc::new(Notify::new());
    f.transport
        .push(long_chat().as_bytes(), Some(gate.clone()), false);
    let mut out = f.post(&s, &raw_body()).send().await.unwrap();
    assert_eq!(out.status(), 200);
    let mut emitted = out.chunk().await.unwrap().unwrap().to_vec();
    f.db().execute_batch("CREATE TRIGGER reject_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.finished' BEGIN SELECT RAISE(ABORT,'synthetic'); END").unwrap();
    gate.notify_one();
    loop {
        match out.chunk().await {
            Ok(Some(bytes)) => emitted.extend(bytes),
            Err(_) => break,
            Ok(None) => panic!("failed terminal audit became clean EOF"),
        }
    }
    assert!(!String::from_utf8_lossy(&emitted).contains("[DONE]"));
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.finished'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(f.totals(), (1, 0, 1));
    drop(owner);
    let _ = tokio::time::timeout(Duration::from_secs(5), f.broker.serve_task)
        .await
        .unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn get_models_has_empty_body_and_zero_output_and_wrong_model_never_starts() {
    let f = Fixture::new("openai", "models", 10, 100, false).await;
    let (owner, s) = f.mint().await;
    f.response(br#"{"data":[]}"#);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let out = client
        .get(f.url(&s))
        .header("x-api-key", format!("rkc_{}", s.session.capability_token))
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 200);
    assert_eq!(out.bytes().await.unwrap().as_ref(), br#"{"data":[]}"#);
    assert_eq!(f.totals(), (1, 0, 0));
    let sent = f.broker.fake.take_requests();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].body.is_empty());
    assert!(
        !sent[0]
            .headers
            .iter()
            .any(|(name, _)| name == "content-type")
    );
    let out = client
        .get(f.url(&s))
        .header("x-api-key", format!("rkc_{}", s.session.capability_token))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 400);
    assert!(f.broker.fake.take_requests().is_empty());
    drop(owner);
    f.broker.shutdown().await;
    let f = Fixture::new("openai", "chat-completions", 10, 100, false).await;
    let (owner, s) = f.mint().await;
    assert_eq!(
        f.post(&s, br#"{"model":"not-signed"}"#)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(f.totals(), (0, 0, 0));
    assert!(f.broker.fake.take_requests().is_empty());
    // Existing common MIME normalization remains authoritative for SDK callers.
    f.response(b"{}");
    let out = client
        .post(f.url(&s))
        .bearer_auth(format!("rkc_{}", s.session.capability_token))
        .header("content-type", "application/json; charset=utf-8")
        .body(BODY.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 200);
    assert_eq!(f.totals(), (1, 20, 0));
    drop(owner);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_auth_octets_chunked_limit_and_body_deadline_fail_before_execution() {
    let f = Fixture::new("openai", "chat-completions", 10, 100, false).await;
    let (owner, session) = f.mint().await;
    let port = session.gateway.as_ref().unwrap().port;
    let token = format!("rkc_{}", session.session.capability_token);
    let prefix = format!("POST /p/work/v1/chat/completions HTTP/1.1\r\nHost: localhost:{port}\r\n");
    for value in [
        format!("Bearer {token},other").into_bytes(),
        [b"Bearer ".as_slice(), &[0xff]].concat(),
        b"Bearer rkc_rkc_invalid".to_vec(),
    ] {
        let mut raw = prefix.as_bytes().to_vec();
        raw.extend_from_slice(b"Authorization: ");
        raw.extend(value);
        raw.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let response = raw_http(port, &raw).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 401"));
    }
    let auth = format!("Authorization: Bearer {token}\r\nContent-Type: application/json\r\n");
    let raw = format!(
        "{prefix}{auth}Transfer-Encoding: chunked\r\n\r\n1388\r\n{}\r\n0\r\n\r\n",
        "x".repeat(5000)
    );
    assert!(
        String::from_utf8_lossy(&raw_http(port, raw.as_bytes()).await).starts_with("HTTP/1.1 400")
    );
    let raw = format!(
        "{prefix}{auth}X-large: {}\r\nContent-Length: {}\r\n\r\n{}",
        "x".repeat(17000),
        BODY.len(),
        std::str::from_utf8(BODY).unwrap()
    );
    let response = raw_http(port, raw.as_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 431"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    // A partially supplied body is bounded by the HTTP read deadline, while
    // neither a permit nor a durable request has yet been created.
    let raw = format!("{prefix}{auth}Content-Length: 2\r\n\r\n{{");
    assert!(
        String::from_utf8_lossy(&raw_http(port, raw.as_bytes()).await).starts_with("HTTP/1.1 400")
    );
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(f.totals(), (0, 0, 0));
    drop(owner);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn anthropic_optional_beta_is_preserved_for_messages_and_count_tokens() {
    for capability in ["messages", "count-tokens"] {
        let f = Fixture::new("anthropic", capability, 10, 100, false).await;
        let (owner, s) = f.mint().await;
        let ActionTarget::Template { target, .. } = &f.actions[0].target else {
            panic!()
        };
        for query in ["", "?beta=true"] {
            let reply = if capability == "messages" {
                br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#
                    .as_slice()
            } else {
                br#"{"input_tokens":1}"#.as_slice()
            };
            f.response(reply);
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(format!("{}{query}", f.url(&s)))
                .bearer_auth(format!("rkc_{}", s.session.capability_token))
                .header("content-type", "application/json")
                .body(BODY.to_vec())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{capability}/{query}");
            assert_eq!(response.bytes().await.unwrap().as_ref(), reply);
            let sent = f.broker.fake.take_requests();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].path, format!("{}{query}", target.path_pattern()));
            assert!(
                !sent[0]
                    .headers
                    .iter()
                    .any(|(name, _)| name == "anthropic-beta")
            );
        }
        assert_eq!(
            f.totals(),
            (2, if capability == "messages" { 14 } else { 0 }, 0)
        );
        drop(owner);
        f.broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn beta_query_requires_the_selected_action_declaration() {
    for (provider, capability) in [
        ("openai", "responses"),
        ("openai", "models"),
        ("anthropic", "models"),
    ] {
        let f = Fixture::new(provider, capability, 10, 100, false).await;
        let (owner, s) = f.mint().await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = format!("{}?beta=true", f.url(&s));
        let request = if capability == "models" {
            client.get(url)
        } else {
            client
                .post(url)
                .header("content-type", "application/json")
                .body(BODY.to_vec())
        };
        assert_eq!(
            request
                .bearer_auth(format!("rkc_{}", s.session.capability_token))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        assert!(f.broker.fake.take_requests().is_empty());
        assert_eq!(f.totals(), (0, 0, 0));
        drop(owner);
        f.broker.shutdown().await;
    }
}
