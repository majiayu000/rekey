//! Real signed Connections + MCP stdio + Broker/Authority/SQLite.
//! Upstream transport alone is synthetic; no local token or Profile is minted.
mod common;

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use rekey_domain::action::HttpsOrigin;
use rekey_domain::connection::{Connection, MethodClass, MethodSelector, RuleEffect};
use rekey_domain::ipc::{self, Channel, admin_msg, agent_msg};
use serde_json::{Value, json};

const SECRET: &str = "mcp-synthetic-secret-20261005";
const GENERIC_NAMES: [&str; 9] = [
    "list_capabilities",
    "describe",
    "call",
    "http",
    "request_access",
    "await_access",
    "await_approval",
    "cancel_approval",
    "await_unlock",
];

struct StreamTransport {
    fake: Arc<rekey_broker::testing::FakeUpstreamTransport>,
}
struct StreamChunks(VecDeque<zeroize::Zeroizing<Vec<u8>>>);
impl rekey_broker::upstream::UpstreamBody for StreamChunks {
    fn next_chunk(&mut self) -> rekey_broker::upstream::UpstreamChunkFuture<'_> {
        Box::pin(async move { Ok(self.0.pop_front()) })
    }
}
impl rekey_broker::upstream::UpstreamTransport for StreamTransport {
    fn send(
        &self,
        request: rekey_broker::upstream::UpstreamRequest,
    ) -> rekey_broker::upstream::UpstreamFuture<'_> {
        self.fake.send(request)
    }
    fn open_stream(
        &self,
        request: rekey_broker::upstream::UpstreamRequest,
    ) -> rekey_broker::upstream::UpstreamStreamFuture<'_> {
        Box::pin(async move {
            let response = self.fake.send(request).await?;
            let chunks = response
                .body
                .chunks(7)
                .map(|bytes| bytes.to_vec().into())
                .collect();
            Ok(rekey_broker::upstream::UpstreamStreamResponse {
                status: response.status,
                headers: response.headers,
                body: Box::new(StreamChunks(chunks)),
            })
        })
    }
}

struct Mcp {
    child: Child,
    input: ChildStdin,
    responses: Receiver<Value>,
}
impl Mcp {
    fn start(socket: &Path, version: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
            .arg("--agent-socket")
            .arg(socket)
            .env_remove("REKEY_AGENT_SOCKET")
            .env_remove("REKEY_CAPABILITY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, responses) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                for private in [
                    SECRET,
                    "capability_token",
                    "REKEY_CAPABILITY",
                    std::str::from_utf8(common::PASSWORD).unwrap(),
                ] {
                    assert!(
                        !line.contains(private),
                        "MCP stdout contained private material"
                    );
                }
                if send.send(serde_json::from_str(&line).unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut mcp = Self {
            child,
            input,
            responses,
        };
        let response = mcp.request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"mcp-test","version":"1"}}}));
        assert_eq!(response["result"]["protocolVersion"], version);
        writeln!(
            mcp.input,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .unwrap();
        mcp
    }
    fn request(&mut self, value: Value) -> Value {
        writeln!(self.input, "{value}").unwrap();
        self.responses
            .recv_timeout(Duration::from_secs(10))
            .expect("MCP did not answer")
    }
    fn list(&mut self) -> Value {
        self.request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
    }
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
    }
}
impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct Fixture {
    broker: common::TestBroker,
    connection: Connection,
}
impl Fixture {
    async fn new(preset: &str) -> Self {
        let fake = Arc::new(rekey_broker::testing::FakeUpstreamTransport::new());
        let broker = common::start_broker_with_transport(
            Duration::from_secs(300),
            Duration::from_secs(2),
            fake.clone(),
            Arc::new(StreamTransport { fake }),
        )
        .await;
        common::unlock(&broker).await;
        let credential = common::add_credential(&broker, "mcp", SECRET.as_bytes()).await;
        let preset = if preset == "generic-bearer" {
            let mut preset = rekey_policy::presets::generic_preset(
                HttpsOrigin::parse("https://api.example.com").unwrap(),
                "authorization",
                "Bearer ",
            )
            .unwrap();
            for rule in &mut preset.rules {
                rule.effect = RuleEffect::Allow;
            }
            preset
        } else {
            rekey_policy::presets::builtin_preset(preset).unwrap()
        };
        let mut connection = preset.connection("fixture".into(), credential.parse().unwrap());
        if connection.preset == "openai" {
            connection.llm = Some(rekey_domain::connection::ConnectionLlmLimits {
                models: ["synthetic-model".into()].into_iter().collect(),
                max_tokens: 32,
                max_requests_per_day: 600,
                max_output_tokens_per_day: 20000,
            });
        }
        let fixture = Self { broker, connection };
        fixture.activate(1).await;
        fixture
    }
    async fn activate(&self, version: u64) {
        common::policy::activate_snapshot(
            &self.broker,
            json!({
                "format_version":7,"version":version,"expires_at_ms":4_102_444_800_000_i64,
                "approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],
                "connections":[self.connection],"ssh_keys":[],"derived_credentials":[],
            }),
        )
        .await;
    }
    fn mcp(&self, version: &str) -> Mcp {
        Mcp::start(&self.broker.agent_sock(), version)
    }
    async fn admin(&self, opcode: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            opcode,
            &serde_json::to_vec(&metadata).unwrap(),
            body,
        )
        .await
    }
    async fn agent(&self, opcode: u16, metadata: Value) -> common::WireResponse {
        common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            opcode,
            &serde_json::to_vec(&metadata).unwrap(),
            &[],
        )
        .await
    }
    fn allow_writes(&mut self) {
        for rule in &mut self.connection.rules {
            if matches!(rule.methods, MethodSelector::Class(MethodClass::Write)) {
                rule.effect = RuleEffect::Allow;
            }
        }
    }
}
fn tools(list: &Value) -> &[Value] {
    list["result"]["tools"].as_array().expect("tools list")
}
fn generic_only(list: &Value) {
    assert_eq!(tools(list).len(), GENERIC_NAMES.len());
    for name in GENERIC_NAMES {
        assert!(tools(list).iter().any(|tool| tool["name"] == name));
    }
}
fn tool<'a>(list: &'a Value, name: &str) -> &'a Value {
    tools(list)
        .iter()
        .find(|tool| tool["name"] == name)
        .expect("named tool")
}
fn result_code(response: &Value) -> &str {
    response["result"]["structuredContent"]["code"]
        .as_str()
        .expect("structured error")
}
fn successful(response: &Value) -> &Value {
    assert_eq!(response["result"]["isError"], false, "{response}");
    &response["result"]["structuredContent"]
}
fn issue() -> Value {
    json!({"owner":"fixture","repo":"project","number":3})
}
fn get_http() -> Value {
    json!({"connection":"fixture","method":"GET","path":"/records"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_connection_discovery_is_public_non_consuming_and_protocol_compatible() {
    let f = Fixture::new("github-pat").await;
    let inventory = f.agent(agent_msg::LIST_CAPABILITIES, json!({})).await;
    inventory.ok();
    let text = std::str::from_utf8(&inventory.body).unwrap();
    for private in ["credential_id", "fixed_headers", "signer_id", SECRET] {
        assert!(!text.contains(private));
    }
    let mut upstream_calls = 0;
    for version in ["2025-06-18", "2025-11-25"] {
        let mut mcp = f.mcp(version);
        let list = mcp.list();
        assert_eq!(tools(&list).len(), GENERIC_NAMES.len() + 6);
        assert_eq!(
            tool(&list, "github_get_issue")["inputSchema"]["required"],
            json!(["owner", "repo", "number"])
        );
        assert_eq!(mcp.list(), list);
        let described = mcp.call("describe", json!({"operation":"github.get_issue"}));
        assert_eq!(
            successful(&described)["operation"]["name"],
            "github.get_issue"
        );
        let mut dry_args = issue();
        dry_args["dry_run"] = true.into();
        let dry = mcp.call("github_get_issue", dry_args);
        assert_eq!(successful(&dry)["path"], "/repos/fixture/project/issues/3");
        assert_eq!(successful(&dry)["effect"], "allow");
        assert!(f.broker.fake.take_requests().is_empty());
        let response = mcp.call("github_get_issue", issue());
        assert_eq!(successful(&response)["status"], 200);
        assert_eq!(response["result"]["content"][0]["text"], r#"{"ok":true}"#);
        assert_eq!(mcp.list(), list);
        upstream_calls += f.broker.fake.take_requests().len();
    }
    assert_eq!(upstream_calls, 2);
    let status = f.admin(admin_msg::STATUS, json!({}), &[]).await;
    assert_eq!(status.ok()["sessions_active"], 0);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_and_http_calls_keep_schema_query_body_and_fixed_headers_under_daemon_authority() {
    let mut f = Fixture::new("github-pat").await;
    f.allow_writes();
    f.activate(2).await;
    let mut mcp = f.mcp("2025-11-25");
    assert_eq!(
        tool(&mcp.list(), "github_create_issue")["inputSchema"]["properties"]["title"]["minLength"],
        1
    );
    for args in [
        json!({}),
        json!({"owner":"fixture","repo":"project","number":"bad"}),
        json!({"owner":"fixture","repo":"project","number":3,"secret":"unused"}),
    ] {
        assert_eq!(
            mcp.call("github_get_issue", args)["result"]["isError"],
            true
        );
    }
    let protected = mcp.call("http", json!({"connection":"fixture","method":"GET","path":"/repos/fixture/project/issues","headers":[["authorization","override"]]}));
    assert_eq!(protected["result"]["isError"], true);
    assert!(f.broker.fake.take_requests().is_empty());
    successful(&mcp.call("http", json!({"connection":"fixture","method":"GET","path":"/repos/fixture/project/issues","query":{"state":"open","page":"2"}})));
    successful(&mcp.call("github_get_issue", issue()));
    successful(&mcp.call(
        "github_create_issue",
        json!({"owner":"fixture","repo":"project","title":"issue","body":"details"}),
    ));
    let requests = f.broker.fake.take_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].path,
        "/repos/fixture/project/issues?page=2&state=open"
    );
    assert_eq!(requests[1].path, "/repos/fixture/project/issues/3");
    assert!(requests[0].body.is_empty() && requests[1].body.is_empty());
    assert_eq!(requests[2].body, br#"{"body":"details","title":"issue"}"#);
    for request in requests {
        assert_eq!(request.auth_value, format!("Bearer {SECRET}").as_bytes());
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == "accept" && value == "application/vnd.github+json")
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == "x-github-api-version" && value == "2022-11-28")
        );
    }
    drop(mcp);
    f.broker.shutdown().await;
}

#[test]
fn unavailable_daemon_keeps_recovery_tools_and_invalid_protocol_input_is_structured() {
    let dir = tempfile::tempdir().unwrap();
    let mut mcp = Mcp::start(&dir.path().join("missing.sock"), "2025-11-25");
    generic_only(&mcp.list());
    let unavailable = mcp.call("list_capabilities", json!({}));
    assert_eq!(result_code(&unavailable), "IPC_UNAVAILABLE");
    assert!(
        unavailable["result"]["structuredContent"]["next"]
            .as_str()
            .unwrap()
            .contains("rekeyd serve")
    );
    assert_eq!(
        result_code(&mcp.call(
            "await_approval",
            json!({"request_id":rekey_domain::ids::ApprovalRequestId::new_random(),"timeout_s":121})
        )),
        "INVALID_INPUT"
    );
    writeln!(mcp.input, "{{broken").unwrap();
    assert_eq!(
        mcp.responses.recv_timeout(Duration::from_secs(2)).unwrap()["error"]["code"],
        -32700
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .args(["--manifest", "/not-used.json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_and_unconfigured_daemons_keep_generic_tools_and_preserve_next_step() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let mut mcp = Mcp::start(&broker.agent_sock(), "2025-11-25");
    generic_only(&mcp.list());
    let missing = mcp.call("list_capabilities", json!({}));
    assert_eq!(result_code(&missing), "NOT_CONFIGURED");
    assert!(
        missing["result"]["structuredContent"]["next"]
            .as_str()
            .unwrap()
            .contains("request_access")
    );
    successful(&mcp.call(
        "request_access",
        json!({"provider":"github-pat","reason":"Read the requested issue"}),
    ));
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    generic_only(&mcp.list());
    let locked = mcp.call("http", get_http());
    assert_eq!(result_code(&locked), "LOCKED");
    assert!(
        locked["result"]["structuredContent"]["next"]
            .as_str()
            .unwrap()
            .contains("await_unlock")
    );
    drop(mcp);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_changes_disable_cached_named_tools_and_connection_budget_never_hides_inventory() {
    let mut f = Fixture::new("github-pat").await;
    f.connection.limits.requests_per_hour = 1;
    f.activate(2).await;
    let mut mcp = f.mcp("2025-11-25");
    let list = mcp.list();
    successful(&mcp.call("github_get_issue", issue()));
    assert_eq!(
        result_code(&mcp.call("github_get_issue", issue())),
        "BUDGET_EXCEEDED"
    );
    assert_eq!(mcp.list(), list);
    assert_eq!(f.broker.fake.take_requests().len(), 1);
    f.connection.enabled = false;
    f.activate(3).await;
    generic_only(&mcp.list());
    assert_eq!(
        mcp.call("github_get_issue", issue())["result"]["isError"],
        true
    );
    assert!(f.broker.fake.take_requests().is_empty());
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_request_waits_pending_and_resolves_without_a_token_or_implicit_execution() {
    let f = Fixture::new("github-pat").await;
    let mut mcp = f.mcp("2025-11-25");
    let requested = mcp.call(
        "request_access",
        json!({"connection":"fixture","reason":"Read the requested issue"}),
    );
    let access = successful(&requested);
    assert!(access["next"].as_str().unwrap().contains("await_access"));
    let wait = json!({"request_id":access["request_id"],"timeout_s":1});
    assert_eq!(
        successful(&mcp.call("await_access", wait.clone()))["status"],
        "PENDING"
    );
    assert!(f.broker.fake.take_requests().is_empty());
    f.admin(admin_msg::ACCESS_RESOLVE, json!({"action":"resolve","request_id":access["request_id"],"granted":true,"block_caller":false}), &common::proof_body(common::PASSWORD)).await.ok();
    assert_eq!(
        successful(&mcp.call("await_access", wait))["status"],
        "GRANTED"
    );
    assert!(f.broker.fake.take_requests().is_empty());
    let missing = mcp.call(
        "await_access",
        json!({"request_id":rekey_domain::ids::RequestId::new_random(),"timeout_s":1}),
    );
    assert!(missing["result"]["isError"].as_bool().unwrap());
    assert!(missing["result"]["structuredContent"]["next"].is_string());
    successful(&mcp.call("github_get_issue", issue()));
    assert_eq!(f.broker.fake.take_requests().len(), 1);
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_approval_preserves_next_wait_and_exactly_one_explicit_replay() {
    let f = Fixture::new("github-pat").await;
    let mut mcp = f.mcp("2025-11-25");
    let request = json!({"owner":"fixture","repo":"project","title":"hello"});
    let required = mcp.call("github_create_issue", request.clone());
    assert_eq!(result_code(&required), "APPROVAL_REQUIRED");
    let error = &required["result"]["structuredContent"];
    assert_eq!(error["retryable"], false);
    assert!(error["next"].as_str().unwrap().contains("await"));
    let challenge = error["approval"]["challenge_id"].clone();
    assert!(challenge.is_string());
    assert!(f.broker.fake.take_requests().is_empty());
    let remembered = f
        .admin(
            admin_msg::DESKTOP_REMEMBER,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    remembered.ok();
    let review = f
        .admin(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":challenge}),
            &[],
        )
        .await;
    let mut proof = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut proof);
    f.admin(admin_msg::APPROVAL_LOCAL_APPROVE, json!({"approval_request_id":challenge,"expected_review_sha256":review.ok()["review_sha256"]}), &proof).await.ok();
    let wait = json!({"request_id":challenge,"timeout_s":1});
    assert_eq!(
        successful(&mcp.call("await_approval", wait.clone()))["state"],
        "approved"
    );
    assert!(f.broker.fake.take_requests().is_empty());
    let mut retry = request;
    retry["approval_request_id"] = challenge;
    successful(&mcp.call("github_create_issue", retry.clone()));
    assert_eq!(
        successful(&mcp.call("await_approval", wait))["state"],
        "consumed"
    );
    assert_eq!(
        mcp.call("github_create_issue", retry)["result"]["isError"],
        true
    );
    assert_eq!(f.broker.fake.take_requests().len(), 1);
    let cancel = mcp.call(
        "github_create_issue",
        json!({"owner":"fixture","repo":"project","title":"cancel"}),
    );
    let id = cancel["result"]["structuredContent"]["approval"]["challenge_id"].clone();
    assert_eq!(
        successful(&mcp.call("cancel_approval", json!({"request_id":id})))["state"],
        "cancelled"
    );
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_status_mime_base64_and_reflected_secret_remain_public_safe() {
    use rekey_broker::upstream::UpstreamResponse;
    let f = Fixture::new("generic-bearer").await;
    let mut mcp = f.mcp("2025-11-25");
    for (status, mime, body) in [
        (403, "application/json", b"{}".to_vec()),
        (200, "application/octet-stream", vec![255, 254]),
        (200, "text/plain", SECRET.as_bytes().to_vec()),
    ] {
        f.broker.fake.push_response(Ok(UpstreamResponse {
            status,
            headers: vec![("content-type".into(), mime.into())].into(),
            body: body.into(),
        }));
        let response = mcp.call("http", get_http());
        if status == 403 {
            assert_eq!(response["result"]["isError"], true);
            assert_eq!(response["result"]["structuredContent"]["status"], 403);
            assert_eq!(result_code(&response), "UPSTREAM_ERROR");
            assert!(
                response["result"]["structuredContent"]["next"]
                    .as_str()
                    .unwrap()
                    .contains("sealed response")
            );
        } else if mime == "application/octet-stream" {
            let result = successful(&response);
            assert_eq!(result["mime_type"], mime);
            assert_eq!(result["body_encoding"], "base64");
            assert_eq!(result["body"], "//4=");
        } else {
            assert_eq!(result_code(&response), "RESPONSE_BLOCKED");
        }
    }
    assert_eq!(f.broker.fake.take_requests().len(), 3);
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn llm_sse_is_completed_and_sealed_before_mcp_returns_it() {
    use rekey_broker::upstream::UpstreamResponse;
    const SSE: &str = "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"safe\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"completion_tokens\":7}}\n\ndata: [DONE]\n\n";
    let f = Fixture::new("openai").await;
    let mut mcp = f.mcp("2025-11-25");
    let args = json!({"model":"synthetic-model","messages":[],"max_tokens":16,"stream":true});
    f.broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into())].into(),
        body: SSE.as_bytes().to_vec().into(),
    }));
    let response = mcp.call("openai_chat", args.clone());
    let result = successful(&response);
    assert_eq!(result["mime_type"], "text/event-stream");
    assert!(result["body"].as_str().unwrap().contains("safe"));
    assert!(result["body"].as_str().unwrap().contains("[DONE]"));
    let reflected = SSE.replace("safe", SECRET);
    f.broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into())].into(),
        body: reflected.into_bytes().into(),
    }));
    assert_eq!(mcp.call("openai_chat", args)["result"]["isError"], true);
    assert_eq!(f.broker.fake.take_requests().len(), 2);
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_mcp_performs_500_calls_without_proof_token_or_agent_launcher() {
    let f = Fixture::new("generic-bearer").await;
    let mut mcp = f.mcp("2025-11-25");
    generic_only(&mcp.list());
    for i in 0..500 {
        if i % 100 == 0 {
            generic_only(&mcp.list());
        }
        let response = mcp.call("http", get_http());
        assert_eq!(successful(&response)["status"], 200);
    }
    assert_eq!(f.broker.fake.take_requests().len(), 500);
    generic_only(&mcp.list());
    let status = f.admin(admin_msg::STATUS, json!({}), &[]).await;
    assert_eq!(status.ok()["sessions_active"], 0);
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_custom_operations_are_discovered_without_builtin_provider_semantics() {
    let mut f = Fixture::new("generic-bearer").await;
    f.connection.preset = "custom-mcp".into();
    f.connection.operations = vec![rekey_domain::connection::PresetOperation {
        name: "custom.record".into(),
        description: "Read one record".into(),
        method: rekey_domain::action::FixedMethod::Get,
        path: "/custom/{item}".into(),
        parameters: json!({"type":"object","properties":{"item":{"type":"string"}},"required":["item"],"additionalProperties":false}),
        read_semantics: None,
    }];
    f.activate(2).await;
    let mut mcp = f.mcp("2025-11-25");
    assert_eq!(tools(&mcp.list()).len(), GENERIC_NAMES.len() + 1);
    successful(&mcp.call("custom_record", json!({"item":"record"})));
    let requests = f.broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/custom/record");
    assert!(requests[0].body.is_empty());
    drop(mcp);
    f.broker.shutdown().await;
}
