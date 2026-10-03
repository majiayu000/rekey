//! Real Profile mint + MCP stdio + Broker/Authority/SQLite. Only upstream IO is fake.
mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rekey_domain::action::FixedHttpAction;
use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId, RequestId};
use rekey_domain::ipc::{self, Channel, FrameHeader, admin_msg, agent_msg};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const SECRET: &str = "mcp-test-secret";

struct Mcp {
    child: Child,
    input: ChildStdin,
    responses: Receiver<Value>,
}
impl Mcp {
    fn start(socket: Option<&Path>, token: Option<&str>, version: &str) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"));
        command
            .env_remove("REKEY_AGENT_SOCKET")
            .env_remove("REKEY_CAPABILITY");
        if let Some(socket) = socket {
            command.env("REKEY_AGENT_SOCKET", socket);
        }
        if let Some(token) = token {
            command.env("REKEY_CAPABILITY", token);
        }
        Self::spawn(command, token, version)
    }
    fn spawn(mut command: Command, token: Option<&str>, version: &str) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let token = Zeroizing::new(token.unwrap_or_default().to_owned());
        let (send, responses) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                assert!(!line.contains(SECRET));
                assert!(!line.contains("capability_token"));
                assert!(!line.contains("REKEY_CAPABILITY"));
                assert!(!line.contains(std::str::from_utf8(common::PASSWORD).unwrap()));
                assert!(token.is_empty() || !line.contains(token.as_str()));
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
    actions: Vec<FixedHttpAction>,
    snapshot: Value,
}
impl Fixture {
    async fn new(
        source: Value,
        capabilities: &[&str],
        bindings: Value,
        uses: u32,
        ttl: i64,
        approval: bool,
    ) -> Self {
        Self::with_signed_template(source, capabilities, bindings, uses, ttl, approval, None).await
    }
    async fn with_signed_template(
        source: Value,
        capabilities: &[&str],
        bindings: Value,
        uses: u32,
        ttl: i64,
        approval: bool,
        name: Option<&str>,
    ) -> Self {
        let broker = common::start_broker().await;
        common::unlock(&broker).await;
        let credential = common::add_credential(&broker, "mcp", SECRET.as_bytes()).await;
        let signer = name.map(|_| {
            let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            (
                PolicySignerId::new_random(),
                Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap(),
            )
        });
        let package = if let Some((id, key)) = &signer {
            let trust = json!({"format_version":1,"signer_id":id,"algorithm":"ed25519","public_key":data_encoding::HEXLOWER.encode(key.public_key().as_ref())});
            common::call(
                &broker.admin_sock(),
                Channel::Admin,
                admin_msg::POLICY_TRUST_INSTALL,
                &serde_json::to_vec(&trust).unwrap(),
                &common::proof_body(common::PASSWORD),
            )
            .await
            .ok();
            let mut package = json!({"format_version":1,"signer_id":id,"template":{
                "template":name.unwrap(),"display":"Custom MCP fixture","origin":"https://api.example.com",
                "credential":{"kind":"opaque-token","inject":{"header":"authorization","prefix":"Bearer "}},
                "bindings":{"owner":{"type":"slug"}},"capabilities":[{"id":"records","risk":"low","actions":[
                    {"method":"GET","path":"/custom/{owner}/{item}","params":{"item":"slug"},"query":{"page":"int:1..10"}},
                    {"method":"POST","path":"/custom/{owner}/{item}","params":{"item":"slug"},"body_schema":"record.json"}
                ]}]},"schemas":{"record.json":{"type":"object","required":["title"],"properties":{"title":{"type":"string"}},"additionalProperties":false}}});
            let mut bytes = rekey_policy::templates::TEMPLATE_SIGN_PREFIX.to_vec();
            bytes.extend(serde_jcs::to_vec(&package).unwrap());
            package["signature"] = data_encoding::BASE64URL_NOPAD
                .encode(key.sign(&bytes).as_ref())
                .into();
            serde_json::to_vec(&package).unwrap()
        } else {
            Vec::new()
        };
        let install = json!({"source":source,"credential_id":credential,"bindings":bindings,"capabilities":capabilities,
            "name_prefix":"mcp","timeout_ms":2000,"request_max_bytes":4096,"allowed_extra_headers":[],
            "response_max_bytes":4096,"allowed_response_headers":["content-type"]});
        let response = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::TEMPLATE_INSTALL,
            &serde_json::to_vec(&install).unwrap(),
            &common::proof_and_secret_body(common::PASSWORD, &package),
        )
        .await;
        let actions: Vec<FixedHttpAction> = response.ok()["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|action| serde_json::from_value(action["action"].clone()).unwrap())
            .collect();
        let principal = PrincipalId::new_random();
        let grants: Vec<_> = capabilities.iter().map(|capability| json!({"rule":"template-default","capability":capability,"actions":actions.iter()
            .filter(|action| matches!(&action.target, rekey_domain::action::ActionTarget::Template {source,..} if &source.capability == capability))
            .map(|action|json!({"action_id":action.id,"version":action.version})).collect::<Vec<_>>()})).collect();
        let rules: Vec<_> = actions.iter().map(|action| {
            let mut rule = json!({"id":PolicyRuleId::new_random(),"effect":"permit","principal_id":principal,
                "action_id":action.id,"version":action.version,"resource":{"type":"mcp","id":action.id},"parameters":{"kind":"any_validated"}});
            if approval { rule["effect"] = "require-approval".into(); rule["approver"] = json!({"kind":"local-presence"});
                rule["approval"] = json!({"mode":"one-time","max_uses":1}); }
            rule
        }).collect();
        let snapshot = json!({"format_version":6,"version":1,"expires_at_ms":4_102_444_800_000_i64,
            "approvers":[],"workload_identities":[],"profiles":[{"name":"mcp","principal_id":principal,
                "grants":[{"instance":"fixture","capabilities":grants}],"session":{"ttl_ms":ttl,"max_uses":uses},
                "confirm_each_run":false,"isolation":"none","egress":"allow","llm_limits":[]}],
            "bindings":actions.iter().map(|action| json!({"action_id":action.id,"version":action.version,
                "resource":{"type":"mcp","id":action.id},"parameter_schema_id":"mcp/v1","parameter_schema":{}})).collect::<Vec<_>>(),"rules":rules});
        if let Some((id, key)) = signer {
            let mut envelope = json!({"format_version":1,"signer_id":id,"snapshot":snapshot});
            let mut bytes = b"RKPOLICY\0\x01".to_vec();
            bytes.extend(serde_jcs::to_vec(&envelope).unwrap());
            envelope["signature"] = data_encoding::BASE64URL_NOPAD
                .encode(key.sign(&bytes).as_ref())
                .into();
            let metadata = common::policy::activation_metadata(
                &broker,
                &serde_json::to_vec(&envelope).unwrap(),
            )
            .await;
            common::call(
                &broker.admin_sock(),
                Channel::Admin,
                admin_msg::POLICY_ACTIVATE,
                &metadata,
                &common::proof_body(common::PASSWORD),
            )
            .await
            .ok();
        } else {
            common::policy::activate_snapshot(&broker, snapshot.clone()).await;
        }
        Self {
            broker,
            actions,
            snapshot,
        }
    }
    async fn generic(uses: u32, ttl: i64, approval: bool) -> Self {
        Self::new(json!({"kind":"generic-bearer","origin":"https://api.example.com","actions":[{"method":"POST","path":"/mcp"}]}),
            &["fixed-actions"],json!([{}]),uses,ttl,approval).await
    }
    async fn mint(&self) -> (UnixStream, Zeroizing<String>) {
        let mut control = UnixStream::connect(self.broker.admin_sock()).await.unwrap();
        let response = frame(
            &mut control,
            Channel::Admin,
            admin_msg::PROFILE_SESSION_CREATE,
            json!({"profile":"mcp"}),
            &[],
        )
        .await;
        assert_eq!(response.ok(), &json!({}));
        let mut session: ipc::ProfileSessionCreatedResponse =
            serde_json::from_slice(&response.body).unwrap();
        (
            control,
            Zeroizing::new(std::mem::take(&mut session.session.capability_token)),
        )
    }
    fn mcp(&self, token: &str, version: &str) -> Mcp {
        Mcp::start(Some(&self.broker.agent_sock()), Some(token), version)
    }
}
async fn frame(
    stream: &mut UnixStream,
    channel: Channel,
    opcode: u16,
    metadata: Value,
    body: &[u8],
) -> common::WireResponse {
    let meta = Zeroizing::new(serde_json::to_vec(&metadata).unwrap());
    let header = FrameHeader {
        channel,
        flags: 0,
        message_type: opcode,
        request_id: RequestId::new_random(),
        metadata_len: meta.len() as u32,
        body_len: body.len() as u32,
    };
    stream.write_all(&header.encode()).await.unwrap();
    stream.write_all(&meta).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut bytes = [0; ipc::FRAME_HEADER_LEN];
    stream.read_exact(&mut bytes).await.unwrap();
    let h = FrameHeader::decode(&bytes).unwrap();
    let mut metadata = vec![0; h.metadata_len as usize];
    let mut body = vec![0; h.body_len as usize];
    stream.read_exact(&mut metadata).await.unwrap();
    stream.read_exact(&mut body).await.unwrap();
    common::WireResponse {
        message_type: h.message_type,
        metadata: serde_json::from_slice(&metadata).unwrap(),
        body,
    }
}
fn tool_name(list: &Value) -> String {
    list["result"]["tools"][0]["name"]
        .as_str()
        .expect("authorized tool")
        .into()
}
fn result_code(response: &Value) -> &str {
    response["result"]["structuredContent"]["code"]
        .as_str()
        .unwrap()
}
fn list_code(response: &Value) -> &str {
    response["error"]["data"]["code"].as_str().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_profile_discovery_is_public_non_consuming_and_preserves_protocol_and_body() {
    let f = Fixture::generic(1, 60000, false).await;
    for version in ["2025-06-18", "2025-11-25"] {
        let (control, token) = f.mint().await;
        let mut stream = UnixStream::connect(f.broker.agent_sock()).await.unwrap();
        let inventory = frame(
            &mut stream,
            Channel::Agent,
            agent_msg::PROFILE_INVENTORY,
            json!({"capability_token":token.as_str()}),
            &[],
        )
        .await;
        assert_eq!(inventory.ok(), &json!({}));
        let text = std::str::from_utf8(&inventory.body).unwrap();
        for private in [
            "credential_id",
            "auth",
            "fixed_headers",
            "signer_id",
            SECRET,
        ] {
            assert!(!text.contains(private));
        }
        let mut mcp = f.mcp(&token, version);
        let list = mcp.list();
        let name = tool_name(&list);
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 3);
        assert_eq!(
            list["result"]["tools"][0]["title"],
            "fixture / fixed-actions"
        );
        assert_eq!(
            list["result"]["tools"][0]["inputSchema"]["required"],
            json!(["body"])
        );
        assert_eq!(mcp.list(), list);
        assert_eq!(
            mcp.call(&name, json!({"operation":"0","body":{}}))["error"]["code"],
            -32602
        );
        assert_eq!(
            mcp.call(
                &name,
                json!({"body":{},"extra_headers":[["authorization","override"]]})
            )["error"]["code"],
            -32602
        );
        let response = mcp.call(
            &name,
            json!({"body":{"title":"hello","approval_challenge":"business value"}}),
        );
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["content"][0]["text"], r#"{"ok":true}"#);
        assert_eq!(list_code(&mcp.list()), "CAPABILITY_EXHAUSTED");
        assert_eq!(
            result_code(&mcp.call(&name, json!({"body":{}}))),
            "CAPABILITY_EXHAUSTED"
        );
        drop((mcp, control));
    }
    let requests = f.broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.path, "/mcp");
        assert_eq!(
            request.body,
            br#"{"approval_challenge":"business value","title":"hello"}"#
        );
        assert!(request.auth_value == b"Bearer mcp-test-secret");
    }
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_multi_action_has_closed_operations_and_get_keeps_params_query_outside_body() {
    let f = Fixture::new(
        json!({"kind":"github-pat"}),
        &["read-repo"],
        json!([{"owner":"fixture","repo":"project"}]),
        20,
        60000,
        false,
    )
    .await;
    let (control, token) = f.mint().await;
    let mut mcp = f.mcp(&token, "2025-11-25");
    let list = mcp.list();
    let name = tool_name(&list);
    assert_eq!(
        list["result"]["tools"][0]["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    for args in [
        json!({}),
        json!({"operation":"7"}),
        json!({"operation":"00"}),
        json!({"operation":"0","body":null}),
    ] {
        assert_eq!(mcp.call(&name, args)["error"]["code"], -32602);
    }
    let args = [
        json!({"operation":"0"}),
        json!({"operation":"1","query":{"state":"open","page":"2"}}),
        json!({"operation":"2","params":{"number":"3"}}),
        json!({"operation":"3","params":{"number":"3"}}),
        json!({"operation":"4"}),
        json!({"operation":"5"}),
        json!({"operation":"6","params":{"path":"README.md"}}),
    ];
    for args in args {
        assert_eq!(mcp.call(&name, args)["result"]["isError"], false);
    }
    let requests = f.broker.fake.take_requests();
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests[1].path,
        "/repos/fixture/project/issues?page=2&state=open"
    );
    assert_eq!(requests[2].path, "/repos/fixture/project/pulls/3");
    assert_eq!(
        requests[6].path,
        "/repos/fixture/project/contents/README.md"
    );
    for request in requests {
        assert_eq!(request.method, "GET");
        assert!(request.body.is_empty());
        assert!(
            request
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
        );
    }
    drop((mcp, control));
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_body_schema_and_fixed_headers_remain_daemon_authority() {
    let f = Fixture::new(
        json!({"kind":"github-pat"}),
        &["create-issue"],
        json!([{"owner":"fixture","repo":"project"}]),
        3,
        60000,
        false,
    )
    .await;
    let (control, token) = f.mint().await;
    let mut mcp = f.mcp(&token, "2025-11-25");
    let list = mcp.list();
    let name = tool_name(&list);
    assert_eq!(
        list["result"]["tools"][0]["inputSchema"]["properties"]["body"]["allOf"][1]["required"],
        json!(["title"])
    );
    assert_eq!(
        mcp.call(
            &name,
            json!({"body":{},"extra_headers":[["accept","unsafe"]]})
        )["error"]["code"],
        -32602
    );
    assert_eq!(
        mcp.call(&name, json!({"body":{}}))["result"]["isError"],
        true
    );
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(
        mcp.call(&name, json!({"body":{"title":"issue"}}))["result"]["isError"],
        false
    );
    let requests = f.broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/repos/fixture/project/issues");
    assert_eq!(requests[0].body, br#"{"title":"issue"}"#);
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "accept" && value == "application/vnd.github+json")
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "x-github-api-version" && value == "2022-11-28")
    );
    drop((mcp, control));
    f.broker.shutdown().await;
}

#[test]
fn no_session_is_structured_and_old_manifest_has_no_fallback() {
    let mut mcp = Mcp::start(None, None, "2025-11-25");
    assert_eq!(list_code(&mcp.list()), "NEEDS_SESSION");
    assert_eq!(
        result_code(&mcp.call("missing", json!({}))),
        "NEEDS_SESSION"
    );
    assert_eq!(
        result_code(&mcp.call(
            "await_approval",
            json!({"challenge_id":rekey_domain::ids::ApprovalRequestId::new_random()})
        )),
        "NEEDS_SESSION"
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
async fn refresh_after_owner_eof_expiry_policy_change_and_lock_never_serves_cached_list() {
    for mode in ["eof", "expiry", "policy", "lock", "disabled"] {
        let mut f = Fixture::generic(10, if mode == "expiry" { 250 } else { 60000 }, false).await;
        let (control, token) = f.mint().await;
        let mut mcp = f.mcp(&token, "2025-11-25");
        let name = tool_name(&mcp.list());
        let mut control = Some(control);
        match mode {
            "eof" => drop(control.take()),
            "expiry" => tokio::time::sleep(Duration::from_millis(300)).await,
            "policy" => {
                f.snapshot["version"] = 2.into();
                common::policy::activate_snapshot(&f.broker, f.snapshot.clone()).await;
            }
            "lock" => {
                common::call(
                    &f.broker.admin_sock(),
                    Channel::Admin,
                    admin_msg::LOCK,
                    b"{}",
                    &[],
                )
                .await
                .ok();
            }
            "disabled" => {
                common::call(
                    &f.broker.admin_sock(),
                    Channel::Admin,
                    admin_msg::ACTION_DISABLE,
                    &serde_json::to_vec(&json!({"action_id":f.actions[0].id})).unwrap(),
                    &common::proof_body(common::PASSWORD),
                )
                .await
                .ok();
            }
            _ => unreachable!(),
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let list = mcp.list();
            if list.get("error").is_some() {
                assert!(list["result"]["tools"].is_null());
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            mcp.call(&name, json!({"body":{}}))["result"]["isError"],
            true
        );
        assert!(f.broker.fake.take_requests().is_empty());
        drop((mcp, control));
        f.broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exhausted_profile_control_waits_for_owner_close_ttl_or_lock() {
    for mode in ["owner", "ttl", "lock"] {
        let f = Fixture::generic(1, if mode == "ttl" { 1000 } else { 60000 }, false).await;
        let (mut control, token) = f.mint().await;
        let mut mcp = f.mcp(&token, "2025-11-25");
        let name = tool_name(&mcp.list());
        let response = mcp.call(&name, json!({"body":{}}));
        assert_eq!(response["result"]["content"][0]["text"], r#"{"ok":true}"#);
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(list_code(&mcp.list()), "CAPABILITY_EXHAUSTED");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), control.read_u8())
                .await
                .is_err(),
            "exhaustion closed the owner control connection"
        );
        if mode == "lock" {
            common::call(
                &f.broker.admin_sock(),
                Channel::Admin,
                admin_msg::LOCK,
                b"{}",
                &[],
            )
            .await
            .ok();
        }
        if mode != "owner" {
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), control.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
        drop(control);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let response = mcp.list();
            let code = list_code(&response);
            if code != "CAPABILITY_EXHAUSTED" {
                assert!(matches!(
                    code,
                    "INVALID_CAPABILITY" | "CAPABILITY_EXPIRED" | "LOCKED" | "DRAINING"
                ));
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(f.broker.fake.take_requests().len(), 1);
        drop(mcp);
        f.broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_approval_query_survives_consumed_last_use_and_retry_stays_explicit() {
    let f = Fixture::generic(1, 60000, true).await;
    let (control, token) = f.mint().await;
    let mut mcp = f.mcp(&token, "2025-11-25");
    let name = tool_name(&mcp.list());
    let request = json!({"body":{"title":"hello"}});
    let response = mcp.call(&name, request.clone());
    let required = &response["result"]["structuredContent"];
    assert_eq!(required["code"], "APPROVAL_REQUIRED");
    assert_eq!(required["retryable"], false);
    let challenge = required["approval"]["challenge_id"].clone();
    assert!(challenge.is_string());
    assert_eq!(tool_name(&mcp.list()), name);
    assert!(f.broker.fake.take_requests().is_empty());
    let remembered = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::DESKTOP_REMEMBER,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    remembered.ok();
    let review = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        &serde_json::to_vec(&json!({"approval_request_id":challenge})).unwrap(),
        &[],
    )
    .await;
    let mut proof = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut proof);
    common::call(&f.broker.admin_sock(),Channel::Admin,admin_msg::APPROVAL_LOCAL_APPROVE,&serde_json::to_vec(&json!({"approval_request_id":challenge,"expected_review_sha256":review.ok()["review_sha256"]})).unwrap(),&proof).await.ok();
    let wait = json!({"challenge_id":challenge});
    assert_eq!(
        mcp.call("await_approval", wait.clone())["result"]["structuredContent"]["state"],
        "approved"
    );
    let mut retry = request;
    retry["approval_challenge"] = challenge;
    assert_eq!(mcp.call(&name, retry.clone())["result"]["isError"], false);
    assert_eq!(list_code(&mcp.list()), "CAPABILITY_EXHAUSTED");
    assert_eq!(
        mcp.call("await_approval", wait.clone())["result"]["structuredContent"]["state"],
        "consumed"
    );
    assert_eq!(
        mcp.call("cancel_approval", wait)["result"]["structuredContent"]["state"],
        "consumed"
    );
    assert_eq!(result_code(&mcp.call(&name, retry)), "CAPABILITY_EXHAUSTED");
    assert_eq!(f.broker.fake.take_requests().len(), 1);
    drop((mcp, control));
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_status_mime_binary_and_reflected_secret_contract_remain() {
    use rekey_broker::upstream::UpstreamResponse;
    let f = Fixture::generic(10, 60000, false).await;
    let (control, token) = f.mint().await;
    let mut mcp = f.mcp(&token, "2025-11-25");
    let name = tool_name(&mcp.list());
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
        let response = mcp.call(&name, json!({"body":{}}));
        if status == 403 {
            assert_eq!(response["result"]["isError"], true);
            assert_eq!(
                response["result"]["structuredContent"]["upstream_status"],
                403
            );
        } else if mime == "application/octet-stream" {
            assert_eq!(
                response["result"]["content"][0]["resource"]["mimeType"],
                mime
            );
            assert_eq!(response["result"]["content"][0]["resource"]["blob"], "//4=");
        } else {
            assert_eq!(result_code(&response), "RESPONSE_SECURITY_VIOLATION");
        }
    }
    assert_eq!(f.broker.fake.take_requests().len(), 3);
    drop((mcp, control));
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn software_t11_real_run_to_mcp_performs_500_calls_without_proof_or_prompt() {
    let f = Fixture::generic(500, 120000, false).await;
    let executable = std::env::current_exe().unwrap();
    let cli = executable.parent().unwrap().parent().unwrap().join("rekey");
    assert!(
        cli.is_file(),
        "build current rekey CLI in this target before T11"
    );
    let mut command = Command::new(cli);
    command
        .arg("--state-dir")
        .arg(&f.broker.state_dir)
        .args(["run", "mcp", "--"])
        .arg(env!("CARGO_BIN_EXE_rekey-mcp"))
        .env_remove("REKEY_CAPABILITY")
        .env_remove("REKEY_AGENT_SOCKET");
    // The open stdin contains only MCP requests, never proof input or a TTY.
    let mut mcp = Mcp::spawn(command, None, "2025-11-25");
    let name = tool_name(&mcp.list());
    for i in 0..500 {
        if i % 100 == 0 {
            assert_eq!(tool_name(&mcp.list()), name);
        }
        if i % 100 == 0 {
            eprintln!("T11 software progress: completed_calls={i}");
        }
        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mcp.call(&name, json!({"body":{"title":"synthetic"}}))
        })) {
            Ok(response) => response,
            Err(failure) => {
                let status = mcp.child.try_wait().unwrap();
                eprintln!(
                    "T11 failure: attempted_call={} actual_upstream_calls={} owner_exit={:?}",
                    i + 1,
                    f.broker.fake.requests.lock().unwrap().len(),
                    status.and_then(|status| status.code())
                );
                // The MCP descendant can retain stderr after run exits. Diagnostics
                // must not wait for either process or a pipe EOF before unwinding.
                std::panic::resume_unwind(failure);
            }
        };
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["content"][0]["text"], r#"{"ok":true}"#);
        assert_eq!(
            response["result"]["structuredContent"]["upstream_status"],
            200
        );
    }
    eprintln!(
        "T11 software progress: completed_calls=500 actual_upstream_calls={}",
        f.broker.fake.requests.lock().unwrap().len()
    );
    assert_eq!(list_code(&mcp.list()), "CAPABILITY_EXHAUSTED");
    assert_eq!(
        result_code(&mcp.call(&name, json!({"body":{}}))),
        "CAPABILITY_EXHAUSTED"
    );
    let count = f.broker.fake.take_requests().len();
    assert_eq!(count, 500);
    eprintln!("T11 software: expected_upstream_calls=500 actual_upstream_calls={count}");
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_custom_template_real_run_mcp_discovers_and_executes_without_builtin_semantics() {
    // An authenticated custom package may use this name without becoming an LLM provider.
    let f = Fixture::with_signed_template(
        json!({"kind":"signed-package"}),
        &["records"],
        json!([{"owner":"fixture"}]),
        4,
        60000,
        false,
        Some("anthropic@1"),
    )
    .await;
    let executable = std::env::current_exe().unwrap();
    let cli = executable.parent().unwrap().parent().unwrap().join("rekey");
    assert!(
        cli.is_file(),
        "build current rekey CLI in this target first"
    );
    let mut command = Command::new(cli);
    command
        .arg("--state-dir")
        .arg(&f.broker.state_dir)
        .args(["run", "mcp", "--"])
        .arg(env!("CARGO_BIN_EXE_rekey-mcp"))
        .env_remove("REKEY_CAPABILITY")
        .env_remove("REKEY_AGENT_SOCKET");
    let mut mcp = Mcp::spawn(command, None, "2025-11-25");
    let list = mcp.list();
    let name = tool_name(&list);
    assert_eq!(list["result"]["tools"][0]["title"], "fixture / records");
    assert_eq!(
        list["result"]["tools"][0]["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for arguments in [
        json!({"params":{"item":"record"}}),
        json!({"operation":"2"}),
        json!({"operation":"0","params":{"item":"record"},"body":{}}),
    ] {
        assert_eq!(mcp.call(&name, arguments)["error"]["code"], -32602);
    }
    assert!(f.broker.fake.take_requests().is_empty());
    assert_eq!(
        mcp.call(
            &name,
            json!({"operation":"0","params":{"item":"record"},"query":{"page":"2"}})
        )["result"]["isError"],
        false
    );
    assert_eq!(
        mcp.call(
            &name,
            json!({"operation":"1","params":{"item":"record"},"body":{"title":"fixture"}})
        )["result"]["isError"],
        false
    );
    let requests = f.broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/custom/fixture/record?page=2");
    assert_eq!(requests[0].method, "GET");
    assert!(requests[0].body.is_empty());
    assert_eq!(requests[1].path, "/custom/fixture/record");
    assert_eq!(requests[1].body, br#"{"title":"fixture"}"#);
    assert!(
        requests
            .iter()
            .all(|r| r.auth_value == b"Bearer mcp-test-secret")
    );
    drop(mcp);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let response = common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::STATUS,
            b"{}",
            &[],
        )
        .await;
        if response.ok()["sessions_active"] == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "run owner did not revoke"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f.broker.shutdown().await;
}
