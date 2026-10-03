//! Real stdio binary through real broker IPC; only upstream HTTP is a test seam.
mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use rekey_domain::ipc::{Channel, admin_msg};
use serde_json::{Value, json};

fn private(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rekey-test","version":"1"}}})
}

fn invocation(name: &str) -> Value {
    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":{"body":{"title":"hello"}}}})
}

fn call(manifest: &Path, requests: &[Value], token: &str) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .arg("--manifest")
        .arg(manifest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for request in requests {
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("mcp-test-secret"));
        assert!(!text.contains(token));
    }
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

async fn setup(broker: &common::TestBroker) -> (std::path::PathBuf, String, String, String) {
    common::unlock(broker).await;
    let credential = common::add_credential(broker, "mcp", b"mcp-test-secret").await;
    let action = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        common::action_meta(&credential).to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action = action.ok();
    let id = action["id"].as_str().unwrap().to_owned();
    let token = common::create_session(broker, &id, 1).await;
    let dir = broker.dir.path();
    private(&dir.join("action.json"), action);
    private(
        &dir.join("session.json"),
        &json!({"capability_token":token}),
    );
    let manifest = dir.join("mcp.json");
    private(
        &manifest,
        &json!({"agent_socket":broker.agent_sock(),"session_file":dir.join("session.json"),"tools":[{"action_file":dir.join("action.json"),"input_schema":{"type":"object","required":["title"],"properties":{"title":{"type":"string"}}}}]}),
    );
    (manifest, format!("rekey.{id}.v1"), token, id)
}

fn requests(name: &str) -> Vec<Value> {
    vec![
        initialize(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        invocation(name),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_and_success_use_fixed_action_without_leaking() {
    let broker = common::start_broker().await;
    let (manifest, name, token, _) = setup(&broker).await;
    let output = call(
        &manifest,
        &[
            json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
            initialize(),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            invocation(&name),
            invocation("missing"),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":name,"arguments":[]}}),
            json!({"jsonrpc":"2.0","id":5,"method":"admin/unlock"}),
            json!([{"jsonrpc":"2.0","id":6,"method":"ping"}]),
            json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":name,"arguments":{}}}),
        ],
        &token,
    );
    assert_eq!(output.len(), 8);
    assert_eq!(output[0]["error"]["code"], -32600);
    assert_eq!(output[1]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(output[2]["result"]["tools"].as_array().unwrap().len(), 3);
    assert_eq!(output[2]["result"]["tools"][0]["name"], name);
    assert_eq!(
        output[2]["result"]["tools"][0]["inputSchema"]["required"],
        json!(["body"])
    );
    assert_eq!(
        output[2]["result"]["tools"][0]["inputSchema"]["properties"]["body"]["properties"]["title"]
            ["type"],
        "string"
    );
    assert_eq!(output[3]["result"]["isError"], false);
    assert_eq!(
        output[3]["result"]["structuredContent"]["upstream_status"],
        200
    );
    assert_eq!(output[3]["result"]["content"][0]["text"], r#"{"ok":true}"#);
    assert_eq!(output[4]["error"]["code"], -32602);
    assert_eq!(output[5]["error"]["code"], -32602);
    assert_eq!(output[6]["error"]["code"], -32601);
    assert_eq!(output[7]["error"]["code"], -32600);
    let upstream = broker.fake.take_requests();
    assert_eq!(upstream.len(), 1);
    assert_eq!(upstream[0].body, br#"{"title":"hello"}"#);
    assert_eq!(upstream[0].auth_value, b"Bearer mcp-test-secret");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_expired_locked_are_explicit_and_do_not_reach_upstream() {
    let broker = common::start_broker().await;
    let (manifest, name, token, id) = setup(&broker).await;
    // A second principal has a valid capability, but no signed permit rule.
    let denied = common::policy::create_session_grant(&broker, &id, 1, 1).await;
    private(
        &broker.dir.path().join("session.json"),
        &json!({"capability_token":denied.capability_token}),
    );
    let output = call(&manifest, &requests(&name), &denied.capability_token);
    assert_eq!(output[1]["result"]["isError"], true);
    assert!(
        output[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("REQUEST_DENIED")
    );
    let expired = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        json!({"actions":[{"action_id":id,"version":1}],"ttl_ms":1,"max_uses":1})
            .to_string()
            .as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let expired = expired.ok()["capability_token"].as_str().unwrap();
    private(
        &broker.dir.path().join("session.json"),
        &json!({"capability_token":expired}),
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    let output = call(&manifest, &requests(&name), expired);
    assert!(
        output[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("CAPABILITY_EXPIRED")
    );
    private(
        &broker.dir.path().join("session.json"),
        &json!({"capability_token":token}),
    );
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    let output = call(&manifest, &requests(&name), &token);
    assert!(
        output[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("LOCKED")
    );
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[test]
fn malformed_json_and_private_file_failures_are_safe() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("mcp.json");
    let session = dir.path().join("session.json");
    private(&session, &json!({"capability_token":"private-test-token"}));
    private(
        &manifest,
        &json!({"agent_socket":"/no/broker/agent.sock","session_file":session,"tools":[]}),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .arg("--manifest")
        .arg(&manifest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{broken\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], -32700);
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .arg("--manifest")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-test-token"));
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("linked.json");
    std::os::unix::fs::symlink(&session, &link).unwrap();
    private(
        &manifest,
        &json!({"agent_socket":"/no/broker/agent.sock","session_file":link,"tools":[]}),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .arg("--manifest")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_body_get_actions_send_empty_bytes_without_content_type() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "mcp-get", b"mcp-test-secret").await;
    let mut meta = common::action_meta(&credential);
    meta["method"] = json!("GET");
    let action = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action = action.ok();
    let token = common::create_session(&broker, action["id"].as_str().unwrap(), 1).await;
    let dir = broker.dir.path();
    private(&dir.join("action.json"), action);
    private(
        &dir.join("session.json"),
        &json!({"capability_token":token}),
    );
    let manifest = dir.join("mcp-get.json");
    private(
        &manifest,
        &json!({
            "agent_socket": broker.agent_sock(),
            "session_file": dir.join("session.json"),
            "tools": [{
                "action_file": dir.join("action.json"),
                "input_schema": {"type": "object", "additionalProperties": false, "properties": {}}
            }]
        }),
    );
    let name = format!("rekey.{}.v1", action["id"].as_str().unwrap());
    let output = call(
        &manifest,
        &[
            initialize(),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            invocation(&name),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":name,"arguments":{}}}),
        ],
        &token,
    );
    assert_eq!(output[1]["error"]["code"], -32602);
    assert_eq!(output[2]["result"]["isError"], false);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
    assert!(
        requests[0]
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn template_fixed_content_type_is_not_duplicated_in_ipc() {
    use rekey_domain::ipc::{FRAME_HEADER_LEN, FrameHeader, agent_msg, resp_msg};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let broker = common::start_broker().await;
    let (manifest, name, token, _) = setup(&broker).await;
    let action_path = broker.dir.path().join("action.json");
    let mut action: Value = serde_json::from_slice(&std::fs::read(&action_path).unwrap()).unwrap();
    action["target"] = json!({
        "kind":"template", "target":{"path":"/v1/run","params":{},"query":{}},
        "fixed_headers":{"content-type":"application/json"},
        "body_schema":{"type":"object"},
        "source":{"template":"fixture@1","capability":"run","action_index":0,"digest":vec![7;32],"signer_id":null},
        "default_policy":{"rule":"allow"}
    });
    private(&action_path, &action);
    let socket = broker.agent_sock().with_file_name("mcp-mock.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut definition: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    definition["agent_socket"] = json!(socket);
    private(&manifest, &definition);
    let receiver = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; FRAME_HEADER_LEN];
        stream.read_exact(&mut bytes).await.unwrap();
        let header = FrameHeader::decode(&bytes).unwrap();
        assert_eq!(header.channel, Channel::Agent);
        assert_eq!(header.message_type, agent_msg::EXECUTE_FIXED_HTTP_ACTION);
        let mut metadata = vec![0; header.metadata_len as usize];
        let mut body = vec![0; header.body_len as usize];
        stream.read_exact(&mut metadata).await.unwrap();
        stream.read_exact(&mut body).await.unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert!(metadata["content_type"].is_null());
        assert_eq!(body, br#"{"title":"hello"}"#);
        let metadata = br#"{"upstream_status":200,"headers":[["content-type","application/json"]],"body_len":2}"#;
        let response = FrameHeader {
            channel: Channel::Agent,
            flags: 0,
            message_type: resp_msg::OK,
            request_id: header.request_id,
            metadata_len: metadata.len() as u32,
            body_len: 2,
        };
        stream.write_all(&response.encode()).await.unwrap();
        stream.write_all(metadata).await.unwrap();
        stream.write_all(b"{}").await.unwrap();
    });
    let output = call(&manifest, &requests(&name), &token);
    tokio::time::timeout(Duration::from_secs(3), receiver)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output[1]["result"]["isError"], false);
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn local_approval_wait_and_explicit_retry_work_with_one_capability_use() {
    use rekey_domain::ids::{PolicyRuleId, PrincipalId};
    use rekey_domain::ipc::ProofKind;
    let broker = common::start_broker().await;
    let (manifest, name, _, action) = setup(&broker).await;
    let principal = PrincipalId::new_random().to_string();
    common::policy::activate_snapshot(&broker, json!({
        // setup has installed version 1; this replaces it with local approval.
        "format_version":4, "version":2,
        "expires_at_ms":4_102_444_800_000_i64,"approvers":[],"workload_identities":[],
        "bindings":[{"action_id":action,"version":1,"resource":{"type":"test-action","id":action},"parameter_schema_id":"test-any-json/v1","parameter_schema":{}}],
        "rules":[{"id":PolicyRuleId::new_random(),"effect":"require-approval","principal_id":principal,"action_id":action,"version":1,"resource":{"type":"test-action","id":action},"parameters":{"kind":"any_validated"},"approver":{"kind":"local-presence"},"approval":{"mode":"one-time","max_uses":1}}]
    })).await;
    let session =
        common::policy::create_session_for_principal(&broker, &action, 1, 1, Some(&principal))
            .await;
    let token = session.capability_token;
    private(
        &broker.dir.path().join("session.json"),
        &json!({"capability_token":token}),
    );
    let output = call(&manifest, &requests(&name), &token);
    let required = &output[1]["result"]["structuredContent"];
    assert_eq!(required["code"], "APPROVAL_REQUIRED");
    assert_eq!(required["retryable"], false);
    let challenge = required["approval"]["challenge_id"].clone();
    assert!(challenge.is_string());
    assert!(broker.fake.take_requests().is_empty());

    let remembered = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::DESKTOP_REMEMBER,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    remembered.ok();
    let review = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        json!({"approval_request_id":challenge})
            .to_string()
            .as_bytes(),
        &[],
    )
    .await;
    assert_eq!(review.ok()["record_type"], "rekey.approval.local-review.v1");
    let mut proof = Vec::new();
    rekey_domain::ipc::encode_proof_body(ProofKind::Presence, &remembered.body, &mut proof);
    let approved = common::call(&broker.admin_sock(), Channel::Admin, admin_msg::APPROVAL_LOCAL_APPROVE, json!({"approval_request_id":challenge,"expected_review_sha256":review.metadata["review_sha256"]}).to_string().as_bytes(), &proof).await;
    assert_eq!(approved.ok()["state"], "approved");
    assert!(broker.fake.take_requests().is_empty());
    let wait = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"await_approval","arguments":{"challenge_id":challenge}}});
    let mut retry = invocation(&name);
    retry["params"]["arguments"]["approval_challenge"] = challenge;
    let output = call(
        &manifest,
        &[
            initialize(),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            wait.clone(),
            retry.clone(),
            wait,
            retry,
        ],
        &token,
    );
    assert_eq!(
        output[1]["result"]["structuredContent"]["state"],
        "approved"
    );
    assert_eq!(output[2]["result"]["isError"], false);
    assert_eq!(
        output[3]["result"]["structuredContent"]["state"],
        "consumed"
    );
    assert_eq!(output[4]["result"]["isError"], true);
    assert!(
        output[4]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("CAPABILITY_EXHAUSTED")
    );
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, br#"{"title":"hello"}"#);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_http_errors_and_reflected_secrets_are_not_successes() {
    use rekey_broker::upstream::UpstreamResponse;
    let broker = common::start_broker().await;
    let (manifest, name, token, _) = setup(&broker).await;
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 403,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())].into(),
        body: b"{\"error\":\"forbidden\"}".to_vec().into(),
    }));
    let output = call(&manifest, &requests(&name), &token);
    assert_eq!(output[1]["result"]["isError"], true);
    assert_eq!(
        output[1]["result"]["structuredContent"]["upstream_status"],
        403
    );
    assert_eq!(
        output[1]["result"]["content"][0]["text"],
        r#"{"error":"forbidden"}"#
    );
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())].into(),
        body: b"mcp-test-secret".to_vec().into(),
    }));
    let output = call(&manifest, &requests(&name), &token);
    assert_eq!(output[1]["result"]["isError"], true);
    assert!(
        output[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("RESPONSE_SECURITY_VIOLATION")
    );
    assert_eq!(broker.fake.take_requests().len(), 2);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn manifest_refuses_text_stream_action_before_advertising_a_tool() {
    let broker = common::start_broker().await;
    let (manifest, _, _, _) = setup(&broker).await;
    let path = broker.dir.path().join("action.json");
    let mut action: rekey_domain::action::FixedHttpAction =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    action.origin = rekey_domain::action::HttpsOrigin::parse("https://api.anthropic.com").unwrap();
    action.target = rekey_domain::action::ActionTarget::Fixed {
        path: rekey_domain::action::ExactPath::parse("/v1/messages").unwrap(),
    };
    action.auth = rekey_domain::action::HeaderCredentialUse::new(
        rekey_domain::action::HeaderName::new("x-api-key").unwrap(),
        rekey_domain::action::HeaderPrefix::new("").unwrap(),
    )
    .unwrap();
    action.request_policy.allowed_extra_headers.clear();
    action.response_policy.allowed_headers.clear();
    action.text_stream = Some(rekey_domain::action::AnthropicTextStream {
        model: "fixed-model".into(),
        max_tokens: 1024,
    });
    action.validate().unwrap();
    private(&path, &serde_json::to_value(action).unwrap());
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .arg("--manifest")
        .arg(&manifest)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid manifest action"));
    assert_eq!(broker.fake.take_requests().len(), 0);
    broker.shutdown().await;
}
