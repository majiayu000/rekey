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
    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":{"title":"hello"}}})
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
    assert_eq!(output[2]["result"]["tools"].as_array().unwrap().len(), 1);
    assert_eq!(output[2]["result"]["tools"][0]["name"], name);
    assert_eq!(
        output[2]["result"]["tools"][0]["inputSchema"]["required"],
        json!(["title"])
    );
    assert_eq!(
        output[2]["result"]["tools"][0]["inputSchema"]["properties"]["title"]["type"],
        "string"
    );
    assert_eq!(output[3]["result"]["isError"], false);
    let result: Value =
        serde_json::from_str(output[3]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["upstream_status"], 200);
    assert_eq!(
        data_encoding::BASE64
            .decode(result["body_base64"].as_str().unwrap().as_bytes())
            .unwrap(),
        br#"{"ok":true}"#
    );
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
async fn no_body_get_actions_are_rejected_at_manifest_load() {
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
    private(&dir.join("action.json"), &action);
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
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
        .arg("--manifest")
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no-body GET actions are incompatible with MCP JSON invocation"),
        "{stderr}"
    );
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
    let body: Value =
        serde_json::from_str(output[1]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["upstream_status"], 403);
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
