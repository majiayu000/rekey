//! Real Broker/Authority/Agent IPC and native reference sidecar; no GitHub IO.
#![cfg(target_os = "macos")]
mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use data_encoding::BASE64;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use serde_json::{Value, json};

fn profile() -> Vec<u8> {
    let generated = Command::new("/usr/bin/openssl")
        .args(["genrsa", "2048"])
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(generated.status.success());
    let mut convert = Command::new("/usr/bin/openssl")
        .args(["rsa", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    convert
        .stdin
        .take()
        .unwrap()
        .write_all(&generated.stdout)
        .unwrap();
    let der = convert.wait_with_output().unwrap();
    assert!(der.status.success());
    serde_json::to_vec(&json!({
        "credential_type":"github-app-installation-v2", "client_id":"fixture-client",
        "app_id":1,"installation_id":42,"repositories":[{"id":7,"owner":"owner","name":"repo"}],
        "permissions":{"metadata":"read","issues":"write"}, "webhook_secret":"s".repeat(32),
        "private_key_pkcs1_der_base64":BASE64.encode(&der.stdout)
    }))
    .unwrap()
}

fn response(status: u16, body: Value) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: Vec::new().into(),
        body: serde_json::to_vec(&body).unwrap().into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_public_request_reaches_broker_transport_and_revoke_precedes_success() {
    // Cargo builds broker binaries for this integration target.
    assert!(std::path::Path::new(env!("CARGO_BIN_EXE_rekey-github-create-issue")).is_file());
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        br#"{"label":"github","kind":"github-app-installation"}"#,
        &common::proof_and_secret_body(common::PASSWORD, &profile()),
    )
    .await;
    let credential = added.ok()["id"].as_str().unwrap();
    let mut meta = common::action_meta(credential);
    meta["origin"] = json!("https://api.github.com");
    meta["exact_path"] = json!("/repos/owner/repo/issues");
    meta["allowed_extra_headers"] = json!([]);
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action = created.ok()["id"].as_str().unwrap();
    let capability = common::create_session(&broker, action, 1).await;
    broker.fake.push_response(Ok(response(
        201,
        json!({
            "token":"installation-token-fixture-canary", "expires_at":"2099-01-01T00:00:00Z",
            "permissions":{"metadata":"read","issues":"write"}, "repositories":[{"id":7}],
            "repository_selection":"selected"
        }),
    )));
    broker.fake.push_response(Ok(response(
        201,
        json!({
            "id":44,"number":7,"repository_url":"https://api.github.com/repos/owner/repo",
            "html_url":"https://github.com/owner/repo/issues/7"
        }),
    )));
    let revoke = broker.fake.push_response_gated(Ok(UpstreamResponse {
        status: 204,
        headers: Vec::new().into(),
        body: Vec::new().into(),
    }));
    let socket = broker.agent_sock();
    let metadata = common::execute_meta(&capability, action, 1).to_string();
    let call_socket = socket.clone();
    let call_metadata = metadata.clone();
    let call = tokio::spawn(async move {
        common::call(
            &call_socket,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            call_metadata.as_bytes(),
            br#"{ "body" : "public details", "title" : "reference plugin" }"#,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while broker.fake.requests.lock().unwrap().len() < 3 {
            assert!(
                !call.is_finished(),
                "execution terminated before gated revoke"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("revoke request must reach deterministic transport");
    assert!(
        !call.is_finished(),
        "success must wait for revoke completion"
    );
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3, "exchange, public effect, revoke");
    assert_eq!(requests[0].path, "/app/installations/42/access_tokens");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
        json!({"repository_ids":[7],"permissions":{"metadata":"read","issues":"write"}})
    );
    assert_eq!(requests[1].path, "/repos/owner/repo/issues");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].body,
        br#"{"title":"reference plugin","body":"public details"}"#
    );
    assert_eq!(
        requests[1].auth_value,
        b"Bearer installation-token-fixture-canary"
    );
    assert_eq!(requests[2].path, "/installation/token");
    assert_eq!(requests[2].method, "DELETE");
    revoke.notify_one();
    let reply = call.await.unwrap();
    assert_eq!(reply.metadata["upstream_status"], 201, "{}", reply.metadata);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["number"],
        7
    );

    // Unknown and altered-effect fields fail before exchange; no extra upstream.
    for body in [
        br#"{"title":"reference","url":"https://evil"}"#.as_slice(),
        br#"{"title":""}"#,
    ] {
        let reply = common::call(
            &socket,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            metadata.as_bytes(),
            body,
        )
        .await;
        assert_eq!(reply.err_code(), "REQUEST_DENIED");
        assert!(broker.fake.take_requests().is_empty());
    }
    let state = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
    let mut statement = db.prepare("SELECT event_type FROM audit_events WHERE event_type LIKE 'execution.%' OR event_type LIKE 'connector.github.%' ORDER BY sequence").unwrap();
    let events: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let authorized = events
        .iter()
        .position(|event| event == "connector.github.authorized")
        .unwrap();
    let revoked = events
        .iter()
        .position(|event| event == "connector.github.token_revoked")
        .unwrap();
    let finished = events
        .iter()
        .position(|event| event == "execution.finished")
        .unwrap();
    assert!(
        events[..authorized]
            .iter()
            .any(|event| event == "execution.started")
    );
    assert!(authorized < revoked && revoked < finished);
}
