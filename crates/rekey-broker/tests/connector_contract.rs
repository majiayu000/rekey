//! Connector registry binding at the real Broker/Authority/UDS boundary.

mod common;

use rekey_domain::ipc::{Channel, admin_msg, agent_msg};

#[tokio::test(flavor = "multi_thread")]
async fn reserved_github_action_never_falls_back_to_opaque_header_injection() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "opaque", b"opaque-canary").await;
    let action = serde_json::json!({
        "name": "reserved-github-action",
        "credential_id": credential_id,
        "origin": "https://api.github.com",
        "method": "GET",
        "exact_path": "/installation/repositories",
        "auth_header": "authorization",
        "auth_prefix": "Bearer ",
        "timeout_ms": 30000,
        "request_max_bytes": 65536,
        "allowed_extra_headers": [],
        "response_max_bytes": 262144,
        "allowed_response_headers": [],
    });
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        action.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action_id = created.ok()["id"].as_str().unwrap().to_owned();
    let version = created.ok()["version"].as_u64().unwrap();
    let capability = common::create_session(&broker, &action_id, version).await;

    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "REQUEST_DENIED");
    assert!(
        broker.fake.take_requests().is_empty(),
        "registry mismatch must happen before upstream IO"
    );
    broker.shutdown().await;
}
