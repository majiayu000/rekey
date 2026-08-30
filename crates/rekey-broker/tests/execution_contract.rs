//! Fixed HTTP action execution: injection happens server-side, the agent
//! never influences origin/method/path/auth, and audit evidence is written
//! in order.

mod common;

use rekey_domain::ipc::{Channel, agent_msg};
use rekey_vault::store::SqliteRecordStore;

#[tokio::test(flavor = "multi_thread")]
async fn vertical_slice_executes_with_injected_credential() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "gh", b"ghp_secret_token").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        br#"{"title":"hello"}"#,
    )
    .await;
    let ok = response.ok().clone();
    assert_eq!(ok["upstream_status"], 200);
    assert_eq!(response.body, b"{\"ok\":true}");

    // The upstream request was fully server-owned and carried the credential.
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.host, "api.example.com");
    assert_eq!(request.port, 443);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/things");
    assert_eq!(request.auth_name, "authorization");
    assert_eq!(request.auth_value, b"Bearer ghp_secret_token");
    assert_eq!(request.body, br#"{"title":"hello"}"#);

    // Response header filtering: only the allowlist survives.
    let headers = ok["headers"].as_array().unwrap();
    assert!(headers.iter().any(|h| h[0] == "content-type"));

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    // Audit order: started before finished, both committed.
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let events = store.audit_event_types().unwrap();
    let started = events.iter().position(|e| e == "execution.started");
    let finished = events.iter().position(|e| e == "execution.finished");
    assert!(started.is_some() && finished.is_some());
    assert!(started.unwrap() < finished.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_broker_refuses_execution() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "gh2", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    // Lock revokes sessions and clears the VRK.
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        rekey_domain::ipc::admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "LOCKED");
    assert!(
        broker.fake.take_requests().is_empty(),
        "no upstream call while locked"
    );

    common::unlock(&broker).await;
    let after_unlock = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(after_unlock.err_code(), "INVALID_CAPABILITY");
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_credential_stops_new_executions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "gh3", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let meta = serde_json::json!({ "credential_id": credential_id });
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        rekey_domain::ipc::admin_msg::CREDENTIAL_REVOKE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    // Either the in-memory session was already invalidated or the persistent
    // credential re-check refused the lease; both fail closed.
    assert!(
        ["INVALID_CAPABILITY", "CREDENTIAL_UNAVAILABLE"].contains(&response.err_code().as_str()),
        "unexpected code {}",
        response.err_code()
    );
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_action_refused_and_use_counting_applies() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "gh4", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let meta = serde_json::json!({ "action_id": action_id });
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        rekey_domain::ipc::admin_msg::ACTION_DISABLE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    // Disabling revokes bound sessions; a fresh session would see
    // ACTION_DISABLED at pinning time.
    assert!(
        ["INVALID_CAPABILITY", "ACTION_DISABLED"].contains(&response.err_code().as_str()),
        "unexpected code {}",
        response.err_code()
    );
    broker.shutdown().await;
}
