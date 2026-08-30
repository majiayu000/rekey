//! Capability session contract at the broker boundary: creation requires
//! step-up, tokens die with restart/lock, and expiry/use limits bind.

mod common;

use rekey_domain::ipc::{Channel, admin_msg, agent_msg};

#[tokio::test(flavor = "multi_thread")]
async fn session_create_requires_step_up_and_valid_actions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "sess", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;

    // Wrong proof.
    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 60_000,
        "max_uses": 5,
    });
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(b"wrong"),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    // Unknown action version.
    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version + 5}],
        "ttl_ms": 60_000,
        "max_uses": 5,
    });
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(response.err_code(), "ACTION_NOT_FOUND");

    // TTL above 24h rejected.
    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 25 * 3600 * 1000i64,
        "max_uses": 5,
    });
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_CAPABILITY");

    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn new_session_cannot_pin_retired_action_version() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "retire", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    assert_eq!(version, 1);

    let update = serde_json::json!({
        "action_id": action_id,
        "definition": common::action_meta(&credential_id),
    });
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_UPDATE,
        update.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();

    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": 1}],
        "ttl_ms": 60_000,
        "max_uses": 5,
    });
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(response.err_code(), "ACTION_DISABLED");

    let token = common::create_session(&broker, &action_id, 2).await;
    assert!(!token.is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn use_count_exhaustion_revokes() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "uses", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;

    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 60_000,
        "max_uses": 2,
    });
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let ok = response.ok();
    let token = ok["capability_token"].as_str().unwrap().to_owned();
    common::activate_test_policy(
        &broker,
        &action_id,
        version,
        ok["principal_id"].as_str().unwrap(),
    )
    .await;

    for _ in 0..2 {
        let meta = common::execute_meta(&token, &action_id, version);
        let response = common::call(
            &broker.agent_sock(),
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            meta.to_string().as_bytes(),
            b"{}",
        )
        .await;
        response.ok();
    }
    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert!(
        ["CAPABILITY_EXHAUSTED", "INVALID_CAPABILITY"].contains(&response.err_code().as_str()),
        "got {}",
        response.err_code()
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_revokes_all_sessions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "restart", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let state_dir = broker.state_dir.clone();
    let dir = broker.shutdown_keep_dir().await;

    // Boot a second broker over the same state directory.
    let fake = std::sync::Arc::new(rekey_broker::testing::FakeUpstreamTransport::new());
    let mut config = rekey_broker::runtime::BrokerConfig::new(state_dir.clone());
    config.idle_lock = std::time::Duration::from_secs(300);
    config.transport =
        Some(fake.clone() as std::sync::Arc<dyn rekey_broker::upstream::UpstreamTransport>);
    config.unlock_backoff_base = std::time::Duration::from_millis(20);
    config.drain_timeout = std::time::Duration::from_secs(2);
    let serve_task = tokio::spawn(async move {
        rekey_broker::runtime::serve(config)
            .await
            .expect("second serve");
    });
    let admin_sock = state_dir.join("runtime").join("admin.sock");
    for _ in 0..200 {
        if admin_sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    common::call(
        &admin_sock,
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        common::PASSWORD,
    )
    .await
    .ok();

    // Sessions are memory-only: the old token must be dead.
    let agent_sock = state_dir.join("runtime").join("agent.sock");
    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &agent_sock,
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_CAPABILITY");

    let body = common::proof_body(common::PASSWORD);
    common::call(
        &admin_sock,
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &body,
    )
    .await
    .ok();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), serve_task).await;
    drop(dir);
}
