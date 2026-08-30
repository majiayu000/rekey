//! Agent IPC contract: the agent socket carries execution and a redacted
//! status only — no admin messages, no secret reads, no unlock.

mod common;

use rekey_domain::ipc::{Channel, admin_msg, agent_msg};

#[tokio::test]
async fn empty_agent_uid_allowlist_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    rekey_vault::bootstrap::init_vault(
        &state_dir,
        &rekey_vault::secret::SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
    )
    .expect("init vault");
    let mut config = rekey_broker::runtime::BrokerConfig::new(state_dir);
    config.allowed_agent_uids.clear();
    let err = rekey_broker::runtime::serve(config)
        .await
        .expect_err("empty Agent UID allowlist must reject startup");
    assert_eq!(err.code(), "INSECURE_STATE_PERMISSIONS");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_messages_rejected_on_agent_socket() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let agent = broker.agent_sock();

    // Admin-channel frame on the agent socket: dropped.
    let raw = {
        let header = rekey_domain::ipc::FrameHeader {
            channel: Channel::Admin,
            flags: 0,
            message_type: admin_msg::CREDENTIAL_LIST,
            request_id: rekey_domain::ids::RequestId::new_random(),
            metadata_len: 2,
            body_len: 0,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"{}");
        bytes
    };
    assert!(common::send_raw(&agent, &raw).await.is_none());

    // Agent-channel frame with an admin message type id: explicit error.
    for admin_type in [
        admin_msg::UNLOCK_PASSWORD,
        admin_msg::CREDENTIAL_ADD,
        admin_msg::CREDENTIAL_LIST,
        admin_msg::SESSION_CREATE,
        admin_msg::BACKUP,
        admin_msg::SHUTDOWN,
    ] {
        // Same numeric ids exist on the agent channel only for EXECUTE(1) and
        // STATUS(2); everything else must be rejected.
        if admin_type == agent_msg::EXECUTE_FIXED_HTTP_ACTION
            || admin_type == agent_msg::AGENT_STATUS
        {
            continue;
        }
        let response = common::call(&agent, Channel::Agent, admin_type, b"{}", &[]).await;
        assert_eq!(
            response.err_code(),
            "INVALID_FRAME",
            "type {admin_type} must be rejected"
        );
    }

    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_status_is_redacted() {
    let broker = common::start_broker().await;
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::AGENT_STATUS,
        b"{}",
        &[],
    )
    .await;
    let ok = response.ok();
    assert_eq!(ok["state"], "locked");
    // Redacted subset: no vault id, no format version, no session counts.
    assert!(ok.get("vault_id").is_none());
    assert!(ok.get("format_version").is_none());
    assert!(ok.get("sessions_active").is_none());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_requires_valid_capability() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "cap-test", b"secret-value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;

    // Garbage token.
    let meta = common::execute_meta("not-a-real-token", &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_CAPABILITY");

    // Valid token, wrong action version.
    let token = common::create_session(&broker, &action_id, version).await;
    let meta = common::execute_meta(&token, &action_id, version + 1);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "ACTION_DENIED");

    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn capability_token_is_not_admin_proof() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "not-admin", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    // Using the capability token as a step-up proof must fail.
    let meta = serde_json::json!({"label": "escalation", "kind": "opaque-token"});
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        meta.to_string().as_bytes(),
        &common::proof_and_secret_body(token.as_bytes(), b"v2"),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    broker.shutdown().await;
}
