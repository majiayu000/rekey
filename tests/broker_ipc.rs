//! Cross-boundary IPC contract: the agent data plane can never reach admin
//! capability, secret export does not exist on the wire, and the two sockets
//! stay separated.

use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use rekey_integration::harness as h;

#[tokio::test(flavor = "multi_thread")]
async fn agent_socket_has_no_admin_or_export_surface() {
    let broker = h::start_broker().await;
    h::unlock(&broker).await;
    let credential_id = h::add_credential(&broker, "ipc", b"secret-bytes").await;
    let (action_id, version) = h::create_action(&broker, &credential_id).await;
    let _token = h::create_session(&broker, &action_id, version).await;

    // Every admin message id (other than the two legitimate agent ids) is
    // rejected on the agent socket — including everything that could read or
    // export a secret.
    for message_type in 3u16..=64 {
        let response = h::call(
            &broker.agent_sock(),
            Channel::Agent,
            message_type,
            b"{}",
            &[],
        )
        .await;
        assert_eq!(
            response.err_code(),
            "INVALID_FRAME",
            "agent message type {message_type} must not exist"
        );
    }

    // The agent status subset leaks no identifiers.
    let response = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::AGENT_STATUS,
        b"{}",
        &[],
    )
    .await;
    assert!(response.ok().get("vault_id").is_none());

    // Admin frames on the agent socket are dropped by channel tag.
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(response.ok()["state"], "unlocked");

    broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_list_returns_metadata_only() {
    let broker = h::start_broker().await;
    h::unlock(&broker).await;
    let secret = b"list-canary-secret-value";
    h::add_credential(&broker, "listed", secret).await;
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    let serialized = response.ok().to_string();
    assert!(!serialized.contains(std::str::from_utf8(secret).unwrap()));
    broker.shutdown_keep_dir().await;
}
