//! Admin IPC contract: locked-state behavior, step-up proofs, and channel
//! separation on the admin socket.

mod common;

use rekey_domain::ipc::{Channel, admin_msg};

#[tokio::test(flavor = "multi_thread")]
async fn admin_lifecycle_and_step_up() {
    let broker = common::start_broker().await;
    let admin = broker.admin_sock();

    // Status while locked.
    let response = common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
    assert_eq!(response.ok()["state"], "locked");

    // Mutations while locked fail closed.
    let meta = serde_json::json!({"label": "x"});
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        meta.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, b"v"),
    )
    .await;
    assert_eq!(response.err_code(), "LOCKED");

    // Wrong unlock is uniform.
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        b"wrong",
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    common::unlock(&broker).await;
    let response = common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
    assert_eq!(response.ok()["state"], "unlocked");

    // Unlocked but wrong step-up proof: mutation still denied.
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        meta.to_string().as_bytes(),
        &common::proof_and_secret_body(b"wrong-password", b"v"),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    // Correct proof works end to end.
    let credential_id = common::add_credential(&broker, "gh-token", b"ghp_value").await;
    assert!(!credential_id.is_empty());

    // Lock revokes and locks.
    let response = common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await;
    assert_eq!(response.ok()["locked"], true);
    let response = common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
    assert_eq!(response.ok()["state"], "locked");

    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_channel_frames_rejected_on_admin_socket() {
    let broker = common::start_broker().await;
    // A frame tagged with the agent channel must be rejected by the admin
    // socket handler (connection closed, no response).
    let response = common::send_raw(&broker.admin_sock(), &{
        let header = rekey_domain::ipc::FrameHeader {
            channel: Channel::Agent,
            flags: 0,
            message_type: 1,
            request_id: rekey_domain::ids::RequestId::new_random(),
            metadata_len: 2,
            body_len: 0,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"{}");
        bytes
    })
    .await;
    assert!(
        response.is_none(),
        "admin socket must drop agent-channel frames"
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_frames_close_connection() {
    let broker = common::start_broker().await;
    for bytes in [
        b"XXXX0000000000000000000000000000000000".to_vec(),
        vec![0u8; 4],
        {
            // Correct magic, unsupported version.
            let mut bytes = rekey_domain::ipc::FRAME_MAGIC.to_vec();
            bytes.extend_from_slice(&9u16.to_be_bytes());
            bytes.extend_from_slice(&[1, 0, 0, 1, 0, 0]);
            bytes.extend_from_slice(&[1u8; 16]);
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes
        },
    ] {
        let response = common::send_raw(&broker.admin_sock(), &bytes).await;
        assert!(response.is_none(), "malformed frame must not get a reply");
    }
    broker.shutdown().await;
}
