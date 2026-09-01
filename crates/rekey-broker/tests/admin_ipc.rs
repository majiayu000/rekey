//! Admin IPC contract: locked-state behavior, step-up proofs, and channel
//! separation on the admin socket.

mod common;

use std::time::Duration;

use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{self, Channel, FrameHeader, admin_msg, agent_msg};

#[tokio::test(flavor = "multi_thread")]
async fn admin_lifecycle_and_step_up() {
    let broker = common::start_broker().await;
    let admin = broker.admin_sock();

    // Status while locked.
    let response = common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
    assert_eq!(response.ok()["state"], "locked");

    // Mutations while locked fail closed.
    let meta = serde_json::json!({"label": "x", "kind": "opaque-token"});
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

#[tokio::test(flavor = "multi_thread")]
async fn admin_reader_rejects_oversized_fields_before_body_allocation() {
    let broker = common::start_broker().await;
    for (message_type, body_len) in [
        (
            admin_msg::UNLOCK_PASSWORD,
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES + 1,
        ),
        (
            admin_msg::SESSION_CREATE,
            ipc::ADMIN_PROOF_BODY_MAX_BYTES + 1,
        ),
    ] {
        let header = FrameHeader {
            channel: Channel::Admin,
            flags: 0,
            message_type,
            request_id: RequestId::new_random(),
            metadata_len: 2,
            body_len,
        };
        let response = common::send_raw(&broker.admin_sock(), &header.encode()).await;
        assert!(
            response.is_none(),
            "oversized Admin body must close the connection"
        );
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bodyless_admin_messages_reject_attached_bodies() {
    let broker = common::start_broker().await;
    for message in [
        admin_msg::STATUS,
        admin_msg::CREDENTIAL_LIST,
        admin_msg::ACTION_LIST,
        admin_msg::POLICY_STATUS,
        admin_msg::LOCK,
        u16::MAX,
    ] {
        let header = FrameHeader {
            channel: Channel::Admin,
            flags: 0,
            message_type: message,
            request_id: RequestId::new_random(),
            metadata_len: 2,
            body_len: 1,
        };
        let response = common::send_raw(&broker.admin_sock(), &header.encode()).await;
        assert!(
            response.is_none(),
            "bodyless Admin frame must close before body read"
        );
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_and_policy_status_keep_an_unlocked_broker_active() {
    let broker = common::start_broker_with(Duration::from_secs(2), Duration::from_secs(2)).await;
    common::unlock(&broker).await;

    for message in [
        admin_msg::STATUS,
        admin_msg::STATUS,
        admin_msg::POLICY_STATUS,
        admin_msg::POLICY_STATUS,
    ] {
        tokio::time::sleep(Duration::from_millis(700)).await;
        let response =
            common::call(&broker.admin_sock(), Channel::Admin, message, b"{}", &[]).await;
        response.ok();
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let status = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(status.ok()["state"], "unlocked");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_does_not_queue_behind_an_active_drain() {
    let broker = common::start_broker_with(Duration::from_secs(300), Duration::from_secs(5)).await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "drain-unlock", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;
    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: Vec::new().into(),
            body: b"{}".to_vec().into(),
        }),
        Duration::from_secs(2),
    );

    let agent = broker.agent_sock();
    let metadata = common::execute_meta(&token, &action_id, version)
        .to_string()
        .into_bytes();
    let execute = tokio::spawn(async move {
        common::call(
            &agent,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            &metadata,
            b"{}",
        )
        .await
    });
    for _ in 0..100 {
        if !broker.fake.requests.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let admin = broker.admin_sock();
    let lock_admin = admin.clone();
    let lock = tokio::spawn(async move {
        common::call(&lock_admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let unlock = tokio::time::timeout(
        Duration::from_secs(1),
        common::call(
            &admin,
            Channel::Admin,
            admin_msg::UNLOCK_PASSWORD,
            b"{}",
            common::PASSWORD,
        ),
    )
    .await
    .expect("unlock must not wait for the drain");
    assert_eq!(unlock.err_code(), "AUTHORITY_BUSY");
    execute.await.unwrap().ok();
    assert_eq!(lock.await.unwrap().ok()["locked"], true);
    broker.shutdown().await;
}
