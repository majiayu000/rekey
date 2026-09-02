//! Admin IPC contract: locked-state behavior, step-up proofs, and channel
//! separation on the admin socket.

mod common;

use std::time::Duration;

use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{self, Channel, FrameHeader, ProofKind, admin_msg, agent_msg};

const NEW_PASSWORD: &[u8] = b"replacement horse battery staple";
const FINAL_PASSWORD: &[u8] = b"recovered horse battery staple";

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
async fn password_and_recovery_lifecycle_is_exposed_over_admin_ipc() {
    let broker = common::start_broker().await;
    let admin = broker.admin_sock();

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::PASSWORD_CHANGE,
        b"{}",
        &common::proof_and_secret_body(common::PASSWORD, NEW_PASSWORD),
    )
    .await;
    assert_eq!(response.err_code(), "LOCKED");

    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "wrapper-session", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let _token = common::create_session(&broker, &action, version).await;
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::PASSWORD_CHANGE,
        b"{}",
        &common::proof_and_secret_body(b"wrong", NEW_PASSWORD),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::PASSWORD_CHANGE,
        b"{}",
        &common::proof_and_secret_body(common::PASSWORD, NEW_PASSWORD),
    )
    .await;
    assert_eq!(response.ok()["changed"], true);
    assert!(response.body.is_empty());
    let response = common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
    assert_eq!(response.ok()["sessions_active"], 1);

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::RECOVERY_ROTATE,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    let mut wrong_kind = Vec::new();
    ipc::encode_proof_body(ProofKind::Recovery, b"RKREC1-NOT-A-KEY", &mut wrong_kind);
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::RECOVERY_ROTATE,
        b"{}",
        &wrong_kind,
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_INPUT");

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::RECOVERY_ROTATE,
        b"{}",
        &common::proof_body(NEW_PASSWORD),
    )
    .await;
    assert_eq!(response.ok()["rotated"], true);
    assert!(response.body.starts_with(b"RKREC1-"));
    let recovery = response.body;

    let mut recovery_change = Vec::new();
    ipc::encode_proof_and_secret_body(
        ProofKind::Recovery,
        &recovery,
        FINAL_PASSWORD,
        &mut recovery_change,
    );
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::PASSWORD_CHANGE,
        b"{}",
        &recovery_change,
    )
    .await;
    assert_eq!(response.ok()["changed"], true);

    common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[])
        .await
        .ok();
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        NEW_PASSWORD,
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::UNLOCK_RECOVERY,
        b"{}",
        &recovery,
    )
    .await;
    assert_eq!(response.ok()["unlocked"], true);

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(FINAL_PASSWORD),
    )
    .await;
    assert_eq!(response.ok()["shutdown"], true);
    tokio::time::timeout(Duration::from_secs(5), broker.serve_task)
        .await
        .expect("broker shutdown timed out")
        .expect("serve task panicked")
        .expect("broker shutdown failed");
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
        (
            admin_msg::PASSWORD_CHANGE,
            ipc::ADMIN_SECRET_BODY_MAX_BYTES + 1,
        ),
        (
            admin_msg::RECOVERY_ROTATE,
            ipc::ADMIN_PROOF_BODY_MAX_BYTES + 1,
        ),
        (
            admin_msg::POLICY_TRUST_INSTALL,
            ipc::ADMIN_PROOF_BODY_MAX_BYTES + 1,
        ),
        (
            admin_msg::POLICY_ACTIVATE,
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
    for message in [admin_msg::STATUS, admin_msg::POLICY_STATUS] {
        let broker =
            common::start_broker_with(Duration::from_secs(1), Duration::from_secs(2)).await;
        common::unlock(&broker).await;

        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(700)).await;
            common::call(&broker.admin_sock(), Channel::Admin, message, b"{}", &[])
                .await
                .ok();
        }

        let status = common::call(
            &broker.agent_sock(),
            Channel::Agent,
            agent_msg::AGENT_STATUS,
            b"{}",
            &[],
        )
        .await;
        assert_eq!(status.ok()["state"], "unlocked", "message {message}");
        broker.shutdown().await;
    }
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
