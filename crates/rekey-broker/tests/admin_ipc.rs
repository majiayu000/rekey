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
async fn explicit_principal_issuance_requires_step_up_and_is_admin_only() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "reissue", b"synthetic-token").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let principal = rekey_domain::ids::PrincipalId::new_random().to_string();
    common::activate_test_policy(&broker, &action, version, &principal).await;
    let metadata = serde_json::json!({"actions":[{"action_id":action,"version":version}],
        "ttl_ms":60000,"max_uses":2,"principal_id":principal})
    .to_string();
    let rejected = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        metadata.as_bytes(),
        &common::proof_body(b"wrong-proof"),
    )
    .await;
    assert_eq!(rejected.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        metadata.as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(created.ok()["principal_id"], principal);
    let rejected = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        metadata.as_bytes(),
        b"synthetic.invalid.token",
    )
    .await;
    assert_eq!(rejected.err_code(), "INVALID_FRAME");
    broker.shutdown().await;
}
#[cfg(not(feature = "lab"))]
#[tokio::test(flavor = "multi_thread")]
async fn default_broker_rejects_lab_wire_entrypoints_and_source_registration() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    for operation in [
        admin_msg::METRICS,
        admin_msg::OIDC_LOGIN_BEGIN,
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
    ] {
        let reply = common::call(&broker.admin_sock(), Channel::Admin, operation, b"{}", &[]).await;
        assert_eq!(reply.err_code(), "INVALID_FRAME");
    }
    let reply = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        b"{}",
        b"synthetic.jwt",
    )
    .await;
    assert_eq!(reply.err_code(), "INVALID_FRAME");
    for kind in [
        "vault-kv-v2-source",
        "vault-dynamic-source",
        "keycloak-token-exchange",
        "gcp-secret-manager-source",
        "aws-secrets-manager-source",
        "azure-key-vault-source",
        "onepassword-connect-source",
        "macos-keychain-source",
    ] {
        let metadata = serde_json::json!({"label":"lab-source", "kind":kind}).to_string();
        let reply = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::CREDENTIAL_ADD,
            metadata.as_bytes(),
            &common::proof_and_secret_body(common::PASSWORD, b"synthetic-profile"),
        )
        .await;
        assert_eq!(reply.err_code(), "INVALID_INPUT", "{kind}");
    }
    let reply = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    assert!(reply.ok()["credentials"].as_array().unwrap().is_empty());
    broker.shutdown().await;
}

#[cfg(feature = "lab")]
const VAULT_PROFILE: &[u8] = br#"{
  "credential_type":"vault-kv-v2-source-v1",
  "origin":"https://vault.example.com",
  "mount":"secret",
  "path":"agents/github",
  "key":"token",
  "version":7,
  "vault_token":"hvs.source-canary"
}"#;
#[cfg(feature = "lab")]
const VAULT_DYNAMIC_PROFILE: &[u8] = br#"{
  "credential_type":"vault-dynamic-source-v2",
  "origin":"https://vault.example.com",
  "mount":"database",
  "role":"agent-api-token",
  "key":"token",
  "renew_increment_seconds":60,
  "vault_token":"hvs.dynamic-canary"
}"#;

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
#[cfg(feature = "lab")]
async fn vault_profile_admin_checks_proof_before_profile_and_preserves_kind() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let admin = broker.admin_sock();
    let add_meta = serde_json::json!({"label":"vault","kind":"vault-kv-v2-source"});

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        add_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(b"wrong-password", b"not-json"),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        add_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, VAULT_PROFILE),
    )
    .await;
    let vault_id = response.ok()["id"].as_str().unwrap().to_owned();
    assert_eq!(response.ok()["current_version"], 1);

    let opaque_id = common::add_credential(&broker, "opaque", b"secret").await;
    for (credential_id, profile) in [(&opaque_id, VAULT_PROFILE), (&vault_id, b"not-json")] {
        let rotate_meta = serde_json::json!({"credential_id":credential_id});
        let response = common::call(
            &admin,
            Channel::Admin,
            admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
            rotate_meta.to_string().as_bytes(),
            &common::proof_and_secret_body(common::PASSWORD, profile),
        )
        .await;
        assert_eq!(response.err_code(), "INVALID_INPUT");
    }

    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    let credentials = response.ok()["credentials"].as_array().unwrap();
    assert!(
        credentials
            .iter()
            .all(|credential| credential["current_version"] == 1)
    );

    let rotate_meta = serde_json::json!({"credential_id":vault_id});
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
        rotate_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, VAULT_PROFILE),
    )
    .await;
    assert_eq!(response.ok()["current_version"], 2);

    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "lab")]
async fn vault_dynamic_admin_checks_proof_before_profile_and_preserves_kind() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let admin = broker.admin_sock();
    let add_meta = serde_json::json!({"label":"dynamic","kind":"vault-dynamic-source"});

    let bad_proof = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        add_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(b"wrong-password", b"not-json"),
    )
    .await;
    assert_eq!(bad_proof.err_code(), "INVALID_UNLOCK_CREDENTIAL");

    let added = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        add_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, VAULT_DYNAMIC_PROFILE),
    )
    .await;
    let credential_id = added.ok()["id"].as_str().unwrap().to_owned();
    let opaque_id = common::add_credential(&broker, "dynamic-opaque", b"secret").await;
    for (target, profile) in [
        (opaque_id.as_str(), VAULT_DYNAMIC_PROFILE),
        (credential_id.as_str(), b"not-json".as_slice()),
    ] {
        let rotate_meta = serde_json::json!({"credential_id":target});
        let rejected = common::call(
            &admin,
            Channel::Admin,
            admin_msg::CREDENTIAL_ROTATE_VAULT_DYNAMIC,
            rotate_meta.to_string().as_bytes(),
            &common::proof_and_secret_body(common::PASSWORD, profile),
        )
        .await;
        assert_eq!(rejected.err_code(), "INVALID_INPUT");
    }
    let rotate_meta = serde_json::json!({"credential_id":credential_id});
    let rotated = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE_VAULT_DYNAMIC,
        rotate_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, VAULT_DYNAMIC_PROFILE),
    )
    .await;
    assert_eq!(rotated.ok()["current_version"], 2);

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
        admin_msg::APPROVAL_ORIGIN,
        admin_msg::APPROVAL_PENDING,
        admin_msg::APPROVAL_GET,
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

#[tokio::test(flavor = "multi_thread")]
async fn desktop_values_use_body_and_agent_channel_cannot_reveal() {
    let broker = common::start_broker().await;
    let admin = broker.admin_sock();
    let login = common::call(
        &admin,
        Channel::Admin,
        admin_msg::DESKTOP_LOGIN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(login.ok()["expires_in_seconds"], 604_800);
    let token = login.body;
    assert_eq!(token.len(), 64);
    let metadata = br#"{"label":"GLM","kind":"opaque-token"}"#;
    let saved = common::call(
        &admin,
        Channel::Admin,
        admin_msg::DESKTOP_ADD,
        metadata,
        &common::proof_and_secret_body(&token, b"desktop-value-canary"),
    )
    .await;
    let id = saved.ok()["id"].as_str().unwrap().to_owned();
    let reference = serde_json::json!({"credential_id":id}).to_string();
    let revealed = common::call(
        &admin,
        Channel::Admin,
        admin_msg::DESKTOP_REVEAL,
        reference.as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(revealed.body, b"desktop-value-canary");
    assert_eq!(revealed.ok(), &serde_json::json!({}));
    let recovery = common::call(
        &admin,
        Channel::Admin,
        admin_msg::RECOVERY_ROTATE,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await
    .body;
    let mut recovery_proof = Vec::new();
    ipc::encode_proof_body(ProofKind::Recovery, &recovery, &mut recovery_proof);
    let recovered = common::call(
        &admin,
        Channel::Admin,
        admin_msg::DESKTOP_REVEAL,
        reference.as_bytes(),
        &recovery_proof,
    )
    .await;
    assert_eq!(recovered.ok(), &serde_json::json!({}));
    assert_eq!(recovered.body, b"desktop-value-canary");
    for (body, expected) in [
        (common::proof_body(&token), "INVALID_UNLOCK_CREDENTIAL"),
        (
            common::proof_body(b"wrong-proof"),
            "INVALID_UNLOCK_CREDENTIAL",
        ),
        (common::proof_body(&recovery), "INVALID_UNLOCK_CREDENTIAL"),
        (Vec::new(), "INVALID_FRAME"),
    ] {
        let denied = common::call(
            &admin,
            Channel::Admin,
            admin_msg::DESKTOP_REVEAL,
            reference.as_bytes(),
            &body,
        )
        .await;
        assert_eq!(denied.err_code(), expected);
        assert!(
            denied.body.is_empty(),
            "rejection must not return plaintext"
        );
    }

    let denied = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        admin_msg::DESKTOP_REVEAL,
        reference.as_bytes(),
        &[],
    )
    .await;
    assert!(!denied.err_code().is_empty());
    common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[])
        .await
        .ok();
    let locked = common::call(
        &admin,
        Channel::Admin,
        admin_msg::DESKTOP_REVEAL,
        reference.as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(locked.err_code(), "LOCKED");
    broker.shutdown().await;
}

#[tokio::test]
async fn passive_status_polling_does_not_postpone_idle_lock() {
    let broker = common::start_broker_with(
        std::time::Duration::from_millis(80),
        std::time::Duration::from_secs(2),
    )
    .await;
    common::unlock(&broker).await;
    let mut locked = false;
    for _ in 0..20 {
        let status = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::PASSIVE_STATUS,
            b"{}",
            &[],
        )
        .await;
        if status.ok()["state"] == "locked" {
            locked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(locked, "background polling must allow idle locking");
    broker.shutdown().await;
}

#[tokio::test]
#[cfg(feature = "lab")]
async fn metrics_polling_does_not_postpone_idle_lock() {
    let broker = common::start_broker_with(Duration::from_millis(80), Duration::from_secs(2)).await;
    common::unlock(&broker).await;
    let mut locked = false;
    for _ in 0..20 {
        let snapshot = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::METRICS,
            b"{}",
            &[],
        )
        .await;
        assert!(snapshot.body.is_empty());
        serde_json::from_value::<ipc::MetricsResponse>(snapshot.ok().clone()).unwrap();
        let status = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::PASSIVE_STATUS,
            b"{}",
            &[],
        )
        .await;
        if status.ok()["state"] == "locked" {
            locked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(locked, "metrics polling must allow idle locking");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dek_rotation_is_admin_step_up_only_and_preserves_existing_capabilities() {
    let broker = common::start_broker().await;
    let admin = broker.admin_sock();
    let proof = common::proof_body(common::PASSWORD);
    let locked = common::call(
        &admin,
        Channel::Admin,
        admin_msg::KEY_ROTATE_DEK,
        b"{}",
        &proof,
    )
    .await;
    assert_eq!(locked.err_code(), "LOCKED");
    let denied = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        admin_msg::KEY_ROTATE_DEK,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(denied.err_code(), "INVALID_FRAME");
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "dek-canary", b"DEK-IPC-PRIVATE-CANARY").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let token = common::create_session(&broker, &action, version).await;
    let before = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    let wrong = common::call(
        &admin,
        Channel::Admin,
        admin_msg::KEY_ROTATE_DEK,
        b"{}",
        &common::proof_body(b"wrong-proof"),
    )
    .await;
    assert_eq!(wrong.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let malformed = common::call(
        &admin,
        Channel::Admin,
        admin_msg::KEY_ROTATE_DEK,
        br#"{"credential_id":"unaccepted-selector"}"#,
        &proof,
    )
    .await;
    assert_eq!(malformed.err_code(), "INVALID_FRAME");
    let absent = common::call(
        &admin,
        Channel::Admin,
        admin_msg::KEY_ROTATE_DEK,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(absent.err_code(), "INVALID_FRAME");
    let rotated = common::call(
        &admin,
        Channel::Admin,
        admin_msg::KEY_ROTATE_DEK,
        b"{}",
        &proof,
    )
    .await;
    assert_eq!(rotated.ok(), &serde_json::json!({"rotated_versions": 1}));
    assert!(rotated.body.is_empty());
    let after = common::call(
        &admin,
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(before.ok(), after.ok());
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: b"{}".to_vec().into(),
    }));
    let executed = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token, &action, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(executed.ok()["upstream_status"], 200);
    assert!(broker.fake.requests.lock().unwrap()[0].auth_value == b"Bearer DEK-IPC-PRIVATE-CANARY");
    assert!(!executed.ok().to_string().contains("DEK-IPC-PRIVATE-CANARY"));
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_shutdown_cannot_interrupt_a_vrk_rotation_before_authentication() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let broker =
        common::start_broker_with(Duration::from_secs(300), Duration::from_millis(20)).await;
    common::unlock(&broker).await;
    common::add_credential(&broker, "stop-root", b"STOP-VRK-CANARY").await;
    let recovery = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::RECOVERY_ROTATE,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    recovery.ok();
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    db.busy_timeout(Duration::ZERO).unwrap();
    let old_header: Vec<u8> = db
        .query_row("SELECT integrity_ciphertext FROM vault_header", [], |r| {
            r.get(0)
        })
        .unwrap();
    // Span the 20ms drain plus 5s finalize grace without exhausting the 45s cleanup budget.
    db.execute_batch("CREATE TRIGGER slow_root_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.vrk_rotated' BEGIN SELECT sum(n) FROM (WITH RECURSIVE delay(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM delay WHERE n<30000000) SELECT n FROM delay); END;").unwrap();
    let body = common::proof_and_secret_body(common::PASSWORD, &recovery.body);
    let mut stream = tokio::net::UnixStream::connect(broker.admin_sock())
        .await
        .unwrap();
    stream
        .write_all(
            &FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: admin_msg::KEY_ROTATE_VRK,
                request_id: RequestId::new_random(),
                metadata_len: 2,
                body_len: body.len() as u32,
            }
            .encode(),
        )
        .await
        .unwrap();
    stream.write_all(b"{}").await.unwrap();
    stream.write_all(&body).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match db.execute_batch("BEGIN IMMEDIATE;") {
            Ok(()) => db.execute_batch("ROLLBACK;").unwrap(),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                break;
            }
            Err(e) => panic!("unexpected lock probe {e}"),
        }
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let proofless = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(proofless.err_code(), "AUTHENTICATION_FAILED");
    let shutdown = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(b"wrong-proof"),
    )
    .await;
    assert_eq!(shutdown.err_code(), "AUTHORITY_BUSY");
    assert!(
        !broker.serve_task.is_finished(),
        "unauthenticated timeout must not stop the runtime"
    );
    // The earlier rotation retains its owner and may finish or reject at its own deadline.
    let mut header = [0; rekey_domain::ipc::FRAME_HEADER_LEN];
    tokio::time::timeout(Duration::from_secs(45), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let response = FrameHeader::decode(&header).unwrap();
    let mut metadata = vec![0; response.metadata_len as usize];
    stream.read_exact(&mut metadata).await.unwrap();
    let mut body = vec![0; response.body_len as usize];
    stream.read_exact(&mut body).await.unwrap();
    assert!(body.is_empty());
    let metadata: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    if response.message_type == ipc::resp_msg::ERROR {
        assert_eq!(metadata["code"], "AUTHORITY_BUSY");
    } else {
        assert_eq!(response.message_type, ipc::resp_msg::OK);
    }
    let successes: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='vault.vrk_rotated'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let new_header: Vec<u8> = db
        .query_row("SELECT integrity_ciphertext FROM vault_header", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(old_header == new_header, successes == 0);
    db.execute_batch("DROP TRIGGER slow_root_audit;").unwrap();
    drop(db);
    let status = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(status.ok()["state"], "locked");
    let stopped = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(stopped.ok()["shutdown"], true);
    tokio::time::timeout(Duration::from_secs(5), broker.serve_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn retention_admin_requires_explicit_days_proof_and_rejects_agent_opcodes() {
    let broker = common::start_broker().await;
    let admin = broker.admin_sock();
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::AUDIT_RETENTION_STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(response.err_code(), "LOCKED");
    common::call(
        &admin,
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        common::PASSWORD,
    )
    .await
    .ok();
    for metadata in [
        b"{}".as_slice(),
        b"{\"days\":0}",
        b"{\"days\":1,\"extra\":true}",
    ] {
        let response = common::call(
            &admin,
            Channel::Admin,
            admin_msg::AUDIT_RETENTION_SET,
            metadata,
            &common::proof_body(common::PASSWORD),
        )
        .await;
        assert_ne!(response.err_code(), "");
    }
    let response = common::call(
        &admin,
        Channel::Admin,
        admin_msg::AUDIT_RETENTION_SET,
        b"{\"days\":1}",
        &common::proof_body(b"wrong"),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    assert_eq!(
        common::call(
            &admin,
            Channel::Admin,
            admin_msg::AUDIT_RETENTION_SET,
            b"{\"days\":1}",
            &common::proof_body(common::PASSWORD)
        )
        .await
        .ok()["days"],
        1
    );
    assert_eq!(
        common::call(
            &admin,
            Channel::Admin,
            admin_msg::AUDIT_RETENTION_STATUS,
            b"{}",
            &[]
        )
        .await
        .ok()["days"],
        1
    );
    assert!(
        common::call(
            &admin,
            Channel::Admin,
            admin_msg::AUDIT_RETENTION_SET,
            b"{\"days\":null}",
            &common::proof_body(common::PASSWORD)
        )
        .await
        .ok()["days"]
            .is_null()
    );
    for opcode in [
        admin_msg::AUDIT_RETENTION_SET,
        admin_msg::AUDIT_RETENTION_STATUS,
    ] {
        let response = common::call(&broker.agent_sock(), Channel::Agent, opcode, b"{}", &[]).await;
        assert_ne!(response.err_code(), "");
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_shutdown_requires_current_proof_in_locked_and_unlocked_states() {
    for locked in [false, true] {
        for recovery_factor in [false, true] {
            let broker = common::start_broker().await;
            let admin = broker.admin_sock();
            common::unlock(&broker).await;
            let recovery = common::call(
                &admin,
                Channel::Admin,
                admin_msg::RECOVERY_ROTATE,
                b"{}",
                &common::proof_body(common::PASSWORD),
            )
            .await
            .body;
            if locked {
                common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[])
                    .await
                    .ok();
            }
            let mut wrong_recovery = Vec::new();
            ipc::encode_proof_body(
                ProofKind::Recovery,
                b"invalid-recovery",
                &mut wrong_recovery,
            );
            for (body, code) in [
                (Vec::new(), "AUTHENTICATION_FAILED"),
                (
                    common::proof_body(b"incorrect"),
                    "INVALID_UNLOCK_CREDENTIAL",
                ),
                (wrong_recovery, "INVALID_UNLOCK_CREDENTIAL"),
            ] {
                let reply =
                    common::call(&admin, Channel::Admin, admin_msg::SHUTDOWN, b"{}", &body).await;
                assert_eq!(reply.err_code(), code);
                assert!(!broker.serve_task.is_finished());
                let status =
                    common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
                assert_eq!(
                    status.ok()["state"],
                    if locked { "locked" } else { "unlocked" }
                );
            }
            let mut body = Vec::new();
            let (kind, proof) = if recovery_factor {
                (ProofKind::Recovery, recovery.as_slice())
            } else {
                (ProofKind::Password, common::PASSWORD)
            };
            ipc::encode_proof_body(kind, proof, &mut body);
            let reply =
                common::call(&admin, Channel::Admin, admin_msg::SHUTDOWN, b"{}", &body).await;
            assert_eq!(reply.ok()["shutdown"], true);
            tokio::time::timeout(Duration::from_secs(5), broker.serve_task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}
