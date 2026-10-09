//! Disposable real Authority/Unix IPC; no Keychain or device authentication.
mod common;
use rekey_domain::ipc::{Channel, admin_msg};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

async fn admin(
    b: &common::TestBroker,
    opcode: u16,
    meta: serde_json::Value,
    body: &[u8],
) -> common::WireResponse {
    common::call(
        &b.admin_sock(),
        Channel::Admin,
        opcode,
        &serde_json::to_vec(&meta).unwrap(),
        body,
    )
    .await
}

#[tokio::test]
async fn explicit_remember_lifetimes_and_strict_metadata() {
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let proof = common::proof_body(common::PASSWORD);
    assert_eq!(
        admin(&b, admin_msg::DESKTOP_REMEMBER, json!({}), &proof)
            .await
            .err_code(),
        "INVALID_FRAME"
    );
    for days in [1, 7, 30] {
        let duration = days * 86_400_000_i64;
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let receipt = admin(
            &b,
            admin_msg::DESKTOP_REMEMBER,
            json!({"lifetime_ms":duration}),
            &proof,
        )
        .await;
        let expiry = receipt.ok()["expires_at_ms"].as_i64().unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!((before + duration..=after + duration).contains(&expiry));
        let resumed = admin(
            &b,
            admin_msg::DESKTOP_RESUME,
            json!({}),
            &common::proof_body(&receipt.body),
        )
        .await;
        let session_expiry = resumed.ok()["expires_at_ms"].as_i64().unwrap();
        assert!(session_expiry <= expiry);
        if days <= 7 {
            assert_eq!(session_expiry, expiry);
        } else {
            assert!(session_expiry < before + 8 * 86_400_000);
        }
        let refused = admin(
            &b,
            admin_msg::DESKTOP_REMEMBER,
            json!({"lifetime_ms":duration}),
            &{
                let mut body = Vec::new();
                rekey_domain::ipc::encode_proof_body(
                    rekey_domain::ipc::ProofKind::Presence,
                    &receipt.body,
                    &mut body,
                );
                body
            },
        )
        .await;
        assert_eq!(refused.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    }
    for duration in [0, 999, 2_592_000_001_i64] {
        assert_eq!(
            admin(
                &b,
                admin_msg::DESKTOP_REMEMBER,
                json!({"lifetime_ms":duration}),
                &proof
            )
            .await
            .err_code(),
            "INVALID_UNLOCK_CREDENTIAL"
        );
    }
    b.shutdown().await;
}

#[tokio::test]
async fn privacy_lock_rejects_wrong_token_and_can_forget_grant_without_locking_vault() {
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let proof = common::proof_body(common::PASSWORD);
    let login = admin(&b, admin_msg::DESKTOP_LOGIN, json!({}), &proof).await;
    login.ok();
    let grant = admin(
        &b,
        admin_msg::DESKTOP_REMEMBER,
        json!({"lifetime_ms":86_400_000}),
        &proof,
    )
    .await;
    grant.ok();
    let wrong = admin(
        &b,
        admin_msg::DESKTOP_LOCK,
        json!({"forget_remembered":true}),
        &common::proof_body(&[b'a'; 64]),
    )
    .await;
    assert_eq!(wrong.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let add = |label: &str| json!({"label":label,"kind":"opaque-token"});
    admin(
        &b,
        admin_msg::DESKTOP_ADD,
        add("before-lock"),
        &common::proof_and_secret_body(&login.body, b"SYNTHETIC-DESKTOP-VALUE"),
    )
    .await
    .ok();
    admin(
        &b,
        admin_msg::DESKTOP_LOCK,
        json!({"forget_remembered":false}),
        &common::proof_body(&login.body),
    )
    .await
    .ok();
    assert_eq!(
        admin(&b, admin_msg::STATUS, json!({}), &[]).await.ok()["state"],
        "unlocked"
    );
    assert_eq!(
        admin(
            &b,
            admin_msg::DESKTOP_ADD,
            add("stale-session"),
            &common::proof_and_secret_body(&login.body, b"SYNTHETIC-DESKTOP-VALUE")
        )
        .await
        .err_code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    let resumed = admin(
        &b,
        admin_msg::DESKTOP_RESUME,
        json!({}),
        &common::proof_body(&grant.body),
    )
    .await;
    resumed.ok();
    admin(
        &b,
        admin_msg::DESKTOP_LOCK,
        json!({"forget_remembered":true}),
        &common::proof_body(&resumed.body),
    )
    .await
    .ok();
    assert_eq!(
        admin(
            &b,
            admin_msg::DESKTOP_RESUME,
            json!({}),
            &common::proof_body(&grant.body)
        )
        .await
        .err_code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    assert_eq!(
        admin(&b, admin_msg::STATUS, json!({}), &[]).await.ok()["state"],
        "unlocked"
    );
    b.shutdown().await;
}

#[tokio::test]
async fn short_grant_clamps_existing_desktop_session() {
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let proof = common::proof_body(common::PASSWORD);
    let login = admin(&b, admin_msg::DESKTOP_LOGIN, json!({}), &proof).await;
    login.ok();
    admin(
        &b,
        admin_msg::DESKTOP_REMEMBER,
        json!({"lifetime_ms":1000}),
        &proof,
    )
    .await
    .ok();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let request = common::proof_and_secret_body(&login.body, b"SYNTHETIC-DESKTOP-VALUE");
    assert_eq!(
        admin(
            &b,
            admin_msg::DESKTOP_ADD,
            json!({"label":"expired","kind":"opaque-token"}),
            &request
        )
        .await
        .err_code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    b.shutdown().await;
}

#[cfg(feature = "lab")]
#[tokio::test]
async fn privacy_lock_preserves_an_existing_agent_execution_capability() {
    use rekey_domain::ipc::agent_msg;
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let credential =
        common::add_credential(&b, "agent-continuity", b"SYNTHETIC-AGENT-CREDENTIAL").await;
    let (action, version) = common::create_action(&b, &credential).await;
    let token = common::create_session(&b, &action, version).await;
    let login = admin(
        &b,
        admin_msg::DESKTOP_LOGIN,
        json!({}),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    login.ok();
    admin(
        &b,
        admin_msg::DESKTOP_LOCK,
        json!({"forget_remembered":false}),
        &common::proof_body(&login.body),
    )
    .await
    .ok();
    b.fake
        .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: b"{}".to_vec().into(),
        }));
    common::call(
        &b.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        &serde_json::to_vec(&common::execute_meta(&token, &action, version)).unwrap(),
        b"{}",
    )
    .await
    .ok();
    b.shutdown().await;
}
