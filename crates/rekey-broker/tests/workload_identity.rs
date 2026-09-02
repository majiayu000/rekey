mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::ids::PrincipalId;
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use serde_json::{Value, json};

fn key_pair() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn identity(principal_id: PrincipalId, key: &Ed25519KeyPair) -> Value {
    json!({
        "principal_id": principal_id,
        "issuer": "https://issuer.example",
        "audiences": ["rekey://broker-test"],
        "max_token_age_ms": 900_000,
        "profile": {"kind":"oidc","subject":"service:builder"},
        "keys": [{
            "algorithm": "ed25519",
            "kid": "workload-key",
            "x": BASE64URL_NOPAD.encode(key.public_key().as_ref())
        }]
    })
}

fn token(key: &Ed25519KeyPair, jti: &str) -> Vec<u8> {
    let now = now_seconds();
    let header = BASE64URL_NOPAD.encode(
        &serde_json::to_vec(&json!({"alg":"EdDSA","kid":"workload-key","typ":"JWT"})).unwrap(),
    );
    let claims = BASE64URL_NOPAD.encode(
        &serde_json::to_vec(&json!({
            "iss": "https://issuer.example",
            "sub": "service:builder",
            "aud": "rekey://broker-test",
            "jti": jti,
            "iat": now - 1,
            "nbf": now - 1,
            "exp": now + 600
        }))
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    format!(
        "{input}.{}",
        BASE64URL_NOPAD.encode(key.sign(input.as_bytes()).as_ref())
    )
    .into_bytes()
}

fn create_meta(action_id: &str, version: u64, max_uses: u32) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 900_000,
        "max_uses": max_uses
    }))
    .unwrap()
}

async fn mint(
    broker: &common::TestBroker,
    action_id: &str,
    version: u64,
    token: &[u8],
    max_uses: u32,
) -> common::WireResponse {
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        &create_meta(action_id, version, max_uses),
        token,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_mint_executes_without_step_up_and_audits_redacted_origin() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "workload", b"secret-value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    let principal_id = PrincipalId::new_random();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(principal_id, &key),
        &[],
    )
    .await;
    let jwt = token(&key, "workload-success-canary");
    let mut line = jwt.clone();
    line.push(b'\n');
    let response = mint(&broker, &action_id, version, &line, 2).await;
    let created = response.ok();
    assert_eq!(created["principal_id"], principal_id.to_string());
    assert!(
        created["capability_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    let session_id = created["session_id"].as_str().unwrap().to_owned();
    let capability = created["capability_token"].as_str().unwrap().to_owned();

    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await
    .ok();

    let query = json!({
        "request_id": null,
        "session_id": session_id,
        "action_id": null,
        "credential_id": null,
        "outcome": null,
        "since_ms": null,
        "until_ms": null,
        "snapshot_max_sequence": null,
        "before_sequence": null,
        "limit": 100
    });
    let audit = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        query.to_string().as_bytes(),
        &[],
    )
    .await;
    audit.ok();
    let page: Value = serde_json::from_slice(&audit.body).unwrap();
    assert!(page["events"].as_array().unwrap().iter().any(|event| {
        event["event_type"] == "session.created" && event["reason_code"] == "workload-attested"
    }));
    let serialized = serde_json::to_string(&page).unwrap();
    for canary in [
        "workload-success-canary",
        "service:builder",
        std::str::from_utf8(&jwt).unwrap(),
        &capability,
    ] {
        assert!(!serialized.contains(canary), "audit leaked {canary}");
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_is_denied_atomically_in_a_concurrent_race() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "race", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(PrincipalId::new_random(), &key),
        &[],
    )
    .await;
    let jwt = token(&key, "one-use-race");
    let (left, right) = tokio::join!(
        mint(&broker, &action_id, version, &jwt, 1),
        mint(&broker, &action_id, version, &jwt, 1),
    );
    let outcomes = [left.message_type, right.message_type];
    assert_eq!(
        outcomes
            .iter()
            .filter(|kind| **kind == rekey_domain::ipc::resp_msg::OK)
            .count(),
        1
    );
    let denied = if left.message_type == rekey_domain::ipc::resp_msg::ERROR {
        left
    } else {
        right
    };
    assert_eq!(denied.err_code(), "WORKLOAD_IDENTITY_INVALID");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_mint_rejects_unauthorized_and_disabled_actions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "admission", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(PrincipalId::new_random(), &key),
        &[],
    )
    .await;

    let retryable = token(&key, "unauthorized");
    let unauthorized = mint(&broker, &action_id, version + 1, &retryable, 1).await;
    assert_eq!(unauthorized.err_code(), "REQUEST_DENIED");
    mint(&broker, &action_id, version, &retryable, 1).await.ok();

    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_DISABLE,
        json!({"action_id":action_id}).to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    let disabled = mint(&broker, &action_id, version, &token(&key, "disabled"), 1).await;
    assert_eq!(disabled.err_code(), "ACTION_DISABLED");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_activation_revokes_only_workload_sessions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "rotation", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let admin = common::policy::create_session_grant(&broker, &action_id, version, 5).await;
    let key = key_pair();
    let workload_principal = PrincipalId::new_random();
    let bundle = common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(workload_principal, &key),
        &[&admin.principal_id],
    )
    .await;
    let workload = mint(
        &broker,
        &action_id,
        version,
        &token(&key, "before-rotation"),
        5,
    )
    .await;
    let workload_capability = workload.ok()["capability_token"]
        .as_str()
        .unwrap()
        .to_owned();

    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::POLICY_ACTIVATE,
        &bundle,
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&workload_capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await
    .ok();

    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(workload_principal, &key),
        &[&admin.principal_id],
    )
    .await;
    let workload_execute = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&workload_capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(workload_execute.err_code(), "INVALID_CAPABILITY");
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&admin.capability_token, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await
    .ok();
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_tokens_share_one_error_and_workload_message_is_agent_only() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "invalid", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(PrincipalId::new_random(), &key),
        &[],
    )
    .await;
    for bad in [b"not.a.jwt".as_slice(), b" leading", b"two\nlines", b"\0"] {
        assert_eq!(
            mint(&broker, &action_id, version, bad, 1).await.err_code(),
            "WORKLOAD_IDENTITY_INVALID"
        );
    }
    let admin_response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        agent_msg::WORKLOAD_SESSION_CREATE,
        &create_meta(&action_id, version, 1),
        &token(&key, "wrong-channel"),
    )
    .await;
    assert_ne!(admin_response.message_type, rekey_domain::ipc::resp_msg::OK);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_audit_failure_revokes_capability_and_faults_closed() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "audit-failure", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(PrincipalId::new_random(), &key),
        &[],
    )
    .await;
    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_workload_session_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'session.created'
              AND NEW.reason_code = 'workload-attested'
             BEGIN SELECT RAISE(ABORT, 'injected workload audit failure'); END;",
        )
        .unwrap();
    drop(connection);
    let response = mint(
        &broker,
        &action_id,
        version,
        &token(&key, "audit-failure"),
        1,
    )
    .await;
    assert_eq!(response.err_code(), "AUDIT_COMMIT_FAILED");
    let stopped = tokio::time::timeout(Duration::from_secs(5), broker.serve_task).await;
    assert!(stopped.is_ok(), "faulted broker did not stop");
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_revokes_capability_but_preserves_replay_denial() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "restart-replay", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(PrincipalId::new_random(), &key),
        &[],
    )
    .await;
    let jwt = token(&key, "restart-replay");
    let first = mint(&broker, &action_id, version, &jwt, 1).await;
    let old_capability = first.ok()["capability_token"].as_str().unwrap().to_owned();
    let state_dir = broker.state_dir.clone();
    let dir = broker.shutdown_keep_dir().await;

    let fake = Arc::new(rekey_broker::testing::FakeUpstreamTransport::new());
    let mut config = rekey_broker::runtime::BrokerConfig::new(state_dir.clone());
    config.idle_lock = Duration::from_secs(300);
    config.transport = Some(fake as Arc<dyn rekey_broker::upstream::UpstreamTransport>);
    config.unlock_backoff_base = Duration::from_millis(20);
    config.drain_timeout = Duration::from_secs(2);
    let serve_task = tokio::spawn(async move { rekey_broker::runtime::serve(config).await });
    let admin_socket = state_dir.join("runtime/admin.sock");
    for _ in 0..200 {
        if admin_socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    common::call(
        &admin_socket,
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        common::PASSWORD,
    )
    .await
    .ok();
    let agent_socket = state_dir.join("runtime/agent.sock");
    let replay = common::call(
        &agent_socket,
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        &create_meta(&action_id, version, 1),
        &jwt,
    )
    .await;
    assert_eq!(replay.err_code(), "WORKLOAD_IDENTITY_INVALID");
    let old = common::call(
        &agent_socket,
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&old_capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(old.err_code(), "INVALID_CAPABILITY");
    common::call(
        &admin_socket,
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    let result = tokio::time::timeout(Duration::from_secs(5), serve_task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
    drop(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_sessions_obey_use_expiry_revoke_and_lock_lifecycle() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "workload-lifecycle", b"value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let key = key_pair();
    common::policy::activate_workload_policy(
        &broker,
        &action_id,
        version,
        identity(PrincipalId::new_random(), &key),
        &[],
    )
    .await;

    let one_use = mint(&broker, &action_id, version, &token(&key, "one-use"), 1).await;
    let capability = one_use.ok()["capability_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let execute_meta = common::execute_meta(&capability, &action_id, version).to_string();
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        execute_meta.as_bytes(),
        b"{}",
    )
    .await
    .ok();
    let exhausted = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        execute_meta.as_bytes(),
        b"{}",
    )
    .await;
    assert!(matches!(
        exhausted.err_code().as_str(),
        "CAPABILITY_EXHAUSTED" | "INVALID_CAPABILITY"
    ));

    let short_meta = serde_json::to_vec(&json!({
        "actions":[{"action_id":action_id,"version":version}],
        "ttl_ms":1,
        "max_uses":1
    }))
    .unwrap();
    let short = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        &short_meta,
        &token(&key, "short-lived"),
    )
    .await;
    let short_capability = short.ok()["capability_token"].as_str().unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let expired = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&short_capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert!(matches!(
        expired.err_code().as_str(),
        "CAPABILITY_EXPIRED" | "INVALID_CAPABILITY"
    ));

    let revoked = mint(&broker, &action_id, version, &token(&key, "revoked"), 2).await;
    let revoked_session = revoked.ok()["session_id"].as_str().unwrap().to_owned();
    let revoked_capability = revoked.ok()["capability_token"]
        .as_str()
        .unwrap()
        .to_owned();
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_REVOKE,
        json!({"session_id":revoked_session}).to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    let denied = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&revoked_capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(denied.err_code(), "INVALID_CAPABILITY");

    let locked = mint(&broker, &action_id, version, &token(&key, "locked"), 2).await;
    let locked_capability = locked.ok()["capability_token"].as_str().unwrap().to_owned();
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    let denied = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&locked_capability, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(denied.err_code(), "LOCKED");
    broker.shutdown().await;
}
