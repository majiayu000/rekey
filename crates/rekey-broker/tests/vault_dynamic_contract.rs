//! One-shot Vault dynamic leases at the real Broker/Authority/UDS boundary.

mod common;

use rekey_broker::upstream::{UpstreamError, UpstreamResponse};
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use zeroize::Zeroizing;

const LEASE_ID: &str = "database/creds/agent-api-token/lease-one";
const DYNAMIC_VALUE: &str = "dynamic-secret-one";

fn profile(token: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "credential_type":"vault-dynamic-source-v1",
        "origin":"https://vault.example.com",
        "mount":"database",
        "role":"agent-api-token",
        "key":"token",
        "vault_token":token
    }))
    .unwrap()
}

fn response(status: u16, body: &[u8]) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())].into(),
        body: Zeroizing::new(body.to_vec()),
    }
}

fn issued() -> UpstreamResponse {
    response(
        200,
        serde_json::to_vec(&serde_json::json!({
            "lease_id":LEASE_ID,
            "lease_duration":60,
            "renewable":true,
            "data":{"username":"ignored","token":DYNAMIC_VALUE},
            "request_id":"ignored"
        }))
        .unwrap()
        .as_slice(),
    )
}

async fn setup() -> (common::TestBroker, String, String, u64, String) {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let metadata = serde_json::json!({"label":"dynamic","kind":"vault-dynamic-source"});
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, &profile("hvs.bootstrap")),
    )
    .await;
    let credential_id = added.ok()["id"].as_str().unwrap().to_owned();
    let (action_id, action_version) = common::create_action(&broker, &credential_id).await;
    let capability = common::create_session(&broker, &action_id, action_version).await;
    (broker, credential_id, action_id, action_version, capability)
}

async fn execute(
    broker: &common::TestBroker,
    capability: &str,
    action_id: &str,
    action_version: u64,
) -> common::WireResponse {
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(capability, action_id, action_version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn success_is_held_until_exact_synchronous_revoke() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"result":"clean"}"#)));
    broker.fake.push_response(Ok(response(204, b"")));

    let executed = execute(&broker, &capability, &action_id, action_version).await;
    executed.ok();
    assert_eq!(executed.body, br#"{"result":"clean"}"#);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/v1/database/creds/agent-api-token");
    assert_eq!(requests[0].auth_name, "x-vault-token");
    assert_eq!(requests[0].auth_value, b"hvs.bootstrap");
    assert_eq!(requests[1].path, "/v1/things");
    assert_eq!(requests[1].auth_value, b"Bearer dynamic-secret-one");
    assert_eq!(requests[2].method, "POST");
    assert_eq!(requests[2].path, "/v1/sys/leases/revoke");
    assert_eq!(requests[2].auth_name, "x-vault-token");
    assert_eq!(
        requests[2].body,
        br#"{"lease_id":"database/creds/agent-api-token/lease-one","sync":true}"#
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_issuance_with_a_candidate_revokes_before_failing() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Ok(response(
        200,
        br#"{"lease_id":"database/creds/agent-api-token/recoverable","lease_duration":60,"renewable":true,"data":{}}"#,
    )));
    broker.fake.push_response(Ok(response(204, b"")));

    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(failed.metadata["retryable"], false);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
    assert!(
        String::from_utf8_lossy(&requests[1].body).contains("recoverable"),
        "the captured exact lease must be revoked"
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_failure_hides_an_already_successful_action_response() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"must":"stay-private"}"#)));
    broker
        .fake
        .push_response(Ok(response(500, br#"{"errors":["failed"]}"#)));

    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(failed.metadata["retryable"], false);
    assert!(failed.body.is_empty());
    assert_eq!(broker.fake.take_requests().len(), 3);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn issuance_uncertainty_and_final_reflection_fail_closed() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Err(UpstreamError::Transport));
    let uncertain = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(uncertain.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(uncertain.metadata["retryable"], false);
    assert_eq!(broker.fake.take_requests().len(), 1);

    broker.fake.push_response(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"debug":"dynamic-secret-one"}"#)));
    broker.fake.push_response(Ok(response(204, b"")));
    let reflected = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(reflected.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert_eq!(broker.fake.take_requests().len(), 3);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn source_preflight_is_definite_but_post_send_uncertainty_is_not_retryable() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker
        .fake
        .push_response(Err(UpstreamError::Blocked("private-address")));
    let blocked = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(blocked.err_code(), "UPSTREAM_FAILED");
    assert_eq!(blocked.metadata["retryable"], true);
    assert_eq!(broker.fake.take_requests().len(), 1);

    for uncertain in [
        UpstreamError::Blocked("redirect"),
        UpstreamError::ResponseTooLarge,
        UpstreamError::Timeout,
    ] {
        broker.fake.push_response(Err(uncertain));
        let failed = execute(&broker, &capability, &action_id, action_version).await;
        assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
        assert_eq!(failed.metadata["retryable"], false);
        assert_eq!(broker.fake.take_requests().len(), 1);
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bounded_candidate_is_revoked_after_an_ambiguous_response() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Ok(response(
        200,
        br#"{"lease_id":"database/creds/role/one","lease_id":"database/creds/role/two","lease_duration":60,"renewable":true,"data":{"token":"x"}}"#,
    )));
    broker.fake.push_response(Ok(response(204, b"")));
    broker.fake.push_response(Ok(response(204, b"")));

    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3);
    assert!(String::from_utf8_lossy(&requests[1].body).contains("/one"));
    assert!(String::from_utf8_lossy(&requests[2].body).contains("/two"));
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_waits_for_an_admitted_dynamic_lease_to_revoke() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    let release = broker.fake.push_response_gated(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"ok":true}"#)));
    broker.fake.push_response(Ok(response(204, b"")));

    let agent = broker.agent_sock();
    let execute_action = action_id.clone();
    let execution = tokio::spawn(async move {
        common::call(
            &agent,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            common::execute_meta(&capability, &execute_action, action_version)
                .to_string()
                .as_bytes(),
            b"{}",
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if !broker.fake.requests.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("lease request did not start");

    let admin = broker.admin_sock();
    let lock = tokio::spawn(async move {
        common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!lock.is_finished(), "lock returned before lease cleanup");
    release.notify_one();
    execution.await.unwrap().ok();
    lock.await.unwrap().ok();
    assert_eq!(broker.fake.take_requests().len(), 3);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn issued_audit_failure_skips_the_action_but_still_attempts_revoke() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    let connection = rusqlite::Connection::open(broker.state_dir.join("vault.sqlite3")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_dynamic_issued_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'vault.lease.issued'
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    drop(connection);
    broker.fake.push_response(Ok(issued()));
    broker.fake.push_response(Ok(response(204, b"")));

    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_ne!(failed.message_type, rekey_domain::ipc::resp_msg::OK);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_audit_failure_hides_the_action_response_and_faults_closed() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    let connection = rusqlite::Connection::open(broker.state_dir.join("vault.sqlite3")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_dynamic_revoked_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'vault.lease.revoked'
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    drop(connection);
    broker.fake.push_response(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"must":"stay-private"}"#)));
    broker.fake.push_response(Ok(response(204, b"")));

    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_ne!(failed.message_type, rekey_domain::ipc::resp_msg::OK);
    assert!(failed.body.is_empty());
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].path, "/v1/sys/leases/revoke");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn final_and_revoke_timeouts_attempt_cleanup_and_never_return_success() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Ok(issued()));
    broker.fake.push_response(Err(UpstreamError::Timeout));
    broker.fake.push_response(Ok(response(204, b"")));
    let action_timeout = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(action_timeout.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(broker.fake.take_requests().len(), 3);

    broker.fake.push_response(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"must":"stay-private"}"#)));
    broker.fake.push_response(Err(UpstreamError::Timeout));
    let revoke_timeout = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(revoke_timeout.err_code(), "UPSTREAM_INDETERMINATE");
    assert!(revoke_timeout.body.is_empty());
    assert_eq!(broker.fake.take_requests().len(), 3);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn source_final_and_revoke_reflections_never_reach_the_agent() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    let source_reflection = serde_json::to_vec(&serde_json::json!({
        "lease_id":LEASE_ID,
        "lease_duration":60,
        "renewable":true,
        "data":{"token":DYNAMIC_VALUE},
        "debug":"hvs.bootstrap"
    }))
    .unwrap();
    broker
        .fake
        .push_response(Ok(response(200, &source_reflection)));
    broker.fake.push_response(Ok(response(204, b"")));
    let source_failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(source_failed.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert_eq!(broker.fake.take_requests().len(), 2);

    broker.fake.push_response(Ok(issued()));
    broker.fake.push_response(Ok(response(
        200,
        br#"{"debug":"ZHluYW1pYy1zZWNyZXQtb25l"}"#,
    )));
    broker.fake.push_response(Ok(response(204, b"")));
    let final_failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(final_failed.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert_eq!(broker.fake.take_requests().len(), 3);

    broker.fake.push_response(Ok(issued()));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"result":"private"}"#)));
    broker.fake.push_response(Ok(response(
        204,
        format!(r#"{{"debug":"{LEASE_ID}"}}"#).as_bytes(),
    )));
    let revoke_failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(revoke_failed.err_code(), "UPSTREAM_INDETERMINATE");
    assert!(revoke_failed.body.is_empty());
    assert_eq!(broker.fake.take_requests().len(), 3);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn action_timeout_below_two_seconds_stops_before_lease_acquisition() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let metadata = serde_json::json!({"label":"short-timeout","kind":"vault-dynamic-source"});
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, &profile("hvs.bootstrap")),
    )
    .await;
    let credential_id = added.ok()["id"].as_str().unwrap();
    let mut action = common::action_meta(credential_id);
    action["timeout_ms"] = 1_999.into();
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        action.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action_id = created.ok()["id"].as_str().unwrap().to_owned();
    let capability = common::create_session(&broker, &action_id, 1).await;
    let failed = execute(&broker, &capability, &action_id, 1).await;
    assert_eq!(failed.err_code(), "REQUEST_DENIED");
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}
