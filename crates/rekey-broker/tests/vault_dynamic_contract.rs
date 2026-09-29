//! One-shot Vault dynamic leases at the real Broker/Authority/UDS boundary.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamTransport,
};
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use zeroize::Zeroizing;

const LEASE_ID: &str = "database/creds/agent-api-token/lease-one";
const DYNAMIC_VALUE: &str = "dynamic-secret-one";

struct ObservedTransport {
    fake: Arc<FakeUpstreamTransport>,
    timeouts: Arc<Mutex<Vec<Duration>>>,
}

impl UpstreamTransport for ObservedTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        self.timeouts.lock().unwrap().push(request.timeout);
        self.fake.send(request)
    }
}

fn profile(token: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "credential_type":"vault-dynamic-source-v2",
        "origin":"https://vault.example.com",
        "mount":"database",
        "role":"agent-api-token",
        "key":"token",
        "renew_increment_seconds":60,
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
    register(broker, 30_000).await
}

async fn register(
    broker: common::TestBroker,
    timeout_ms: u32,
) -> (common::TestBroker, String, String, u64, String) {
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
    let mut action = common::action_meta(&credential_id);
    action["timeout_ms"] = timeout_ms.into();
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        action.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action_id = created.ok()["id"].as_str().unwrap().to_owned();
    let action_version = 1;
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
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn escaped_lease_id_is_revoked_when_semantic_parse_fails() {
    let (broker, _, action_id, action_version, capability) = setup().await;
    broker.fake.push_response(Ok(response(
        200,
        br#"{"lease_id":"database\/creds\/agent-api-token\/recoverable","lease_duration":60,"renewable":true,"data":{}}"#,
    )));
    broker.fake.push_response(Ok(response(204, b"")));

    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
    assert_eq!(
        requests[1].body,
        br#"{"lease_id":"database/creds/agent-api-token/recoverable","sync":true}"#
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
    assert_eq!(execution.await.unwrap().err_code(), "DRAINING");
    lock.await.unwrap().ok();
    assert_eq!(broker.fake.take_requests().len(), 2);
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

fn short_issued(renewable: bool) -> UpstreamResponse {
    response(
        200,
        &serde_json::to_vec(&serde_json::json!({
            "lease_id": LEASE_ID, "lease_duration":5, "renewable":renewable,
            "data":{"token": DYNAMIC_VALUE}
        }))
        .unwrap(),
    )
}

fn renewed(ttl: u64) -> UpstreamResponse {
    response(
        200,
        &serde_json::to_vec(&serde_json::json!({
            "lease_id": LEASE_ID, "lease_duration":ttl, "renewable":true,
            "data":null, "auth":null, "request_id":"ignored"
        }))
        .unwrap(),
    )
}

fn audit_events(broker: &common::TestBroker) -> Vec<String> {
    let db = rusqlite::Connection::open(broker.state_dir.join("vault.sqlite3")).unwrap();
    let mut query = db.prepare("SELECT event_type FROM audit_events WHERE event_type LIKE 'execution.%' OR event_type LIKE 'vault.lease.%' ORDER BY sequence").unwrap();
    query
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

async fn wait_requests(broker: &common::TestBroker, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while broker.fake.requests.lock().unwrap().len() < count {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

fn spawn_execute(
    broker: &common::TestBroker,
    capability: &str,
    action_id: &str,
) -> tokio::task::JoinHandle<common::WireResponse> {
    let socket = broker.agent_sock();
    let metadata = common::execute_meta(capability, action_id, 1).to_string();
    tokio::spawn(async move {
        common::call(
            &socket,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            metadata.as_bytes(),
            b"{}",
        )
        .await
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn renews_once_before_business_and_audits_before_io_without_leaking_canaries() {
    let (broker, _, id, version, cap) = register(common::start_broker().await, 8_000).await;
    broker.fake.push_response(Ok(short_issued(true)));
    let release = broker.fake.push_response_gated(Ok(renewed(60)));
    broker
        .fake
        .push_response(Ok(response(200, br#"{"ok":true}"#)));
    broker.fake.push_response(Ok(response(204, b"")));
    let execution = spawn_execute(&broker, &cap, &id);
    wait_requests(&broker, 2).await;
    assert_eq!(
        audit_events(&broker),
        [
            "execution.started",
            "vault.lease.issued",
            "vault.lease.renewal_started"
        ]
    );
    release.notify_one();
    let result = execution.await.unwrap();
    result.ok();
    assert_eq!(result.body, br#"{"ok":true}"#);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].host, "vault.example.com");
    assert_eq!(requests[1].path, "/v1/sys/leases/renew");
    assert_eq!(requests[1].auth_name, "x-vault-token");
    assert_eq!(requests[1].auth_value, b"hvs.bootstrap");
    assert_eq!(
        requests[1].body,
        format!(r#"{{"lease_id":"{LEASE_ID}","increment":60}}"#).as_bytes()
    );
    assert_eq!(requests[2].path, "/v1/things");
    assert_eq!(requests[3].path, "/v1/sys/leases/revoke");
    assert_eq!(
        requests[3].body,
        format!(r#"{{"lease_id":"{LEASE_ID}","sync":true}}"#).as_bytes()
    );
    assert_eq!(
        audit_events(&broker),
        [
            "execution.started",
            "vault.lease.issued",
            "vault.lease.renewal_started",
            "vault.lease.renewed",
            "vault.lease.revoked",
            "execution.finished"
        ]
    );
    let db = rusqlite::Connection::open(broker.state_dir.join("vault.sqlite3")).unwrap();
    let mut query = db
        .prepare("SELECT event_type || outcome || reason_code FROM audit_events ORDER BY sequence")
        .unwrap();
    let audit: Vec<String> = query
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let public = format!(
        "{}{}{}",
        serde_json::to_string(&result.metadata).unwrap(),
        String::from_utf8_lossy(&result.body),
        audit.join("")
    );
    for canary in [
        LEASE_ID,
        DYNAMIC_VALUE,
        "hvs.bootstrap",
        "vault.example.com",
    ] {
        assert!(!public.contains(canary));
    }
    assert_eq!(version, 1);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_renewal_when_not_renewable_or_initial_ttl_covers_action() {
    for (renewable, ttl) in [(false, 5), (true, 60)] {
        let (broker, _, id, version, cap) = register(common::start_broker().await, 8_000).await;
        broker.fake.push_response(Ok(if ttl == 5 {
            short_issued(renewable)
        } else {
            issued()
        }));
        broker
            .fake
            .push_response(Ok(response(200, br#"{"ok":true}"#)));
        broker.fake.push_response(Ok(response(204, b"")));
        execute(&broker, &cap, &id, version).await.ok();
        let requests = broker.fake.take_requests();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|r| r.path != "/v1/sys/leases/renew"));
        assert!(
            !audit_events(&broker)
                .iter()
                .any(|event| event.contains("renew"))
        );
        broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_mismatch_duplicate_new_data_and_short_ttl_revoke_only_known_id() {
    let (broker, _, id, version, cap) = register(common::start_broker().await, 8_000).await;
    for body in [
        r#"{"lease_id":"wrong-id","lease_duration":60,"renewable":true}"#.to_owned(),
        format!(
            r#"{{"lease_id":"{LEASE_ID}","lease_id":"{LEASE_ID}","lease_duration":60,"renewable":true}}"#
        ),
        format!(
            r#"{{"lease_id":"{LEASE_ID}","lease_duration":60,"lease_duration":60,"renewable":true}}"#
        ),
        format!(
            r#"{{"lease_id":"{LEASE_ID}","lease_duration":60,"renewable":true,"renewable":false}}"#
        ),
        format!(
            r#"{{"lease_id":"{LEASE_ID}","lease_duration":60,"renewable":true,"data":{{"token":"new-secret"}}}}"#
        ),
        format!(r#"{{"lease_id":"{LEASE_ID}","lease_duration":4,"renewable":true}}"#),
    ] {
        broker.fake.push_response(Ok(short_issued(true)));
        broker
            .fake
            .push_response(Ok(response(200, body.as_bytes())));
        broker.fake.push_response(Ok(response(204, b"")));
        let failed = execute(&broker, &cap, &id, version).await;
        assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
        assert_eq!(failed.metadata["retryable"], false);
        assert!(failed.body.is_empty());
        let requests = broker.fake.take_requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2].path, "/v1/sys/leases/revoke");
        assert_eq!(
            requests[2].body,
            format!(r#"{{"lease_id":"{LEASE_ID}","sync":true}}"#).as_bytes()
        );
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn renew_rejection_transport_and_reflection_are_nonretryable_and_skip_business() {
    let (broker, _, id, version, cap) = register(common::start_broker().await, 8_000).await;
    let mut header_reflection = renewed(60);
    header_reflection.headers = vec![("x-debug".to_owned(), LEASE_ID.to_owned())].into();
    for result in [
        Err(UpstreamError::Timeout), Err(UpstreamError::Transport),
        Ok(response(403, br#"{"errors":["denied"]}"#)),
        Ok(response(200, format!(r#"{{"lease_id":"{LEASE_ID}","lease_duration":60,"renewable":true,"debug":"hvs.bootstrap"}}"#).as_bytes())),
        Ok(response(200, format!(r#"{{"lease_id":"{LEASE_ID}","lease_duration":60,"renewable":true,"debug":"ZHluYW1pYy1zZWNyZXQtb25l"}}"#).as_bytes())),
        Ok(header_reflection),
    ] {
        broker.fake.push_response(Ok(short_issued(true)));
        broker.fake.push_response(result);
        broker.fake.push_response(Ok(response(204, b"")));
        let failed = execute(&broker, &cap, &id, version).await;
        assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
        assert_eq!(failed.metadata["retryable"], false);
        assert!(failed.body.is_empty());
        let public = serde_json::to_string(&failed.metadata).unwrap();
        assert!(!public.contains(DYNAMIC_VALUE));
        assert!(!public.contains("hvs.bootstrap"));
        assert_eq!(broker.fake.take_requests().len(), 3);
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_started_or_result_audit_failure_cleans_up_and_faults_closed() {
    for event in ["vault.lease.renewal_started", "vault.lease.renewed"] {
        let (broker, _, id, version, cap) = register(common::start_broker().await, 8_000).await;
        let db = rusqlite::Connection::open(broker.state_dir.join("vault.sqlite3")).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER fail_renew_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = '{event}' BEGIN SELECT RAISE(ABORT, 'injected'); END;")).unwrap();
        drop(db);
        broker.fake.push_response(Ok(short_issued(true)));
        if event.ends_with("renewed") {
            broker.fake.push_response(Ok(renewed(60)));
        }
        broker.fake.push_response(Ok(response(204, b"")));
        let failed = execute(&broker, &cap, &id, version).await;
        assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
        assert_eq!(failed.metadata["retryable"], false);
        assert!(failed.body.is_empty());
        let requests = broker.fake.take_requests();
        assert_eq!(
            requests.len(),
            if event.ends_with("renewed") { 3 } else { 2 }
        );
        assert_eq!(requests.last().unwrap().path, "/v1/sys/leases/revoke");
        broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_during_renewal_or_business_cancels_io_and_waits_for_exact_cleanup() {
    for during_renewal in [true, false] {
        let broker = common::start_broker_with(
            std::time::Duration::from_secs(300),
            std::time::Duration::from_millis(25),
        )
        .await;
        let (broker, _, id, _, cap) = register(broker, 8_000).await;
        broker.fake.push_response(Ok(short_issued(true)));
        if during_renewal {
            broker.fake.push_response_gated(Ok(renewed(60)));
        } else {
            broker.fake.push_response(Ok(renewed(60)));
            broker
                .fake
                .push_response_gated(Ok(response(200, br#"{"must":"stay-private"}"#)));
        }
        let cleanup = broker.fake.push_response_gated(Ok(response(204, b"")));
        let execution = spawn_execute(&broker, &cap, &id);
        wait_requests(&broker, if during_renewal { 2 } else { 3 }).await;
        let admin = broker.admin_sock();
        let lock = tokio::spawn(async move {
            common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
        });
        wait_requests(&broker, if during_renewal { 3 } else { 4 }).await;
        assert!(!lock.is_finished());
        cleanup.notify_one();
        let failed = execution.await.unwrap();
        assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
        assert_eq!(failed.metadata["retryable"], false);
        assert!(failed.body.is_empty());
        lock.await.unwrap().ok();
        let requests = broker.fake.take_requests();
        assert_eq!(requests.last().unwrap().path, "/v1/sys/leases/revoke");
        if during_renewal {
            assert!(requests.iter().all(|r| r.path != "/v1/things"));
        }
        broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_deadline_timeout_still_has_cleanup_budget() {
    let (broker, _, id, version, cap) = register(common::start_broker().await, 6_000).await;
    broker.fake.push_response(Ok(short_issued(true)));
    broker.fake.push_response_gated(Ok(renewed(60)));
    broker.fake.push_response(Ok(response(204, b"")));
    let failed = execute(&broker, &cap, &id, version).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(failed.metadata["retryable"], false);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].path, "/v1/sys/leases/revoke");
    assert_eq!(
        audit_events(&broker).last().unwrap(),
        "execution.indeterminate"
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_renewal_ttl_and_original_action_deadline_bound_business_io() {
    for (actual_ttl, action_ms, maximum_business_ms) in [(5, 8_000, 4_400), (60, 6_000, 5_400)] {
        let fake = Arc::new(FakeUpstreamTransport::new());
        let timeouts = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(ObservedTransport {
            fake: Arc::clone(&fake),
            timeouts: Arc::clone(&timeouts),
        });
        let broker = common::start_broker_with_transport(
            Duration::from_secs(300),
            Duration::from_secs(2),
            fake,
            transport,
        )
        .await;
        let (broker, _, id, version, cap) = register(broker, action_ms).await;
        broker.fake.push_response(Ok(short_issued(true)));
        broker
            .fake
            .push_response_delayed(Ok(renewed(actual_ttl)), Duration::from_millis(150));
        broker
            .fake
            .push_response(Ok(response(200, br#"{"ok":true}"#)));
        broker.fake.push_response(Ok(response(204, b"")));
        execute(&broker, &cap, &id, version).await.ok();
        let observed = timeouts.lock().unwrap().clone();
        assert_eq!(observed.len(), 4);
        assert!(
            observed[2] <= Duration::from_millis(maximum_business_ms),
            "business timeout exceeded actual-TTL or Action cap: {:?}",
            observed[2]
        );
        assert!(observed[2] > Duration::from_secs(1));
        broker.shutdown().await;
    }
}
