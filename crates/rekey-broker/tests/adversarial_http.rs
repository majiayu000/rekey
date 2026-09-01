//! Adversarial agent inputs: the wire protocol offers no field for origin,
//! method, path, or auth — and everything adjacent (headers, sizes,
//! upstream failures) fails closed.

mod common;

use rekey_broker::upstream::{UpstreamError, UpstreamResponse};
use rekey_domain::ipc::{Channel, agent_msg};
use rekey_vault::store::SqliteRecordStore;

async fn setup() -> (common::TestBroker, String, u64, String) {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "adv", b"top-secret-value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;
    (broker, action_id, version, token)
}

async fn execute_with_meta(
    broker: &common::TestBroker,
    meta: serde_json::Value,
    body: &[u8],
) -> common::WireResponse {
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        body,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_meta_fields_are_rejected_before_upstream() {
    let (broker, action_id, version, token) = setup().await;

    // An attacker adds url/method/path/authorization fields to the metadata.
    // Strict DTO decoding must reject the entire request before it reaches
    // either credential preparation or the upstream.
    let mut meta = common::execute_meta(&token, &action_id, version);
    meta["url"] = serde_json::json!("https://attacker.example/exfil");
    meta["origin"] = serde_json::json!("https://attacker.example");
    meta["method"] = serde_json::json!("DELETE");
    meta["path"] = serde_json::json!("/../../admin");
    meta["authorization"] = serde_json::json!("Bearer attacker-token");
    meta["redirect"] = serde_json::json!(true);

    let response = execute_with_meta(&broker, meta, b"{}").await;
    assert_eq!(response.err_code(), "INVALID_FRAME");
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_and_forbidden_extra_headers_rejected() {
    let (broker, action_id, version, token) = setup().await;

    for (name, value) in [
        ("authorization", "Bearer attacker"),
        ("Authorization", "Bearer attacker"),
        ("cookie", "session=steal"),
        ("host", "attacker.example"),
        ("content-length", "999999"),
        ("transfer-encoding", "chunked"),
        ("x-not-allowlisted", "value"),
        ("x-request-id", "bad\r\ninjected: 1"),
    ] {
        let mut meta = common::execute_meta(&token, &action_id, version);
        meta["extra_headers"] = serde_json::json!([[name, value]]);
        let response = execute_with_meta(&broker, meta, b"{}").await;
        let code = response.err_code();
        assert_eq!(code, "REQUEST_DENIED", "header {name} must be rejected");
    }
    // Nothing reached the upstream.
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_request_body_rejected() {
    let (broker, action_id, version, token) = setup().await;
    let meta = common::execute_meta(&token, &action_id, version);
    // Action allows 64 KiB; send more.
    let body = vec![b'a'; 70 * 1024];
    let response = execute_with_meta(&broker, meta, &body).await;
    assert_eq!(response.err_code(), "REQUEST_DENIED");
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_failures_map_to_denials() {
    let (broker, action_id, version, token) = setup().await;

    broker
        .fake
        .push_response(Err(UpstreamError::Blocked("private-address")));
    let meta = common::execute_meta(&token, &action_id, version);
    let response = execute_with_meta(&broker, meta, b"{}").await;
    assert_eq!(response.err_code(), "UPSTREAM_FAILED");

    broker
        .fake
        .push_response(Err(UpstreamError::ResponseTooLarge));
    let meta = common::execute_meta(&token, &action_id, version);
    let response = execute_with_meta(&broker, meta, b"{}").await;
    assert_eq!(response.err_code(), "RESPONSE_TOO_LARGE");

    broker
        .fake
        .push_response(Err(UpstreamError::Blocked("redirect")));
    let meta = common::execute_meta(&token, &action_id, version);
    let response = execute_with_meta(&broker, meta, b"{}").await;
    assert_eq!(response.err_code(), "UPSTREAM_FAILED");

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let event_types: Vec<_> = store
        .audit_execution_log()
        .unwrap()
        .into_iter()
        .map(|(_, event_type)| event_type)
        .collect();
    assert_eq!(
        event_types,
        vec![
            "execution.started",
            "execution.blocked",
            "execution.started",
            "execution.indeterminate",
            "execution.started",
            "execution.indeterminate",
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn forbidden_response_headers_are_stripped() {
    let (broker, action_id, version, token) = setup().await;
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("set-cookie".to_owned(), "sid=secret".to_owned()),
            ("www-authenticate".to_owned(), "Basic realm=x".to_owned()),
            ("x-internal".to_owned(), "not-allowlisted".to_owned()),
        ],
        body: b"{}".to_vec().into(),
    }));
    let meta = common::execute_meta(&token, &action_id, version);
    let response = execute_with_meta(&broker, meta, b"{}").await;
    let ok = response.ok();
    let headers: Vec<String> = ok["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h[0].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(headers, vec!["content-type".to_owned()]);
    broker.shutdown().await;
}
