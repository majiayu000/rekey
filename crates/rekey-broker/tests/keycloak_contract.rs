//! Closed Keycloak exchange lifecycle through the actual Broker/Authority/UDS.
mod common;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use zeroize::Zeroizing;
const SECRET: &str = "client-secret-%/:+\\\"-synthetic";
const SUBJECT: &str = "subject-token-synthetic";
const ISSUED: &str = "issued-token-synthetic";
fn response(status: u16, body: &[u8]) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: Vec::new().into(),
        body: Zeroizing::new(body.to_vec()),
    }
}
fn issued(token: &str, ttl: u64) -> UpstreamResponse {
    response(200, &serde_json::to_vec(&serde_json::json!({"access_token":token,"expires_in":ttl,"token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"})).unwrap())
}
async fn setup() -> (common::TestBroker, String, String, u64) {
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let p=serde_json::to_vec(&serde_json::json!({"credential_type":"keycloak-token-exchange-v1","origin":"https://keycloak.example.com","realm":"test","client_id":"requester","client_secret":SECRET,"subject_token":SUBJECT,"audience":"target","target_origin":"https://api.example.com","target_path":"/v1/things"})).unwrap();
    let added = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        br#"{"label":"oauth","kind":"keycloak-token-exchange"}"#,
        &common::proof_and_secret_body(common::PASSWORD, &p),
    )
    .await;
    let id = added.ok()["id"].as_str().unwrap().to_owned();
    let mut meta = common::action_meta(&id);
    meta["method"] = "GET".into();
    let action = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let a = action.ok()["id"].as_str().unwrap().to_owned();
    let v = action.ok()["version"].as_u64().unwrap();
    let cap = common::create_session(&b, &a, v).await;
    (b, cap, a, v)
}
async fn execute(b: &common::TestBroker, c: &str, a: &str, v: u64) -> common::WireResponse {
    let mut meta = common::execute_meta(c, a, v);
    meta["content_type"] = serde_json::Value::Null;
    common::call(
        &b.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"",
    )
    .await
}
#[tokio::test(flavor = "multi_thread")]
async fn success_special_basic_and_direct_revoke() {
    let (b, c, a, v) = setup().await;
    b.fake.push_response(Ok(issued(ISSUED, 60)));
    b.fake.push_response(Ok(response(200, b"clean")));
    b.fake.push_response(Ok(response(200, b"")));
    let result = execute(&b, &c, &a, v).await;
    result.ok();
    assert_eq!(result.body, b"clean");
    let r = b.fake.take_requests();
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].method, "POST");
    assert_eq!(r[0].path, "/realms/test/protocol/openid-connect/token");
    let decoded = data_encoding::BASE64.decode(&r[0].auth_value[6..]).unwrap();
    assert_eq!(
        std::str::from_utf8(&decoded).unwrap(),
        "requester:client-secret-%25%2F%3A%2B%5C%22-synthetic"
    );
    let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&r[0].body)
        .into_owned()
        .collect();
    assert_eq!(form["subject_token"], SUBJECT);
    assert_eq!(form["audience"], "target");
    assert_eq!(form.len(), 5);
    assert_eq!(r[1].method, "GET");
    assert_eq!(r[1].auth_value, b"Bearer issued-token-synthetic");
    assert_eq!(r[2].path, "/realms/test/protocol/openid-connect/revoke");
    assert_eq!(r[2].method, "POST");
    assert_eq!(
        r[2].body,
        b"token=issued-token-synthetic&token_type_hint=access_token"
    );
    b.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn source_reflection_never_reaches_target_but_is_revoked() {
    let (b, c, a, v) = setup().await;
    b.fake.push_response(Ok(issued(SUBJECT, 60)));
    b.fake.push_response(Ok(response(200, b"")));
    let result = execute(&b, &c, &a, v).await;
    assert_eq!(result.err_code(), "UPSTREAM_INDETERMINATE");
    assert!(result.body.is_empty());
    let r = b.fake.take_requests();
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|r| r.method == "POST"));
    assert!(r[1].path.ends_with("/revoke"));
    b.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn expired_exchange_and_failed_revoke_never_return_success() {
    let (b, c, a, v) = setup().await;
    b.fake.push_response(Ok(issued(ISSUED, 0)));
    b.fake.push_response(Ok(response(200, b"")));
    let invalid = execute(&b, &c, &a, v).await;
    assert_eq!(invalid.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(b.fake.take_requests().len(), 2);
    b.fake.push_response(Ok(issued(ISSUED, 60)));
    b.fake.push_response(Ok(response(200, b"private-result")));
    b.fake.push_response(Ok(response(500, b"")));
    let failed = execute(&b, &c, &a, v).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(failed.metadata["retryable"], false);
    assert!(failed.body.is_empty());
    assert_eq!(b.fake.take_requests().len(), 3);
    b.shutdown().await;
}
#[tokio::test(flavor = "multi_thread")]
async fn reflected_resource_is_sealed_after_revoke_and_invalid_request_has_no_io() {
    let (b, c, a, v) = setup().await;
    b.fake.push_response(Ok(issued(ISSUED, 60)));
    b.fake.push_response(Ok(response(200, ISSUED.as_bytes())));
    b.fake.push_response(Ok(response(200, b"")));
    let failed = execute(&b, &c, &a, v).await;
    assert_eq!(failed.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert!(failed.body.is_empty());
    assert_eq!(b.fake.take_requests().len(), 3);
    let bad = common::call(
        &b.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&c, &a, v).to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(bad.err_code(), "REQUEST_DENIED");
    assert!(b.fake.take_requests().is_empty());
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn json_escaped_source_secret_is_rejected_before_resource_and_revoked() {
    let (b, c, a, v) = setup().await;
    let mut source: serde_json::Value = serde_json::from_slice(&issued(ISSUED, 60).body).unwrap();
    source["debug"] = format!("prefix:{SECRET}:suffix").into();
    b.fake
        .push_response(Ok(response(200, &serde_json::to_vec(&source).unwrap())));
    b.fake.push_response(Ok(response(200, b"")));
    let failed = execute(&b, &c, &a, v).await;
    assert_eq!(failed.err_code(), "UPSTREAM_INDETERMINATE");
    assert!(failed.body.is_empty());
    let requests = b.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.method == "POST"));
    assert!(requests[1].path.ends_with("/revoke"));
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn json_escaped_resource_secret_is_sealed_after_revoke() {
    let (b, c, a, v) = setup().await;
    b.fake.push_response(Ok(issued(ISSUED, 60)));
    let echo = serde_json::to_vec(&serde_json::json!({"debug":format!("prefix:{SECRET}:suffix")}))
        .unwrap();
    b.fake.push_response(Ok(response(200, &echo)));
    b.fake.push_response(Ok(response(200, b"")));
    let failed = execute(&b, &c, &a, v).await;
    assert_eq!(failed.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert!(failed.body.is_empty());
    let requests = b.fake.take_requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].path.ends_with("/revoke"));
    b.shutdown().await;
}
