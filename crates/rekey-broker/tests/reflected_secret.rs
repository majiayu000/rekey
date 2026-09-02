//! Response secret sealing: an upstream that reflects the injected secret —
//! raw or encoded — is blocked before anything reaches the agent.

mod common;

use data_encoding::{BASE64, BASE64URL_NOPAD};
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ipc::{Channel, agent_msg};

const SECRET: &[u8] = b"ghp_reflected_secret_value";

async fn run_with_reflection(body: Vec<u8>) -> String {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "reflect", SECRET).await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())].into(),
        body: body.into(),
    }));

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    let code = response.err_code();
    broker.shutdown().await;
    code
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_reflection_blocked() {
    let mut body = b"leaked: ".to_vec();
    body.extend_from_slice(SECRET);
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn full_auth_header_reflection_blocked() {
    let mut body = b"header was: Bearer ".to_vec();
    body.extend_from_slice(SECRET);
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn base64_reflection_blocked() {
    let body = format!("data:{}", BASE64.encode(SECRET)).into_bytes();
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn base64url_reflection_blocked() {
    let body = BASE64URL_NOPAD.encode(SECRET).into_bytes();
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn percent_encoded_reflection_blocked() {
    // "ghp_..." percent-encodes alphanumerics verbatim, so encode the header
    // value which contains a space: "Bearer%20ghp_..."
    let mut body = b"url=Bearer%20".to_vec();
    body.extend_from_slice(SECRET);
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fully_percent_encoded_unreserved_bytes_are_blocked() {
    let body = SECRET
        .iter()
        .flat_map(|byte| format!("%{byte:02x}").into_bytes())
        .collect();
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn selectively_percent_encoded_bytes_are_blocked() {
    let mut body = SECRET.to_vec();
    body.splice(4..5, format!("%{:02x}", SECRET[4]).into_bytes());
    assert_eq!(
        run_with_reflection(body).await,
        "RESPONSE_SECURITY_VIOLATION"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_case_percent_encoded_reflection_blocked() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "mixed-percent", b"+/=").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())].into(),
        body: b"leaked=%2B%2f%3D".to_vec().into(),
    }));

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "RESPONSE_SECURITY_VIOLATION");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn content_type_header_reflection_blocked() {
    // Body is clean; the only copy of the secret is an allowlisted header.
    // This is the C1 leak: Content-Type is in the default response allowlist.
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "hdr", SECRET).await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let mut content_type = b"text/plain; charset=".to_vec();
    content_type.extend_from_slice(SECRET);
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![(
            "content-type".to_owned(),
            String::from_utf8(content_type).unwrap(),
        )]
        .into(),
        body: b"{\"ok\":true}".to_vec().into(),
    }));

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "RESPONSE_SECURITY_VIOLATION");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn content_type_base64_header_reflection_blocked() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "hdrb64", SECRET).await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![(
            "content-type".to_owned(),
            format!("application/json; x={}", BASE64.encode(SECRET)),
        )]
        .into(),
        body: b"{\"ok\":true}".to_vec().into(),
    }));

    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "RESPONSE_SECURITY_VIOLATION");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_response_passes() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "clean", SECRET).await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;
    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.ok()["upstream_status"], 200);
    broker.shutdown().await;
}
