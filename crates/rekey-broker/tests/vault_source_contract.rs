//! Vault KV v2 source resolution at the real Broker/Authority/UDS boundary.

mod common;

use rekey_broker::upstream::{UpstreamError, UpstreamResponse};
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use zeroize::Zeroizing;

fn profile(version: u64, source_token: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "credential_type":"vault-kv-v2-source-v1",
        "origin":"https://vault.example.com",
        "mount":"secret",
        "path":"agents/github",
        "key":"token",
        "version":version,
        "vault_token":source_token
    }))
    .unwrap()
}

fn response(status: u16, body: serde_json::Value) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())].into(),
        body: Zeroizing::new(serde_json::to_vec(&body).unwrap()),
    }
}

async fn add_source(broker: &common::TestBroker, source_profile: &[u8]) -> String {
    let metadata = serde_json::json!({"label":"vault-source","kind":"vault-kv-v2-source"});
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, source_profile),
    )
    .await;
    added.ok()["id"].as_str().unwrap().to_owned()
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
async fn exact_source_value_is_consumed_by_the_fixed_action_and_rotates() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = add_source(&broker, &profile(7, "hvs.source-one")).await;
    let (action_id, action_version) = common::create_action(&broker, &credential_id).await;
    let capability = common::create_session(&broker, &action_id, action_version).await;

    broker.fake.push_response(Ok(response(
        200,
        serde_json::json!({
            "data":{"data":{"token":"resolved-one"},"metadata":{"version":7,"deletion_time":"","destroyed":false}},
            "request_id":"provider-extra"
        }),
    )));
    broker
        .fake
        .push_response(Ok(response(200, serde_json::json!({"result":"clean"}))));
    let executed = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&capability, &action_id, action_version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    executed.ok();
    assert_eq!(executed.body, br#"{"result":"clean"}"#);
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].host, "vault.example.com");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/v1/secret/data/agents/github?version=7");
    assert_eq!(requests[0].auth_name, "x-vault-token");
    assert_eq!(requests[0].auth_value, b"hvs.source-one");
    assert_eq!(requests[1].host, "api.example.com");
    assert_eq!(requests[1].auth_name, "authorization");
    assert_eq!(requests[1].auth_value, b"Bearer resolved-one");

    let rotate_meta = serde_json::json!({"credential_id":credential_id});
    let rotated = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
        rotate_meta.to_string().as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, &profile(8, "hvs.source-two")),
    )
    .await;
    assert_eq!(rotated.ok()["current_version"], 2);

    broker.fake.push_response(Ok(response(
        200,
        serde_json::json!({"data":{"data":{"token":"resolved-two"},"metadata":{"version":8,"deletion_time":"","destroyed":false}}}),
    )));
    broker
        .fake
        .push_response(Ok(response(200, serde_json::json!({"rotated":true}))));
    let executed = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&capability, &action_id, action_version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    executed.ok();
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/secret/data/agents/github?version=8");
    assert_eq!(requests[0].auth_value, b"hvs.source-two");
    assert_eq!(requests[1].auth_value, b"Bearer resolved-two");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_version_and_source_token_reflection_stop_before_final_action() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = add_source(&broker, &profile(7, "hvs.source-canary")).await;
    let (action_id, action_version) = common::create_action(&broker, &credential_id).await;
    let capability = common::create_session(&broker, &action_id, action_version).await;

    broker.fake.push_response(Ok(response(
        200,
        serde_json::json!({"data":{"data":{"token":"resolved"},"metadata":{"version":8,"deletion_time":"","destroyed":false}}}),
    )));
    let wrong_version = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&capability, &action_id, action_version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(wrong_version.err_code(), "UPSTREAM_FAILED");
    assert_eq!(wrong_version.metadata["retryable"], true);
    assert_eq!(broker.fake.take_requests().len(), 1);

    broker.fake.push_response(Ok(response(
        200,
        serde_json::json!({
            "data":{"data":{"token":"resolved"},"metadata":{"version":7,"deletion_time":"","destroyed":false}},
            "debug":"hvs.source-canary"
        }),
    )));
    let reflected = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&capability, &action_id, action_version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(reflected.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert_eq!(broker.fake.take_requests().len(), 1);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn source_failures_remain_retryable_and_never_reach_the_final_action() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = add_source(&broker, &profile(7, "hvs.source-canary")).await;
    let (action_id, action_version) = common::create_action(&broker, &credential_id).await;
    let capability = common::create_session(&broker, &action_id, action_version).await;

    for failure in [
        UpstreamError::Transport,
        UpstreamError::Timeout,
        UpstreamError::ResponseTooLarge,
        UpstreamError::Blocked("private-address"),
        UpstreamError::Blocked("redirect"),
    ] {
        broker.fake.push_response(Err(failure));
        let failed = execute(&broker, &capability, &action_id, action_version).await;
        assert_eq!(failed.err_code(), "UPSTREAM_FAILED");
        assert_eq!(failed.metadata["retryable"], true);
        assert_eq!(broker.fake.take_requests().len(), 1);
    }

    for invalid in [
        response(403, serde_json::json!({"errors":["denied"]})),
        response(200, serde_json::json!({"data":{}})),
        UpstreamResponse {
            status: 200,
            headers: Vec::new().into(),
            body: Zeroizing::new(b"not-json".to_vec()),
        },
    ] {
        broker.fake.push_response(Ok(invalid));
        let failed = execute(&broker, &capability, &action_id, action_version).await;
        assert_eq!(failed.err_code(), "UPSTREAM_FAILED");
        assert_eq!(failed.metadata["retryable"], true);
        assert_eq!(broker.fake.take_requests().len(), 1);
    }
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn source_and_resolved_secret_encodings_are_sealed_at_each_boundary() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = add_source(&broker, &profile(7, "hvs.source-canary")).await;
    let (action_id, action_version) = common::create_action(&broker, &credential_id).await;
    let capability = common::create_session(&broker, &action_id, action_version).await;

    let reflected_source = UpstreamResponse {
        status: 200,
        headers: vec![(
            "x-debug".to_owned(),
            "aHZzLnNvdXJjZS1jYW5hcnk=".to_owned(),
        )]
        .into(),
        body: Zeroizing::new(
            br#"{"data":{"data":{"token":"resolved"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}"#
                .to_vec(),
        ),
    };
    broker.fake.push_response(Ok(reflected_source));
    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(failed.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert_eq!(broker.fake.take_requests().len(), 1);

    broker.fake.push_response(Ok(response(
        200,
        serde_json::json!({"data":{"data":{"token":"resolved-canary"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
    )));
    broker.fake.push_response(Ok(response(
        200,
        serde_json::json!({"debug":"cmVzb2x2ZWQtY2FuYXJ5"}),
    )));
    let failed = execute(&broker, &capability, &action_id, action_version).await;
    assert_eq!(failed.err_code(), "RESPONSE_SECURITY_VIOLATION");
    assert_eq!(broker.fake.take_requests().len(), 2);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_between_source_read_and_action_closes_final_effect_admission() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = add_source(&broker, &profile(7, "hvs.source-canary")).await;
    let (action_id, action_version) = common::create_action(&broker, &credential_id).await;
    let capability = common::create_session(&broker, &action_id, action_version).await;
    let release = broker.fake.push_response_gated(Ok(response(
        200,
        serde_json::json!({"data":{"data":{"token":"resolved"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
    )));

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
    .expect("source request did not start");

    let admin = broker.admin_sock();
    let lock = tokio::spawn(async move {
        common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let probe = common::call(
                &broker.agent_sock(),
                Channel::Agent,
                agent_msg::EXECUTE_FIXED_HTTP_ACTION,
                common::execute_meta("invalid", &action_id, action_version)
                    .to_string()
                    .as_bytes(),
                b"{}",
            )
            .await;
            match probe.err_code().as_str() {
                "DRAINING" => break,
                "INVALID_CAPABILITY" => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await
                }
                code => panic!("unexpected drain probe result: {code}"),
            }
        }
    })
    .await
    .expect("lock did not close remote-effect admission");

    release.notify_one();
    assert_eq!(execution.await.unwrap().err_code(), "DRAINING");
    lock.await.unwrap().ok();
    assert_eq!(broker.fake.take_requests().len(), 1);
    broker.shutdown().await;
}
