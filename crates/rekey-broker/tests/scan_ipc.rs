//! Real Broker, Authority and SQLite answering SCAN on the Agent socket with a
//! signed policy. Synthetic credential only; no upstream is contacted.
mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rekey_domain::ids::PolicyRuleId;
use rekey_domain::ipc::{Channel, agent_msg};
use serde_json::{Value, json};

const CANARY: &[u8] = b"synthetic-broker-scan-canary-4d2f";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

async fn scan(broker: &common::TestBroker, body: &[u8]) -> common::WireResponse {
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::SCAN,
        br#"{"path":"fixture.txt"}"#,
        body,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cannot_scan_states_are_explicit_and_an_expired_policy_is_not_configured() {
    let broker = common::start_broker().await;
    assert_eq!(scan(&broker, CANARY).await.err_code(), "LOCKED");
    common::unlock(&broker).await;
    let missing = scan(&broker, CANARY).await;
    assert_eq!(missing.err_code(), "NOT_CONFIGURED");
    assert_eq!(
        missing.metadata["message"],
        "no active signed policy; nothing was scanned"
    );

    let credential = common::add_credential(&broker, "scan-fixture", CANARY).await;
    let mut connection = rekey_policy::presets::builtin_preset("github-pat")
        .unwrap()
        .connection("fixture".into(), credential.parse().unwrap());
    for rule in &mut connection.rules {
        rule.id = PolicyRuleId::new_random();
    }
    let expires = now_ms() + 3_000;
    common::policy::activate_snapshot(
        &broker,
        json!({
            "format_version":8,"version":1,"expires_at_ms":expires,
            "approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],
            "connections":[connection],"ssh_keys":[],"derived_credentials":[],
        }),
    )
    .await;
    let found = scan(&broker, &[b"first\n  ".as_slice(), CANARY].concat()).await;
    found.ok();
    assert_eq!(
        serde_json::from_slice::<Value>(&found.body).unwrap(),
        json!({
            "findings": [{"path":"fixture.txt","line":2,"column":3,"connection":"fixture"}],
            "unavailable_credentials": 0
        })
    );
    assert!(!found.body.windows(CANARY.len()).any(|part| part == CANARY));

    tokio::time::sleep(Duration::from_millis(
        (expires - now_ms()).max(0) as u64 + 200,
    ))
    .await;
    let expired = scan(&broker, CANARY).await;
    assert_eq!(expired.err_code(), "NOT_CONFIGURED");
    assert_eq!(
        expired.metadata["message"],
        "the signed policy expired; nothing was scanned"
    );
    broker.shutdown().await;
}
