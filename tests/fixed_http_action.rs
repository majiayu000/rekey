//! Workspace vertical slice: init → serve → unlock → credential → action →
//! session → agent execution, with the credential injected server-side and
//! the agent never seeing the secret.

use rekey_domain::ipc::{Channel, agent_msg};
use rekey_integration::harness as h;

const SECRET: &[u8] = b"vertical-slice-secret-token";

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_fixed_action() {
    let broker = h::start_broker().await;
    h::unlock(&broker).await;
    let credential_id = h::add_credential(&broker, "vertical", SECRET).await;
    let (action_id, version) = h::create_action(&broker, &credential_id).await;
    let token = h::create_session(&broker, &action_id, version).await;

    let meta = h::execute_meta(&token, &action_id, version);
    let response = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        br#"{"input":1}"#,
    )
    .await;
    assert_eq!(response.ok()["upstream_status"], 200);

    // The injected header carried the real secret to the upstream...
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    let mut expected = b"Bearer ".to_vec();
    expected.extend_from_slice(SECRET);
    assert_eq!(requests[0].auth_value, expected);

    // ...but the agent-visible response metadata and body never contain it.
    let meta_bytes = response.metadata.to_string();
    assert!(!meta_bytes.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(!response.body.windows(SECRET.len()).any(|w| w == SECRET));

    broker.shutdown_keep_dir().await;
}
