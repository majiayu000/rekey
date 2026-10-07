#![cfg(feature = "lab")]
//! Template installation at the real admin socket; no upstream is contacted.
mod common;

use rekey_domain::ipc::{Channel, admin_msg};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn catalog_and_install_use_closed_metadata_and_explicit_step_up_body() {
    let broker = common::start_broker().await;
    let catalog = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::TEMPLATE_CATALOG,
        br#"{"source":{"kind":"anthropic"}}"#,
        b"",
    )
    .await;
    assert_eq!(catalog.ok()["template"]["template"], "anthropic@1");
    let override_source = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::TEMPLATE_CATALOG,
        br#"{"source":{"kind":"anthropic","origin":"https://attacker.example.com"}}"#,
        b"",
    )
    .await;
    assert_eq!(override_source.err_code(), "INVALID_FRAME");
    common::unlock(&broker).await;
    let credential =
        common::add_credential(&broker, "synthetic-template", b"synthetic-template-token").await;
    let request = json!({"source":{"kind":"anthropic"},"credential_id":credential,"bindings":[{}],"capabilities":["messages","models"],"name_prefix":"app","timeout_ms":1000,"request_max_bytes":1024,"allowed_extra_headers":[],"response_max_bytes":1024,"allowed_response_headers":[]});
    let bytes = serde_json::to_vec(&request).unwrap();
    for body in [
        vec![],
        common::proof_body(common::PASSWORD),
        common::proof_and_secret_body(common::PASSWORD, b"unexpected-builtin-package"),
    ] {
        let response = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::TEMPLATE_INSTALL,
            &bytes,
            &body,
        )
        .await;
        assert!(matches!(
            response.err_code().as_str(),
            "INVALID_FRAME" | "INVALID_INPUT"
        ));
    }
    let installed = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::TEMPLATE_INSTALL,
        &bytes,
        &common::proof_and_secret_body(common::PASSWORD, b""),
    )
    .await;
    let actions = installed.ok()["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 2);
    assert!(actions.iter().all(
        |value| value["binding_index"] == 0 && value["action"]["target"]["kind"] == "template"
    ));
    // The old exact-path action command remains usable after template install.
    common::create_action(&broker, &credential).await;
    let listed = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_LIST,
        b"{}",
        b"",
    )
    .await;
    assert_eq!(listed.ok()["actions"].as_array().unwrap().len(), 3);
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn team_catalog_requires_installed_trust_and_failed_batch_leaves_no_actions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let team = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::TEMPLATE_CATALOG,
        br#"{"source":{"kind":"signed-package"}}"#,
        b"{}",
    )
    .await;
    assert_eq!(team.err_code(), "POLICY_UNAVAILABLE");
    let credential =
        common::add_credential(&broker, "synthetic-template", b"synthetic-token").await;
    let request = json!({"source":{"kind":"github-pat"},"credential_id":credential,"bindings":[{"owner":"acme","repo":"good"},{"owner":"acme","repo":"../bad"}],"capabilities":["read-repo"],"name_prefix":"repos","timeout_ms":1000,"request_max_bytes":1024,"allowed_extra_headers":[],"response_max_bytes":1024,"allowed_response_headers":[]});
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::TEMPLATE_INSTALL,
        &serde_json::to_vec(&request).unwrap(),
        &common::proof_and_secret_body(common::PASSWORD, b""),
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_INPUT");
    let listed = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_LIST,
        b"{}",
        b"",
    )
    .await;
    assert!(listed.ok()["actions"].as_array().unwrap().is_empty());
    broker.shutdown().await;
}
