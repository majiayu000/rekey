use std::sync::atomic::Ordering;

use aws_lc_rs::signature::KeyPair;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::authorization::ApprovalMode;
use rekey_domain::ids::{ApproverId, PolicyRuleId};
use rekey_domain::ipc::{Channel, admin_msg};

use super::{PASSWORD, TestBroker, call, proof_body};

pub struct TestSession {
    pub capability_token: String,
    pub principal_id: String,
    pub session_id: String,
}

pub async fn create_session_grant(
    broker: &TestBroker,
    action_id: &str,
    version: u64,
    max_uses: u32,
) -> TestSession {
    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 3_600_000,
        "max_uses": max_uses,
    });
    let response = call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &proof_body(PASSWORD),
    )
    .await;
    let ok = response.ok();
    TestSession {
        capability_token: ok["capability_token"].as_str().unwrap().to_owned(),
        principal_id: ok["principal_id"].as_str().unwrap().to_owned(),
        session_id: ok["session_id"].as_str().unwrap().to_owned(),
    }
}

pub async fn activate_test_policy(
    broker: &TestBroker,
    action_id: &str,
    action_version: u64,
    principal_id: &str,
) {
    let resource = serde_json::json!({"type": "test-action", "id": action_id});
    let snapshot = serde_json::json!({
        "format_version": 2,
        "version": broker.policy_version.fetch_add(1, Ordering::Relaxed),
        "expires_at_ms": 4_102_444_800_000_i64,
        "approvers": [],
        "bindings": [binding(action_id, action_version, &resource)],
        "rules": [{
            "id": PolicyRuleId::new_random(),
            "effect": "permit",
            "principal_id": principal_id,
            "action_id": action_id,
            "version": action_version,
            "resource": resource,
            "parameters": {"kind": "any_validated"},
        }],
    });
    activate_snapshot(broker, snapshot).await;
}

pub struct ApprovalPolicy<'a> {
    pub principal_id: &'a str,
    pub approvers: &'a [(ApproverId, [u8; 32])],
    pub quorum: u8,
    pub mode: ApprovalMode,
    pub max_uses: u32,
    pub max_window_ms: Option<i64>,
}

pub async fn activate_approval_policy(
    broker: &TestBroker,
    action_id: &str,
    action_version: u64,
    policy: ApprovalPolicy<'_>,
) -> PolicyRuleId {
    let rule_id = PolicyRuleId::new_random();
    let resource = serde_json::json!({"type": "test-action", "id": action_id});
    let mut approval = serde_json::json!({
        "approver_ids": policy.approvers.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        "quorum": policy.quorum,
        "mode": policy.mode,
        "max_uses": policy.max_uses,
    });
    if let Some(max_window_ms) = policy.max_window_ms {
        approval
            .as_object_mut()
            .expect("approval object")
            .insert("max_window_ms".to_owned(), max_window_ms.into());
    }
    let snapshot = serde_json::json!({
        "format_version": 2,
        "version": broker.policy_version.fetch_add(1, Ordering::Relaxed),
        "expires_at_ms": 4_102_444_800_000_i64,
        "approvers": policy.approvers.iter().map(|(id, key)| serde_json::json!({
            "approver_id": id,
            "algorithm": "ed25519",
            "public_key": HEXLOWER.encode(key),
        })).collect::<Vec<_>>(),
        "bindings": [binding(action_id, action_version, &resource)],
        "rules": [{
            "id": rule_id,
            "effect": "require-approval",
            "principal_id": policy.principal_id,
            "action_id": action_id,
            "version": action_version,
            "resource": resource,
            "parameters": {"kind": "any_validated"},
            "approval": approval,
        }],
    });
    activate_snapshot(broker, snapshot).await;
    rule_id
}

fn binding(action_id: &str, version: u64, resource: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "action_id": action_id,
        "version": version,
        "resource": resource,
        "parameter_schema_id": "test-any-json/v1",
        "parameter_schema": {},
    })
}

async fn activate_snapshot(broker: &TestBroker, snapshot: serde_json::Value) {
    let trust = serde_json::json!({
        "format_version": 1,
        "signer_id": broker.policy_signer_id,
        "algorithm": "ed25519",
        "public_key": HEXLOWER.encode(broker.policy_signer.public_key().as_ref()),
    });
    call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::POLICY_TRUST_INSTALL,
        trust.to_string().as_bytes(),
        &proof_body(PASSWORD),
    )
    .await
    .ok();
    let unsigned = serde_json::json!({
        "format_version": 1,
        "signer_id": broker.policy_signer_id,
        "snapshot": snapshot,
    });
    let mut message = b"RKPOLICY\0\x01".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).expect("canonical policy"));
    let signature = BASE64URL_NOPAD.encode(broker.policy_signer.sign(&message).as_ref());
    let mut bundle = unsigned;
    bundle
        .as_object_mut()
        .expect("policy envelope object")
        .insert("signature".to_owned(), serde_json::Value::String(signature));
    call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::POLICY_ACTIVATE,
        &serde_jcs::to_vec(&bundle).expect("canonical bundle"),
        &proof_body(PASSWORD),
    )
    .await
    .ok();
}
