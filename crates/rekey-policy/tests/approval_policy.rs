use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::HEXLOWER;
use rekey_domain::Timestamp;
use rekey_domain::authorization::{ApproverSpec, AuthorizationRequest, Decision, Principal};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ActionId, ApproverId, PolicyRuleId, PrincipalId, SessionId, TenantId};
use rekey_policy::{ValidatedSnapshot, evaluate, parse_and_validate_snapshot};
use serde_json::{Value, json};

struct Fixture {
    action: ActionVersionRef,
    principal: PrincipalId,
    value: Value,
}

fn policy_fixture() -> Fixture {
    let action = ActionVersionRef {
        action_id: ActionId::new_random(),
        version: 1,
    };
    let principal = PrincipalId::new_random();
    let resource = json!({"type": "test.resource", "id": "one"});
    Fixture {
        action,
        principal,
        value: json!({
            "format_version": 8, "connections": [], "ssh_keys": [], "derived_credentials": [], "profiles": [],
            "version": 1,
            "expires_at_ms": 10_000,
            "approvers": [],
            "workload_identities": [],
            "bindings": [{
                "action_id": action.action_id,
                "version": action.version,
                "resource": resource,
                "parameter_schema_id": "test/v1",
                "parameter_schema": {},
            }],
            "rules": [{
                "id": PolicyRuleId::new_random(),
                "effect": "permit",
                "principal_id": principal,
                "action_id": action.action_id,
                "version": action.version,
                "resource": resource,
                "parameters": {"kind": "any_validated"},
            }],
        }),
    }
}

fn add_approver(value: &mut Value, approver_id: ApproverId, key: [u8; 32]) {
    value["approvers"].as_array_mut().unwrap().push(json!({
        "approver_id": approver_id,
        "algorithm": "ed25519",
        "public_key": HEXLOWER.encode(&key),
    }));
}

fn approval_rule(fixture: &Fixture, approvers: &[ApproverId], max_uses: u32) -> Value {
    let keys: Vec<_> = approvers
        .iter()
        .map(|id| {
            fixture.value["approvers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["approver_id"] == json!(id))
                .map(|a| a["public_key"].clone())
                .unwrap_or(json!(HEXLOWER.encode(&[9u8; 32])))
        })
        .collect();
    json!({
        "id": PolicyRuleId::new_random(),
        "effect": "require-approval",
        "principal_id": fixture.principal,
        "action_id": fixture.action.action_id,
        "version": fixture.action.version,
        "resource": {"type": "test.resource", "id": "one"},
        "parameters": {"kind": "any_validated"},
        "approver": {"kind":"ed25519","keys":keys,"threshold":1},
        "approval": {
            "mode": "time-window",
            "max_uses": max_uses,
            "max_window_ms": 60_000,
        },
    })
}

fn validated(value: &Value) -> ValidatedSnapshot {
    parse_and_validate_snapshot(
        &serde_json::to_vec(value).unwrap(),
        Timestamp::from_unix_ms(1),
    )
    .unwrap()
}

fn request(fixture: &Fixture, snapshot: &ValidatedSnapshot) -> AuthorizationRequest {
    let action = serde_json::from_value(json!({
        "id": fixture.action.action_id, "name":"policy-test", "version":fixture.action.version,
        "enabled":true,"credential_id":ActionId::new_random(),"origin":"https://example.com",
        "method":"POST","target":{"kind":"fixed","path":"/test"},
        "auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":5000,
        "request_policy":{"max_body_bytes":4096,"allowed_extra_headers":[]},
        "response_policy":{"max_body_bytes":4096,"allowed_headers":[]}
    }))
    .unwrap();
    let (resource, parameters, _) = snapshot
        .canonicalize(
            &action,
            rekey_policy::ActionRequest {
                params: &Default::default(),
                query: &Default::default(),
                content_type: Some("application/json"),
                headers: &[],
                body: b"{}",
            },
        )
        .unwrap();
    AuthorizationRequest {
        principal: Principal {
            tenant_id: TenantId::new_random(),
            principal_id: fixture.principal,
            session_id: SessionId::new_random(),
        },
        action: fixture.action,
        resource,
        parameters,
    }
}

#[test]
fn approval_wins_over_permit_and_forbid_wins_over_approval() {
    let mut fixture = policy_fixture();
    let approver = ApproverId::new_random();
    add_approver(&mut fixture.value, approver, [1u8; 32]);
    let required = approval_rule(&fixture, &[approver], 2);
    fixture.value["rules"]
        .as_array_mut()
        .unwrap()
        .push(required);
    let snapshot = validated(&fixture.value);
    assert!(matches!(
        evaluate(
            &snapshot,
            &request(&fixture, &snapshot),
            Timestamp::from_unix_ms(2),
            false,
        ),
        Decision::RequireApproval { .. }
    ));

    fixture.value["rules"].as_array_mut().unwrap().push(json!({
        "id": PolicyRuleId::new_random(),
        "effect": "forbid",
        "principal_id": fixture.principal,
        "action_id": fixture.action.action_id,
        "version": fixture.action.version,
        "resource": {"type": "test.resource", "id": "one"},
        "parameters": {"kind": "any_validated"},
    }));
    let snapshot = validated(&fixture.value);
    assert!(matches!(
        evaluate(
            &snapshot,
            &request(&fixture, &snapshot),
            Timestamp::from_unix_ms(2),
            false,
        ),
        Decision::Deny { .. }
    ));
}

#[test]
fn approver_catalog_and_overlapping_requirements_are_closed_and_bounded() {
    let mut fixture = policy_fixture();
    let approver = ApproverId::new_random();
    add_approver(&mut fixture.value, approver, [1u8; 32]);
    let required = approval_rule(&fixture, &[approver], 2);
    fixture.value["rules"]
        .as_array_mut()
        .unwrap()
        .push(required);
    let mut conflicting = approval_rule(&fixture, &[approver], 3);
    conflicting["parameters"] =
        json!({"kind": "exact_hash", "sha256": HEXLOWER.encode(&[9u8; 32])});
    fixture.value["rules"]
        .as_array_mut()
        .unwrap()
        .push(conflicting);
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&fixture.value).unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .is_err()
    );

    let mut missing = policy_fixture();
    let missing_rule = approval_rule(&missing, &[ApproverId::new_random()], 1);
    missing.value["rules"]
        .as_array_mut()
        .unwrap()
        .push(missing_rule);
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&missing.value).unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .is_err()
    );

    let mut duplicate_key = policy_fixture();
    let duplicate_public_key: [u8; 32] = Ed25519KeyPair::from_seed_unchecked(&[7; 32])
        .unwrap()
        .public_key()
        .as_ref()
        .try_into()
        .unwrap();
    add_approver(
        &mut duplicate_key.value,
        ApproverId::new_random(),
        duplicate_public_key,
    );
    add_approver(
        &mut duplicate_key.value,
        ApproverId::new_random(),
        duplicate_public_key,
    );
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&duplicate_key.value).unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .is_err()
    );

    let mut oversized = policy_fixture();
    for marker in 0..33u8 {
        let mut key = [0u8; 32];
        key[0] = marker;
        add_approver(&mut oversized.value, ApproverId::new_random(), key);
    }
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&oversized.value).unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .is_err()
    );
}

#[test]
fn approver_is_the_only_authority_source_and_local_never_becomes_allow() {
    let mut fixture = policy_fixture();
    let mut rule = approval_rule(&fixture, &[], 1);
    rule["approver"] = json!({"kind":"local-presence"});
    rule["approval"] = json!({"mode":"one-time","max_uses":1});
    fixture.value["rules"] = json!([rule]);
    let snapshot = validated(&fixture.value);
    assert!(matches!(
        evaluate(
            &snapshot,
            &request(&fixture, &snapshot),
            Timestamp::from_unix_ms(2),
            false
        ),
        Decision::RequireApproval {
            approver: ApproverSpec::LocalPresence {},
            ..
        }
    ));
    for (field, value) in [
        ("approver", json!({"kind":"local-presence","threshold":1})),
        ("approver", json!({"kind":"local-presence","keys":[]})),
        ("approver", json!({"kind":"remote"})),
        ("approver", Value::Null),
        ("approval", Value::Null),
        ("approval", json!({"mode":"one-time","max_uses":2})),
        (
            "approval",
            json!({"mode":"one-time","max_uses":1,"max_window_ms":1}),
        ),
        (
            "approval",
            json!({"mode":"time-window","max_uses":1,"max_window_ms":1}),
        ),
        (
            "approval",
            json!({"mode":"one-time","max_uses":1,"quorum":1}),
        ),
        (
            "approval",
            json!({"mode":"one-time","max_uses":1,"approver_ids":[]}),
        ),
        ("effect", json!("permit")),
        ("effect", json!("forbid")),
    ] {
        let mut invalid = fixture.value.clone();
        invalid["rules"][0][field] = value;
        assert!(
            parse_and_validate_snapshot(
                &serde_json::to_vec(&invalid).unwrap(),
                Timestamp::from_unix_ms(1)
            )
            .is_err(),
            "accepted {invalid}"
        );
    }
    fixture.value["format_version"] = 3.into();
    assert!(matches!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&fixture.value).unwrap(),
            Timestamp::from_unix_ms(1)
        ),
        Err(rekey_policy::PolicyError::UnsupportedFormat)
    ));
}

#[test]
fn ed25519_keys_resolve_unique_ids_and_keep_single_double_and_window_limits() {
    let mut fixture = policy_fixture();
    let first = ApproverId::new_random();
    let second = ApproverId::new_random();
    let second_key: [u8; 32] = Ed25519KeyPair::from_seed_unchecked(&[7; 32])
        .unwrap()
        .public_key()
        .as_ref()
        .try_into()
        .unwrap();
    add_approver(&mut fixture.value, first, [1; 32]);
    add_approver(&mut fixture.value, second, second_key);
    let mut rule = approval_rule(&fixture, &[second, first], 10_000);
    rule["approver"]["threshold"] = 2.into();
    rule["approval"]["max_window_ms"] = (8 * 60 * 60 * 1000).into();
    fixture.value["rules"] = json!([rule.clone()]);
    let snapshot = validated(&fixture.value);
    let keys = vec![HEXLOWER.encode(&second_key), HEXLOWER.encode(&[1; 32])];
    let mut ids = vec![first, second];
    ids.sort();
    assert_eq!(snapshot.ed25519_approver_ids(&keys), Some(ids));
    let decision = evaluate(
        &snapshot,
        &request(&fixture, &snapshot),
        Timestamp::from_unix_ms(2),
        false,
    );
    let Decision::RequireApproval {
        approver: ApproverSpec::Ed25519 { keys, threshold: 2 },
        requirement,
        ..
    } = decision
    else {
        panic!("double approval lost");
    };
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(requirement.max_uses, 10_000);
    assert_eq!(snapshot.ed25519_approver_ids(&[]), None);
    assert_eq!(
        snapshot.ed25519_approver_ids(&[keys[0].clone(), keys[0].clone()]),
        None
    );
    assert_eq!(snapshot.ed25519_approver_ids(&["ff".repeat(32)]), None);
    for invalid in [
        json!({"kind":"ed25519","keys":[],"threshold":1}),
        json!({"kind":"ed25519","keys":[keys[0]],"threshold":0}),
        json!({"kind":"ed25519","keys":[keys[0]],"threshold":2}),
        json!({"kind":"ed25519","keys":keys,"threshold":3}),
        json!({"kind":"ed25519","keys":[keys[0],keys[0]],"threshold":1}),
        json!({"kind":"ed25519","keys":["ff".repeat(32)],"threshold":1}),
        json!({"kind":"ed25519","keys":["AA".repeat(32)],"threshold":1}),
    ] {
        let mut bad = fixture.value.clone();
        bad["rules"][0]["approver"] = invalid;
        assert!(
            parse_and_validate_snapshot(
                &serde_json::to_vec(&bad).unwrap(),
                Timestamp::from_unix_ms(1)
            )
            .is_err()
        );
    }
    // Equivalent key sets in another order remain equivalent overlapping rules.
    let mut equivalent = rule.clone();
    equivalent["id"] = json!(PolicyRuleId::new_random());
    equivalent["approver"]["keys"]
        .as_array_mut()
        .unwrap()
        .reverse();
    fixture.value["rules"]
        .as_array_mut()
        .unwrap()
        .push(equivalent);
    validated(&fixture.value);
    fixture.value["rules"][1]["approver"]["threshold"] = 1.into();
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&fixture.value).unwrap(),
            Timestamp::from_unix_ms(1)
        )
        .is_err()
    );
    fixture.value["rules"] = json!([rule]);
    fixture.value["rules"][0]["approval"] = json!({"mode":"one-time","max_uses":1});
    for threshold in [1, 2] {
        fixture.value["rules"][0]["approver"]["threshold"] = threshold.into();
        validated(&fixture.value);
    }
    for limits in [
        json!({"mode":"time-window","max_uses":10001,"max_window_ms":1}),
        json!({"mode":"time-window","max_uses":1,"max_window_ms":28800001}),
        json!({"mode":"time-window","max_uses":1,"max_window_ms":0}),
    ] {
        fixture.value["rules"][0]["approval"] = limits;
        assert!(
            parse_and_validate_snapshot(
                &serde_json::to_vec(&fixture.value).unwrap(),
                Timestamp::from_unix_ms(1)
            )
            .is_err()
        );
    }
}
