use data_encoding::HEXLOWER;
use rekey_domain::Timestamp;
use rekey_domain::authorization::{AuthorizationRequest, Decision, Principal};
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
            "format_version": 2,
            "version": 1,
            "expires_at_ms": 10_000,
            "approvers": [],
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
    json!({
        "id": PolicyRuleId::new_random(),
        "effect": "require-approval",
        "principal_id": fixture.principal,
        "action_id": fixture.action.action_id,
        "version": fixture.action.version,
        "resource": {"type": "test.resource", "id": "one"},
        "parameters": {"kind": "any_validated"},
        "approval": {
            "approver_ids": approvers,
            "quorum": 1,
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
    let (resource, parameters) = snapshot
        .canonicalize(fixture.action, Some("application/json"), &[], b"{}")
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
    add_approver(
        &mut duplicate_key.value,
        ApproverId::new_random(),
        [7u8; 32],
    );
    add_approver(
        &mut duplicate_key.value,
        ApproverId::new_random(),
        [7u8; 32],
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
