use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::Timestamp;
use rekey_domain::authorization::{
    AuthorizationRequest, Decision, PolicyTrustAlgorithm, Principal,
};
use rekey_domain::ids::{ActionId, PolicyRuleId, PolicySignerId, PrincipalId, SessionId, TenantId};
use rekey_policy::{
    PolicyError, PolicyVerificationKey, ValidatedPolicyTrust, evaluate,
    parse_and_validate_snapshot, parse_and_validate_snapshot_for_load,
    parse_and_verify_policy_bundle,
};
use serde_json::{Value, json};

const NOW: Timestamp = Timestamp::from_unix_ms(1);

fn fixture() -> Value {
    let principal = PrincipalId::new_random();
    let action = ActionId::new_random();
    json!({
        "format_version":8,"connections":[],"ssh_keys":[],"derived_credentials":[],"version":1,"expires_at_ms":10_000,
        "approvers":[],"workload_identities":[],
        "bindings":[{"action_id":action,"version":1,"resource":{"type":"action","id":action},"parameter_schema_id":"test","parameter_schema":true}],
        "rules":[{"id":PolicyRuleId::new_random(),"effect":"require-approval","principal_id":principal,
            "action_id":action,"version":1,"resource":{"type":"action","id":action},"parameters":{"kind":"any_validated"},
            "approver":{"kind":"local-presence"},"approval":{"mode":"one-time","max_uses":1}}],
        "profiles":[{
            "name":"claude-code","principal_id":principal,
            "grants":[{"instance":"anthropic","capabilities":[{"rule":"template-default","capability":"messages","actions":[{"action_id":action,"version":1}]}]}],
            "session":{"ttl_ms":43200000,"max_uses":5000},"confirm_each_run":false,"isolation":"none","egress":"allow",
            "llm_limits":[{"instance":"anthropic","models":["model-a","model-b"],"max_output_tokens_per_request":4096,"max_requests_per_day":2000,"max_output_tokens_per_day":2000000}]
        }]
    })
}

fn validate(value: &Value) -> Result<rekey_policy::ValidatedSnapshot, PolicyError> {
    parse_and_validate_snapshot(&serde_json::to_vec(value).unwrap(), NOW)
}

fn second_profile(value: &mut Value) {
    let mut profile = value["profiles"][0].clone();
    profile["name"] = "codex".into();
    value["profiles"].as_array_mut().unwrap().push(profile);
}

#[test]
fn snapshot_six_requires_profiles_and_rejects_five_even_without_new_field() {
    let mut value = fixture();
    assert_eq!(
        validate(&value)
            .unwrap()
            .profile("claude-code")
            .unwrap()
            .session
            .max_uses,
        5000
    );
    assert!(validate(&value).unwrap().profile("absent").is_none());
    value["profiles"] = json!([]);
    validate(&value).unwrap();
    value.as_object_mut().unwrap().remove("profiles");
    assert!(matches!(validate(&value), Err(PolicyError::Malformed)));
    value["format_version"] = 5.into();
    assert!(matches!(
        validate(&value),
        Err(PolicyError::UnsupportedFormat)
    ));
    assert!(matches!(
        parse_and_validate_snapshot_for_load(&serde_json::to_vec(&value).unwrap()),
        Err(PolicyError::UnsupportedFormat)
    ));
}

#[test]
fn snapshot_six_rejects_missing_or_unknown_rule_and_old_empty_profiles() {
    let value = fixture();
    for rule in [None, Some(json!("deny")), Some(Value::Null)] {
        let mut malformed = value.clone();
        let cap = malformed["profiles"][0]["grants"][0]["capabilities"][0]
            .as_object_mut()
            .unwrap();
        match rule {
            Some(rule) => {
                cap.insert("rule".into(), rule);
            }
            None => {
                cap.remove("rule");
            }
        }
        assert!(matches!(validate(&malformed), Err(PolicyError::Malformed)));
    }
    let mut old = value;
    old["format_version"] = 5.into();
    old["profiles"] = json!([]);
    assert!(matches!(
        validate(&old),
        Err(PolicyError::UnsupportedFormat)
    ));
}

#[test]
fn missing_bindings_wrong_principal_and_duplicate_profiles_are_rejected() {
    let valid = fixture();
    let mut value = valid.clone();
    value["bindings"] = json!([]);
    assert!(validate(&value).is_err());
    let mut value = valid.clone();
    value["rules"] = json!([]);
    assert!(validate(&value).is_err());
    let mut value = valid.clone();
    value["profiles"][0]["principal_id"] = json!(PrincipalId::new_random());
    assert!(validate(&value).is_err());
    let mut value = valid.clone();
    value["profiles"][0]["grants"][0]["capabilities"][0]["actions"][0]["version"] = 2.into();
    assert!(validate(&value).is_err());
    let mut value = valid;
    second_profile(&mut value);
    value["profiles"][1]["name"] = "claude-code".into();
    assert!(validate(&value).is_err());
}

#[test]
fn profiles_do_not_override_require_approval_or_forbid() {
    let mut value = fixture();
    value["profiles"][0]["grants"][0]["capabilities"][0]["rule"] = "allow".into();
    for effect in ["require-approval", "forbid"] {
        value["rules"][0]["effect"] = effect.into();
        if effect == "forbid" {
            value["rules"][0]
                .as_object_mut()
                .unwrap()
                .remove("approver");
            value["rules"][0]
                .as_object_mut()
                .unwrap()
                .remove("approval");
        }
        let snapshot = validate(&value).unwrap();
        let profile = &snapshot.profiles()[0];
        let action = profile.action_refs().next().unwrap();
        let request = AuthorizationRequest {
            principal: Principal {
                tenant_id: TenantId::new_random(),
                principal_id: profile.principal_id,
                session_id: SessionId::new_random(),
            },
            action,
            resource: snapshot.binding(action).unwrap().resource.clone(),
            parameters: rekey_domain::authorization::CanonicalParameters {
                schema_id: snapshot
                    .binding(action)
                    .unwrap()
                    .parameter_schema_id
                    .clone(),
                canonical_hash: [0; 32],
                canonical_json: vec![],
            },
        };
        let decision = evaluate(&snapshot, &request, NOW, false);
        assert!(if effect == "forbid" {
            matches!(decision, Decision::Deny { .. })
        } else {
            matches!(decision, Decision::RequireApproval { .. })
        });
    }
}

#[test]
fn shared_principal_instance_limits_are_identical_sets_including_presence() {
    let mut value = fixture();
    second_profile(&mut value);
    value["profiles"][1]["llm_limits"][0]["models"] = json!(["model-b", "model-a"]);
    validate(&value).unwrap();
    for field in [
        "max_output_tokens_per_request",
        "max_requests_per_day",
        "max_output_tokens_per_day",
    ] {
        let mut different = value.clone();
        different["profiles"][1]["llm_limits"][0][field] = 123.into();
        assert!(validate(&different).is_err(), "{field}");
    }
    let mut different = value.clone();
    different["profiles"][1]["llm_limits"][0]["models"] = json!(["model-c"]);
    assert!(validate(&different).is_err());
    let mut different = value.clone();
    different["profiles"][1]["llm_limits"] = json!([]);
    assert!(validate(&different).is_err());
    // Another stable principal has its own budget, with a matching rule.
    let other = PrincipalId::new_random();
    value["profiles"][1]["principal_id"] = json!(other);
    value["profiles"][1]["llm_limits"][0]["max_requests_per_day"] = 123.into();
    let mut rule = value["rules"][0].clone();
    rule["id"] = json!(PolicyRuleId::new_random());
    rule["principal_id"] = json!(other);
    value["rules"].as_array_mut().unwrap().push(rule);
    validate(&value).unwrap();
}

#[test]
fn independent_principals_can_bind_the_same_slug_to_distinct_actions() {
    let mut value = fixture();
    second_profile(&mut value);
    let principal = PrincipalId::new_random();
    let action = ActionId::new_random();
    value["profiles"][1]["principal_id"] = json!(principal);
    value["profiles"][1]["grants"][0]["capabilities"][0]["actions"] =
        json!([{"action_id":action,"version":1}]);
    let mut binding = value["bindings"][0].clone();
    binding["action_id"] = json!(action);
    value["bindings"].as_array_mut().unwrap().push(binding);
    let mut rule = value["rules"][0].clone();
    rule["id"] = json!(PolicyRuleId::new_random());
    rule["principal_id"] = json!(principal);
    rule["action_id"] = json!(action);
    value["rules"].as_array_mut().unwrap().push(rule);
    validate(&value).unwrap();
    // Sharing a principal still cannot give one instance inconsistent mappings.
    value["profiles"][1]["principal_id"] = value["profiles"][0]["principal_id"].clone();
    value["rules"][1]["principal_id"] = value["profiles"][0]["principal_id"].clone();
    assert!(validate(&value).is_err());
}

#[test]
fn shared_slug_capability_maps_exact_sorted_refs_but_allows_subsets() {
    let mut value = fixture();
    let another = ActionId::new_random();
    let mut binding = value["bindings"][0].clone();
    binding["action_id"] = json!(another);
    value["bindings"].as_array_mut().unwrap().push(binding);
    let mut rule = value["rules"][0].clone();
    rule["id"] = json!(PolicyRuleId::new_random());
    rule["action_id"] = json!(another);
    value["rules"].as_array_mut().unwrap().push(rule);
    value["profiles"][0]["grants"][0]["capabilities"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!({"action_id":another,"version":1}));
    second_profile(&mut value);
    value["profiles"][1]["grants"][0]["capabilities"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .reverse();
    validate(&value).unwrap();
    let mut different = value.clone();
    different["profiles"][1]["grants"][0]["capabilities"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(validate(&different).is_err());
    // Different capability subsets are permitted; the same capability must agree.
    value["profiles"][0]["grants"][0]["capabilities"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .pop();
    value["profiles"][1]["grants"][0]["capabilities"][0]["actions"] =
        json!([{"action_id":another,"version":1}]);
    value["profiles"][1]["grants"][0]["capabilities"][0]["capability"] = "count-tokens".into();
    validate(&value).unwrap();
}

fn signed(mut snapshot: Value) -> (Value, ValidatedPolicyTrust) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let trust = ValidatedPolicyTrust::from_parts(
        PolicySignerId::new_random(),
        PolicyVerificationKey::from_bytes(PolicyTrustAlgorithm::Ed25519, key.public_key().as_ref())
            .unwrap(),
    );
    let mut value =
        json!({"format_version":1,"signer_id":trust.signer_id(),"snapshot":snapshot.take()});
    let mut message = b"RKPOLICY\0\x01".to_vec();
    message.extend(serde_jcs::to_vec(&value).unwrap());
    value["signature"] = BASE64URL_NOPAD.encode(key.sign(&message).as_ref()).into();
    (value, trust)
}

#[test]
fn signed_profile_constraints_are_authenticated_and_legacy_bundles_rejected() {
    let (mut value, trust) = signed(fixture());
    assert_eq!(
        parse_and_verify_policy_bundle(&serde_json::to_vec(&value).unwrap(), &trust, NOW)
            .unwrap()
            .snapshot()
            .profiles()
            .len(),
        1
    );
    value["snapshot"]["profiles"][0]["confirm_each_run"] = true.into();
    assert!(matches!(
        parse_and_verify_policy_bundle(&serde_json::to_vec(&value).unwrap(), &trust, NOW),
        Err(PolicyError::InvalidSignature)
    ));
    let mut old = fixture();
    old["format_version"] = 4.into();
    old.as_object_mut().unwrap().remove("profiles");
    let (value, trust) = signed(old);
    assert!(matches!(
        parse_and_verify_policy_bundle(&serde_json::to_vec(&value).unwrap(), &trust, NOW),
        Err(PolicyError::UnsupportedFormat)
    ));
}

#[test]
fn profile_integer_rounding_is_rejected_before_signing_or_verifying_jcs() {
    let mut value = fixture();
    value["profiles"][0]["llm_limits"][0]["max_requests_per_day"] = json!(9_007_199_254_740_992u64);
    validate(&value).unwrap(); // Exactly representable, not an arbitrary 2^53-1 cap.
    for field in ["max_requests_per_day", "max_output_tokens_per_day"] {
        let mut lossy = value.clone();
        lossy["profiles"][0]["llm_limits"][0][field] = json!(9_007_199_254_740_993u64);
        assert!(matches!(validate(&lossy), Err(PolicyError::Invalid)));
        // A signature over rounded JCS must not authorize the distinct raw integer.
        let (bundle, trust) = signed(lossy);
        assert!(matches!(
            parse_and_verify_policy_bundle(&serde_json::to_vec(&bundle).unwrap(), &trust, NOW),
            Err(PolicyError::Invalid)
        ));
    }
    value["profiles"][0]["grants"][0]["capabilities"][0]["actions"][0]["version"] =
        json!(9_007_199_254_740_993u64);
    assert!(matches!(validate(&value), Err(PolicyError::Invalid)));
}
