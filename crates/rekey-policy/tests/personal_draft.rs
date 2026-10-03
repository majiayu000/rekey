use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::Timestamp;
use rekey_domain::action::{ActionTarget, ExactPath, FixedHttpAction};
use rekey_domain::authorization::PolicyTrustAlgorithm;
use rekey_domain::ids::{ActionId, ApproverId, CredentialId, PolicySignerId, PrincipalId};
use rekey_domain::profile::{AgentProfile, ProfileRule};
use rekey_domain::template::TemplateValues;
use rekey_policy::personal::PersonalPolicyDraft;
use rekey_policy::templates::{BuiltinTemplate, builtin_template};
use rekey_policy::{
    ActionRequest, PolicyError, PolicyVerificationKey, SNAPSHOT_MAX_BYTES, ValidatedPolicyBundle,
    ValidatedPolicyTrust, parse_and_verify_policy_bundle,
};
use serde_json::{Value, json};

const PREFIX: &[u8] = b"RKPOLICY\0\x01";
const NOW: Timestamp = Timestamp::from_unix_ms(1);

// Build an explicit signed Profile for the existing Action-focused fixtures.
fn generate_personal_draft(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    actions: &[FixedHttpAction],
    principal: PrincipalId,
    expires: i64,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    let mut selected: Vec<_> = actions.iter().collect();
    selected.sort_by_key(|action| (action.id, action.version));
    let grants: Vec<_> = selected
        .iter()
        .map(|action| {
            let capability = match &action.target {
                ActionTarget::Template { source, .. } => source.capability.as_str(),
                _ => "fixed-actions",
            };
            json!({"instance":format!("a-{}",action.id),"capabilities":[{"rule":"template-default","capability":capability,
            "actions":[{"action_id":action.id,"version":action.version}]}]})
        })
        .collect();
    let profiles = if grants.is_empty() {
        Vec::new()
    } else {
        vec![
            serde_json::from_value(json!({"name":"fixture","principal_id":principal,
            "grants":grants,"session":{"ttl_ms":1000,"max_uses":100},"confirm_each_run":false,
            "isolation":"none","egress":"allow","llm_limits":[]}))
            .unwrap(),
        ]
    };
    rekey_policy::personal::generate_personal_draft(
        trust, previous, actions, &profiles, expires, now,
    )
}

fn signer() -> (EcdsaKeyPair, ValidatedPolicyTrust) {
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
    let trust = ValidatedPolicyTrust::from_parts(
        PolicySignerId::new_random(),
        PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::SecureEnclaveP256,
            key.public_key().as_ref(),
        )
        .unwrap(),
    );
    (key, trust)
}

fn action(capability: &str) -> FixedHttpAction {
    let package = builtin_template(BuiltinTemplate::GitHubPat).unwrap();
    let bound = package
        .template()
        .bind(
            &[
                ("owner".into(), "acme".into()),
                ("repo".into(), "repo".into()),
            ]
            .into(),
        )
        .unwrap();
    let materialized = bound.materialize(capability, 0).unwrap();
    let definition = materialized.definition();
    let schema = definition
        .body_schema
        .as_ref()
        .map(|name| package.schema(name).unwrap().definition().clone());
    serde_json::from_value(json!({
        "id":ActionId::new_random(), "name":capability, "version":1, "enabled":true,
        "credential_id":CredentialId::new_random(), "origin":definition.origin, "method":definition.method,
        "target":{"kind":"template", "target":definition.target, "fixed_headers":definition.fixed_headers,
            "body_schema":schema, "default_policy":definition.default_policy,
            "source":{"template":definition.template,"capability":definition.capability,
                "action_index":definition.action_index,"digest":package.digest(),"signer_id":null}},
        "auth":{"header_name":definition.credential.inject.header,"prefix":definition.credential.inject.prefix},
        "timeout_ms":1000,"request_policy":{"max_body_bytes":4096,"allowed_extra_headers":[]},
        "response_policy":{"max_body_bytes":4096,"allowed_headers":[]}
    })).unwrap()
}

fn signed_value(
    mut unsigned: Value,
    key: &EcdsaKeyPair,
    trust: &ValidatedPolicyTrust,
) -> ValidatedPolicyBundle {
    let mut message = PREFIX.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
    unsigned["signature"] = BASE64URL_NOPAD
        .encode(key.sign(&SystemRandom::new(), &message).unwrap().as_ref())
        .into();
    parse_and_verify_policy_bundle(&serde_json::to_vec(&unsigned).unwrap(), trust, NOW).unwrap()
}

fn sign_draft(
    draft: &PersonalPolicyDraft,
    key: &EcdsaKeyPair,
    trust: &ValidatedPolicyTrust,
) -> ValidatedPolicyBundle {
    assert!(draft.sign_bytes().starts_with(PREFIX));
    let mut unsigned: Value = serde_json::from_slice(&draft.sign_bytes()[PREFIX.len()..]).unwrap();
    assert_eq!(
        serde_jcs::to_vec(&unsigned["snapshot"]).unwrap(),
        draft.canonical_snapshot()
    );
    unsigned["signature"] = BASE64URL_NOPAD
        .encode(
            key.sign(&SystemRandom::new(), draft.sign_bytes())
                .unwrap()
                .as_ref(),
        )
        .into();
    let bytes = serde_json::to_vec(&unsigned).unwrap();
    assert!(bytes.len() <= SNAPSHOT_MAX_BYTES);
    parse_and_verify_policy_bundle(&bytes, trust, NOW).unwrap()
}

fn change<'a>(
    draft: &'a PersonalPolicyDraft,
    field: &str,
) -> &'a rekey_policy::personal::PolicyFieldChange {
    draft
        .diff()
        .iter()
        .find(|change| change.field == field)
        .unwrap()
}

#[test]
fn low_and_medium_actions_produce_deterministic_full_policy_that_p256_verifies() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let actions = [action("read-repo"), action("create-issue")];
    let original = serde_json::to_value(&actions).unwrap();
    let draft = generate_personal_draft(&trust, None, &actions, principal, 10_000, NOW).unwrap();
    let reversed = generate_personal_draft(
        &trust,
        None,
        &[actions[1].clone(), actions[0].clone()],
        principal,
        10_000,
        NOW,
    )
    .unwrap();
    assert_eq!(draft.canonical_snapshot(), reversed.canonical_snapshot());
    assert_eq!(draft.sign_bytes(), reversed.sign_bytes());
    assert_eq!(draft.diff(), reversed.diff());
    assert_eq!(original, serde_json::to_value(&actions).unwrap());
    let snapshot: Value = serde_json::from_slice(draft.canonical_snapshot()).unwrap();
    assert_eq!(snapshot["version"], 1);
    assert_eq!(snapshot["format_version"], 6);
    assert_eq!(snapshot["profiles"][0]["principal_id"], json!(principal));
    assert_eq!(snapshot["approvers"], json!([]));
    assert_eq!(snapshot["workload_identities"], json!([]));
    for action in &actions {
        let binding = snapshot["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["action_id"] == json!(action.id))
            .unwrap();
        let ActionTarget::Template { body_schema, .. } = &action.target else {
            unreachable!()
        };
        assert_eq!(
            binding["parameter_schema"],
            body_schema.clone().unwrap_or(json!(true))
        );
        assert_eq!(
            binding["parameter_schema_id"],
            format!("action/{}/{}", action.id, action.version)
        );
        assert_eq!(binding["resource"], json!({"type":"action","id":action.id}));
        let rule = snapshot["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["action_id"] == json!(action.id))
            .unwrap();
        assert_eq!(rule["principal_id"], json!(principal));
        assert_eq!(rule["effect"], "permit");
    }
    let verified = sign_draft(&draft, &key, &trust);
    assert_eq!(verified.snapshot().version().get(), 1);
    let refs: Vec<_> = verified.snapshot().action_refs().collect();
    assert_eq!(refs.len(), actions.len());
    for action in &actions {
        assert!(refs.iter().any(
            |reference| reference.action_id == action.id && reference.version == action.version
        ));
    }
    let second =
        generate_personal_draft(&trust, Some(&verified), &actions, principal, 10_000, NOW).unwrap();
    assert_eq!(
        second.diff().iter().map(|c| c.field).collect::<Vec<_>>(),
        ["version"]
    );
    assert_eq!(
        sign_draft(&second, &key, &trust).snapshot().version().get(),
        2
    );
}

#[test]
fn unselected_permissions_and_empty_selection_are_explicitly_removed() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let actions = [action("read-repo"), action("create-issue")];
    let original = generate_personal_draft(&trust, None, &actions, principal, 10_000, NOW).unwrap();
    let previous = sign_draft(&original, &key, &trust);
    let reduced = generate_personal_draft(
        &trust,
        Some(&previous),
        &actions[..1],
        principal,
        20_000,
        NOW,
    )
    .unwrap();
    for field in ["bindings", "rules"] {
        let diff = change(&reduced, field);
        assert_eq!(diff.before.as_array().unwrap().len(), 2);
        assert_eq!(diff.after.as_array().unwrap().len(), 1);
        assert_eq!(diff.after[0]["action_id"], json!(actions[0].id));
        assert!(
            diff.before
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["action_id"] == json!(actions[1].id))
        );
    }
    let empty =
        generate_personal_draft(&trust, Some(&previous), &[], principal, 20_000, NOW).unwrap();
    for field in ["bindings", "rules"] {
        assert_eq!(change(&empty, field).before.as_array().unwrap().len(), 2);
        assert_eq!(change(&empty, field).after, json!([]));
    }
    sign_draft(&empty, &key, &trust);
    let initially_empty =
        generate_personal_draft(&trust, None, &[], principal, 10_000, NOW).unwrap();
    sign_draft(&initially_empty, &key, &trust);
}

#[test]
fn previous_approvers_and_workloads_are_removed_with_complete_before_values() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let draft =
        generate_personal_draft(&trust, None, &[action("read-repo")], principal, 10_000, NOW)
            .unwrap();
    let mut unsigned: Value = serde_json::from_slice(&draft.sign_bytes()[PREFIX.len()..]).unwrap();
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let external = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    unsigned["snapshot"]["approvers"] = json!([{"approver_id":ApproverId::new_random(),"algorithm":"ed25519","public_key":HEXLOWER.encode(external.public_key().as_ref())}]);
    unsigned["snapshot"]["workload_identities"] = json!([{"principal_id":principal,"issuer":"https://issuer.example","audiences":["rekey://test"],"max_token_age_ms":60_000,"profile":{"kind":"oidc","subject":"alice"},"keys":[{"algorithm":"ed25519","kid":"fixture","x":BASE64URL_NOPAD.encode(external.public_key().as_ref())}]}]);
    let before = unsigned["snapshot"].clone();
    let previous = signed_value(unsigned, &key, &trust);
    let empty =
        generate_personal_draft(&trust, Some(&previous), &[], principal, 20_000, NOW).unwrap();
    for field in ["approvers", "workload_identities", "bindings", "rules"] {
        assert_eq!(change(&empty, field).before, before[field]);
        assert_eq!(change(&empty, field).after, json!([]));
    }
    sign_draft(&empty, &key, &trust);
}

#[test]
fn generated_policy_reuses_authenticated_target_and_body_schema_for_requests() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let selected = action("create-issue");
    let draft = generate_personal_draft(
        &trust,
        None,
        std::slice::from_ref(&selected),
        principal,
        10_000,
        NOW,
    )
    .unwrap();
    let verified = sign_draft(&draft, &key, &trust);
    let values = TemplateValues::new();
    let request = |params, body| ActionRequest {
        params,
        query: &values,
        content_type: Some("application/json"),
        headers: &[],
        body,
    };
    let (_, _, target) = verified
        .snapshot()
        .canonicalize(
            &selected,
            request(&values, br#"{"title":"synthetic issue"}"#),
        )
        .unwrap();
    assert_eq!(target.request_target(), "/repos/acme/repo/issues");
    assert!(
        verified
            .snapshot()
            .canonicalize(&selected, request(&values, br#"{"title":true}"#))
            .is_err()
    );
    let override_owner = [("owner".into(), "other".into())].into();
    assert!(
        verified
            .snapshot()
            .canonicalize(
                &selected,
                request(&override_owner, br#"{"title":"synthetic"}"#)
            )
            .is_err()
    );
}

#[test]
fn duplicate_disabled_fixed_and_invalid_schema_actions_are_rejected() {
    let (_, trust) = signer();
    let principal = PrincipalId::new_random();
    let selected = action("read-repo");
    assert!(matches!(
        generate_personal_draft(
            &trust,
            None,
            &[selected.clone(), selected.clone()],
            principal,
            10_000,
            NOW
        ),
        Err(PolicyError::Invalid)
    ));
    let mut disabled = selected.clone();
    disabled.enabled = false;
    let mut fixed = selected.clone();
    fixed.target = ActionTarget::Fixed {
        path: ExactPath::parse("/fixed").unwrap(),
    };
    for rejected in [disabled, fixed] {
        assert!(matches!(
            generate_personal_draft(&trust, None, &[rejected], principal, 10_000, NOW),
            Err(PolicyError::Invalid)
        ));
    }
    for schema in [
        json!({"type":7}),
        json!({"$ref":"https://example.com/schema"}),
    ] {
        let mut invalid = selected.clone();
        if let ActionTarget::Template { body_schema, .. } = &mut invalid.target {
            *body_schema = Some(schema);
        }
        assert!(matches!(
            generate_personal_draft(&trust, None, &[invalid], principal, 10_000, NOW),
            Err(PolicyError::Invalid)
        ));
    }
    let mut rounded_version = selected.clone();
    rounded_version.version = (1_u64 << 53) + 1;
    assert!(matches!(
        generate_personal_draft(&trust, None, &[rounded_version], principal, 10_000, NOW),
        Err(PolicyError::Invalid)
    ));
    let mut next_version = selected.clone();
    next_version.version += 1;
    assert!(
        generate_personal_draft(
            &trust,
            None,
            &[selected, next_version],
            principal,
            10_000,
            NOW
        )
        .is_err()
    );
}

#[test]
fn high_risk_template_generates_signed_single_use_local_approval_not_permit() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let high = action("merge-pr");
    let ordinary = action("create-issue");
    let draft = generate_personal_draft(
        &trust,
        None,
        &[high.clone(), ordinary.clone()],
        principal,
        10_000,
        NOW,
    )
    .unwrap();
    sign_draft(&draft, &key, &trust);
    let snapshot: Value = serde_json::from_slice(draft.canonical_snapshot()).unwrap();
    let rule = |id: ActionId| {
        snapshot["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["action_id"] == id.to_string())
            .unwrap()
    };
    assert_eq!(rule(high.id)["effect"], "require-approval");
    assert_eq!(rule(high.id)["approver"], json!({"kind":"local-presence"}));
    assert_eq!(
        rule(high.id)["approval"],
        json!({"mode":"one-time","max_uses":1})
    );
    assert_eq!(rule(ordinary.id)["effect"], "permit");
    assert!(rule(ordinary.id)["approver"].is_null());
    assert!(snapshot["approvers"].as_array().unwrap().is_empty());
}

#[test]
fn team_wrong_signer_expiry_and_jcs_inexact_next_version_are_rejected() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let external = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let team = ValidatedPolicyTrust::from_parts(
        trust.signer_id(),
        PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::Ed25519,
            external.public_key().as_ref(),
        )
        .unwrap(),
    );
    assert!(matches!(
        generate_personal_draft(&team, None, &[], principal, 10_000, NOW),
        Err(PolicyError::Invalid)
    ));
    for expiry in [-1, 0, 1] {
        assert!(matches!(
            generate_personal_draft(&trust, None, &[], principal, expiry, NOW),
            Err(PolicyError::Expired)
        ));
    }
    let draft = generate_personal_draft(&trust, None, &[], principal, 10_000, NOW).unwrap();
    let previous = sign_draft(&draft, &key, &trust);
    let (_, other) = signer();
    assert!(matches!(
        generate_personal_draft(&other, Some(&previous), &[], principal, 10_000, NOW),
        Err(PolicyError::InvalidSignature)
    ));
    let mut unsigned: Value = serde_json::from_slice(&draft.sign_bytes()[PREFIX.len()..]).unwrap();
    // This predecessor is verifiable, but its next integer is not exact in JCS.
    unsigned["snapshot"]["version"] = json!(1_u64 << 53);
    let terminal = signed_value(unsigned, &key, &trust);
    assert!(matches!(
        generate_personal_draft(&trust, Some(&terminal), &[], principal, 10_000, NOW),
        Err(PolicyError::Invalid)
    ));
    assert!(matches!(
        generate_personal_draft(&trust, None, &[], principal, (1_i64 << 53) + 1, NOW),
        Err(PolicyError::Invalid)
    ));
    // An expired verified predecessor can still be replaced by a fresh version.
    let renewed = generate_personal_draft(
        &trust,
        Some(&previous),
        &[],
        principal,
        30_000,
        Timestamp::from_unix_ms(20_000),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(renewed.canonical_snapshot()).unwrap()["version"],
        2
    );
}

#[test]
fn diff_after_values_are_the_exact_canonical_snapshot_projection() {
    let (_, trust) = signer();
    let mut selected = action("read-repo");
    if let ActionTarget::Template { body_schema, .. } = &mut selected.target {
        *body_schema = Some(json!({"type":"number","minimum":-0.0}));
    }
    let draft = generate_personal_draft(
        &trust,
        None,
        &[selected],
        PrincipalId::new_random(),
        10_000,
        NOW,
    )
    .unwrap();
    let snapshot: Value = serde_json::from_slice(draft.canonical_snapshot()).unwrap();
    assert_eq!(
        snapshot["bindings"][0]["parameter_schema"]["minimum"],
        json!(0)
    );
    for change in draft.diff() {
        assert_eq!(change.after, snapshot[change.field]);
    }
}

fn padded_action(size: usize, character: char) -> FixedHttpAction {
    let mut value = action("read-repo");
    if let ActionTarget::Template { body_schema, .. } = &mut value.target {
        *body_schema = Some(json!({"$comment":character.to_string().repeat(size)}));
    }
    value
}

#[test]
fn snapshot_and_complete_diff_limits_reject_instead_of_truncating() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let large = generate_personal_draft(
        &trust,
        None,
        &[padded_action(60_000, 'x')],
        principal,
        10_000,
        NOW,
    )
    .unwrap();
    sign_draft(&large, &key, &trust);
    assert!(matches!(
        generate_personal_draft(
            &trust,
            None,
            &[padded_action(SNAPSHOT_MAX_BYTES, 'x')],
            principal,
            10_000,
            NOW
        ),
        Err(PolicyError::TooLarge)
    ));
    let old = generate_personal_draft(
        &trust,
        None,
        &[padded_action(40_000, 'a')],
        principal,
        10_000,
        NOW,
    )
    .unwrap();
    let previous = sign_draft(&old, &key, &trust);
    let replacement = padded_action(40_000, 'b');
    assert!(
        generate_personal_draft(
            &trust,
            None,
            std::slice::from_ref(&replacement),
            principal,
            10_000,
            NOW
        )
        .is_ok()
    );
    assert!(matches!(
        generate_personal_draft(
            &trust,
            Some(&previous),
            &[replacement],
            principal,
            10_000,
            NOW
        ),
        Err(PolicyError::TooLarge)
    ));
}

#[test]
fn full_replacement_explicitly_removes_verified_profiles_in_diff() {
    let (key, trust) = signer();
    let principal = PrincipalId::new_random();
    let actions = [action("read-repo")];
    let original = generate_personal_draft(&trust, None, &actions, principal, 10_000, NOW).unwrap();
    let mut unsigned: Value =
        serde_json::from_slice(&original.sign_bytes()[PREFIX.len()..]).unwrap();
    unsigned["snapshot"]["profiles"] = json!([{
        "name":"reader","principal_id":principal,
        "grants":[{"instance":"github","capabilities":[{"rule":"template-default","capability":"read-repo","actions":[{"action_id":actions[0].id,"version":1}]}]}],
        "session":{"ttl_ms":1000,"max_uses":1},"confirm_each_run":true,
        "isolation":"none","egress":"allow","llm_limits":[]
    }]);
    let before = unsigned["snapshot"]["profiles"].clone();
    let previous = signed_value(unsigned, &key, &trust);
    assert_eq!(previous.snapshot().profiles().len(), 1);
    // Empty Profile selection is a full replacement: no hidden carry-over.
    let draft =
        generate_personal_draft(&trust, Some(&previous), &[], principal, 20_000, NOW).unwrap();
    assert_eq!(change(&draft, "profiles").before, before);
    assert_eq!(change(&draft, "profiles").after, json!([]));
    assert!(
        sign_draft(&draft, &key, &trust)
            .snapshot()
            .profiles()
            .is_empty()
    );
}

#[test]
fn multiple_profiles_sign_all_limits_and_deduplicate_principal_action_rules() {
    let (key, trust) = signer();
    let actions = [action("read-repo")];
    let initial = generate_personal_draft(
        &trust,
        None,
        &actions,
        PrincipalId::new_random(),
        10000,
        NOW,
    )
    .unwrap();
    let snapshot: Value = serde_json::from_slice(initial.canonical_snapshot()).unwrap();
    let first: rekey_domain::profile::AgentProfile =
        serde_json::from_value(snapshot["profiles"][0].clone()).unwrap();
    let mut second = first.clone();
    second.name = "second".into();
    second.confirm_each_run = true;
    second.session.ttl_ms = 2000;
    second.session.max_uses = 25;
    let mut profiles = vec![first.clone(), second];
    let shared = rekey_policy::personal::generate_personal_draft(
        &trust, None, &actions, &profiles, 10000, NOW,
    )
    .unwrap();
    let verified = sign_draft(&shared, &key, &trust);
    assert_eq!(verified.snapshot().profiles(), profiles);
    let value: Value = serde_json::from_slice(shared.canonical_snapshot()).unwrap();
    assert_eq!(value["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(value["rules"].as_array().unwrap().len(), 1);
    profiles[1].principal_id = PrincipalId::new_random();
    let separate = rekey_policy::personal::generate_personal_draft(
        &trust,
        Some(&verified),
        &actions,
        &profiles,
        20000,
        NOW,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(separate.canonical_snapshot()).unwrap();
    assert_eq!(value["rules"].as_array().unwrap().len(), 2);
    assert_eq!(
        change(&separate, "profiles").before,
        json!(verified.snapshot().profiles())
    );
    assert_eq!(change(&separate, "profiles").after, json!(profiles));
    assert!(
        rekey_policy::personal::generate_personal_draft(&trust, None, &actions, &[], 10000, NOW)
            .is_err()
    );
}

#[test]
fn generated_profile_budget_must_not_round_before_signing() {
    let (_, trust) = signer();
    let actions = [action("read-repo")];
    let initial = generate_personal_draft(
        &trust,
        None,
        &actions,
        PrincipalId::new_random(),
        10000,
        NOW,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(initial.canonical_snapshot()).unwrap();
    let mut profiles: Vec<rekey_domain::profile::AgentProfile> =
        serde_json::from_value(value["profiles"].clone()).unwrap();
    let instance = profiles[0].grants[0].instance.clone();
    profiles[0]
        .llm_limits
        .push(rekey_domain::profile::ProfileLlmLimit {
            instance,
            models: vec!["synthetic".into()],
            max_output_tokens_per_request: 1,
            max_requests_per_day: (1_u64 << 53) + 1,
            max_output_tokens_per_day: 100,
        });
    profiles[0].validate().unwrap();
    assert!(matches!(
        rekey_policy::personal::generate_personal_draft(
            &trust, None, &actions, &profiles, 10000, NOW
        ),
        Err(PolicyError::Invalid)
    ));
    profiles[0].llm_limits[0].max_requests_per_day = 100;
    profiles[0].llm_limits[0].max_output_tokens_per_day = (1_u64 << 53) + 1;
    assert!(matches!(
        rekey_policy::personal::generate_personal_draft(
            &trust, None, &actions, &profiles, 10000, NOW
        ),
        Err(PolicyError::Invalid)
    ));
}

#[test]
fn explicit_choices_sign_exact_rules_and_keep_replacement_diff() {
    let (key, trust) = signer();
    for (capability, choice, effect) in [
        ("merge-pr", ProfileRule::Allow, "permit"),
        (
            "read-repo",
            ProfileRule::RequireApproval,
            "require-approval",
        ),
    ] {
        let actions = [action(capability)];
        let original = generate_personal_draft(
            &trust,
            None,
            &actions,
            PrincipalId::new_random(),
            10000,
            NOW,
        )
        .unwrap();
        let previous = sign_draft(&original, &key, &trust);
        let before: Value = serde_json::from_slice(original.canonical_snapshot()).unwrap();
        let mut profiles = previous.snapshot().profiles().to_vec();
        profiles[0].grants[0].capabilities[0].rule = choice;
        let changed = rekey_policy::personal::generate_personal_draft(
            &trust,
            Some(&previous),
            &actions,
            &profiles,
            20000,
            NOW,
        )
        .unwrap();
        let after: Value = serde_json::from_slice(changed.canonical_snapshot()).unwrap();
        assert_eq!(after["rules"][0]["id"], before["rules"][0]["id"]);
        assert_eq!(after["rules"][0]["effect"], effect);
        assert_eq!(change(&changed, "profiles").after, json!(profiles));
        assert_eq!(change(&changed, "rules").before, before["rules"]);
        assert_eq!(change(&changed, "rules").after, after["rules"]);
        assert_eq!(
            sign_draft(&changed, &key, &trust).snapshot().profiles(),
            profiles
        );
        if effect == "require-approval" {
            assert_eq!(
                after["rules"][0]["approver"],
                json!({"kind":"local-presence"})
            );
            assert_eq!(
                after["rules"][0]["approval"],
                json!({"mode":"one-time","max_uses":1})
            );
        } else {
            assert!(after["rules"][0]["approval"].is_null());
        }
    }
}

#[test]
fn choices_conflict_only_for_the_same_principal_action_and_version() {
    let (key, trust) = signer();
    let actions = [action("read-repo")];
    let original = generate_personal_draft(
        &trust,
        None,
        &actions,
        PrincipalId::new_random(),
        10000,
        NOW,
    )
    .unwrap();
    let snapshot: Value = serde_json::from_slice(original.canonical_snapshot()).unwrap();
    let first: AgentProfile = serde_json::from_value(snapshot["profiles"][0].clone()).unwrap();
    let mut second = first.clone();
    second.name = "second".into();
    let mut profiles = vec![first, second];
    let shared = rekey_policy::personal::generate_personal_draft(
        &trust, None, &actions, &profiles, 10000, NOW,
    )
    .unwrap();
    let shared: Value = serde_json::from_slice(shared.canonical_snapshot()).unwrap();
    assert_eq!(shared["rules"].as_array().unwrap().len(), 1);
    // Identical resolved effect is still conflicting authoring input.
    for choice in [ProfileRule::Allow, ProfileRule::RequireApproval] {
        profiles[1].grants[0].capabilities[0].rule = choice;
        assert!(matches!(
            rekey_policy::personal::generate_personal_draft(
                &trust, None, &actions, &profiles, 10000, NOW
            ),
            Err(PolicyError::Invalid)
        ));
    }
    profiles[1].principal_id = PrincipalId::new_random();
    let separate = rekey_policy::personal::generate_personal_draft(
        &trust, None, &actions, &profiles, 10000, NOW,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(separate.canonical_snapshot()).unwrap();
    for (profile, effect) in profiles.iter().zip(["permit", "require-approval"]) {
        let rule = value["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["principal_id"] == json!(profile.principal_id))
            .unwrap();
        assert_eq!(rule["effect"], effect);
    }
    assert_eq!(
        sign_draft(&separate, &key, &trust).snapshot().profiles(),
        profiles
    );
}

#[test]
fn choice_replacement_does_not_merge_previous_forbid_or_approval() {
    let (key, trust) = signer();
    let actions = [action("read-repo")];
    let principal = PrincipalId::new_random();
    let original = generate_personal_draft(&trust, None, &actions, principal, 10000, NOW).unwrap();
    let mut unsigned: Value =
        serde_json::from_slice(&original.sign_bytes()[PREFIX.len()..]).unwrap();
    let mut forbid = unsigned["snapshot"]["rules"][0].clone();
    forbid["id"] = json!(rekey_domain::ids::PolicyRuleId::new_random());
    forbid["effect"] = "forbid".into();
    unsigned["snapshot"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(forbid);
    let before = unsigned["snapshot"]["rules"].clone();
    let previous = signed_value(unsigned, &key, &trust);
    let mut profiles = previous.snapshot().profiles().to_vec();
    profiles[0].grants[0].capabilities[0].rule = ProfileRule::RequireApproval;
    let draft = rekey_policy::personal::generate_personal_draft(
        &trust,
        Some(&previous),
        &actions,
        &profiles,
        20000,
        NOW,
    )
    .unwrap();
    assert_eq!(change(&draft, "rules").before, before);
    assert_eq!(change(&draft, "rules").after.as_array().unwrap().len(), 1);
    assert_eq!(
        change(&draft, "rules").after[0]["effect"],
        "require-approval"
    );
    sign_draft(&draft, &key, &trust);
}
