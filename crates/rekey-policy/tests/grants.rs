use std::collections::BTreeMap;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rekey_domain::Timestamp;
use rekey_domain::authorization::PolicyTrustAlgorithm;
use rekey_domain::connection::{DerivedCredentialConnection, DerivedCredentialTarget, RuleEffect};
use rekey_domain::ids::{CredentialId, PolicySignerId};
use rekey_policy::personal::{generate_connection_draft, generate_connection_draft_with_grants};
use rekey_policy::{
    PolicyError, PolicyVerificationKey, ValidatedPolicyTrust, parse_and_validate_snapshot,
    parse_and_verify_policy_bundle,
};
use serde_json::{Value, json};

fn aws() -> DerivedCredentialConnection {
    DerivedCredentialConnection {
        name: "aws-dev".into(),
        credential_id: CredentialId::new_random(),
        effect: RuleEffect::Approve,
        max_ttl_seconds: 900,
        target: DerivedCredentialTarget::AwsAssumeRole {
            role_arn: "arn:aws:iam::123456789012:role/dev".into(),
            region: "us-east-1".into(),
            session_policy: json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::test/*"}]}),
        },
    }
}
fn snapshot(grants: &[DerivedCredentialConnection]) -> Value {
    json!({"format_version":8,"version":1,"expires_at_ms":10000,"connections":[],"ssh_keys":[],"derived_credentials":grants,"profiles":[],"bindings":[],"rules":[],"approvers":[],"workload_identities":[]})
}
fn parse(value: &Value) -> Result<rekey_policy::ValidatedSnapshot, PolicyError> {
    parse_and_validate_snapshot(
        &serde_json::to_vec(value).unwrap(),
        Timestamp::from_unix_ms(1),
    )
}

#[test]
fn derived_grants_are_required_and_names_are_unique_across_protocols() {
    let grant = aws();
    assert_eq!(
        parse(&snapshot(std::slice::from_ref(&grant)))
            .unwrap()
            .derived_credential("aws-dev")
            .unwrap(),
        &grant
    );
    let mut missing = snapshot(&[]);
    missing
        .as_object_mut()
        .unwrap()
        .remove("derived_credentials");
    assert!(parse(&missing).is_err());
    let mut deny_alias = grant.clone();
    deny_alias.effect = RuleEffect::Deny;
    for grants in [
        vec![grant.clone(), deny_alias.clone()],
        vec![deny_alias, grant.clone()],
    ] {
        assert!(matches!(
            parse(&snapshot(&grants)),
            Err(PolicyError::Invalid)
        ));
    }
    let c = rekey_policy::presets::generic_preset(
        rekey_domain::action::HttpsOrigin::parse("https://example.com").unwrap(),
        "authorization",
        "Bearer ",
    )
    .unwrap()
    .connection(grant.name.clone(), CredentialId::new_random());
    let mut http_collision = snapshot(std::slice::from_ref(&grant));
    http_collision["connections"] = json!([c]);
    assert!(matches!(parse(&http_collision), Err(PolicyError::Invalid)));
    let mut ssh_collision = snapshot(std::slice::from_ref(&grant));
    ssh_collision["ssh_keys"] = json!([{"name":grant.name,"credential_id":CredentialId::new_random(),"user_public_key":data_encoding::BASE64.encode(b"synthetic public key"),"hosts":[],"git_signing":"deny","approver":{"kind":"local-presence"},"session_budget":{"max_signatures":100,"max_seconds":600}}]);
    assert!(matches!(parse(&ssh_collision), Err(PolicyError::Invalid)));
}

#[test]
fn provider_lifetimes_and_target_permission_ceilings_cannot_be_omitted() {
    let mut grant = aws();
    for ttl in [0, 899, 3601, u32::MAX] {
        grant.max_ttl_seconds = ttl;
        assert!(grant.validate().is_err());
    }
    grant.max_ttl_seconds = 3600;
    assert!(grant.validate().is_ok());
    grant.target = DerivedCredentialTarget::KubernetesEks {
        cluster_id: "test-cluster".into(),
        region: "us-east-1".into(),
    };
    assert!(grant.validate().is_err());
    grant.max_ttl_seconds = 900;
    assert!(grant.validate().is_ok());
    grant.target = DerivedCredentialTarget::GitHubApp {
        installation_id: 1,
        repository_ids: vec![2],
        permissions: BTreeMap::from([("issues".into(), "read".into())]),
    };
    assert!(grant.validate().is_err());
    grant.max_ttl_seconds = 3600;
    assert!(grant.validate().is_ok());
    if let DerivedCredentialTarget::GitHubApp { repository_ids, .. } = &mut grant.target {
        repository_ids.push(2);
    }
    assert!(grant.validate().is_err());
    let mut unsafe_integer = snapshot(&[grant]);
    unsafe_integer["derived_credentials"][0]["target"]["installation_id"] =
        json!(9_007_199_254_740_993u64);
    assert!(parse(&unsafe_integer).is_err());
}

#[test]
fn draft_preserves_omitted_grants_revokes_explicit_empty_and_binds_signed_targets() {
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
    let grant = aws();
    let draft = generate_connection_draft_with_grants(
        &trust,
        None,
        &[],
        None,
        Some(std::slice::from_ref(&grant)),
        10000,
        Timestamp::from_unix_ms(1),
    )
    .unwrap();
    assert!(
        draft
            .diff()
            .iter()
            .any(|diff| diff.field == "derived_credentials")
    );
    let mut envelope: Value =
        serde_json::from_slice(&draft.sign_bytes()[b"RKPOLICY\0\x01".len()..]).unwrap();
    envelope["signature"] = data_encoding::BASE64URL_NOPAD
        .encode(
            key.sign(&SystemRandom::new(), draft.sign_bytes())
                .unwrap()
                .as_ref(),
        )
        .into();
    let bundle = parse_and_verify_policy_bundle(
        &serde_json::to_vec(&envelope).unwrap(),
        &trust,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    assert_eq!(
        bundle.snapshot().derived_credentials(),
        std::slice::from_ref(&grant)
    );
    let preserved = generate_connection_draft(
        &trust,
        Some(&bundle),
        &[],
        10000,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(preserved.canonical_snapshot()).unwrap()["derived_credentials"],
        json!([grant])
    );
    let revoked = generate_connection_draft_with_grants(
        &trust,
        Some(&bundle),
        &[],
        None,
        Some(&[]),
        10000,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(revoked.canonical_snapshot()).unwrap()["derived_credentials"],
        json!([])
    );
    envelope["snapshot"]["derived_credentials"][0]["target"]["role_arn"] =
        "arn:aws:iam::123456789012:role/admin".into();
    assert!(matches!(
        parse_and_verify_policy_bundle(
            &serde_json::to_vec(&envelope).unwrap(),
            &trust,
            Timestamp::from_unix_ms(2)
        ),
        Err(PolicyError::InvalidSignature)
    ));
}

#[test]
fn oauth_presets_bind_provider_origin_and_operation_scope_ceiling() {
    use rekey_domain::connection::OAuthBinding;
    use rekey_policy::presets::{builtin_preset, oauth_provider, oauth_required_scopes};
    for name in [
        "google-drive",
        "google-gmail",
        "google-calendar",
        "github-oauth",
        "slack",
        "notion",
    ] {
        let preset = builtin_preset(name).unwrap();
        let mut c = preset.connection(format!("test-{name}"), CredentialId::new_random());
        c.oauth = Some(OAuthBinding {
            provider: oauth_provider(name).unwrap(),
            client_id: "synthetic-public-client".into(),
            scopes: preset
                .operations
                .iter()
                .flat_map(|op| oauth_required_scopes(name, &op.name).unwrap())
                .collect(),
        });
        let mut value = snapshot(&[]);
        value["connections"] = json!([c]);
        assert!(parse(&value).is_ok(), "{name}");
        let mut bad_origin = value.clone();
        bad_origin["connections"][0]["origin"] = "https://attacker.example".into();
        assert!(
            matches!(parse(&bad_origin), Err(PolicyError::Invalid)),
            "{name}"
        );
        let mut injected_scope = value.clone();
        injected_scope["connections"][0]["oauth"]["scopes"] = json!(["unrecognized_full_admin"]);
        assert!(
            matches!(parse(&injected_scope), Err(PolicyError::Invalid)),
            "{name}"
        );
        let mut changed_semantics = value;
        changed_semantics["connections"][0]["operations"][0]["path"] = "/admin".into();
        assert!(
            matches!(parse(&changed_semantics), Err(PolicyError::Invalid)),
            "{name}"
        );
    }
}

#[test]
fn oauth_generic_calls_cannot_escape_finite_operations_or_read_only_scopes() {
    use rekey_domain::action::FixedMethod;
    use rekey_domain::connection::OAuthBinding;
    use rekey_domain::ipc::CallMeta;
    use rekey_policy::connections::evaluate_connection;
    use rekey_policy::presets::{builtin_preset, oauth_required_scopes};
    let mut c = builtin_preset("notion")
        .unwrap()
        .connection("notion-read".into(), CredentialId::new_random());
    c.oauth = Some(OAuthBinding {
        provider: rekey_domain::connection::OAuthProvider::Notion,
        client_id: "synthetic-client".into(),
        scopes: oauth_required_scopes("notion", "notion.search").unwrap(),
    });
    let mut value = snapshot(&[]);
    value["connections"] = json!([c]);
    let validated = parse(&value).unwrap();
    let search = CallMeta::http("notion-read".into(), FixedMethod::Post, "/v1/search".into());
    let allowed = evaluate_connection(
        &validated,
        &search,
        b"{}",
        "unknown",
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    assert_eq!(allowed.effect, RuleEffect::Allow);
    assert_eq!(
        allowed.method_class,
        rekey_domain::connection::MethodClass::Read
    );
    let write = CallMeta::http("notion-read".into(), FixedMethod::Post, "/v1/pages".into());
    assert!(matches!(
        evaluate_connection(
            &validated,
            &write,
            b"{}",
            "unknown",
            Timestamp::from_unix_ms(2)
        ),
        Err(PolicyError::NotConfigured)
    ));
    let unknown = CallMeta::http("notion-read".into(), FixedMethod::Get, "/v1/users".into());
    assert!(matches!(
        evaluate_connection(
            &validated,
            &unknown,
            b"",
            "unknown",
            Timestamp::from_unix_ms(2)
        ),
        Err(PolicyError::NotConfigured)
    ));
    let delete = CallMeta::http(
        "notion-read".into(),
        FixedMethod::Delete,
        "/v1/pages/page1".into(),
    );
    assert!(matches!(
        evaluate_connection(
            &validated,
            &delete,
            b"",
            "unknown",
            Timestamp::from_unix_ms(2)
        ),
        Err(PolicyError::NotConfigured)
    ));
}
