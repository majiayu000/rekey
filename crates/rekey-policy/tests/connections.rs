use std::collections::BTreeMap;

use rekey_domain::Timestamp;
use rekey_domain::action::{FixedMethod, HeaderName, HttpsOrigin};
use rekey_domain::connection::{
    Connection, ConnectionLlmLimits, ConnectionRule, MethodClass, MethodSelector, RuleEffect,
};
use rekey_domain::ids::{CredentialId, PolicyRuleId};
use rekey_domain::ipc::CallMeta;
use rekey_policy::connections::{decide, evaluate_connection};
use rekey_policy::presets::{builtin_preset, generic_preset};
use rekey_policy::{PolicyError, ValidatedSnapshot, parse_and_validate_snapshot};
use serde_json::json;

fn connection() -> Connection {
    let mut c = generic_preset(
        HttpsOrigin::parse("https://example.com").unwrap(),
        "authorization",
        "Bearer ",
    )
    .unwrap()
    .connection("example".into(), CredentialId::new_random());
    c.rules[0].effect = RuleEffect::Allow;
    c
}
fn snapshot(connection: &Connection) -> ValidatedSnapshot {
    parse_and_validate_snapshot(&serde_json::to_vec(&json!({"format_version":8,"version":1,"expires_at_ms":10000,"connections":[connection],"ssh_keys":[],"derived_credentials":[],"profiles":[],"bindings":[],"rules":[],"approvers":[],"workload_identities":[]})).unwrap(),Timestamp::from_unix_ms(1)).unwrap()
}
fn rule(methods: MethodSelector, path: &str, effect: RuleEffect) -> ConnectionRule {
    ConnectionRule {
        id: PolicyRuleId::new_random(),
        methods,
        path: path.into(),
        effect,
    }
}
fn class(c: MethodClass) -> MethodSelector {
    MethodSelector::Class(c)
}
fn call(
    c: &Connection,
    method: FixedMethod,
    path: &str,
) -> Result<rekey_policy::connections::ConnectionAuthorization, PolicyError> {
    evaluate_connection(
        &snapshot(c),
        &CallMeta::http(c.name.clone(), method, path.into()),
        b"",
        "unknown",
        Timestamp::from_unix_ms(2),
    )
}

#[test]
fn deny_precedence_specificity_and_approval_ties_follow_signed_rules() {
    let mut c = connection();
    c.rules = vec![
        rule(class(MethodClass::Read), "/**", RuleEffect::Allow),
        rule(
            class(MethodClass::Read),
            "/repos/*/*/issues",
            RuleEffect::Approve,
        ),
        rule(
            class(MethodClass::Read),
            "/repos/acme/rekey/issues",
            RuleEffect::Allow,
        ),
        rule(
            class(MethodClass::Read),
            "/repos/acme/rekey/private/**",
            RuleEffect::Deny,
        ),
    ];
    for (path, expected) in [
        ("/", RuleEffect::Allow),
        ("/repos/other/repo/issues", RuleEffect::Approve),
        ("/repos/acme/rekey/issues", RuleEffect::Allow),
        ("/repos/acme/rekey/private/issues", RuleEffect::Deny),
    ] {
        assert_eq!(
            call(&c, FixedMethod::Get, path).unwrap().effect,
            expected,
            "{path}"
        );
    }
    c.rules.push(rule(
        class(MethodClass::Read),
        "/repos/acme/rekey/issues",
        RuleEffect::Approve,
    ));
    assert_eq!(
        call(&c, FixedMethod::Get, "/repos/acme/rekey/issues")
            .unwrap()
            .effect,
        RuleEffect::Approve
    );
    c.rules
        .push(rule(class(MethodClass::Read), "/**", RuleEffect::Deny));
    assert_eq!(
        call(&c, FixedMethod::Get, "/repos/acme/rekey/issues")
            .unwrap()
            .effect,
        RuleEffect::Deny
    );
    c.rules.clear();
    assert_eq!(
        call(&c, FixedMethod::Get, "/").unwrap().effect,
        RuleEffect::Deny
    );
}

#[test]
fn forged_or_missing_caller_never_expands_defaults() {
    for default in [RuleEffect::Allow, RuleEffect::Approve, RuleEffect::Deny] {
        for override_effect in [RuleEffect::Allow, RuleEffect::Approve, RuleEffect::Deny] {
            let mut c = connection();
            c.rules = vec![rule(class(MethodClass::Read), "/**", default)];
            c.caller_overrides.insert(
                "codex".into(),
                vec![rule(class(MethodClass::Read), "/**", override_effect)],
            );
            assert_eq!(
                decide(
                    &c,
                    FixedMethod::Get,
                    MethodClass::Read,
                    "/repos/acme",
                    "codex"
                )
                .0,
                default.max(override_effect)
            );
            assert_eq!(
                decide(
                    &c,
                    FixedMethod::Get,
                    MethodClass::Read,
                    "/repos/acme",
                    "unknown"
                )
                .0,
                default
            );
        }
    }
    let mut c = connection();
    c.rules.clear();
    c.caller_overrides.insert(
        "codex".into(),
        vec![rule(class(MethodClass::Read), "/**", RuleEffect::Allow)],
    );
    assert_eq!(
        decide(&c, FixedMethod::Get, MethodClass::Read, "/", "codex").0,
        RuleEffect::Deny
    );
}

#[test]
fn path_injection_and_non_slug_segments_fail_before_admission() {
    let c = connection();
    for path in [
        "..", "/../a", "/a/..", "/a/.", "/a/%2f", "/a//b", "/a\\b", "/a;b", "/a?b=x", "/a#x", "/а",
        "/_a", "/a/", "/ a",
    ] {
        assert!(
            matches!(
                call(&c, FixedMethod::Get, path),
                Err(PolicyError::InvalidParameters)
            ),
            "{path}"
        );
    }
    assert!(call(&c, FixedMethod::Get, &format!("/{}", "a".repeat(101))).is_err());
    for method in ["OPTIONS", "CONNECT", "TRACE"] {
        assert!(FixedMethod::parse(method).is_err());
    }
    assert_eq!(
        call(&c, FixedMethod::Head, "/").unwrap().method_class,
        MethodClass::Read
    );
}

#[test]
fn bindings_exact_methods_and_audit_path_hide_values() {
    let mut c = connection();
    c.rules = vec![rule(
        MethodSelector::Methods(vec![FixedMethod::Post]),
        "/repos/{owner}/{repo}/issues",
        RuleEffect::Approve,
    )];
    c.bindings = BTreeMap::from([
        ("owner".into(), vec!["acme".into()]),
        ("repo".into(), vec!["*".into()]),
    ]);
    assert_eq!(
        call(&c, FixedMethod::Post, "/repos/acme/secret-project/issues")
            .unwrap()
            .normalized_path,
        "/repos/{owner}/{repo}/issues"
    );
    assert_eq!(
        call(&c, FixedMethod::Post, "/repos/other/project/issues")
            .unwrap()
            .effect,
        RuleEffect::Deny
    );
    assert_eq!(
        call(&c, FixedMethod::Put, "/repos/acme/project/issues")
            .unwrap()
            .effect,
        RuleEffect::Deny
    );
    c.bindings.remove("owner");
    assert!(c.validate().is_err());
}

#[test]
fn request_hash_binds_body_headers_query_method_policy_and_connection() {
    let c = connection();
    let s = snapshot(&c);
    let req = CallMeta::http(c.name.clone(), FixedMethod::Post, "/endpoint".into());
    let hash = |req: &CallMeta, body: &[u8]| {
        evaluate_connection(&s, req, body, "script", Timestamp::from_unix_ms(2))
            .unwrap()
            .parameters
            .canonical_hash
    };
    let original = hash(&req, b"one");
    assert_ne!(original, hash(&req, b"two"));
    let mut changed = req.clone();
    changed.method = Some(FixedMethod::Put);
    assert_ne!(original, hash(&changed, b"one"));
    changed = req.clone();
    changed.query.insert("query".into(), "value".into());
    assert_ne!(original, hash(&changed, b"one"));
    changed = req.clone();
    changed
        .headers
        .push(("content-type".into(), "application/json".into()));
    assert_ne!(original, hash(&changed, b"one"));
    changed = req.clone();
    changed.dry_run = true;
    assert_eq!(original, hash(&changed, b"one"));
    let mut policy = c.clone();
    policy.rules[1].effect = RuleEffect::Deny;
    assert_ne!(
        original,
        evaluate_connection(
            &snapshot(&policy),
            &req,
            b"one",
            "script",
            Timestamp::from_unix_ms(2)
        )
        .unwrap()
        .parameters
        .canonical_hash
    );
}

#[test]
fn query_keys_values_and_headers_are_checked_once_then_encoded() {
    let mut c = connection();
    c.query_allowlist = Some(["q".into()].into_iter().collect());
    let s = snapshot(&c);
    let mut request = CallMeta::http(c.name.clone(), FixedMethod::Get, "/search".into());
    request
        .query
        .insert("q".into(), "hello&admin=true#fragment 你好".into());
    let admitted =
        evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).unwrap();
    assert_eq!(
        admitted.target.request_target(),
        "/search?q=hello%26admin%3Dtrue%23fragment%20%E4%BD%A0%E5%A5%BD"
    );
    request.query.insert("not_declared".into(), "x".into());
    assert!(evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).is_err());
    request.query.remove("not_declared");
    request.query.insert("q".into(), "x".repeat(1025));
    assert!(evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).is_err());
    request.query.clear();
    for name in [
        "authorization",
        "x-api-key",
        "cookie",
        "host",
        "proxy-x",
        "x-unknown",
    ] {
        request.headers = vec![(name.into(), "value".into())];
        assert!(
            evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).is_err(),
            "{name}"
        );
    }
    request.headers = vec![("content-type".into(), "ok\r\nx-api-key: injected".into())];
    assert!(evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).is_err());
    request.headers = vec![
        ("Content-Type".into(), "a".into()),
        ("content-type".into(), "b".into()),
    ];
    assert!(evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).is_err());
    c.allowed_headers
        .insert(HeaderName::new("x-api-key").unwrap());
    assert!(c.validate().is_err());
}

#[test]
fn named_operations_normalize_arguments_without_action_expansion() {
    let c = builtin_preset("github-pat")
        .unwrap()
        .connection("github".into(), CredentialId::new_random());
    let s = snapshot(&c);
    let request = CallMeta::operation(
        "github.create_issue".into(),
        BTreeMap::from([
            ("owner".into(), "acme".into()),
            ("repo".into(), "rekey".into()),
            ("title".into(), "a bug".into()),
        ]),
    );
    let result =
        evaluate_connection(&s, &request, b"", "codex", Timestamp::from_unix_ms(2)).unwrap();
    assert_eq!(result.effect, RuleEffect::Approve);
    assert_eq!(result.target.path.as_str(), "/repos/acme/rekey/issues");
    assert_eq!(result.request_body, br#"{"title":"a bug"}"#);
    assert_eq!(
        call(&c, FixedMethod::Delete, "/repos/acme/rekey")
            .unwrap()
            .effect,
        RuleEffect::Deny
    );
    let mut request = request;
    request.args.insert("owner".into(), "../root".into());
    assert!(evaluate_connection(&s, &request, b"", "codex", Timestamp::from_unix_ms(2)).is_err());
}

#[test]
fn graphql_mutations_ambiguous_documents_and_parse_failure_are_writes() {
    let c = builtin_preset("github-pat")
        .unwrap()
        .connection("github".into(), CredentialId::new_random());
    let s = snapshot(&c);
    let request = CallMeta::http(c.name.clone(), FixedMethod::Post, "/graphql".into());
    for (query, expected) in [
        ("{ viewer { login } }", MethodClass::Read),
        (
            "# mutation in comment\n query Read { viewer { login } }",
            MethodClass::Read,
        ),
        (
            "mutation { deleteRepository(input:{repositoryId:\"x\"}) { clientMutationId } }",
            MethodClass::Write,
        ),
        (
            "query Read { viewer { login } } mutation Write { updateIssue(input:{id:\"x\"}) { clientMutationId } }",
            MethodClass::Write,
        ),
        (
            "query A { viewer { login } } query B { viewer { login } }",
            MethodClass::Write,
        ),
        ("not graphql", MethodClass::Write),
    ] {
        let body = serde_json::to_vec(&json!({"query":query})).unwrap();
        let result =
            evaluate_connection(&s, &request, &body, "unknown", Timestamp::from_unix_ms(2))
                .unwrap();
        assert_eq!(result.method_class, expected, "{query}");
    }
}

#[test]
fn llm_read_requires_signed_model_budget_and_output_ceiling() {
    let mut c = builtin_preset("openai")
        .unwrap()
        .connection("openai-personal".into(), CredentialId::new_random());
    assert!(c.validate().is_err());
    c.llm = Some(ConnectionLlmLimits {
        models: ["fixture-model".into()].into_iter().collect(),
        max_tokens: 128,
        max_requests_per_day: 10,
        max_output_tokens_per_day: 1024,
    });
    let s = snapshot(&c);
    let request = CallMeta::http(
        c.name.clone(),
        FixedMethod::Post,
        "/v1/chat/completions".into(),
    );
    let result = evaluate_connection(
        &s,
        &request,
        br#"{"model":"fixture-model","messages":[],"stream":true}"#,
        "codex",
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    assert_eq!(result.effect, RuleEffect::Allow);
    assert_eq!(result.generation_max_output, Some(128));
    assert!(result.streaming);
    assert!(
        String::from_utf8(result.request_body)
            .unwrap()
            .contains("\"max_completion_tokens\":128")
    );
    for body in [
        br#"{"model":"unknown"}"#.as_slice(),
        br#"{"model":"fixture-model","max_tokens":129}"#,
        br#"{"model":"fixture-model","max_tokens":128,"max_completion_tokens":129}"#,
        br#"{"model":"fixture-model","max_tokens":1,"max_tokens":128}"#,
    ] {
        assert!(
            evaluate_connection(&s, &request, body, "codex", Timestamp::from_unix_ms(2)).is_err()
        );
    }
}

#[test]
fn policy8_is_required_and_connections_are_not_unsigned_side_data() {
    let c = connection();
    let mut value = json!({"format_version":8,"version":1,"expires_at_ms":10000,"connections":[c],"ssh_keys":[],"derived_credentials":[],"profiles":[],"bindings":[],"rules":[],"approvers":[],"workload_identities":[]});
    value["format_version"] = 6.into();
    assert!(matches!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&value).unwrap(),
            Timestamp::from_unix_ms(1)
        ),
        Err(PolicyError::UnsupportedFormat)
    ));
    value["format_version"] = 8.into();
    value.as_object_mut().unwrap().remove("connections");
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&value).unwrap(),
            Timestamp::from_unix_ms(1)
        )
        .is_err()
    );
}

#[test]
fn ssh_identity_aliases_and_http_names_cannot_shadow_authorization() {
    use rekey_domain::connection::{SshHostRule, SshKeyConnection};
    let c = connection();
    let first = SshKeyConnection {
        name: "ssh-first".into(),
        credential_id: CredentialId::new_random(),
        user_public_key: data_encoding::BASE64.encode(b"synthetic public key one"),
        hosts: vec![SshHostRule {
            host: "example.com".into(),
            host_key: data_encoding::BASE64.encode(b"synthetic host key"),
            rule_id: c.rules[0].id,
            effect: RuleEffect::Allow,
        }],
        git_signing: RuleEffect::Allow,
        approver: rekey_domain::authorization::ApproverSpec::LocalPresence {},
        session_budget: rekey_domain::connection::SshSessionBudget {
            max_signatures: 100,
            max_seconds: 600,
        },
    };
    let mut second = first.clone();
    second.name = "ssh-second".into();
    second.credential_id = CredentialId::new_random();
    second.user_public_key = data_encoding::BASE64.encode(b"synthetic public key two");
    second.hosts[0].effect = RuleEffect::Deny;
    second.git_signing = RuleEffect::Deny;
    let value = |keys: Vec<SshKeyConnection>| json!({"format_version":8,"version":1,"expires_at_ms":10000,"connections":[c],"ssh_keys":keys,"derived_credentials":[],"profiles":[],"bindings":[],"rules":[],"approvers":[],"workload_identities":[]});
    let parse = |keys| {
        parse_and_validate_snapshot(
            &serde_json::to_vec(&value(keys)).unwrap(),
            Timestamp::from_unix_ms(1),
        )
    };
    assert!(parse(vec![first.clone(), second.clone()]).is_ok());
    for alias in ["public-key", "credential", "connection-name"] {
        let mut aliased = second.clone();
        match alias {
            "public-key" => aliased.user_public_key = first.user_public_key.clone(),
            "credential" => aliased.credential_id = first.credential_id,
            _ => aliased.name = c.name.clone(),
        }
        for keys in [
            vec![first.clone(), aliased.clone()],
            vec![aliased.clone(), first.clone()],
        ] {
            assert!(matches!(parse(keys), Err(PolicyError::Invalid)), "{alias}");
        }
    }
}

#[test]
fn personal_draft_signs_entire_connection_rules_and_detects_tampering() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use data_encoding::BASE64URL_NOPAD;
    use rekey_domain::authorization::PolicyTrustAlgorithm;
    use rekey_domain::ids::PolicySignerId;
    use rekey_policy::{
        PolicyVerificationKey, ValidatedPolicyTrust, parse_and_verify_policy_bundle,
    };
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
    let c = connection();
    let draft = rekey_policy::personal::generate_connection_draft(
        &trust,
        None,
        std::slice::from_ref(&c),
        10000,
        Timestamp::from_unix_ms(1),
    )
    .unwrap();
    assert!(
        draft
            .diff()
            .iter()
            .any(|change| change.field == "connections")
    );
    let unsigned = &draft.sign_bytes()[b"RKPOLICY\0\x01".len()..];
    let mut envelope: serde_json::Value = serde_json::from_slice(unsigned).unwrap();
    let signature = key.sign(&SystemRandom::new(), draft.sign_bytes()).unwrap();
    envelope["signature"] = BASE64URL_NOPAD.encode(signature.as_ref()).into();
    let bundle = parse_and_verify_policy_bundle(
        &serde_json::to_vec(&envelope).unwrap(),
        &trust,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    assert_eq!(bundle.snapshot().connections(), std::slice::from_ref(&c));
    let ssh = rekey_domain::connection::SshKeyConnection {
        name: "git".into(),
        user_public_key: data_encoding::BASE64.encode(&[1; 51]),
        credential_id: CredentialId::new_random(),
        hosts: Vec::new(),
        git_signing: RuleEffect::Allow,
        approver: rekey_domain::authorization::ApproverSpec::LocalPresence {},
        session_budget: rekey_domain::connection::SshSessionBudget {
            max_signatures: 100,
            max_seconds: 600,
        },
    };
    let ssh_draft = rekey_policy::personal::generate_connection_draft_with_ssh(
        &trust,
        Some(&bundle),
        std::slice::from_ref(&c),
        Some(std::slice::from_ref(&ssh)),
        10000,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    let mut signed: serde_json::Value =
        serde_json::from_slice(&ssh_draft.sign_bytes()[b"RKPOLICY\0\x01".len()..]).unwrap();
    signed["signature"] = BASE64URL_NOPAD
        .encode(
            key.sign(&SystemRandom::new(), ssh_draft.sign_bytes())
                .unwrap()
                .as_ref(),
        )
        .into();
    let ssh_bundle = parse_and_verify_policy_bundle(
        &serde_json::to_vec(&signed).unwrap(),
        &trust,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    let mut aliased = signed.clone();
    let mut alias = serde_json::to_value(&ssh).unwrap();
    alias["name"] = "ssh-alias".into();
    alias["git_signing"] = "deny".into();
    aliased["snapshot"]["ssh_keys"]
        .as_array_mut()
        .unwrap()
        .push(alias);
    assert!(matches!(
        parse_and_verify_policy_bundle(
            &serde_json::to_vec(&aliased).unwrap(),
            &trust,
            Timestamp::from_unix_ms(2)
        ),
        Err(PolicyError::InvalidSignature)
    ));
    aliased.as_object_mut().unwrap().remove("signature");
    let mut message = b"RKPOLICY\0\x01".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&aliased).unwrap());
    aliased["signature"] = BASE64URL_NOPAD
        .encode(key.sign(&SystemRandom::new(), &message).unwrap().as_ref())
        .into();
    assert!(matches!(
        parse_and_verify_policy_bundle(
            &serde_json::to_vec(&aliased).unwrap(),
            &trust,
            Timestamp::from_unix_ms(2)
        ),
        Err(PolicyError::Invalid)
    ));
    let preserved = rekey_policy::personal::generate_connection_draft(
        &trust,
        Some(&ssh_bundle),
        &[c],
        10000,
        Timestamp::from_unix_ms(2),
    )
    .unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_slice(preserved.canonical_snapshot()).unwrap();
    assert_eq!(snapshot["ssh_keys"], json!([ssh]));
    envelope["snapshot"]["connections"][0]["rules"][0]["effect"] = "deny".into();
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
fn signed_team_preset_binds_semantic_read_and_rejects_old_format() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use data_encoding::BASE64URL_NOPAD;
    use rekey_domain::authorization::PolicyTrustAlgorithm;
    use rekey_domain::ids::PolicySignerId;
    use rekey_policy::{PolicyVerificationKey, ValidatedPolicyTrust};
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let trust = ValidatedPolicyTrust::from_parts(
        PolicySignerId::new_random(),
        PolicyVerificationKey::from_bytes(PolicyTrustAlgorithm::Ed25519, key.public_key().as_ref())
            .unwrap(),
    );
    let mut value = json!({"format_version":2,"signer_id":trust.signer_id(),"preset":builtin_preset("github-pat").unwrap()});
    let mut message = b"RKTEMPLATE\0\x01".to_vec();
    message.extend(serde_jcs::to_vec(&value).unwrap());
    value["signature"] = BASE64URL_NOPAD.encode(key.sign(&message).as_ref()).into();
    let preset = rekey_policy::presets::parse_and_verify_preset_package(
        &serde_json::to_vec(&value).unwrap(),
        &trust,
    )
    .unwrap();
    assert_eq!(preset.name, "github-pat");
    value["preset"]["operations"][0]["path"] = "/user".into();
    assert!(matches!(
        rekey_policy::presets::parse_and_verify_preset_package(
            &serde_json::to_vec(&value).unwrap(),
            &trust
        ),
        Err(PolicyError::InvalidSignature)
    ));
    value["format_version"] = 1.into();
    assert!(matches!(
        rekey_policy::presets::parse_and_verify_preset_package(
            &serde_json::to_vec(&value).unwrap(),
            &trust
        ),
        Err(PolicyError::UnsupportedFormat)
    ));
}

#[test]
fn signed_external_preset_path_arguments_cannot_expand_semantic_read_segments() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use data_encoding::BASE64URL_NOPAD;
    use rekey_domain::authorization::PolicyTrustAlgorithm;
    use rekey_domain::connection::{PresetOperation, ReadSemantics};
    use rekey_domain::ids::PolicySignerId;
    use rekey_policy::{PolicyVerificationKey, ValidatedPolicyTrust};

    let key = Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let trust = ValidatedPolicyTrust::from_parts(
        PolicySignerId::new_random(),
        PolicyVerificationKey::from_bytes(PolicyTrustAlgorithm::Ed25519, key.public_key().as_ref())
            .unwrap(),
    );
    let mut preset = generic_preset(
        HttpsOrigin::parse("https://example.com").unwrap(),
        "authorization",
        "Bearer ",
    )
    .unwrap();
    preset.name = "team-api".into();
    preset.rules[0].effect = RuleEffect::Allow;
    preset.operations.push(PresetOperation {
        name: "team.lookup".into(),
        description: "Read one item".into(),
        method: FixedMethod::Post,
        path: "/items/{id}/lookup".into(),
        // The signed package does not need to duplicate the shared path grammar.
        parameters: json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}),
        read_semantics: Some(ReadSemantics::Fixed),
    });
    let mut package = json!({"format_version":2,"signer_id":trust.signer_id(),"preset":preset});
    let mut message = b"RKTEMPLATE\0\x01".to_vec();
    message.extend(serde_jcs::to_vec(&package).unwrap());
    package["signature"] = BASE64URL_NOPAD.encode(key.sign(&message).as_ref()).into();
    let preset = rekey_policy::presets::parse_and_verify_preset_package(
        &serde_json::to_vec(&package).unwrap(),
        &trust,
    )
    .unwrap();
    let c = preset.connection("team".into(), CredentialId::new_random());
    let s = snapshot(&c);
    let mut request = CallMeta::operation(
        "team.lookup".into(),
        BTreeMap::from([("id".into(), "a".into())]),
    );
    let allowed =
        evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)).unwrap();
    assert_eq!(allowed.target.path.as_str(), "/items/a/lookup");
    assert_eq!(allowed.method_class, MethodClass::Read);
    assert_eq!(allowed.effect, RuleEffect::Allow);
    let expanded = call(&c, FixedMethod::Post, "/items/a/b/lookup").unwrap();
    assert_eq!(expanded.method_class, MethodClass::Write);
    assert_eq!(expanded.effect, RuleEffect::Approve);

    request.args.insert("id".into(), "a/b".into());
    assert!(matches!(
        evaluate_connection(&s, &request, b"", "unknown", Timestamp::from_unix_ms(2)),
        Err(PolicyError::InvalidParameters)
    ));
}

#[test]
fn all_builtins_preserve_baseline_provider_paths_and_caller_constraints() {
    for (preset, path) in [
        ("anthropic", "/v1/messages"),
        ("openai", "/v1/responses"),
        ("glm", "/api/anthropic/v1/messages"),
        ("glm-responses", "/api/v1/responses"),
    ] {
        let p = builtin_preset(preset).unwrap();
        assert!(p.operations.iter().any(|o| o.path == path));
        let mut c = p.connection(format!("{preset}-personal"), CredentialId::new_random());
        c.llm = Some(ConnectionLlmLimits {
            models: ["fixture-model".into()].into_iter().collect(),
            max_tokens: 32,
            max_requests_per_day: 10,
            max_output_tokens_per_day: 100,
        });
        c.validate().unwrap();
        let response = evaluate_connection(
            &snapshot(&c),
            &CallMeta::http(c.name.clone(), FixedMethod::Post, path.into()),
            br#"{"model":"fixture-model"}"#,
            "unknown",
            Timestamp::from_unix_ms(2),
        )
        .unwrap();
        assert_eq!(response.effect, RuleEffect::Allow);
        assert_eq!(response.generation_max_output, Some(32));
    }
    let mut c = builtin_preset("openai")
        .unwrap()
        .connection("openai".into(), CredentialId::new_random());
    c.llm = Some(ConnectionLlmLimits {
        models: ["fixture-model".into()].into_iter().collect(),
        max_tokens: 32,
        max_requests_per_day: 10,
        max_output_tokens_per_day: 100,
    });
    let s = snapshot(&c);
    for (path, body) in [
        ("/v1/chat/completions", r#"{"model":"fixture-model","n":2}"#),
        (
            "/v1/chat/completions",
            r#"{"model":"fixture-model","max_tokens":1,"max_completion_tokens":1}"#,
        ),
        (
            "/v1/responses",
            r#"{"model":"fixture-model","background":true}"#,
        ),
        (
            "/v1/embeddings",
            r#"{"model":"fixture-model","stream":true}"#,
        ),
    ] {
        assert!(
            evaluate_connection(
                &s,
                &CallMeta::http(c.name.clone(), FixedMethod::Post, path.into()),
                body.as_bytes(),
                "unknown",
                Timestamp::from_unix_ms(2)
            )
            .is_err()
        );
    }
}

#[test]
fn github_git_fixed_endpoints_bind_repo_and_classify_upload_as_read() {
    let mut c = builtin_preset("github-git")
        .unwrap()
        .connection("github-git-dev".into(), CredentialId::new_random());
    c.bindings.insert("owner".into(), vec!["acme".into()]);
    c.bindings.insert("repo".into(), vec!["rekey.git".into()]);
    assert_eq!(c.origin.as_str(), "https://github.com");
    assert_eq!(c.auth.header().unwrap().prefix.as_str(), "Basic ");
    for (method, path, class, effect) in [
        (
            FixedMethod::Get,
            "/acme/rekey.git/info/refs",
            MethodClass::Read,
            RuleEffect::Allow,
        ),
        (
            FixedMethod::Post,
            "/acme/rekey.git/git-upload-pack",
            MethodClass::Read,
            RuleEffect::Allow,
        ),
        (
            FixedMethod::Post,
            "/acme/rekey.git/git-receive-pack",
            MethodClass::Write,
            RuleEffect::Approve,
        ),
        (
            FixedMethod::Post,
            "/other/rekey.git/git-upload-pack",
            MethodClass::Read,
            RuleEffect::Deny,
        ),
    ] {
        let result = call(&c, method, path).unwrap();
        assert_eq!((result.method_class, result.effect), (class, effect));
    }
    assert!(matches!(
        call(&c, FixedMethod::Post, "/acme/rekey.git/anything"),
        Err(PolicyError::NotConfigured)
    ));
    c.bindings.insert("owner".into(), vec!["*".into()]);
    let value = json!({"format_version":8,"version":1,"expires_at_ms":10000,"connections":[c],"ssh_keys":[],"derived_credentials":[],"profiles":[],"bindings":[],"rules":[],"approvers":[],"workload_identities":[]});
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&value).unwrap(),
            Timestamp::from_unix_ms(1)
        )
        .is_err()
    );
    let generic = connection();
    assert_eq!(
        call(
            &generic,
            FixedMethod::Post,
            "/acme/rekey.git/git-upload-pack"
        )
        .unwrap()
        .method_class,
        MethodClass::Write
    );
}
