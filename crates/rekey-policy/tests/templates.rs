use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::action::{ExactPath, FixedMethod, HttpsOrigin};
use rekey_domain::authorization::PolicyTrustAlgorithm;
use rekey_domain::ids::PolicySignerId;
use rekey_policy::templates::{
    BuiltinTemplate, GITHUB_CREATE_ISSUE_SCHEMA, TEMPLATE_PACKAGE_MAX_BYTES, TEMPLATE_SIGN_PREFIX,
    TemplatePackageError, ValidatedTemplatePackage, builtin_template,
    parse_and_verify_template_package,
};
use rekey_policy::{PolicyVerificationKey, ValidatedPolicyTrust, parse_policy_trust};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn fixture() -> (Ed25519KeyPair, ValidatedPolicyTrust, Value) {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let signer_id = PolicySignerId::new_random();
    let trust = parse_policy_trust(
        &serde_json::to_vec(&json!({
            "format_version": 1,
            "signer_id": signer_id,
            "algorithm": "ed25519",
            "public_key": HEXLOWER.encode(key.public_key().as_ref()),
        }))
        .unwrap(),
    )
    .unwrap();
    let envelope = json!({
        "format_version": 1,
        "signer_id": signer_id,
        "template": {
            "template": "team-example@1",
            "display": "Team fixture",
            "credential": {"kind": "opaque-token", "inject": {"header": "authorization", "prefix": "Bearer "}},
            "origin": "https://api.example.com",
            "bindings": {"owner": {"type": "slug"}},
            "capabilities": [{"id": "create", "risk": "medium", "actions": [{
                "method": "POST", "path": "/repos/{owner}/issues", "body_schema": "schemas/create.json"
            }]}]
        },
        "schemas": {"schemas/create.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object", "required": ["title"],
            "properties": {"title": {"$ref": "#/$defs/title"}},
            "$defs": {"title": {"type": "string"}},
            "additionalProperties": false
        }}
    });
    (key, trust, envelope)
}

fn signed_value(unsigned: &Value, prefix: &[u8], key: &Ed25519KeyPair) -> Value {
    let mut message = prefix.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(unsigned).unwrap());
    let mut signed = unsigned.clone();
    signed["signature"] = BASE64URL_NOPAD.encode(key.sign(&message).as_ref()).into();
    signed
}

fn encode_signed(unsigned: &Value, key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&signed_value(unsigned, TEMPLATE_SIGN_PREFIX, key)).unwrap()
}

fn error(result: Result<ValidatedTemplatePackage, TemplatePackageError>) -> TemplatePackageError {
    match result {
        Ok(_) => panic!("unexpected validated package"),
        Err(error) => error,
    }
}

#[test]
fn signed_package_preserves_authenticated_declaration_and_offline_schema() {
    let (key, trust, unsigned) = fixture();
    let package =
        parse_and_verify_template_package(&encode_signed(&unsigned, &key), &trust).unwrap();
    assert_eq!(package.signer_id(), Some(trust.signer_id()));
    assert_eq!(package.template().definition().template, "team-example@1");
    let schema = package.schema("schemas/create.json").unwrap();
    assert!(schema.is_valid(&json!({"title": "synthetic issue"})));
    assert!(!schema.is_valid(&json!({"title": 3})));
    assert!(!schema.is_valid(&json!({"title": "x", "origin": "https://other.example"})));
    let expected = serde_jcs::to_vec(
        &json!({"template": unsigned["template"], "schemas": unsigned["schemas"]}),
    )
    .unwrap();
    assert_eq!(package.canonical_bytes(), expected);
    assert_eq!(
        package.digest(),
        <[u8; 32]>::from(Sha256::digest(&expected))
    );
    assert_ne!(
        package.canonical_bytes(),
        serde_jcs::to_vec(&unsigned).unwrap()
    );
    assert!(package.schema("schemas/missing.json").is_err());
    // Binding is available only on the declaration obtained after verification.
    assert!(
        package
            .template()
            .bind(&[("owner".to_owned(), "acme".to_owned())].into())
            .is_ok()
    );
}

#[test]
fn canonical_digest_is_stable_across_json_layout_but_changes_with_any_schema_content() {
    let (key, trust, mut unsigned) = fixture();
    let signed = signed_value(&unsigned, TEMPLATE_SIGN_PREFIX, &key);
    let compact =
        parse_and_verify_template_package(&serde_json::to_vec(&signed).unwrap(), &trust).unwrap();
    let pretty =
        parse_and_verify_template_package(&serde_json::to_vec_pretty(&signed).unwrap(), &trust)
            .unwrap();
    assert_eq!(compact.canonical_bytes(), pretty.canonical_bytes());
    assert_eq!(compact.digest(), pretty.digest());
    unsigned["schemas"]["unused.json"] = json!({"type": "integer"});
    let changed =
        parse_and_verify_template_package(&encode_signed(&unsigned, &key), &trust).unwrap();
    assert_ne!(compact.digest(), changed.digest());
    assert!(changed.schema("unused.json").unwrap().is_valid(&json!(7)));
}

#[test]
fn signature_authenticates_template_schemas_and_signer_with_distinct_domain() {
    let (key, trust, unsigned) = fixture();
    let signed = signed_value(&unsigned, TEMPLATE_SIGN_PREFIX, &key);
    // Independent valid-shape changes must fail signature validation.
    for (path, value) in [
        ("/template/origin", json!("https://other.example.com")),
        ("/schemas/schemas~1create.json/type", json!("string")),
        (
            "/template/capabilities/0/actions/0/path",
            json!("/other/{owner}"),
        ),
        ("/signer_id", json!(PolicySignerId::new_random())),
    ] {
        let mut tampered = signed.clone();
        *tampered.pointer_mut(path).unwrap() = value;
        assert_eq!(
            error(parse_and_verify_template_package(
                &serde_json::to_vec(&tampered).unwrap(),
                &trust
            )),
            TemplatePackageError::InvalidSignature
        );
    }
    for prefix in [
        b"RKPOLICY\0\x01".as_slice(),
        b"RKCHALLENGE\0\x02",
        b"RKGRANT\0\x01",
        b"",
    ] {
        let wrong_domain = signed_value(&unsigned, prefix, &key);
        assert_eq!(
            error(parse_and_verify_template_package(
                &serde_json::to_vec(&wrong_domain).unwrap(),
                &trust
            )),
            TemplatePackageError::InvalidSignature
        );
    }
    let (_, other_trust, _) = fixture();
    let wrong_key = ValidatedPolicyTrust::from_parts(trust.signer_id(), other_trust.key().clone());
    assert_eq!(
        error(parse_and_verify_template_package(
            &encode_signed(&unsigned, &key),
            &wrong_key
        )),
        TemplatePackageError::InvalidSignature
    );
}

#[test]
fn personal_p256_policy_key_cannot_authenticate_a_team_template_package() {
    let (_, trust, mut unsigned) = fixture();
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
    let personal_trust = ValidatedPolicyTrust::from_parts(
        trust.signer_id(),
        PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::SecureEnclaveP256,
            key.public_key().as_ref(),
        )
        .unwrap(),
    );
    let mut message = TEMPLATE_SIGN_PREFIX.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
    unsigned["signature"] = BASE64URL_NOPAD
        .encode(key.sign(&SystemRandom::new(), &message).unwrap().as_ref())
        .into();
    assert_eq!(
        error(parse_and_verify_template_package(
            &serde_json::to_vec(&unsigned).unwrap(),
            &personal_trust,
        )),
        TemplatePackageError::InvalidSignature
    );
}

#[test]
fn signature_encoding_is_exact_unpadded_base64url() {
    let (key, trust, unsigned) = fixture();
    let signed = signed_value(&unsigned, TEMPLATE_SIGN_PREFIX, &key);
    let original = signed["signature"].as_str().unwrap();
    for signature in [
        format!("{original}="),
        format!(" {original}"),
        "A".repeat(86),
        "+".repeat(86),
        BASE64URL_NOPAD.encode(&[0u8; 63]),
        "".to_owned(),
    ] {
        let mut invalid = signed.clone();
        invalid["signature"] = signature.into();
        assert_eq!(
            error(parse_and_verify_template_package(
                &serde_json::to_vec(&invalid).unwrap(),
                &trust
            )),
            TemplatePackageError::InvalidSignature
        );
    }
}

#[test]
fn package_envelope_is_closed_bounded_and_duplicate_free_at_every_level() {
    let (key, trust, unsigned) = fixture();
    let signed = signed_value(&unsigned, TEMPLATE_SIGN_PREFIX, &key);
    let raw = serde_json::to_string(&signed).unwrap();
    for duplicate in [
        raw.replacen(
            "\"format_version\":1",
            "\"format_version\":1,\"format_version\":1",
            1,
        ),
        raw.replacen(
            "\"origin\":",
            "\"origin\":\"https://elsewhere.example\",\"origin\":",
            1,
        ),
        raw.replacen(
            "\"schemas/create.json\":",
            "\"schemas/create.json\":{},\"schemas/create.json\":",
            1,
        ),
        raw.replacen(
            "\"additionalProperties\":false",
            "\"additionalProperties\":true,\"additionalProperties\":false",
            1,
        ),
    ] {
        assert_eq!(
            error(parse_and_verify_template_package(
                duplicate.as_bytes(),
                &trust
            )),
            TemplatePackageError::Malformed
        );
    }
    for field in [
        "format_version",
        "signer_id",
        "template",
        "schemas",
        "signature",
    ] {
        let mut missing = signed.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            error(parse_and_verify_template_package(
                &serde_json::to_vec(&missing).unwrap(),
                &trust
            )),
            TemplatePackageError::Malformed
        );
    }
    let mut unknown = signed.clone();
    unknown["download"] = true.into();
    assert_eq!(
        error(parse_and_verify_template_package(
            &serde_json::to_vec(&unknown).unwrap(),
            &trust
        )),
        TemplatePackageError::Malformed
    );
    let mut wrong_version = unsigned.clone();
    wrong_version["format_version"] = 2.into();
    assert_eq!(
        error(parse_and_verify_template_package(
            &encode_signed(&wrong_version, &key),
            &trust
        )),
        TemplatePackageError::UnsupportedFormat
    );
    let mut padded = raw.into_bytes();
    padded.resize(TEMPLATE_PACKAGE_MAX_BYTES, b' ');
    assert!(parse_and_verify_template_package(&padded, &trust).is_ok());
    padded.push(b' ');
    assert_eq!(
        error(parse_and_verify_template_package(&padded, &trust)),
        TemplatePackageError::TooLarge
    );
}

#[test]
fn signed_invalid_declaration_cannot_be_bound_or_installed() {
    let (key, trust, unsigned) = fixture();
    for (path, value) in [
        ("/template/origin", json!("http://api.example.com")),
        (
            "/template/capabilities/0/actions/0/path",
            json!("/repos/{undeclared}"),
        ),
        ("/template/credential/inject/header", json!("host")),
    ] {
        let mut invalid = unsigned.clone();
        *invalid.pointer_mut(path).unwrap() = value;
        assert_eq!(
            error(parse_and_verify_template_package(
                &encode_signed(&invalid, &key),
                &trust
            )),
            TemplatePackageError::InvalidTemplate
        );
    }
    let mut unknown = unsigned.clone();
    unknown["template"]["unknown"] = true.into();
    assert_eq!(
        error(parse_and_verify_template_package(
            &encode_signed(&unknown, &key),
            &trust
        )),
        TemplatePackageError::InvalidTemplate
    );
}

#[test]
fn body_schema_references_are_exact_local_resources_and_never_paths_to_load() {
    let (key, trust, unsigned) = fixture();
    for reference in [
        "schemas/missing.json",
        "https://example.com/schema.json",
        "file:///tmp/schema.json",
        "/tmp/schema.json",
        "../schema.json",
        "schemas/%2e%2e/schema.json",
        "schemas/create.json#x",
    ] {
        let mut invalid = unsigned.clone();
        invalid["template"]["capabilities"][0]["actions"][0]["body_schema"] = reference.into();
        if reference != "schemas/missing.json" {
            invalid["schemas"][reference] = json!({"type": "object"});
        }
        assert_eq!(
            error(parse_and_verify_template_package(
                &encode_signed(&invalid, &key),
                &trust
            )),
            TemplatePackageError::InvalidSchema
        );
    }
    let mut missing = unsigned.clone();
    missing["schemas"] = json!({});
    assert_eq!(
        error(parse_and_verify_template_package(
            &encode_signed(&missing, &key),
            &trust
        )),
        TemplatePackageError::InvalidSchema
    );
}

#[test]
fn all_schema_reference_keywords_are_offline_even_when_nested_or_unused() {
    let (key, trust, unsigned) = fixture();
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        for reference in [
            "https://example.invalid/schema",
            "http://127.0.0.1:9/schema",
            "file:///synthetic-private-schema",
            "other.json",
            "//example.invalid/schema",
        ] {
            let mut invalid = unsigned.clone();
            invalid["schemas"]["unused.json"] = json!({"$defs": {"nested": {keyword: reference}}});
            assert_eq!(
                error(parse_and_verify_template_package(
                    &encode_signed(&invalid, &key),
                    &trust
                )),
                TemplatePackageError::InvalidSchema,
                "{keyword}: {reference}"
            );
        }
    }
    for schema in [
        json!({"$ref": "#/$defs/missing"}),
        json!({"type": "not-a-json-type"}),
        json!({"required": "title"}),
        json!(7),
        json!({"$schema": "https://example.invalid/meta-schema"}),
        json!({"$schema": "http://json-schema.org/draft-07/schema#"}),
    ] {
        let mut invalid = unsigned.clone();
        invalid["schemas"]["schemas/create.json"] = schema;
        assert_eq!(
            error(parse_and_verify_template_package(
                &encode_signed(&invalid, &key),
                &trust
            )),
            TemplatePackageError::InvalidSchema
        );
    }
}

#[test]
fn builtins_have_closed_provenance_and_github_schema_is_real_content() {
    for builtin in [
        BuiltinTemplate::Anthropic,
        BuiltinTemplate::OpenAi,
        BuiltinTemplate::GitHubPat,
        BuiltinTemplate::GenericBearer {
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            actions: vec![(FixedMethod::Get, ExactPath::parse("/status").unwrap())],
        },
    ] {
        let package = builtin_template(builtin).unwrap();
        assert!(package.signer_id().is_none());
        assert!(!package.canonical_bytes().is_empty());
    }
    let github = builtin_template(BuiltinTemplate::GitHubPat).unwrap();
    let schema = github.schema(GITHUB_CREATE_ISSUE_SCHEMA).unwrap();
    for valid in [
        json!({"title": "synthetic issue"}),
        json!({"title": 4, "body": "details"}),
    ] {
        assert!(schema.is_valid(&valid));
    }
    for invalid in [
        json!({}),
        json!({"title": false}),
        json!({"title": "x", "body": 2}),
        json!({"title": "x", "unknown": "y"}),
    ] {
        assert!(!schema.is_valid(&invalid));
    }
    let canonical: Value = serde_json::from_slice(github.canonical_bytes()).unwrap();
    assert_eq!(
        canonical["schemas"][GITHUB_CREATE_ISSUE_SCHEMA],
        *schema.definition()
    );
    assert!(
        builtin_template(BuiltinTemplate::GenericBearer {
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            actions: vec![]
        })
        .is_err()
    );
}

#[test]
fn imported_builtin_reference_binds_resolved_content_and_explicit_signed_override() {
    let (key, trust, mut unsigned) = fixture();
    unsigned["template"]["capabilities"][0]["actions"][0]["body_schema"] =
        GITHUB_CREATE_ISSUE_SCHEMA.into();
    unsigned["schemas"] = json!({});
    let resolved =
        parse_and_verify_template_package(&encode_signed(&unsigned, &key), &trust).unwrap();
    assert!(
        !resolved
            .schema(GITHUB_CREATE_ISSUE_SCHEMA)
            .unwrap()
            .is_valid(&json!({}))
    );
    let canonical: Value = serde_json::from_slice(resolved.canonical_bytes()).unwrap();
    assert!(canonical["schemas"][GITHUB_CREATE_ISSUE_SCHEMA].is_object());
    // An installed signer may explicitly replace a resource. It is then covered
    // by that signature and changes the source digest; no ambient file is read.
    unsigned["schemas"][GITHUB_CREATE_ISSUE_SCHEMA] = json!({"type": "object"});
    let explicit =
        parse_and_verify_template_package(&encode_signed(&unsigned, &key), &trust).unwrap();
    assert!(
        explicit
            .schema(GITHUB_CREATE_ISSUE_SCHEMA)
            .unwrap()
            .is_valid(&json!({}))
    );
    assert_ne!(resolved.digest(), explicit.digest());
}
