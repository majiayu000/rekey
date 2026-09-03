use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::Timestamp;
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ActionId, PolicyRuleId, PrincipalId};
use rekey_policy::{PolicyError, parse_and_validate_snapshot};
use serde_json::{Value, json};

const NOW_SECONDS: i64 = 1_000_000;

fn ed_key() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn ed_jwk(key: &Ed25519KeyPair, kid: &str) -> Value {
    json!({
        "algorithm": "ed25519",
        "kid": kid,
        "x": BASE64URL_NOPAD.encode(key.public_key().as_ref())
    })
}

fn rsa_jwk(key: &RsaKeyPair, kid: &str) -> Value {
    json!({
        "algorithm": "rs256",
        "kid": kid,
        "n": BASE64URL_NOPAD.encode(key.public_key().modulus().big_endian_without_leading_zero()),
        "e": BASE64URL_NOPAD.encode(key.public_key().exponent().big_endian_without_leading_zero())
    })
}

fn identity(principal_id: PrincipalId, profile: Value, key: Value) -> Value {
    json!({
        "principal_id": principal_id,
        "issuer": "https://issuer.example",
        "audiences": ["rekey://test"],
        "max_token_age_ms": 900_000,
        "profile": profile,
        "keys": [key]
    })
}

fn snapshot(identities: Vec<Value>) -> (Vec<u8>, ActionVersionRef) {
    let action = ActionVersionRef {
        action_id: ActionId::new_random(),
        version: 1,
    };
    let rules = identities
        .iter()
        .map(|identity| {
            json!({
                "id": PolicyRuleId::new_random(),
                "effect": "permit",
                "principal_id": identity["principal_id"],
                "action_id": action.action_id,
                "version": action.version,
                "resource": {"type": "test.resource", "id": "one"},
                "parameters": {"kind": "any_validated"}
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "format_version": 3,
        "version": 1,
        "expires_at_ms": 2_000_000_000,
        "approvers": [],
        "workload_identities": identities,
        "bindings": [{
            "action_id": action.action_id,
            "version": action.version,
            "resource": {"type": "test.resource", "id": "one"},
            "parameter_schema_id": "test/v1",
            "parameter_schema": {}
        }],
        "rules": rules
    });
    (serde_json::to_vec(&value).unwrap(), action)
}

fn claims(subject: &str, jti: &str) -> Value {
    json!({
        "iss": "https://issuer.example",
        "sub": subject,
        "aud": ["rekey://test"],
        "jti": jti,
        "iat": NOW_SECONDS,
        "nbf": NOW_SECONDS,
        "exp": NOW_SECONDS + 600
    })
}

fn ed_token(key: &Ed25519KeyPair, kid: &str, claims: &Value) -> Vec<u8> {
    ed_token_with_header(key, &json!({"alg":"EdDSA","kid":kid,"typ":"JWT"}), claims)
}

fn ed_token_with_header(key: &Ed25519KeyPair, header: &Value, claims: &Value) -> Vec<u8> {
    let header = BASE64URL_NOPAD.encode(&serde_json::to_vec(header).unwrap());
    let body = BASE64URL_NOPAD.encode(&serde_json::to_vec(claims).unwrap());
    let input = format!("{header}.{body}");
    let signature = BASE64URL_NOPAD.encode(key.sign(input.as_bytes()).as_ref());
    format!("{input}.{signature}").into_bytes()
}

fn rsa_token(key: &RsaKeyPair, kid: &str, claims: &Value) -> Vec<u8> {
    let header = BASE64URL_NOPAD
        .encode(&serde_json::to_vec(&json!({"alg":"RS256","kid":kid,"typ":"at+jwt"})).unwrap());
    let body = BASE64URL_NOPAD.encode(&serde_json::to_vec(claims).unwrap());
    let input = format!("{header}.{body}");
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{input}.{}", BASE64URL_NOPAD.encode(&signature)).into_bytes()
}

#[test]
fn all_profiles_map_exact_subjects_and_authorized_actions() {
    let key = ed_key();
    let profiles = [
        (
            json!({"kind":"oidc","subject":"service:build"}),
            "service:build",
        ),
        (
            json!({"kind":"spiffe-jwt-svid","spiffe_id":"spiffe://issuer.example/workload/api"}),
            "spiffe://issuer.example/workload/api",
        ),
        (
            json!({"kind":"kubernetes-service-account","namespace":"prod","service_account":"api"}),
            "system:serviceaccount:prod:api",
        ),
        (
            json!({"kind":"ci-cloud","subject":"repo:owner/name:ref:refs/heads/main"}),
            "repo:owner/name:ref:refs/heads/main",
        ),
    ];
    let mut identities = Vec::new();
    let mut expected = Vec::new();
    for (profile, subject) in profiles {
        let principal = PrincipalId::new_random();
        identities.push(identity(principal, profile, ed_jwk(&key, "shared")));
        expected.push((principal, subject));
    }
    let (bytes, action) = snapshot(identities);
    let policy =
        parse_and_validate_snapshot(&bytes, Timestamp::from_unix_ms(NOW_SECONDS * 1_000)).unwrap();
    for (index, (principal, subject)) in expected.iter().enumerate() {
        let verified = policy
            .verify_workload_token(
                &ed_token(&key, "shared", &claims(subject, &format!("token-{index}"))),
                Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
            )
            .unwrap();
        assert_eq!(verified.principal_id, *principal);
        assert_eq!(verified.expires_at_ms, (NOW_SECONDS + 600) * 1_000);
        assert!(policy.workload_principal_may_request(*principal, action));
        assert!(!policy.workload_principal_may_request(
            *principal,
            ActionVersionRef {
                version: 2,
                ..action
            }
        ));
    }
}

#[test]
fn rs256_verifies_and_signature_or_selector_tampering_fails() {
    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let principal = PrincipalId::new_random();
    let (bytes, _) = snapshot(vec![identity(
        principal,
        json!({"kind":"oidc","subject":"service:rsa"}),
        rsa_jwk(&key, "rsa-1"),
    )]);
    let policy =
        parse_and_validate_snapshot(&bytes, Timestamp::from_unix_ms(NOW_SECONDS * 1_000)).unwrap();
    let valid = rsa_token(&key, "rsa-1", &claims("service:rsa", "rsa-good"));
    assert_eq!(
        policy
            .verify_workload_token(&valid, Timestamp::from_unix_ms(NOW_SECONDS * 1_000))
            .unwrap()
            .principal_id,
        principal
    );
    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() = if tampered.last() == Some(&b'A') {
        b'B'
    } else {
        b'A'
    };
    assert!(
        policy
            .verify_workload_token(&tampered, Timestamp::from_unix_ms(NOW_SECONDS * 1_000))
            .is_err()
    );
    assert!(
        policy
            .verify_workload_token(
                &rsa_token(&key, "missing", &claims("service:rsa", "rsa-kid")),
                Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
            )
            .is_err()
    );
}

#[test]
fn claims_are_exact_bounded_and_replay_digest_is_stable() {
    let key = ed_key();
    let principal = PrincipalId::new_random();
    let (bytes, _) = snapshot(vec![identity(
        principal,
        json!({"kind":"oidc","subject":"service:build"}),
        ed_jwk(&key, "ed-1"),
    )]);
    let policy =
        parse_and_validate_snapshot(&bytes, Timestamp::from_unix_ms(NOW_SECONDS * 1_000)).unwrap();
    let first = policy
        .verify_workload_token(
            &ed_token(&key, "ed-1", &claims("service:build", "same")),
            Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
        )
        .unwrap();
    let second = policy
        .verify_workload_token(
            &ed_token(&key, "ed-1", &claims("service:build", "same")),
            Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
        )
        .unwrap();
    assert_eq!(first.replay_digest, second.replay_digest);

    for bad in [
        json!({"iss":"https://wrong.example","sub":"service:build","aud":["rekey://test"],"jti":"issuer","iat":NOW_SECONDS,"exp":NOW_SECONDS+1}),
        json!({"iss":"https://issuer.example","sub":"wrong","aud":["rekey://test"],"jti":"a","iat":NOW_SECONDS,"exp":NOW_SECONDS+1}),
        json!({"iss":"https://issuer.example","sub":"service:build","aud":["other"],"jti":"b","iat":NOW_SECONDS,"exp":NOW_SECONDS+1}),
        json!({"iss":"https://issuer.example","sub":"service:build","aud":["rekey://test","rekey://test"],"jti":"c","iat":NOW_SECONDS,"exp":NOW_SECONDS+1}),
        json!({"iss":"https://issuer.example","sub":"service:build","aud":["rekey://test"],"jti":"d","iat":NOW_SECONDS+1,"exp":NOW_SECONDS+2}),
        json!({"iss":"https://issuer.example","sub":"service:build","aud":["rekey://test"],"jti":"e","iat":NOW_SECONDS-901,"exp":NOW_SECONDS+1}),
        json!({"iss":"https://issuer.example","sub":"service:build","aud":["rekey://test"],"jti":"f","iat":NOW_SECONDS-1,"nbf":NOW_SECONDS+1,"exp":NOW_SECONDS+1}),
        json!({"iss":"https://issuer.example","sub":"service:build","aud":["rekey://test"],"jti":"g","iat":NOW_SECONDS-1,"exp":NOW_SECONDS}),
    ] {
        assert!(matches!(
            policy.verify_workload_token(
                &ed_token(&key, "ed-1", &bad),
                Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
            ),
            Err(PolicyError::InvalidSignature | PolicyError::Invalid | PolicyError::Malformed)
        ));
    }
}

#[test]
fn malformed_compact_jwt_and_duplicate_claims_fail_closed() {
    let key = ed_key();
    let principal = PrincipalId::new_random();
    let (bytes, _) = snapshot(vec![identity(
        principal,
        json!({"kind":"oidc","subject":"service:build"}),
        ed_jwk(&key, "ed-1"),
    )]);
    let policy =
        parse_and_validate_snapshot(&bytes, Timestamp::from_unix_ms(NOW_SECONDS * 1_000)).unwrap();
    for bad in [
        b"".as_slice(),
        b"a.b",
        b"a.b.c.d",
        b"a=.b.c",
        &[b'a'; 16 * 1024 + 1],
    ] {
        assert!(
            policy
                .verify_workload_token(bad, Timestamp::from_unix_ms(NOW_SECONDS * 1_000))
                .is_err()
        );
    }

    let header = BASE64URL_NOPAD.encode(br#"{"alg":"EdDSA","kid":"ed-1"}"#);
    let duplicate = format!(
        "{{\"iss\":\"https://issuer.example\",\"sub\":\"service:build\",\"sub\":\"other\",\"aud\":\"rekey://test\",\"jti\":\"dup\",\"iat\":{NOW_SECONDS},\"exp\":{}}}",
        NOW_SECONDS + 1
    );
    let body = BASE64URL_NOPAD.encode(duplicate.as_bytes());
    let input = format!("{header}.{body}");
    let token = format!(
        "{input}.{}",
        BASE64URL_NOPAD.encode(key.sign(input.as_bytes()).as_ref())
    );
    assert!(
        policy
            .verify_workload_token(
                token.as_bytes(),
                Timestamp::from_unix_ms(NOW_SECONDS * 1_000)
            )
            .is_err()
    );

    for header in [
        json!({"alg":"none","kid":"ed-1","typ":"JWT"}),
        json!({"alg":"EdDSA","kid":"ed-1","typ":"application/jwt"}),
        json!({"alg":"EdDSA","kid":"ed-1","typ":null}),
        json!({"alg":"EdDSA","kid":"missing","typ":"JWT"}),
    ] {
        assert!(
            policy
                .verify_workload_token(
                    &ed_token_with_header(&key, &header, &claims("service:build", "bad-header"),),
                    Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
                )
                .is_err()
        );
    }
}

#[test]
fn verification_key_is_bound_to_the_matched_identity() {
    let first_key = ed_key();
    let second_key = ed_key();
    let first = PrincipalId::new_random();
    let second = PrincipalId::new_random();
    let (bytes, _) = snapshot(vec![
        identity(
            first,
            json!({"kind":"oidc","subject":"service:first"}),
            ed_jwk(&first_key, "first-key"),
        ),
        identity(
            second,
            json!({"kind":"oidc","subject":"service:second"}),
            ed_jwk(&second_key, "second-key"),
        ),
    ]);
    let policy =
        parse_and_validate_snapshot(&bytes, Timestamp::from_unix_ms(NOW_SECONDS * 1_000)).unwrap();

    assert_eq!(
        policy
            .verify_workload_token(
                &ed_token(
                    &second_key,
                    "second-key",
                    &claims("service:second", "right-key")
                ),
                Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
            )
            .unwrap()
            .principal_id,
        second
    );
    assert!(matches!(
        policy.verify_workload_token(
            &ed_token(
                &first_key,
                "first-key",
                &claims("service:second", "wrong-key")
            ),
            Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
        ),
        Err(PolicyError::InvalidSignature)
    ));
}

#[test]
fn non_canonical_or_invalid_spiffe_ids_are_rejected() {
    let key = ed_key();
    for spiffe_id in [
        "spiffe://ISSUER.example/workload/api",
        "spiffe://issuer.example/workload/../api",
        "spiffe://issuer.example/workload%2Fapi",
        "spiffe://issuer.example/workload//api",
        "spiffe://issuer.example/workload/api/",
        "spiffe://issuer.example/workload/api!",
    ] {
        let (bytes, _) = snapshot(vec![identity(
            PrincipalId::new_random(),
            json!({"kind":"spiffe-jwt-svid","spiffe_id":spiffe_id}),
            ed_jwk(&key, "spiffe-key"),
        )]);
        assert!(
            parse_and_validate_snapshot(&bytes, Timestamp::from_unix_ms(NOW_SECONDS * 1_000))
                .is_err(),
            "accepted invalid SPIFFE ID: {spiffe_id}"
        );
    }
}

#[test]
fn workload_catalog_rejects_unknown_fields_duplicates_and_unusable_principals() {
    let key = ed_key();
    let principal = PrincipalId::new_random();
    let valid = identity(
        principal,
        json!({"kind":"oidc","subject":"service:build"}),
        ed_jwk(&key, "ed-1"),
    );
    let (bytes, _) = snapshot(vec![valid.clone()]);
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["workload_identities"][0]["unknown"] = json!(true);
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&value).unwrap(),
            Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
        )
        .is_err()
    );

    let (duplicate, _) = snapshot(vec![valid.clone(), valid]);
    assert!(
        parse_and_validate_snapshot(&duplicate, Timestamp::from_unix_ms(NOW_SECONDS * 1_000),)
            .is_err()
    );

    let repeated_key = ed_jwk(&key, "ed-1");
    let mut duplicate_key_identity = identity(
        PrincipalId::new_random(),
        json!({"kind":"oidc","subject":"service:duplicate-key"}),
        repeated_key.clone(),
    );
    duplicate_key_identity["keys"] = json!([repeated_key.clone(), repeated_key]);
    let (duplicate_key, _) = snapshot(vec![duplicate_key_identity]);
    assert!(
        parse_and_validate_snapshot(&duplicate_key, Timestamp::from_unix_ms(NOW_SECONDS * 1_000),)
            .is_err()
    );

    let mut duplicate_material_identity = identity(
        PrincipalId::new_random(),
        json!({"kind":"oidc","subject":"service:duplicate-material"}),
        ed_jwk(&key, "ed-1"),
    );
    duplicate_material_identity["keys"] = json!([ed_jwk(&key, "ed-1"), ed_jwk(&key, "ed-2")]);
    let (duplicate_material, _) = snapshot(vec![duplicate_material_identity]);
    assert!(
        parse_and_validate_snapshot(
            &duplicate_material,
            Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
        )
        .is_err()
    );

    let orphan = identity(
        PrincipalId::new_random(),
        json!({"kind":"oidc","subject":"service:orphan"}),
        ed_jwk(&key, "ed-2"),
    );
    let (bytes, _) = snapshot(vec![orphan]);
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["rules"] = json!([]);
    assert!(
        parse_and_validate_snapshot(
            &serde_json::to_vec(&value).unwrap(),
            Timestamp::from_unix_ms(NOW_SECONDS * 1_000),
        )
        .is_err()
    );
}
