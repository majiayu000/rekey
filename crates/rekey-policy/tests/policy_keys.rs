//! Software fixtures only: these exercise encoding and verification, not SE provenance.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::Timestamp;
use rekey_domain::authorization::PolicyTrustAlgorithm;
use rekey_domain::ids::{ApproverId, PolicySignerId};
use rekey_policy::{
    PolicyError, PolicyVerificationKey, ValidatedPolicyTrust, parse_and_verify_policy_bundle,
    parse_and_verify_policy_bundle_for_load, parse_policy_trust, policy_trust_sha256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PREFIX: &[u8] = b"RKPOLICY\0\x01";

fn p256_document() -> aws_lc_rs::pkcs8::Document {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new()).unwrap()
}

fn fixture() -> (EcdsaKeyPair, ValidatedPolicyTrust, Value) {
    let document = p256_document();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
    let trust = ValidatedPolicyTrust::from_parts(
        PolicySignerId::new_random(),
        PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::SecureEnclaveP256,
            key.public_key().as_ref(),
        )
        .unwrap(),
    );
    let unsigned = json!({
        "format_version": 1, "signer_id": trust.signer_id(),
        "snapshot": {"format_version": 7, "connections": [], "ssh_keys": [], "derived_credentials": [], "profiles": [], "version": 1, "expires_at_ms": 10_000,
            "approvers": [], "workload_identities": [], "bindings": [], "rules": []}
    });
    (key, trust, unsigned)
}

fn payload(unsigned: &Value, prefix: &[u8]) -> Vec<u8> {
    let mut message = prefix.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(unsigned).unwrap());
    message
}

fn attach(unsigned: &Value, signature: &[u8]) -> Vec<u8> {
    let mut signed = unsigned.clone();
    signed["signature"] = BASE64URL_NOPAD.encode(signature).into();
    serde_json::to_vec(&signed).unwrap()
}

fn sign(unsigned: &Value, key: &EcdsaKeyPair) -> Vec<u8> {
    let signature = key
        .sign(&SystemRandom::new(), &payload(unsigned, PREFIX))
        .unwrap();
    attach(unsigned, signature.as_ref())
}

fn invalid_signature(bytes: &[u8], trust: &ValidatedPolicyTrust) {
    assert!(matches!(
        parse_and_verify_policy_bundle(bytes, trust, Timestamp::from_unix_ms(1)),
        Err(PolicyError::InvalidSignature)
    ));
}

#[test]
fn verification_keys_reject_wrong_algorithm_sizes_compressed_and_invalid_points() {
    let (key, trust, _) = fixture();
    assert_eq!(
        trust.key().algorithm(),
        PolicyTrustAlgorithm::SecureEnclaveP256
    );
    assert_eq!(trust.public_key(), key.public_key().as_ref());
    let bytes = trust.public_key();
    let mut compressed = vec![2 | (bytes[64] & 1)];
    compressed.extend_from_slice(&bytes[1..33]);
    let mut wrong_prefix = bytes.to_vec();
    wrong_prefix[0] = 6;
    let mut off_curve = vec![0; 65];
    off_curve[0] = 4;
    let mut out_of_field = vec![0xff; 65];
    out_of_field[0] = 4;
    for invalid in [
        vec![],
        vec![0],
        bytes[..64].to_vec(),
        compressed,
        wrong_prefix,
        off_curve,
        out_of_field,
    ] {
        assert!(matches!(
            PolicyVerificationKey::from_bytes(PolicyTrustAlgorithm::SecureEnclaveP256, &invalid),
            Err(PolicyError::Invalid)
        ));
    }
    assert!(PolicyVerificationKey::from_bytes(PolicyTrustAlgorithm::Ed25519, bytes).is_err());
    for invalid in [
        vec![],
        vec![1; 31],
        vec![1; 33],
        vec![0; 32],
        vec![0xff; 32],
    ] {
        assert!(
            PolicyVerificationKey::from_bytes(PolicyTrustAlgorithm::Ed25519, &invalid).is_err()
        );
    }
}

#[test]
fn both_trust_algorithms_roundtrip_canonically_and_bind_the_digest() {
    let (_, personal, _) = fixture();
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let team = ValidatedPolicyTrust::from_parts(
        personal.signer_id(),
        PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::Ed25519,
            signer.public_key().as_ref(),
        )
        .unwrap(),
    );
    for (trust, algorithm) in [(&personal, "secure-enclave-p256"), (&team, "ed25519")] {
        let value = json!({"format_version":1,"signer_id":trust.signer_id(),
            "algorithm":algorithm,"public_key":HEXLOWER.encode(trust.public_key())});
        let parsed = parse_policy_trust(&serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert_eq!(parsed.key(), trust.key());
        assert_eq!(parsed.canonical_bytes(), serde_jcs::to_vec(&value).unwrap());
        assert_eq!(
            policy_trust_sha256(trust.signer_id(), trust.key()).unwrap(),
            <[u8; 32]>::from(Sha256::digest(parsed.canonical_bytes()))
        );
        assert_ne!(
            policy_trust_sha256(trust.signer_id(), trust.key()).unwrap(),
            policy_trust_sha256(PolicySignerId::new_random(), trust.key()).unwrap()
        );
        for (field, replacement) in [
            (
                "public_key",
                json!(HEXLOWER.encode(trust.public_key()).to_uppercase()),
            ),
            (
                "public_key",
                json!(format!(" {}", HEXLOWER.encode(trust.public_key()))),
            ),
            ("public_key", json!("")),
            ("algorithm", json!("p256")),
            (
                "algorithm",
                json!(if algorithm == "ed25519" {
                    "secure-enclave-p256"
                } else {
                    "ed25519"
                }),
            ),
            ("unknown", json!(true)),
        ] {
            let mut malformed = value.clone();
            malformed[field] = replacement;
            assert!(parse_policy_trust(&serde_json::to_vec(&malformed).unwrap()).is_err());
        }
        let duplicate = format!(
            "{{\"algorithm\":\"{algorithm}\",{}",
            &serde_json::to_string(&value).unwrap()[1..]
        );
        assert!(matches!(
            parse_policy_trust(duplicate.as_bytes()),
            Err(PolicyError::Malformed)
        ));
    }
    assert_ne!(
        policy_trust_sha256(personal.signer_id(), personal.key()).unwrap(),
        policy_trust_sha256(team.signer_id(), team.key()).unwrap()
    );
    let (_, other, _) = fixture();
    assert_ne!(
        policy_trust_sha256(personal.signer_id(), personal.key()).unwrap(),
        policy_trust_sha256(personal.signer_id(), other.key()).unwrap()
    );
}

#[test]
fn p256_der_policy_verifies_canonical_json_and_keeps_activation_vs_load_expiry() {
    let (key, trust, unsigned) = fixture();
    let signed = sign(&unsigned, &key);
    let original =
        parse_and_verify_policy_bundle(&signed, &trust, Timestamp::from_unix_ms(1)).unwrap();
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&signed).unwrap()).unwrap();
    let reformatted =
        parse_and_verify_policy_bundle(&pretty, &trust, Timestamp::from_unix_ms(1)).unwrap();
    assert_eq!(original.bundle_digest(), reformatted.bundle_digest());
    assert_eq!(original.policy_digest(), reformatted.policy_digest());
    assert!(matches!(
        parse_and_verify_policy_bundle(&signed, &trust, Timestamp::from_unix_ms(10_000)),
        Err(PolicyError::Expired)
    ));
    assert_eq!(
        original.bundle_digest(),
        parse_and_verify_policy_bundle_for_load(&signed, &trust)
            .unwrap()
            .bundle_digest()
    );
}

#[test]
fn p256_signature_binds_envelope_snapshot_and_trust_key() {
    let (key, trust, unsigned) = fixture();
    let signed = sign(&unsigned, &key);
    let (_, other, _) = fixture();
    let other_key = ValidatedPolicyTrust::from_parts(trust.signer_id(), other.key().clone());
    invalid_signature(&signed, &other_key);
    let original: Value = serde_json::from_slice(&signed).unwrap();
    for (path, value) in [
        ("/signer_id", json!(PolicySignerId::new_random())),
        ("/snapshot/version", json!(2)),
        ("/snapshot/expires_at_ms", json!(9_000)),
    ] {
        let mut tampered = original.clone();
        *tampered.pointer_mut(path).unwrap() = value;
        invalid_signature(&serde_json::to_vec(&tampered).unwrap(), &trust);
    }
}

#[test]
fn p256_rejects_raw_rs_malformed_der_and_noncanonical_base64() {
    let document = p256_document();
    let der_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
    let fixed_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref()).unwrap();
    let (_, _, mut unsigned) = fixture();
    let trust = ValidatedPolicyTrust::from_parts(
        PolicySignerId::new_random(),
        PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::SecureEnclaveP256,
            der_key.public_key().as_ref(),
        )
        .unwrap(),
    );
    unsigned["signer_id"] = json!(trust.signer_id());
    let message = payload(&unsigned, PREFIX);
    let der = der_key.sign(&SystemRandom::new(), &message).unwrap();
    let raw = fixed_key.sign(&SystemRandom::new(), &message).unwrap();
    assert_eq!(raw.as_ref().len(), 64);
    let mut trailing = der.as_ref().to_vec();
    trailing.push(0);
    for invalid in [
        raw.as_ref(),
        &trailing,
        &der.as_ref()[..der.as_ref().len() - 1],
        &[0x30, 0],
        &[0; 64],
        &[],
    ] {
        invalid_signature(&attach(&unsigned, invalid), &trust);
    }
    let encoded = BASE64URL_NOPAD.encode(der.as_ref());
    for signature in [
        format!("{encoded}="),
        format!(" {encoded}"),
        "+/==".into(),
        "".into(),
    ] {
        let mut malformed = unsigned.clone();
        malformed["signature"] = signature.into();
        invalid_signature(&serde_json::to_vec(&malformed).unwrap(), &trust);
    }
}

#[test]
fn p256_rejects_wrong_domain_and_double_hash_signatures() {
    let (key, trust, unsigned) = fixture();
    for prefix in [
        b"".as_slice(),
        b"RKAPPROVAL\0\x01",
        b"RKTEMPLATE\0\x01",
        b"RKPOLICY\0\x02",
    ] {
        let wrong = key
            .sign(&SystemRandom::new(), &payload(&unsigned, prefix))
            .unwrap();
        invalid_signature(&attach(&unsigned, wrong.as_ref()), &trust);
    }
    let already_hashed = Sha256::digest(payload(&unsigned, PREFIX));
    let double_hashed = key.sign(&SystemRandom::new(), &already_hashed).unwrap();
    invalid_signature(&attach(&unsigned, double_hashed.as_ref()), &trust);
}

#[test]
fn personal_policy_trust_does_not_expand_external_approver_algorithms() {
    let (key, trust, mut unsigned) = fixture();
    unsigned["snapshot"]["approvers"] = json!([{
        "approver_id":ApproverId::new_random(),"algorithm":"secure-enclave-p256",
        "public_key":HEXLOWER.encode(trust.public_key())}]);
    assert!(matches!(
        parse_and_verify_policy_bundle(&sign(&unsigned, &key), &trust, Timestamp::from_unix_ms(1)),
        Err(PolicyError::Malformed)
    ));
    unsigned["snapshot"]["approvers"][0]["algorithm"] = "ed25519".into();
    assert!(matches!(
        parse_and_verify_policy_bundle(&sign(&unsigned, &key), &trust, Timestamp::from_unix_ms(1)),
        Err(PolicyError::Invalid)
    ));
}
