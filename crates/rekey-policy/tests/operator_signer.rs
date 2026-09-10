use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Output};

use aws_lc_rs::{rand::SystemRandom, signature::Ed25519KeyPair};
use rekey_domain::Timestamp;
use rekey_policy::{parse_and_verify_policy_bundle, parse_policy_trust};
use serde_json::{Value, json};
use tempfile::TempDir;

const SIGNER: &str = "12345678-1234-4234-8234-123456789abc";
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rekey-policy-sign"))
        .args(args)
        .output()
        .unwrap()
}
struct Fixture {
    dir: TempDir,
    draft: String,
    key: String,
    digest: String,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let draft = dir.path().join("draft.json").to_str().unwrap().to_owned();
        let key = dir.path().join("key.der").to_str().unwrap().to_owned();
        // Test-only key generation; production executable has no keygen operation.
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        fs::write(&key, document.as_ref()).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &draft,
            serde_json::to_vec(&json!({
                "format_version": 3, "version": 1, "expires_at_ms": 4102444800000i64,
                "approvers": [], "workload_identities": [], "bindings": [], "rules": []
            }))
            .unwrap(),
        )
        .unwrap();
        let result = invoke(&["review", &draft]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let review: Value = serde_json::from_slice(&result.stdout).unwrap();
        let digest = review["reviewed_sha256"].as_str().unwrap().to_owned();
        assert_eq!(review["snapshot"]["version"], 1);
        Self {
            dir,
            draft,
            key,
            digest,
        }
    }
    fn sign(&self, name: &str) -> Output {
        invoke(&[
            "sign",
            &self.draft,
            "--reviewed-sha256",
            &self.digest,
            "--signer-id",
            SIGNER,
            "--key-file",
            &self.key,
            "--output",
            self.dir.path().join(name).to_str().unwrap(),
        ])
    }
}

#[test]
fn signed_output_verifies_tampering_fails_and_existing_output_is_preserved() {
    let fixture = Fixture::new();
    let result = fixture.sign("signed");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let dir = fixture.dir.path().join("signed");
    let trust_bytes = fs::read(dir.join("trust.json")).unwrap();
    let trust = parse_policy_trust(&trust_bytes).unwrap();
    let bytes = fs::read(dir.join("policy.json")).unwrap();
    let verified =
        parse_and_verify_policy_bundle(&bytes, &trust, Timestamp::from_unix_ms(1)).unwrap();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&verified.policy_digest()),
        fixture.digest
    );
    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["snapshot"]["version"] = 2.into();
    assert!(
        parse_and_verify_policy_bundle(
            &serde_json::to_vec(&tampered).unwrap(),
            &trust,
            Timestamp::from_unix_ms(1)
        )
        .is_err()
    );
    assert!(!fixture.sign("signed").status.success());
    assert_eq!(fs::read(dir.join("trust.json")).unwrap(), trust_bytes);
    assert_eq!(fs::read(dir.join("policy.json")).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(dir.join("policy.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn changed_or_malformed_drafts_cannot_be_signed() {
    let fixture = Fixture::new();
    let mut draft: Value = serde_json::from_slice(&fs::read(&fixture.draft).unwrap()).unwrap();
    draft["version"] = 2.into();
    fs::write(&fixture.draft, serde_json::to_vec(&draft).unwrap()).unwrap();
    assert!(!fixture.sign("changed").status.success());
    assert!(!fixture.dir.path().join("changed").exists());
    for bytes in [b"{\"version\":1,\"version\":1}".as_slice(), b"{}"] {
        fs::write(&fixture.draft, bytes).unwrap();
        assert!(!invoke(&["review", &fixture.draft]).status.success());
        assert!(!fixture.sign("bad").status.success());
    }
}

#[test]
fn loose_permissions_symlinks_and_invalid_keys_are_rejected() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!fixture.sign("loose").status.success());
    assert!(!fixture.dir.path().join("loose").exists());
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o600)).unwrap();
    let real = fixture.dir.path().join("real.der");
    fs::rename(&fixture.key, &real).unwrap();
    symlink(&real, &fixture.key).unwrap();
    assert!(!fixture.sign("symlink").status.success());
    fs::remove_file(&fixture.key).unwrap();
    fs::write(&fixture.key, b"PRIVATE-KEY-CONTENT-MUST-NOT-BE-LOGGED").unwrap();
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o600)).unwrap();
    let result = fixture.sign("invalid");
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("PRIVATE-KEY-CONTENT"));
    assert!(!fixture.dir.path().join("invalid").exists());
}

#[test]
fn canonical_whitespace_changes_preserve_review_binding() {
    let fixture = Fixture::new();
    let draft: Value = serde_json::from_slice(&fs::read(&fixture.draft).unwrap()).unwrap();
    fs::write(&fixture.draft, serde_json::to_vec_pretty(&draft).unwrap()).unwrap();
    assert!(fixture.sign("formatted").status.success());
}

#[test]
fn non_ascii_schema_keys_and_numbers_use_rfc8785() {
    let mut fixture = Fixture::new();
    let mut draft: Value = serde_json::from_slice(&fs::read(&fixture.draft).unwrap()).unwrap();
    draft["bindings"] = json!([{
        "action_id": SIGNER, "version": 1,
        "resource": {"type": "test", "id": "one"},
        "parameter_schema_id": "test/v1",
        "parameter_schema": {"type": "object", "properties": {
            "\u{e000}": {"enum": [1e-7]}, "\u{10000}": {"enum": [1.0]}
        }}
    }]);
    fs::write(&fixture.draft, serde_json::to_vec(&draft).unwrap()).unwrap();
    let review = invoke(&["review", &fixture.draft]);
    assert!(review.status.success());
    fixture.digest = serde_json::from_slice::<Value>(&review.stdout).unwrap()["reviewed_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(fixture.sign("jcs").status.success());
    let bytes = fs::read(fixture.dir.path().join("jcs/policy.json")).unwrap();
    let encoded = String::from_utf8(bytes.clone()).unwrap();
    assert!(encoded.find('\u{10000}').unwrap() < encoded.find('\u{e000}').unwrap());
    assert!(encoded.contains("[1e-7]"));
    assert!(!encoded.contains("[1.0]"));
    let trust =
        parse_policy_trust(&fs::read(fixture.dir.path().join("jcs/trust.json")).unwrap()).unwrap();
    assert!(parse_and_verify_policy_bundle(&bytes, &trust, Timestamp::from_unix_ms(1)).is_ok());
}
