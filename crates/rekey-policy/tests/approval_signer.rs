use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::Timestamp;
use rekey_policy::{
    parse_and_verify_approval_grant, parse_and_verify_policy_bundle, parse_policy_trust,
};
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn id() -> String {
    rekey_domain::ids::ActionId::new_random().to_string()
}
fn write_json(path: &std::path::Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn signed_envelope(challenge: &Value, origin: &Ed25519KeyPair) -> Value {
    let mut message = b"RKCHALLENGE\0\x02".to_vec();
    message.extend(serde_jcs::to_vec(challenge).unwrap());
    json!({
        "record_type": "rekey.approval.challenge.envelope.v2",
        "challenge": challenge,
        "signature": BASE64URL_NOPAD.encode(origin.sign(&message).as_ref()),
    })
}
struct Fixture {
    dir: TempDir,
    approver: String,
    request: Value,
    policy_expiry: i64,
    origin_der: Vec<u8>,
    origin_hex: String,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let signer_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(signer_der.as_ref()).unwrap();
        let approver_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(approver_der.as_ref()).unwrap();
        let origin_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let origin = Ed25519KeyPair::from_pkcs8(origin_der.as_ref()).unwrap();
        let origin_hex = HEXLOWER.encode(origin.public_key().as_ref());
        fs::write(dir.path().join("key.der"), approver_der.as_ref()).unwrap();
        fs::set_permissions(
            dir.path().join("key.der"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let signer_id = id();
        let approver = id();
        let action_id = id();
        let principal = id();
        let rule = id();
        let created = now_ms();
        let policy_expiry = created + 300_000;
        let trust = json!({"format_version":1,"signer_id":signer_id,"algorithm":"ed25519","public_key":HEXLOWER.encode(signer.public_key().as_ref())});
        let resource = json!({"type":"test.resource","id":"one"});
        let snapshot = json!({"format_version":4,"version":1,"expires_at_ms":policy_expiry,
            "approvers":[{"approver_id":approver,"algorithm":"ed25519","public_key":HEXLOWER.encode(key.public_key().as_ref())}],
            "workload_identities":[],"bindings":[{"action_id":action_id,"version":1,"resource":resource,"parameter_schema_id":"test/v1","parameter_schema":{"type":"object","required":["message"],"properties":{"message":{"type":"string"}},"additionalProperties":false}}],
            "rules":[{"id":rule,"effect":"require-approval","principal_id":principal,"action_id":action_id,"version":1,"resource":resource,"parameters":{"kind":"any_validated"},"approver":{"kind":"ed25519","keys":[HEXLOWER.encode(key.public_key().as_ref())],"threshold":1},"approval":{"mode":"one-time","max_uses":1}}]});
        let mut bundle = json!({"format_version":1,"signer_id":signer_id,"snapshot":snapshot});
        let mut message = b"RKPOLICY\0\x01".to_vec();
        message.extend(serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = BASE64URL_NOPAD
            .encode(signer.sign(&message).as_ref())
            .into();
        write_json(&dir.path().join("trust.json"), &trust);
        write_json(&dir.path().join("policy.json"), &bundle);
        let verified = parse_and_verify_policy_bundle(
            &serde_json::to_vec(&bundle).unwrap(),
            &parse_policy_trust(&serde_json::to_vec(&trust).unwrap()).unwrap(),
            Timestamp::from_unix_ms(created),
        )
        .unwrap();
        let action = json!({"id":action_id,"name":"approval-test","version":1,"enabled":true,"credential_id":id(),"origin":"https://example.com","method":"POST","target":{"kind":"fixed","path":"/approved"},"auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":5000,"request_policy":{"max_body_bytes":4096,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":4096,"allowed_headers":[]}});
        let parsed: rekey_domain::action::FixedHttpAction =
            serde_json::from_value(action.clone()).unwrap();
        parsed.validate().unwrap();
        write_json(&dir.path().join("action.json"), &action);
        let body = r#"{"message":"approved"}"#;
        let (_, parameters, _) = verified
            .snapshot()
            .canonicalize(
                &parsed,
                rekey_policy::ActionRequest {
                    params: &Default::default(),
                    query: &Default::default(),
                    content_type: Some("application/json"),
                    headers: &[],
                    body: body.as_bytes(),
                },
            )
            .unwrap();
        let inner = json!({"record_type":"rekey.approval.challenge.v2","approval_request_id":id(),"tenant_id":id(),"principal_id":principal,"session_id":id(),"action_id":action_id,"action_version":1,"resource":resource,"schema_id":"test/v1","parameter_sha256":HEXLOWER.encode(&parameters.canonical_hash),"policy_version":1,"policy_sha256":HEXLOWER.encode(&verified.policy_digest()),"policy_rule_id":rule,"mode":"one-time","approver":{"kind":"ed25519","keys":[HEXLOWER.encode(key.public_key().as_ref())],"threshold":1},"max_uses":1,"created_at_ms":created,"max_expires_at_ms":created+120_000});
        let request = json!({"challenge":signed_envelope(&inner, &origin),"content_type":"application/json","headers":[],"body":body});
        write_json(&dir.path().join("request.json"), &request);
        Self {
            dir,
            approver,
            request,
            policy_expiry,
            origin_der: origin_der.as_ref().to_vec(),
            origin_hex,
        }
    }
    fn origin(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_pkcs8(&self.origin_der).unwrap()
    }
    fn inner(&self) -> &Value {
        &self.request["challenge"]["challenge"]
    }
    fn persist_request(&mut self) {
        write_json(&self.path("request.json"), &self.request);
    }
    fn resign_inner(&mut self) {
        let inner = self.request["challenge"]["challenge"].clone();
        self.request["challenge"] = signed_envelope(&inner, &self.origin());
        self.persist_request();
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn invoke(&self, mode: &str, digest: Option<&str>, output: &str) -> Output {
        self.invoke_with_origin(mode, digest, output, &self.origin_hex)
    }
    fn invoke_with_origin(
        &self,
        mode: &str,
        digest: Option<&str>,
        output: &str,
        origin_hex: &str,
    ) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rekey-approval-sign"));
        cmd.arg(mode)
            .arg(self.path("request.json"))
            .arg("--policy")
            .arg(self.path("policy.json"))
            .arg("--trust")
            .arg(self.path("trust.json"))
            .arg("--action")
            .arg(self.path("action.json"))
            .arg("--approver-id")
            .arg(&self.approver)
            .arg("--origin-key")
            .arg(origin_hex);
        if let Some(digest) = digest {
            cmd.arg("--reviewed-sha256")
                .arg(digest)
                .arg("--key-file")
                .arg(self.path("key.der"))
                .arg("--output")
                .arg(self.path(output));
        }
        cmd.output().unwrap()
    }
    fn review(&self) -> String {
        let out = self.invoke("review", None, "unused");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["reviewed_sha256"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn reject_sign(&self, digest: &str) {
        let out = self.invoke("sign", Some(digest), "rejected.json");
        assert!(!out.status.success());
        assert!(!self.path("rejected.json").exists());
    }
}

#[test]
fn valid_grant_verifies_is_private_bounded_and_never_overwrites() {
    let f = Fixture::new();
    let digest = f.review();
    let before = now_ms();
    let out = f.invoke("sign", Some(&digest), "grant.json");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = now_ms();
    let bytes = fs::read(f.path("grant.json")).unwrap();
    let trust = parse_policy_trust(&fs::read(f.path("trust.json")).unwrap()).unwrap();
    let policy = parse_and_verify_policy_bundle(
        &fs::read(f.path("policy.json")).unwrap(),
        &trust,
        Timestamp::from_unix_ms(after),
    )
    .unwrap();
    let verified = parse_and_verify_approval_grant(&bytes, policy.snapshot()).unwrap();
    let grant = verified.grant();
    assert_eq!(grant.format_version, 1);
    assert_eq!(
        grant.approval_request_id.to_string(),
        f.inner()["approval_request_id"].as_str().unwrap()
    );
    assert_eq!(
        grant.parameter_sha256,
        f.inner()["parameter_sha256"].as_str().unwrap()
    );
    assert_eq!(grant.max_uses, 1);
    assert!(grant.expires_at_ms > before);
    assert!(grant.expires_at_ms <= after + 60_000);
    assert!(grant.expires_at_ms <= f.policy_expiry);
    assert!(grant.expires_at_ms <= f.inner()["max_expires_at_ms"].as_i64().unwrap());
    assert_eq!(
        fs::metadata(f.path("grant.json")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(
        !f.invoke("sign", Some(&digest), "grant.json")
            .status
            .success()
    );
    assert_eq!(fs::read(f.path("grant.json")).unwrap(), bytes);
}

#[test]
fn reviewed_digest_and_changed_body_are_rejected() {
    let mut f = Fixture::new();
    let digest = f.review();
    f.reject_sign(&"0".repeat(64));
    f.request["body"] = r#"{"message":"changed"}"#.into();
    write_json(&f.path("request.json"), &f.request);
    assert!(!f.invoke("review", None, "unused").status.success());
    f.reject_sign(&digest);
}

#[test]
fn changed_trusted_target_requires_a_new_challenge() {
    let f = Fixture::new();
    let digest = f.review();
    let mut action: Value =
        serde_json::from_slice(&fs::read(f.path("action.json")).unwrap()).unwrap();
    action["target"]["path"] = "/different-target".into();
    write_json(&f.path("action.json"), &action);
    assert!(!f.invoke("review", None, "unused").status.success());
    f.reject_sign(&digest);
}

#[test]
fn wrong_approver_key_and_non_private_key_are_rejected() {
    let f = Fixture::new();
    let digest = f.review();
    let original = fs::read(f.path("key.der")).unwrap();
    let wrong = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    fs::write(f.path("key.der"), wrong.as_ref()).unwrap();
    f.reject_sign(&digest);
    fs::write(f.path("key.der"), original).unwrap();
    fs::set_permissions(f.path("key.der"), fs::Permissions::from_mode(0o644)).unwrap();
    f.reject_sign(&digest);
}

#[test]
fn expired_challenge_is_rejected_without_signing() {
    let mut f = Fixture::new();
    let digest = f.review();
    let now = now_ms();
    f.request["challenge"]["challenge"]["created_at_ms"] = (now - 120_000).into();
    f.request["challenge"]["challenge"]["max_expires_at_ms"] = (now - 1).into();
    f.resign_inner();
    assert!(!f.invoke("review", None, "unused").status.success());
    f.reject_sign(&digest);
}

#[test]
fn signer_rejects_local_remote_double_and_window_without_expanding_its_role() {
    for kind in [
        "local",
        "remote",
        "double",
        "window",
        "unregistered",
        "old-record",
    ] {
        let mut f = Fixture::new();
        let digest = f.review();
        let challenge = &mut f.request["challenge"]["challenge"];
        match kind {
            "local" => challenge["approver"] = json!({"kind":"local-presence"}),
            "remote" => challenge["approver"] = json!({"kind":"remote"}),
            "double" => {
                let other = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
                let other = Ed25519KeyPair::from_pkcs8(other.as_ref()).unwrap();
                let keys = challenge["approver"]["keys"].as_array_mut().unwrap();
                keys.push(json!(HEXLOWER.encode(other.public_key().as_ref())));
                keys.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                challenge["approver"]["threshold"] = 2.into();
            }
            "window" => challenge["mode"] = "time-window".into(),
            "unregistered" => challenge["approver"]["keys"] = json!(["ff".repeat(32)]),
            "old-record" => challenge["record_type"] = "rekey.approval.challenge.v1".into(),
            _ => unreachable!(),
        }
        f.resign_inner();
        assert!(
            !f.invoke("review", None, "unused").status.success(),
            "accepted {kind}"
        );
        f.reject_sign(&digest);
    }
}

#[test]
fn unsigned_or_wrong_origin_challenge_is_rejected() {
    let mut f = Fixture::new();
    let digest = f.review();
    let inner = f.inner().clone();
    f.request["challenge"] = inner;
    f.persist_request();
    assert!(!f.invoke("review", None, "unused").status.success());
    f.reject_sign(&digest);
    let f = Fixture::new();
    let digest = f.review();
    let other = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let other_key = Ed25519KeyPair::from_pkcs8(other.as_ref()).unwrap();
    let wrong = HEXLOWER.encode(other_key.public_key().as_ref());
    assert!(
        !f.invoke_with_origin("review", None, "unused", &wrong)
            .status
            .success()
    );
    assert!(
        !f.invoke_with_origin("sign", Some(&digest), "rejected.json", &wrong)
            .status
            .success()
    );
    assert!(!f.path("rejected.json").exists());
}

#[test]
fn template_signer_reviews_the_rendered_target_and_rejects_changed_values() {
    let mut f = Fixture::new();
    let mut action: Value =
        serde_json::from_slice(&fs::read(f.path("action.json")).unwrap()).unwrap();
    action["target"] = json!({"kind":"template","target":{"path":"/issues/{number}","params":{"number":"int:1..100"},"query":{"state":"enum:open,closed","page":"int:1..100"}},"fixed_headers":{"x-template":"one"},"body_schema":{"type":"object","required":["message"],"properties":{"message":{"const":"approved"}},"additionalProperties":false},"source":{"template":"team@1","capability":"issues","action_index":0,"digest":vec![7;32],"signer_id":null},"default_policy":{"rule":"allow"}});
    write_json(&f.path("action.json"), &action);
    let parsed: rekey_domain::action::FixedHttpAction = serde_json::from_value(action).unwrap();
    f.request["params"] = json!({"number":"007"});
    f.request["query"] = json!({"state":"open","page":"02"});
    let trust = parse_policy_trust(&fs::read(f.path("trust.json")).unwrap()).unwrap();
    let bundle = parse_and_verify_policy_bundle(
        &fs::read(f.path("policy.json")).unwrap(),
        &trust,
        Timestamp::from_unix_ms(now_ms()),
    )
    .unwrap();
    let (_, parameters, _) = bundle
        .snapshot()
        .canonicalize(
            &parsed,
            rekey_policy::ActionRequest {
                params: &serde_json::from_value(f.request["params"].clone()).unwrap(),
                query: &serde_json::from_value(f.request["query"].clone()).unwrap(),
                content_type: Some("application/json"),
                headers: &[],
                body: f.request["body"].as_str().unwrap().as_bytes(),
            },
        )
        .unwrap();
    f.request["challenge"]["challenge"]["parameter_sha256"] =
        HEXLOWER.encode(&parameters.canonical_hash).into();
    f.resign_inner();
    let reviewed = f.invoke("review", None, "unused");
    assert!(reviewed.status.success());
    let review: Value = serde_json::from_slice(&reviewed.stdout).unwrap();
    assert_eq!(
        review["review"]["request_target"],
        "/issues/7?page=2&state=open"
    );
    assert_eq!(review["review"]["target"]["params"]["number"], "7");
    let digest = review["reviewed_sha256"].as_str().unwrap();
    assert!(
        f.invoke("sign", Some(digest), "template-grant.json")
            .status
            .success()
    );
    let original = f.request.clone();
    for (field, name, value) in [
        ("params", "number", "8"),
        ("query", "state", "closed"),
        ("query", "page", "3"),
    ] {
        f.request = original.clone();
        f.request[field][name] = value.into();
        f.persist_request();
        assert!(!f.invoke("review", None, "unused").status.success());
        f.reject_sign(digest);
    }
    f.request = original;
    f.request["body"] = r#"{"message":"approved","message":"changed"}"#.into();
    f.persist_request();
    assert!(!f.invoke("review", None, "unused").status.success());
    f.reject_sign(digest);
}
