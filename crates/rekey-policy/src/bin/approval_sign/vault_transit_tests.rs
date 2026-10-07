use super::*;
use data_encoding::BASE64;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
const CANARY: &str = "synthetic-transit-token-canary-20260930";
fn no_token(text: &str) {
    for forbidden in [
        CANARY.to_owned(),
        BASE64.encode(CANARY.as_bytes()),
        BASE64URL_NOPAD.encode(CANARY.as_bytes()),
        HEXLOWER.encode(CANARY.as_bytes()),
        HEXLOWER.encode(&Sha256::digest(CANARY.as_bytes())),
    ] {
        assert!(
            !text.contains(&forbidden),
            "credential canary escaped protected input"
        );
    }
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

impl Fixture {
    fn profile(&self, origin: &str, token_expiry: i64) {
        let key = Ed25519KeyPair::from_pkcs8(&self.approver_der).unwrap();
        write_json(
            &self.path("transit.json"),
            &json!({"credential_type":"vault-transit-approval-v1",
            "origin":origin,"mount":"transit","key":"approval-key","key_version":7,
            "public_key":HEXLOWER.encode(key.public_key().as_ref()),"vault_token":CANARY,
            "token_expires_at_ms":token_expiry}),
        );
        fs::set_permissions(self.path("transit.json"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn args(&self, mode: &str, digest: Option<&str>) -> Vec<String> {
        let mut args = vec![mode.into(), self.path("request.json").display().to_string()];
        for (name, value) in [
            ("--policy", self.path("policy.json").display().to_string()),
            ("--trust", self.path("trust.json").display().to_string()),
            ("--action", self.path("action.json").display().to_string()),
            ("--approver-id", self.approver.clone()),
            ("--origin-key", self.origin_hex.clone()),
            (
                "--vault-transit-profile",
                self.path("transit.json").display().to_string(),
            ),
        ] {
            args.extend([name.into(), value]);
        }
        if let Some(digest) = digest {
            args.extend([
                "--reviewed-sha256".into(),
                digest.into(),
                "--output".into(),
                self.path("grant.json").display().to_string(),
            ]);
        }
        args
    }

    fn review(&self) -> String {
        let mut text = Vec::new();
        run_args(self.args("review", None), &mut text).unwrap();
        let value: Value = serde_json::from_slice(&text).unwrap();
        let display = String::from_utf8(text).unwrap();
        no_token(&display);
        value["reviewed_sha256"].as_str().unwrap().into()
    }

    fn sign(&self, digest: &str) -> Result<Vec<u8>> {
        let mut text = Vec::new();
        run_args(self.args("sign", Some(digest)), &mut text)?;
        no_token(&String::from_utf8_lossy(&text));
        Ok(text)
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Success,
    Forbidden,
    Redirect,
    WrongVersion,
    WrongSignature,
    Oversized,
    Malformed,
    Lost,
    Slow,
    Delay,
}

#[derive(Clone)]
struct Capture {
    line: String,
    body: Value,
}

struct TlsFixture {
    address: SocketAddr,
    certificate: reqwest::Certificate,
    stop: Arc<AtomicBool>,
    captures: Arc<Mutex<Vec<Capture>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl TlsFixture {
    fn new(key_der: Vec<u8>, mode: Mode) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_params =
            rcgen::CertificateParams::new(vec!["transit.fixture.test".into()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let captures = Arc::new(Mutex::new(Vec::new()));
        let stop_worker = stop.clone();
        let captured = captures.clone();
        let worker = thread::spawn(move || {
            let config = Arc::new(config);
            while !stop_worker.load(Ordering::SeqCst) {
                let Ok((stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, stream);
                let mut bytes = Vec::new();
                let mut byte = [0];
                let mut failed = false;
                while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 16384 {
                    if stream.read_exact(&mut byte).is_err() {
                        failed = true;
                        break;
                    }
                    bytes.push(byte[0]);
                }
                if failed {
                    continue;
                }
                let header = String::from_utf8(bytes).unwrap();
                assert!(
                    header
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case(&format!("x-vault-token: {CANARY}")))
                );
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                assert!(length < 65536);
                let mut body = vec![0; length];
                if stream.read_exact(&mut body).is_err() {
                    continue;
                }
                let value: Value = serde_json::from_slice(&body).unwrap();
                captured.lock().unwrap().push(Capture {
                    line: header.lines().next().unwrap().into(),
                    body: value.clone(),
                });
                if matches!(mode, Mode::Lost) {
                    continue;
                }
                if matches!(mode, Mode::Delay) {
                    thread::sleep(Duration::from_millis(200));
                }
                let message = BASE64
                    .decode(value["input"].as_str().unwrap().as_bytes())
                    .unwrap();
                let key = Ed25519KeyPair::from_pkcs8(&key_der).unwrap();
                let mut signature = key.sign(&message).as_ref().to_vec();
                if matches!(mode, Mode::WrongSignature) {
                    signature[0] ^= 1;
                }
                let version = if matches!(mode, Mode::WrongVersion) {
                    8
                } else {
                    7
                };
                let body = match mode {
                    Mode::Oversized => vec![b'x';65537],
                    Mode::Malformed => format!("{{\"error\":\"{CANARY}\"}}").into_bytes(),
                    _ => serde_json::to_vec(&json!({"request_id":"fixture", "data":{"signature":format!("vault:v{version}:{}",BASE64.encode(&signature))}})).unwrap(),
                };
                let status = match mode {
                    Mode::Forbidden => "403 Forbidden",
                    Mode::Redirect => "302 Found",
                    _ => "200 OK",
                };
                let headers = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: https://transit.fixture.test/redirect\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(headers.as_bytes()).is_err() {
                    continue;
                }
                if matches!(mode, Mode::Slow) {
                    for byte in body.iter().take(8) {
                        if stream
                            .write_all(&[*byte])
                            .and_then(|_| stream.flush())
                            .is_err()
                        {
                            break;
                        }
                        thread::sleep(Duration::from_millis(30));
                    }
                } else {
                    let _ = stream.write_all(&body);
                    let _ = stream.flush();
                }
            }
        });
        Self {
            address,
            certificate: reqwest::Certificate::from_der(ca.der()).unwrap(),
            stop,
            captures,
            worker: Some(worker),
        }
    }

    fn configure(&self, deadline: Duration) {
        vault_transit::TEST_TRANSPORT.with(|value| {
            *value.borrow_mut() = Some(vault_transit::TestTransport {
                addresses: vec![self.address],
                certificate: self.certificate.clone(),
                deadline,
                dns_delay: Duration::ZERO,
            })
        });
    }
    fn origin(&self) -> String {
        format!("https://transit.fixture.test:{}", self.address.port())
    }
    fn captures(&self) -> Vec<Capture> {
        self.captures.lock().unwrap().clone()
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        vault_transit::TEST_TRANSPORT.with(|value| *value.borrow_mut() = None);
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn transit_tls_exact_domain_bytes_verified_grant_and_private_output() {
    let fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Success);
    tls.configure(Duration::from_secs(2));
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    fixture.sign(&digest).unwrap();
    let captured = tls.captures();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].line,
        "POST /v1/transit/sign/approval-key HTTP/1.1"
    );
    assert_eq!(captured[0].body.as_object().unwrap().len(), 3);
    assert_eq!(captured[0].body["key_version"], 7);
    assert_eq!(captured[0].body["prehashed"], false);
    let bytes = fs::read(fixture.path("grant.json")).unwrap();
    let trust = parse_policy_trust(&fs::read(fixture.path("trust.json")).unwrap()).unwrap();
    let policy = parse_and_verify_policy_bundle(
        &fs::read(fixture.path("policy.json")).unwrap(),
        &trust,
        now().unwrap(),
    )
    .unwrap();
    let verified = parse_and_verify_approval_grant(&bytes, policy.snapshot()).unwrap();
    assert!(verified.grant().expires_at_ms <= fixture.policy_expiry);
    let mut grant: Value = serde_json::from_slice(&bytes).unwrap();
    grant.as_object_mut().unwrap().remove("signature");
    let mut expected = b"RKAPPROVAL\0\x01".to_vec();
    expected.extend(serde_jcs::to_vec(&grant).unwrap());
    assert_eq!(
        BASE64
            .decode(captured[0].body["input"].as_str().unwrap().as_bytes())
            .unwrap(),
        expected
    );
    let meta = fs::metadata(fixture.path("grant.json")).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    no_token(&String::from_utf8_lossy(&bytes));
    assert!(fixture.sign(&digest).is_err());
    assert_eq!(fs::read(fixture.path("grant.json")).unwrap(), bytes);
}

#[test]
fn transit_remote_failures_one_request_no_output_no_canary() {
    for mode in [
        Mode::Forbidden,
        Mode::Redirect,
        Mode::WrongVersion,
        Mode::WrongSignature,
        Mode::Oversized,
        Mode::Malformed,
        Mode::Lost,
        Mode::Slow,
    ] {
        let fixture = Fixture::new();
        let tls = TlsFixture::new(fixture.approver_der.clone(), mode);
        tls.configure(if matches!(mode, Mode::Slow) {
            Duration::from_millis(80)
        } else {
            Duration::from_secs(2)
        });
        fixture.profile(&tls.origin(), now_ms() + 300000);
        let digest = fixture.review();
        let started = Instant::now();
        let error = fixture.sign(&digest).unwrap_err().to_string();
        no_token(&error);
        assert!(error.contains("remote result may be unknown"));
        assert!(!fixture.path("grant.json").exists());
        assert_eq!(tls.captures().len(), 1);
        if matches!(mode, Mode::Slow) {
            assert!(started.elapsed() < Duration::from_millis(500));
        }
    }
}

#[test]
fn transit_digest_binds_target_key_metadata_but_not_token() {
    let fixture = Fixture::new();
    fixture.profile("https://transit.fixture.test", now_ms() + 300000);
    let digest = fixture.review();
    let original: Value =
        serde_json::from_slice(&fs::read(fixture.path("transit.json")).unwrap()).unwrap();
    for (field, value) in [
        ("origin", json!("https://other.fixture.test")),
        ("mount", json!("other")),
        ("key", json!("other")),
        ("key_version", json!(8)),
    ] {
        let mut profile = original.clone();
        profile[field] = value;
        write_json(&fixture.path("transit.json"), &profile);
        assert!(
            fixture
                .sign(&digest)
                .unwrap_err()
                .to_string()
                .contains("reviewed digest mismatch")
        );
        assert!(!fixture.path("grant.json").exists());
    }
    let mut profile = original.clone();
    profile["vault_token"] = "renewed-synthetic-token".into();
    profile["token_expires_at_ms"] = (now_ms() + 600000).into();
    write_json(&fixture.path("transit.json"), &profile);
    assert_eq!(fixture.review(), digest);
    let wrong = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    profile["public_key"] = HEXLOWER
        .encode(
            Ed25519KeyPair::from_pkcs8(wrong.as_ref())
                .unwrap()
                .public_key()
                .as_ref(),
        )
        .into();
    write_json(&fixture.path("transit.json"), &profile);
    assert!(
        fixture
            .sign(&digest)
            .unwrap_err()
            .to_string()
            .contains("does not match policy approver")
    );
}

#[test]
fn transit_expiry_before_and_during_call_never_outputs() {
    let fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Delay);
    tls.configure(Duration::from_secs(2));
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    fixture.profile(&tls.origin(), now_ms() - 1);
    assert!(
        fixture
            .sign(&digest)
            .unwrap_err()
            .to_string()
            .contains("token expired")
    );
    assert!(tls.captures().is_empty());
    fixture.profile(&tls.origin(), now_ms() + 100);
    assert!(
        fixture
            .sign(&digest)
            .unwrap_err()
            .to_string()
            .contains("token expired")
    );
    assert_eq!(tls.captures().len(), 1);
    assert!(!fixture.path("grant.json").exists());
}

#[test]
fn transit_grant_expiry_during_call_never_outputs() {
    let mut fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Delay);
    tls.configure(Duration::from_secs(2));
    fixture.request["challenge"]["challenge"]["max_expires_at_ms"] = (now_ms() + 150).into();
    fixture.resign_inner();
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    assert!(
        fixture
            .sign(&digest)
            .unwrap_err()
            .to_string()
            .contains("expired while signing")
    );
    assert!(!fixture.path("grant.json").exists());
    assert_eq!(tls.captures().len(), 1);
}

#[test]
fn transit_private_profile_strict_permissions_symlink_size_and_fields() {
    let fixture = Fixture::new();
    fixture.profile("https://transit.fixture.test", now_ms() + 300000);
    let path = fixture.path("transit.json");
    let original = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(vault_transit::Profile::load(path.to_str().unwrap()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&path, fixture.path("link.json")).unwrap();
    assert!(vault_transit::Profile::load(fixture.path("link.json").to_str().unwrap()).is_err());
    for raw in [
        vec![b'x'; 65537],
        original
            .iter()
            .copied()
            .take(original.len() - 1)
            .chain(b",\"unexpected\":true}".iter().copied())
            .collect(),
        original
            .iter()
            .copied()
            .take(original.len() - 1)
            .chain(b",\"vault_token\":\"duplicate\"}".iter().copied())
            .collect(),
    ] {
        fs::write(&path, raw).unwrap();
        let error = vault_transit::Profile::load(path.to_str().unwrap())
            .err()
            .unwrap()
            .to_string();
        assert_eq!(error, "invalid private Transit profile");
        assert!(!error.contains(CANARY));
    }
    fs::write(&path, &original).unwrap();
    for origin in [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com?token=secret",
        "https://example.com#secret",
    ] {
        let mut profile: Value = serde_json::from_slice(&original).unwrap();
        profile["origin"] = origin.into();
        write_json(&path, &profile);
        assert!(vault_transit::Profile::load(path.to_str().unwrap()).is_err());
    }
}

#[test]
fn transit_dns_screen_rejects_any_private_including_ipv6() {
    let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
    assert_eq!(
        vault_transit::screen_for_test(vec![public]).unwrap(),
        vec![public]
    );
    for private in [
        "127.0.0.1:443",
        "169.254.169.254:443",
        "[::1]:443",
        "[::ffff:10.0.0.1]:443",
        "[64:ff9b::a00:1]:443",
        "[2001:db8::1]:443",
        "[fc00::1]:443",
    ] {
        assert!(vault_transit::screen_for_test(vec![public, private.parse().unwrap()]).is_err());
    }
    assert!(vault_transit::screen_for_test(vec![]).is_err());
    let ipv6 = "[2606:4700:4700::1111]:443".parse().unwrap();
    assert_eq!(
        vault_transit::screen_for_test(vec![ipv6]).unwrap(),
        vec![ipv6]
    );
}

#[test]
fn transit_backend_exclusivity_and_output_symlink() {
    let fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Success);
    tls.configure(Duration::from_secs(2));
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    let mut args = fixture.args("sign", Some(&digest));
    args.extend([
        "--key-file".into(),
        fixture.path("key.der").display().to_string(),
    ]);
    assert!(run_args(args, &mut Vec::new()).is_err());
    assert!(tls.captures().is_empty());
    fs::write(fixture.path("protected"), b"unchanged").unwrap();
    std::os::unix::fs::symlink(fixture.path("protected"), fixture.path("grant.json")).unwrap();
    assert!(fixture.sign(&digest).is_err());
    assert_eq!(fs::read(fixture.path("protected")).unwrap(), b"unchanged");
}

#[test]
fn transit_wrong_origin_policy_body_and_review_never_calls_provider() {
    let mut fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Success);
    tls.configure(Duration::from_secs(2));
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    assert!(fixture.sign("wrong-reviewed-digest").is_err());
    let original = fixture.request.clone();
    fixture.request["body"] = "{\"message\":\"changed\"}".into();
    fixture.persist_request();
    assert!(fixture.sign(&digest).is_err());
    fixture.request = original;
    fixture.persist_request();
    let mut args = fixture.args("sign", Some(&digest));
    let index = args.iter().position(|arg| arg == "--origin-key").unwrap();
    args[index + 1] = HEXLOWER.encode(
        Ed25519KeyPair::from_pkcs8(&fixture.approver_der)
            .unwrap()
            .public_key()
            .as_ref(),
    );
    assert!(run_args(args, &mut Vec::new()).is_err());
    let mut policy: Value =
        serde_json::from_slice(&fs::read(fixture.path("policy.json")).unwrap()).unwrap();
    policy["snapshot"]["version"] = 2.into();
    write_json(&fixture.path("policy.json"), &policy);
    assert!(fixture.sign(&digest).is_err());
    assert!(tls.captures().is_empty());
}

#[test]
fn transit_dns_deadline_and_expiry_stop_before_admission() {
    let fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Success);
    tls.configure(Duration::from_millis(25));
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    vault_transit::TEST_TRANSPORT
        .with(|value| value.borrow_mut().as_mut().unwrap().dns_delay = Duration::from_millis(100));
    let start = Instant::now();
    assert!(fixture.sign(&digest).is_err());
    assert!(start.elapsed() < Duration::from_millis(250));
    thread::sleep(Duration::from_millis(150));
    assert!(tls.captures().is_empty());
    tls.configure(Duration::from_secs(1));
    vault_transit::TEST_TRANSPORT
        .with(|value| value.borrow_mut().as_mut().unwrap().dns_delay = Duration::from_millis(100));
    fixture.profile(&tls.origin(), now_ms() + 50);
    assert!(fixture.sign(&digest).is_err());
    assert!(tls.captures().is_empty());
    assert!(!fixture.path("grant.json").exists());
}

#[test]
fn transit_wrong_ca_and_hostname_never_send_http() {
    let fixture = Fixture::new();
    let tls = TlsFixture::new(fixture.approver_der.clone(), Mode::Success);
    tls.configure(Duration::from_secs(1));
    fixture.profile(&tls.origin(), now_ms() + 300000);
    let digest = fixture.review();
    let other = rcgen::generate_simple_self_signed(vec!["other.fixture.test".into()]).unwrap();
    vault_transit::TEST_TRANSPORT.with(|value| {
        value.borrow_mut().as_mut().unwrap().certificate =
            reqwest::Certificate::from_der(other.cert.der()).unwrap()
    });
    assert!(fixture.sign(&digest).is_err());
    assert!(tls.captures().is_empty());
    tls.configure(Duration::from_secs(1));
    fixture.profile(
        &format!("https://other.fixture.test:{}", tls.address.port()),
        now_ms() + 300000,
    );
    let digest = fixture.review();
    assert!(fixture.sign(&digest).is_err());
    assert!(tls.captures().is_empty());
    assert!(!fixture.path("grant.json").exists());
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
    approver_der: Vec<u8>,
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
        let snapshot = json!({"format_version": 7, "connections": [], "ssh_keys": [], "derived_credentials": [], "profiles": [],"version":1,"expires_at_ms":policy_expiry,
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
            approver_der: approver_der.as_ref().to_vec(),
        }
    }
    fn origin(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_pkcs8(&self.origin_der).unwrap()
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
}
