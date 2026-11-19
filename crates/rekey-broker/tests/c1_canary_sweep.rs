//! C1 / I1 in the default build. One personal vault holds a synthetic canary as
//! the credential of an activated, signed Connection. Every caller surface (the
//! `rekey` CLI, the `rekey-mcp` tools, the local HTTP service and the SSH agent)
//! is driven through discovery, calls, dry runs, refusals and errors while the
//! synthetic upstream reflects the canary in each encoding that response sealing
//! supports. No output may contain the canary raw, base64/base64url, hex,
//! percent-encoded or JSON-escaped, also after decoding the output's JSON and
//! percent escapes. The CLI is the workspace `rekey` binary next to `rekeyd`:
//! build the workspace binaries first (`cargo test --workspace` does).
#[path = "c1_canary_sweep/cli.rs"]
mod cli;
mod common;
#[path = "c1_canary_sweep/mcp.rs"]
mod mcp;
#[path = "c1_canary_sweep/paths.rs"]
mod paths;
#[path = "c1_canary_sweep/service.rs"]
mod service;
#[path = "ssh_support/mod.rs"]
mod ssh_support;
#[path = "c1_canary_sweep/stream.rs"]
mod stream;
#[path = "c1_canary_sweep/t1.rs"]
mod t1;

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamStreamFuture,
    UpstreamStreamResponse, UpstreamTransport,
};
use rekey_domain::authorization::PolicyMode;
use rekey_domain::ids::{PolicyRuleId, PolicySignerId};
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};
use tokio::net::UnixStream;

/// Synthetic credential. `/`, `+`, `"`, `\`, the space and `=` make every
/// percent and JSON form differ from the raw bytes.
const CANARY: &[u8] = br#"c1-canary/7f3a+"quoted"\path tail=09b2e6"#;
const SSH_KEY_NAME: &str = "c1-ssh";
/// Seed of the imported synthetic SSH key, so every sweep can refuse it.
const SSH_SEED: [u8; 32] = [41; 32];
const SIGN_PREFIX: &[u8] = b"RKPOLICY\0\x01";

pub(crate) struct Fixture {
    dir: tempfile::TempDir,
    state: PathBuf,
    fake: Arc<FakeUpstreamTransport>,
    streams: Arc<Mutex<VecDeque<UpstreamStreamResponse>>>,
    task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    service_url: String,
}

/// Buffered calls use the recording fake; streaming LLM calls take queued
/// stream responses in order (an unexpected stream call panics the daemon task).
struct SweepTransport {
    fake: Arc<FakeUpstreamTransport>,
    streams: Arc<Mutex<VecDeque<UpstreamStreamResponse>>>,
}

impl UpstreamTransport for SweepTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        self.fake.send(request)
    }

    fn open_stream(&self, _request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        let next = self.streams.lock().unwrap().pop_front();
        Box::pin(async move { Ok(next.expect("a queued stream response")) })
    }
}

/// Policy additions for the sensitive-path sweep: more Connections and T1 grants.
#[derive(Default)]
pub(crate) struct Extra {
    connections: Vec<Value>,
    derived_credentials: Vec<Value>,
}

impl Fixture {
    async fn start() -> Self {
        let mut f = Self::boot().await;
        f.activate(Extra::default()).await;
        f
    }

    /// Starts and unlocks the daemon; nothing is signed yet.
    async fn boot() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(common::PASSWORD),
            common::TEST_PARAMS,
            PolicyMode::Personal,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let fake = Arc::new(FakeUpstreamTransport::new());
        let streams = Arc::new(Mutex::new(VecDeque::new()));
        let mut config = BrokerConfig::new(state.clone());
        config.transport = Some(Arc::new(SweepTransport {
            fake: fake.clone(),
            streams: streams.clone(),
        }));
        config.service_port = Some(0);
        config.unlock_backoff_base = Duration::from_millis(20);
        let task = tokio::spawn(serve(config));
        let f = Self {
            dir,
            state,
            fake,
            streams,
            task,
            service_url: String::new(),
        };
        f.wait_ready().await;
        f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
            .await
            .ok();
        f
    }

    /// Adds one credential and returns its ID.
    async fn add_credential(&self, label: &str, kind: &str, secret: &[u8]) -> Value {
        let credential = self
            .admin(
                admin_msg::CREDENTIAL_ADD,
                json!({"label":label,"kind":kind}),
                &common::proof_and_secret_body(common::PASSWORD, secret),
            )
            .await;
        credential.ok()["id"].clone()
    }

    async fn wait_ready(&self) {
        let started = std::time::Instant::now();
        let limit = common::test_timeout(Duration::from_secs(30));
        loop {
            assert!(!self.task.is_finished(), "broker exited during startup");
            if UnixStream::connect(self.socket("admin.sock")).await.is_ok()
                && UnixStream::connect(self.socket("agent.sock")).await.is_ok()
            {
                return;
            }
            assert!(started.elapsed() < limit, "broker did not start");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Signs and activates one Connection that holds the canary plus one SSH
    /// key, and any `extra` rules; then records the local service URL.
    /// Returns the generated SSH identity.
    async fn activate(&mut self, extra: Extra) -> Value {
        let proof = common::proof_body(common::PASSWORD);
        let generated =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, generated.as_ref()).unwrap();
        self.admin(admin_msg::POLICY_TRUST_INSTALL, json!({
            "format_version": 1, "signer_id": PolicySignerId::new_random(),
            "algorithm": "secure-enclave-p256", "public_key": HEXLOWER.encode(signer.public_key().as_ref()),
        }), &proof).await.ok();
        let credential = self
            .add_credential("c1-canary", "opaque-token", CANARY)
            .await;
        let credential_id = serde_json::from_value(credential).unwrap();
        let connection = rekey_policy::presets::builtin_preset("github-pat")
            .unwrap()
            .connection("fixture".into(), credential_id);
        let mut connections = vec![serde_json::to_value(connection).unwrap()];
        connections.extend(extra.connections);
        let derived = (!extra.derived_credentials.is_empty()).then_some(extra.derived_credentials);
        let generated = self
            .admin(
                admin_msg::SSH_KEY,
                json!({"action":"import","label":SSH_KEY_NAME}),
                &common::proof_and_secret_body(common::PASSWORD, &openssh_private()),
            )
            .await;
        generated.ok();
        let identity: Value = serde_json::from_slice(&generated.body).unwrap();
        let host = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
        let ssh_key = json!({
            "name": SSH_KEY_NAME, "credential_id": identity["credential"]["id"],
            "user_public_key": identity["public_key"],
            "hosts": [{"host":"synthetic.example","host_key":BASE64.encode(&ssh_blob(b"ssh-ed25519", &[host.public_key().as_ref()])),
                "rule_id":PolicyRuleId::new_random(),"effect":"approve"}],
            "git_signing": "approve", "approver": {"kind":"local-presence"},
            "session_budget": {"max_signatures":10,"max_seconds":600},
        });
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 3_600_000;
        let draft = self
            .admin(
                admin_msg::PERSONAL_POLICY_DRAFT,
                json!({"connections":connections,"ssh_keys":[ssh_key],"derived_credentials":derived,
                    "expected_policy_sha256":null,"expires_at_ms":expires}),
                &[],
            )
            .await;
        let metadata = draft.ok().clone();
        assert!(draft.body.starts_with(SIGN_PREFIX));
        let mut bundle: Value = serde_json::from_slice(&draft.body[SIGN_PREFIX.len()..]).unwrap();
        let signature = signer.sign(&SystemRandom::new(), &draft.body).unwrap();
        bundle["signature"] = BASE64URL_NOPAD.encode(signature.as_ref()).into();
        self.admin(
            admin_msg::POLICY_ACTIVATE,
            json!({"expected_vault_id":metadata["vault_id"],
                "expected_trust_sha256":metadata["trust_sha256"],"bundle_json":bundle}),
            &proof,
        )
        .await
        .ok();
        let listed = self.agent(agent_msg::LIST_CAPABILITIES, json!({})).await;
        listed.ok();
        let listed: Value = serde_json::from_slice(&listed.body).unwrap();
        self.service_url = listed["service_url"].as_str().unwrap().to_owned();
        identity
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.state.join("runtime").join(name)
    }

    async fn admin(&self, opcode: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        let metadata = serde_json::to_vec(&metadata).unwrap();
        common::call(
            &self.socket("admin.sock"),
            Channel::Admin,
            opcode,
            &metadata,
            body,
        )
        .await
    }

    async fn agent(&self, opcode: u16, metadata: Value) -> common::WireResponse {
        let metadata = serde_json::to_vec(&metadata).unwrap();
        common::call(
            &self.socket("agent.sock"),
            Channel::Agent,
            opcode,
            &metadata,
            &[],
        )
        .await
    }

    /// Number of upstream requests since the last call; each sweep step
    /// asserts it to prove a reflection was served, or a refusal sent nothing.
    fn upstream_requests(&self) -> usize {
        self.fake.take_requests().len()
    }

    async fn finish(self) {
        self.admin(
            admin_msg::SHUTDOWN,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await
        .ok();
        tokio::time::timeout(common::test_timeout(Duration::from_secs(30)), self.task)
            .await
            .expect("broker stops")
            .unwrap()
            .unwrap();
    }
}

/// Unencrypted OpenSSH private key for `SSH_SEED`, as `ssh-keygen` writes it.
fn openssh_private() -> Vec<u8> {
    let key = Ed25519KeyPair::from_seed_unchecked(&SSH_SEED).unwrap();
    let public = key.public_key().as_ref();
    let blob = ssh_blob(b"ssh-ed25519", &[public]);
    let mut private = [7_u32.to_be_bytes(), 7_u32.to_be_bytes()].concat();
    private.extend(ssh_blob(
        b"ssh-ed25519",
        &[public, &[&SSH_SEED[..], public].concat(), b"c1-sweep"],
    ));
    let padding = 8 - private.len() % 8;
    private.extend((1..=padding).map(|i| i as u8));
    let mut binary = b"openssh-key-v1\0".to_vec();
    binary.extend(ssh_blob(b"none", &[b"none", b""]));
    binary.extend_from_slice(&1_u32.to_be_bytes());
    binary.extend(ssh_blob(&blob, &[&private]));
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
        BASE64.encode(&binary)
    )
    .into_bytes()
}

/// SSH wire encoding: a sequence of length-prefixed strings.
fn ssh_blob(kind: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in std::iter::once(kind).chain(parts.iter().copied()) {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Every refused representation of `secret`, labelled for failure messages.
fn forms(label: &str, secret: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut forms = vec![(format!("{label} raw"), secret.to_vec())];
    for (name, encoding) in [
        ("base64", &BASE64),
        ("unpadded base64", &BASE64_NOPAD),
        ("base64url", &BASE64URL),
        ("unpadded base64url", &BASE64URL_NOPAD),
        ("hex", &HEXLOWER),
        ("upper-case hex", &HEXUPPER),
    ] {
        forms.push((
            format!("{label} {name}"),
            encoding.encode(secret).into_bytes(),
        ));
    }
    // A prefix such as `Bearer ` changes the base64 edge characters; the
    // interior of each of the three byte alignments stays the same.
    for offset in 0..3 {
        let mut aligned = vec![0; offset];
        aligned.extend_from_slice(secret);
        let (start, end) = ((offset * 8).div_ceil(6), aligned.len() * 8 / 6);
        for (name, encoding) in [("base64", &BASE64_NOPAD), ("base64url", &BASE64URL_NOPAD)] {
            let encoded = encoding.encode(&aligned).into_bytes();
            forms.push((
                format!("{label} {name} interior at offset {offset}"),
                encoded[start..end].to_vec(),
            ));
        }
    }
    for (name, every, upper) in [
        ("percent-encoded", false, false),
        ("upper-case percent-encoded", false, true),
        ("fully percent-encoded", true, false),
        ("upper-case fully percent-encoded", true, true),
    ] {
        forms.push((
            format!("{label} {name}"),
            percent_encode(secret, every, upper),
        ));
    }
    // Binary secrets (an SSH seed) have no JSON string forms.
    let Ok(text) = std::str::from_utf8(secret) else {
        return forms;
    };
    let quoted = serde_json::to_string(text).unwrap();
    let escaped = &quoted[1..quoted.len() - 1];
    forms.push((format!("{label} JSON-escaped"), escaped.as_bytes().to_vec()));
    forms.push((
        format!("{label} JSON-escaped with escaped solidus"),
        escaped.replace('/', "\\/").into_bytes(),
    ));
    for upper in [false, true] {
        forms.push((
            format!("{label} JSON unicode-escaped (upper={upper})"),
            unicode_escape(text, upper).into_bytes(),
        ));
    }
    forms
}

fn percent_encode(bytes: &[u8], every: bool, upper: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in bytes {
        if !every && (byte.is_ascii_alphanumeric() || b"-_.~".contains(byte)) {
            out.push(*byte);
        } else if upper {
            out.extend(format!("%{byte:02X}").into_bytes());
        } else {
            out.extend(format!("%{byte:02x}").into_bytes());
        }
    }
    out
}

fn unicode_escape(text: &str, upper: bool) -> String {
    text.chars()
        .map(|c| {
            if upper {
                format!("\\u{:04X}", c as u32)
            } else {
                format!("\\u{:04x}", c as u32)
            }
        })
        .collect()
}

/// Decodes JSON string escapes wherever they occur and keeps other bytes.
fn json_unescape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        if rest.len() >= 6 && rest.starts_with(b"\\u") {
            let unit = std::str::from_utf8(&rest[2..6])
                .ok()
                .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .and_then(char::from_u32);
            if let Some(c) = unit {
                out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                index += 6;
                continue;
            }
        }
        let simple = match rest {
            [b'\\', b'"' | b'\\' | b'/', ..] => Some(rest[1]),
            [b'\\', b'n', ..] => Some(b'\n'),
            [b'\\', b'r', ..] => Some(b'\r'),
            [b'\\', b't', ..] => Some(b'\t'),
            [b'\\', b'b', ..] => Some(8),
            [b'\\', b'f', ..] => Some(12),
            _ => None,
        };
        if let Some(byte) = simple {
            out.push(byte);
            index += 2;
        } else {
            out.push(rest[0]);
            index += 1;
        }
    }
    out
}

/// Decodes `%XX` escapes (either case) and keeps other bytes.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escape = bytes
            .get(index + 1..index + 3)
            .filter(|_| bytes[index] == b'%')
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escape {
            Some(byte) => {
                out.push(byte);
                index += 3;
            }
            None => {
                out.push(bytes[index]);
                index += 1;
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Collects every caller-visible output and fails on the first canary form.
pub(crate) struct Sweep {
    forms: Vec<(String, Vec<u8>)>,
    outputs: BTreeMap<&'static str, usize>,
}

impl Sweep {
    fn new() -> Self {
        let mut forms = forms("canary", CANARY);
        // The vault password and the SSH private key never travel on a caller
        // surface either.
        forms.extend(self::forms("vault password", common::PASSWORD));
        forms.extend(self::forms("SSH seed", &SSH_SEED));
        let key = Ed25519KeyPair::from_seed_unchecked(&SSH_SEED).unwrap();
        let raw = [&SSH_SEED[..], key.public_key().as_ref()].concat();
        forms.extend(self::forms("SSH private key", &raw));
        Self {
            forms,
            outputs: BTreeMap::new(),
        }
    }

    /// Also refuses every form of `secret`.
    pub(crate) fn refuse(&mut self, label: &str, secret: &[u8]) {
        self.forms.extend(forms(label, secret));
    }

    /// Names the first refused form in `output` or in one of its decoded views.
    fn find(&self, output: &[u8]) -> Option<&str> {
        let unescaped = json_unescape(output);
        let decoded = percent_decode(output);
        let views = [
            output.to_vec(),
            percent_decode(&unescaped),
            json_unescape(&decoded),
            unescaped,
            decoded,
        ];
        views.iter().find_map(|view| {
            self.forms
                .iter()
                .find(|(_, form)| contains(view, form))
                .map(|(name, _)| name.as_str())
        })
    }

    pub(crate) fn check(&mut self, surface: &'static str, what: &str, output: &[u8]) {
        if let Some(name) = self.find(output) {
            panic!("{surface} `{what}` returned the {name} form");
        }
        *self.outputs.entry(surface).or_default() += 1;
    }
}

#[test]
fn sweep_oracle_finds_every_form_and_partially_escaped_copies() {
    let sweep = Sweep::new();
    let authorization = [b"Bearer ".as_slice(), CANARY].concat();
    let mixed_case: Vec<u8> = CANARY
        .iter()
        .enumerate()
        .flat_map(|(index, byte)| match index % 2 {
            0 => format!("%{byte:02x}").into_bytes(),
            _ => format!("%{byte:02X}").into_bytes(),
        })
        .collect();
    let mut samples: Vec<Vec<u8>> = forms("canary", CANARY)
        .into_iter()
        .map(|(_, form)| [b"prefix ".as_slice(), &form, b" suffix"].concat())
        .collect();
    samples.extend([
        // Only the quotes in long form, inside surrounding JSON.
        format!(
            r#"{{"echo":"c1-canary/7f3a+{q}quoted{q}\\path tail=09b2e6"}}"#,
            q = unicode_escape("\"", false)
        )
        .into_bytes(),
        // JSON inside percent escapes, and percent escapes written as JSON escapes.
        percent_encode(
            json!({ "echo": std::str::from_utf8(CANARY).unwrap() })
                .to_string()
                .as_bytes(),
            true,
            false,
        ),
        String::from_utf8(percent_encode(CANARY, true, false))
            .unwrap()
            .replace('%', &unicode_escape("%", false))
            .into_bytes(),
        mixed_case,
        BASE64.encode(&authorization).into_bytes(),
        BASE64URL_NOPAD.encode(&authorization).into_bytes(),
        HEXLOWER.encode(&authorization).into_bytes(),
        common::PASSWORD.to_vec(),
    ]);
    for sample in samples {
        assert!(
            sweep.find(&sample).is_some(),
            "missed {}",
            String::from_utf8_lossy(&sample)
        );
    }
    assert_eq!(sweep.find(br#"{"ok":true,"token":"rekey"}"#), None);
}

/// Upstream responses that echo the credential; sealing must refuse each one
/// before any byte or header reaches a caller.
pub(crate) fn reflections() -> Vec<(&'static str, UpstreamResponse)> {
    let text = std::str::from_utf8(CANARY).unwrap();
    let authorization = [b"Bearer ".as_slice(), CANARY].concat();
    let reply = |status: u16, content_type: String, body: Vec<u8>| UpstreamResponse {
        status,
        headers: vec![("content-type".to_owned(), content_type)].into(),
        body: body.into(),
    };
    let plain = |body: Vec<u8>| reply(200, "text/plain".into(), body);
    let json = |body: String| reply(200, "application/json".into(), body.into_bytes());
    vec![
        ("raw body", plain(CANARY.to_vec())),
        ("base64 body", plain(BASE64.encode(CANARY).into_bytes())),
        (
            "base64url body",
            plain(BASE64URL_NOPAD.encode(CANARY).into_bytes()),
        ),
        ("hex body", plain(HEXUPPER.encode(CANARY).into_bytes())),
        ("percent body", plain(percent_encode(CANARY, true, true))),
        (
            "JSON-escaped body",
            json(json!({ "echo": text }).to_string()),
        ),
        (
            "unicode-escaped body",
            json(format!(r#"{{"echo":"{}"}}"#, unicode_escape(text, false))),
        ),
        (
            "authorization echo",
            plain(BASE64.encode(&authorization).into_bytes()),
        ),
        (
            "error status echo",
            reply(
                401,
                "text/plain".into(),
                format!("bad credentials: {text}").into_bytes(),
            ),
        ),
        (
            "header echo",
            reply(
                200,
                format!("text/plain; charset={}", BASE64URL_NOPAD.encode(CANARY)),
                b"{}".to_vec(),
            ),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1_no_caller_surface_returns_the_canary_in_any_encoding() {
    let f = Fixture::start().await;
    let mut sweep = Sweep::new();
    service::http_sweep(&f, &mut sweep).await;
    service::ssh_sweep(&f, &mut sweep).await;
    // The CLI and MCP drivers block on child processes; the broker keeps
    // serving on the runtime's worker threads.
    cli::sweep(&f, &mut sweep);
    mcp::sweep(&f, &mut sweep);
    // Every surface really ran: a skipped step must not pass as clean.
    let reflected = reflections().len();
    for (surface, minimum) in [
        ("http", reflected + 14),
        ("ssh", 4),
        ("cli", 2 * (reflected + 20)),
        ("mcp", reflected + 22),
    ] {
        let seen = sweep.outputs.get(surface).copied().unwrap_or(0);
        assert!(seen >= minimum, "{surface}: {seen} outputs checked");
    }
    f.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1_t1_oauth_llm_stream_and_ssh_approval_never_return_root_material() {
    paths::sweep().await;
}
