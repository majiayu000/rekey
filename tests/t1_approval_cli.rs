//! Real `rekey aws-credentials` against the in-process Broker/Authority/SQLite
//! over UDS. The STS reply is synthetic (fake upstream) and each decision is a
//! synthetic presence proof on the admin socket; no Keychain, Secure Enclave,
//! Touch ID or Internet is used. The `rekey` binary must exist in this target
//! (`cargo test --workspace` builds it).
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::authorization::PolicyMode;
use rekey_domain::connection::{DerivedCredentialConnection, DerivedCredentialTarget, RuleEffect};
use rekey_domain::ids::{PolicySignerId, VaultId};
use rekey_domain::ipc::{self, Channel, admin_msg};
use rekey_integration::harness::{
    PASSWORD, TEST_PARAMS, WireResponse, call, proof_and_secret_body, proof_body,
};
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};

const POLICY_PREFIX: &[u8] = b"RKPOLICY\0\x01";
const ROOT_ID: &str = "AKIASYNTHETICROOT1234";
const ROOT_SECRET: &str = "SYNTHETIC-AWS-ROOT-SECRET";
const TEMP_SECRET: &str = "SYNTHETIC-TEMP-SECRET";

fn cli_binary() -> PathBuf {
    // Integration tests live in <target>/<profile>/deps; use the CLI from the same build.
    let executable = std::env::current_exe().unwrap();
    let binary = executable.parent().unwrap().parent().unwrap().join("rekey");
    assert!(
        binary.is_file(),
        "build rekey in this target before this test"
    );
    binary
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// RFC 3339 UTC for a positive Unix time (civil-from-days); keeps `time` out of this crate.
fn rfc3339(unix: i64) -> String {
    let (days, secs) = (unix / 86_400, unix % 86_400);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

struct Broker {
    _dir: tempfile::TempDir,
    state: PathBuf,
    vault_id: VaultId,
    fake: Arc<FakeUpstreamTransport>,
    task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    presence: Vec<u8>,
}

impl Broker {
    fn admin_sock(&self) -> PathBuf {
        self.state.join("runtime/admin.sock")
    }
    async fn admin(&self, message: u16, metadata: Value, body: &[u8]) -> WireResponse {
        let metadata = serde_json::to_vec(&metadata).unwrap();
        call(&self.admin_sock(), Channel::Admin, message, &metadata, body).await
    }
    fn upstream_requests(&self) -> usize {
        self.fake.requests.lock().unwrap().len()
    }

    /// Personal basic-mode vault with one signed `approve` AWS AssumeRole grant.
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let initialized = rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(PASSWORD),
            TEST_PARAMS,
            PolicyMode::Personal,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let fake = Arc::new(FakeUpstreamTransport::new());
        let mut config = BrokerConfig::new(state.clone());
        config.transport = Some(fake.clone());
        config.service_port = Some(0);
        config.unlock_backoff_base = Duration::from_millis(20);
        config.drain_timeout = Duration::from_secs(2);
        let mut broker = Self {
            _dir: dir,
            state,
            vault_id: initialized.vault_id,
            fake,
            task: tokio::spawn(serve(config)),
            presence: Vec::new(),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while tokio::net::UnixStream::connect(broker.admin_sock())
            .await
            .is_err()
            || tokio::net::UnixStream::connect(broker.state.join("runtime/agent.sock"))
                .await
                .is_err()
        {
            assert!(!broker.task.is_finished(), "broker exited during startup");
            assert!(tokio::time::Instant::now() < deadline, "broker startup");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        broker
            .admin(admin_msg::UNLOCK_PASSWORD, json!({}), PASSWORD)
            .await
            .ok();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
        let trust = json!({"format_version":1,"signer_id":PolicySignerId::new_random(),
            "algorithm":"secure-enclave-p256","public_key":HEXLOWER.encode(signer.public_key().as_ref())});
        broker
            .admin(
                admin_msg::POLICY_TRUST_INSTALL,
                trust,
                &proof_body(PASSWORD),
            )
            .await
            .ok();
        let root = json!({"credential_type":"aws-static-v1","access_key_id":ROOT_ID,
            "secret_access_key":ROOT_SECRET});
        let added = broker
            .admin(
                admin_msg::CREDENTIAL_ADD,
                json!({"label":"synthetic-aws-root","kind":"aws-static"}),
                &proof_and_secret_body(PASSWORD, root.to_string().as_bytes()),
            )
            .await;
        let grant = DerivedCredentialConnection {
            name: "deployment".into(),
            credential_id: serde_json::from_value(added.ok()["id"].clone()).unwrap(),
            effect: RuleEffect::Approve,
            max_ttl_seconds: 900,
            target: DerivedCredentialTarget::AwsAssumeRole {
                role_arn: "arn:aws:iam::123456789012:role/synthetic".into(),
                region: "us-east-1".into(),
                session_policy: json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                    "Action":"s3:GetObject","Resource":"arn:aws:s3:::synthetic/*"}]}),
            },
        };
        let listed = broker
            .admin(admin_msg::CONNECTION_LIST, json!({}), &[])
            .await;
        let base: ipc::ConnectionListResponse = serde_json::from_slice(&listed.body).unwrap();
        let draft = ipc::PersonalPolicyDraftMeta {
            connections: vec![],
            ssh_keys: None,
            derived_credentials: Some(vec![grant]),
            expected_policy_sha256: base.policy_sha256,
            expires_at_ms: now_ms() + 600_000,
        };
        let draft = broker
            .admin(
                admin_msg::PERSONAL_POLICY_DRAFT,
                serde_json::to_value(draft).unwrap(),
                &[],
            )
            .await;
        let trust_sha256 = draft.ok()["trust_sha256"].clone();
        let mut bundle: Value =
            serde_json::from_slice(draft.body.strip_prefix(POLICY_PREFIX).unwrap()).unwrap();
        let mut signed = POLICY_PREFIX.to_vec();
        signed.extend_from_slice(&serde_jcs::to_vec(&bundle).unwrap());
        let signature = signer.sign(&SystemRandom::new(), &signed).unwrap();
        bundle["signature"] = BASE64URL_NOPAD.encode(signature.as_ref()).into();
        let activate = json!({"expected_vault_id":broker.vault_id,
            "expected_trust_sha256":trust_sha256,"bundle_json":bundle});
        broker
            .admin(admin_msg::POLICY_ACTIVATE, activate, &proof_body(PASSWORD))
            .await
            .ok();
        // A synthetic App presence grant decides the challenges below.
        let remembered = broker
            .admin(
                admin_msg::DESKTOP_REMEMBER,
                json!({"lifetime_ms":604800000}),
                &proof_body(PASSWORD),
            )
            .await;
        remembered.ok();
        broker.presence = remembered.body;
        broker
    }

    async fn decide(&self, message: u16, id: &Value, review_sha256: &str) {
        let mut proof = Vec::new();
        ipc::encode_proof_body(ipc::ProofKind::Presence, &self.presence, &mut proof);
        let decision = json!({"approval_request_id":id,"expected_review_sha256":review_sha256});
        self.admin(message, decision, &proof).await.ok();
    }

    async fn pending(&self) -> (Value, String) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let listed = self
                .admin(admin_msg::APPROVAL_PENDING, json!({}), &[])
                .await;
            if let Some(id) = listed.ok()["challenges"].as_array().unwrap().first() {
                let id = id["approval_request_id"].clone();
                let review = self
                    .admin(
                        admin_msg::APPROVAL_LOCAL_REVIEW,
                        json!({"approval_request_id":id}),
                        &[],
                    )
                    .await;
                let body: Value = serde_json::from_slice(&review.body).unwrap();
                assert_eq!(
                    body["canonical_request"]["agent_receives_temporary_credential"],
                    true
                );
                let hash = review.ok()["review_sha256"].as_str().unwrap().to_owned();
                return (id, hash);
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the waiting CLI never produced a local approval"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn events(&self, event_type: &str) -> usize {
        let page = self
            .admin(admin_msg::AUDIT_QUERY, json!({"limit":100}), &[])
            .await;
        page.ok();
        let page: Value = serde_json::from_slice(&page.body).unwrap();
        let rows = page["events"].as_array().unwrap();
        rows.iter()
            .filter(|e| e["event_type"] == event_type)
            .count()
    }

    async fn stop(self) {
        self.admin(admin_msg::SHUTDOWN, json!({}), &proof_body(PASSWORD))
            .await
            .ok();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn spawn_cli(state: &Path, extra: &[&str]) -> tokio::task::JoinHandle<Output> {
    let mut command = Command::new(cli_binary());
    command
        .arg("--state-dir")
        .arg(state)
        .args(["aws-credentials", "deployment"])
        .args(extra)
        .env("REKEY_OUTPUT", "json")
        .stdin(Stdio::null());
    tokio::task::spawn_blocking(move || {
        let output = command.output().unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(ROOT_SECRET) && !text.contains(ROOT_ID));
        }
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TEMP_SECRET));
        output
    })
}

fn approval_required(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "APPROVAL_REQUIRED");
    error
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_process_waits_for_local_approval_then_issues_once() {
    let broker = Broker::start().await;
    let expires = now_ms() / 1000 + 600;
    let xml = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIASYNTHETICTEMP1234</AccessKeyId><SecretAccessKey>{TEMP_SECRET}</SecretAccessKey><SessionToken>SYNTHETIC-TEMP-SESSION</SessionToken><Expiration>{}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>",
        rfc3339(expires)
    );
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/xml".to_owned())].into(),
        body: xml.into_bytes().into(),
    }));

    // Each challenge below is created by the waiting CLI's own first request,
    // so a decision can never land before the CLI asked for it.
    // A rejected wait returns that original challenge and never reissues.
    let cli = spawn_cli(&broker.state, &[]);
    let (id, hash) = broker.pending().await;
    broker
        .decide(admin_msg::APPROVAL_LOCAL_REJECT, &id, &hash)
        .await;
    let rejected = approval_required(&cli.await.unwrap());
    assert_eq!(rejected["approval"]["challenge_id"], id);
    assert_eq!(broker.upstream_requests(), 0);

    // The default command waits; one approval issues exactly one STS call.
    let cli = spawn_cli(&broker.state, &[]);
    let (id, hash) = broker.pending().await;
    assert_eq!(broker.upstream_requests(), 0, "no issuance before approval");
    broker
        .decide(admin_msg::APPROVAL_LOCAL_APPROVE, &id, &hash)
        .await;
    let issued = cli.await.unwrap();
    assert!(
        issued.status.success(),
        "{}",
        String::from_utf8_lossy(&issued.stderr)
    );
    // stdout is exactly the credential_process document.
    let document: Value = serde_json::from_slice(&issued.stdout).unwrap();
    assert_eq!(document["Version"], 1);
    assert_eq!(document["AccessKeyId"], "ASIASYNTHETICTEMP1234");
    assert_eq!(document["SecretAccessKey"], TEMP_SECRET);
    assert_eq!(document["Expiration"], rfc3339(expires));
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 1, "the approval is consumed by one retry");
    assert_eq!(
        (&*requests[0].host, &*requests[0].method),
        ("sts.us-east-1.amazonaws.com", "POST")
    );
    assert_eq!(broker.events("credential.derived_issued").await, 1);
    assert_eq!(broker.events("approval.accepted").await, 1);

    // --no-wait keeps the immediate refusal: no wait and no STS call.
    let refused = approval_required(&spawn_cli(&broker.state, &["--no-wait"]).await.unwrap());
    assert_eq!(
        broker.pending().await.0,
        refused["approval"]["challenge_id"]
    );
    assert_eq!(broker.upstream_requests(), 0);
    broker.stop().await;
}
