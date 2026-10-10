//! Synthetic software P-256 fixtures; these tests make no hardware-trust claim.
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_domain::authorization::PolicyMode;
use rekey_domain::connection::{Connection, RuleEffect};
use rekey_domain::ids::{PolicySignerId, VaultId};
use rekey_domain::ipc::{
    self, Channel, PersonalPolicyDraftMeta, PersonalPolicyDraftResponse, admin_msg,
};
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::UnixStream;

const PREFIX: &[u8] = b"RKPOLICY\0\x01";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: PathBuf,
    task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    signer: EcdsaKeyPair,
    signer_id: PolicySignerId,
    vault_id: VaultId,
    fake: Arc<FakeUpstreamTransport>,
}

impl Fixture {
    async fn new(mode: PolicyMode, install: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let initialized = rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(common::PASSWORD),
            common::TEST_PARAMS,
            mode,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let mut config = BrokerConfig::new(state.clone());
        let fake = Arc::new(FakeUpstreamTransport::new());
        config.transport = Some(fake.clone());
        config.service_port = Some(0);
        config.unlock_backoff_base = Duration::from_millis(20);
        let task = tokio::spawn(serve(config));
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let fixture = Self {
            _dir: dir,
            state,
            task,
            signer: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref())
                .unwrap(),
            signer_id: PolicySignerId::new_random(),
            vault_id: initialized.vault_id,
            fake,
        };
        let mut ready = false;
        for _ in 0..200 {
            if UnixStream::connect(fixture.socket()).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready, "synthetic broker startup");
        if install {
            fixture.unlock().await;
            fixture.install_trust().await;
        }
        fixture
    }

    fn socket(&self) -> PathBuf {
        self.state.join("runtime/admin.sock")
    }

    async fn call(&self, message: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        common::call(
            &self.socket(),
            Channel::Admin,
            message,
            &serde_json::to_vec(&metadata).unwrap(),
            body,
        )
        .await
    }

    async fn unlock(&self) {
        self.call(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
            .await
            .ok();
    }

    async fn install_trust(&self) {
        self.call(admin_msg::POLICY_TRUST_INSTALL, json!({
            "format_version": 1, "signer_id": self.signer_id, "algorithm": "secure-enclave-p256",
            "public_key": data_encoding::HEXLOWER.encode(self.signer.public_key().as_ref()),
        }), &common::proof_body(common::PASSWORD)).await.ok();
    }

    async fn seed(&self) -> Connection {
        let response = self
            .call(
                admin_msg::CREDENTIAL_ADD,
                json!({"label":"fixture","kind":"opaque-token"}),
                &common::proof_and_secret_body(common::PASSWORD, b"synthetic-connection-token"),
            )
            .await;
        rekey_policy::presets::builtin_preset("github-pat")
            .unwrap()
            .connection(
                "fixture".into(),
                serde_json::from_value(response.ok()["id"].clone()).unwrap(),
            )
    }
    async fn draft(&self, connections: Vec<Connection>) -> common::WireResponse {
        let listed = self.call(admin_msg::PROFILE_LIST, json!({}), &[]).await;
        let prior: ipc::ConnectionListResponse = serde_json::from_slice(&listed.body).unwrap();
        self.call(
            admin_msg::PERSONAL_POLICY_DRAFT,
            serde_json::to_value(PersonalPolicyDraftMeta {
                connections,
                ssh_keys: None,
                derived_credentials: None,
                expected_policy_sha256: prior.policy_sha256,
                expires_at_ms: now() + 600_000,
            })
            .unwrap(),
            &[],
        )
        .await
    }
    fn signed(&self, response: &common::WireResponse) -> Value {
        let metadata: PersonalPolicyDraftResponse =
            serde_json::from_value(response.ok().clone()).unwrap();
        metadata.validate().unwrap();
        assert!(response.body.starts_with(PREFIX));
        let mut unsigned: Value = serde_json::from_slice(&response.body[PREFIX.len()..]).unwrap();
        assert_eq!(
            serde_jcs::to_vec(&unsigned).unwrap(),
            response.body[PREFIX.len()..]
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(
                serde_jcs::to_vec(&unsigned["snapshot"]).unwrap()
            )),
            metadata.policy_sha256
        );
        unsigned["signature"] = data_encoding::BASE64URL_NOPAD
            .encode(
                self.signer
                    .sign(&SystemRandom::new(), &response.body)
                    .unwrap()
                    .as_ref(),
            )
            .into();
        unsigned
    }
    async fn activate(
        &self,
        response: &common::WireResponse,
        bundle: &Value,
    ) -> common::WireResponse {
        self.call(admin_msg::POLICY_ACTIVATE,json!({"expected_vault_id":self.vault_id,"expected_trust_sha256":response.metadata["trust_sha256"],"bundle_json":bundle}),&common::proof_body(common::PASSWORD)).await
    }
    async fn agent(&self, message: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        common::call(
            &self.state.join("runtime/agent.sock"),
            Channel::Agent,
            message,
            &serde_json::to_vec(&metadata).unwrap(),
            body,
        )
        .await
    }
    fn counts(&self) -> (i64, i64) {
        let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.state)).unwrap();
        db.query_row(
            "SELECT (SELECT count(*) FROM audit_events),(SELECT count(*) FROM policy_bundle)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }
    async fn finish(self) {
        self.call(
            admin_msg::SHUTDOWN,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await
        .ok();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn signed_connection_draft_readonly_idempotent_and_revocable() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let connection = f.seed().await;
    let before = f.counts();
    let draft = f.draft(vec![connection]).await;
    let bundle = f.signed(&draft);
    assert_eq!(f.counts(), before);
    assert_eq!(bundle["snapshot"]["format_version"], 8);
    assert_eq!(bundle["snapshot"]["profiles"], json!([]));
    assert_eq!(bundle["snapshot"]["ssh_keys"], json!([]));
    let stale = f.draft(vec![]).await;
    f.activate(&draft, &bundle).await.ok();
    let activated = f.counts();
    f.activate(&draft, &bundle).await.ok();
    assert_eq!(f.counts(), activated);
    assert_eq!(
        f.activate(&stale, &f.signed(&stale)).await.err_code(),
        "POLICY_VERSION_CONFLICT"
    );
    let empty = f.draft(vec![]).await;
    f.activate(&empty, &f.signed(&empty)).await.ok();
    let response = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&response.body).unwrap();
    assert!(list.connections.is_empty());
    f.finish().await;
}
#[tokio::test]
async fn token_free_call_and_dryrun_share_rules_without_minting_sessions() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let c = f.seed().await;
    let draft = f.draft(vec![c]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let response = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"GET","path":"/repos/a/b","dry_run":true}),
            &[],
        )
        .await;
    response.ok();
    let dry: ipc::DryRunResponse = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(dry.effect, RuleEffect::Allow);
    assert!(f.fake.take_requests().is_empty());
    let response = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"GET","path":"/repos/a/b"}),
            &[],
        )
        .await;
    response.ok();
    assert_eq!(response.body, b"{\"ok\":true}");
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].auth_value, b"Bearer synthetic-connection-token");
    let approval = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"POST","path":"/repos/a/b/issues"}),
            b"{\"title\":\"test\"}",
        )
        .await;
    assert_eq!(approval.err_code(), "APPROVAL_REQUIRED");
    assert!(f.fake.take_requests().is_empty());
    let denied = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"DELETE","path":"/repos/a/b"}),
            &[],
        )
        .await;
    assert_eq!(denied.err_code(), "DENIED");
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
    let events: Vec<String> = db
        .prepare("SELECT event_type FROM audit_events WHERE event_type LIKE 'execution.%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        events,
        vec![
            "execution.started",
            "execution.finished",
            "execution.blocked"
        ]
    );
    let malformed=f.agent(ipc::agent_msg::CALL,json!({"connection":"fixture","method":"GET","path":"/repos/a/b","capability_token":"forbidden"}),&[]).await;
    assert_eq!(malformed.err_code(), "INVALID_FRAME");
    f.finish().await;
}
#[tokio::test]
async fn reflected_secret_is_sealed_and_real_http_keys_are_rejected() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let c = f.seed().await;
    let draft = f.draft(vec![c]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    f.fake
        .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())].into(),
            body: b"synthetic-connection-token".to_vec().into(),
        }));
    let response = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"GET","path":"/repos/a/b"}),
            &[],
        )
        .await;
    assert!(
        !response
            .body
            .windows(b"synthetic-connection-token".len())
            .any(|b| b == b"synthetic-connection-token")
    );
    let list = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&list.body).unwrap();
    let client = reqwest::Client::new();
    let url = format!("{}/c/fixture/repos/a/b", list.service_url.unwrap());
    let refused = client
        .get(&url)
        .bearer_auth("synthetic-connection-token")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
    let body = refused.text().await.unwrap();
    assert!(body.contains("REAL_KEY_PRESENTED"));
    assert!(!body.contains("synthetic-connection-token"));
    for request in [
        client.get(&url),
        client
            .get(&url)
            .bearer_auth("rekey")
            .header("sec-fetch-site", "cross-site"),
        client
            .get(&url)
            .bearer_auth("rekey")
            .header("origin", "https://evil.example"),
        client
            .get(&url)
            .bearer_auth("rekey")
            .header("host", "evil.example"),
    ] {
        assert_eq!(request.send().await.unwrap().status(), 400);
    }
    assert_eq!(f.fake.take_requests().len(), 1); // only the earlier IPC call
    let accepted = client
        .get(&url)
        .bearer_auth("rekey")
        .header("sec-fetch-mode", "cors")
        .header("accept-language", "*")
        .header("x-stainless-lang", "python")
        .send()
        .await
        .unwrap();
    let status = accepted.status();
    let detail = accepted.text().await.unwrap();
    assert_eq!(status, 200, "{detail}");
    assert!(
        f.fake.take_requests().iter().all(|request| request
            .headers
            .iter()
            .all(|(name, _)| !name.starts_with("x-stainless-")
                && name != "sec-fetch-mode"
                && name != "accept-language"))
    );
    f.finish().await;
}
#[tokio::test]
async fn tampered_connection_and_unregistered_credential_cannot_activate() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let mut c = f.seed().await;
    let draft = f.draft(vec![c.clone()]).await;
    let mut signed = f.signed(&draft);
    signed["snapshot"]["connections"][0]["origin"] = json!("https://other.example");
    assert_eq!(
        f.activate(&draft, &signed).await.err_code(),
        "POLICY_INVALID"
    );
    c.credential_id = rekey_domain::ids::CredentialId::new_random();
    assert_ne!(f.draft(vec![c]).await.message_type, ipc::resp_msg::OK);
    f.finish().await;
}

#[tokio::test]
async fn one_time_approval_binds_body_and_window_never_overrides_deny_or_lock() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let c = f.seed().await;
    let draft = f.draft(vec![c]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let call = json!({"connection":"fixture","method":"POST","path":"/repos/a/b/issues"});
    let pending = f
        .agent(ipc::agent_msg::CALL, call.clone(), b"{\"title\":\"one\"}")
        .await;
    assert_eq!(pending.err_code(), "APPROVAL_REQUIRED");
    let id = pending.metadata["approval"]["challenge_id"].clone();
    let review = f
        .call(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":id}),
            &[],
        )
        .await;
    review.ok();
    assert!(String::from_utf8_lossy(&review.body).contains("one"));
    let remembered = f
        .call(
            admin_msg::DESKTOP_REMEMBER,
            json!({"lifetime_ms":604800000}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    remembered.ok();
    let mut presence = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut presence);
    let decision = json!({"approval_request_id":id,"expected_review_sha256":review.metadata["review_sha256"],"window_seconds":1800});
    f.call(admin_msg::APPROVAL_LOCAL_APPROVE, decision, &presence)
        .await
        .ok();
    let mut replay = call.clone();
    replay["approval_request_id"] = id;
    let mismatch = f
        .agent(
            ipc::agent_msg::CALL,
            replay.clone(),
            b"{\"title\":\"changed\"}",
        )
        .await;
    assert_ne!(mismatch.message_type, ipc::resp_msg::OK);
    f.agent(ipc::agent_msg::CALL, replay, b"{\"title\":\"one\"}")
        .await
        .ok();
    f.agent(ipc::agent_msg::CALL, call.clone(), b"{\"title\":\"two\"}")
        .await
        .ok();
    let denied = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"DELETE","path":"/repos/a/b"}),
            &[],
        )
        .await;
    assert_eq!(denied.err_code(), "DENIED");
    assert_eq!(f.fake.take_requests().len(), 2);
    f.call(admin_msg::LOCK, json!({}), &[]).await.ok();
    f.unlock().await;
    assert_eq!(
        f.agent(ipc::agent_msg::CALL, call, b"{\"title\":\"two\"}")
            .await
            .err_code(),
        "APPROVAL_REQUIRED"
    );
    f.finish().await;
}

#[tokio::test]
async fn failed_started_audit_never_decrypts_or_sends_upstream() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let c = f.seed().await;
    let draft = f.draft(vec![c]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
    db.execute_batch("CREATE TRIGGER reject_started BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.started' BEGIN SELECT RAISE(FAIL,'synthetic started failure'); END;").unwrap();
    let response = f
        .agent(
            ipc::agent_msg::CALL,
            json!({"connection":"fixture","method":"GET","path":"/repos/a/b"}),
            &[],
        )
        .await;
    assert_ne!(response.message_type, ipc::resp_msg::OK);
    assert!(f.fake.take_requests().is_empty());
    db.execute_batch("DROP TRIGGER reject_started;").unwrap();
    // Fault admission may already have stopped; no successful shutdown claim.
    let _ = tokio::time::timeout(Duration::from_secs(5), f.task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn llm_daily_budget_is_shared_between_ipc_and_http_callers() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let credential = f.seed().await.credential_id;
    let mut connection = rekey_policy::presets::builtin_preset("openai")
        .unwrap()
        .connection("fixture".into(), credential);
    connection.llm = Some(rekey_domain::connection::ConnectionLlmLimits {
        models: ["synthetic-model".into()].into_iter().collect(),
        max_tokens: 32,
        max_requests_per_day: 1,
        max_output_tokens_per_day: 100,
    });
    let draft = f.draft(vec![connection]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    f.fake.push_response(Ok(rekey_broker::upstream::UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#.to_vec().into(),
    }));
    let body = br#"{"model":"synthetic-model","messages":[],"max_tokens":16}"#;
    f.agent(
        ipc::agent_msg::CALL,
        json!({"connection":"fixture","method":"POST","path":"/v1/chat/completions"}),
        body,
    )
    .await
    .ok();
    assert_eq!(f.fake.take_requests().len(), 1);
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    let second = reqwest::Client::new()
        .post(format!(
            "{}/c/fixture/v1/chat/completions",
            list.service_url.unwrap()
        ))
        .bearer_auth("rekey")
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert!(!second.status().is_success());
    let denied: Value = serde_json::from_slice(&second.bytes().await.unwrap()).unwrap();
    assert_eq!(denied["code"], "BUDGET_EXCEEDED");
    assert!(denied["next"].as_str().unwrap().contains("UTC"));
    assert!(f.fake.take_requests().is_empty());
    let audit = f
        .call(admin_msg::AUDIT_QUERY, json!({"limit":100}), &[])
        .await;
    audit.ok();
    f.finish().await;
}

#[tokio::test]
async fn five_hundred_allowed_reads_require_no_presence_or_capability() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let connection = f.seed().await;
    let draft = f.draft(vec![connection]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    for _ in 0..500 {
        f.fake
            .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())].into(),
                body: zeroize::Zeroizing::new(b"{}".to_vec()),
            }));
        let response = f
            .agent(
                ipc::agent_msg::CALL,
                json!({"connection":"fixture","method":"GET","path":"/repos/owner/repo"}),
                &[],
            )
            .await;
        assert_eq!(response.ok()["status"], 200);
    }
    assert_eq!(f.fake.take_requests().len(), 500);
    let db = rusqlite::Connection::open(f.state.join("vault.sqlite3")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='approval.requested'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    drop(db);
    f.finish().await;
}
