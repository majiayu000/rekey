//! Shared harness: boots a real broker (two UDS, authority worker, fake
//! upstream) inside a tempdir and speaks the wire protocol directly.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_domain::ids::{PolicyRuleId, RequestId};
use rekey_domain::ipc::{self, Channel, FRAME_HEADER_LEN, FrameHeader, ProofKind, admin_msg};
use rekey_vault::bootstrap::init_vault;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::secret::SecretInput;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const PASSWORD: &[u8] = b"correct horse battery staple";
pub const TEST_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};

pub struct TestBroker {
    pub dir: tempfile::TempDir,
    pub state_dir: PathBuf,
    pub fake: Arc<FakeUpstreamTransport>,
    pub serve_task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
}

pub async fn start_broker() -> TestBroker {
    start_broker_with(Duration::from_secs(300), Duration::from_secs(2)).await
}

pub async fn start_broker_with(idle_lock: Duration, drain_timeout: Duration) -> TestBroker {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    init_vault(&state_dir, &SecretInput::from_slice(PASSWORD), TEST_PARAMS).expect("init");

    let fake = Arc::new(FakeUpstreamTransport::new());
    let mut config = BrokerConfig::new(state_dir.clone());
    config.idle_lock = idle_lock;
    config.transport =
        Some(Arc::clone(&fake) as Arc<dyn rekey_broker::upstream::UpstreamTransport>);
    config.unlock_backoff_base = Duration::from_millis(20);
    config.drain_timeout = drain_timeout;
    let serve_task = tokio::spawn(async move { serve(config).await });

    let admin_sock = state_dir.join("runtime").join("admin.sock");
    for _ in 0..200 {
        if admin_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(admin_sock.exists(), "broker did not come up");

    TestBroker {
        dir,
        state_dir,
        fake,
        serve_task,
    }
}

impl TestBroker {
    pub fn admin_sock(&self) -> PathBuf {
        self.state_dir.join("runtime").join("admin.sock")
    }

    pub fn agent_sock(&self) -> PathBuf {
        self.state_dir.join("runtime").join("agent.sock")
    }

    pub async fn shutdown(self) {
        self.shutdown_keep_dir().await;
    }

    /// Shuts the broker down but keeps the state directory alive so a second
    /// broker can be booted over it.
    pub async fn shutdown_keep_dir(self) -> tempfile::TempDir {
        let body = proof_body(PASSWORD);
        // Works whether locked (empty proof also fine) or unlocked.
        let _ = call(
            &self.admin_sock(),
            Channel::Admin,
            admin_msg::SHUTDOWN,
            b"{}",
            &body,
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), self.serve_task).await;
        self.dir
    }
}

pub struct WireResponse {
    pub message_type: u16,
    pub metadata: serde_json::Value,
    pub body: Vec<u8>,
}

impl WireResponse {
    pub fn ok(&self) -> &serde_json::Value {
        assert_eq!(
            self.message_type,
            ipc::resp_msg::OK,
            "expected OK, got error: {}",
            self.metadata
        );
        &self.metadata
    }

    pub fn err_code(&self) -> String {
        assert_eq!(
            self.message_type,
            ipc::resp_msg::ERROR,
            "expected error, got {}",
            self.metadata
        );
        self.metadata["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

/// One connection, one frame, one response.
pub async fn call(
    socket: &Path,
    channel: Channel,
    message_type: u16,
    metadata: &[u8],
    body: &[u8],
) -> WireResponse {
    let mut stream = UnixStream::connect(socket).await.expect("connect");
    let header = FrameHeader {
        channel,
        flags: 0,
        message_type,
        request_id: RequestId::new_random(),
        metadata_len: metadata.len() as u32,
        body_len: body.len() as u32,
    };
    stream.write_all(&header.encode()).await.unwrap();
    stream.write_all(metadata).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut header_buf = [0u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header_buf)
        .await
        .expect("response header");
    let response = FrameHeader::decode(&header_buf).expect("decode response");
    let mut meta_buf = vec![0u8; response.metadata_len as usize];
    stream.read_exact(&mut meta_buf).await.unwrap();
    let mut body_buf = vec![0u8; response.body_len as usize];
    stream.read_exact(&mut body_buf).await.unwrap();
    WireResponse {
        message_type: response.message_type,
        metadata: serde_json::from_slice(&meta_buf).unwrap_or(serde_json::Value::Null),
        body: body_buf,
    }
}

/// Sends raw bytes and reports whether the peer replied at all.
pub async fn send_raw(socket: &Path, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(socket).await.ok()?;
    stream.write_all(bytes).await.ok()?;
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(0)) | Err(_) | Ok(Err(_)) => None,
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
    }
}

pub fn proof_body(password: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    ipc::encode_proof_body(ProofKind::Password, password, &mut body);
    body
}

pub fn proof_and_secret_body(password: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    ipc::encode_proof_and_secret_body(ProofKind::Password, password, secret, &mut body);
    body
}

pub async fn unlock(broker: &TestBroker) {
    call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        PASSWORD,
    )
    .await
    .ok();
}

pub async fn add_credential(broker: &TestBroker, label: &str, value: &[u8]) -> String {
    let meta = serde_json::json!({ "label": label, "kind": "opaque-token" });
    let response = call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        meta.to_string().as_bytes(),
        &proof_and_secret_body(PASSWORD, value),
    )
    .await;
    response.ok()["id"].as_str().unwrap().to_owned()
}

pub fn action_meta(credential_id: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "example-post",
        "credential_id": credential_id,
        "origin": "https://api.example.com",
        "method": "POST",
        "exact_path": "/v1/things",
        "auth_header": "authorization",
        "auth_prefix": "Bearer ",
        "timeout_ms": 30000,
        "request_max_bytes": 65536,
        "allowed_extra_headers": ["x-request-id"],
        "response_max_bytes": 262144,
        "allowed_response_headers": ["content-type"],
    })
}

pub async fn create_action(broker: &TestBroker, credential_id: &str) -> (String, u64) {
    let response = call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        action_meta(credential_id).to_string().as_bytes(),
        &proof_body(PASSWORD),
    )
    .await;
    let ok = response.ok();
    (
        ok["id"].as_str().unwrap().to_owned(),
        ok["version"].as_u64().unwrap(),
    )
}

pub async fn create_session(broker: &TestBroker, action_id: &str, version: u64) -> String {
    let meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 3_600_000,
        "max_uses": 100,
    });
    let response = call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &proof_body(PASSWORD),
    )
    .await;
    let ok = response.ok();
    let token = ok["capability_token"].as_str().unwrap().to_owned();
    activate_test_policy(
        broker,
        action_id,
        version,
        ok["principal_id"].as_str().unwrap(),
    )
    .await;
    token
}

pub async fn activate_test_policy(
    broker: &TestBroker,
    action_id: &str,
    action_version: u64,
    principal_id: &str,
) {
    static VERSION: AtomicU64 = AtomicU64::new(1);
    let version = VERSION.fetch_add(1, Ordering::Relaxed);
    let resource = serde_json::json!({"type": "test-action", "id": action_id});
    let snapshot = serde_json::json!({
        "format_version": 1,
        "version": version,
        "expires_at_ms": i64::MAX,
        "bindings": [{
            "action_id": action_id,
            "version": action_version,
            "resource": resource,
            "parameter_schema_id": "test-any-json/v1",
            "parameter_schema": {},
        }],
        "rules": [{
            "id": PolicyRuleId::new_random().to_string(),
            "effect": "permit",
            "principal_id": principal_id,
            "action_id": action_id,
            "version": action_version,
            "resource": resource,
            "parameters": {"kind": "any_validated"},
        }],
    });
    call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::POLICY_ACTIVATE,
        snapshot.to_string().as_bytes(),
        &proof_body(PASSWORD),
    )
    .await
    .ok();
}

pub fn execute_meta(token: &str, action_id: &str, version: u64) -> serde_json::Value {
    serde_json::json!({
        "capability_token": token,
        "action_id": action_id,
        "action_version": version,
        "content_type": "application/json",
        "extra_headers": [],
    })
}
