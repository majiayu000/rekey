//! Root crate: hosts workspace-level integration tests and their shared
//! harness. Never shipped.

pub mod harness {
    use std::fmt::Debug;
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

    fn must<T, E: Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    fn required_str<'a>(value: &'a serde_json::Value, field: &str) -> &'a str {
        match value.as_str() {
            Some(value) => value,
            None => panic!("missing or invalid string field: {field}"),
        }
    }

    fn required_u64(value: &serde_json::Value, field: &str) -> u64 {
        match value.as_u64() {
            Some(value) => value,
            None => panic!("missing or invalid integer field: {field}"),
        }
    }

    pub struct TestBroker {
        pub dir: tempfile::TempDir,
        pub state_dir: PathBuf,
        pub fake: Arc<FakeUpstreamTransport>,
        pub serve_task: tokio::task::JoinHandle<()>,
    }

    pub async fn start_broker() -> TestBroker {
        let dir = must(tempfile::tempdir(), "create tempdir");
        let state_dir = dir.path().join("state");
        must(
            init_vault(&state_dir, &SecretInput::from_slice(PASSWORD), TEST_PARAMS),
            "initialize test vault",
        );
        let fake = Arc::new(FakeUpstreamTransport::new());
        let mut config = BrokerConfig::new(state_dir.clone());
        config.idle_lock = Duration::from_secs(300);
        config.transport =
            Some(Arc::clone(&fake) as Arc<dyn rekey_broker::upstream::UpstreamTransport>);
        config.unlock_backoff_base = Duration::from_millis(20);
        config.drain_timeout = Duration::from_secs(2);
        let serve_task = tokio::spawn(async move {
            must(serve(config).await, "serve test broker");
        });
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

        pub async fn shutdown_keep_dir(self) -> tempfile::TempDir {
            let body = proof_body(PASSWORD);
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

    pub async fn call(
        socket: &Path,
        channel: Channel,
        message_type: u16,
        metadata: &[u8],
        body: &[u8],
    ) -> WireResponse {
        let mut stream = must(UnixStream::connect(socket).await, "connect to test broker");
        let header = FrameHeader {
            channel,
            flags: 0,
            message_type,
            request_id: RequestId::new_random(),
            metadata_len: metadata.len() as u32,
            body_len: body.len() as u32,
        };
        must(
            stream.write_all(&header.encode()).await,
            "write frame header",
        );
        must(stream.write_all(metadata).await, "write frame metadata");
        must(stream.write_all(body).await, "write frame body");

        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        must(
            stream.read_exact(&mut header_buf).await,
            "read response header",
        );
        let response = must(FrameHeader::decode(&header_buf), "decode response header");
        let mut meta_buf = vec![0u8; response.metadata_len as usize];
        must(
            stream.read_exact(&mut meta_buf).await,
            "read response metadata",
        );
        let mut body_buf = vec![0u8; response.body_len as usize];
        must(stream.read_exact(&mut body_buf).await, "read response body");
        WireResponse {
            message_type: response.message_type,
            metadata: must(
                serde_json::from_slice(&meta_buf),
                "decode response metadata",
            ),
            body: body_buf,
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
        let meta = serde_json::json!({ "label": label });
        let response = call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::CREDENTIAL_ADD,
            meta.to_string().as_bytes(),
            &proof_and_secret_body(PASSWORD, value),
        )
        .await;
        required_str(&response.ok()["id"], "id").to_owned()
    }

    pub async fn create_action(broker: &TestBroker, credential_id: &str) -> (String, u64) {
        let meta = serde_json::json!({
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
        });
        let response = call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::ACTION_CREATE,
            meta.to_string().as_bytes(),
            &proof_body(PASSWORD),
        )
        .await;
        let ok = response.ok();
        (
            required_str(&ok["id"], "id").to_owned(),
            required_u64(&ok["version"], "version"),
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
        let token = required_str(&ok["capability_token"], "capability_token").to_owned();
        activate_test_policy(
            broker,
            action_id,
            version,
            required_str(&ok["principal_id"], "principal_id"),
        )
        .await;
        token
    }

    async fn activate_test_policy(
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
}
