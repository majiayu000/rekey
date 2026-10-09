//! Opt-in native Agent acceptance. Model clients use their existing login;
//! only Rekey's provider replies and presence UI are synthetic in these tests.
//! Run after building workspace bins: cargo test -p rekey-broker --test
//! native_agents -- --ignored --test-threads=1 --nocapture
mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{ReqwestUpstreamTransport, UpstreamResponse};
use rekey_domain::action::FixedMethod;
use rekey_domain::audit::{AuditPage, AuditQuery};
use rekey_domain::authorization::PolicyMode;
use rekey_domain::connection::{Connection, MethodClass, MethodSelector, RuleEffect};
use rekey_domain::ids::{CredentialId, PolicySignerId, VaultId};
use rekey_domain::ipc::{self, Channel, admin_msg, agent_msg};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UnixStream;
use tokio::process::Command;
use zeroize::Zeroizing;

const SECRET: &str = "NATIVE-REKEY-SYNTHETIC-CANARY-20261005";
const PREFIX: &[u8] = b"RKPOLICY\0\x01";
const EXPECTED_TOOLS: [&str; 6] = [
    "list_capabilities",
    "describe",
    "call",
    "await_approval",
    "request_access",
    "await_access",
];

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

struct Fixture {
    _dir: tempfile::TempDir,
    project: PathBuf,
    state: PathBuf,
    task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    signer: EcdsaKeyPair,
    signer_id: PolicySignerId,
    vault_id: VaultId,
    credential: CredentialId,
    fake: Arc<FakeUpstreamTransport>,
    password: SecretInput,
    live: bool,
}

impl Fixture {
    async fn new() -> Self {
        let f = Self::start(
            SecretInput::from_slice(SECRET.as_bytes()),
            SecretInput::from_slice(common::PASSWORD),
            false,
        )
        .await;
        f.fake.push_response(Ok(Self::response(
            200,
            json!({"number":7,"title":"Native fixture read"}),
        )));
        f.fake.push_response(Ok(Self::response(
            201,
            json!({"number":8,"title":"Native fixture issue"}),
        )));
        f.fake.push_response(Ok(Self::response(
            200,
            json!({"number":9,"title":"Native access read"}),
        )));
        f
    }

    async fn start(credential: SecretInput, password: SecretInput, live: bool) -> Self {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let state = dir.path().join("state");
        let initialized = rekey_vault::bootstrap::init_vault(
            &state,
            &password,
            if live {
                Argon2Params::RFC9106_LOW_MEMORY
            } else {
                common::TEST_PARAMS
            },
            PolicyMode::Personal,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let fake = Arc::new(FakeUpstreamTransport::new());
        let mut config = BrokerConfig::new(state.clone());
        config.service_port = Some(0);
        config.transport = Some(if live {
            Arc::new(ReqwestUpstreamTransport)
        } else {
            fake.clone()
        });
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
        let mut f = Self {
            _dir: dir,
            project,
            state,
            task: tokio::spawn(serve(config)),
            signer,
            signer_id: PolicySignerId::new_random(),
            vault_id: initialized.vault_id,
            credential: CredentialId::new_random(),
            fake,
            password,
            live,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(f.socket(Channel::Admin)).await.is_err() {
            assert!(!f.task.is_finished(), "native fixture daemon exited");
            assert!(
                tokio::time::Instant::now() < deadline,
                "native fixture startup deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), f.password.expose())
            .await
            .ok();
        f.admin(admin_msg::POLICY_TRUST_INSTALL,
            json!({"format_version":1,"signer_id":f.signer_id,"algorithm":"secure-enclave-p256","public_key":HEXLOWER.encode(f.signer.public_key().as_ref())}),
            &f.proof()).await.ok();
        let added = f
            .admin(
                admin_msg::CREDENTIAL_ADD,
                json!({"label":"native-acceptance","kind":"opaque-token"}),
                &Zeroizing::new(common::proof_and_secret_body(
                    f.password.expose(),
                    credential.expose(),
                )),
            )
            .await;
        f.credential = serde_json::from_value(added.ok()["id"].clone()).unwrap();
        f.activate(false).await;
        f
    }

    fn response(status: u16, value: Value) -> UpstreamResponse {
        UpstreamResponse {
            status,
            headers: vec![("content-type".into(), "application/json".into())].into(),
            body: serde_json::to_vec(&value).unwrap().into(),
        }
    }

    fn socket(&self, channel: Channel) -> PathBuf {
        self.state.join(if channel == Channel::Admin {
            "runtime/admin.sock"
        } else {
            "runtime/agent.sock"
        })
    }

    async fn admin(&self, message: u16, meta: Value, body: &[u8]) -> common::WireResponse {
        common::call(
            &self.socket(Channel::Admin),
            Channel::Admin,
            message,
            &serde_json::to_vec(&meta).unwrap(),
            body,
        )
        .await
    }

    fn proof(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(common::proof_body(self.password.expose()))
    }

    async fn agent(&self, meta: Value, body: Value) -> common::WireResponse {
        let body = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        common::call(
            &self.socket(Channel::Agent),
            Channel::Agent,
            agent_msg::CALL,
            &serde_json::to_vec(&meta).unwrap(),
            &body,
        )
        .await
    }

    async fn activate(&self, include_access: bool) {
        let mut connections = Vec::new();
        for name in ["native", "access-native"]
            .into_iter()
            .take(if include_access { 2 } else { 1 })
        {
            let mut connection: Connection = rekey_policy::presets::builtin_preset("github-pat")
                .unwrap()
                .connection(name.into(), self.credential);
            connection.bindings.insert(
                "owner".into(),
                [if self.live { "majiayu000" } else { "example" }.into()]
                    .into_iter()
                    .collect(),
            );
            connection.bindings.insert(
                "repo".into(),
                [if self.live { "rekey" } else { "dedicated-test" }.into()]
                    .into_iter()
                    .collect(),
            );
            if self.live {
                connection.rules.retain(|rule| {
                    rule.effect != RuleEffect::Deny
                        && matches!(
                            rule.methods,
                            MethodSelector::Class(MethodClass::Read | MethodClass::Write)
                        )
                });
                for rule in &mut connection.rules {
                    rule.path = "/repos/majiayu000/rekey/**".into();
                    if rule.methods == MethodSelector::Class(MethodClass::Write) {
                        rule.methods =
                            MethodSelector::Methods(vec![FixedMethod::Post, FixedMethod::Patch]);
                        rule.path = "/repos/majiayu000/rekey/issues/**".into();
                    }
                }
            }
            connections.push(connection);
        }
        let listed = self.admin(admin_msg::PROFILE_LIST, json!({}), &[]).await;
        listed.ok();
        let editing: ipc::ConnectionListResponse = serde_json::from_slice(&listed.body).unwrap();
        let draft = self
            .admin(
                admin_msg::PERSONAL_POLICY_DRAFT,
                serde_json::to_value(ipc::PersonalPolicyDraftMeta {
                    connections,
                    ssh_keys: None,
                    derived_credentials: None,
                    expected_policy_sha256: editing.policy_sha256,
                    expires_at_ms: now() + 600_000,
                })
                .unwrap(),
                &[],
            )
            .await;
        let mut bundle: Value = serde_json::from_slice(&draft.body[PREFIX.len()..]).unwrap();
        let mut sign_bytes = PREFIX.to_vec();
        sign_bytes.extend_from_slice(&serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = BASE64URL_NOPAD
            .encode(
                self.signer
                    .sign(&SystemRandom::new(), &sign_bytes)
                    .unwrap()
                    .as_ref(),
            )
            .into();
        self.admin(admin_msg::POLICY_ACTIVATE,
            json!({"expected_vault_id":self.vault_id,"expected_trust_sha256":draft.ok()["trust_sha256"],"bundle_json":bundle}),
            &self.proof()).await.ok();
    }

    async fn respond_as_fixture_user(&self, approved: &mut BTreeSet<String>, access: &mut bool) {
        let pending = self
            .admin(admin_msg::APPROVAL_PENDING, json!({}), &[])
            .await;
        for challenge in pending.ok()["challenges"].as_array().unwrap() {
            let id = challenge["approval_request_id"].as_str().unwrap();
            if approved.insert(id.into()) {
                let review = self
                    .admin(
                        admin_msg::APPROVAL_LOCAL_REVIEW,
                        json!({"approval_request_id":id}),
                        &[],
                    )
                    .await;
                review.ok();
                let body: Value = serde_json::from_slice(&review.body).unwrap();
                assert_eq!(
                    body["canonical_request"]["path"],
                    "/repos/example/dedicated-test/issues"
                );
                assert_eq!(body["canonical_request"]["method"], "POST");
                assert_eq!(
                    self.fake.requests.lock().unwrap().len(),
                    1,
                    "write sent before local approval"
                );
                let remember = self
                    .admin(
                        admin_msg::DESKTOP_REMEMBER,
                        json!({"lifetime_ms":604800000}),
                        &self.proof(),
                    )
                    .await;
                remember.ok();
                let mut proof = Vec::new();
                ipc::encode_proof_body(ipc::ProofKind::Presence, &remember.body, &mut proof);
                self.admin(admin_msg::APPROVAL_LOCAL_APPROVE,
                    json!({"approval_request_id":id,"expected_review_sha256":review.metadata["review_sha256"]}), &proof).await.ok();
            }
        }
        if !*access && self.fake.requests.lock().unwrap().len() >= 2 {
            let listed = self
                .admin(admin_msg::ACCESS_RESOLVE, json!({"action":"list"}), &[])
                .await;
            listed.ok();
            let requests: Value = serde_json::from_slice(&listed.body).unwrap();
            for request in requests["requests"].as_array().unwrap() {
                if request["status"] == "PENDING" && request["connection"] == "access-native" {
                    self.activate(true).await;
                    self.admin(admin_msg::ACCESS_RESOLVE,
                        json!({"action":"resolve","request_id":request["request_id"],"granted":true,"block_caller":false}),
                        &self.proof()).await.ok();
                    *access = true;
                }
            }
        }
    }

    async fn finish(self) {
        self.admin(admin_msg::SHUTDOWN, json!({}), &self.proof())
            .await
            .ok();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

async fn captured(stream: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut bytes = Vec::new();
    stream
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert!(
        bytes.len() <= 4 * 1024 * 1024,
        "native trace exceeded its limit"
    );
    bytes
}

fn inspect(value: &Value, tools: &mut BTreeSet<String>, codes: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("tool_use")
                && let Some(name) = object
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(|s| s.strip_prefix("mcp__rekey__"))
            {
                tools.insert(name.into());
            }
            if object.get("type").and_then(Value::as_str) == Some("mcp_tool_call")
                && object.get("server").and_then(Value::as_str) == Some("rekey")
                && let Some(name) = object.get("tool").and_then(Value::as_str)
            {
                tools.insert(name.into());
            }
            for key in ["code", "status", "state"] {
                if let Some(v) = object.get(key) {
                    codes.insert(
                        v.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| v.to_string()),
                    );
                }
            }
            for child in object.values() {
                inspect(child, tools, codes);
            }
        }
        Value::Array(array) => {
            for child in array {
                inspect(child, tools, codes);
            }
        }
        Value::String(text) => {
            if text.starts_with('{')
                && let Ok(nested) = serde_json::from_str::<Value>(text)
            {
                inspect(&nested, tools, codes);
            }
        }
        _ => {}
    }
}

const SYNTHETIC_PROMPT: &str = r#"Perform this isolated Rekey acceptance sequence using actual MCP calls, not guesses. Use only Rekey tools; do not read files, run shell commands, use internet tools, inspect auth or ask for keys. A fixture user responds to local approvals and access requests. Follow every step in order:
1. list_capabilities, then describe operation github.get_issue.
2. call operation github.get_issue, connection native, args {"owner":"example","repo":"dedicated-test","number":"7"}; expect title Native fixture read.
3. call operation github.create_issue, connection native, args {"owner":"example","repo":"dedicated-test","title":"Native fixture issue"}. It must first return APPROVAL_REQUIRED. Call await_approval using that error's challenge_id as request_id, timeout_s 120. If still pending, wait again. After approved, explicitly repeat exactly the original call/args with approval_request_id set to the same challenge ID. Expect HTTP201, number8. Never repeat a successful write.
4. request_access connection access-native (omit provider), operation github.get_issue, reason Need the second requested connection. Call await_access with its returned request_id, timeout_s120. After GRANTED, call github.get_issue, connection access-native, args {"owner":"example","repo":"dedicated-test","number":"9"}. Expect title Native access read.
Report the observed steps, including APPROVAL_REQUIRED, approved replay201 and GRANTED. Do not approve requests yourself."#;

fn native_command(client: &str, project: &Path, socket: &Path, prompt: &str) -> Command {
    let binary = env!("CARGO_BIN_EXE_rekey-mcp");
    let args = ["--agent-socket", socket.to_str().unwrap()];
    let mut command = Command::new(client);
    if client == "claude" {
        // The acceptance uses the CLI's existing claude.ai login. Ambient
        // endpoint/auth overrides belong to other sessions and are not copied.
        command
            .env_remove("ANTHROPIC_AUTH_TOKEN")
            .env_remove("ANTHROPIC_BASE_URL")
            .env_remove("ANTHROPIC_API_KEY");
        command.args([
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--disable-slash-commands",
            "--no-chrome",
            "--setting-sources",
            "",
            "--tools",
            "",
            "--allowedTools",
            "mcp__rekey__*",
            "--permission-mode",
            "dontAsk",
            "--max-budget-usd",
            "2",
            "--settings",
            "{\"disableAllHooks\":true}",
        ]);
        command
            .arg("--mcp-config")
            .arg(json!({"mcpServers":{"rekey":{"command":binary,"args":args}}}).to_string());
    } else {
        command.args([
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--sandbox",
            "danger-full-access",
            "--json",
            "-c",
            "approval_policy=\"never\"",
            "-c",
            "features.multi_agent=false",
        ]);
        command.arg("-c").arg(format!(
            "mcp_servers.rekey.command={}",
            serde_json::to_string(binary).unwrap()
        ));
        command.arg("-c").arg(format!(
            "mcp_servers.rekey.args={}",
            serde_json::to_string(&args).unwrap()
        ));
        command.arg(prompt);
    }
    command
        .current_dir(project)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

async fn acceptance(client: &str) {
    let f = Fixture::new().await;
    let mut child = native_command(
        client,
        &f.project,
        &f.socket(Channel::Agent),
        SYNTHETIC_PROMPT,
    )
    .spawn()
    .expect("native client must be installed and already logged in");
    let stdout = tokio::spawn(captured(child.stdout.take().unwrap()));
    let stderr = tokio::spawn(captured(child.stderr.take().unwrap()));
    let mut approved = BTreeSet::new();
    let mut access = false;
    let completed = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            f.respond_as_fixture_user(&mut approved, &mut access).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("native acceptance exceeded its deadline");
    let output = stdout.await.unwrap();
    let diagnostic = stderr.await.unwrap();
    for bytes in [&output, &diagnostic] {
        for secret in [SECRET.as_bytes(), common::PASSWORD] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret),
                "native trace exposed a synthetic credential or proof"
            );
        }
    }
    let mut tools = BTreeSet::new();
    let mut codes = BTreeSet::new();
    let mut event_kinds = BTreeSet::new();
    for line in output
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        if let Ok(event) = serde_json::from_slice::<Value>(line) {
            for key in ["type", "subtype"] {
                if let Some(kind) = event.get(key).and_then(Value::as_str) {
                    event_kinds.insert(kind.to_owned());
                }
            }
            inspect(&event, &mut tools, &mut codes);
        }
    }
    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(&output),
        String::from_utf8_lossy(&diagnostic)
    )
    .to_ascii_lowercase();
    let hints: Vec<_> = [
        "authentication",
        "api key",
        "quota",
        "credit",
        "permission",
        "unavailable",
        "invalid",
        "model",
        "mcp",
        "approval",
    ]
    .into_iter()
    .filter(|hint| combined.contains(hint))
    .collect();
    assert!(
        completed.success(),
        "{client} failed with {}; observed Rekey tools: {tools:?}, public codes: {codes:?}, event kinds: {event_kinds:?}, diagnostic categories: {hints:?}",
        completed.code().unwrap_or(-1)
    );
    for name in EXPECTED_TOOLS {
        assert!(
            tools.contains(name),
            "{client} did not actually invoke {name}; observed: {tools:?}, public codes: {codes:?}, diagnostic categories: {hints:?}"
        );
    }
    assert!(
        codes.contains("APPROVAL_REQUIRED") && codes.contains("201") && codes.contains("GRANTED"),
        "native tool response trace missed approval, HTTP201 or granted access"
    );
    assert_eq!(approved.len(), 1);
    assert!(
        access,
        "fixture user never granted the requested Connection"
    );
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 3, "unexpected provider calls");
    assert_eq!(
        (&*requests[0].method, &*requests[0].path),
        ("GET", "/repos/example/dedicated-test/issues/7")
    );
    assert_eq!(
        (&*requests[1].method, &*requests[1].path),
        ("POST", "/repos/example/dedicated-test/issues")
    );
    assert_eq!(
        (&*requests[2].method, &*requests[2].path),
        ("GET", "/repos/example/dedicated-test/issues/9")
    );
    let query: AuditQuery = serde_json::from_value(json!({"limit":100})).unwrap();
    let response = f
        .admin(
            admin_msg::AUDIT_QUERY,
            serde_json::to_value(&query).unwrap(),
            &[],
        )
        .await;
    response.ok();
    let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
    page.validate_for(&query).unwrap();
    assert!(
        page.events
            .iter()
            .any(|event| event.event_type == "approval.accepted")
    );
    println!(
        "PASS {client}: native MCP list/describe/read, local approval+HTTP201 replay, access+signed Connection activation+await+read; no canary in trace. Software signer and synthetic Presence only."
    );
    f.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires already logged-in native Claude Code; incurs normal model usage"]
async fn claude_code_native_approval_and_access_flow() {
    acceptance("claude").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires already logged-in native Codex; incurs normal model usage"]
async fn codex_native_approval_and_access_flow() {
    acceptance("codex").await;
}

async fn approve_live(f: &Fixture, id: &Value, method: &str, path: &str) -> bool {
    let review = f
        .admin(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":id}),
            &[],
        )
        .await;
    if review.message_type != ipc::resp_msg::OK {
        return false;
    }
    let Ok(displayed) = serde_json::from_slice::<Value>(&review.body) else {
        return false;
    };
    if displayed["canonical_request"]["path"] != path
        || displayed["canonical_request"]["method"] != method
    {
        return false;
    }
    let remembered = f
        .admin(
            admin_msg::DESKTOP_REMEMBER,
            json!({"lifetime_ms":604800000}),
            &f.proof(),
        )
        .await;
    if remembered.message_type != ipc::resp_msg::OK {
        return false;
    }
    let mut proof = Zeroizing::new(Vec::new());
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut proof);
    f.admin(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        json!({"approval_request_id":id,"expected_review_sha256":review.metadata["review_sha256"]}),
        &proof,
    )
    .await
    .message_type
        == ipc::resp_msg::OK
}

async fn live_write(f: &Fixture, method: &str, path: &str, body: Value) -> common::WireResponse {
    let mut meta = json!({"connection":"native","method":method,"path":path});
    let pending = f.agent(meta.clone(), body.clone()).await;
    if pending.metadata["code"] == "APPROVAL_REQUIRED" {
        let id = &pending.metadata["approval"]["challenge_id"];
        if approve_live(f, id, method, path).await {
            meta["approval_request_id"] = id.clone();
            return f.agent(meta, body).await;
        }
    }
    pending
}

async fn live_read(f: &Fixture, client: &str, key: &[u8]) -> bool {
    let prompt = "Use only the actual Rekey MCP tools. Do not read files, run commands, inspect auth, request keys or make any write. Call list_capabilities, describe github.list_issues, then call github.list_issues with connection native and args owner majiayu000, repo rekey. Report the actual HTTP status and issue count. This is an authorized read of the real acceptance repository.";
    let Ok(mut child) =
        native_command(client, &f.project, &f.socket(Channel::Agent), prompt).spawn()
    else {
        return false;
    };
    let stdout = tokio::spawn(captured(child.stdout.take().unwrap()));
    let stderr = tokio::spawn(captured(child.stderr.take().unwrap()));
    let completed = match tokio::time::timeout(Duration::from_secs(180), child.wait()).await {
        Ok(Ok(status)) => status.success(),
        _ => {
            let _ = child.kill().await;
            false
        }
    };
    let output = stdout.await.unwrap();
    let diagnostic = stderr.await.unwrap();
    for bytes in [&output, &diagnostic] {
        for private in [key, f.password.expose()] {
            assert!(
                !bytes.windows(private.len()).any(|w| w == private),
                "live native result exposed authority material"
            );
        }
    }
    let mut tools = BTreeSet::new();
    let mut codes = BTreeSet::new();
    for line in output.split(|b| *b == b'\n') {
        if let Ok(event) = serde_json::from_slice::<Value>(line) {
            inspect(&event, &mut tools, &mut codes);
        }
    }
    let read = completed
        && ["list_capabilities", "describe", "call"]
            .into_iter()
            .all(|name| tools.contains(name))
        && codes.contains("200");
    println!(
        "live {client}: exit_success={completed} native_read={read}; observed Rekey tools={tools:?}, public statuses={codes:?}"
    );
    read
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual authorized majiayu000/rekey acceptance: uses existing gh login, creates one marked issue and closes it"]
async fn live_github_native_reads_and_presence_approved_issue_cleanup() {
    // No shell, auth-file inspection, token argv/env, or secret-bearing output.
    // The existing gh credential enters this process through a private pipe.
    let token = Command::new("gh")
        .args(["auth", "token"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(token.status.success(), "existing gh login is required");
    let mut key = Zeroizing::new(token.stdout);
    while key.last().is_some_and(u8::is_ascii_whitespace) {
        key.pop();
    }
    assert!(!key.is_empty(), "existing gh login returned no credential");
    let mut password = Zeroizing::new(vec![0; 32]);
    SystemRandom::new().fill(&mut password).unwrap();
    let f = Fixture::start(
        SecretInput::from_slice(&key),
        SecretInput::from_slice(&password),
        true,
    )
    .await;
    let preflight = f
        .agent(
            json!({"connection":"native","method":"GET","path":"/repos/majiayu000/rekey/issues","query":{"per_page":"1"}}),
            Value::Null,
        )
        .await;
    let provider_message = String::from_utf8_lossy(&preflight.body).to_ascii_lowercase();
    println!(
        "live GitHub provider preflight: HTTP status={} error code={} user_agent_required={} rate_limited={}",
        preflight.metadata["status"],
        preflight.metadata["code"],
        provider_message.contains("user-agent"),
        provider_message.contains("rate limit")
    );
    if preflight.message_type != ipc::resp_msg::OK || preflight.metadata["status"] != 200 {
        f.finish().await;
        panic!("real GitHub provider preflight did not return HTTP200; no issue was created");
    }
    let claude_read = live_read(&f, "claude", &key).await;
    let codex_read = live_read(&f, "codex", &key).await;
    // Domain test-helper IDs intentionally restart for each process. Use
    // independent entropy so uncertain writes can be reconciled uniquely
    // across repeated manual acceptance runs.
    let mut marker = [0; 16];
    SystemRandom::new().fill(&mut marker).unwrap();
    let title = format!("[Rekey acceptance test] {}", HEXLOWER.encode(&marker));
    let text = "Temporary authorized Rekey 0.4 acceptance issue. Real credential remains inside the temporary encrypted vault. This issue is closed by the same acceptance after verification.";
    let path = "/repos/majiayu000/rekey/issues";
    // Re-sign a fresh review base after the native calls; this cannot broaden
    // the fixed repository or exempt this write from local Presence approval.
    f.activate(false).await;
    let created = live_write(&f, "POST", path, json!({"title":title,"body":text})).await;
    let create_ok = created.message_type == ipc::resp_msg::OK && created.metadata["status"] == 201;
    println!(
        "live GitHub create: HTTP status={} error code={}",
        created.metadata["status"], created.metadata["code"]
    );
    let created_body = serde_json::from_slice::<Value>(&created.body).unwrap_or(Value::Null);
    let provider_message = created_body["message"].as_str().unwrap_or("");
    let public_diagnostics: Vec<_> = [
        "User-Agent",
        "rate limit",
        "Bad credentials",
        "Resource not accessible",
        "administrative rules",
    ]
    .into_iter()
    .filter(|category| provider_message.contains(category))
    .collect();
    println!("live GitHub provider diagnostic categories={public_diagnostics:?}");
    let mut issue = created_body["number"]
        .as_u64()
        .filter(|_| created_body["title"] == title);
    if issue.is_none() {
        // An indeterminate create is never replayed. Locate only this unique
        // marked issue so a successful remote effect can still be cleaned up.
        let listed = f.agent(json!({"connection":"native","method":"GET","path":path,"query":{"state":"all","per_page":"10","sort":"created","direction":"desc"}}), Value::Null).await;
        if listed.message_type == ipc::resp_msg::OK && listed.metadata["status"] == 200 {
            let matches = serde_json::from_slice::<Value>(&listed.body).unwrap_or(Value::Null);
            let matching: Vec<_> = matches
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| {
                    item["title"] == title
                        && item["body"] == text
                        && item.get("pull_request").is_none()
                })
                .collect();
            if matching.len() == 1 {
                issue = matching[0]["number"].as_u64();
            }
        }
    }
    let mut closed = false;
    if let Some(number) = issue {
        let exact = format!("{path}/{number}");
        let cleaned = live_write(
            &f,
            "PATCH",
            &exact,
            json!({"state":"closed","state_reason":"completed"}),
        )
        .await;
        let body = serde_json::from_slice::<Value>(&cleaned.body).unwrap_or(Value::Null);
        closed = cleaned.message_type == ipc::resp_msg::OK
            && cleaned.metadata["status"] == 200
            && body["state"] == "closed"
            && body["number"] == number;
        if !closed {
            // Reconcile an uncertain cleanup with a read; never replay it.
            let observed = f
                .agent(
                    json!({"connection":"native","method":"GET","path":exact}),
                    Value::Null,
                )
                .await;
            let body = serde_json::from_slice::<Value>(&observed.body).unwrap_or(Value::Null);
            closed = observed.message_type == ipc::resp_msg::OK
                && observed.metadata["status"] == 200
                && body["state"] == "closed"
                && body["number"] == number;
        }
        println!(
            "live GitHub marked issue: repo=majiayu000/rekey number={number} created201={create_ok} closed={closed}"
        );
    } else {
        println!("live GitHub: create201={create_ok}; no uniquely marked remote issue was found");
    }
    let query: AuditQuery = serde_json::from_value(json!({"limit":100})).unwrap();
    let audit = f
        .admin(
            admin_msg::AUDIT_QUERY,
            serde_json::to_value(&query).unwrap(),
            &[],
        )
        .await;
    audit.ok();
    let page: AuditPage = serde_json::from_slice(&audit.body).unwrap();
    page.validate_for(&query).unwrap();
    assert!(
        !audit.body.windows(key.len()).any(|w| w == key.as_slice()),
        "live audit exposed root material"
    );
    f.finish().await;
    assert!(closed, "marked acceptance issue was not confirmed closed");
    assert!(create_ok, "actual GitHub creation did not return HTTP201");
    assert!(
        claude_read && codex_read,
        "both native clients must actually read through Rekey before this live acceptance passes"
    );
}
