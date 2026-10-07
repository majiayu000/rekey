//! Exercise the production admission/supervisor/Authority path without an IPC
//! listener. Signature verification, SQLite transactions and terminal ownership
//! are real; policy signer, local approval decision and upstream are synthetic.
use super::*;
use crate::active_policy::ActivePolicy;
use crate::audit::spawn_terminal_worker;
use crate::execution_supervisor::{ExecutionSupervisorHandle, HttpExecution};
use crate::lifecycle::Lifecycle;
use crate::session::SessionRegistry;
use crate::testing::FakeUpstreamTransport;
use crate::upstream::UpstreamResponse;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::action::FixedMethod;
use rekey_domain::connection::{ConnectionLlmLimits, MethodClass, MethodSelector};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{ApprovalId, PolicyRuleId, PolicySignerId};
use rekey_vault::command::UnlockProof;
use rekey_vault::handle::AuthorityConfig;
use rekey_vault::secret::SecretInput;
use serde_json::json;
use tokio::sync::{Notify, RwLock, watch};

const PASSWORD: &[u8] = b"synthetic-admission-password";

fn proof() -> UnlockProof {
    UnlockProof::Password(SecretInput::from_slice(PASSWORD))
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: std::path::PathBuf,
    executor: Arc<ActionExecutor>,
    fake: Arc<FakeUpstreamTransport>,
    executions: ExecutionSupervisorHandle,
    shutdown: watch::Sender<bool>,
    supervisor: tokio::task::JoinHandle<Result<(), BrokerError>>,
    terminal: tokio::task::JoinHandle<()>,
    authority: std::thread::JoinHandle<()>,
}

impl Fixture {
    async fn new(hourly: u32, llm: bool) -> Self {
        Self::with_connections(hourly, llm, 1).await
    }

    async fn with_connections(hourly: u32, llm: bool, count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(PASSWORD),
            rekey_vault::crypto::kdf::Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let (authority, authority_thread) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        authority.unlock(proof()).await.unwrap();
        let credential = authority
            .credential_add(
                CredentialLabel::new("fixture").unwrap(),
                CredentialKind::OpaqueToken,
                SecretInput::from_slice(b"synthetic-upstream-key"),
                proof(),
            )
            .await
            .unwrap();
        let preset = if count > 1 {
            rekey_policy::presets::generic_preset(
                rekey_domain::action::HttpsOrigin::parse("https://api.example.com").unwrap(),
                "authorization",
                "Bearer ",
            )
            .unwrap()
        } else {
            rekey_policy::presets::builtin_preset(if llm { "openai" } else { "github-pat" })
                .unwrap()
        };
        let mut connection = preset.connection("fixture".into(), credential.id);
        connection.limits.requests_per_hour = hourly;
        for rule in &mut connection.rules {
            rule.id = PolicyRuleId::new_random();
            if matches!(rule.methods, MethodSelector::Class(MethodClass::Read)) {
                rule.effect = RuleEffect::Allow;
            }
            if matches!(rule.methods, MethodSelector::Class(MethodClass::Write))
                || (llm
                    && matches!(&rule.methods, MethodSelector::Methods(methods) if methods.contains(&FixedMethod::Post)))
            {
                rule.effect = RuleEffect::Approve;
            }
        }
        if llm {
            connection
                .rules
                .push(rekey_domain::connection::ConnectionRule {
                    id: PolicyRuleId::new_random(),
                    methods: MethodSelector::Methods(vec![FixedMethod::Post]),
                    path: "/v1/chat/completions".into(),
                    effect: RuleEffect::Approve,
                });
            connection.llm = Some(ConnectionLlmLimits {
                models: ["synthetic-model".into()].into_iter().collect(),
                max_tokens: 32,
                max_requests_per_day: 1,
                max_output_tokens_per_day: 1000,
            });
        }
        let signer = Ed25519KeyPair::from_seed_unchecked(&[47; 32]).unwrap();
        let signer_id = PolicySignerId::new_random();
        let trust = rekey_policy::parse_policy_trust(
            &serde_json::to_vec(&json!({
                "format_version":1,"signer_id":signer_id,"algorithm":"ed25519",
                "public_key":HEXLOWER.encode(signer.public_key().as_ref()),
            }))
            .unwrap(),
        )
        .unwrap();
        let connections: Vec<_> = (0..count)
            .map(|index| {
                let mut connection = connection.clone();
                if index > 0 {
                    connection.name = format!("fixture-{index}");
                    for rule in &mut connection.rules {
                        rule.id = PolicyRuleId::new_random();
                    }
                }
                connection
            })
            .collect();
        let mut bundle = json!({"format_version":1,"signer_id":signer_id,"snapshot":{
            "format_version":7,"version":1,"expires_at_ms":4_102_444_800_000_i64,
            "approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],
            "connections":connections,"ssh_keys":[],"derived_credentials":[],
        }});
        let mut sign_bytes = b"RKPOLICY\0\x01".to_vec();
        sign_bytes.extend(serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = json!(BASE64URL_NOPAD.encode(signer.sign(&sign_bytes).as_ref()));
        let now = crate::now_ts().unwrap();
        let bundle = rekey_policy::parse_and_verify_policy_bundle(
            &serde_json::to_vec(&bundle).unwrap(),
            &trust,
            now,
        )
        .unwrap();
        let policy = Arc::new(RwLock::new(Some(Arc::new(
            ActivePolicy::activate_bundle(bundle, now).unwrap(),
        ))));
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let fake = Arc::new(FakeUpstreamTransport::new());
        let (terminals, terminal) = spawn_terminal_worker(authority.clone());
        let executor = Arc::new(ActionExecutor::new(
            authority,
            Arc::new(SessionRegistry::new()),
            fake.clone(),
            lifecycle,
            terminals,
            policy,
        ));
        let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
        let (shutdown, rx) = watch::channel(false);
        let supervisor = tokio::spawn(supervisor.run(rx));
        Self {
            _dir: dir,
            state,
            executor,
            fake,
            executions,
            shutdown,
            supervisor,
            terminal,
            authority: authority_thread,
        }
    }

    fn request(
        method: FixedMethod,
        path: &str,
        body: &[u8],
        approval: Option<ApprovalRequestId>,
    ) -> LocalExecuteRequest {
        let mut meta = CallMeta::http("fixture".into(), method, path.into());
        meta.approval_request_id = approval;
        LocalExecuteRequest {
            request_id: RequestId::new_random(),
            meta,
            body: body.to_vec().into(),
            caller: "fixture".into(),
        }
    }

    async fn call(&self, request: LocalExecuteRequest) -> Result<HttpExecution, BrokerError> {
        self.executions.submit_local(request).await?.await.unwrap()
    }

    async fn approve(&self, path: &str, body: &[u8]) -> ApprovalRequestId {
        let required = self
            .call(Self::request(FixedMethod::Post, path, body, None))
            .await
            .err()
            .unwrap();
        let BrokerError::ApprovalRequired(required) = required else {
            panic!("expected approval, got {}", required.code())
        };
        let local = self
            .executor
            .local_calls
            .get(required.challenge_id, crate::now_ts().unwrap().as_unix_ms())
            .unwrap();
        self.executor
            .local_calls
            .decide(
                required.challenge_id,
                &local.review_sha256,
                Some(ApprovalId::new_random()),
                crate::now_ts().unwrap().as_unix_ms(),
            )
            .unwrap();
        required.challenge_id
    }

    fn state(&self, id: ApprovalRequestId) -> ipc::LocalApprovalState {
        self.executor
            .local_calls
            .get(id, crate::now_ts().unwrap().as_unix_ms())
            .unwrap()
            .state
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.state)).unwrap()
    }

    fn count(&self, event: &str) -> usize {
        self.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type=?1",
                [event],
                |r| r.get(0),
            )
            .unwrap()
    }

    async fn stop(self) {
        self.shutdown.send_replace(true);
        self.supervisor.await.unwrap().unwrap();
        self.executor
            .terminals
            .wait_idle(Duration::from_secs(2))
            .await
            .ok();
        self.executor
            .authority
            .shutdown(Some(proof()))
            .await
            .unwrap();
        self.authority.join().unwrap();
        drop(self.executor);
        self.terminal.await.unwrap();
    }
}

#[tokio::test]
async fn hourly_denial_leaves_approval_retryable_in_real_authority_path() {
    let f = Fixture::new(1, false).await;
    assert!(
        f.call(Fixture::request(FixedMethod::Get, "/repos/a/b", &[], None))
            .await
            .is_ok()
    );
    let body = br#"{"title":"hourly approval"}"#;
    let id = f.approve("/repos/a/b/issues", body).await;
    for _ in 0..2 {
        let error = f
            .call(Fixture::request(
                FixedMethod::Post,
                "/repos/a/b/issues",
                body,
                Some(id),
            ))
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "BUDGET_EXCEEDED");
        assert_eq!(f.state(id), ipc::LocalApprovalState::Approved);
    }
    assert_eq!(f.count("approval.accepted"), 0);
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.fake.requests.lock().unwrap().len(), 1);
    f.stop().await;
}

#[tokio::test]
async fn daily_denial_returns_approval_and_hourly_slot_in_real_authority_path() {
    let f = Fixture::new(2, true).await;
    let body = br#"{"model":"synthetic-model","messages":[],"max_tokens":16}"#;
    let id = f.approve("/v1/chat/completions", body).await;
    f.fake.push_response(Ok(UpstreamResponse { status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#.to_vec().into() }));
    assert!(
        f.call(Fixture::request(
            FixedMethod::Post,
            "/v1/chat/completions",
            body,
            Some(id)
        ))
        .await
        .is_ok()
    );
    let id = f.approve("/v1/chat/completions", body).await;
    let error = f
        .call(Fixture::request(
            FixedMethod::Post,
            "/v1/chat/completions",
            body,
            Some(id),
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "BUDGET_EXCEEDED");
    assert_eq!(f.state(id), ipc::LocalApprovalState::Approved);
    assert_eq!(f.count("approval.accepted"), 1);
    // Non-generating LLM endpoints also share the request budget. Inspect
    // reservation availability without creating another durable execution.
    drop(
        f.executor
            .local_calls
            .reserve_rate("fixture", 2, Duration::from_secs(3600))
            .unwrap(),
    );
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.fake.requests.lock().unwrap().len(), 1);
    f.stop().await;
}

#[tokio::test]
async fn disconnected_receiver_keeps_capacity_and_busy_approval_retries_once() {
    let f = Fixture::new(1000, false).await;
    let body = br#"{"title":"busy approval"}"#;
    let id = f.approve("/repos/a/b/issues", body).await;
    let mut gates: Vec<Arc<Notify>> = Vec::new();
    for expected in 1..=4 {
        gates.push(f.fake.push_response_gated(Ok(UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: b"{}".to_vec().into(),
        })));
        let receiver = f
            .executions
            .submit_local(Fixture::request(FixedMethod::Get, "/repos/a/b", &[], None))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while f.fake.requests.lock().unwrap().len() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(receiver);
    }
    let error = f
        .call(Fixture::request(
            FixedMethod::Post,
            "/repos/a/b/issues",
            body,
            Some(id),
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "AUTHORITY_BUSY");
    assert_eq!(f.state(id), ipc::LocalApprovalState::Approved);
    assert_eq!(f.executor.lifecycle.local_in_flight(), 4);
    gates.pop().unwrap().notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.executor.lifecycle.local_in_flight() == 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (first, second) = tokio::join!(
        f.call(Fixture::request(
            FixedMethod::Post,
            "/repos/a/b/issues",
            body,
            Some(id)
        )),
        f.call(Fixture::request(
            FixedMethod::Post,
            "/repos/a/b/issues",
            body,
            Some(id)
        ))
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(f.state(id), ipc::LocalApprovalState::Consumed);
    assert_eq!(f.count("approval.accepted"), 1);
    for gate in gates {
        gate.notify_one();
    }
    f.stop().await;
}

#[tokio::test]
async fn failed_started_transaction_never_consumes_approval_or_sends_upstream() {
    let f = Fixture::new(1, false).await;
    let body = br#"{"title":"started failure"}"#;
    let id = f.approve("/repos/a/b/issues", body).await;
    f.db().execute_batch("CREATE TRIGGER reject_started BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.started' BEGIN SELECT RAISE(ABORT,'synthetic started failure'); END;").unwrap();
    let error = f
        .call(Fixture::request(
            FixedMethod::Post,
            "/repos/a/b/issues",
            body,
            Some(id),
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
    assert_eq!(f.state(id), ipc::LocalApprovalState::Approved);
    assert_eq!(f.count("execution.started"), 0);
    assert_eq!(f.count("approval.accepted"), 0);
    assert!(f.fake.requests.lock().unwrap().is_empty());
    assert_eq!(f.executor.lifecycle.local_in_flight(), 0);
    let error = f
        .call(Fixture::request(
            FixedMethod::Post,
            "/repos/a/b/issues",
            body,
            Some(id),
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "FAULTED");
    f.stop().await;
}

#[tokio::test]
async fn disconnected_receivers_cannot_exceed_global_supervised_execution_limit() {
    let f = Fixture::with_connections(1000, false, 31).await;
    let request = |index: usize| {
        let mut request = Fixture::request(FixedMethod::Get, "/repos/a/b", &[], None);
        if index > 0 {
            request.meta.connection = format!("fixture-{index}");
        }
        request
    };
    let mut gates = Vec::new();
    for count in 0..120 {
        gates.push(f.fake.push_response_gated(Ok(UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: b"{}".to_vec().into(),
        })));
        let receiver = f.executions.submit_local(request(count / 4)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while f.fake.requests.lock().unwrap().len() != count + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(receiver);
    }
    for _ in 0..5 {
        assert_eq!(
            f.call(request(30)).await.err().unwrap().code(),
            "AUTHORITY_BUSY"
        );
    }
    assert_eq!(f.executor.lifecycle.local_in_flight(), 120);
    assert_eq!(f.count("execution.started"), 120);
    gates.pop().unwrap().notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match f.call(request(30)).await {
                Ok(_) => break,
                Err(error) => assert_eq!(error.code(), "AUTHORITY_BUSY"),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for gate in gates {
        gate.notify_one();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.executor.lifecycle.local_in_flight() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.count("execution.started"), 121);
    assert_eq!(f.count("execution.finished"), 121);
    assert_eq!(f.fake.requests.lock().unwrap().len(), 121);
    f.stop().await;
}
