//! Exercise the production admission/supervisor/Authority path without an IPC
//! listener. Signature verification, SQLite transactions and terminal ownership
//! are real; policy signer, local approval decision and upstream are synthetic.
use super::*;
use crate::active_policy::ActivePolicy;
use crate::audit::{StartedAuditGuard, spawn_terminal_worker};
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
        Self::build(hourly, llm, count, false).await
    }

    async fn build(hourly: u32, llm: bool, count: usize, oauth: bool) -> Self {
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
            if oauth {
                rekey_domain::authorization::PolicyMode::Personal
            } else {
                rekey_domain::authorization::PolicyMode::Team
            },
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let (authority, authority_thread) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        authority.unlock(proof()).await.unwrap();
        let credential = if oauth {
            authority.oauth_grant_create(
                CredentialLabel::new("fixture").unwrap(),
                SecretInput::from_slice(br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","client_secret":"synthetic-client-secret","scopes":["https://www.googleapis.com/auth/drive.readonly"],"refresh_token":"synthetic-refresh-token","expires_at_ms":null}"#),
                proof(), None,
            ).await.unwrap()
        } else {
            authority
                .credential_add(
                    CredentialLabel::new("fixture").unwrap(),
                    CredentialKind::OpaqueToken,
                    SecretInput::from_slice(b"synthetic-upstream-key"),
                    proof(),
                )
                .await
                .unwrap()
        };
        let preset = if count > 1 {
            rekey_policy::presets::generic_preset(
                rekey_domain::action::HttpsOrigin::parse("https://api.example.com").unwrap(),
                "authorization",
                "Bearer ",
            )
            .unwrap()
        } else {
            rekey_policy::presets::builtin_preset(if oauth {
                "google-drive"
            } else if llm {
                "openai"
            } else {
                "github-pat"
            })
            .unwrap()
        };
        let mut connection = preset.connection("fixture".into(), credential.id);
        connection.limits.requests_per_hour = hourly;
        if oauth {
            connection.oauth = Some(rekey_domain::connection::OAuthBinding {
                provider: rekey_domain::connection::OAuthProvider::Google,
                client_id: "synthetic-client".into(),
                scopes: ["https://www.googleapis.com/auth/drive.readonly".into()]
                    .into_iter()
                    .collect(),
            });
        }
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

#[tokio::test]
async fn oauth_refresh_authority_queue_full_is_unconfirmed() {
    use std::future::Future;
    use std::task::Poll;
    for rotated in [true, false] {
        let f = Fixture::build(1000, false, 1, true).await;
        let upstream = if rotated {
            Ok(UpstreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())].into(),
                body: br#"{"access_token":"synthetic-access","refresh_token":"synthetic-rotated","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/drive.readonly"}"#.to_vec().into(),
            })
        } else {
            Err(crate::upstream::UpstreamError::Transport)
        };
        let release = f.fake.push_response_gated(upstream);
        let admitted = f
            .executor
            .admit_connection(Fixture::request(
                FixedMethod::Get,
                "/drive/v3/files",
                &[],
                None,
            ))
            .await
            .unwrap();
        let mut run = Box::pin(admitted.run());
        std::future::poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            if f.fake.requests.lock().unwrap().is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        let db = f.db();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let ctx = ExecutionAuditContext {
            request_context: None,
            request_id: RequestId::new_random(),
            session_id: SessionId::new_random(),
            action: ActionVersionRef {
                action_id: rekey_domain::ids::ActionId::new_random(),
                version: 1,
            },
            credential_id: rekey_domain::ids::CredentialId::new_random(),
            authorization: None,
        };
        let audit = crate::audit::execution_blocked(&ctx, "synthetic-queue-blocker");
        let authority = f.executor.authority.clone();
        let mut blocker = Box::pin(authority.append_audit(audit));
        std::future::poll_fn(|cx| {
            assert!(blocker.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Count commands actually admitted to the queue. CheckIdle is
        // fire-and-forget: rejected sends cannot prove that the owner has
        // dequeued the blocker, leaving its later free slot unaccounted for.
        for _ in 0..rekey_vault::handle::DEFAULT_QUEUE_CAPACITY {
            loop {
                let mut queued = Box::pin(authority.status());
                let polled = std::future::poll_fn(|cx| Poll::Ready(queued.as_mut().poll(cx))).await;
                match polled {
                    Poll::Pending => break,
                    Poll::Ready(Err(rekey_vault::AuthorityError::AuthorityBusy)) => {
                        tokio::task::yield_now().await;
                    }
                    other => panic!("queue blocker did not hold the owner: {other:?}"),
                }
            }
        }
        assert!(matches!(
            f.executor.authority.status().await,
            Err(rekey_vault::AuthorityError::AuthorityBusy)
        ));
        release.notify_one();
        std::future::poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            if f.executor.terminals.has_pending() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        // The refresh's Busy error has now transferred its terminal to the
        // tracker. Release SQL by that observed handoff, not a sleep timer.
        db.execute_batch("COMMIT").unwrap();
        let error = run
            .await
            .err()
            .expect("saturated Authority must reject refresh persistence");
        blocker.await.unwrap();
        assert_eq!(f.fake.take_requests().len(), 1, "target must not be sent");
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(f.count("execution.indeterminate"), 1);
        assert_eq!(error.code(), "UPSTREAM_FAILED");
        assert_eq!(error.agent_message(), "upstream request failed");
        assert!(
            !error.retryable(),
            "post-refresh Busy must never invite replay"
        );
        f.stop().await;
    }
}

#[tokio::test]
async fn lost_response_terminal_worker_deadline_is_unconfirmed() {
    use std::future::Future;
    use std::task::Poll;
    let f = Fixture::new(1000, false).await;
    let release = f
        .fake
        .push_response_gated(Err(crate::upstream::UpstreamError::Transport));
    let mut admitted = f
        .executor
        .admit_connection(Fixture::request(FixedMethod::Get, "/repos/a/b", &[], None))
        .await
        .unwrap();
    admitted.effect_deadline = Instant::now() + Duration::from_millis(150);
    let mut run = Box::pin(admitted.run());
    std::future::poll_fn(|cx| {
        assert!(run.as_mut().poll(cx).is_pending());
        if f.fake.requests.lock().unwrap().is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    let db = f.db();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let unlock = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        db.execute_batch("COMMIT").unwrap();
    });
    release.notify_one();
    let error = run.await.err().expect("response is lost");
    assert!(
        !error.retryable(),
        "terminal audit timeout must never invite replay"
    );
    assert_eq!(error.code(), "UPSTREAM_FAILED");
    unlock.join().unwrap();
    f.executor
        .terminals
        .wait_idle(Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(f.fake.take_requests().len(), 1);
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.count("execution.indeterminate"), 1);
    assert_eq!(f.count("execution.blocked"), 0);
    f.stop().await;
}

#[tokio::test]
async fn terminal_guard_real_authority_busy_reply_is_unconfirmed() {
    for terminal in ["finished", "indeterminate", "blocked"] {
        let f = Fixture::new(1000, false).await;
        let ctx = ExecutionAuditContext {
            request_context: None,
            request_id: RequestId::new_random(),
            session_id: SessionId::new_random(),
            action: ActionVersionRef {
                action_id: rekey_domain::ids::ActionId::new_random(),
                version: 1,
            },
            credential_id: rekey_domain::ids::CredentialId::new_random(),
            authorization: None,
        };
        // Production terminal commits wait for capacity. This test hook gets
        // a real immediate Busy from an expired Authority mutation instead:
        // no SQLite lock or caller deadline must race the guard assertion.
        let (tracker, worker) = crate::audit::spawn_terminal_worker_with({
            let authority = f.executor.authority.clone();
            move |draft| {
                let authority = authority.clone();
                async move {
                    authority
                        .commit_audit_before(draft, Some(Instant::now()))
                        .await
                }
            }
        });
        let mut guard = StartedAuditGuard::new_for_test(&tracker, ctx);
        if terminal != "blocked" {
            guard.mark_remote_effect_started();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let error = match terminal {
            "finished" => guard.finished_until(deadline, 1, 200, 0).await,
            "indeterminate" => {
                guard
                    .indeterminate_until(deadline, "upstream-transport")
                    .await
            }
            _ => guard.blocked_until(deadline, "private-address").await,
        }
        .unwrap_err();
        assert!(tracker.wait_idle(Duration::from_secs(2)).await.is_err());
        assert!(tracker.has_failed());
        assert_eq!(f.count("execution.finished"), 0);
        assert_eq!(f.count("execution.indeterminate"), 0);
        if terminal == "blocked" {
            assert_eq!(error.code(), "AUTHORITY_BUSY");
            assert!(error.retryable());
        } else {
            assert_eq!(error.code(), "UPSTREAM_FAILED");
            assert!(
                !error.retryable(),
                "post-effect terminal Busy must never invite replay"
            );
        }
        drop(guard);
        drop(tracker);
        worker.await.unwrap();
        f.stop().await;
    }
}

#[tokio::test]
async fn proven_target_block_terminal_deadline_preserves_prior_oauth_effect() {
    use std::future::Future;
    use std::task::Poll;
    for oauth in [false, true] {
        let f = Fixture::build(1000, false, 1, oauth).await;
        if oauth {
            f.fake.push_response(Ok(UpstreamResponse {
                status: 200, headers: vec![("content-type".into(), "application/json".into())].into(),
                body: br#"{"access_token":"synthetic-access","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/drive.readonly"}"#.to_vec().into(),
            }));
        }
        let release = f
            .fake
            .push_response_gated(Err(crate::upstream::UpstreamError::Blocked(
                "private-address",
            )));
        let path = if oauth {
            "/drive/v3/files"
        } else {
            "/repos/a/b"
        };
        let mut admitted = f
            .executor
            .admit_connection(Fixture::request(FixedMethod::Get, path, &[], None))
            .await
            .unwrap();
        admitted.effect_deadline = Instant::now() + Duration::from_millis(150);
        let mut run = Box::pin(admitted.run());
        std::future::poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            if f.fake.requests.lock().unwrap().len() < 1 + usize::from(oauth) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        let db = f.db();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let unlock = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            db.execute_batch("COMMIT").unwrap();
        });
        release.notify_one();
        let error = run.await.err().unwrap();
        unlock.join().unwrap();
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(f.fake.take_requests().len(), 1 + usize::from(oauth));
        assert_eq!(f.count("execution.started"), 1);
        assert_eq!(f.count("execution.indeterminate"), usize::from(oauth));
        assert_eq!(f.count("execution.blocked"), usize::from(!oauth));
        assert_eq!(error.code(), "UPSTREAM_FAILED");
        assert_eq!(
            error.retryable(),
            !oauth,
            "only a proven no-effect execution permits retry"
        );
        f.stop().await;
    }
}

#[tokio::test]
async fn proven_stream_open_block_keeps_safe_retry_and_one_blocked_terminal() {
    let f = Fixture::new(1000, true).await;
    let body = br#"{"model":"synthetic-model","messages":[],"max_tokens":8,"stream":true}"#;
    let approval = f.approve("/v1/chat/completions", body).await;
    let admitted = f
        .executor
        .admit_connection(Fixture::request(
            FixedMethod::Post,
            "/v1/chat/completions",
            body,
            Some(approval),
        ))
        .await
        .unwrap();
    let (sender, _receiver) = tokio::sync::mpsc::channel(8);
    // The existing fake's default open_stream refuses before any IO.
    let error = admitted.run_stream(&sender).await.err().unwrap();
    assert!(error.retryable());
    assert_eq!(error.code(), "UPSTREAM_FAILED");
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.count("execution.blocked"), 1);
    assert_eq!(f.count("execution.indeterminate"), 0);
    assert!(f.fake.take_requests().is_empty());
    f.stop().await;
}

#[tokio::test]
async fn oauth_refresh_non_retryable_persistence_failure_is_unconfirmed() {
    use std::future::Future;
    use std::task::Poll;
    for epoch_changed in [false, true] {
        let f = Fixture::build(1000, false, 1, true).await;
        let release = f.fake.push_response_gated(Ok(UpstreamResponse {
            status: 200, headers: vec![("content-type".into(), "application/json".into())].into(),
            body: br#"{"access_token":"synthetic-access","refresh_token":"synthetic-rotated","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/drive.readonly"}"#.to_vec().into(),
        }));
        let admitted = f
            .executor
            .admit_connection(Fixture::request(
                FixedMethod::Get,
                "/drive/v3/files",
                &[],
                None,
            ))
            .await
            .unwrap();
        let credential_id = admitted.action.credential_id;
        let mut run = Box::pin(admitted.run());
        std::future::poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            if f.fake.requests.lock().unwrap().is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        if epoch_changed {
            // This is the production invalidation used during lock/restart.
            f.executor.oauth.clear();
        } else {
            f.executor.authority.oauth_grant_update(
                credential_id, 1,
                SecretInput::from_slice(br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","client_secret":"synthetic-client-secret","scopes":["https://www.googleapis.com/auth/drive.readonly"],"refresh_token":"synthetic-replacement","expires_at_ms":null}"#),
                proof(), None,
            ).await.unwrap();
        }
        release.notify_one();
        let error = run.await.err().unwrap();
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            f.fake.take_requests().len(),
            1,
            "only the refresh provider was contacted"
        );
        assert_eq!(f.count("execution.started"), 1);
        assert_eq!(f.count("execution.indeterminate"), 1);
        assert_eq!(f.count("execution.blocked"), 0);
        assert_eq!(error.code(), "UPSTREAM_FAILED");
        assert!(!error.retryable());
        assert_eq!(error.agent_message(), "upstream request failed");
        assert_eq!(
            error.agent_next(),
            "Check whether the upstream effect completed; do not retry automatically."
        );
        f.stop().await;
    }
}

#[tokio::test]
async fn oauth_pre_refresh_locked_preserves_authority_error() {
    let f = Fixture::build(1000, false, 1, true).await;
    let admitted = f
        .executor
        .admit_connection(Fixture::request(
            FixedMethod::Get,
            "/drive/v3/files",
            &[],
            None,
        ))
        .await
        .unwrap();
    f.executor
        .authority
        .lock("synthetic-pre-refresh-lock")
        .await
        .unwrap();
    let error = admitted.run().await.err().unwrap();
    assert_eq!(error.code(), "LOCKED");
    assert!(!error.retryable());
    assert!(f.fake.take_requests().is_empty());
    assert_eq!(f.count("execution.blocked"), 1);
    assert_eq!(f.count("execution.indeterminate"), 0);
    f.stop().await;
}

#[tokio::test]
async fn oauth_refresh_terminal_audit_failure_preserves_authority_contract() {
    use std::future::Future;
    use std::task::Poll;
    let f = Fixture::build(1000, false, 1, true).await;
    let release = f
        .fake
        .push_response_gated(Err(crate::upstream::UpstreamError::Transport));
    let admitted = f
        .executor
        .admit_connection(Fixture::request(
            FixedMethod::Get,
            "/drive/v3/files",
            &[],
            None,
        ))
        .await
        .unwrap();
    let mut run = Box::pin(admitted.run());
    std::future::poll_fn(|cx| {
        assert!(run.as_mut().poll(cx).is_pending());
        if f.fake.requests.lock().unwrap().is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    f.db().execute_batch("CREATE TRIGGER reject_refresh_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.indeterminate' BEGIN SELECT RAISE(ABORT,'synthetic terminal failure'); END;").unwrap();
    release.notify_one();
    let error = run.await.err().unwrap();
    assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
    assert!(!error.retryable());
    assert!(f.executor.terminals.has_failed());
    assert_eq!(f.fake.take_requests().len(), 1);
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.count("execution.indeterminate"), 0);
    f.stop().await;
}
