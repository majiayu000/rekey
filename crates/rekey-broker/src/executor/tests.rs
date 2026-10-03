use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use data_encoding::{BASE64, BASE64URL_NOPAD};
use rekey_domain::Timestamp;
use rekey_domain::authorization::Principal;
use rekey_domain::capability::SessionGrant;
use rekey_domain::ids::{ActionId, CredentialId, PrincipalId, SessionId, TenantId};
use tokio::sync::Notify;

use super::*;
use crate::audit::spawn_terminal_worker_with;

fn execution_context() -> ExecutionAuditContext {
    ExecutionAuditContext {
        request_id: RequestId::new_random(),
        session_id: SessionId::new_random(),
        action: ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        },
        credential_id: CredentialId::new_random(),
        authorization: None,
    }
}

#[test]
fn oversized_execute_response_metadata_is_rejected_before_success() {
    let headers = vec![("x-response".to_owned(), "v".repeat(65_536))];
    assert!(!response_metadata_fits(200, &headers, 0));
}

#[tokio::test]
async fn drain_linearizes_before_started() {
    let commits = Arc::new(AtomicUsize::new(0));
    let (tracker, worker) = spawn_terminal_worker_with({
        let commits = Arc::clone(&commits);
        move |_| {
            commits.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        }
    });
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running().unwrap();
    let policy = RwLock::new(None);
    let _coordinator = lifecycle.coordinate().await;
    lifecycle.enter_draining();
    let err = match commit_started_while_running(
        &lifecycle,
        &tracker,
        &policy,
        None,
        execution_context(),
        Vec::new(),
        None,
    )
    .await
    {
        Ok(_) => panic!("draining admission unexpectedly committed started"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "DRAINING");
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    drop(tracker);
    worker.await.unwrap();
}

#[tokio::test]
async fn running_coordinator_contention_fails_without_waiting() {
    let (tracker, worker) = spawn_terminal_worker_with(|_| async { Ok(()) });
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running().unwrap();
    let policy = RwLock::new(None);
    let sessions = Arc::new(SessionRegistry::new());
    sessions.open_for_admission();
    let action = ActionVersionRef {
        action_id: ActionId::new_random(),
        version: 1,
    };
    let session_id = SessionId::new_random();
    let token = sessions
        .admit(
            SessionGrant::new(
                session_id,
                Principal {
                    tenant_id: TenantId::new_random(),
                    principal_id: PrincipalId::new_random(),
                    session_id,
                },
                vec![action],
                Timestamp::from_unix_ms(0),
                60_000,
                1,
            )
            .unwrap(),
            vec![(action, 50)],
        )
        .unwrap();
    let permit = sessions
        .acquire(&token, action, Timestamp::from_unix_ms(1))
        .unwrap();
    assert_eq!(permit.timeout_ms, 50);
    assert_eq!(sessions.in_flight_total(), 1);
    let _coordinator = lifecycle.coordinate().await;

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        commit_started_while_running(
            &lifecycle,
            &tracker,
            &policy,
            None,
            execution_context(),
            Vec::new(),
            None,
        ),
    )
    .await
    .expect("final admission gate must not wait behind the drain coordinator");
    let err = match result {
        Ok(_) => panic!("contended admission unexpectedly committed started"),
        Err(err) => err,
    };
    assert_eq!(err.code(), "AUTHORITY_BUSY");
    drop(permit);
    assert_eq!(sessions.in_flight_total(), 0);
    drop(tracker);
    worker.await.unwrap();
}

#[tokio::test]
async fn changed_policy_blocks_before_started_commit() {
    let commits = Arc::new(Mutex::new(Vec::new()));
    let (tracker, worker) = spawn_terminal_worker_with({
        let commits = Arc::clone(&commits);
        move |draft| {
            commits.lock().unwrap().push(draft);
            async { Ok(()) }
        }
    });
    let lifecycle = Lifecycle::new();
    lifecycle.enter_running().unwrap();
    let policy = RwLock::new(None);
    let expected_policy = PolicyIdentity {
        signer_id: None,
        version: 1,
        policy_digest: [7; 32],
        bundle_digest: None,
    };

    let error = match commit_started_while_running(
        &lifecycle,
        &tracker,
        &policy,
        Some(expected_policy),
        execution_context(),
        Vec::new(),
        None,
    )
    .await
    {
        Ok(_) => panic!("changed policy unexpectedly committed started"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "REQUEST_DENIED");
    tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
    {
        let commits = commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].event_type, "execution.blocked");
        assert_eq!(commits[0].reason_code, "policy-changed");
    }
    drop(tracker);
    worker.await.unwrap();
}

#[test]
fn sealing_detects_direct_and_encoded_secret() {
    let secret = b"ghp_super_secret_token_value";
    let auth = b"Bearer ghp_super_secret_token_value";
    let needles = sealing_needles(secret, auth);

    assert!(contains_secret(
        b"before ghp_super_secret_token_value after",
        &needles
    ));
    let b64 = BASE64.encode(secret);
    assert!(contains_secret(format!("x{b64}y").as_bytes(), &needles));
    let url = BASE64URL_NOPAD.encode(auth);
    assert!(contains_secret(url.as_bytes(), &needles));
    let pct = percent_encode(auth, true);
    assert!(contains_secret(pct.as_bytes(), &needles));
    assert!(contains_secret(
        b"%67%68%70%5f%73%75%70%65%72%5f%73%65%63%72%65%74%5f%74%6f%6b%65%6e%5f%76%61%6c%75%65",
        &needles
    ));
    assert!(contains_secret(
        b"ghp_%73uper_%73ecret_token_value",
        &needles
    ));
    let mixed_percent = sealing_needles(b"+/=", b"+/=");
    assert!(contains_secret(b"prefix-%2B%2f%3D-suffix", &mixed_percent));
    assert!(!contains_secret(b"clean response body", &needles));

    let leak = vec![("content-type".to_owned(), format!("text/plain; {b64}"))];
    assert!(headers_contain_secret(&leak.into(), &needles));
    let clean = vec![("content-type".to_owned(), "application/json".to_owned())];
    assert!(!headers_contain_secret(&clean.into(), &needles));
}

#[tokio::test]
async fn authority_waits_respect_the_action_deadline() {
    let deadline = Instant::now() + Duration::from_millis(20);
    let error = deadline::await_authority(
        deadline,
        std::future::pending::<Result<(), AuthorityError>>(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "UPSTREAM_FAILED");
}

#[test]
fn post_response_failures_are_indeterminate() {
    assert!(upstream_failure_is_indeterminate(
        &crate::upstream::UpstreamError::ResponseTooLarge
    ));
    assert!(upstream_failure_is_indeterminate(
        &crate::upstream::UpstreamError::Blocked("redirect")
    ));
    assert!(!upstream_failure_is_indeterminate(
        &crate::upstream::UpstreamError::Blocked("private-address")
    ));
}

#[test]
fn github_uncertain_exchange_without_token_does_not_invite_retry() {
    let uncertain = github_without_token_error("exchange-timeout", true);
    assert_eq!(uncertain.code(), "UPSTREAM_INDETERMINATE");
    assert!(!uncertain.retryable());

    let definite = github_without_token_error("exchange-denied", false);
    assert_eq!(definite.code(), "UPSTREAM_FAILED");
    assert!(definite.retryable());
}

#[test]
fn github_write_post_effect_failures_do_not_invite_retry() {
    let write = github_post_effect_error("resource-transport");
    assert_eq!(write.code(), "UPSTREAM_INDETERMINATE");
    assert!(!write.retryable());

    let read = github_post_effect_error("resource-transport");
    assert_eq!(read.code(), "UPSTREAM_INDETERMINATE");
    assert!(!read.retryable());
}

#[tokio::test]
async fn cancellation_after_terminal_submission_does_not_submit_fallback() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let commits = Arc::new(AtomicUsize::new(0));
    let (tracker, worker) = spawn_terminal_worker_with({
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        let commits = Arc::clone(&commits);
        move |_| {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let commits = Arc::clone(&commits);
            async move {
                commits.fetch_add(1, Ordering::SeqCst);
                entered.notify_one();
                release.notified().await;
                Ok(())
            }
        }
    });
    let guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
    let commit = tokio::spawn(async move {
        let mut guard = guard;
        guard
            .blocked_until(Instant::now() + Duration::from_secs(1), "test-cancel")
            .await
    });
    entered.notified().await;
    commit.abort();
    drop(commit.await);
    release.notify_one();
    tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
    assert_eq!(commits.load(Ordering::SeqCst), 1);
    drop(tracker);
    worker.await.unwrap();
}

#[tokio::test]
async fn closed_remote_effect_gate_commits_one_blocked_terminal() {
    let commits = Arc::new(Mutex::new(Vec::new()));
    let (tracker, worker) = spawn_terminal_worker_with({
        let commits = Arc::clone(&commits);
        move |draft| {
            commits.lock().unwrap().push(draft);
            async { Ok(()) }
        }
    });
    let mut guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
    let lifecycle = Lifecycle::new();
    let error = try_begin_remote_effect(
        &lifecycle,
        &mut guard,
        Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "DRAINING");
    tracker.wait_idle(Duration::from_secs(1)).await.unwrap();
    {
        let commits = commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(
            commits[0].event_type,
            rekey_vault::model::event_type::EXECUTION_BLOCKED
        );
        assert_eq!(commits[0].reason_code, "remote-effect-admission-closed");
    }
    drop(guard);
    drop(tracker);
    worker.await.unwrap();
}

#[test]
fn github_comment_uncertainty_never_invites_retry() {
    let error = github_post_effect_error("resource-transport");
    assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
    assert!(!error.retryable());
}

// Real Authority actor and recovery orchestration, with no TCP or UDS listener.
mod lease_recovery {
    use super::*;
    #[cfg(feature = "lab")]
    use crate::upstream::UpstreamFuture;
    use crate::upstream::UpstreamResponse;
    #[cfg(feature = "lab")]
    use rekey_domain::action::{
        ActionName, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName, HeaderPrefix,
        HttpsOrigin, RequestPolicy, ResponsePolicy,
    };
    use rekey_domain::credential::{CredentialKind, CredentialLabel};
    use rekey_vault::command::UnlockProof;
    #[cfg(feature = "lab")]
    use rekey_vault::command::{ActionDefinition, AuditDraft};
    use rekey_vault::handle::AuthorityConfig;
    #[cfg(feature = "lab")]
    use rekey_vault::model::{LeaseExecutionContext, LeaseReceipt, LeaseSourceRef};
    use rekey_vault::secret::SecretInput;
    const PASSWORD: &[u8] = b"recovery-local-fixture";
    #[cfg(feature = "lab")]
    const LEASE: &[u8] = b"database/creds/role/exact-recovery-fixture";
    #[cfg(feature = "lab")]
    const PROFILE: &[u8] = br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"synthetic-recovery-token"}"#;
    fn proof() -> UnlockProof {
        UnlockProof::Password(SecretInput::from_slice(PASSWORD))
    }
    struct Fixture {
        _dir: tempfile::TempDir,
        state: std::path::PathBuf,
        executor: ActionExecutor,
        join: std::thread::JoinHandle<()>,
        worker: tokio::task::JoinHandle<()>,
    }
    impl Fixture {
        async fn new(transport: Arc<dyn UpstreamTransport>) -> Self {
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
            let (authority, join) =
                rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone()))
                    .unwrap();
            let (terminals, worker) = spawn_terminal_worker_with(|_| async { Ok(()) });
            Self {
                _dir: dir,
                state,
                executor: ActionExecutor::new(
                    authority,
                    Arc::new(SessionRegistry::new()),
                    transport,
                    Arc::new(Lifecycle::new()),
                    terminals,
                    Arc::new(RwLock::new(None)),
                ),
                join,
                worker,
            }
        }
        #[cfg(feature = "lab")]
        async fn pending(&self) -> LeaseReceipt {
            let authority = &self.executor.authority;
            authority.unlock(proof()).await.unwrap();
            let credential = authority
                .credential_add(
                    CredentialLabel::new("recovery").unwrap(),
                    CredentialKind::VaultDynamicSource,
                    SecretInput::from_slice(PROFILE),
                    proof(),
                )
                .await
                .unwrap();
            let action = authority
                .action_upsert(
                    None,
                    ActionDefinition {
                        native_plugin: None,
                        text_stream: None,
                        name: ActionName::new("recovery").unwrap(),
                        credential_id: credential.id,
                        origin: HttpsOrigin::parse("https://api.example.com").unwrap(),
                        method: FixedMethod::Post,
                        target: rekey_domain::action::ActionTarget::Fixed {
                            path: ExactPath::parse("/business").unwrap(),
                        },
                        auth: HeaderCredentialUse::new(
                            HeaderName::new("authorization").unwrap(),
                            HeaderPrefix::new("Bearer ").unwrap(),
                        )
                        .unwrap(),
                        timeout_ms: 30000,
                        request_policy: RequestPolicy {
                            max_body_bytes: 1024,
                            allowed_extra_headers: Default::default(),
                        },
                        response_policy: ResponsePolicy {
                            max_body_bytes: 1024,
                            allowed_headers: Default::default(),
                        },
                    },
                    proof(),
                )
                .await
                .unwrap();
            let c = LeaseExecutionContext {
                request_id: RequestId::new_random(),
                session_id: SessionId::new_random(),
                action_id: action.id,
                action_version: action.version,
                credential_id: credential.id,
                credential_version: 1,
            };
            authority
                .append_audit(AuditDraft {
                    request_id: Some(c.request_id),
                    session_id: Some(c.session_id),
                    action_id: Some(c.action_id),
                    action_version: Some(c.action_version),
                    credential_id: Some(c.credential_id),
                    credential_version: Some(1),
                    authorization: None,
                    approval: None,
                    event_type: rekey_vault::model::event_type::EXECUTION_STARTED,
                    outcome: rekey_vault::model::outcome::SUCCESS,
                    reason_code: "allowed".into(),
                    upstream_status: None,
                    latency_ms: None,
                })
                .await
                .unwrap();
            let receipt = authority
                .lease_acquire_begin(
                    c,
                    LeaseSourceRef {
                        origin: HttpsOrigin::parse("https://vault.example.com").unwrap(),
                        mount: "database".into(),
                        role: "role".into(),
                    },
                    None,
                )
                .await
                .unwrap();
            authority
                .lease_record_issued(
                    receipt.registration_id,
                    SecretInput::from_slice(LEASE),
                    crate::now_ts().unwrap().as_unix_ms(),
                    60,
                    true,
                    None,
                )
                .await
                .unwrap()
        }
        async fn stop(self) {
            let unlocked = self.executor.authority.status().await.unwrap().state == "unlocked";
            self.executor
                .authority
                .shutdown(unlocked.then(proof))
                .await
                .unwrap();
            self.join.join().unwrap();
            drop(self.executor);
            self.worker.await.unwrap();
        }
    }
    #[cfg(feature = "lab")]
    struct DelayedBuilder {
        requests: AtomicUsize,
        completed: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }
    #[cfg(feature = "lab")]
    struct DropEvidence(Arc<AtomicUsize>);
    #[cfg(feature = "lab")]
    impl Drop for DropEvidence {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[cfg(feature = "lab")]
    impl UpstreamTransport for DelayedBuilder {
        fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
            assert_eq!(request.method, FixedMethod::Post);
            assert_eq!(request.host, "vault.example.com");
            assert_eq!(request.path, "/v1/sys/leases/revoke");
            assert_eq!(
                request.auth_header.1.as_slice(),
                b"synthetic-recovery-token"
            );
            assert_eq!(
                request.body.as_slice(),
                br#"{"lease_id":"database/creds/role/exact-recovery-fixture","sync":true}"#
            );
            self.requests.fetch_add(1, Ordering::SeqCst);
            // This occurs after revoke_all calculated remaining, before its
            // relative timeout is created. Old code completes after ~650ms.
            std::thread::sleep(Duration::from_millis(350));
            let drop_evidence = DropEvidence(Arc::clone(&self.dropped));
            Box::pin(async move {
                let _drop_evidence = drop_evidence;
                tokio::time::sleep(Duration::from_millis(300)).await;
                self.completed.fetch_add(1, Ordering::SeqCst);
                Ok(UpstreamResponse {
                    status: 204,
                    headers: Vec::new().into(),
                    body: Zeroizing::new(Vec::new()),
                })
            })
        }
    }
    #[tokio::test]
    #[cfg(feature = "lab")]
    async fn absolute_recovery_deadline_cancels_delayed_exact_revoke_and_keeps_source_closed() {
        let transport = Arc::new(DelayedBuilder {
            requests: AtomicUsize::new(0),
            completed: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let fixture = Fixture::new(transport.clone()).await;
        fixture.pending().await;
        let began = Instant::now();
        let summary = fixture.executor.recover_vault_leases(true).await.unwrap();
        assert_eq!(
            summary.leases[0].outcome,
            rekey_domain::ipc::LeaseRecoveryOutcome::Unconfirmed
        );
        assert_eq!(summary.journal.pending, 1);
        assert_eq!(summary.journal.complete, 0);
        assert!(began.elapsed() < Duration::from_secs(2));
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport.dropped.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(transport.completed.load(Ordering::SeqCst), 0);
        let db = rusqlite::Connection::open(fixture.state.join("vault.sqlite3")).unwrap();
        let state: (String, String) = db
            .query_row(
                "SELECT phase,cleanup_outcome FROM vault_lease_journal",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("cleanup_started".into(), "unconfirmed".into()));
        assert_eq!(fixture.executor.lifecycle.phase(), BrokerPhase::Locked);
        assert!(!fixture.executor.lifecycle.try_begin_remote_effect());
        fixture.stop().await;
    }
    #[tokio::test]
    #[cfg(feature = "lab")]
    async fn unavailable_authority_snapshot_refuses_recovery_without_opening_admission() {
        let transport = Arc::new(DelayedBuilder {
            requests: AtomicUsize::new(0),
            completed: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let fixture = Fixture::new(transport.clone()).await;
        assert!(matches!(
            fixture.executor.recover_vault_leases(true).await,
            Err(BrokerError::Authority(AuthorityError::Locked))
        ));
        assert!(
            !fixture
                .executor
                .lease_journal_status()
                .await
                .unwrap()
                .verified
        );
        fixture.pending().await;
        assert!(matches!(
            fixture.executor.authority.fault_integrity().await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert!(matches!(
            fixture.executor.recover_vault_leases(true).await,
            Err(BrokerError::Authority(AuthorityError::Faulted))
        ));
        assert!(matches!(
            fixture.executor.recover_vault_leases(false).await,
            Err(BrokerError::Authority(AuthorityError::Faulted))
        ));
        let status = fixture.executor.lease_journal_status().await.unwrap();
        assert!(!status.verified);
        assert_eq!(status.pending, 1);
        assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.executor.lifecycle.phase(), BrokerPhase::Locked);
        assert!(!fixture.executor.lifecycle.try_begin_remote_effect());
        fixture.stop().await;
    }
    #[cfg(feature = "lab")]
    struct LateAuditFault {
        database: Mutex<Option<std::path::PathBuf>>,
        writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    }
    #[cfg(feature = "lab")]
    impl UpstreamTransport for LateAuditFault {
        fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
            assert_eq!(request.path, "/v1/sys/leases/revoke");
            assert_eq!(
                request.body.as_slice(),
                br#"{"lease_id":"database/creds/role/exact-recovery-fixture","sync":true}"#
            );
            let database =
                rusqlite::Connection::open(self.database.lock().unwrap().as_ref().unwrap())
                    .unwrap();
            database.execute_batch("CREATE TRIGGER fail_late_recovery_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.lease.revoked' BEGIN SELECT RAISE(ABORT,'synthetic-audit-fault'); END; BEGIN IMMEDIATE;").unwrap();
            *self.writer.lock().unwrap() = Some(std::thread::spawn(move || {
                // finish waits for this SQLite writer beyond its 1s await;
                // after release its audit insert faults the real owner.
                std::thread::sleep(Duration::from_millis(1200));
                database.execute_batch("ROLLBACK").unwrap();
            }));
            Box::pin(async {
                Ok(UpstreamResponse {
                    status: 204,
                    headers: Vec::new().into(),
                    body: Zeroizing::new(Vec::new()),
                })
            })
        }
    }
    #[tokio::test]
    #[cfg(feature = "lab")]
    async fn final_recovery_snapshot_rejects_late_audit_fault_after_entry_timeout() {
        let transport = Arc::new(LateAuditFault {
            database: Mutex::new(None),
            writer: Mutex::new(None),
        });
        let fixture = Fixture::new(transport.clone()).await;
        fixture.pending().await;
        *transport.database.lock().unwrap() = Some(fixture.state.join("vault.sqlite3"));
        let began = Instant::now();
        assert!(matches!(
            fixture.executor.recover_vault_leases(true).await,
            Err(BrokerError::Authority(AuthorityError::Faulted))
        ));
        assert!(began.elapsed() >= Duration::from_secs(1));
        transport
            .writer
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(
            fixture.executor.authority.status().await.unwrap().state,
            "faulted"
        );
        let snapshot = fixture
            .executor
            .authority
            .lease_recovery_batch()
            .await
            .unwrap();
        assert!(matches!(
            snapshot.unavailable,
            Some(AuthorityError::Faulted)
        ));
        assert!(!snapshot.counts.verified);
        assert_eq!(snapshot.counts.pending, 1);
        assert!(snapshot.known.is_empty());
        assert_eq!(fixture.executor.lifecycle.phase(), BrokerPhase::Locked);
        assert!(!fixture.executor.lifecycle.try_begin_remote_effect());
        fixture.stop().await;
    }
    #[tokio::test]
    async fn actor_opaque_edge_ows_seals_exact_parsed_forms_without_changing_outbound_bytes() {
        let fake = Arc::new(crate::testing::FakeUpstreamTransport::new());
        let mut f = Fixture::new(fake.clone()).await;
        f.executor.authority.unlock(proof()).await.unwrap();
        let (tracker, worker) = crate::audit::spawn_terminal_worker(f.executor.authority.clone());
        f.executor.terminals = tracker;
        let old_worker = std::mem::replace(&mut f.worker, worker);
        old_worker.await.unwrap();
        f.executor.lifecycle.enter_running().unwrap();
        let mut evidence = Vec::new();
        for (index, (secret, parsed)) in [
            (
                b" \t edge-opaque-value \t ".as_slice(),
                b"edge-opaque-value".as_slice(),
            ),
            (
                b" \t opaque-\xff-value \t ".as_slice(),
                b"opaque-\xff-value".as_slice(),
            ),
            (b" \t ".as_slice(), b"".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let credential = f
                .executor
                .authority
                .credential_add(
                    CredentialLabel::new(&format!("opaque-ows-{index}")).unwrap(),
                    CredentialKind::OpaqueToken,
                    SecretInput::from_slice(secret),
                    proof(),
                )
                .await
                .unwrap();
            let action: FixedHttpAction = serde_json::from_value(serde_json::json!({
                "id":ActionId::new_random(),"name":"opaque-ows","version":1,"enabled":true,
                "credential_id":credential.id,"origin":"https://api.example.com","method":"POST",
                "target":{"kind":"fixed","path":"/business"},"auth":{"header_name":"authorization","prefix":"Bearer "},
                "timeout_ms":30000,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},
                "response_policy":{"max_body_bytes":1024,"allowed_headers":[]}
            })).unwrap();
            action.validate().unwrap();
            let raw_auth = [b"Bearer ".as_slice(), secret].concat();
            let normalized_auth = [b"Bearer ".as_slice(), parsed].concat();
            let header_edge_auth = raw_auth.strip_suffix(b" \t ").unwrap();
            let forms: Vec<_> = sealing_needles(parsed, &normalized_auth)
                .into_iter()
                .chain(sealing_needles(parsed, header_edge_auth))
                .collect();
            // Whitespace-only credentials must not manufacture an empty/bare-scheme needle.
            let forms = if parsed.is_empty() {
                vec![Zeroizing::new(b"Bearer clean unrelated body".to_vec())]
            } else {
                forms
            };
            for form in forms.into_iter().chain(std::iter::once(Zeroizing::new(
                b"clean independent body".to_vec(),
            ))) {
                for location in ["body", "utf8-header", "nonutf8-header"] {
                    if location == "utf8-header" && std::str::from_utf8(&form).is_err() {
                        continue;
                    }
                    let clean = form.as_slice() == b"clean independent body" || parsed.is_empty();
                    let mut reflected = UpstreamResponse {
                        status: 200,
                        headers: vec![].into(),
                        body: Zeroizing::new(b"clean independent body".to_vec()),
                    };
                    if location == "body" {
                        reflected.body = form.clone();
                    } else {
                        let bytes = if location == "nonutf8-header" {
                            [b"\xff".as_slice(), &form, b"\xfe"].concat()
                        } else {
                            form.to_vec()
                        };
                        let mut headers = reqwest::header::HeaderMap::new();
                        headers.insert(
                            "x-reflection",
                            reqwest::header::HeaderValue::from_bytes(&bytes).unwrap(),
                        );
                        reflected.headers =
                            crate::upstream::ResponseHeaders::from_header_map(&headers);
                    }
                    fake.push_response(Ok(reflected));
                    let ctx = ExecutionAuditContext {
                        request_id: RequestId::new_random(),
                        session_id: SessionId::new_random(),
                        action: ActionVersionRef {
                            action_id: action.id,
                            version: 1,
                        },
                        credential_id: credential.id,
                        authorization: None,
                    };
                    let request = ExecuteRequest {
                        request_id: ctx.request_id,
                        capability_token: "unused-admitted-test".into(),
                        action: ctx.action,
                        content_type: None,
                        extra_headers: vec![],
                        params: Default::default(),
                        query: Default::default(),
                        body: vec![],
                        approval_grants: vec![],
                        local_approval_request_id: None,
                    };
                    let end = Instant::now() + Duration::from_secs(30);
                    let mut started = f
                        .executor
                        .terminals
                        .commit_started(ctx, vec![], Some(end), None)
                        .await
                        .unwrap();
                    let result = f
                        .executor
                        .run_started(
                            &mut started,
                            &request,
                            &action,
                            end,
                            &AtomicU8::new(EFFECT_NOT_STARTED),
                            None,
                        )
                        .await;
                    let sealed = matches!(result, Err(BrokerError::ResponseSecurityViolation));
                    eprintln!(
                        "OPAQUE OWS location={location} clean={clean} outcome={} business_requests=1 raw_authorization_exact=true",
                        if sealed {
                            "RESPONSE_SECURITY_VIOLATION"
                        } else if result.is_ok() {
                            "SUCCESS"
                        } else {
                            "OTHER_ERROR"
                        }
                    );
                    evidence.push(if clean { result.is_ok() } else { sealed });
                    let sent = fake.take_requests();
                    assert_eq!(sent.len(), 1);
                    assert_eq!(sent[0].auth_value, raw_auth);
                }
            }
        }
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(2))
            .await
            .unwrap();
        let db = rusqlite::Connection::open(f.state.join("vault.sqlite3")).unwrap();
        let started: usize = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.started'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(started, evidence.len());
        drop(db);
        f.stop().await;
        assert!(
            evidence.iter().all(|ok| *ok),
            "unsealed opaque outcomes: {evidence:?}"
        );
    }
}

#[tokio::test]
#[cfg(feature = "lab")]
async fn keychain_fixed_header_fake_transport_injects_and_seals_all_reflected_forms() {
    let action: FixedHttpAction = serde_json::from_value(serde_json::json!({
        "id":ActionId::new_random(),"name":"keychain-fixture","version":1,"enabled":true,
        "credential_id":CredentialId::new_random(),"origin":"https://api.example.com","method":"POST",
        "target":{"kind":"fixed","path":"/business"},"auth":{"header_name":"authorization","prefix":"Bearer "},
        "timeout_ms":30000,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},
        "response_policy":{"max_body_bytes":1024,"allowed_headers":[]}
    })).unwrap();
    assert_eq!(
        resolve_builtin(
            rekey_domain::credential::CredentialKind::MacosKeychainSource,
            &action
        )
        .unwrap(),
        BuiltInConnector::MacosKeychainSourceV1
    );
    let request = ExecuteRequest {
        request_id: RequestId::new_random(),
        capability_token: "synthetic".into(),
        action: ActionVersionRef {
            action_id: action.id,
            version: 1,
        },
        content_type: None,
        extra_headers: vec![],
        params: Default::default(),
        query: Default::default(),
        body: vec![],
        approval_grants: vec![],
        local_approval_request_id: None,
    };
    let value = b"synthetic-native-value";
    let forms = fixed_header_sealing_needles(value, b"Bearer synthetic-native-value", b"Bearer ");
    for form in forms.into_iter().chain(std::iter::once(Zeroizing::new(
        b"synthetic%2dnative-value".to_vec(),
    ))) {
        for location in ["body", "header-value", "header-name"] {
            let PreparedExecution::Opaque { upstream, needles } = prepare_fixed_header(
                &action,
                &request,
                &RenderedTarget {
                    path: action.target.fixed_path().unwrap().clone(),
                    params: Default::default(),
                    query: Default::default(),
                },
                value,
            )
            .unwrap() else {
                unreachable!()
            };
            assert_eq!(upstream.host, "api.example.com");
            assert_eq!(upstream.path, "/business");
            assert_eq!(
                upstream.auth_header.1.as_slice(),
                b"Bearer synthetic-native-value"
            );
            let mut response = crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean".to_vec()),
            };
            if location == "body" {
                response.body = form.clone();
            } else if location == "header-value" {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    "x-unlisted-reflection",
                    reqwest::header::HeaderValue::from_bytes(&form).unwrap(),
                );
                response.headers = crate::upstream::ResponseHeaders::from_header_map(&headers);
            } else {
                // HTTP header names cannot carry JSON/base64 punctuation; direct byte-name fixture remains sealed.
                response.headers =
                    vec![(String::from_utf8_lossy(&form).into_owned(), "clean".into())].into();
            }
            let fake = crate::testing::FakeUpstreamTransport::new();
            fake.push_response(Ok(response));
            let response = fake.send(upstream).await.unwrap();
            assert!(
                contains_secret(&response.body, &needles)
                    || headers_contain_secret(&response.headers, &needles)
            );
        }
    }
    let PreparedExecution::Opaque { needles, .. } = prepare_fixed_header(
        &action,
        &request,
        &RenderedTarget {
            path: action.target.fixed_path().unwrap().clone(),
            params: Default::default(),
            query: Default::default(),
        },
        value,
    )
    .unwrap() else {
        unreachable!()
    };
    assert!(!contains_secret(b"independent clean response", &needles));
}

#[tokio::test]
async fn template_targets_preserve_locked_credential_and_fixed_profile_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let password =
        rekey_vault::secret::SecretInput::from_slice(b"synthetic-template-gate-password");
    rekey_vault::bootstrap::init_vault(
        &state,
        &password,
        rekey_vault::crypto::kdf::Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        },
        rekey_domain::authorization::PolicyMode::Team,
    )
    .unwrap();
    rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
    let (authority, join) =
        rekey_vault::authority::spawn_authority(rekey_vault::handle::AuthorityConfig::new(state))
            .unwrap();
    // The authority stays locked and has no credential. Reaching preparation
    // must still fail with Locked, with no upstream request.
    let fake = Arc::new(crate::testing::FakeUpstreamTransport::new());
    let (tracker, worker) = spawn_terminal_worker_with(|_| async { Ok(()) });
    let executor = ActionExecutor::new(
        authority.clone(),
        Arc::new(SessionRegistry::new()),
        fake.clone(),
        Arc::new(Lifecycle::new()),
        tracker.clone(),
        Arc::new(RwLock::new(None)),
    );
    let action: FixedHttpAction=serde_json::from_value(serde_json::json!({
        "id":ActionId::new_random(),"name":"template-gate","version":1,"enabled":true,"credential_id":CredentialId::new_random(),
        "origin":"https://api.example.com","method":"GET",
        "target":{"kind":"template","target":{"path":"/fixed","params":{},"query":{}},"fixed_headers":{},"body_schema":null,
            "source":{"template":"team@1","capability":"read","action_index":0,"digest":vec![1;32],"signer_id":null},"default_policy":{"rule":"allow"}},
        "auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":1000,
        "request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":1024,"allowed_headers":[]}
    })).unwrap();
    let request = ExecuteRequest {
        request_id: RequestId::new_random(),
        capability_token: "synthetic".into(),
        action: ActionVersionRef {
            action_id: action.id,
            version: 1,
        },
        content_type: None,
        extra_headers: vec![],
        params: Default::default(),
        query: Default::default(),
        body: vec![],
        approval_grants: vec![],
        local_approval_request_id: None,
    };
    assert_eq!(validate_request(&action, &request), Ok(()));
    assert!(build_upstream(&action, &request, Zeroizing::new(vec![])).is_err());
    let mut guard = StartedAuditGuard::new_for_test(&tracker, execution_context());
    assert!(matches!(
        executor
            .run_started(
                &mut guard,
                &request,
                &action,
                Instant::now() + Duration::from_secs(1),
                &AtomicU8::new(0),
                None
            )
            .await,
        Err(BrokerError::Authority(AuthorityError::Locked))
    ));
    assert!(fake.take_requests().is_empty());
    assert_eq!(authority.status().await.unwrap().state, "locked");
    drop(guard);
    drop(executor);
    drop(tracker);
    worker.await.unwrap();
    authority.shutdown(None).await.unwrap();
    join.join().unwrap();
}
