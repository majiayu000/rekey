use super::*;
use rekey_vault::bootstrap::{confirm_vault_init, init_vault};
use rekey_vault::command::AuditDraft;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::secret::SecretInput;
use std::future::{Future, poll_fn};
use std::sync::atomic::AtomicUsize;
use std::task::Poll;
use tokio::sync::Barrier;

#[tokio::test]
async fn idle_status_poll_does_not_occupy_execution_admission() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    init_vault(
        &state,
        &SecretInput::from_slice(b"fixture-proof"),
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        },
    )
    .unwrap();
    confirm_vault_init(&state).unwrap();
    let (authority, join) =
        rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
    authority
        .unlock(UnlockProof::Password(SecretInput::from_slice(
            b"fixture-proof",
        )))
        .await
        .unwrap();
    let sessions = Arc::new(SessionRegistry::new());
    let transport: Arc<dyn UpstreamTransport> = Arc::new(ReqwestUpstreamTransport);
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running().unwrap();
    let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
    let policy = Arc::new(RwLock::new(None));
    let executor = Arc::new(ActionExecutor::new(
        authority.clone(),
        sessions.clone(),
        transport.clone(),
        lifecycle.clone(),
        terminals.clone(),
        policy.clone(),
    ));
    let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
    drop(supervisor);
    let (shutdown_tx, _) = watch::channel(false);
    let (stop_tx, _) = mpsc::unbounded_channel();
    let ctx = BrokerCtx {
        #[cfg(feature = "lab")]
        oidc_admin: None,
        #[cfg(feature = "lab")]
        metrics: crate::metrics::Metrics::default(),
        authority: authority.clone(),
        sessions,
        executions,
        executor,
        #[cfg(feature = "lab")]
        workload_transport: transport,
        #[cfg(feature = "lab")]
        online_jwks_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        lifecycle,
        policy,
        policy_trust: Arc::new(RwLock::new(None)),
        terminals,
        drain_timeout: Duration::from_secs(1),
        shutdown_flag: AtomicBool::new(false),
        shutdown_tx,
        stop_tx,
        allowed_agent_uids: vec![unsafe { libc::geteuid() }].into(),
    };
    // Queue a blocked audit ahead of Status to make the polling window deterministic.
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut audit = Box::pin(authority.append_audit(AuditDraft {
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: "test.idle-poll",
        outcome: "success",
        reason_code: "fixture".into(),
        upstream_status: None,
        latency_ms: None,
    }));
    poll_fn(|cx| {
        assert!(audit.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let mut idle = Box::pin(ctx.try_idle_lock(Duration::from_secs(3600)));
    poll_fn(|cx| {
        assert!(idle.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let admission_available = ctx.lifecycle.try_coordinate().is_ok();
    drop(idle);
    db.execute_batch("COMMIT").unwrap();
    audit.await.unwrap();
    authority
        .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
            b"fixture-proof",
        ))))
        .await
        .unwrap();
    // A poll already scheduled when shutdown owns the coordinator is harmless.
    let stop_owner = ctx.lifecycle.coordinate().await;
    ctx.lifecycle.enter_shutting_down();
    let stopped_poll = ctx.try_idle_lock(Duration::from_secs(3600)).await;
    drop(stop_owner);
    drop(ctx);
    terminal_task.await.unwrap();
    join.join().unwrap();
    assert!(
        stopped_poll.is_ok(),
        "idle polling must not fault a completed shutdown"
    );
    assert!(
        admission_available,
        "ordinary idle polling must not reject a running execution as busy"
    );
}

#[test]
fn runtime_directory_rejects_symlink_before_chmod() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    let alias = dir.path().join("runtime");
    std::os::unix::fs::symlink(&target, &alias).unwrap();

    assert_eq!(
        prepare_runtime_dir(&alias, 0o700, None).unwrap_err().code(),
        "INSECURE_STATE_PERMISSIONS"
    );
    assert_eq!(
        fs::metadata(target).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn agent_runtime_rejects_parent_segments_and_symlink_aliases_into_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let outside = dir.path().join("outside");
    fs::create_dir(&state).unwrap();
    fs::create_dir(&outside).unwrap();

    let mut config = BrokerConfig::new(state.clone());
    config.agent_runtime_dir = Some(outside.join("../state/agent"));
    assert_eq!(
        validate_agent_endpoint(&config).unwrap_err().code(),
        "INSECURE_STATE_PERMISSIONS"
    );

    std::os::unix::fs::symlink(&state, outside.join("state-alias")).unwrap();
    config.agent_runtime_dir = Some(outside.join("state-alias/agent"));
    assert_eq!(
        validate_agent_endpoint(&config).unwrap_err().code(),
        "INSECURE_STATE_PERMISSIONS"
    );

    config.agent_runtime_dir = Some(outside.join("agent"));
    validate_agent_endpoint(&config).unwrap();

    let target = outside.join("agent-target");
    fs::create_dir(&target).unwrap();
    let alias = outside.join("agent-alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    config.agent_runtime_dir = Some(alias);
    assert_eq!(
        validate_agent_endpoint(&config).unwrap_err().code(),
        "INSECURE_STATE_PERMISSIONS"
    );

    let ancestor_target = outside.join("ancestor-target");
    fs::create_dir(&ancestor_target).unwrap();
    let ancestor_alias = outside.join("ancestor-alias");
    std::os::unix::fs::symlink(&ancestor_target, &ancestor_alias).unwrap();
    config.allowed_agent_uids = vec![unsafe { libc::geteuid() }.wrapping_add(1)];
    config.agent_socket_gid = Some(unsafe { libc::getegid() });
    config.agent_runtime_dir = Some(ancestor_alias.join("agent"));
    assert_eq!(
        validate_agent_endpoint(&config).unwrap_err().code(),
        "INSECURE_STATE_PERMISSIONS"
    );
}

#[tokio::test]
async fn shared_agent_runtime_is_traversable_but_not_group_writable() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("agent-runtime");
    let gid = unsafe { libc::getegid() };

    prepare_runtime_dir(&runtime, 0o750, Some(gid)).unwrap();
    let listener = bind_socket(&runtime.join("agent.sock"), 0o660, Some(gid)).unwrap();

    let runtime_metadata = fs::metadata(&runtime).unwrap();
    assert_eq!(runtime_metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(runtime_metadata.gid(), gid);
    assert_eq!(runtime_metadata.permissions().mode() & 0o777, 0o750);
    let socket_metadata = fs::metadata(runtime.join("agent.sock")).unwrap();
    assert_eq!(socket_metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(socket_metadata.gid(), gid);
    assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o660);
    drop(listener);
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_selection_closes_paused_remote_effect_admission() {
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running().unwrap();
    let paused = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let exchanges = Arc::new(AtomicUsize::new(0));
    let admission = tokio::spawn({
        let lifecycle = Arc::clone(&lifecycle);
        let paused = Arc::clone(&paused);
        let release = Arc::clone(&release);
        let exchanges = Arc::clone(&exchanges);
        async move {
            paused.wait().await;
            release.wait().await;
            if lifecycle.try_begin_remote_effect() {
                exchanges.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    paused.wait().await;

    let (_stop_tx, mut stop_rx) = mpsc::unbounded_channel();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
    let mut execution_task = tokio::spawn(async {
        std::future::pending::<()>().await;
        Ok(())
    });
    let _unlock_owner = lifecycle.coordinate().await;
    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
    let selected = tokio::time::timeout(
        Duration::from_secs(1),
        select_stop(
            &lifecycle,
            &mut stop_rx,
            &mut sigterm,
            &mut sigint,
            &mut execution_task,
        ),
    )
    .await
    .expect("SIGTERM stop selection must be bounded");
    assert!(matches!(selected, SelectedStop::Signal("sigterm")));
    assert_eq!(lifecycle.reject_if_busy().unwrap_err().code(), "DRAINING");

    release.wait().await;
    admission.await.unwrap();
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    execution_task.abort();
    let _ = execution_task.await;
}

#[tokio::test]
async fn fault_while_initially_locked_revokes_remembered_desktop() {
    use rekey_vault::bootstrap::{confirm_vault_init, init_vault};
    use rekey_vault::crypto::kdf::Argon2Params;
    use rekey_vault::secret::SecretInput;
    for coordinator_blocked in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let proof = || UnlockProof::Password(SecretInput::from_slice(b"synthetic-desktop-proof"));
        init_vault(
            &state,
            &SecretInput::from_slice(b"synthetic-desktop-proof"),
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        )
        .unwrap();
        confirm_vault_init(&state).unwrap();
        let (authority, join) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        authority.unlock(proof()).await.unwrap();
        let (key, _) = authority.desktop_remember(proof(), None).await.unwrap();
        authority.lock_for_restart("restart").await.unwrap();
        authority.shutdown(None).await.unwrap();
        join.join().unwrap();
        rekey_vault::authority::finish_runtime(&state).unwrap();
        let (authority, join) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        assert_eq!(authority.status().await.unwrap().state, "locked");
        assert!(state.join("desktop-unlock.bin").exists());
        let sessions = Arc::new(SessionRegistry::new());
        let transport: Arc<dyn UpstreamTransport> = Arc::new(ReqwestUpstreamTransport);
        let lifecycle = Arc::new(Lifecycle::new());
        let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
        let policy = Arc::new(RwLock::new(None));
        let executor = Arc::new(ActionExecutor::new(
            authority.clone(),
            sessions.clone(),
            transport.clone(),
            lifecycle.clone(),
            terminals.clone(),
            policy.clone(),
        ));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
        let mut execution_task = tokio::spawn(supervisor.run(shutdown_rx));
        let (stop_tx, _stop_rx) = mpsc::unbounded_channel();
        let ctx = BrokerCtx {
            #[cfg(feature = "lab")]
            oidc_admin: None,
            #[cfg(feature = "lab")]
            metrics: crate::metrics::Metrics::default(),
            authority: authority.clone(),
            sessions,
            executions,
            executor,
            #[cfg(feature = "lab")]
            workload_transport: transport,
            #[cfg(feature = "lab")]
            online_jwks_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            lifecycle,
            policy,
            policy_trust: Arc::new(RwLock::new(None)),
            terminals,
            drain_timeout: Duration::from_secs(1),
            shutdown_flag: AtomicBool::new(false),
            shutdown_tx,
            stop_tx,
            allowed_agent_uids: vec![unsafe { libc::geteuid() }].into(),
        };
        let hold = if coordinator_blocked {
            Some(ctx.lifecycle.coordinate().await)
        } else {
            None
        };
        let outcome = ctx
            .central_stop(
                shutdown::StopCause::Fault,
                tokio::time::Instant::now()
                    + if coordinator_blocked {
                        Duration::from_millis(50)
                    } else {
                        Duration::from_secs(5)
                    },
                &mut execution_task,
                None,
            )
            .await;
        assert!(matches!(
            outcome,
            shutdown::StopDisposition::Stopped(Some(_))
        ));
        if !coordinator_blocked {
            assert!(!state.join("desktop-unlock.bin").exists());
        }
        drop(hold);
        drop(ctx);
        terminal_task.abort();
        let _ = terminal_task.await;
        if !execution_task.is_finished() {
            execution_task.abort();
            let _ = execution_task.await;
        }
        drop(authority);
        join.join().unwrap();
        let (authority, join) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        assert!(
            !state.join("desktop-unlock.bin").exists(),
            "even early fault exits must revoke before next resume"
        );
        assert!(
            authority
                .desktop_resume(SecretInput::from_slice(&key), None)
                .await
                .is_err()
        );
        authority.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

pub(crate) async fn oidc_test_ctx() -> (
    tempfile::TempDir,
    Arc<BrokerCtx>,
    std::thread::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    init_vault(
        &state,
        &SecretInput::from_slice(b"fixture-proof"),
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        },
    )
    .unwrap();
    confirm_vault_init(&state).unwrap();
    let (authority, join) =
        rekey_vault::authority::spawn_authority(AuthorityConfig::new(state)).unwrap();
    authority
        .unlock(UnlockProof::Password(SecretInput::from_slice(
            b"fixture-proof",
        )))
        .await
        .unwrap();
    let sessions = Arc::new(SessionRegistry::new());
    sessions.open_for_admission();
    let transport: Arc<dyn UpstreamTransport> = Arc::new(ReqwestUpstreamTransport);
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running().unwrap();
    let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
    let policy = Arc::new(RwLock::new(None));
    let executor = Arc::new(ActionExecutor::new(
        authority.clone(),
        sessions.clone(),
        transport.clone(),
        lifecycle.clone(),
        terminals.clone(),
        policy.clone(),
    ));
    let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
    drop(supervisor);
    let (shutdown_tx, _) = watch::channel(false);
    let (stop_tx, _) = mpsc::unbounded_channel();
    let ctx = Arc::new(BrokerCtx {
        #[cfg(feature = "lab")]
        oidc_admin: None,
        #[cfg(feature = "lab")]
        metrics: crate::metrics::Metrics::default(),
        authority,
        sessions,
        executions,
        executor,
        #[cfg(feature = "lab")]
        workload_transport: transport,
        #[cfg(feature = "lab")]
        online_jwks_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        lifecycle,
        policy,
        policy_trust: Arc::new(RwLock::new(None)),
        terminals,
        drain_timeout: Duration::from_secs(1),
        shutdown_flag: AtomicBool::new(false),
        shutdown_tx,
        stop_tx,
        allowed_agent_uids: vec![unsafe { libc::geteuid() }].into(),
    });
    (dir, ctx, join, terminal_task)
}

#[tokio::test]
async fn retention_tick_cadence_busy_lock_shutdown_and_disable_are_coordinated() {
    use rekey_domain::audit::AuditRetentionSet;
    let (_dir, ctx, join, terminal_task) = oidc_test_ctx().await;
    let mut due = tokio::time::Instant::now();
    let owner = ctx.lifecycle.coordinate().await;
    tokio::time::timeout(
        Duration::from_millis(100),
        ctx.audit_retention_tick(&mut due),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(due >= tokio::time::Instant::now() + Duration::from_secs(59));
    drop(owner);
    ctx.authority
        .audit_retention_set_before(
            AuditRetentionSet { days: Some(1) },
            UnlockProof::Password(SecretInput::from_slice(b"fixture-proof")),
            None,
        )
        .await
        .unwrap();
    ctx.lifecycle.enter_locked();
    due = tokio::time::Instant::now();
    ctx.audit_retention_tick(&mut due).await.unwrap();
    ctx.lifecycle.enter_running().unwrap();
    ctx.authority
        .audit_retention_set_before(
            AuditRetentionSet { days: None },
            UnlockProof::Password(SecretInput::from_slice(b"fixture-proof")),
            None,
        )
        .await
        .unwrap();
    due = tokio::time::Instant::now();
    ctx.audit_retention_tick(&mut due).await.unwrap();
    let after = due;
    ctx.audit_retention_tick(&mut due).await.unwrap();
    assert_eq!(due, after, "a second early tick does not advance or burst");
    ctx.lifecycle.mark_stop_pending();
    due = tokio::time::Instant::now();
    ctx.audit_retention_tick(&mut due).await.unwrap();
    ctx.lifecycle.enter_shutting_down();
    due = tokio::time::Instant::now();
    ctx.audit_retention_tick(&mut due).await.unwrap();
    #[cfg(feature = "lab")]
    assert_eq!(ctx.metrics.fault_signals.load(Ordering::Relaxed), 0);
    ctx.authority
        .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
            b"fixture-proof",
        ))))
        .await
        .unwrap();
    drop(ctx);
    terminal_task.await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn retention_tick_unknown_reply_timeout_stops_and_keeps_owner_until_outcome() {
    let (dir, ctx, join, terminal_task) = oidc_test_ctx().await;
    ctx.authority
        .audit_retention_set_before(
            rekey_domain::audit::AuditRetentionSet { days: Some(1) },
            UnlockProof::Password(SecretInput::from_slice(b"fixture-proof")),
            None,
        )
        .await
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
        .unwrap();
    let request = rekey_domain::ids::RequestId::new_random();
    for kind in ["execution.started", "execution.finished"] {
        db.execute("INSERT INTO audit_events(event_id,request_id,event_type,outcome,reason_code,created_at_ms) VALUES (?1,?2,?3,'success','retention-timeout',10)", rusqlite::params![rekey_domain::ids::RequestId::new_random().as_bytes().as_slice(),request.as_bytes().as_slice(),kind]).unwrap();
    }
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut queued = Box::pin(ctx.authority.append_audit(AuditDraft {
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: "fixture.blocked",
        outcome: "success",
        reason_code: "test".into(),
        upstream_status: None,
        latency_ms: None,
    }));
    poll_fn(|cx| {
        assert!(queued.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let started = tokio::time::Instant::now();
    let mut maintenance = Box::pin(ctx.try_audit_retention());
    poll_fn(|cx| {
        assert!(maintenance.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(
        ctx.lifecycle.try_coordinate().is_err(),
        "owner cannot release while the writer outcome is pending"
    );
    assert!(matches!(
        maintenance.await,
        Err(BrokerError::Authority(AuthorityError::Faulted))
    ));
    assert!(started.elapsed() >= Duration::from_millis(900));
    #[cfg(feature = "lab")]
    assert_eq!(ctx.metrics.fault_signals.load(Ordering::Relaxed), 1);
    assert!(ctx.lifecycle.try_coordinate().is_ok());
    db.execute_batch("COMMIT").unwrap();
    queued.await.unwrap();
    ctx.authority.audit_retention_status().await.unwrap();
    let rows: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE request_id=?1",
            [request.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let markers: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='audit.pruned'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        (rows, markers),
        (2, 0),
        "late dequeue must not prune an enabled old group after the original deadline"
    );
    // The queued original deadline is expired: it cannot mutate after the broker timeout.
    ctx.authority
        .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
            b"fixture-proof",
        ))))
        .await
        .unwrap();
    drop(ctx);
    terminal_task.await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn retention_closed_reply_channel_is_faulted_without_retry() {
    let (_dir, ctx, join, terminal) = oidc_test_ctx().await;
    ctx.authority
        .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
            b"fixture-proof",
        ))))
        .await
        .unwrap();
    join.join().unwrap();
    assert!(matches!(
        ctx.try_audit_retention().await,
        Err(BrokerError::Authority(AuthorityError::Faulted))
    ));
    #[cfg(feature = "lab")]
    assert_eq!(ctx.metrics.fault_signals.load(Ordering::Relaxed), 1);
    drop(ctx);
    terminal.await.unwrap();
}

pub(crate) async fn exact3_maintenance(ctx: &BrokerCtx) -> Result<(), BrokerError> {
    ctx.try_audit_retention().await
}

pub(crate) fn exact3_pause_stop_consumer(ctx: &mut Arc<BrokerCtx>) -> Box<dyn FnMut() -> bool> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    Arc::get_mut(ctx).unwrap().stop_tx = tx;
    Box::new(move || rx.try_recv().is_ok())
}
