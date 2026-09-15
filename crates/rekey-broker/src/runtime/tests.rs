use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Barrier;

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
            authority: authority.clone(),
            sessions,
            executions,
            executor,
            workload_transport: transport,
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
