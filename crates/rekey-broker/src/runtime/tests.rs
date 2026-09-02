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
