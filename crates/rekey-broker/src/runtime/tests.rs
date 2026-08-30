use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Barrier;

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
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_selection_closes_paused_remote_effect_admission() {
    let lifecycle = Arc::new(Lifecycle::new());
    lifecycle.enter_running();
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

    release.wait().await;
    admission.await.unwrap();
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    execution_task.abort();
    let _ = execution_task.await;
}
