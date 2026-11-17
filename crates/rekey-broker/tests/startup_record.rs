//! The public startup-failure record the App reads when it cannot connect.
//! It is written only by the serve-lock owner after a failed start, holds no
//! secret, never lands in an empty directory and disappears on success.
mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rekey_broker::runtime::{BrokerConfig, STARTUP_FAILURE_FILE, serve};
use rekey_domain::authorization::PolicyMode;
use rekey_vault::secret::SecretInput;
use serde_json::Value;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn vault(dir: &Path) -> PathBuf {
    let state = dir.join("state");
    rekey_vault::bootstrap::init_vault(
        &state,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
        PolicyMode::Personal,
    )
    .unwrap();
    rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
    state
}

fn use_port(state: &Path, port: u16) {
    let path = state.join("service.json");
    std::fs::write(&path, format!("{{\"port\":{port}}}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Reads the record exactly as the App does: one owner-only bounded file.
fn read_record(state: &Path) -> Value {
    let path = state.join(STARTUP_FAILURE_FILE);
    let metadata = std::fs::symlink_metadata(&path).expect("startup-failure record");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() <= 1024, "record must stay small");
    let canary = common::PASSWORD;
    assert!(!bytes.windows(canary.len()).any(|part| part == canary));
    let record: Value = serde_json::from_slice(&bytes).unwrap();
    let mut keys: Vec<_> = record.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["at_ms", "code", "message", "next", "port"]);
    record
}

fn wait_exit(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "rekeyd did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn rekeyd_serve(state: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_rekeyd"))
        .args(["serve", "--state-dir"])
        .arg(state)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn rekeyd_port_conflict_leaves_a_public_record_until_a_successful_start() {
    let dir = tempfile::tempdir().unwrap();
    let state = vault(dir.path());
    let occupant = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = occupant.local_addr().unwrap().port();
    use_port(&state, port);
    let before = now_ms();
    let mut failed = rekeyd_serve(&state);
    let status = wait_exit(&mut failed, Duration::from_secs(60));
    let stderr = std::io::read_to_string(failed.stderr.take().unwrap()).unwrap();
    assert_eq!(status.code(), Some(5), "{stderr}");
    let event = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|line| line["fields"]["event"] == "rekeyd.command_failed")
        .expect("structured failure event");
    assert_eq!(event["fields"]["error_code"], "SERVICE_PORT_IN_USE");
    assert_eq!(event["fields"]["code"], 5);

    let record = read_record(&state);
    assert_eq!(record["code"], "SERVICE_PORT_IN_USE");
    assert_eq!(record["port"], port);
    assert!(
        record["message"]
            .as_str()
            .unwrap()
            .contains("already in use")
    );
    assert!(record["next"].as_str().unwrap().contains("service.json"));
    let at = record["at_ms"].as_i64().unwrap();
    assert!(before <= at && at <= now_ms(), "{record}");
    assert!(!state.join("runtime/admin.sock").exists());

    // The user frees the port (here: picks another one) and starts again.
    let free = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    use_port(&state, port);
    let mut running = rekeyd_serve(&state);
    let deadline = Instant::now() + Duration::from_secs(60);
    while state.join(STARTUP_FAILURE_FILE).exists() {
        assert!(running.try_wait().unwrap().is_none(), "second start failed");
        assert!(
            Instant::now() < deadline,
            "successful start kept the record"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(running.try_wait().unwrap().is_none(), "service stays up");
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert_eq!(unsafe { libc::kill(running.id() as i32, libc::SIGTERM) }, 0);
    assert!(wait_exit(&mut running, Duration::from_secs(60)).success());
    assert!(!state.join(STARTUP_FAILURE_FILE).exists());
    drop(occupant);
}

#[tokio::test]
async fn unsupported_layout_is_recorded_with_rebuild_guidance() {
    let dir = tempfile::tempdir().unwrap();
    let state = vault(dir.path());
    // A 0.4 (vault26) directory lacks the vault27 PKI fact tables.
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
    db.execute_batch("DROP TABLE pki_crls; DROP TABLE pki_certificates;")
        .unwrap();
    drop(db);
    let mut config = BrokerConfig::new(state.clone());
    config.service_port = Some(0);
    let error = tokio::time::timeout(Duration::from_secs(60), serve(config))
        .await
        .expect("startup must fail promptly")
        .unwrap_err();
    assert_eq!(error.code(), "UNSUPPORTED_VAULT_LAYOUT");
    let record = read_record(&state);
    assert_eq!(record["code"], "UNSUPPORTED_VAULT_LAYOUT");
    assert_eq!(record["port"], Value::Null);
    let next = record["next"].as_str().unwrap();
    assert!(next.contains("never reads or migrates") && next.contains("new empty state directory"));
}

#[tokio::test]
async fn empty_directory_gets_no_record_and_can_still_be_initialized() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(60),
        serve(BrokerConfig::new(state.clone())),
    )
    .await
    .expect("startup must fail promptly")
    .unwrap_err();
    assert_eq!(error.code(), "NOT_INITIALIZED");
    assert!(!state.join(STARTUP_FAILURE_FILE).exists());
    rekey_vault::bootstrap::init_vault(
        &state,
        &SecretInput::from_slice(common::PASSWORD),
        common::TEST_PARAMS,
        PolicyMode::Personal,
    )
    .expect("a failed start must not block init");
}

#[tokio::test]
async fn a_start_without_the_serve_lock_writes_no_record() {
    let broker = common::start_broker().await;
    let error = tokio::time::timeout(
        Duration::from_secs(60),
        serve(BrokerConfig::new(broker.state_dir.clone())),
    )
    .await
    .expect("contended start must fail promptly")
    .unwrap_err();
    assert_eq!(error.code(), "STORAGE_UNAVAILABLE");
    assert!(!broker.state_dir.join(STARTUP_FAILURE_FILE).exists());
    broker.shutdown().await;
}
