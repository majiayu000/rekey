use anyhow::{Result, bail};
use std::fs::OpenOptions;
use std::process::{Command, Stdio};

fn is_daemon_child() -> bool {
    std::env::var("REKEY_DAEMON_CHILD").ok().as_deref() == Some("1")
}

fn spawn_daemon_child(port: u16, password: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let log_path = super::cmd_runtime::log_path();
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_err = log.try_clone()?;

    let mut child = Command::new(exe)
        .arg("start")
        .arg("--port")
        .arg(port.to_string())
        .env("REKEY_DAEMON_CHILD", "1")
        .env("REKEY_PASSWORD", password)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()?;

    for _ in 0..50 {
        if let Some(status) = child.try_wait()? {
            bail!("daemon exited early with status: {status}");
        }
        if super::cmd_runtime::current_runtime_if_running()
            .ok()
            .flatten()
            .is_some()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    println!(
        "rekey daemon started on 127.0.0.1:{port} (pid: {})",
        child.id()
    );
    println!("log file: {}", log_path.display());
    Ok(())
}

pub fn run(daemon: bool, port: u16) -> Result<()> {
    super::cmd_runtime::cleanup_stale_runtime();
    if let Some(state) = super::cmd_runtime::current_runtime_if_running()? {
        bail!(
            "rekey is already running (pid={}, port={})",
            state.pid,
            state.port
        );
    }
    if !super::cmd_runtime::is_port_available(port) {
        bail!("port {port} is already in use");
    }

    let dir = super::cmd_init::rekey_dir();
    let ca = rekey_ca::authority::CertificateAuthority::load(&dir)?;
    let password = super::cmd_init::prompt_password("Master password: ")?;

    let conn = rekey_vault::db::open_connection(super::cmd_init::db_path())?;
    let salt: Vec<u8> = conn.query_row("SELECT value FROM config WHERE key = 'salt'", [], |r| {
        r.get(0)
    })?;
    let master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;
    drop(conn);

    if daemon && !is_daemon_child() {
        return spawn_daemon_child(port, &password);
    }

    let now = super::cmd_runtime::now_unix();
    let state = super::cmd_runtime::RuntimeState {
        pid: std::process::id(),
        port,
        started_at: now,
        updated_at: now,
    };
    super::cmd_runtime::write_runtime_state(&state)?;
    super::cmd_runtime::write_pid(state.pid)?;

    println!("rekey proxy starting on 127.0.0.1:{port}");
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        let server = rekey_proxy::server::ProxyServer::new(
            ca,
            master_key,
            super::cmd_init::db_path().to_string_lossy().to_string(),
            port,
        );
        server.run().await
    });
    super::cmd_runtime::cleanup_runtime_files();
    result
}
