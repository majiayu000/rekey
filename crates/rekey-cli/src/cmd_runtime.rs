use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_PORT: u16 = 10800;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeState {
    pub pid: u32,
    pub port: u16,
    pub started_at: i64,
    pub updated_at: i64,
}

pub fn default_port() -> u16 {
    DEFAULT_PORT
}

pub fn runtime_path() -> PathBuf {
    super::cmd_init::rekey_dir().join("runtime.json")
}

pub fn pid_path() -> PathBuf {
    super::cmd_init::rekey_dir().join("rekey.pid")
}

pub fn log_path() -> PathBuf {
    super::cmd_init::rekey_dir().join("rekey.log")
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn read_runtime_state() -> Result<Option<RuntimeState>> {
    let path = runtime_path();
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path).context("failed to read runtime state")?;
    let state: RuntimeState = serde_json::from_str(&content).context("invalid runtime state")?;
    Ok(Some(state))
}

pub fn write_runtime_state(state: &RuntimeState) -> Result<()> {
    fs::create_dir_all(super::cmd_init::rekey_dir())?;
    let path = runtime_path();
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_string_pretty(state)?;
    fs::write(&tmp, content)?;
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn read_pid() -> Result<Option<u32>> {
    let path = pid_path();
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)?;
    let pid = text.trim().parse::<u32>().context("invalid pid file")?;
    Ok(Some(pid))
}

pub fn write_pid(pid: u32) -> Result<()> {
    fs::create_dir_all(super::cmd_init::rekey_dir())?;
    fs::write(pid_path(), pid.to_string())?;
    Ok(())
}

pub fn is_pid_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

pub fn cleanup_runtime_files() {
    let _ = fs::remove_file(runtime_path());
    let _ = fs::remove_file(pid_path());
}

pub fn cleanup_stale_runtime() {
    let stale = if let Some(state) = read_runtime_state().ok().flatten() {
        !is_pid_running(state.pid)
    } else if let Some(pid) = read_pid().ok().flatten() {
        !is_pid_running(pid)
    } else {
        false
    };
    if stale {
        cleanup_runtime_files();
    }
}

pub fn current_runtime_if_running() -> Result<Option<RuntimeState>> {
    cleanup_stale_runtime();
    if let Some(state) = read_runtime_state()? {
        if is_pid_running(state.pid) {
            return Ok(Some(state));
        }
        cleanup_runtime_files();
    }
    Ok(None)
}

pub fn resolve_port() -> u16 {
    current_runtime_if_running()
        .ok()
        .flatten()
        .map(|s| s.port)
        .unwrap_or(DEFAULT_PORT)
}

pub fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

pub fn send_signal(pid: u32, signal: &str) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .arg(signal)
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, signal);
        false
    }
}

pub fn wait_pid_exit(pid: u32, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !is_pid_running(pid) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    !is_pid_running(pid)
}
