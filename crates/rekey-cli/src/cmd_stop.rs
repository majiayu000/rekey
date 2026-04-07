use anyhow::{Result, bail};

pub fn run() -> Result<()> {
    super::cmd_runtime::cleanup_stale_runtime();
    let pid = match super::cmd_runtime::read_pid()? {
        Some(pid) => pid,
        None => bail!("rekey is not running"),
    };

    if !super::cmd_runtime::is_pid_running(pid) {
        super::cmd_runtime::cleanup_runtime_files();
        bail!("rekey is not running");
    }

    if !super::cmd_runtime::send_signal(pid, "-TERM") {
        bail!("failed to send TERM to pid {pid}");
    }
    if !super::cmd_runtime::wait_pid_exit(pid, std::time::Duration::from_secs(5)) {
        let _ = super::cmd_runtime::send_signal(pid, "-KILL");
        if !super::cmd_runtime::wait_pid_exit(pid, std::time::Duration::from_secs(2)) {
            bail!("failed to stop pid {pid}");
        }
    }

    super::cmd_runtime::cleanup_runtime_files();
    println!("Stopped rekey (pid: {pid})");
    Ok(())
}
