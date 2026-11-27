//! Agent-facing `next` guidance for locally raised errors.

pub(super) fn local_next(code: &str) -> &'static str {
    match code {
        "IPC_UNAVAILABLE" => {
            "Open Rekey or start rekeyd serve; wait for unlock before issuing a new call. Do not replay a write whose outcome is unknown."
        }
        "USAGE" | "INVALID_INPUT" => {
            "Check the command arguments; use describe for the named operation's parameters."
        }
        "UPSTREAM_ERROR" => {
            "Inspect the returned status and sealed response body. Do not automatically repeat a write."
        }
        _ => {
            "Review the error and Rekey status before taking another action. Do not automatically repeat a write."
        }
    }
}

/// `next` for a completed call whose upstream status is not 2xx.
pub fn upstream_status_next(status: u16) -> &'static str {
    match status {
        401 | 403 => {
            "The upstream rejected the stored key (HTTP 401/403): it is invalid, expired, revoked or lacks the needed scope. Tell the user to replace the key or widen its scope in Rekey; request_access cannot fix a rejected key. Do not automatically repeat a write."
        }
        _ => {
            "Inspect the returned status and sealed response body. Do not automatically repeat a write."
        }
    }
}

/// A refused connect usually means an Agent sandbox (for example Codex
/// Seatbelt) blocks Unix sockets while the daemon is running normally.
/// Socket file permissions fail with EACCES instead and keep the generic hint.
pub(super) fn connect_error(err: std::io::Error) -> super::CliError {
    if err.raw_os_error() != Some(libc::EPERM) {
        return super::io_err(err);
    }
    let mut error = super::CliError::local(
        "IPC_UNAVAILABLE",
        format!("broker socket connection refused: {err}"),
    );
    error.next = Some(
        "A sandbox around this process blocked the local Rekey socket; Rekey itself may be running. Use the Rekey MCP tools instead (they run outside the Agent sandbox), or ask the user to allow Unix sockets for this sandbox. Do not replay a write whose outcome is unknown."
            .to_owned(),
    );
    error
}
