//! One start attempt: the exclusive serve lock and the public startup-failure
//! record the App reads when it cannot connect (agent-call §6.3, v3 §9.3).
//!
//! The record is bounded public JSON: a stable code, the safe error text, an
//! optional fix hint and port, and a timestamp. It holds no secret, proof or
//! path, is not part of the vault format, and rekeyd never reads it back.
//! Only the lock owner writes or removes it, and never in a directory without
//! vault state, so a failed start cannot block a later `init`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rekey_domain::ids::RequestId;
use rekey_vault::{AuthorityError, paths};

use super::{BrokerConfig, BrokerCtx};
use crate::error::BrokerError;

/// Public App guidance in the state directory; never part of the vault format.
pub const STARTUP_FAILURE_FILE: &str = "startup-failure.json";

const MESSAGE_CHARS: usize = 120;
const REBUILD: &str = "This release never reads or migrates another vault format. Keep this directory and its backups unchanged, initialize a new vault in a new empty state directory, then add the keys again.";

/// Runs the broker. A start that fails while holding the serve lock leaves a
/// startup-failure record; a successful start removes any earlier record.
pub async fn serve(config: BrokerConfig) -> Result<(), BrokerError> {
    let state_dir = config.state_dir.clone();
    let port = config.service_port;
    let attempt = Attempt::default();
    let result = super::run_attempt(config, &attempt).await;
    if let Err(error) = &result
        && attempt.lock.get().is_some()
        && !attempt.started.load(Ordering::Acquire)
    {
        record(&state_dir, error, port);
    }
    // The serve lock is released only here, after the record is final.
    result
}

#[derive(Default)]
pub(super) struct Attempt {
    lock: OnceLock<ServeLock>,
    started: AtomicBool,
}

impl Attempt {
    /// Holds the exclusive serve lock for the whole attempt, record included.
    /// Another instance's lock leaves that owner's record untouched.
    pub(super) fn lock(&self, state_dir: &Path) -> Result<(), AuthorityError> {
        let lock = acquire_serve_lock(state_dir)?;
        let _ = self.lock.set(lock);
        Ok(())
    }

    /// Final startup step: bind the local HTTP service, then retire the record.
    pub(super) async fn start(&self, ctx: &BrokerCtx) -> Result<(), BrokerError> {
        ctx.start_local_service().await?;
        self.started.store(true, Ordering::Release);
        clear(&ctx.state_dir);
        Ok(())
    }
}

struct ServeLock {
    _file: fs::File,
}

fn acquire_serve_lock(state_dir: &std::path::Path) -> Result<ServeLock, AuthorityError> {
    let path = paths::broker_lock(state_dir);
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(AuthorityError::storage)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(AuthorityError::storage)?;
    // Match bootstrap: brief retry for transient macOS EAGAIN/WouldBlock on LOCK_NB.
    const ATTEMPTS: u32 = 50;
    const DELAY: Duration = Duration::from_millis(2);
    let mut last_err = None;
    for attempt in 0..ATTEMPTS {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(ServeLock { _file: file });
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                if attempt + 1 < ATTEMPTS =>
            {
                last_err = Some(err);
                std::thread::sleep(DELAY);
            }
            _ => return Err(AuthorityError::storage(err)),
        }
    }
    Err(AuthorityError::storage(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "broker lock remained unavailable",
        )
    })))
}

/// Best effort: a record that cannot be written never replaces the error.
fn record(state_dir: &Path, error: &BrokerError, port: Option<u16>) {
    if !holds_vault_state(state_dir) {
        return;
    }
    let code = error.code();
    let next = match error {
        BrokerError::LocalCall(_, _, next) => Some(*next),
        _ if matches!(
            code,
            "UNSUPPORTED_VAULT_LAYOUT" | "UNSUPPORTED_FORMAT_VERSION"
        ) =>
        {
            Some(REBUILD)
        }
        _ => None,
    };
    let at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0);
    // `Display` and `code()` are the IPC-safe forms: no secret, path or SQL.
    // Static hints plus a capped message keep the record under 1 KiB.
    let message: String = error
        .to_string()
        .chars()
        .filter(|c| !c.is_control())
        .take(MESSAGE_CHARS)
        .collect();
    let body = serde_json::json!({
        "code": code,
        "message": message,
        "next": next,
        "port": port.filter(|_| code == "SERVICE_PORT_IN_USE"),
        "at_ms": at_ms,
    });
    if let Err(cause) = publish(state_dir, body.to_string().as_bytes()) {
        tracing::warn!(event = "startup.record_failed", %cause);
    }
}

/// Mirrors the Authority occupancy rule: an empty directory stays ready for `init`.
fn holds_vault_state(state_dir: &Path) -> bool {
    fs::read_dir(state_dir).is_ok_and(|mut entries| {
        entries.any(|entry| {
            entry.is_ok_and(|entry| {
                let name = entry.file_name();
                name != paths::BROKER_LOCK_FILE && name != paths::RUNTIME_DIR
            })
        })
    })
}

fn publish(state_dir: &Path, body: &[u8]) -> std::io::Result<()> {
    let id = crate::random_id(RequestId::from_random_bytes).map_err(std::io::Error::other)?;
    let temporary = state_dir.join(format!(".startup-failure-{id}.tmp"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(body)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, state_dir.join(STARTUP_FAILURE_FILE))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn clear(state_dir: &Path) {
    match fs::remove_file(state_dir.join(STARTUP_FAILURE_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(cause) => tracing::warn!(event = "startup.record_clear_failed", %cause),
    }
}
