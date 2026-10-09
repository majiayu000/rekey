//! BrokerRuntime: owns the two Unix listeners, the session registry, the
//! executor, and the AuthorityWorker lifecycle. Starts locked; never reads
//! secrets from the environment.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rekey_domain::action::ACTION_TIMEOUT_HARD_MAX_MS;
use rekey_policy::ValidatedPolicyTrust;
use rekey_vault::AuthorityError;
use rekey_vault::bootstrap::verify_state_dir_permissions;
use rekey_vault::command::UnlockProof;
use rekey_vault::handle::{AuthorityConfig, AuthorityHandle};
use rekey_vault::paths;
use tokio::net::UnixListener;
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::active_policy::ActivePolicy;
use crate::audit::{TerminalAuditTracker, spawn_terminal_worker};
use crate::error::BrokerError;
use crate::execution_supervisor::ExecutionSupervisorHandle;
use crate::executor::ActionExecutor;
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::SessionRegistry;
use crate::upstream::{ReqwestUpstreamTransport, UpstreamTransport};

mod admin;
mod call;
mod connections;
mod derived;
mod gateway;
pub(crate) mod local_calls;
pub(crate) mod profile;
mod profile_inventory;
mod shutdown;
#[cfg(feature = "lab")]
mod workload;

pub const MAX_AGENT_CONNECTIONS: usize = 120;
pub const MAX_ADMIN_CONNECTIONS: usize = 8;
pub const CAPACITY_REPLY_CONNECTIONS_PER_CHANNEL: usize = 1;
pub const MAX_AGENT_REQUEST_CONNECTIONS: usize =
    MAX_AGENT_CONNECTIONS - CAPACITY_REPLY_CONNECTIONS_PER_CHANNEL;
pub const MAX_ADMIN_REQUEST_CONNECTIONS: usize =
    MAX_ADMIN_CONNECTIONS - CAPACITY_REPLY_CONNECTIONS_PER_CHANNEL;
/// Dedicated bound for unauthenticated online JWKS fetches. Kept far below
/// Agent request slots so forged JWTs cannot monopolize the Agent channel.
pub const MAX_ONLINE_JWKS_FETCHES: usize = 2;

pub fn default_drain_timeout() -> Duration {
    Duration::from_millis(ACTION_TIMEOUT_HARD_MAX_MS as u64)
}

pub struct BrokerConfig {
    pub state_dir: PathBuf,
    /// Explicit HTTP port; embedded/test runtimes can omit the listener.
    pub service_port: Option<u16>,
    #[cfg(feature = "lab")]
    pub oidc_admin_profile: Option<PathBuf>,
    /// P1 seam: an isolated Agent endpoint may live outside the private state tree.
    pub agent_runtime_dir: Option<PathBuf>,
    /// OS-verified peer UIDs accepted on the Agent endpoint.
    pub allowed_agent_uids: Vec<u32>,
    /// Optional shared group for an isolated Agent endpoint (directory 0750, socket 0660).
    pub agent_socket_gid: Option<u32>,
    pub idle_lock: Duration,
    /// Test seam: production always uses ReqwestUpstreamTransport.
    pub transport: Option<Arc<dyn UpstreamTransport>>,
    pub unlock_backoff_base: Duration,
    /// How long lock/idle/shutdown wait for in-flight executes before dropping VRK.
    pub drain_timeout: Duration,
}

impl BrokerConfig {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            service_port: None,
            #[cfg(feature = "lab")]
            oidc_admin_profile: None,
            agent_runtime_dir: None,
            allowed_agent_uids: vec![unsafe { libc::geteuid() }],
            agent_socket_gid: None,
            idle_lock: rekey_vault::handle::DEFAULT_IDLE_LOCK,
            transport: None,
            unlock_backoff_base: Duration::from_secs(1),
            drain_timeout: default_drain_timeout(),
        }
    }
}

pub struct BrokerCtx {
    pub(crate) state_dir: PathBuf,
    #[cfg(feature = "lab")]
    pub(crate) metrics: crate::metrics::Metrics,
    pub authority: AuthorityHandle,
    #[cfg(feature = "lab")]
    pub(crate) oidc_admin: Option<Arc<crate::oidc_admin::Manager>>,
    pub sessions: Arc<SessionRegistry>,
    pub(crate) executions: ExecutionSupervisorHandle,
    pub(crate) executor: Arc<ActionExecutor>,
    #[cfg(feature = "lab")]
    workload_transport: Arc<dyn UpstreamTransport>,
    #[cfg(feature = "lab")]
    online_jwks_slots: Arc<tokio::sync::Semaphore>,
    pub lifecycle: Arc<Lifecycle>,
    pub(crate) policy: Arc<RwLock<Option<Arc<ActivePolicy>>>>,
    gateway: gateway::Gateway,
    pub(crate) local_calls: Arc<local_calls::LocalCalls>,
    policy_trust: Arc<RwLock<Option<ValidatedPolicyTrust>>>,
    terminals: Arc<TerminalAuditTracker>,
    drain_timeout: Duration,
    shutdown_flag: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    stop_tx: mpsc::UnboundedSender<shutdown::StopCommand>,
    allowed_agent_uids: Arc<[u32]>,
}

impl BrokerCtx {
    pub(crate) fn has_pending_terminals(&self) -> bool {
        self.terminals.has_pending()
    }

    pub(crate) fn publish_shutdown(&self) {
        self.gateway.close();
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if self.shutdown_tx.send(true).is_err() {
            tracing::debug!(event = "runtime.shutdown_notice_without_receivers");
        }
    }

    pub(crate) fn close_fault_admission(&self) {
        self.lifecycle.mark_stop_pending();
        self.gateway.close();
        self.lifecycle.close_remote_effect_admission();
        self.lifecycle.signal_cancel();
        self.sessions.close_and_revoke_all();
        self.local_calls.clear();
        self.executor.oauth.clear();
    }

    pub(crate) fn request_fault(&self) {
        self.close_fault_admission();
        #[cfg(feature = "lab")]
        if let Some(manager) = &self.oidc_admin {
            manager.clear();
            self.sessions.close_and_revoke_all();
            self.local_calls.clear();
            self.executor.oauth.clear();
        }
        #[cfg(feature = "lab")]
        self.metrics.fault_signals.fetch_add(1, Ordering::Relaxed);
        let _ = self.stop_tx.send(shutdown::StopCommand::Fault);
    }

    pub(crate) async fn request_admin_shutdown(
        &self,
        proof: UnlockProof,
    ) -> Result<(), BrokerError> {
        let (reply, result) = oneshot::channel();
        self.stop_tx
            .send(shutdown::StopCommand::Admin { proof, reply })
            .map_err(|_| BrokerError::Authority(AuthorityError::Draining))?;
        result
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::Faulted))?
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_flag.load(Ordering::SeqCst)
    }

    pub(crate) fn agent_uid_allowed(&self, uid: u32) -> bool {
        self.allowed_agent_uids.contains(&uid)
    }

    pub async fn unlock(
        &self,
        proof: UnlockProof,
    ) -> Result<rekey_domain::ipc::LeaseRecoverySummary, BrokerError> {
        self.unlock_with_desktop(proof, false)
            .await
            .map(|(_, summary)| summary)
    }

    pub(crate) async fn unlock_with_desktop(
        &self,
        proof: UnlockProof,
        desktop: bool,
    ) -> Result<
        (
            Option<zeroize::Zeroizing<Vec<u8>>>,
            rekey_domain::ipc::LeaseRecoverySummary,
        ),
        BrokerError,
    > {
        let _owner = self
            .lifecycle
            .try_coordinate()
            .map_err(|_| BrokerError::Admission(AuthorityError::AuthorityBusy))?;
        self.lifecycle.reject_if_busy()?;
        let recover = self.lifecycle.phase() == BrokerPhase::Locked;
        self.authority.unlock(proof).await?;
        let summary = self.activate_unlocked(recover).await?;
        if desktop {
            Ok((Some(self.authority.desktop_issue().await?), summary))
        } else {
            Ok((None, summary))
        }
    }

    async fn activate_unlocked(
        &self,
        recover: bool,
    ) -> Result<rekey_domain::ipc::LeaseRecoverySummary, BrokerError> {
        if let Err(error) = self.reload_policy_after_unlock().await {
            self.sessions.close_and_revoke_all();
            self.local_calls.clear();
            self.executor.oauth.clear();
            let lock_result = self.authority.lock("policy-reload-failed").await;
            *self.policy.write().await = None;
            *self.policy_trust.write().await = None;
            self.lifecycle.enter_locked();
            if lock_result.is_err() {
                self.request_fault();
            }
            return Err(error);
        }
        let summary = match self.executor.recover_vault_leases(recover).await {
            Ok(summary) => summary,
            Err(error) => {
                self.sessions.close_and_revoke_all();
                self.local_calls.clear();
                self.executor.oauth.clear();
                let locked = self.authority.lock("lease-recovery-failed").await;
                *self.policy.write().await = None;
                *self.policy_trust.write().await = None;
                self.lifecycle.enter_locked();
                if locked.is_err() {
                    self.request_fault();
                }
                return Err(error);
            }
        };
        if let Err(transition_error) = self.lifecycle.enter_running() {
            self.sessions.close_and_revoke_all();
            self.local_calls.clear();
            self.executor.oauth.clear();
            let lock_result = self.authority.lock("stop-during-unlock").await;
            *self.policy.write().await = None;
            *self.policy_trust.write().await = None;
            self.lifecycle.enter_locked();
            if let Err(lock_error) = lock_result {
                self.request_fault();
                return Err(lock_error.into());
            }
            return Err(transition_error);
        }
        self.sessions.open_for_admission();
        self.reconcile_gateway().await;
        tracing::info!(event = "authority.state", state = "running");
        Ok(summary)
    }

    pub(crate) async fn resume_desktop(
        &self,
        token: rekey_vault::secret::SecretInput,
    ) -> Result<
        (
            zeroize::Zeroizing<Vec<u8>>,
            i64,
            rekey_domain::ipc::LeaseRecoverySummary,
        ),
        BrokerError,
    > {
        let _owner = self
            .lifecycle
            .try_coordinate()
            .map_err(|_| BrokerError::Admission(AuthorityError::AuthorityBusy))?;
        self.lifecycle.reject_if_busy()?;
        let recover = self.lifecycle.phase() == BrokerPhase::Locked;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        // The worker rolls back a late resume before replying. Do not abandon
        // its result while it may temporarily own an unlocked root key.
        let expires = self
            .authority
            .desktop_resume(token, Some(deadline.into_std()))
            .await?;
        if tokio::time::Instant::now() >= deadline {
            self.authority
                .lock_for_restart("desktop-resume-timeout")
                .await?;
            return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
        }
        let expires = expires.min(
            crate::now_ts()?
                .as_unix_ms()
                .saturating_add(7 * 24 * 60 * 60 * 1000),
        );
        let session = match self.authority.desktop_issue().await {
            Ok(session) => session,
            Err(error) => {
                if let Err(lock_error) = self
                    .authority
                    .lock_for_restart("desktop-session-failed")
                    .await
                {
                    self.request_fault();
                    return Err(lock_error.into());
                }
                return Err(error.into());
            }
        };
        let summary = self.activate_unlocked(recover).await?;
        Ok((session, expires, summary))
    }

    pub(crate) async fn confirm_rollback(
        &self,
        expected: rekey_domain::ipc::RollbackContext,
        proof: rekey_vault::bootstrap::RestoreProof,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_busy()?;
        let status = tokio::time::timeout_at(deadline, self.authority.status())
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))??;
        match status.state {
            "rollback-suspected" => {}
            "faulted" => return Err(AuthorityError::Faulted.into()),
            _ => return Err(AuthorityError::RollbackSuspected.into()),
        }
        // Confirmation cannot revive old sessions or race prepared executions.
        // The Authority retains suspected context across lock and validates
        // both the supplied proof and current context at its trusted boundary.
        self.run_drain_lock("rollback-confirm", tokio::time::Instant::now(), deadline)
            .await?;
        tokio::time::timeout_at(
            deadline,
            self.authority
                .confirm_rollback(expected, proof, deadline.into_std()),
        )
        .await
        .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))??;
        Ok(())
    }

    /// Runs after dispatch has released its coordinator. A failed mutation
    /// may have faulted the Authority while retaining its original error code.
    /// Return whether the caller must send the existing fault-stop after
    /// attempting the original error response, including a failed write.
    pub(crate) async fn settle_failed_admin(&self) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let owner = self.lifecycle.coordinate_until(deadline).await;
        if let Ok(_owner) = owner
            && let Ok(Ok(status)) = tokio::time::timeout_at(deadline, self.authority.status()).await
        {
            if matches!(status.state, "locked" | "unlocked") {
                return false;
            }
            if status.state == "rollback-suspected"
                && self
                    .run_drain_lock("rollback-suspected", tokio::time::Instant::now(), deadline)
                    .await
                    .is_ok()
            {
                return false;
            }
        }
        // Unknown Authority state cannot preserve execution admission.
        self.close_fault_admission();
        true
    }

    /// Revoke sessions, wait in-flight executes, then zeroize the VRK.
    pub async fn drain_lock(&self, reason: &'static str) -> Result<(), BrokerError> {
        let natural_deadline = tokio::time::Instant::now() + self.drain_timeout;
        let stop_deadline = natural_deadline + Duration::from_secs(5);
        let _owner = self.lifecycle.coordinate_until(stop_deadline).await?;
        self.run_drain_lock(reason, natural_deadline, stop_deadline)
            .await
    }

    /// Poll activity without excluding execution admission. Only a possible
    /// idle drain takes the coordinator and rechecks activity under it.
    pub async fn try_idle_lock(&self, idle_lock: Duration) -> Result<(), BrokerError> {
        let status = self.authority.status().await;
        // A queued poll may outlive a concurrent lock/shutdown. That owner
        // handles Authority failures; polling must not fault its clean stop.
        if !self.lifecycle.is_running() {
            return Ok(());
        }
        let status = status?;
        if status.state == "unlocked"
            && status.idle_for_ms >= idle_lock.as_millis() as u64
            && (self.sessions.in_flight_total() + self.lifecycle.local_in_flight()) == 0
        {
            let natural_deadline = tokio::time::Instant::now() + self.drain_timeout;
            let stop_deadline = natural_deadline + Duration::from_secs(5);
            // Passive status holds this coordinator too. Once idle, queue
            // fairly instead of repeatedly losing to background polling.
            let Ok(_owner) =
                tokio::time::timeout_at(stop_deadline, self.lifecycle.coordinate()).await
            else {
                return Ok(());
            };
            if !self.lifecycle.is_running() {
                return Ok(());
            }
            // A terminal audit refreshes activity before its execution permit
            // drops. Re-reading after observing zero in-flight prevents stale
            // pre-completion status from immediately locking the authority.
            let status = self.authority.status().await?;
            if status.state != "unlocked"
                || status.idle_for_ms < idle_lock.as_millis() as u64
                || (self.sessions.in_flight_total() + self.lifecycle.local_in_flight()) != 0
            {
                return Ok(());
            }
            self.run_drain_lock("idle-timeout", natural_deadline, stop_deadline)
                .await?;
        }
        Ok(())
    }

    async fn audit_retention_tick(
        &self,
        next_tick: &mut tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        if tokio::time::Instant::now() < *next_tick {
            return Ok(());
        }
        let result = self.try_audit_retention().await;
        if result.is_ok()
            || matches!(
                result,
                Err(BrokerError::Authority(AuthorityError::AuthorityBusy))
            )
        {
            *next_tick = tokio::time::Instant::now() + Duration::from_secs(60);
        }
        result
    }

    /// The lifecycle owner is retained until the maintenance outcome is known.
    async fn try_audit_retention(&self) -> Result<(), BrokerError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let Ok(_owner) = self.lifecycle.try_coordinate() else {
            return Ok(());
        };
        if !self.lifecycle.is_running() || self.lifecycle.reject_if_busy().is_err() {
            return Ok(());
        }
        let result = match tokio::time::timeout_at(
            deadline,
            self.authority
                .audit_retention_maintenance(deadline.into_std()),
        )
        .await
        {
            Ok(Ok(Some(receipt))) => receipt
                .validate_for(&rekey_domain::audit::AuditPruneRequest {
                    before_ms: receipt.before_ms,
                })
                .map_err(BrokerError::Domain),
            Ok(Ok(None)) => Ok(()),
            Ok(Err(error)) => Err(BrokerError::Authority(error)),
            Err(_) => Err(BrokerError::Authority(AuthorityError::Faulted)),
        };
        if result.as_ref().is_err_and(|error| {
            !matches!(error, BrokerError::Authority(AuthorityError::AuthorityBusy))
        }) {
            // Close every admission while this owner still excludes queued work.
            self.lifecycle.enter_draining();
            self.lifecycle.mark_stop_pending();
            self.sessions.close_and_revoke_all();
            self.local_calls.clear();
            self.executor.oauth.clear();
            self.request_fault();
        }
        result
    }

    async fn run_drain_lock(
        &self,
        reason: &'static str,
        natural_deadline: tokio::time::Instant,
        stop_deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        #[cfg(feature = "lab")]
        if let Some(manager) = &self.oidc_admin {
            manager.clear();
        }
        match self.lifecycle.phase() {
            BrokerPhase::ShuttingDown => {
                return Err(BrokerError::Authority(AuthorityError::Draining));
            }
            BrokerPhase::Locked => {
                return self
                    .authority
                    .lock(reason)
                    .await
                    .map_err(BrokerError::Authority);
            }
            BrokerPhase::Draining | BrokerPhase::Running => {}
        }
        if self.lifecycle.phase() == BrokerPhase::Running {
            self.lifecycle.enter_draining();
            self.sessions.close_and_revoke_all();
            self.local_calls.clear();
            self.executor.oauth.clear();
        }
        self.wait_executes_drained_until(natural_deadline, stop_deadline)
            .await?;
        let audit = self.terminals.wait_idle_until(stop_deadline).await;
        match tokio::time::timeout_at(stop_deadline, self.authority.lock(reason)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
            }
        }
        *self.policy.write().await = None;
        *self.policy_trust.write().await = None;
        self.lifecycle.enter_locked();
        tracing::info!(event = "authority.state", state = "locked", reason);
        audit.map_err(BrokerError::Authority)
    }

    async fn wait_executes_drained_until(
        &self,
        natural_deadline: tokio::time::Instant,
        stop_deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        wait_in_flight_until(self, natural_deadline).await;
        if (self.sessions.in_flight_total() + self.lifecycle.local_in_flight()) > 0 {
            self.lifecycle.signal_cancel();
            wait_in_flight_until(self, stop_deadline).await;
        }
        if (self.sessions.in_flight_total() + self.lifecycle.local_in_flight()) > 0 {
            return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
        }
        Ok(())
    }
}

async fn wait_in_flight_until(ctx: &BrokerCtx, deadline: tokio::time::Instant) {
    loop {
        if ctx.sessions.in_flight_total() + ctx.lifecycle.local_in_flight() == 0 {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
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

fn set_group(path: &std::path::Path, gid: u32) -> Result<(), BrokerError> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        BrokerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path contains NUL",
        ))
    })?;
    let rc = unsafe { libc::chown(path.as_ptr(), libc::uid_t::MAX, gid) };
    if rc != 0 {
        return Err(BrokerError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn prepare_runtime_dir(
    path: &std::path::Path,
    mode: u32,
    gid: Option<u32>,
) -> Result<(), BrokerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(BrokerError::Authority(
                AuthorityError::InsecureStatePermissions,
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(BrokerError::Io(error)),
    }
    fs::create_dir_all(path).map_err(BrokerError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(BrokerError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(BrokerError::Authority(
            AuthorityError::InsecureStatePermissions,
        ));
    }
    if let Some(gid) = gid {
        set_group(path, gid)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(BrokerError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(BrokerError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != mode
        || gid.is_some_and(|expected| metadata.gid() != expected)
    {
        return Err(BrokerError::Authority(
            AuthorityError::InsecureStatePermissions,
        ));
    }
    Ok(())
}

fn bind_socket(
    path: &std::path::Path,
    mode: u32,
    gid: Option<u32>,
) -> Result<UnixListener, BrokerError> {
    if path.exists() {
        fs::remove_file(path).map_err(BrokerError::Io)?;
    }
    let listener = UnixListener::bind(path).map_err(BrokerError::Io)?;
    if let Some(gid) = gid {
        set_group(path, gid)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(BrokerError::Io)?;
    let metadata = fs::metadata(path).map_err(BrokerError::Io)?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != mode
        || gid.is_some_and(|expected| metadata.gid() != expected)
    {
        return Err(BrokerError::Authority(
            AuthorityError::InsecureStatePermissions,
        ));
    }
    Ok(listener)
}

fn resolved_future_path(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "path escapes filesystem root",
                    ));
                }
            }
        }
    }

    let mut cursor = normalized.as_path();
    let mut missing = Vec::new();
    while !cursor.exists() {
        let name = cursor.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "path has no existing ancestor",
            )
        })?;
        missing.push(name.to_owned());
        cursor = cursor.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "path has no existing ancestor",
            )
        })?;
    }
    let mut resolved = cursor.canonicalize()?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn validate_agent_endpoint(config: &BrokerConfig) -> Result<(), BrokerError> {
    let broker_uid = unsafe { libc::geteuid() };
    if config.allowed_agent_uids.is_empty()
        || (config.agent_runtime_dir.is_none()
            && (config.agent_socket_gid.is_some()
                || config
                    .allowed_agent_uids
                    .iter()
                    .any(|uid| *uid != broker_uid)))
        || (config
            .allowed_agent_uids
            .iter()
            .any(|uid| *uid != broker_uid)
            && config.agent_socket_gid.is_none())
    {
        return Err(BrokerError::Authority(
            AuthorityError::InsecureStatePermissions,
        ));
    }
    if let Some(agent_dir) = &config.agent_runtime_dir {
        match fs::symlink_metadata(agent_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BrokerError::Authority(
                    AuthorityError::InsecureStatePermissions,
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(BrokerError::Io(error)),
        }
        if config
            .allowed_agent_uids
            .iter()
            .any(|uid| *uid != broker_uid)
        {
            crate::ipc::peer::verify_cross_uid_runtime_ancestors(
                agent_dir,
                broker_uid,
                &config.allowed_agent_uids,
            )?;
        }
        let state_dir = config.state_dir.canonicalize().map_err(BrokerError::Io)?;
        let agent_dir = resolved_future_path(agent_dir).map_err(BrokerError::Io)?;
        if agent_dir.starts_with(&state_dir) || state_dir.starts_with(&agent_dir) {
            return Err(BrokerError::Authority(
                AuthorityError::InsecureStatePermissions,
            ));
        }
    }
    Ok(())
}

enum SelectedStop {
    Admin {
        proof: UnlockProof,
        reply: oneshot::Sender<Result<(), BrokerError>>,
    },
    Signal(&'static str),
    Fault,
    Execution(shutdown::ExecutionTaskResult),
}

async fn select_stop(
    lifecycle: &Lifecycle,
    stop_rx: &mut mpsc::UnboundedReceiver<shutdown::StopCommand>,
    sigterm: &mut tokio::signal::unix::Signal,
    sigint: &mut tokio::signal::unix::Signal,
    execution_task: &mut JoinHandle<Result<(), BrokerError>>,
) -> SelectedStop {
    let selected = tokio::select! {
        command = stop_rx.recv() => match command {
            Some(shutdown::StopCommand::Admin { proof, reply }) => {
                SelectedStop::Admin { proof, reply }
            }
            Some(shutdown::StopCommand::Fault) | None => SelectedStop::Fault,
        },
        _ = sigterm.recv() => SelectedStop::Signal("sigterm"),
        _ = sigint.recv() => SelectedStop::Signal("sigint"),
        result = &mut *execution_task => SelectedStop::Execution(result),
    };
    // Admin authentication must precede any stop admission change. A pending
    // coordinator owner may outlive the Admin deadline without stopping service.
    if !matches!(&selected, SelectedStop::Admin { .. }) {
        lifecycle.mark_stop_pending();
    }
    selected
}

/// Runs the broker until an admin Shutdown arrives. Foreground only.
pub async fn serve(config: BrokerConfig) -> Result<(), BrokerError> {
    verify_state_dir_permissions(&config.state_dir)?;
    #[cfg(feature = "lab")]
    let oidc_admin = config
        .oidc_admin_profile
        .as_deref()
        .map(crate::oidc_admin::Manager::load)
        .transpose()?;
    validate_agent_endpoint(&config)?;
    let _lock = acquire_serve_lock(&config.state_dir)?;
    // Register fallible process resources before spawning any runtime owner;
    // an initialization error must not detach a live Authority or listener.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(BrokerError::Io)?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(BrokerError::Io)?;

    let mut authority_config = AuthorityConfig::new(config.state_dir.clone());
    authority_config.idle_lock = config.idle_lock;
    authority_config.unlock_backoff_base = config.unlock_backoff_base;
    let (authority, authority_join) = rekey_vault::authority::spawn_authority(authority_config)?;

    #[cfg(feature = "lab")]
    if let Some(manager) = &oidc_admin {
        let actual = authority.status().await?;
        if actual.vault_id != manager.vault_id() {
            authority.shutdown(None).await?;
            tokio::task::spawn_blocking(move || authority_join.join())
                .await
                .map_err(|_| BrokerError::Authority(AuthorityError::Faulted))?
                .map_err(|_| BrokerError::Authority(AuthorityError::Faulted))?;
            return Err(BrokerError::Denied("OIDC profile vault mismatch"));
        }
    }
    let runtime_dir = paths::runtime_dir(&config.state_dir);
    prepare_runtime_dir(&runtime_dir, 0o700, None)?;
    let agent_runtime_dir = config
        .agent_runtime_dir
        .clone()
        .unwrap_or_else(|| runtime_dir.clone());
    if config.agent_runtime_dir.is_some() && agent_runtime_dir == runtime_dir {
        return Err(BrokerError::Authority(
            AuthorityError::InsecureStatePermissions,
        ));
    }
    if config.agent_runtime_dir.is_some() {
        let agent_dir_mode = if config.agent_socket_gid.is_some() {
            // The shared group only needs to traverse the Broker-owned
            // directory to connect to agent.sock. Group write would let an
            // Agent unlink and replace the Broker endpoint.
            0o750
        } else {
            0o700
        };
        prepare_runtime_dir(&agent_runtime_dir, agent_dir_mode, config.agent_socket_gid)?;
    }
    let agent_socket = agent_runtime_dir.join(paths::AGENT_SOCKET_FILE);
    let admin_listener = bind_socket(&paths::admin_socket(&config.state_dir), 0o600, None)?;
    let agent_mode = if config.agent_socket_gid.is_some() {
        0o660
    } else {
        0o600
    };
    let agent_listener = bind_socket(&agent_socket, agent_mode, config.agent_socket_gid)?;
    let ssh_socket = config.state_dir.join("ssh-agent.sock");
    let ssh_listener = bind_socket(&ssh_socket, 0o600, None)?;

    let sessions = Arc::new(SessionRegistry::new());
    let transport = config
        .transport
        .unwrap_or_else(|| Arc::new(ReqwestUpstreamTransport));
    let lifecycle = Arc::new(Lifecycle::new());
    let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
    let policy = Arc::new(RwLock::new(None));
    let policy_trust = Arc::new(RwLock::new(None));
    let executor = Arc::new(ActionExecutor::new(
        authority.clone(),
        Arc::clone(&sessions),
        Arc::clone(&transport),
        Arc::clone(&lifecycle),
        Arc::clone(&terminals),
        Arc::clone(&policy),
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (executions, execution_supervisor) =
        crate::execution_supervisor::new(Arc::clone(&executor));
    let mut execution_task = tokio::spawn(execution_supervisor.run(shutdown_rx.clone()));
    let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
    let ctx = Arc::new(BrokerCtx {
        state_dir: config.state_dir.clone(),
        #[cfg(feature = "lab")]
        metrics: crate::metrics::Metrics::default(),
        #[cfg(feature = "lab")]
        workload_transport: transport,
        #[cfg(feature = "lab")]
        online_jwks_slots: Arc::new(tokio::sync::Semaphore::new(MAX_ONLINE_JWKS_FETCHES)),
        authority: authority.clone(),
        #[cfg(feature = "lab")]
        oidc_admin,
        sessions,
        executions,
        local_calls: Arc::clone(&executor.local_calls),
        executor,
        lifecycle,
        policy,
        policy_trust,
        gateway: gateway::Gateway::new(config.state_dir.clone(), config.service_port),
        terminals,
        drain_timeout: config.drain_timeout,
        shutdown_flag: AtomicBool::new(false),
        shutdown_tx,
        stop_tx,
        allowed_agent_uids: config.allowed_agent_uids.into(),
    });

    ctx.gateway.attach(&ctx);
    ctx.executor.oauth.attach(&ctx);
    if let Err(error) = ctx.start_local_service().await {
        ctx.publish_shutdown();
        let _ = execution_task.await;
        let _ = authority.shutdown(None).await;
        return Err(error);
    }

    #[cfg(feature = "lab")]
    let mut oidc_poll_task = ctx.oidc_admin.clone().map(|manager| {
        let weak = Arc::downgrade(&ctx);
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _=shutdown.changed()=>break,
                    _=tick.tick()=>{
                        let Some(ctx)=weak.upgrade() else {break};
                        if ctx.lifecycle.is_running() {
                            tokio::select! { _=shutdown.changed()=>break, _=manager.poll(&ctx)=>() }
                        }
                    }
                }
            }
            manager.clear();
        })
    });

    // Reserve Admin capacity. An untrusted Agent can exhaust only its own
    // channel and must never make lock or shutdown unreachable.
    let admin_slots = Arc::new(tokio::sync::Semaphore::new(MAX_ADMIN_REQUEST_CONNECTIONS));
    let agent_slots = Arc::new(tokio::sync::Semaphore::new(MAX_AGENT_REQUEST_CONNECTIONS));

    let idle_ctx = Arc::clone(&ctx);
    let idle_lock = config.idle_lock;
    let idle_interval = idle_lock
        .min(Duration::from_secs(5))
        .max(Duration::from_millis(10));
    let mut idle_shutdown = shutdown_rx.clone();
    let idle_task = tokio::spawn(async move {
        let mut next_retention_tick = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(idle_interval) => {
                    if idle_ctx.lifecycle.phase() == BrokerPhase::Running {
                        match idle_ctx.try_idle_lock(idle_lock).await {
                            Ok(()) => {}
                            Err(BrokerError::Authority(AuthorityError::AuthorityBusy)) => {
                                tracing::warn!(event = "runtime.idle_lock_deferred", code = "AUTHORITY_BUSY");
                            }
                            Err(error) => {
                                tracing::error!(event = "runtime.idle_lock_fault", code = error.code());
                                idle_ctx.request_fault();
                                return Err(error);
                            }
                        }
                    }
                    match idle_ctx.audit_retention_tick(&mut next_retention_tick).await {
                        Ok(()) => {}
                        Err(BrokerError::Authority(AuthorityError::AuthorityBusy)) => {
                            tracing::warn!(event = "runtime.audit_retention_deferred", code = "AUTHORITY_BUSY");
                        }
                        Err(error) => {
                            tracing::error!(event = "runtime.audit_retention_fault", code = error.code());
                            return Err(error);
                        }
                    }
                }
                _ = idle_shutdown.changed() => return Ok(()),
            }
        }
    });

    let mut ssh_task = tokio::spawn(connections::accept_ssh_loop(
        ssh_listener,
        Arc::clone(&ctx),
        shutdown_rx.clone(),
    ));
    let mut admin_task = tokio::spawn(connections::accept_loop(
        admin_listener,
        Arc::clone(&ctx),
        admin_slots,
        shutdown_rx.clone(),
        true,
    ));
    let mut agent_task = tokio::spawn(connections::accept_loop(
        agent_listener,
        Arc::clone(&ctx),
        agent_slots,
        shutdown_rx.clone(),
        false,
    ));

    let (mut runtime_error, stop_deadline) = loop {
        let selected = select_stop(
            &ctx.lifecycle,
            &mut stop_rx,
            &mut sigterm,
            &mut sigint,
            &mut execution_task,
        )
        .await;
        let deadline = shutdown::deadline(config.drain_timeout);
        let (cause, admin_reply, completed_execution) = match selected {
            SelectedStop::Admin { proof, reply } => {
                (shutdown::StopCause::Admin(proof), Some(reply), None)
            }
            SelectedStop::Signal(signal) => {
                tracing::info!(event = "runtime.signal_received", signal);
                (shutdown::StopCause::Signal, None, None)
            }
            SelectedStop::Fault => (shutdown::StopCause::Fault, None, None),
            SelectedStop::Execution(result) => {
                tracing::error!(
                    event = "runtime.execution_supervisor_stopped",
                    code = "FAULTED"
                );
                (shutdown::StopCause::Fault, None, Some(result))
            }
        };
        match ctx
            .central_stop(cause, deadline, &mut execution_task, completed_execution)
            .await
        {
            shutdown::StopDisposition::Rejected(err) => {
                if let Some(reply) = admin_reply {
                    if reply.send(Err(err)).is_err() {
                        tracing::debug!(event = "runtime.admin_shutdown_reply_dropped");
                    }
                    continue;
                }
                break (Some(err), deadline);
            }
            shutdown::StopDisposition::Stopped(error) => {
                if let Some(reply) = admin_reply {
                    match error {
                        Some(err) => {
                            tracing::error!(event = "runtime.stop_failed", code = err.code());
                            if reply.send(Err(err)).is_err() {
                                tracing::debug!(event = "runtime.admin_shutdown_reply_dropped");
                            }
                            break (
                                Some(BrokerError::Authority(AuthorityError::Faulted)),
                                deadline,
                            );
                        }
                        None => {
                            if reply.send(Ok(())).is_err() {
                                tracing::debug!(event = "runtime.admin_shutdown_reply_dropped");
                            }
                            break (None, deadline);
                        }
                    }
                }
                break (error, deadline);
            }
        }
    };

    let mut idle_task = idle_task;
    // central_stop may consume the full stop budget. Preserve a bounded tail
    // for the admin connection to flush the already-produced shutdown reply.
    let connection_deadline = std::cmp::max(
        stop_deadline,
        tokio::time::Instant::now() + Duration::from_secs(1),
    );
    match tokio::time::timeout_at(connection_deadline, async {
        tokio::join!(
            &mut admin_task,
            &mut agent_task,
            &mut idle_task,
            &mut ssh_task
        )
    })
    .await
    {
        Ok((admin_result, agent_result, idle_result, ssh_result)) => {
            if runtime_error.is_none() {
                runtime_error = [admin_result, agent_result, idle_result, ssh_result]
                    .into_iter()
                    .find_map(|result| match result {
                        Ok(Ok(())) => None,
                        Ok(Err(err)) => Some(err),
                        Err(_) => Some(BrokerError::Authority(AuthorityError::Faulted)),
                    });
            }
        }
        Err(_) => {
            admin_task.abort();
            agent_task.abort();
            idle_task.abort();
            ssh_task.abort();
            runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
            tracing::error!(event = "runtime.connection_join_timeout", code = "FAULTED");
        }
    }
    #[cfg(feature = "lab")]
    if let Some(task) = &mut oidc_poll_task {
        match tokio::time::timeout_at(stop_deadline, &mut *task).await {
            Ok(Ok(())) => (),
            Ok(Err(_)) => {
                runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
            }
            Err(_) => {
                task.abort();
                runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
            }
        }
    }
    drop(ctx);
    let mut terminal_task = terminal_task;
    match tokio::time::timeout_at(stop_deadline, &mut terminal_task).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
        }
        Err(_) => {
            terminal_task.abort();
            runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
            tracing::error!(event = "runtime.terminal_join_timeout", code = "FAULTED");
        }
    }

    let _ = fs::remove_file(paths::admin_socket(&config.state_dir));
    let _ = fs::remove_file(ssh_socket);
    let _ = fs::remove_file(agent_socket);

    drop(authority);
    while !authority_join.is_finished() && tokio::time::Instant::now() < stop_deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if authority_join.is_finished() {
        if authority_join.join().is_err() {
            runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
        }
    } else {
        drop(authority_join);
        runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
        tracing::error!(event = "runtime.authority_join_timeout", code = "FAULTED");
    }
    match runtime_error {
        Some(err) => Err(err),
        None => rekey_vault::authority::finish_runtime(&config.state_dir).map_err(Into::into),
    }
}

#[cfg(test)]
pub(crate) mod tests;

pub(crate) fn call_audit(
    event: &'static str,
    connection: &str,
    caller: &str,
) -> Result<rekey_vault::command::AuditDraft, BrokerError> {
    Ok(rekey_vault::command::AuditDraft {
        request_id: Some(crate::random_id(
            rekey_domain::ids::RequestId::from_random_bytes,
        )?),
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        request_context: Some(rekey_domain::audit::RequestAuditContext::Connection(
            rekey_domain::connection::ConnectionRequestAuditContext {
                connection: connection.to_owned(),
                caller: caller.to_owned(),
                method_class: rekey_domain::connection::MethodClass::Read,
                normalized_path: "/".into(),
                rule_id: None,
            },
        )),
        usage: None,
        event_type: event,
        outcome: rekey_vault::model::outcome::SUCCESS,
        reason_code: "local-call".into(),
        upstream_status: None,
        latency_ms: None,
    })
}

/// Public connection evidence for non-execution OAuth lifecycle events.
pub(crate) fn oauth_audit(
    event: &'static str,
    connection: &rekey_domain::connection::Connection,
    active: &ActivePolicy,
) -> Result<rekey_vault::command::AuditDraft, BrokerError> {
    use sha2::{Digest, Sha256};
    let mut draft = call_audit(event, &connection.name, "rekeyd")?;
    let digest = Sha256::digest(connection.name.as_bytes());
    let mut principal = [0; 16];
    principal.copy_from_slice(&digest[..16]);
    draft.credential_id = Some(connection.credential_id);
    draft.authorization = Some(Box::new(rekey_vault::model::AuthorizationEvidence {
        principal_id: rekey_domain::ids::PrincipalId::from_random_bytes(principal),
        policy_version: active.snapshot().version().get(),
        policy_digest: active.snapshot().digest(),
        policy_rule_id: None,
        resource_type: "connection".into(),
        resource_id: connection.name.clone(),
        parameter_hash: Sha256::digest(
            serde_jcs::to_vec(&connection.oauth)
                .map_err(|_| rekey_domain::ipc::FrameError::InvalidField)?,
        )
        .into(),
    }));
    Ok(draft)
}
