//! BrokerRuntime: owns the two Unix listeners, the session registry, the
//! executor, and the AuthorityWorker lifecycle. Starts locked; never reads
//! secrets from the environment.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rekey_domain::action::ACTION_TIMEOUT_HARD_MAX_MS;
use rekey_domain::ipc::PolicyStatusResponse;
use rekey_policy::ValidatedSnapshot;
use rekey_vault::AuthorityError;
use rekey_vault::bootstrap::verify_state_dir_permissions;
use rekey_vault::command::UnlockProof;
use rekey_vault::handle::{AuthorityConfig, AuthorityHandle};
use rekey_vault::paths;
use tokio::net::UnixListener;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinSet;

use crate::audit::{TerminalAuditTracker, spawn_terminal_worker};
use crate::error::BrokerError;
use crate::executor::ActionExecutor;
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::SessionRegistry;
use crate::upstream::{ReqwestUpstreamTransport, UpstreamTransport};

pub const MAX_AGENT_CONNECTIONS: usize = 120;
pub const MAX_ADMIN_CONNECTIONS: usize = 8;

pub fn default_drain_timeout() -> Duration {
    Duration::from_millis(ACTION_TIMEOUT_HARD_MAX_MS as u64)
}

pub struct BrokerConfig {
    pub state_dir: PathBuf,
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
            idle_lock: rekey_vault::handle::DEFAULT_IDLE_LOCK,
            transport: None,
            unlock_backoff_base: Duration::from_secs(1),
            drain_timeout: default_drain_timeout(),
        }
    }
}

pub struct BrokerCtx {
    pub authority: AuthorityHandle,
    pub sessions: Arc<SessionRegistry>,
    pub executor: Arc<ActionExecutor>,
    pub lifecycle: Arc<Lifecycle>,
    policy: Arc<RwLock<Option<Arc<ValidatedSnapshot>>>>,
    terminals: Arc<TerminalAuditTracker>,
    drain_timeout: Duration,
    shutdown_flag: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
}

impl BrokerCtx {
    pub async fn policy_status(&self) -> PolicyStatusResponse {
        let guard = self.policy.read().await;
        match guard.as_ref() {
            Some(snapshot) => PolicyStatusResponse {
                active: true,
                version: Some(snapshot.version().get()),
                expires_at_ms: Some(snapshot.expires_at_ms()),
                sha256_hex: Some(data_encoding::HEXLOWER.encode(&snapshot.digest())),
            },
            None => PolicyStatusResponse {
                active: false,
                version: None,
                expires_at_ms: None,
                sha256_hex: None,
            },
        }
    }

    pub async fn activate_policy(
        &self,
        snapshot: ValidatedSnapshot,
        proof: UnlockProof,
    ) -> Result<(), BrokerError> {
        self.lifecycle.reject_if_not_running()?;
        self.authority.verify_proof(proof).await?;
        self.lifecycle.reject_if_not_running()?;
        let mut guard = self.policy.write().await;
        if guard
            .as_ref()
            .is_some_and(|current| snapshot.version() <= current.version())
        {
            return Err(BrokerError::Denied("policy-version-not-increasing"));
        }
        self.authority
            .append_audit(rekey_vault::command::AuditDraft {
                request_id: None,
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                event_type: rekey_vault::model::event_type::POLICY_ACTIVATED,
                outcome: rekey_vault::model::outcome::SUCCESS,
                reason_code: "policy-activated".to_owned(),
                upstream_status: None,
                latency_ms: None,
            })
            .await?;
        *guard = Some(Arc::new(snapshot));
        Ok(())
    }

    pub fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_flag.load(Ordering::SeqCst)
    }

    pub async fn unlock(&self, proof: UnlockProof) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate().await;
        self.lifecycle.reject_if_busy()?;
        self.authority.unlock(proof).await?;
        self.sessions.open_for_admission();
        self.lifecycle.enter_running();
        tracing::info!(event = "authority.state", state = "running");
        Ok(())
    }

    /// Revoke sessions, wait in-flight executes, then zeroize the VRK.
    pub async fn drain_lock(&self, reason: &'static str) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate().await;
        self.run_drain_lock(reason).await
    }

    /// Idle must not become a second drain owner: skip if lock/shutdown holds
    /// the coordinator.
    pub async fn try_drain_lock(&self, reason: &'static str) -> Result<(), BrokerError> {
        let Ok(_owner) = self.lifecycle.try_coordinate() else {
            return Ok(());
        };
        self.run_drain_lock(reason).await
    }

    async fn run_drain_lock(&self, reason: &'static str) -> Result<(), BrokerError> {
        match self.lifecycle.phase() {
            BrokerPhase::ShuttingDown => {
                return Err(BrokerError::Authority(AuthorityError::Draining));
            }
            BrokerPhase::Locked => return Ok(()),
            BrokerPhase::Draining | BrokerPhase::Running => {}
        }
        if self.lifecycle.phase() == BrokerPhase::Running {
            self.lifecycle.enter_draining();
            self.sessions.close_and_revoke_all();
        }
        self.wait_executes_drained().await?;
        let audit = self.terminals.wait_idle(self.drain_timeout).await;
        self.authority.lock(reason).await?;
        *self.policy.write().await = None;
        self.lifecycle.enter_locked();
        tracing::info!(event = "authority.state", state = "locked", reason);
        audit.map_err(BrokerError::Authority)
    }

    /// Same drain, then stop the worker and accept loops.
    pub async fn drain_and_shutdown(&self, proof: Option<UnlockProof>) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate().await;
        let status = self.authority.status().await?;
        if status.state == "unlocked" && proof.is_none() {
            return Err(BrokerError::Authority(AuthorityError::AuthenticationFailed));
        }
        if self.lifecycle.phase() != BrokerPhase::ShuttingDown {
            self.lifecycle.enter_shutting_down();
            self.sessions.close_and_revoke_all();
        }
        self.wait_executes_drained().await?;
        let audit = self.terminals.wait_idle(self.drain_timeout).await;
        if audit.is_err() && self.terminals.has_pending() {
            return Err(BrokerError::Authority(AuthorityError::AuditCommitFailed));
        }
        self.authority.shutdown(proof).await?;
        *self.policy.write().await = None;
        tracing::info!(event = "authority.state", state = "shutting_down");
        self.request_shutdown();
        audit.map_err(BrokerError::Authority)
    }

    async fn wait_executes_drained(&self) -> Result<(), BrokerError> {
        wait_in_flight(&self.sessions, self.drain_timeout).await;
        if self.sessions.in_flight_total() > 0 {
            self.lifecycle.signal_cancel();
            wait_in_flight(&self.sessions, self.drain_timeout).await;
        }
        if self.sessions.in_flight_total() > 0 {
            return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
        }
        Ok(())
    }
}

async fn wait_in_flight(sessions: &SessionRegistry, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if sessions.in_flight_total() == 0 {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn accept_loop(
    listener: UnixListener,
    ctx: Arc<BrokerCtx>,
    slots: Arc<tokio::sync::Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    admin: bool,
) -> Result<(), BrokerError> {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::error!(
                            event = "runtime.listener_fault",
                            channel = if admin { "admin" } else { "agent" },
                            code = "IPC_UNAVAILABLE"
                        );
                        ctx.request_shutdown();
                        while conns.join_next().await.is_some() {}
                        return Err(BrokerError::Io(err));
                    }
                };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    continue;
                };
                let ctx = Arc::clone(&ctx);
                conns.spawn(async move {
                    if admin {
                        crate::ipc::admin::handle_admin_conn(stream, ctx).await;
                    } else {
                        crate::ipc::agent::handle_agent_conn(stream, ctx).await;
                    }
                    drop(permit);
                });
            }
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    while conns.join_next().await.is_some() {}
    Ok(())
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
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(AuthorityError::storage(std::io::Error::last_os_error()));
    }
    Ok(ServeLock { _file: file })
}

fn bind_socket(path: &std::path::Path) -> Result<UnixListener, BrokerError> {
    if path.exists() {
        fs::remove_file(path).map_err(BrokerError::Io)?;
    }
    let listener = UnixListener::bind(path).map_err(BrokerError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(BrokerError::Io)?;
    let mode = fs::metadata(path)
        .map_err(BrokerError::Io)?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(BrokerError::Authority(
            AuthorityError::InsecureStatePermissions,
        ));
    }
    Ok(listener)
}

/// Runs the broker until an admin Shutdown arrives. Foreground only.
pub async fn serve(config: BrokerConfig) -> Result<(), BrokerError> {
    verify_state_dir_permissions(&config.state_dir)?;
    let _lock = acquire_serve_lock(&config.state_dir)?;

    let mut authority_config = AuthorityConfig::new(config.state_dir.clone());
    authority_config.idle_lock = config.idle_lock;
    authority_config.unlock_backoff_base = config.unlock_backoff_base;
    let (authority, authority_join) = rekey_vault::authority::spawn_authority(authority_config)?;

    let runtime_dir = paths::runtime_dir(&config.state_dir);
    fs::create_dir_all(&runtime_dir).map_err(BrokerError::Io)?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))
        .map_err(BrokerError::Io)?;
    let admin_listener = bind_socket(&paths::admin_socket(&config.state_dir))?;
    let agent_listener = bind_socket(&paths::agent_socket(&config.state_dir))?;

    let sessions = Arc::new(SessionRegistry::new());
    let transport = config
        .transport
        .unwrap_or_else(|| Arc::new(ReqwestUpstreamTransport));
    let lifecycle = Arc::new(Lifecycle::new());
    let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
    let policy = Arc::new(RwLock::new(None));
    let executor = Arc::new(ActionExecutor::new(
        authority.clone(),
        Arc::clone(&sessions),
        transport,
        Arc::clone(&lifecycle),
        Arc::clone(&terminals),
        Arc::clone(&policy),
    ));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let ctx = Arc::new(BrokerCtx {
        authority: authority.clone(),
        sessions,
        executor,
        lifecycle,
        policy,
        terminals,
        drain_timeout: config.drain_timeout,
        shutdown_flag: AtomicBool::new(false),
        shutdown_tx,
    });

    // Reserve Admin capacity. An untrusted Agent can exhaust only its own
    // channel and must never make lock or shutdown unreachable.
    let admin_slots = Arc::new(tokio::sync::Semaphore::new(MAX_ADMIN_CONNECTIONS));
    let agent_slots = Arc::new(tokio::sync::Semaphore::new(MAX_AGENT_CONNECTIONS));

    let idle_ctx = Arc::clone(&ctx);
    let idle_lock = config.idle_lock;
    let idle_interval = idle_lock
        .min(Duration::from_secs(5))
        .max(Duration::from_millis(10));
    let mut idle_shutdown = shutdown_rx.clone();
    let idle_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(idle_interval) => {
                    if idle_ctx.lifecycle.phase() != BrokerPhase::Running {
                        continue;
                    }
                    let status = match idle_ctx.authority.status().await {
                        Ok(status) => status,
                        Err(AuthorityError::AuthorityBusy) => {
                            tracing::warn!(
                                event = "runtime.idle_check_deferred",
                                code = "AUTHORITY_BUSY"
                            );
                            continue;
                        }
                        Err(err) => {
                            tracing::error!(
                                event = "runtime.idle_check_fault",
                                code = err.code()
                            );
                            idle_ctx.request_shutdown();
                            return Err(BrokerError::Authority(err));
                        }
                    };
                    if status.state == "unlocked"
                        && status.idle_for_ms >= idle_lock.as_millis() as u64
                    {
                        match idle_ctx.try_drain_lock("idle-timeout").await {
                            Ok(()) => {}
                            Err(BrokerError::Authority(AuthorityError::AuthorityBusy)) => {
                                tracing::warn!(
                                    event = "runtime.idle_lock_deferred",
                                    code = "AUTHORITY_BUSY"
                                );
                            }
                            Err(err) => {
                                tracing::error!(
                                    event = "runtime.idle_lock_fault",
                                    code = err.code()
                                );
                                idle_ctx.request_shutdown();
                                return Err(err);
                            }
                        }
                    }
                }
                _ = idle_shutdown.changed() => return Ok(()),
            }
        }
    });

    let admin_task = tokio::spawn(accept_loop(
        admin_listener,
        Arc::clone(&ctx),
        admin_slots,
        shutdown_rx.clone(),
        true,
    ));
    let agent_task = tokio::spawn(accept_loop(
        agent_listener,
        Arc::clone(&ctx),
        agent_slots,
        shutdown_rx.clone(),
        false,
    ));

    // Wait for shutdown.
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
    let (admin_result, agent_result, idle_result) = tokio::join!(admin_task, agent_task, idle_task);
    let mut runtime_error = [admin_result, agent_result, idle_result]
        .into_iter()
        .find_map(|result| match result {
            Ok(Ok(())) => None,
            Ok(Err(err)) => Some(err),
            Err(_) => Some(BrokerError::Authority(AuthorityError::Faulted)),
        });

    if runtime_error.is_some() {
        // A listener/idle supervisor fault must not leave a half-alive daemon.
        // Use the normal drain/lock path so in-flight terminal audit semantics
        // remain intact, then stop the now-locked VRK owner without proof.
        if let Err(err) = ctx.drain_lock("runtime-fault").await {
            tracing::error!(event = "runtime.fault_drain_failed", code = err.code());
        }
        if let Err(err) = ctx.authority.shutdown(None).await {
            tracing::error!(event = "runtime.fault_shutdown_failed", code = err.code());
        }
    }
    drop(ctx);
    if terminal_task.await.is_err() && runtime_error.is_none() {
        runtime_error = Some(BrokerError::Authority(AuthorityError::Faulted));
    }

    let _ = fs::remove_file(paths::admin_socket(&config.state_dir));
    let _ = fs::remove_file(paths::agent_socket(&config.state_dir));

    // The authority worker exits after processing Shutdown; joining here
    // guarantees the VRK owner is gone before serve returns.
    if tokio::task::spawn_blocking(move || authority_join.join())
        .await
        .is_err()
        && runtime_error.is_none()
    {
        runtime_error = Some(BrokerError::Authority(AuthorityError::Faulted));
    }
    match runtime_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}
