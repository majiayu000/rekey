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
use rekey_vault::AuthorityError;
use rekey_vault::bootstrap::verify_state_dir_permissions;
use rekey_vault::command::UnlockProof;
use rekey_vault::handle::{AuthorityConfig, AuthorityHandle};
use rekey_vault::paths;
use tokio::net::UnixListener;
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::active_policy::ActivePolicy;
use crate::audit::{TerminalAuditTracker, spawn_terminal_worker};
use crate::error::BrokerError;
use crate::execution_supervisor::ExecutionSupervisorHandle;
use crate::executor::ActionExecutor;
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::SessionRegistry;
use crate::upstream::{ReqwestUpstreamTransport, UpstreamTransport};

mod admin;
mod shutdown;

pub const MAX_AGENT_CONNECTIONS: usize = 120;
pub const MAX_ADMIN_CONNECTIONS: usize = 8;

pub fn default_drain_timeout() -> Duration {
    Duration::from_millis(ACTION_TIMEOUT_HARD_MAX_MS as u64)
}

pub struct BrokerConfig {
    pub state_dir: PathBuf,
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
    pub authority: AuthorityHandle,
    pub sessions: Arc<SessionRegistry>,
    pub(crate) executions: ExecutionSupervisorHandle,
    pub lifecycle: Arc<Lifecycle>,
    policy: Arc<RwLock<Option<Arc<ActivePolicy>>>>,
    terminals: Arc<TerminalAuditTracker>,
    drain_timeout: Duration,
    shutdown_flag: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    stop_tx: mpsc::UnboundedSender<shutdown::StopCommand>,
    allowed_agent_uids: Arc<[u32]>,
}

impl BrokerCtx {
    pub(crate) fn publish_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if self.shutdown_tx.send(true).is_err() {
            tracing::debug!(event = "runtime.shutdown_notice_without_receivers");
        }
    }

    pub(crate) fn request_fault(&self) {
        let _ = self.stop_tx.send(shutdown::StopCommand::Fault);
    }

    pub(crate) async fn request_admin_shutdown(
        &self,
        proof: Option<UnlockProof>,
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

    pub async fn unlock(&self, proof: UnlockProof) -> Result<(), BrokerError> {
        let _owner = self
            .lifecycle
            .try_coordinate()
            .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?;
        self.lifecycle.reject_if_busy()?;
        self.authority.unlock(proof).await?;
        self.sessions.open_for_admission();
        self.lifecycle.enter_running();
        tracing::info!(event = "authority.state", state = "running");
        Ok(())
    }

    /// Revoke sessions, wait in-flight executes, then zeroize the VRK.
    pub async fn drain_lock(&self, reason: &'static str) -> Result<(), BrokerError> {
        let natural_deadline = tokio::time::Instant::now() + self.drain_timeout;
        let stop_deadline = natural_deadline + Duration::from_secs(5);
        let _owner = self.lifecycle.coordinate_until(stop_deadline).await?;
        self.run_drain_lock(reason, natural_deadline, stop_deadline)
            .await
    }

    /// Idle must not become a second drain owner: skip if lock/shutdown holds
    /// the coordinator, then re-read activity under the coordinator so a
    /// completed admin operation cannot be followed by a drain from stale
    /// status.
    pub async fn try_idle_lock(&self, idle_lock: Duration) -> Result<(), BrokerError> {
        let Ok(_owner) = self.lifecycle.try_coordinate() else {
            return Ok(());
        };
        let status = self.authority.status().await?;
        if status.state == "unlocked"
            && status.idle_for_ms >= idle_lock.as_millis() as u64
            && self.sessions.in_flight_total() == 0
        {
            // A terminal audit refreshes activity before its execution permit
            // drops. Re-reading after observing zero in-flight prevents stale
            // pre-completion status from immediately locking the authority.
            let status = self.authority.status().await?;
            if status.state != "unlocked"
                || status.idle_for_ms < idle_lock.as_millis() as u64
                || self.sessions.in_flight_total() != 0
            {
                return Ok(());
            }
            let natural_deadline = tokio::time::Instant::now() + self.drain_timeout;
            let stop_deadline = natural_deadline + Duration::from_secs(5);
            self.run_drain_lock("idle-timeout", natural_deadline, stop_deadline)
                .await?;
        }
        Ok(())
    }

    async fn run_drain_lock(
        &self,
        reason: &'static str,
        natural_deadline: tokio::time::Instant,
        stop_deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
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
        self.lifecycle.enter_locked();
        tracing::info!(event = "authority.state", state = "locked", reason);
        audit.map_err(BrokerError::Authority)
    }

    async fn wait_executes_drained_until(
        &self,
        natural_deadline: tokio::time::Instant,
        stop_deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        wait_in_flight_until(&self.sessions, natural_deadline).await;
        if self.sessions.in_flight_total() > 0 {
            self.lifecycle.signal_cancel();
            wait_in_flight_until(&self.sessions, stop_deadline).await;
        }
        if self.sessions.in_flight_total() > 0 {
            return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
        }
        Ok(())
    }
}

async fn wait_in_flight_until(sessions: &SessionRegistry, deadline: tokio::time::Instant) {
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
                        ctx.request_fault();
                        return Err(BrokerError::Io(err));
                    }
                };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    continue;
                };
                let ctx = Arc::clone(&ctx);
                let conn_shutdown = shutdown.clone();
                conns.spawn(async move {
                    if admin {
                        crate::ipc::admin::handle_admin_conn(stream, ctx, conn_shutdown).await;
                    } else {
                        crate::ipc::agent::handle_agent_conn(stream, ctx, conn_shutdown).await;
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
        proof: Option<UnlockProof>,
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
    lifecycle.close_remote_effect_admission();
    selected
}

/// Runs the broker until an admin Shutdown arrives. Foreground only.
pub async fn serve(config: BrokerConfig) -> Result<(), BrokerError> {
    verify_state_dir_permissions(&config.state_dir)?;
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
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (executions, execution_supervisor) = crate::execution_supervisor::new(executor);
    let mut execution_task = tokio::spawn(execution_supervisor.run(shutdown_rx.clone()));
    let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
    let ctx = Arc::new(BrokerCtx {
        authority: authority.clone(),
        sessions,
        executions,
        lifecycle,
        policy,
        terminals,
        drain_timeout: config.drain_timeout,
        shutdown_flag: AtomicBool::new(false),
        shutdown_tx,
        stop_tx,
        allowed_agent_uids: config.allowed_agent_uids.into(),
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
                    match idle_ctx.try_idle_lock(idle_lock).await {
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
                            idle_ctx.request_fault();
                            return Err(err);
                        }
                    }
                }
                _ = idle_shutdown.changed() => return Ok(()),
            }
        }
    });

    let mut admin_task = tokio::spawn(accept_loop(
        admin_listener,
        Arc::clone(&ctx),
        admin_slots,
        shutdown_rx.clone(),
        true,
    ));
    let mut agent_task = tokio::spawn(accept_loop(
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
        tokio::join!(&mut admin_task, &mut agent_task, &mut idle_task)
    })
    .await
    {
        Ok((admin_result, agent_result, idle_result)) => {
            if runtime_error.is_none() {
                runtime_error = [admin_result, agent_result, idle_result]
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
            runtime_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
            tracing::error!(event = "runtime.connection_join_timeout", code = "FAULTED");
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
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
