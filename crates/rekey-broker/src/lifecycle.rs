//! Broker-owned lifecycle: one coordinator for idle / explicit lock /
//! shutdown. Phase is not an AtomicBool that concurrent drains can flip.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use rekey_domain::ids::{CredentialId, RequestId};
use rekey_vault::AuthorityError;
use tokio::sync::{Mutex, MutexGuard, TryLockError, watch};

use crate::error::BrokerError;

const REMOTE_EFFECT_CLOSED: u8 = 0;
const REMOTE_EFFECT_OPEN: u8 = 1;
const REMOTE_EFFECT_STOP_PENDING: u8 = 2;

pub(crate) const MAX_CONNECTION_EXECUTIONS: u32 = 120;
pub(crate) const MAX_EXECUTIONS_PER_CONNECTION: u32 = 4;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerPhase {
    Locked = 0,
    Running = 1,
    Draining = 2,
    ShuttingDown = 3,
}

impl BrokerPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Draining,
            3 => Self::ShuttingDown,
            _ => Self::Locked,
        }
    }
}

pub struct Lifecycle {
    local_in_flight: AtomicU32,
    connection_in_flight: StdMutex<BTreeMap<String, u32>>,
    phase: AtomicU8,
    coordinator: Mutex<()>,
    cancel_tx: watch::Sender<bool>,
    remote_effect_gate: AtomicU8,
    private_credentials: StdMutex<BTreeMap<(CredentialId, RequestId), watch::Sender<bool>>>,
    private_closed: tokio::sync::Notify,
}

impl Lifecycle {
    pub fn new() -> Self {
        let (cancel_tx, _) = watch::channel(false);
        Self {
            local_in_flight: AtomicU32::new(0),
            connection_in_flight: StdMutex::new(BTreeMap::new()),
            phase: AtomicU8::new(BrokerPhase::Locked as u8),
            coordinator: Mutex::new(()),
            cancel_tx,
            remote_effect_gate: AtomicU8::new(REMOTE_EFFECT_CLOSED),
            private_credentials: StdMutex::new(BTreeMap::new()),
            private_closed: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn local_in_flight(&self) -> u32 {
        self.local_in_flight.load(Ordering::SeqCst)
    }

    // Called under the coordinator before the admitted execution is published.
    pub(crate) fn local_permit(self: &Arc<Self>) -> LocalExecutionPermit {
        self.local_in_flight.fetch_add(1, Ordering::SeqCst);
        LocalExecutionPermit(Arc::clone(self))
    }

    // Caller labels do not create another slot. Keep the permit with the
    // durable started/terminal owner, including asynchronous fallback commits.
    pub(crate) fn connection_permit(
        self: &Arc<Self>,
        connection: &str,
    ) -> Result<ConnectionExecutionPermit, BrokerError> {
        self.reject_if_not_running()?;
        if !self.try_begin_remote_effect() {
            return Err(BrokerError::Admission(AuthorityError::Draining));
        }
        let mut active = self
            .connection_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if active.values().sum::<u32>() >= MAX_CONNECTION_EXECUTIONS
            || active.get(connection).copied().unwrap_or(0) >= MAX_EXECUTIONS_PER_CONNECTION
        {
            return Err(BrokerError::Admission(AuthorityError::AuthorityBusy));
        }
        *active.entry(connection.to_owned()).or_default() += 1;
        Ok(ConnectionExecutionPermit {
            local: self.local_permit(),
            connection: connection.to_owned(),
            needs_terminal: false,
        })
    }

    // Registration and cancellation are serialized by the existing coordinator.
    // This tracks live private-key owners only; authorization stays in policy.
    pub(crate) fn private_credential_owner(
        self: &Arc<Self>,
        credential: CredentialId,
        request: RequestId,
    ) -> Result<PrivateCredentialOwner, BrokerError> {
        self.reject_if_not_running()?;
        let (cancel, receiver) = watch::channel(false);
        let mut owners = self
            .private_credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if owners.contains_key(&(credential, request)) {
            return Err(BrokerError::Admission(AuthorityError::AuthorityBusy));
        }
        owners.insert((credential, request), cancel);
        Ok(PrivateCredentialOwner {
            lifecycle: Arc::clone(self),
            credential,
            request,
            cancel: receiver,
        })
    }

    pub(crate) async fn cancel_private_credentials_until(
        &self,
        credential: Option<CredentialId>,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        {
            let owners = self
                .private_credentials
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for ((id, _), cancel) in owners
                .iter()
                .filter(|((id, _), _)| credential.is_none_or(|target| target == *id))
            {
                let _ = id;
                cancel.send_replace(true);
            }
        }
        loop {
            let closed = self.private_closed.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            if !self
                .private_credentials
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .keys()
                .any(|(id, _)| credential.is_none_or(|target| target == *id))
            {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, closed)
                .await
                .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?;
        }
    }

    pub fn phase(&self) -> BrokerPhase {
        BrokerPhase::from_u8(self.phase.load(Ordering::SeqCst))
    }

    pub fn is_running(&self) -> bool {
        self.phase() == BrokerPhase::Running
    }

    pub fn subscribe_cancel(&self) -> watch::Receiver<bool> {
        self.cancel_tx.subscribe()
    }

    /// SessionCreate and mutations that require an unlocked running broker.
    pub fn reject_if_not_running(&self) -> Result<(), BrokerError> {
        match self.phase() {
            BrokerPhase::Running => Ok(()),
            BrokerPhase::Locked => Err(BrokerError::Admission(AuthorityError::Locked)),
            BrokerPhase::Draining | BrokerPhase::ShuttingDown => {
                Err(BrokerError::Admission(AuthorityError::Draining))
            }
        }
    }

    /// Unlock is allowed from Locked/Running, never while a drain owns the
    /// lifecycle. Callers must hold the coordinator lock.
    pub fn reject_if_busy(&self) -> Result<(), BrokerError> {
        if self.remote_effect_gate.load(Ordering::SeqCst) == REMOTE_EFFECT_STOP_PENDING {
            return Err(BrokerError::Admission(AuthorityError::Draining));
        }
        match self.phase() {
            BrokerPhase::Locked | BrokerPhase::Running => Ok(()),
            BrokerPhase::Draining | BrokerPhase::ShuttingDown => {
                Err(BrokerError::Admission(AuthorityError::Draining))
            }
        }
    }

    pub async fn coordinate(&self) -> MutexGuard<'_, ()> {
        self.coordinator.lock().await
    }

    pub async fn coordinate_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<MutexGuard<'_, ()>, BrokerError> {
        tokio::time::timeout_at(deadline, self.coordinator.lock())
            .await
            .map_err(|_| BrokerError::Admission(AuthorityError::AuthorityBusy))
    }

    pub fn try_coordinate(&self) -> Result<MutexGuard<'_, ()>, TryLockError> {
        self.coordinator.try_lock()
    }

    pub fn enter_draining(&self) {
        self.close_remote_effect_admission();
        self.phase
            .store(BrokerPhase::Draining as u8, Ordering::SeqCst);
    }

    pub fn enter_shutting_down(&self) {
        self.close_remote_effect_admission();
        self.phase
            .store(BrokerPhase::ShuttingDown as u8, Ordering::SeqCst);
        self.signal_cancel();
    }

    pub fn enter_locked(&self) {
        self.close_remote_effect_admission();
        self.cancel_tx.send_replace(false);
        self.phase
            .store(BrokerPhase::Locked as u8, Ordering::SeqCst);
    }

    pub fn enter_running(&self) -> Result<(), BrokerError> {
        let previous = self.phase();
        self.cancel_tx.send_replace(false);
        self.phase
            .store(BrokerPhase::Running as u8, Ordering::SeqCst);
        let gate = self.remote_effect_gate.load(Ordering::SeqCst);
        if gate == REMOTE_EFFECT_STOP_PENDING
            || (gate == REMOTE_EFFECT_CLOSED
                && self
                    .remote_effect_gate
                    .compare_exchange(
                        REMOTE_EFFECT_CLOSED,
                        REMOTE_EFFECT_OPEN,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_err())
        {
            self.phase.store(previous as u8, Ordering::SeqCst);
            return Err(BrokerError::Authority(AuthorityError::Draining));
        }
        Ok(())
    }

    pub(crate) fn try_begin_remote_effect(&self) -> bool {
        self.remote_effect_gate.load(Ordering::SeqCst) == REMOTE_EFFECT_OPEN
    }

    pub(crate) fn close_remote_effect_admission(&self) {
        if let Err(state) = self.remote_effect_gate.compare_exchange(
            REMOTE_EFFECT_OPEN,
            REMOTE_EFFECT_CLOSED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            debug_assert!(matches!(
                state,
                REMOTE_EFFECT_CLOSED | REMOTE_EFFECT_STOP_PENDING
            ));
        }
    }

    pub(crate) fn mark_stop_pending(&self) {
        self.remote_effect_gate
            .store(REMOTE_EFFECT_STOP_PENDING, Ordering::SeqCst);
    }

    pub fn signal_cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct LocalExecutionPermit(Arc<Lifecycle>);
impl Drop for LocalExecutionPermit {
    fn drop(&mut self) {
        self.0.local_in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct ConnectionExecutionPermit {
    local: LocalExecutionPermit,
    connection: String,
    needs_terminal: bool,
}

impl ConnectionExecutionPermit {
    pub(crate) fn started(&mut self) {
        self.needs_terminal = true;
    }

    pub(crate) fn complete(mut self) {
        self.needs_terminal = false;
    }
}

impl Drop for ConnectionExecutionPermit {
    fn drop(&mut self) {
        let lifecycle = &self.local.0;
        if self.needs_terminal {
            lifecycle.mark_stop_pending();
        }
        let mut active = lifecycle
            .connection_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = active.get_mut(&self.connection) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.connection);
            }
        }
    }
}

/// Dropped after every TLS/protocol/key owner has closed, including cancellation.
pub(crate) struct PrivateCredentialOwner {
    lifecycle: Arc<Lifecycle>,
    credential: CredentialId,
    request: RequestId,
    pub(crate) cancel: watch::Receiver<bool>,
}
impl Drop for PrivateCredentialOwner {
    fn drop(&mut self) {
        self.lifecycle
            .private_credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(self.credential, self.request));
        self.lifecycle.private_closed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_capacity_is_per_connection_and_global_until_owner_drops() {
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_EXECUTIONS_PER_CONNECTION {
            held.push(lifecycle.connection_permit("shared").unwrap());
        }
        assert!(matches!(
            lifecycle.connection_permit("shared"),
            Err(BrokerError::Admission(AuthorityError::AuthorityBusy))
        ));
        for index in MAX_EXECUTIONS_PER_CONNECTION..MAX_CONNECTION_EXECUTIONS {
            held.push(
                lifecycle
                    .connection_permit(&format!("connection-{index}"))
                    .unwrap(),
            );
        }
        assert_eq!(lifecycle.local_in_flight(), MAX_CONNECTION_EXECUTIONS);
        assert!(matches!(
            lifecycle.connection_permit("another"),
            Err(BrokerError::Admission(AuthorityError::AuthorityBusy))
        ));
        held.pop();
        drop(lifecycle.connection_permit("another").unwrap());
        drop(held);
        assert_eq!(lifecycle.local_in_flight(), 0);
        assert!(lifecycle.connection_in_flight.lock().unwrap().is_empty());
    }

    #[test]
    fn unfinished_terminal_closes_admission_before_capacity_returns() {
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let mut permit = lifecycle.connection_permit("test").unwrap();
        permit.started();
        drop(permit);
        assert_eq!(lifecycle.local_in_flight(), 0);
        assert!(!lifecycle.try_begin_remote_effect());
        assert!(matches!(
            lifecycle.connection_permit("test"),
            Err(BrokerError::Admission(AuthorityError::Draining))
        ));
    }

    #[tokio::test]
    async fn bounded_coordinator_wait_does_not_acquire_later() {
        let lifecycle = Lifecycle::new();
        let owner = lifecycle.coordinate().await;
        let error = lifecycle
            .coordinate_until(tokio::time::Instant::now() + std::time::Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "AUTHORITY_BUSY");
        drop(owner);
        assert!(lifecycle.try_coordinate().is_ok());
    }
}
