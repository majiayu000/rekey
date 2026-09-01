//! Broker-owned lifecycle: one coordinator for idle / explicit lock /
//! shutdown. Phase is not an AtomicBool that concurrent drains can flip.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use rekey_vault::AuthorityError;
use tokio::sync::{Mutex, MutexGuard, TryLockError, watch};

use crate::error::BrokerError;

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
    phase: AtomicU8,
    coordinator: Mutex<()>,
    cancel_tx: watch::Sender<bool>,
    remote_effect_admission_open: AtomicBool,
}

impl Lifecycle {
    pub fn new() -> Self {
        let (cancel_tx, _) = watch::channel(false);
        Self {
            phase: AtomicU8::new(BrokerPhase::Locked as u8),
            coordinator: Mutex::new(()),
            cancel_tx,
            remote_effect_admission_open: AtomicBool::new(false),
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
            BrokerPhase::Locked => Err(BrokerError::Authority(AuthorityError::Locked)),
            BrokerPhase::Draining | BrokerPhase::ShuttingDown => {
                Err(BrokerError::Authority(AuthorityError::Draining))
            }
        }
    }

    /// Unlock is allowed from Locked/Running, never while a drain owns the
    /// lifecycle. Callers must hold the coordinator lock.
    pub fn reject_if_busy(&self) -> Result<(), BrokerError> {
        match self.phase() {
            BrokerPhase::Locked | BrokerPhase::Running => Ok(()),
            BrokerPhase::Draining | BrokerPhase::ShuttingDown => {
                Err(BrokerError::Authority(AuthorityError::Draining))
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
            .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))
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

    pub fn enter_running(&self) {
        self.cancel_tx.send_replace(false);
        self.remote_effect_admission_open
            .store(true, Ordering::SeqCst);
        self.phase
            .store(BrokerPhase::Running as u8, Ordering::SeqCst);
    }

    pub(crate) fn try_begin_remote_effect(&self) -> bool {
        self.remote_effect_admission_open
            .compare_exchange(true, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub(crate) fn close_remote_effect_admission(&self) {
        self.remote_effect_admission_open
            .store(false, Ordering::SeqCst);
    }

    /// Only a rejected stop may resume the current Running epoch. Its caller
    /// holds the lifecycle coordinator, so no drain transition can race this.
    pub(crate) fn resume_remote_effect_admission_if_running(&self) {
        if self.phase() == BrokerPhase::Running {
            self.remote_effect_admission_open
                .store(true, Ordering::SeqCst);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_stop_reopens_remote_effects_only_while_running() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter_running();
        lifecycle.close_remote_effect_admission();
        lifecycle.resume_remote_effect_admission_if_running();
        assert!(lifecycle.try_begin_remote_effect());

        lifecycle.enter_draining();
        lifecycle.resume_remote_effect_admission_if_running();
        assert!(!lifecycle.try_begin_remote_effect());
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
