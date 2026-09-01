//! AuthorityWorker: the single owner of the SQLite connection, the unlocked
//! VRK, and every credential mutation. Runs on a dedicated blocking thread;
//! everything else talks to it through the bounded queue in `handle`.

use std::time::{Duration, Instant};

use rekey_domain::action::FixedHttpAction;
use rekey_domain::credential::CredentialState;
use rekey_domain::ids::{ActionId, CredentialId};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;

use crate::bootstrap::{kek_for_wrapper, unwrap_vrk, verify_state_dir_permissions};
use crate::command::{
    ActionDefinition, AuditDraft, AuthorityCommand, PinnedAction, StatusInfo, UnlockProof,
};
use crate::convert::{action_to_record, record_to_action};
use crate::crypto::keys::RootKey;
use crate::crypto::random_array;
use crate::error::AuthorityError;
use crate::handle::{AuthorityConfig, AuthorityHandle};
use crate::model::{AuditEvent, WrapperKind, event_type, outcome};
use crate::now_ms;
use crate::paths;
use crate::store::SqliteRecordStore;

mod backup;
mod credential;

const FREE_UNLOCK_FAILURES: u32 = 3;
const UNLOCK_BACKOFF_CAP: Duration = Duration::from_secs(30);

fn reconcile_abandoned_executions(store: &mut SqliteRecordStore) -> Result<(), AuthorityError> {
    for row in store.unterminated_executions()? {
        store.append_audit(&AuditEvent {
            event_id: random_array()?,
            request_id: Some(row.request_id),
            session_id: row.session_id,
            action_id: row.action_id,
            action_version: row.action_version,
            credential_id: row.credential_id,
            credential_version: None,
            authorization: row.authorization,
            event_type: event_type::EXECUTION_INDETERMINATE,
            outcome: outcome::UNKNOWN,
            reason_code: "abandoned-on-restart".to_owned(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: now_ms()?,
        })?;
    }
    Ok(())
}

enum VaultState {
    Locked,
    Unlocked { vrk: RootKey },
    Faulted,
}

impl VaultState {
    fn name(&self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Unlocked { .. } => "unlocked",
            Self::Faulted => "faulted",
        }
    }
}

/// Spawns the worker thread. The store is opened and verified before the
/// thread starts so startup failures surface synchronously.
pub fn spawn_authority(
    config: AuthorityConfig,
) -> Result<(AuthorityHandle, std::thread::JoinHandle<()>), AuthorityError> {
    config.validate()?;
    verify_state_dir_permissions(&config.state_dir)?;
    for marker in [
        paths::init_incomplete(&config.state_dir),
        paths::restore_incomplete(&config.state_dir),
    ] {
        match std::fs::symlink_metadata(marker) {
            Ok(_) => return Err(AuthorityError::UnsupportedVaultLayout),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(AuthorityError::storage(err)),
        }
    }
    let db = paths::vault_db(&config.state_dir);
    if !db.exists() {
        let mut entries = std::fs::read_dir(&config.state_dir).map_err(AuthorityError::storage)?;
        let occupied = entries.any(|e| {
            e.as_ref()
                .map(|e| {
                    e.file_name() != paths::BROKER_LOCK_FILE && e.file_name() != paths::RUNTIME_DIR
                })
                .unwrap_or(true)
        });
        return Err(if occupied {
            AuthorityError::UnsupportedVaultLayout
        } else {
            AuthorityError::NotInitialized
        });
    }
    let mut store = SqliteRecordStore::open(&db)?;
    let header = store.load_header()?;
    reconcile_abandoned_executions(&mut store)?;
    let (tx, rx) = mpsc::channel(config.queue_capacity);
    let worker = Worker {
        store,
        header,
        state: VaultState::Locked,
        failed_unlocks: 0,
        next_unlock_at: Instant::now(),
        last_activity: Instant::now(),
        config,
    };
    let join = std::thread::Builder::new()
        .name("rekey-authority".to_owned())
        .spawn(move || worker.run(rx))
        .map_err(AuthorityError::storage)?;
    Ok((AuthorityHandle { tx }, join))
}

struct Worker {
    store: SqliteRecordStore,
    header: crate::model::VaultHeaderRecord,
    state: VaultState,
    failed_unlocks: u32,
    next_unlock_at: Instant,
    last_activity: Instant,
    config: AuthorityConfig,
}

impl Worker {
    fn run(mut self, mut rx: mpsc::Receiver<AuthorityCommand>) {
        while let Some(cmd) = rx.blocking_recv() {
            if self.handle(cmd) {
                break;
            }
        }
        // Dropping the state zeroizes the VRK through SecretBox.
        self.state = VaultState::Locked;
    }

    /// Returns true when the worker should stop.
    fn handle(&mut self, cmd: AuthorityCommand) -> bool {
        match cmd {
            AuthorityCommand::Status(reply) => {
                let idle_for_ms = if matches!(self.state, VaultState::Unlocked { .. }) {
                    self.last_activity.elapsed().as_millis() as u64
                } else {
                    0
                };
                let _ = reply.send(Ok(StatusInfo {
                    state: self.state.name(),
                    vault_id: self.header.vault_id,
                    format_version: self.header.format_version,
                    idle_for_ms,
                }));
            }
            AuthorityCommand::Unlock { proof, reply } => {
                let result = self.unlock(proof);
                let _ = reply.send(result);
            }
            AuthorityCommand::Lock { reason, reply } => {
                let result = self.lock(reason);
                let _ = reply.send(result);
            }
            AuthorityCommand::CheckIdle => {
                if matches!(self.state, VaultState::Unlocked { .. })
                    && self.last_activity.elapsed() >= self.config.idle_lock
                {
                    let _ = self.lock("idle-timeout");
                }
            }
            AuthorityCommand::Shutdown { proof, reply } => {
                let result = match (&self.state, proof) {
                    (VaultState::Unlocked { .. }, Some(proof)) => self.verify_proof(&proof),
                    (VaultState::Unlocked { .. }, None) => {
                        Err(AuthorityError::AuthenticationFailed)
                    }
                    _ => Ok(()),
                };
                let ok = result.is_ok();
                if ok {
                    self.state = VaultState::Locked;
                }
                let _ = reply.send(result);
                return ok;
            }
            AuthorityCommand::VerifyProof { proof, reply } => {
                let result = self
                    .require_unlocked()
                    .map(|_| ())
                    .and_then(|_| self.verify_proof(&proof));
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialAdd {
                label,
                kind,
                secret,
                proof,
                reply,
            } => {
                let result = self.credential_add(label, kind, secret, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialList(reply) => {
                let _ = reply.send(self.credential_list());
            }
            AuthorityCommand::CredentialRotate {
                credential_id,
                secret,
                proof,
                reply,
            } => {
                let result = self.credential_rotate(credential_id, secret, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialRevoke {
                credential_id,
                proof,
                reply,
            } => {
                let result = self.credential_revoke(credential_id, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionUpsert {
                existing,
                definition,
                proof,
                reply,
            } => {
                let result = self.action_upsert(existing, *definition, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionDisable {
                action_id,
                proof,
                reply,
            } => {
                let result = self.action_disable(action_id, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionList(reply) => {
                let _ = reply.send(self.action_list());
            }
            AuthorityCommand::ActionGet {
                action_id,
                version,
                reply,
            } => {
                let _ = reply.send(self.action_get(action_id, version));
            }
            AuthorityCommand::ActionIdsForCredential {
                credential_id,
                reply,
            } => {
                let result = self
                    .store
                    .list_active_actions_for_credential(credential_id)
                    .map(|records| records.into_iter().map(|r| r.action_id).collect());
                let _ = reply.send(result);
            }
            AuthorityCommand::PrepareCredential {
                credential_id,
                reply,
            } => {
                let result = self.prepare_credential(credential_id);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::AppendAudit { draft, reply } => {
                let execution_completed = matches!(
                    draft.event_type,
                    event_type::EXECUTION_FINISHED
                        | event_type::EXECUTION_BLOCKED
                        | event_type::EXECUTION_INDETERMINATE
                );
                let result = self.append_audit(draft);
                if execution_completed {
                    self.touch_if_ok(&result);
                }
                let _ = reply.send(result);
            }
            AuthorityCommand::Backup {
                output,
                proof,
                reply,
            } => {
                let result = self.backup(output, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
        }
        false
    }

    fn touch_if_ok<T>(&mut self, result: &Result<T, AuthorityError>) {
        if result.is_ok() {
            self.last_activity = Instant::now();
        }
    }

    fn require_unlocked(&self) -> Result<&RootKey, AuthorityError> {
        match &self.state {
            VaultState::Unlocked { vrk } => Ok(vrk),
            VaultState::Locked => Err(AuthorityError::Locked),
            VaultState::Faulted => Err(AuthorityError::Faulted),
        }
    }

    fn fault(&mut self, reason: &'static str) {
        self.state = VaultState::Faulted;
        if let (Ok(event_id), Ok(created_at_ms)) = (random_array(), now_ms()) {
            let _ = self.store.append_audit(&AuditEvent {
                event_id,
                request_id: None,
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                event_type: event_type::RUNTIME_FAULTED,
                outcome: outcome::FAILURE,
                reason_code: reason.to_owned(),
                upstream_status: None,
                latency_ms: None,
                created_at_ms,
            });
        }
    }

    fn audit_event(&self, draft: AuditDraft) -> Result<AuditEvent, AuthorityError> {
        Ok(AuditEvent {
            event_id: random_array()?,
            request_id: draft.request_id,
            session_id: draft.session_id,
            action_id: draft.action_id,
            action_version: draft.action_version,
            credential_id: draft.credential_id,
            credential_version: draft.credential_version,
            authorization: draft.authorization.map(|evidence| *evidence),
            event_type: draft.event_type,
            outcome: draft.outcome,
            reason_code: draft.reason_code,
            upstream_status: draft.upstream_status,
            latency_ms: draft.latency_ms,
            created_at_ms: now_ms()?,
        })
    }

    /// Audit failure is fail-closed: the worker faults instead of continuing
    /// without evidence.
    fn append_audit(&mut self, draft: AuditDraft) -> Result<(), AuthorityError> {
        let event = self.audit_event(draft)?;
        match self.store.append_audit(&event) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.fault("audit-commit-failed");
                Err(err)
            }
        }
    }

    fn verify_proof(&self, proof: &UnlockProof) -> Result<(), AuthorityError> {
        let current_vrk = self.require_unlocked()?;
        let (kind, secret) = match proof {
            UnlockProof::Password(secret) => (WrapperKind::Password, secret),
            UnlockProof::Recovery(secret) => (WrapperKind::Recovery, secret),
        };
        let candidate = (|| {
            let wrapper = self.store.active_wrapper(kind)?;
            let kek = kek_for_wrapper(&wrapper, secret)?;
            unwrap_vrk(self.header.vault_id, &wrapper, &kek)
        })()
        .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
        if bool::from(candidate.bytes().ct_eq(current_vrk.bytes())) {
            Ok(())
        } else {
            Err(AuthorityError::InvalidUnlockCredential)
        }
    }

    fn unlock(&mut self, proof: UnlockProof) -> Result<(), AuthorityError> {
        if matches!(self.state, VaultState::Faulted) {
            return Err(AuthorityError::Faulted);
        }
        if Instant::now() < self.next_unlock_at {
            return Err(AuthorityError::UnlockRateLimited);
        }
        let (kind, secret) = match &proof {
            UnlockProof::Password(secret) => (WrapperKind::Password, secret),
            UnlockProof::Recovery(secret) => (WrapperKind::Recovery, secret),
        };
        let attempt = (|| {
            let wrapper = self.store.active_wrapper(kind)?;
            let kek = kek_for_wrapper(&wrapper, secret)
                .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
            unwrap_vrk(self.header.vault_id, &wrapper, &kek)
        })();
        match attempt {
            Ok(vrk) => {
                self.failed_unlocks = 0;
                self.next_unlock_at = Instant::now();
                self.state = VaultState::Unlocked { vrk };
                self.last_activity = Instant::now();
                self.append_audit(unlock_audit(
                    event_type::VAULT_UNLOCKED,
                    outcome::SUCCESS,
                    "unlock",
                ))
            }
            Err(_) => {
                self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                if self.failed_unlocks >= FREE_UNLOCK_FAILURES {
                    let shift = (self.failed_unlocks - FREE_UNLOCK_FAILURES).min(16);
                    let delay = self
                        .config
                        .unlock_backoff_base
                        .saturating_mul(1u32 << shift)
                        .min(UNLOCK_BACKOFF_CAP);
                    self.next_unlock_at = Instant::now() + delay;
                }
                let _ = self.append_audit(unlock_audit(
                    event_type::VAULT_UNLOCK_FAILED,
                    outcome::DENIED,
                    "invalid-credential",
                ));
                // Uniform error: never reveal whether the wrapper exists or
                // which decryption stage failed.
                Err(AuthorityError::InvalidUnlockCredential)
            }
        }
    }

    fn lock(&mut self, reason: &'static str) -> Result<(), AuthorityError> {
        if matches!(self.state, VaultState::Faulted) {
            return Err(AuthorityError::Faulted);
        }
        self.state = VaultState::Locked;
        self.append_audit(unlock_audit(
            event_type::VAULT_LOCKED,
            outcome::SUCCESS,
            reason,
        ))
    }

    fn action_upsert(
        &mut self,
        existing: Option<ActionId>,
        definition: ActionDefinition,
        proof: UnlockProof,
    ) -> Result<FixedHttpAction, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let credential = self.load_verified_credential(definition.credential_id)?;
        if credential.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        let (action_id, version, event) = match existing {
            Some(id) => {
                let current = self
                    .store
                    .list_actions()?
                    .iter()
                    .filter(|r| r.action_id == id)
                    .map(|r| r.version)
                    .max()
                    .ok_or(AuthorityError::ActionNotFound)?;
                (id, current + 1, event_type::ACTION_UPDATED)
            }
            None => (ActionId::new_random(), 1, event_type::ACTION_CREATED),
        };
        let action = FixedHttpAction {
            id: action_id,
            name: definition.name,
            version,
            enabled: true,
            credential_id: definition.credential_id,
            origin: definition.origin,
            method: definition.method,
            exact_path: definition.exact_path,
            auth: definition.auth,
            timeout_ms: definition.timeout_ms,
            request_policy: definition.request_policy,
            response_policy: definition.response_policy,
        };
        action.validate()?;
        let record = action_to_record(&action, now_ms()?)?;
        let mut draft = credential_audit(event, definition.credential_id, 0, "upsert");
        draft.credential_version = None;
        draft.action_id = Some(action_id);
        draft.action_version = Some(version);
        let audit = self.audit_event(draft)?;
        self.store.insert_action(&record, audit)?;
        Ok(action)
    }

    fn action_disable(
        &mut self,
        action_id: ActionId,
        proof: UnlockProof,
    ) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let mut draft = unlock_audit(event_type::ACTION_DISABLED, outcome::SUCCESS, "disable");
        draft.action_id = Some(action_id);
        let audit = self.audit_event(draft)?;
        self.store.disable_action(action_id, audit)
    }

    fn action_list(&self) -> Result<Vec<FixedHttpAction>, AuthorityError> {
        self.require_unlocked()?;
        self.store
            .list_actions()?
            .iter()
            .map(record_to_action)
            .collect()
    }

    fn action_get(
        &self,
        action_id: ActionId,
        version: u64,
    ) -> Result<PinnedAction, AuthorityError> {
        let record = self.store.get_action(action_id, version)?;
        Ok(PinnedAction {
            action: record_to_action(&record)?,
            state: record.state,
        })
    }
}

fn unlock_audit(event_type: &'static str, outcome: &'static str, reason: &str) -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        event_type,
        outcome,
        reason_code: reason.to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

fn credential_audit(
    event_type: &'static str,
    credential_id: CredentialId,
    version: u64,
    reason: &str,
) -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: Some(credential_id),
        credential_version: Some(version),
        authorization: None,
        event_type,
        outcome: outcome::SUCCESS,
        reason_code: reason.to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}
