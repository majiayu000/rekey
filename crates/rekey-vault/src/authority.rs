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

mod audit;
mod backup;
mod credential;
mod policy;
mod wrapper;

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
            approval: None,
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
            AuthorityCommand::Status {
                refresh_activity,
                reply,
            } => {
                let policy_state = self.store.load_policy_state();
                let policy_state = self.fault_on_integrity(policy_state);
                let (policy_trust_installed, policy_bundle_persisted) = match policy_state {
                    Ok(state) => (state.trust_installed, state.bundle_activated),
                    Err(error) => {
                        drop(reply.send(Err(error)));
                        return false;
                    }
                };
                if refresh_activity && matches!(self.state, VaultState::Unlocked { .. }) {
                    self.last_activity = Instant::now();
                }
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
                    policy_trust_installed,
                    policy_bundle_persisted,
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
            AuthorityCommand::PasswordChange {
                proof,
                new_password,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.password_change(proof, new_password, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::RecoveryRotate {
                password,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.recovery_rotate(password, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialAdd {
                label,
                kind,
                secret,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_add(label, kind, secret, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialList(reply) => {
                let result = self.credential_list();
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialRotate {
                credential_id,
                secret,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_rotate(credential_id, secret, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialRevoke {
                credential_id,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_revoke(credential_id, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionUpsert {
                existing,
                definition,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.action_upsert(existing, *definition, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionDisable {
                action_id,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.action_disable(action_id, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionList(reply) => {
                let result = self.action_list();
                self.touch_if_ok(&result);
                let _ = reply.send(result);
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
                let records = self.store.list_actions_for_credential(credential_id);
                let result = self.fault_on_integrity(records).map(|records| {
                    let mut action_ids = records
                        .into_iter()
                        .map(|record| record.action_id)
                        .collect::<Vec<_>>();
                    action_ids.sort_unstable();
                    action_ids.dedup();
                    action_ids
                });
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
            AuthorityCommand::AppendAudit {
                draft,
                not_after,
                reply,
            } => {
                let refreshes_idle = matches!(
                    draft.event_type,
                    event_type::EXECUTION_FINISHED
                        | event_type::EXECUTION_BLOCKED
                        | event_type::EXECUTION_INDETERMINATE
                        | event_type::SESSION_CREATED
                        | event_type::SESSION_REVOKED
                        | event_type::POLICY_ACTIVATED
                );
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.append_audit(draft)
                };
                if refreshes_idle {
                    self.touch_if_ok(&result);
                }
                let _ = reply.send(result);
            }
            AuthorityCommand::AppendAudits {
                drafts,
                not_after,
                wall_not_after_ms,
                reply,
            } => {
                let refreshes_idle = drafts.iter().any(|draft| {
                    matches!(
                        draft.event_type,
                        event_type::EXECUTION_FINISHED
                            | event_type::EXECUTION_BLOCKED
                            | event_type::EXECUTION_INDETERMINATE
                            | event_type::SESSION_CREATED
                            | event_type::SESSION_REVOKED
                            | event_type::POLICY_ACTIVATED
                    )
                });
                let result = (|| {
                    if mutation_expired(not_after) {
                        return Err(AuthorityError::AuthorityBusy);
                    }
                    if let Some(deadline_ms) = wall_not_after_ms
                        && now_ms()? >= deadline_ms
                    {
                        return Err(AuthorityError::AuthorityBusy);
                    }
                    self.append_audits(drafts)
                })();
                if refreshes_idle {
                    self.touch_if_ok(&result);
                }
                drop(reply.send(result));
            }
            AuthorityCommand::ConsumeWorkloadToken {
                replay_digest,
                expires_at_ms,
                audit,
                not_after,
                reply,
            } => {
                let result = (|| {
                    if mutation_expired(not_after) {
                        return Err(AuthorityError::AuthorityBusy);
                    }
                    self.require_unlocked().map(|_| ())?;
                    let event = self.audit_event_or_fault(audit)?;
                    let result =
                        self.store
                            .consume_workload_token(replay_digest, expires_at_ms, event);
                    self.fault_on_audit_failure(result)
                })();
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::AuditQuery { query, reply } => {
                let result = if matches!(self.state, VaultState::Faulted) {
                    Err(AuthorityError::Faulted)
                } else {
                    let result = self.store.audit_query(&query);
                    self.fault_on_integrity(result)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PolicyMaterial { reply } => {
                let result = self.policy_material();
                let result = self.fault_on_integrity(result);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::PolicyTrustInstall {
                input,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.policy_trust_install(input, proof, not_after)
                };
                let result = self.fault_on_integrity(result);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::PolicyBundleActivate {
                input,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.policy_bundle_activate(input, proof, not_after)
                };
                let result = self.fault_on_integrity(result);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::FaultIntegrity { reply } => {
                self.fault("persisted-policy-validation-failed");
                drop(reply.send(Err(AuthorityError::StorageIntegrityFailed)));
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

    fn fault_on_integrity<T>(
        &mut self,
        result: Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        if matches!(result, Err(AuthorityError::StorageIntegrityFailed))
            && !matches!(self.state, VaultState::Faulted)
        {
            self.fault("persisted-state-integrity-failed");
        }
        result
    }

    fn require_unlocked(&self) -> Result<&RootKey, AuthorityError> {
        match &self.state {
            VaultState::Unlocked { vrk } => Ok(vrk),
            VaultState::Locked => Err(AuthorityError::Locked),
            VaultState::Faulted => Err(AuthorityError::Faulted),
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
                if let Err(error) = self.policy_material() {
                    self.fault("persisted-policy-integrity-failed");
                    return Err(error);
                }
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
        not_after: Option<Instant>,
    ) -> Result<FixedHttpAction, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let credential = self.load_verified_credential(definition.credential_id)?;
        if credential.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        let (action_id, version, event) = match existing {
            Some(id) => {
                let records = self.store.list_actions();
                let current = self
                    .fault_on_integrity(records)?
                    .iter()
                    .filter(|r| r.action_id == id)
                    .map(|r| r.version)
                    .max()
                    .ok_or(AuthorityError::ActionNotFound)?;
                (id, current + 1, event_type::ACTION_UPDATED)
            }
            None => (
                ActionId::from_random_bytes(random_array()?),
                1,
                event_type::ACTION_CREATED,
            ),
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
        let audit = self.audit_event_or_fault(draft)?;
        ensure_mutation_current(not_after)?;
        let result = self.store.insert_action(&record, audit);
        self.fault_on_audit_failure(result)?;
        Ok(action)
    }

    fn action_disable(
        &mut self,
        action_id: ActionId,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let mut draft = unlock_audit(event_type::ACTION_DISABLED, outcome::SUCCESS, "disable");
        draft.action_id = Some(action_id);
        let audit = self.audit_event_or_fault(draft)?;
        ensure_mutation_current(not_after)?;
        let result = self.store.disable_action(action_id, audit);
        self.fault_on_audit_failure(result)
    }

    fn action_list(&mut self) -> Result<Vec<FixedHttpAction>, AuthorityError> {
        self.require_unlocked()?;
        let records = self.store.list_actions();
        let result = records.and_then(|records| records.iter().map(record_to_action).collect());
        self.fault_on_integrity(result)
    }

    fn action_get(
        &mut self,
        action_id: ActionId,
        version: u64,
    ) -> Result<PinnedAction, AuthorityError> {
        let result = (|| {
            let record = self.store.get_action(action_id, version)?;
            Ok(PinnedAction {
                action: record_to_action(&record)?,
                state: record.state,
            })
        })();
        self.fault_on_integrity(result)
    }
}

fn mutation_expired(not_after: Option<Instant>) -> bool {
    not_after.is_some_and(|deadline| Instant::now() >= deadline)
}

fn ensure_mutation_current(not_after: Option<Instant>) -> Result<(), AuthorityError> {
    if mutation_expired(not_after) {
        return Err(AuthorityError::AuthorityBusy);
    }
    Ok(())
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
        approval: None,
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
        approval: None,
        event_type,
        outcome: outcome::SUCCESS,
        reason_code: reason.to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}
