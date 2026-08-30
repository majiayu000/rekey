//! AuthorityWorker: the single owner of the SQLite connection, the unlocked
//! VRK, and every credential mutation. Runs on a dedicated blocking thread;
//! everything else talks to it through the bounded queue in `handle`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rekey_domain::action::FixedHttpAction;
use rekey_domain::credential::{
    CredentialKind, CredentialLabel, CredentialMetadata, CredentialState, VersionState,
};
use rekey_domain::ids::{ActionId, CredentialId};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::bootstrap::{kek_for_wrapper, unwrap_vrk, verify_state_dir_permissions};
use crate::command::{
    ActionDefinition, AuditDraft, AuthorityCommand, PinnedAction, StatusInfo, UnlockProof,
};
use crate::convert::{action_to_record, record_to_action, record_to_metadata};
use crate::crypto::aad::{AadPurpose, AadV1};
use crate::crypto::keys::{DataKey, RootKey};
use crate::crypto::{AAD_VERSION_V1, CRYPTO_SUITE_V1, aead, random_array};
use crate::error::AuthorityError;
use crate::handle::{AuthorityConfig, AuthorityHandle};
use crate::model::{
    AuditEvent, CredentialRecord, CredentialVersionRecord, WrapperKind, event_type, outcome,
};
use crate::paths;
use crate::secret::{PreparedCredential, SecretInput};
use crate::store::SqliteRecordStore;

mod backup;

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
            event_type: event_type::EXECUTION_BLOCKED,
            outcome: outcome::DENIED,
            reason_code: "abandoned-on-restart".to_owned(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: now_ms(),
        })?;
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
    match std::fs::symlink_metadata(paths::restore_incomplete(&config.state_dir)) {
        Ok(_) => return Err(AuthorityError::UnsupportedVaultLayout),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(AuthorityError::storage(err)),
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
                secret,
                proof,
                reply,
            } => {
                let result = self.credential_add(label, secret, proof);
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
                let _ = reply.send(self.append_audit(draft));
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
        if let Ok(event_id) = random_array() {
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
                created_at_ms: now_ms(),
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
            created_at_ms: now_ms(),
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
        let (kind, secret) = match proof {
            UnlockProof::Password(secret) => (WrapperKind::Password, secret),
            UnlockProof::Recovery(secret) => (WrapperKind::Recovery, secret),
        };
        let wrapper = self.store.active_wrapper(kind)?;
        let kek = kek_for_wrapper(&wrapper, secret)
            .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
        unwrap_vrk(self.header.vault_id, &wrapper, &kek)?;
        Ok(())
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

    fn encrypt_new_version(
        &self,
        credential_id: CredentialId,
        version: u64,
        secret: &SecretInput,
        vrk: &RootKey,
    ) -> Result<CredentialVersionRecord, AuthorityError> {
        let dek = DataKey::generate()?;
        let payload_aad = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id: self.header.vault_id,
            object_id: *credential_id.as_bytes(),
            object_version: version,
            credential_kind: CredentialKind::OpaqueToken.aad_code(),
            constraints_hash: [0u8; 32],
        }
        .encode();
        let payload = aead::seal(dek.bytes(), &payload_aad, secret.expose())?;
        let dek_aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id: self.header.vault_id,
            object_id: *credential_id.as_bytes(),
            object_version: version,
            credential_kind: 0,
            constraints_hash: [0u8; 32],
        }
        .encode();
        let wrapped = aead::seal(vrk.bytes(), &dek_aad, dek.bytes())?;
        Ok(CredentialVersionRecord {
            credential_id,
            version,
            state: VersionState::Active,
            aad_version: AAD_VERSION_V1,
            crypto_suite: CRYPTO_SUITE_V1.to_owned(),
            dek_nonce: wrapped.nonce,
            wrapped_dek: wrapped.ciphertext,
            payload_nonce: payload.nonce,
            encrypted_payload: payload.ciphertext,
            created_at_ms: now_ms(),
            retired_at_ms: None,
        })
    }

    fn credential_add(
        &mut self,
        label: CredentialLabel,
        secret: SecretInput,
        proof: UnlockProof,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        if secret.is_empty() {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidCapability,
            ));
        }
        let VaultState::Unlocked { vrk } = &self.state else {
            return Err(AuthorityError::Locked);
        };
        let credential_id = CredentialId::new_random();
        let now = now_ms();
        let version = self.encrypt_new_version(credential_id, 1, &secret, vrk)?;
        let record = CredentialRecord {
            credential_id,
            label: label.as_str().to_owned(),
            kind: CredentialKind::OpaqueToken,
            state: CredentialState::Active,
            current_version: 1,
            created_at_ms: now,
            updated_at_ms: now,
            revoked_at_ms: None,
        };
        let audit = self.audit_event(credential_audit(
            event_type::CREDENTIAL_CREATED,
            credential_id,
            1,
            "add",
        ))?;
        self.store.insert_credential(&record, &version, audit)?;
        record_to_metadata(&record)
    }

    fn credential_list(&self) -> Result<Vec<CredentialMetadata>, AuthorityError> {
        self.require_unlocked()?;
        self.store
            .list_credentials()?
            .iter()
            .map(record_to_metadata)
            .collect()
    }

    fn credential_rotate(
        &mut self,
        credential_id: CredentialId,
        secret: SecretInput,
        proof: UnlockProof,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let existing = self.store.get_credential(credential_id)?;
        if existing.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        let VaultState::Unlocked { vrk } = &self.state else {
            return Err(AuthorityError::Locked);
        };
        let next = existing.current_version + 1;
        let version = self.encrypt_new_version(credential_id, next, &secret, vrk)?;
        let audit = self.audit_event(credential_audit(
            event_type::CREDENTIAL_ROTATED,
            credential_id,
            next,
            "rotate",
        ))?;
        self.store
            .rotate_credential(credential_id, &version, now_ms(), audit)?;
        self.store
            .get_credential(credential_id)
            .and_then(|r| record_to_metadata(&r))
    }

    fn credential_revoke(
        &mut self,
        credential_id: CredentialId,
        proof: UnlockProof,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let existing = self.store.get_credential(credential_id)?;
        let audit = self.audit_event(credential_audit(
            event_type::CREDENTIAL_REVOKED,
            credential_id,
            existing.current_version,
            "revoke",
        ))?;
        self.store
            .revoke_credential(credential_id, now_ms(), audit)?;
        self.store
            .get_credential(credential_id)
            .and_then(|r| record_to_metadata(&r))
    }

    fn action_upsert(
        &mut self,
        existing: Option<ActionId>,
        definition: ActionDefinition,
        proof: UnlockProof,
    ) -> Result<FixedHttpAction, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let credential = self.store.get_credential(definition.credential_id)?;
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
        let record = action_to_record(&action, now_ms())?;
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

    /// Decrypts the current active version. Every call re-checks persisted
    /// credential state, so a revoked credential can never produce a new
    /// lease even if in-memory session cleanup failed.
    fn prepare_credential(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<PreparedCredential, AuthorityError> {
        let vrk = self.require_unlocked()?;
        let credential = self.store.get_credential(credential_id)?;
        if credential.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        let version = self
            .store
            .get_version(credential_id, credential.current_version)?;
        if version.state != VersionState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        let dek_aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id: self.header.vault_id,
            object_id: *credential_id.as_bytes(),
            object_version: version.version,
            credential_kind: 0,
            constraints_hash: [0u8; 32],
        }
        .encode();
        let dek_bytes = aead::open(
            vrk.bytes(),
            &dek_aad,
            &version.dek_nonce,
            &version.wrapped_dek,
        )
        .map_err(|_| AuthorityError::CryptoFailure)?;
        let dek_arr: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityError::CryptoFailure)?;
        let dek = DataKey::from_bytes(dek_arr);
        let payload_aad = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id: self.header.vault_id,
            object_id: *credential_id.as_bytes(),
            object_version: version.version,
            credential_kind: credential.kind.aad_code(),
            constraints_hash: [0u8; 32],
        }
        .encode();
        let payload = aead::open(
            dek.bytes(),
            &payload_aad,
            &version.payload_nonce,
            &version.encrypted_payload,
        )
        .map_err(|_| AuthorityError::CryptoFailure)?;
        Ok(PreparedCredential::new(
            Zeroizing::new(payload.to_vec()),
            credential_id,
            version.version,
        ))
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
