//! AuthorityWorker: the single owner of the SQLite connection, the unlocked
//! VRK, and every credential mutation. Runs on a dedicated blocking thread;
//! everything else talks to it through the bounded queue in `handle`.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rekey_domain::action::{
    ActionName, ActionTarget, FixedHttpAction, HeaderCredentialUse, HeaderName, RequestPolicy,
    ResponsePolicy, TemplateActionSource,
};
use rekey_domain::credential::{CredentialKind, CredentialState};
use rekey_domain::ids::{ActionId, CredentialId};
use rekey_domain::ipc::{
    self, TemplateCatalogResponse, TemplateInstallMeta, TemplateInstallResponse,
    TemplateInstalledAction, TemplateSource,
};
use rekey_policy::templates::{
    self, BuiltinTemplate, TemplatePackageError, ValidatedTemplatePackage,
};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;

use crate::bootstrap::{kek_for_wrapper, unwrap_vrk, verify_state_dir_permissions};
use crate::command::{ActionDefinition, AuditDraft, AuthorityCommand, PinnedAction, UnlockProof};
use crate::convert::{action_to_record, verified_record_to_action};
use crate::crypto::keys::RootKey;
use crate::crypto::{action_state, random_array};
use crate::error::AuthorityError;
use crate::generation_anchor::{AnchorObservation, GenerationAnchors};
use crate::handle::{AuthorityConfig, AuthorityHandle};
use crate::model::{ActionRecord, ActionState, AuditEvent, WrapperKind, event_type, outcome};
use crate::now_ms;
use crate::paths;
use crate::store::SqliteRecordStore;
use crate::store::generation::{GenerationAttempt, rollback_context};
use rekey_domain::ipc::RollbackContext;

mod audit;
mod backup;
mod credential;
mod desktop;
mod dispatch;
#[cfg(feature = "lab")]
mod keychain_source;
#[cfg(all(test, feature = "lab"))]
mod keychain_source_tests;
pub(crate) mod lease_journal;
/// Clear the crash marker only after every runtime task has joined cleanly,
/// while the caller still holds the exclusive runtime lock.
pub use desktop::finish_runtime;
mod policy;
mod vrk_rotation;
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
            request_context: row.request_context,
            usage: None,
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
    RollbackSuspected(RollbackContext),
}

impl VaultState {
    fn name(&self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Unlocked { .. } => "unlocked",
            Self::Faulted => "faulted",
            Self::RollbackSuspected(_) => "rollback-suspected",
        }
    }
}

/// Spawns the worker thread. The store is opened and verified before the
/// thread starts so startup failures surface synchronously.
pub fn spawn_authority(
    config: AuthorityConfig,
) -> Result<(AuthorityHandle, std::thread::JoinHandle<()>), AuthorityError> {
    spawn_authority_inner(
        config,
        #[cfg(all(test, feature = "lab"))]
        None,
    )
}

fn spawn_authority_inner(
    config: AuthorityConfig,
    #[cfg(all(test, feature = "lab"))] keychain_fixture: Option<KeychainFixture>,
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
    let anchors = GenerationAnchors::open(&config.state_dir, header.vault_id)?;
    reconcile_abandoned_executions(&mut store)?;
    desktop::begin_runtime(&config.state_dir)?;
    let (tx, rx) = mpsc::channel(config.queue_capacity);
    let worker = Worker {
        #[cfg(all(test, feature = "lab"))]
        keychain_fixture,
        anchors,
        store,
        header,
        state: VaultState::Locked,
        desktop_session: None,
        desktop_resume_expiry: None,
        presence_grant: None,
        failed_unlocks: 0,
        next_unlock_at: Instant::now(),
        last_activity: Instant::now(),
        retention_last_clock_ms: None,
        config,
    };
    let join = std::thread::Builder::new()
        .name("rekey-authority".to_owned())
        .spawn(move || worker.run(rx))
        .map_err(AuthorityError::storage)?;
    Ok((AuthorityHandle { tx }, join))
}

#[cfg(all(test, feature = "lab"))]
type KeychainFixture = Box<
    dyn FnMut(&keychain_source::Reference) -> Result<zeroize::Zeroizing<Vec<u8>>, AuthorityError>
        + Send,
>;

struct Worker {
    #[cfg(all(test, feature = "lab"))]
    keychain_fixture: Option<KeychainFixture>,
    desktop_resume_expiry: Option<i64>,
    presence_grant: Option<desktop::PresenceState>,
    desktop_session: Option<(zeroize::Zeroizing<Vec<u8>>, Instant)>,
    anchors: GenerationAnchors,
    store: SqliteRecordStore,
    header: crate::model::VaultHeaderRecord,
    state: VaultState,
    failed_unlocks: u32,
    next_unlock_at: Instant,
    last_activity: Instant,
    retention_last_clock_ms: Option<i64>,
    config: AuthorityConfig,
}

impl Worker {
    fn run(mut self, mut rx: mpsc::Receiver<AuthorityCommand>) {
        while let Some(cmd) = rx.blocking_recv() {
            if self.handle(cmd) {
                break;
            }
        }
        // Dropping the state zeroizes the VRK through its key owner.
        self.presence_grant = None;
        self.desktop_session = None;
        self.state = VaultState::Locked;
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

    fn check_generation(
        &mut self,
        header: &crate::model::VaultHeaderRecord,
    ) -> Result<AnchorObservation, AuthorityError> {
        let observed = match self.anchors.read() {
            Ok(observed) => observed,
            Err(error) => {
                self.fault("generation-anchor-unavailable");
                return Err(error);
            }
        };
        if !crate::store::generation::current(header, observed)
            || matches!(self.state, VaultState::RollbackSuspected(_))
        {
            self.state = VaultState::RollbackSuspected(rollback_context(header, observed));
            self.desktop_session = None;
            self.desktop_resume_expiry = None;
            if let Err(error) = self.forget_desktop() {
                self.fault("desktop-revocation-failed");
                return Err(error);
            }
            return Err(AuthorityError::RollbackSuspected);
        }
        Ok(observed)
    }

    fn mutation_observation(&mut self) -> Result<AnchorObservation, AuthorityError> {
        self.check_generation(&self.header.clone())
    }

    fn complete_generation<T>(
        &mut self,
        result: Result<T, AuthorityError>,
        completed: (u64, [u8; 32], bool),
    ) -> Result<T, AuthorityError> {
        let (generation, mac, reserved) = completed;
        if result.is_ok() {
            self.header.generation = generation;
            self.header.generation_mac = mac;
        } else if reserved && !matches!(self.state, VaultState::Faulted) {
            self.fault("generation-reserved-commit-failed");
        }
        self.fault_on_integrity(result)
    }

    fn require_unlocked(&self) -> Result<&RootKey, AuthorityError> {
        match &self.state {
            VaultState::Unlocked { vrk } => Ok(vrk),
            VaultState::Locked => Err(AuthorityError::Locked),
            VaultState::Faulted => Err(AuthorityError::Faulted),
            VaultState::RollbackSuspected(_) => Err(AuthorityError::RollbackSuspected),
        }
    }

    fn approval_origin_public_key(&self) -> Result<[u8; 32], AuthorityError> {
        let vrk = self.require_unlocked()?;
        crate::crypto::approval_origin::approval_origin_public_key(vrk, self.header.vault_id)
    }

    fn sign_approval_origin(&self, message: Vec<u8>) -> Result<[u8; 64], AuthorityError> {
        let vrk = self.require_unlocked()?;
        crate::crypto::approval_origin::sign_approval_origin(vrk, self.header.vault_id, &message)
    }

    fn verify_proof(&self, proof: &UnlockProof) -> Result<(), AuthorityError> {
        let current_vrk = self.require_unlocked()?;
        let (kind, secret) = match proof {
            UnlockProof::Password(secret) => (WrapperKind::Password, secret),
            UnlockProof::Recovery(secret) => (WrapperKind::Recovery, secret),
            UnlockProof::Presence(secret) => return self.verify_presence(secret),
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

    /// Admin shutdown may authenticate a locked vault without unlocking it.
    /// The temporary root key is dropped here; no policy/session is loaded.
    fn verify_shutdown_proof(&mut self, proof: &UnlockProof) -> Result<(), AuthorityError> {
        match self.state {
            VaultState::Faulted => return Err(AuthorityError::Faulted),
            VaultState::Unlocked { .. } => return self.verify_proof(proof),
            VaultState::Locked | VaultState::RollbackSuspected(_) => {}
        }
        if Instant::now() < self.next_unlock_at {
            return Err(AuthorityError::UnlockRateLimited);
        }
        let (kind, secret) = match proof {
            UnlockProof::Password(secret) => (WrapperKind::Password, secret),
            UnlockProof::Recovery(secret) => (WrapperKind::Recovery, secret),
            UnlockProof::Presence(_) => return Err(AuthorityError::InvalidUnlockCredential),
        };
        // Preserve storage failures instead of treating them as an absent proof.
        let wrapper = self.store.active_wrapper(kind)?;
        let attempt = kek_for_wrapper(&wrapper, secret)
            .map_err(|_| AuthorityError::InvalidUnlockCredential)
            .and_then(|kek| unwrap_vrk(self.header.vault_id, &wrapper, &kek));
        match attempt {
            Ok(_candidate) => {
                self.failed_unlocks = 0;
                self.next_unlock_at = Instant::now();
                Ok(())
            }
            Err(error) => {
                self.record_unlock_failure()?;
                Err(error)
            }
        }
    }

    fn advance_unlock_backoff(&mut self) {
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
    }

    fn record_unlock_failure(&mut self) -> Result<(), AuthorityError> {
        self.advance_unlock_backoff();
        self.append_audit(unlock_audit(
            event_type::VAULT_UNLOCK_FAILED,
            outcome::DENIED,
            "invalid-credential",
        ))
    }

    fn verify_desktop(&self, token: &crate::secret::SecretInput) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        // A resumed grant has both a monotonic limit and its original wall-clock expiry.
        self.desktop_session_duration()?;
        match &self.desktop_session {
            Some((expected, expires))
                if Instant::now() < *expires
                    && bool::from(expected.as_slice().ct_eq(token.expose())) =>
            {
                Ok(())
            }
            _ => Err(AuthorityError::InvalidUnlockCredential),
        }
    }

    fn confirm_rollback(
        &mut self,
        expected: RollbackContext,
        proof: crate::bootstrap::RestoreProof,
        not_after: Instant,
    ) -> Result<(), AuthorityError> {
        let result = self.confirm_rollback_inner(expected, proof, not_after);
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }

    fn confirm_rollback_inner(
        &mut self,
        expected: RollbackContext,
        proof: crate::bootstrap::RestoreProof,
        not_after: Instant,
    ) -> Result<(), AuthorityError> {
        ensure_mutation_current(Some(not_after))?;
        match &self.state {
            VaultState::RollbackSuspected(context) if context == &expected => {}
            VaultState::Faulted => return Err(AuthorityError::Faulted),
            _ => return Err(AuthorityError::RollbackSuspected),
        }
        if Instant::now() < self.next_unlock_at {
            return Err(AuthorityError::UnlockRateLimited);
        }
        let header = self.store.load_header()?;
        let root = match crate::bootstrap::authenticate_restore(&self.store, &header, &proof) {
            Ok((root, _)) => root,
            Err(AuthorityError::InvalidUnlockCredential) => {
                self.advance_unlock_backoff();
                return Err(AuthorityError::InvalidUnlockCredential);
            }
            Err(error) => return Err(error),
        };
        let observed = self.anchors.read()?;
        if rollback_context(&header, observed) != expected {
            return Err(AuthorityError::RollbackSuspected);
        }
        let next = header
            .generation
            .max(expected.high_water.unwrap_or(0))
            .checked_add(1)
            .ok_or(AuthorityError::StorageIntegrityFailed)?;
        let audit = self.audit_event_or_fault(unlock_audit(
            event_type::RESTORE_COMPLETED,
            outcome::SUCCESS,
            "rollback-confirmed",
        ))?;
        let mut generation = GenerationAttempt::new(
            &self.anchors,
            &header,
            observed,
            root.bytes(),
            next,
            Some(not_after),
            None,
        )?;
        let result = self.store.confirm_generation(audit, &mut generation);
        let completed = generation.finish();
        self.complete_generation(result, completed)?;
        let mut header = header;
        header.generation = completed.0;
        header.generation_mac = completed.1;
        self.header = header;
        self.state = VaultState::Locked;
        self.failed_unlocks = 0;
        self.next_unlock_at = Instant::now();
        Ok(())
    }

    fn unlock(&mut self, proof: UnlockProof) -> Result<(), AuthorityError> {
        let recover_usage = matches!(self.state, VaultState::Locked);
        if matches!(self.state, VaultState::Faulted) {
            return Err(AuthorityError::Faulted);
        }
        if Instant::now() < self.next_unlock_at {
            return Err(AuthorityError::UnlockRateLimited);
        }
        let (kind, secret) = match &proof {
            UnlockProof::Password(secret) => (WrapperKind::Password, secret),
            UnlockProof::Recovery(secret) => (WrapperKind::Recovery, secret),
            UnlockProof::Presence(_) => return Err(AuthorityError::InvalidUnlockCredential),
        };
        let attempt = (|| {
            let wrapper = self.store.active_wrapper(kind)?;
            let kek = kek_for_wrapper(&wrapper, secret)
                .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
            unwrap_vrk(self.header.vault_id, &wrapper, &kek)
        })();
        match attempt {
            Ok(vrk) => {
                let header = self.store.load_header().and_then(|header| {
                    crate::bootstrap::prove_integrity(&header, vrk.bytes())?;
                    Ok(header)
                });
                // Once a wrapper has authenticated the candidate root, every
                // header-load/authentication failure revokes prior authority.
                let header = match header {
                    Ok(header) => header,
                    Err(error) => {
                        self.fault("vault-header-integrity-failed");
                        return Err(error);
                    }
                };
                if let Err(error) = self
                    .store
                    .verified_policy_material(vrk.bytes(), header.vault_id)
                {
                    self.fault("persisted-policy-integrity-failed");
                    return Err(error);
                }
                if let Err(error) = self
                    .store
                    .verified_audit_retention(vrk.bytes(), header.vault_id)
                {
                    self.fault("audit-retention-integrity-failed");
                    return Err(error);
                }
                if let Err(error) =
                    lease_journal::verify_store(&self.store, vrk.bytes(), header.vault_id)
                {
                    self.fault("lease-journal-integrity-failed");
                    return Err(error);
                }
                self.check_generation(&header)?;
                let usage = if recover_usage {
                    self.store
                        .recover_profile_usage(vrk.bytes(), header.vault_id)
                } else {
                    self.store
                        .verified_usage(vrk.bytes(), header.vault_id)
                        .map(|_| ())
                };
                if let Err(error) = usage {
                    self.fault("profile-usage-recovery-failed");
                    return Err(error);
                }
                self.append_audit(unlock_audit(
                    event_type::VAULT_UNLOCKED,
                    outcome::SUCCESS,
                    "unlock",
                ))?;
                // Publish only after the existing required material and success
                // audit have completed using the still-local candidate key.
                self.header = header;
                self.suspend_presence();
                self.desktop_resume_expiry = None;
                self.failed_unlocks = 0;
                self.next_unlock_at = Instant::now();
                self.desktop_session = None;
                self.state = VaultState::Unlocked { vrk };
                self.last_activity = Instant::now();
                Ok(())
            }
            Err(_) => {
                let _ = self.record_unlock_failure();
                // Uniform error: never reveal whether the wrapper exists or
                // which decryption stage failed.
                Err(AuthorityError::InvalidUnlockCredential)
            }
        }
    }

    fn lock(&mut self, reason: &'static str) -> Result<(), AuthorityError> {
        self.set_locked(reason, false)
    }

    fn set_locked(
        &mut self,
        reason: &'static str,
        preserve_desktop: bool,
    ) -> Result<(), AuthorityError> {
        if matches!(self.state, VaultState::Faulted) {
            return Err(AuthorityError::Faulted);
        }
        if matches!(self.state, VaultState::RollbackSuspected(_)) {
            return Ok(());
        }
        self.suspend_presence();
        if !preserve_desktop && let Err(error) = self.forget_desktop() {
            self.fault("desktop-revocation-failed");
            return Err(error);
        }
        self.desktop_resume_expiry = None;
        self.desktop_session = None;
        self.state = VaultState::Locked;
        self.append_audit(unlock_audit(
            event_type::VAULT_LOCKED,
            outcome::SUCCESS,
            reason,
        ))
    }

    fn authenticated_template(
        &mut self,
        source: TemplateSource,
        bytes: &[u8],
    ) -> Result<ValidatedTemplatePackage, AuthorityError> {
        if bytes.len() > templates::TEMPLATE_PACKAGE_MAX_BYTES {
            return Err(template_input("template package is too large"));
        }
        if matches!(source, TemplateSource::SignedPackage {}) {
            let material = self.policy_material();
            let material = self.fault_on_integrity(material)?;
            if material.state.mode != rekey_domain::authorization::PolicyMode::Team {
                return Err(template_input("signed template packages require team mode"));
            }
            let trust = material.trust.ok_or(AuthorityError::PolicyUnavailable)?;
            let trust = rekey_policy::ValidatedPolicyTrust::from_parts(trust.signer_id, trust.key);
            return templates::parse_and_verify_template_package(bytes, &trust)
                .map_err(template_package_error);
        }
        if !bytes.is_empty() {
            return Err(template_input(
                "built-in template package body must be empty",
            ));
        }
        let builtin = match source {
            TemplateSource::Anthropic {} => BuiltinTemplate::Anthropic,
            TemplateSource::OpenAi {} => BuiltinTemplate::OpenAi,
            TemplateSource::GitHubPat {} => BuiltinTemplate::GitHubPat,
            TemplateSource::GenericBearer { origin, actions } => BuiltinTemplate::GenericBearer {
                origin,
                actions: actions
                    .into_iter()
                    .map(|action| (action.method, action.path))
                    .collect(),
            },
            TemplateSource::SignedPackage {} => unreachable!(),
        };
        templates::builtin_template(builtin).map_err(template_package_error)
    }

    fn template_catalog(
        &mut self,
        source: TemplateSource,
        bytes: &[u8],
        not_after: Option<Instant>,
    ) -> Result<TemplateCatalogResponse, AuthorityError> {
        let package = self.authenticated_template(source, bytes)?;
        let response = TemplateCatalogResponse {
            template: package.template().clone(),
            digest: package.digest(),
            signer_id: package.signer_id(),
        };
        template_metadata_fits(&response)?;
        ensure_mutation_current(not_after)?;
        Ok(response)
    }

    fn template_install(
        &mut self,
        input: TemplateInstallMeta,
        bytes: &[u8],
        proof: UnlockProof,
        request_id: rekey_domain::ids::RequestId,
        not_after: Option<Instant>,
    ) -> Result<TemplateInstallResponse, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        ensure_mutation_current(not_after)?;
        template_metadata_fits(&input)?;
        let package = self.authenticated_template(input.source, bytes)?;
        let credential = self.load_verified_credential(input.credential_id)?;
        if credential.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        if credential.kind != CredentialKind::OpaqueToken {
            return Err(template_input(
                "provider templates require opaque-token credentials",
            ));
        }
        if input.bindings.is_empty()
            || input.capabilities.is_empty()
            || input.capabilities.iter().collect::<BTreeSet<_>>().len() != input.capabilities.len()
        {
            return Err(template_input(
                "template bindings and unique capabilities are required",
            ));
        }
        let capabilities = input
            .capabilities
            .iter()
            .map(|id| {
                package
                    .template()
                    .definition()
                    .capabilities
                    .iter()
                    .find(|capability| &capability.id == id)
                    .ok_or_else(|| template_input("unknown template capability"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prefix = ActionName::new(&input.name_prefix)?;
        let request_policy = RequestPolicy {
            max_body_bytes: input.request_max_bytes,
            allowed_extra_headers: input
                .allowed_extra_headers
                .iter()
                .map(|name| HeaderName::new(name))
                .collect::<Result<_, _>>()?,
        };
        let response_policy = ResponsePolicy {
            max_body_bytes: input.response_max_bytes,
            allowed_headers: input
                .allowed_response_headers
                .iter()
                .map(|name| HeaderName::new(name))
                .collect::<Result<_, _>>()?,
        };
        let mut catalog = ipc::ActionListResponse {
            actions: self.action_list()?,
        };
        let mut response = TemplateInstallResponse {
            actions: Vec::new(),
        };
        let mut records = Vec::new();
        for (binding_index, values) in input.bindings.iter().enumerate() {
            let bound = package.template().bind(values)?;
            for capability in &capabilities {
                for action_index in 0..capability.actions.len() {
                    ensure_mutation_current(not_after)?;
                    let materialized = bound.materialize(&capability.id, action_index)?;
                    let definition = materialized.definition();
                    let body_schema = definition
                        .body_schema
                        .as_deref()
                        .map(|reference| {
                            package
                                .schema(reference)
                                .map(|schema| schema.definition().clone())
                        })
                        .transpose()
                        .map_err(template_package_error)?;
                    let action_id = ActionId::from_random_bytes(random_array()?);
                    let (action, record) = self.prepare_action(
                        ActionDefinition {
                            native_plugin: None,
                            text_stream: None,
                            name: ActionName::new(&format!(
                                "{}/{}/{}/{}",
                                prefix.as_str(),
                                binding_index,
                                capability.id,
                                action_index
                            ))?,
                            credential_id: input.credential_id,
                            origin: definition.origin.clone(),
                            method: definition.method,
                            target: ActionTarget::Template {
                                target: definition.target.clone(),
                                fixed_headers: definition.fixed_headers.clone(),
                                body_schema,
                                default_policy: definition.default_policy.clone(),
                                source: Box::new(TemplateActionSource {
                                    template: definition.template.clone(),
                                    capability: definition.capability.clone(),
                                    action_index: definition.action_index,
                                    digest: package.digest(),
                                    signer_id: package.signer_id(),
                                }),
                            },
                            auth: HeaderCredentialUse::new(
                                definition.credential.inject.header.clone(),
                                definition.credential.inject.prefix.clone(),
                            )?,
                            timeout_ms: input.timeout_ms,
                            request_policy: request_policy.clone(),
                            response_policy: response_policy.clone(),
                        },
                        action_id,
                        1,
                    )?;
                    catalog.actions.push(action.clone());
                    response.actions.push(TemplateInstalledAction {
                        binding_index,
                        action,
                    });
                    // Bound expansion as it happens, before it can allocate an unbounded batch.
                    template_metadata_fits(&catalog)?;
                    template_metadata_fits(&response)?;
                    let mut draft = credential_audit(
                        event_type::ACTION_CREATED,
                        input.credential_id,
                        0,
                        "template-install",
                    );
                    draft.credential_version = None;
                    draft.request_id = Some(request_id);
                    draft.action_id = Some(action_id);
                    draft.action_version = Some(1);
                    records.push((record, self.audit_event_or_fault(draft)?));
                }
            }
        }
        ensure_mutation_current(not_after)?;
        if records.is_empty() {
            return Ok(response);
        }
        let observed = self.mutation_observation()?;
        let mut generation = crate::store::generation::GenerationAttempt::new(
            &self.anchors,
            &self.header,
            observed,
            self.require_unlocked()?.bytes(),
            self.header
                .generation
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            not_after,
            None,
        )?;
        let result = self
            .store
            .insert_actions_before(&records, not_after, &mut generation);
        let result = self.complete_generation(result, generation.finish());
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)?;
        Ok(response)
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
        if matches!(definition.target, ActionTarget::Template { .. })
            && credential.kind != CredentialKind::OpaqueToken
        {
            return Err(rekey_domain::DomainError::InvalidActionDefinition(
                "provider templates require opaque-token credentials".into(),
            )
            .into());
        }
        if let Some(plugin) = definition.native_plugin.as_ref() {
            let required = match plugin.protocol.as_str() {
                "github-issues-v1" => CredentialKind::GitHubAppInstallation,
                "anthropic-messages-v1" => CredentialKind::OpaqueToken,
                _ => {
                    return Err(rekey_domain::DomainError::InvalidActionDefinition(
                        "invalid native plugin declaration".into(),
                    )
                    .into());
                }
            };
            if credential.kind != required {
                return Err(rekey_domain::DomainError::InvalidActionDefinition(
                    if plugin.protocol == "github-issues-v1" {
                        "GitHub issue plugins require a GitHub App credential"
                    } else {
                        "Anthropic message plugins require an opaque-token credential"
                    }
                    .into(),
                )
                .into());
            }
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                target_env = "gnu",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        if definition.native_plugin.is_some() {
            return Err(rekey_domain::DomainError::InvalidActionDefinition(
                "native plugins require macOS or Linux GNU x86_64/aarch64".into(),
            )
            .into());
        }
        let mut retired = Vec::new();
        let (action_id, version, event) = match existing {
            Some(id) => {
                let previous: Vec<_> = self
                    .verified_actions()?
                    .into_iter()
                    .filter(|(record, _)| record.action_id == id)
                    .map(|(record, _)| record)
                    .collect();
                let current = previous
                    .iter()
                    .map(|record| record.version)
                    .max()
                    .ok_or(AuthorityError::ActionNotFound)?;
                let version = current
                    .checked_add(1)
                    .filter(|v| *v <= i64::MAX as u64)
                    .ok_or(AuthorityError::StorageIntegrityFailed)?;
                for mut record in previous {
                    if record.state != ActionState::Retired {
                        record.state = ActionState::Retired;
                        let seal = action_state::seal(
                            self.require_unlocked()?.bytes(),
                            self.header.vault_id,
                            &record,
                        )?;
                        record.seal_nonce = seal.nonce;
                        record.seal_ciphertext = seal.ciphertext;
                        retired.push(record);
                    }
                }
                (id, version, event_type::ACTION_UPDATED)
            }
            None => (
                ActionId::from_random_bytes(random_array()?),
                1,
                event_type::ACTION_CREATED,
            ),
        };
        let credential_id = definition.credential_id;
        let (action, record) = self.prepare_action(definition, action_id, version)?;
        let mut draft = credential_audit(event, credential_id, 0, "upsert");
        draft.credential_version = None;
        draft.action_id = Some(action_id);
        draft.action_version = Some(version);
        let audit = self.audit_event_or_fault(draft)?;
        ensure_mutation_current(not_after)?;
        let observed = self.mutation_observation()?;
        let mut generation = crate::store::generation::GenerationAttempt::new(
            &self.anchors,
            &self.header,
            observed,
            self.require_unlocked()?.bytes(),
            self.header
                .generation
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            not_after,
            None,
        )?;
        let result = self
            .store
            .insert_action(&record, &retired, audit, &mut generation);
        let result = self.complete_generation(result, generation.finish());
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)?;
        Ok(action)
    }

    fn prepare_action(
        &self,
        definition: ActionDefinition,
        action_id: ActionId,
        version: u64,
    ) -> Result<(FixedHttpAction, ActionRecord), AuthorityError> {
        let action = FixedHttpAction {
            native_plugin: definition.native_plugin,
            text_stream: definition.text_stream,
            id: action_id,
            name: definition.name,
            version,
            enabled: true,
            credential_id: definition.credential_id,
            origin: definition.origin,
            method: definition.method,
            target: definition.target,
            auth: definition.auth,
            timeout_ms: definition.timeout_ms,
            request_policy: definition.request_policy,
            response_policy: definition.response_policy,
        };
        action.validate()?;
        let mut record = action_to_record(&action, now_ms()?)?;
        let seal = action_state::seal(
            self.require_unlocked()?.bytes(),
            self.header.vault_id,
            &record,
        )?;
        record.seal_nonce = seal.nonce;
        record.seal_ciphertext = seal.ciphertext;
        Ok((action, record))
    }

    fn action_disable(
        &mut self,
        action_id: ActionId,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let mut record = self
            .verified_actions()?
            .into_iter()
            .find(|(record, _)| {
                record.action_id == action_id && record.state == ActionState::Active
            })
            .map(|(record, _)| record)
            .ok_or(AuthorityError::ActionNotFound)?;
        record.state = ActionState::Disabled;
        let seal = action_state::seal(
            self.require_unlocked()?.bytes(),
            self.header.vault_id,
            &record,
        )?;
        record.seal_nonce = seal.nonce;
        record.seal_ciphertext = seal.ciphertext;
        let mut draft = unlock_audit(event_type::ACTION_DISABLED, outcome::SUCCESS, "disable");
        draft.action_id = Some(action_id);
        let audit = self.audit_event_or_fault(draft)?;
        ensure_mutation_current(not_after)?;
        let observed = self.mutation_observation()?;
        let mut generation = crate::store::generation::GenerationAttempt::new(
            &self.anchors,
            &self.header,
            observed,
            self.require_unlocked()?.bytes(),
            self.header
                .generation
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            not_after,
            None,
        )?;
        let result = self.store.disable_action(&record, audit, &mut generation);
        let result = self.complete_generation(result, generation.finish());
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }

    fn verified_actions(&mut self) -> Result<Vec<(ActionRecord, FixedHttpAction)>, AuthorityError> {
        self.require_unlocked()?;
        let result = (|| {
            let key = self.require_unlocked()?.bytes();
            self.store
                .list_all_actions()?
                .into_iter()
                .map(|record| {
                    let action = verified_record_to_action(&record, key, self.header.vault_id)?;
                    Ok((record, action))
                })
                .collect()
        })();
        self.fault_on_integrity(result)
    }

    fn action_list(&mut self) -> Result<Vec<FixedHttpAction>, AuthorityError> {
        Ok(self
            .verified_actions()?
            .into_iter()
            .filter(|(record, _)| record.state != ActionState::Retired)
            .map(|(_, action)| action)
            .collect())
    }

    fn action_get(
        &mut self,
        action_id: ActionId,
        version: u64,
    ) -> Result<PinnedAction, AuthorityError> {
        self.require_unlocked()?;
        let result = (|| {
            let record = self.store.get_action(action_id, version)?;
            Ok(PinnedAction {
                action: verified_record_to_action(
                    &record,
                    self.require_unlocked()?.bytes(),
                    self.header.vault_id,
                )?,
                state: record.state,
            })
        })();
        self.fault_on_integrity(result)
    }
}

fn template_input(message: &'static str) -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition(message.into()).into()
}

fn template_package_error(error: TemplatePackageError) -> AuthorityError {
    match error {
        TemplatePackageError::InvalidSignature => AuthorityError::AuthenticationFailed,
        _ => template_input("invalid template package"),
    }
}

fn template_metadata_fits(value: &impl serde::Serialize) -> Result<(), AuthorityError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| template_input("invalid template metadata"))?;
    if bytes.len() > ipc::METADATA_MAX_BYTES as usize {
        return Err(template_input(
            "template action catalog exceeds metadata limit",
        ));
    }
    Ok(())
}

fn mutation_expired(not_after: Option<Instant>) -> bool {
    not_after.is_some_and(|deadline| Instant::now() >= deadline)
}

pub(crate) fn ensure_mutation_current(not_after: Option<Instant>) -> Result<(), AuthorityError> {
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
        request_context: None,
        usage: None,
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
        request_context: None,
        usage: None,
        event_type,
        outcome: outcome::SUCCESS,
        reason_code: reason.to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

mod usage;
