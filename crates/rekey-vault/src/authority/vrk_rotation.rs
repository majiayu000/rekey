//! Offline-within-worker root replacement: never installs either root in state.
use std::time::Instant;

use rekey_domain::ids::WrapperId;
use rekey_domain::ipc::{ApprovalOriginResponse, VrkRotatedResponse};
use subtle::ConstantTimeEq;

use super::{
    FREE_UNLOCK_FAILURES, UNLOCK_BACKOFF_CAP, VaultState, Worker, ensure_mutation_current,
    unlock_audit,
};
use crate::bootstrap::{kek_for_wrapper, prove_integrity, seal_integrity, unwrap_vrk, wrap_vrk};
use crate::crypto::kdf::{Argon2Params, KDF_ALGORITHM_ARGON2ID, KDF_ALGORITHM_HKDF_SHA256};
use crate::crypto::keys::RootKey;
use crate::crypto::{credential_state, policy_state, random_array};
use crate::error::AuthorityError;
use crate::model::{KeyWrapperRecord, WrapperKind, WrapperState, event_type, outcome};
use crate::secret::SecretInput;

impl Worker {
    pub(super) fn rotate_vrk(
        &mut self,
        password: SecretInput,
        recovery: SecretInput,
        not_after: Option<Instant>,
    ) -> Result<VrkRotatedResponse, AuthorityError> {
        let result = self.rotate_vrk_inner(password, recovery, not_after);
        if matches!(
            result,
            Err(AuthorityError::CryptoFailure | AuthorityError::StorageIntegrityFailed)
        ) {
            self.fault("root-rotation-integrity-failed");
        }
        self.fault_on_audit_failure(result)
    }

    fn rotate_vrk_inner(
        &mut self,
        password: SecretInput,
        recovery: SecretInput,
        not_after: Option<Instant>,
    ) -> Result<VrkRotatedResponse, AuthorityError> {
        ensure_mutation_current(not_after)?;
        match self.state {
            VaultState::Locked => {}
            VaultState::Faulted => return Err(AuthorityError::Faulted),
            VaultState::Unlocked { .. } => {
                return Err(AuthorityError::Domain(
                    rekey_domain::DomainError::InvalidActionDefinition(
                        "VRK rotation requires an explicit lock first".to_owned(),
                    ),
                ));
            }
        }
        if Instant::now() < self.next_unlock_at {
            return Err(AuthorityError::UnlockRateLimited);
        }
        // Both inputs are checked without temporarily opening the worker.
        let candidate = |kind, secret: &SecretInput| {
            let result = self.store.active_wrapper(kind).and_then(|wrapper| {
                let kek = kek_for_wrapper(&wrapper, secret)?;
                unwrap_vrk(self.header.vault_id, &wrapper, &kek)
            });
            match result {
                Ok(root) => Ok(Some(root)),
                Err(AuthorityError::InvalidUnlockCredential) => Ok(None),
                Err(error) => Err(error),
            }
        };
        let password_root = candidate(WrapperKind::Password, &password)?;
        let recovery_root = candidate(WrapperKind::Recovery, &recovery)?;
        let old_root = match (password_root, recovery_root) {
            (Some(a), Some(b)) if bool::from(a.bytes().ct_eq(b.bytes())) => a,
            _ => {
                self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                if self.failed_unlocks >= FREE_UNLOCK_FAILURES {
                    let shift = (self.failed_unlocks - FREE_UNLOCK_FAILURES).min(16);
                    self.next_unlock_at = Instant::now()
                        + self
                            .config
                            .unlock_backoff_base
                            .saturating_mul(1u32 << shift)
                            .min(UNLOCK_BACKOFF_CAP);
                }
                self.append_audit(unlock_audit(
                    event_type::VAULT_UNLOCK_FAILED,
                    outcome::DENIED,
                    "invalid-credential",
                ))?;
                return Err(AuthorityError::InvalidUnlockCredential);
            }
        };
        ensure_mutation_current(not_after)?;
        prove_integrity(&self.header, &old_root)?;
        self.store.validate_credential_version_invariants()?;
        let mut credentials = self.store.list_credentials()?;
        for record in &credentials {
            ensure_mutation_current(not_after)?;
            credential_state::verify(old_root.bytes(), self.header.vault_id, record)?;
        }
        let mut policy = self
            .store
            .verified_policy_material(old_root.bytes(), self.header.vault_id)?;
        let new_root = RootKey::generate()?;
        let versions =
            self.rotated_version_ciphertexts(old_root.bytes(), new_root.bytes(), not_after)?;
        for record in &mut credentials {
            ensure_mutation_current(not_after)?;
            let seal = credential_state::seal(new_root.bytes(), self.header.vault_id, record)?;
            record.state_nonce = seal.nonce;
            record.state_ciphertext = seal.ciphertext;
        }
        let seal = policy_state::seal_state(new_root.bytes(), self.header.vault_id, &policy.state)?;
        policy.state.seal_nonce = seal.nonce;
        policy.state.seal_ciphertext = seal.ciphertext;
        if let Some(trust) = &mut policy.trust {
            let seal = policy_state::seal_trust(new_root.bytes(), self.header.vault_id, trust)?;
            trust.seal_nonce = seal.nonce;
            trust.seal_ciphertext = seal.ciphertext;
        }
        if let Some(bundle) = &mut policy.bundle {
            let seal = policy_state::seal_bundle(new_root.bytes(), self.header.vault_id, bundle)?;
            bundle.seal_nonce = seal.nonce;
            bundle.seal_ciphertext = seal.ciphertext;
        }
        let mut header = self.header.clone();
        let integrity = seal_integrity(header.vault_id, &new_root)?;
        header.integrity_nonce = integrity.nonce;
        header.integrity_ciphertext = integrity.ciphertext;
        let now = crate::now_ms()?;
        let mut wrappers = Vec::with_capacity(2);
        for (kind, secret) in [
            (WrapperKind::Password, &password),
            (WrapperKind::Recovery, &recovery),
        ] {
            ensure_mutation_current(not_after)?;
            let mut wrapper = KeyWrapperRecord {
                wrapper_id: WrapperId::from_random_bytes(random_array()?),
                kind,
                state: WrapperState::Active,
                kdf_algorithm: match kind {
                    WrapperKind::Password => KDF_ALGORITHM_ARGON2ID,
                    WrapperKind::Recovery => KDF_ALGORITHM_HKDF_SHA256,
                }
                .to_owned(),
                kdf_params_json: match kind {
                    WrapperKind::Password => Argon2Params::RFC9106_LOW_MEMORY.to_json(),
                    WrapperKind::Recovery => "{}".to_owned(),
                },
                salt: random_array()?,
                nonce: [0; 12],
                wrapped_vrk: Vec::new(),
                created_at_ms: now,
                disabled_at_ms: None,
            };
            let kek = kek_for_wrapper(&wrapper, secret)?;
            (wrapper.nonce, wrapper.wrapped_vrk) =
                wrap_vrk(header.vault_id, wrapper.wrapper_id, &kek, &new_root)?;
            wrappers.push(wrapper);
        }
        let public_key =
            crate::crypto::approval_origin::approval_origin_public_key(&new_root, header.vault_id)?;
        let receipt = VrkRotatedResponse {
            vault_id: header.vault_id,
            rotated_versions: versions.len() as u64,
            resealed_credentials: credentials.len() as u64,
            approval_origin: ApprovalOriginResponse {
                algorithm: "ed25519".to_owned(),
                public_key: data_encoding::HEXLOWER.encode(&public_key),
            },
            locked: true,
        };
        let audit = self.audit_event_or_fault(unlock_audit(
            event_type::VAULT_VRK_ROTATED,
            outcome::SUCCESS,
            "vrk-rotation",
        ))?;
        ensure_mutation_current(not_after)?;
        // Filesystem and SQLite cannot commit atomically. Revocation is one-way,
        // including if a subsequent SQL/deadline failure keeps the old root.
        self.desktop_session = None;
        self.desktop_resume_expiry = None;
        let forgotten = self.forget_desktop().and_then(|_| {
            crate::durable::fsync(&self.config.state_dir).map_err(AuthorityError::storage)
        });
        if let Err(error) = forgotten {
            self.fault("desktop-revocation-failed");
            return Err(error);
        }
        ensure_mutation_current(not_after)?;
        self.store.replace_root_ciphertexts(
            &header,
            &versions,
            &credentials,
            &policy,
            &wrappers,
            audit,
            not_after,
        )?;
        // No fallible operation is allowed after commit.
        self.header = header;
        self.failed_unlocks = 0;
        Ok(receipt)
    }
}
