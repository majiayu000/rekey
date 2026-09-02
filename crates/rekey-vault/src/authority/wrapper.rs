use rekey_domain::ids::WrapperId;
use zeroize::Zeroizing;

use super::{Worker, ensure_mutation_current, unlock_audit};
use crate::bootstrap::wrap_vrk;
use crate::command::UnlockProof;
use crate::crypto::kdf::{
    Argon2Params, KDF_ALGORITHM_ARGON2ID, KDF_ALGORITHM_HKDF_SHA256, derive_password_kek,
    derive_recovery_kek,
};
use crate::crypto::recovery::encode_recovery_key;
use crate::crypto::{KEY_LEN, SALT_LEN, random_array};
use crate::error::AuthorityError;
use crate::model::{KeyWrapperRecord, WrapperKind, WrapperState, event_type, outcome};
use crate::now_ms;
use crate::secret::SecretInput;

const SECRET_INPUT_MAX_BYTES: usize = 64 * 1024;

impl Worker {
    pub(super) fn password_change(
        &mut self,
        proof: UnlockProof,
        new_password: SecretInput,
        not_after: Option<std::time::Instant>,
    ) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        let reason = match &proof {
            UnlockProof::Password(_) => "password-step-up",
            UnlockProof::Recovery(_) => "recovery-step-up",
        };
        if let Err(error) = self.verify_proof(&proof) {
            if matches!(error, AuthorityError::InvalidUnlockCredential) {
                self.append_audit(unlock_audit(
                    event_type::VAULT_PASSWORD_CHANGE_FAILED,
                    outcome::DENIED,
                    "invalid-step-up",
                ))?;
            }
            return Err(error);
        }
        if new_password.is_empty() || new_password.expose().len() > SECRET_INPUT_MAX_BYTES {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidActionDefinition(
                    "new password must be between 1 byte and 64 KiB".to_owned(),
                ),
            ));
        }

        let wrapper_id = WrapperId::from_random_bytes(random_array()?);
        let salt: [u8; SALT_LEN] = random_array()?;
        let params = Argon2Params::RFC9106_LOW_MEMORY;
        let kek = derive_password_kek(new_password.expose(), &salt, &params)?;
        let vrk = self.require_unlocked()?;
        let (nonce, wrapped_vrk) = wrap_vrk(self.header.vault_id, wrapper_id, &kek, vrk)?;
        let now = now_ms()?;
        let replacement = KeyWrapperRecord {
            wrapper_id,
            kind: WrapperKind::Password,
            state: WrapperState::Active,
            kdf_algorithm: KDF_ALGORITHM_ARGON2ID.to_owned(),
            kdf_params_json: params.to_json(),
            salt,
            nonce,
            wrapped_vrk,
            created_at_ms: now,
            disabled_at_ms: None,
        };
        let audit = self.audit_event_or_fault(unlock_audit(
            event_type::VAULT_PASSWORD_CHANGED,
            outcome::SUCCESS,
            reason,
        ))?;
        ensure_mutation_current(not_after)?;
        let result = self
            .store
            .replace_wrapper(WrapperKind::Password, &replacement, now, audit);
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }

    pub(super) fn recovery_rotate(
        &mut self,
        password: SecretInput,
        not_after: Option<std::time::Instant>,
    ) -> Result<Zeroizing<String>, AuthorityError> {
        self.require_unlocked()?;
        let proof = UnlockProof::Password(password);
        if let Err(error) = self.verify_proof(&proof) {
            if matches!(error, AuthorityError::InvalidUnlockCredential) {
                self.append_audit(unlock_audit(
                    event_type::VAULT_RECOVERY_ROTATION_FAILED,
                    outcome::DENIED,
                    "invalid-step-up",
                ))?;
            }
            return Err(error);
        }

        let recovery_key: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(random_array()?);
        let recovery_display = encode_recovery_key(&recovery_key);
        let wrapper_id = WrapperId::from_random_bytes(random_array()?);
        let salt: [u8; SALT_LEN] = random_array()?;
        let kek = derive_recovery_kek(&recovery_key, &salt)?;
        let vrk = self.require_unlocked()?;
        let (nonce, wrapped_vrk) = wrap_vrk(self.header.vault_id, wrapper_id, &kek, vrk)?;
        let now = now_ms()?;
        let replacement = KeyWrapperRecord {
            wrapper_id,
            kind: WrapperKind::Recovery,
            state: WrapperState::Active,
            kdf_algorithm: KDF_ALGORITHM_HKDF_SHA256.to_owned(),
            kdf_params_json: "{}".to_owned(),
            salt,
            nonce,
            wrapped_vrk,
            created_at_ms: now,
            disabled_at_ms: None,
        };
        let audit = self.audit_event_or_fault(unlock_audit(
            event_type::VAULT_RECOVERY_ROTATED,
            outcome::SUCCESS,
            "password-step-up",
        ))?;
        ensure_mutation_current(not_after)?;
        let result = self
            .store
            .replace_wrapper(WrapperKind::Recovery, &replacement, now, audit);
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)?;
        Ok(recovery_display)
    }
}
