use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Worker, ensure_mutation_current, unlock_audit};
use crate::command::{PolicyBundleInput, PolicyMaterial, PolicyTrustInput, UnlockProof};
use crate::crypto::policy_state;
use crate::error::AuthorityError;
use crate::model::{PolicyBundleRecord, PolicyStateRecord, PolicyTrustRecord, event_type, outcome};
use crate::now_ms;

impl Worker {
    pub(super) fn policy_material(&mut self) -> Result<PolicyMaterial, AuthorityError> {
        let key = Zeroizing::new(*self.require_unlocked()?.bytes());
        self.store
            .verified_policy_material(&key, self.header.vault_id)
    }

    pub(super) fn policy_trust_install(
        &mut self,
        input: PolicyTrustInput,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<PolicyMaterial, AuthorityError> {
        self.verify_proof(&proof)?;
        let current = self.policy_material()?;
        if let Some(trust) = current.trust {
            return if trust.signer_id == input.signer_id && trust.public_key == input.public_key {
                self.policy_material()
            } else {
                Err(AuthorityError::PolicyTrustConflict)
            };
        }
        ensure_mutation_current(not_after)?;
        let key = Zeroizing::new(*self.require_unlocked()?.bytes());
        let now = now_ms()?;
        let mut trust = PolicyTrustRecord {
            signer_id: input.signer_id,
            public_key: input.public_key,
            installed_at_ms: now,
            seal_nonce: [0u8; 12],
            seal_ciphertext: [0u8; 16],
        };
        let trust_seal = policy_state::seal_trust(&key, self.header.vault_id, &trust)?;
        trust.seal_nonce = trust_seal.nonce;
        trust.seal_ciphertext = trust_seal.ciphertext;
        let mut state = PolicyStateRecord {
            trust_installed: true,
            bundle_activated: false,
            signer_id: Some(input.signer_id),
            highest_version: None,
            policy_digest: None,
            bundle_digest: None,
            updated_at_ms: now,
            seal_nonce: [0u8; 12],
            seal_ciphertext: [0u8; 16],
        };
        let state_seal = policy_state::seal_state(&key, self.header.vault_id, &state)?;
        state.seal_nonce = state_seal.nonce;
        state.seal_ciphertext = state_seal.ciphertext;
        let event = self.audit_event_or_fault(unlock_audit(
            event_type::POLICY_TRUST_INSTALLED,
            outcome::SUCCESS,
            "policy-trust-installed",
        ))?;
        ensure_mutation_current(not_after)?;
        let result = self.store.install_policy_trust(&state, &trust, event);
        self.fault_on_audit_failure(result)?;
        self.policy_material()
    }

    pub(super) fn policy_bundle_activate(
        &mut self,
        input: PolicyBundleInput,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<PolicyMaterial, AuthorityError> {
        self.verify_proof(&proof)?;
        let current = self.policy_material()?;
        let trust = current.trust.ok_or(AuthorityError::PolicyUnavailable)?;
        if trust.signer_id != input.signer_id
            || input.version == 0
            || input.version >= i64::MAX as u64
            || input.expires_at_ms < 0
            || input.bundle_json.len() > 64 * 1024
            || Sha256::digest(&input.bundle_json).as_slice() != input.bundle_digest
        {
            return Err(AuthorityError::PolicyVersionConflict);
        }
        if let Some(existing) = current.bundle {
            if existing.version == input.version && existing.bundle_digest == input.bundle_digest {
                return self.policy_material();
            }
            if existing.version >= i64::MAX as u64 - 1 {
                return Err(AuthorityError::PolicyVersionExhausted);
            }
            if input.version != existing.version + 1 {
                return Err(AuthorityError::PolicyVersionConflict);
            }
        } else if input.version != 1 {
            return Err(AuthorityError::PolicyVersionConflict);
        }
        ensure_mutation_current(not_after)?;
        let key = Zeroizing::new(*self.require_unlocked()?.bytes());
        let now = now_ms()?;
        let mut bundle = PolicyBundleRecord {
            signer_id: input.signer_id,
            version: input.version,
            expires_at_ms: input.expires_at_ms,
            policy_digest: input.policy_digest,
            bundle_digest: input.bundle_digest,
            bundle_json: input.bundle_json,
            activated_at_ms: now,
            seal_nonce: [0u8; 12],
            seal_ciphertext: [0u8; 16],
        };
        let bundle_seal = policy_state::seal_bundle(&key, self.header.vault_id, &bundle)?;
        bundle.seal_nonce = bundle_seal.nonce;
        bundle.seal_ciphertext = bundle_seal.ciphertext;
        let mut state = PolicyStateRecord {
            trust_installed: true,
            bundle_activated: true,
            signer_id: Some(input.signer_id),
            highest_version: Some(input.version),
            policy_digest: Some(input.policy_digest),
            bundle_digest: Some(input.bundle_digest),
            updated_at_ms: now,
            seal_nonce: [0u8; 12],
            seal_ciphertext: [0u8; 16],
        };
        let state_seal = policy_state::seal_state(&key, self.header.vault_id, &state)?;
        state.seal_nonce = state_seal.nonce;
        state.seal_ciphertext = state_seal.ciphertext;
        let event = self.audit_event_or_fault(unlock_audit(
            event_type::POLICY_ACTIVATED,
            outcome::SUCCESS,
            "policy-activated",
        ))?;
        ensure_mutation_current(not_after)?;
        if bundle.expires_at_ms <= now_ms()? {
            return Err(AuthorityError::PolicyVersionConflict);
        }
        let result = self.store.activate_policy_bundle(&state, &bundle, event);
        self.fault_on_audit_failure(result)?;
        self.policy_material()
    }
}
