use rekey_domain::credential::{
    CredentialKind, CredentialLabel, CredentialMetadata, CredentialState, VersionState,
};
use rekey_domain::ids::CredentialId;

use super::{VaultState, Worker, credential_audit, ensure_mutation_current};
use crate::command::UnlockProof;
use crate::convert::record_to_metadata;
use crate::crypto::aad::{AadPurpose, AadV1};
use crate::crypto::aead;
use crate::crypto::credential_state;
use crate::crypto::keys::DataKey;
use crate::crypto::{AAD_VERSION_V1, CRYPTO_SUITE_V1};
use crate::error::AuthorityError;
use crate::model::{CredentialRecord, CredentialVersionRecord, event_type};
use crate::now_ms;
use crate::secret::{PreparedCredential, SecretInput};

impl Worker {
    fn refresh_state_seal(&self, record: &mut CredentialRecord) -> Result<(), AuthorityError> {
        let vrk = self.require_unlocked()?;
        let seal = credential_state::seal(vrk.bytes(), self.header.vault_id, record)?;
        record.state_nonce = seal.nonce;
        record.state_ciphertext = seal.ciphertext;
        Ok(())
    }

    pub(super) fn load_verified_credential(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<CredentialRecord, AuthorityError> {
        let result = (|| {
            self.require_unlocked()?;
            self.store.validate_credential_version_invariants()?;
            let record = self.store.get_credential(credential_id)?;
            let vrk = self.require_unlocked()?;
            credential_state::verify(vrk.bytes(), self.header.vault_id, &record)?;
            Ok(record)
        })();
        self.fault_on_integrity(result)
    }

    fn encrypt_new_version(
        &self,
        credential_id: CredentialId,
        version: u64,
        kind: CredentialKind,
        secret: &SecretInput,
        created_at_ms: i64,
    ) -> Result<CredentialVersionRecord, AuthorityError> {
        let vrk = self.require_unlocked()?;
        let dek = DataKey::generate()?;
        let payload_aad = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id: self.header.vault_id,
            object_id: *credential_id.as_bytes(),
            object_version: version,
            credential_kind: kind.aad_code(),
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
            created_at_ms,
            retired_at_ms: None,
        })
    }

    pub(super) fn credential_add(
        &mut self,
        label: CredentialLabel,
        kind: CredentialKind,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        if secret.is_empty() {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidCapability,
            ));
        }
        let credential_id = CredentialId::from_random_bytes(crate::crypto::random_array()?);
        let now = now_ms()?;
        let version = self.encrypt_new_version(credential_id, 1, kind, &secret, now)?;
        let mut record = CredentialRecord {
            credential_id,
            label: label.as_str().to_owned(),
            kind,
            state: CredentialState::Active,
            current_version: 1,
            created_at_ms: now,
            updated_at_ms: now,
            revoked_at_ms: None,
            state_nonce: [0u8; 12],
            state_ciphertext: [0u8; 16],
        };
        self.refresh_state_seal(&mut record)?;
        let audit = self.audit_event_or_fault(credential_audit(
            event_type::CREDENTIAL_CREATED,
            credential_id,
            1,
            "add",
        ))?;
        ensure_mutation_current(not_after)?;
        let result = self.store.insert_credential(&record, &version, audit);
        self.fault_on_audit_failure(result)?;
        record_to_metadata(&record)
    }

    pub(super) fn credential_list(&mut self) -> Result<Vec<CredentialMetadata>, AuthorityError> {
        let result = (|| {
            self.require_unlocked()?;
            self.store.validate_credential_version_invariants()?;
            let records = self.store.list_credentials()?;
            let vrk = self.require_unlocked()?;
            records
                .iter()
                .map(|record| {
                    credential_state::verify(vrk.bytes(), self.header.vault_id, record)?;
                    record_to_metadata(record)
                })
                .collect()
        })();
        self.fault_on_integrity(result)
    }

    pub(super) fn credential_rotate(
        &mut self,
        credential_id: CredentialId,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        if secret.is_empty() {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidCapability,
            ));
        }
        let mut updated = self.load_verified_credential(credential_id)?;
        if updated.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        if updated.kind != CredentialKind::OpaqueToken {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidActionDefinition(
                    "generic rotate only supports opaque-token credentials".to_owned(),
                ),
            ));
        }
        let next = updated.current_version + 1;
        let now = now_ms()?;
        let version = self.encrypt_new_version(
            credential_id,
            next,
            CredentialKind::OpaqueToken,
            &secret,
            now,
        )?;
        updated.current_version = next;
        updated.updated_at_ms = now;
        self.refresh_state_seal(&mut updated)?;
        let audit = self.audit_event_or_fault(credential_audit(
            event_type::CREDENTIAL_ROTATED,
            credential_id,
            next,
            "rotate",
        ))?;
        ensure_mutation_current(not_after)?;
        let result = self.store.rotate_credential(&updated, &version, now, audit);
        self.fault_on_audit_failure(result)?;
        record_to_metadata(&updated)
    }

    pub(super) fn credential_revoke(
        &mut self,
        credential_id: CredentialId,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let mut updated = self.load_verified_credential(credential_id)?;
        let now = now_ms()?;
        updated.state = CredentialState::Revoked;
        updated.updated_at_ms = now;
        updated.revoked_at_ms = Some(now);
        self.refresh_state_seal(&mut updated)?;
        let audit = self.audit_event_or_fault(credential_audit(
            event_type::CREDENTIAL_REVOKED,
            credential_id,
            updated.current_version,
            "revoke",
        ))?;
        ensure_mutation_current(not_after)?;
        let result = self.store.revoke_credential(&updated, now, audit);
        self.fault_on_audit_failure(result)?;
        record_to_metadata(&updated)
    }

    /// Decrypts the current active version. Every call re-checks persisted
    /// credential state, so a revoked credential can never produce a new
    /// lease even if in-memory session cleanup failed.
    pub(super) fn prepare_credential(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<PreparedCredential, AuthorityError> {
        let result = self.prepare_credential_inner(credential_id);
        if matches!(
            result,
            Err(AuthorityError::CryptoFailure | AuthorityError::StorageIntegrityFailed)
        ) && !matches!(self.state, VaultState::Faulted)
        {
            self.fault("credential-integrity-failed");
        }
        result
    }

    fn prepare_credential_inner(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<PreparedCredential, AuthorityError> {
        let credential = self.load_verified_credential(credential_id)?;
        let vrk = self.require_unlocked()?;
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
        let mut dek_arr: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityError::CryptoFailure)?;
        let dek = DataKey::from_bytes(&mut dek_arr);
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
            payload,
            credential_id,
            credential.kind,
            version.version,
        ))
    }
}
