use rekey_domain::credential::{CredentialState, VersionState};
use rekey_domain::ids::CredentialId;
use zeroize::Zeroizing;

use super::Worker;
use crate::crypto::aad::{AadPurpose, AadV1};
use crate::crypto::aead;
use crate::crypto::keys::DataKey;
use crate::error::AuthorityError;
use crate::secret::PreparedCredential;

impl Worker {
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
        ) {
            self.fault("credential-integrity-failed");
        }
        result
    }

    fn prepare_credential_inner(
        &self,
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
            credential.kind,
            version.version,
        ))
    }
}
