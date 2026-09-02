use rekey_domain::credential::CredentialState;
use rekey_domain::ids::VaultId;
use sha2::{Digest, Sha256};

use super::aad::{AadPurpose, AadV1};
use super::aead;
use crate::error::AuthorityError;
use crate::model::CredentialRecord;

const STATE_MAGIC: [u8; 4] = *b"RKCS";
const STATE_VERSION: u16 = 1;
const STATE_TAG_LEN: usize = 16;

pub struct CredentialStateSeal {
    pub nonce: [u8; 12],
    pub ciphertext: [u8; STATE_TAG_LEN],
}

fn state_code(state: CredentialState) -> u16 {
    match state {
        CredentialState::Active => 1,
        CredentialState::Revoked => 2,
    }
}

pub fn canonical_record(record: &CredentialRecord) -> Result<Vec<u8>, AuthorityError> {
    let label = record.label.as_bytes();
    let label_len =
        u16::try_from(label.len()).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let revoked_at_ms = match (record.state, record.revoked_at_ms) {
        (CredentialState::Active, None) => -1,
        (CredentialState::Revoked, Some(value)) if value != -1 => value,
        _ => return Err(AuthorityError::StorageIntegrityFailed),
    };
    let mut bytes = Vec::with_capacity(60 + label.len());
    bytes.extend_from_slice(&STATE_MAGIC);
    bytes.extend_from_slice(&STATE_VERSION.to_be_bytes());
    bytes.extend_from_slice(record.credential_id.as_bytes());
    bytes.extend_from_slice(&label_len.to_be_bytes());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(&record.kind.aad_code().to_be_bytes());
    bytes.extend_from_slice(&state_code(record.state).to_be_bytes());
    bytes.extend_from_slice(&record.current_version.to_be_bytes());
    bytes.extend_from_slice(&record.created_at_ms.to_be_bytes());
    bytes.extend_from_slice(&record.updated_at_ms.to_be_bytes());
    bytes.extend_from_slice(&revoked_at_ms.to_be_bytes());
    Ok(bytes)
}

fn aad(vault_id: VaultId, record: &CredentialRecord) -> Result<[u8; 84], AuthorityError> {
    let constraints_hash: [u8; 32] = Sha256::digest(canonical_record(record)?).into();
    Ok(AadV1 {
        purpose: AadPurpose::CredentialState,
        vault_id,
        object_id: *record.credential_id.as_bytes(),
        object_version: record.current_version,
        credential_kind: record.kind.aad_code(),
        constraints_hash,
    }
    .encode())
}

pub fn seal(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &CredentialRecord,
) -> Result<CredentialStateSeal, AuthorityError> {
    let sealed = aead::seal(key, &aad(vault_id, record)?, &[])?;
    let ciphertext = sealed
        .ciphertext
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)?;
    Ok(CredentialStateSeal {
        nonce: sealed.nonce,
        ciphertext,
    })
}

pub fn verify(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &CredentialRecord,
) -> Result<(), AuthorityError> {
    let plaintext = aead::open(
        key,
        &aad(vault_id, record)?,
        &record.state_nonce,
        &record.state_ciphertext,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if !plaintext.is_empty() {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rekey_domain::credential::CredentialKind;
    use rekey_domain::ids::CredentialId;

    use super::*;

    fn record() -> CredentialRecord {
        CredentialRecord {
            credential_id: CredentialId::from_bytes([0x11; 16]).unwrap(),
            label: "api-key".to_owned(),
            kind: CredentialKind::OpaqueToken,
            state: CredentialState::Active,
            current_version: 3,
            created_at_ms: 10,
            updated_at_ms: 20,
            revoked_at_ms: None,
            state_nonce: [0u8; 12],
            state_ciphertext: [0u8; 16],
        }
    }

    #[test]
    fn canonical_record_is_big_endian_and_stable() {
        let encoded = canonical_record(&record()).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"RKCS");
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&7u16.to_be_bytes());
        expected.extend_from_slice(b"api-key");
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(&3u64.to_be_bytes());
        expected.extend_from_slice(&10i64.to_be_bytes());
        expected.extend_from_slice(&20i64.to_be_bytes());
        expected.extend_from_slice(&(-1i64).to_be_bytes());
        assert_eq!(encoded, expected);
    }

    #[test]
    fn seal_binds_every_lifecycle_field() {
        let key = [0x33; 32];
        let vault_id = VaultId::from_bytes([0x22; 16]).unwrap();
        let mut original = record();
        let seal = seal(&key, vault_id, &original).unwrap();
        original.state_nonce = seal.nonce;
        original.state_ciphertext = seal.ciphertext;
        verify(&key, vault_id, &original).unwrap();

        let mut variants = Vec::new();
        let mut value = original.clone();
        value.label = "other".to_owned();
        variants.push(value);
        let mut value = original.clone();
        value.kind = CredentialKind::GitHubAppInstallation;
        variants.push(value);
        let mut value = original.clone();
        value.state = CredentialState::Revoked;
        variants.push(value);
        let mut value = original.clone();
        value.current_version += 1;
        variants.push(value);
        let mut value = original.clone();
        value.created_at_ms += 1;
        variants.push(value);
        let mut value = original.clone();
        value.updated_at_ms += 1;
        variants.push(value);
        let mut value = original.clone();
        value.revoked_at_ms = Some(1);
        variants.push(value);

        for variant in variants {
            assert!(matches!(
                verify(&key, vault_id, &variant),
                Err(AuthorityError::StorageIntegrityFailed)
            ));
        }
    }

    #[test]
    fn sentinel_and_state_combinations_are_unambiguous() {
        let mut value = record();
        value.revoked_at_ms = Some(-1);
        assert!(matches!(
            canonical_record(&value),
            Err(AuthorityError::StorageIntegrityFailed)
        ));

        value.state = CredentialState::Revoked;
        value.revoked_at_ms = None;
        assert!(matches!(
            canonical_record(&value),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }
}
