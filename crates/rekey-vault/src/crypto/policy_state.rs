use sha2::{Digest, Sha256};

use super::aad::{AadPurpose, AadV1};
use super::aead;
use crate::error::AuthorityError;
use crate::model::{PolicyBundleRecord, PolicyStateRecord, PolicyTrustRecord};
use rekey_domain::ids::VaultId;

pub struct LifecycleSeal {
    pub nonce: [u8; 12],
    pub ciphertext: [u8; 16],
}

pub fn canonical_state(
    vault_id: VaultId,
    record: &PolicyStateRecord,
) -> Result<Vec<u8>, AuthorityError> {
    validate_state(record)?;
    let mut bytes = Vec::with_capacity(148);
    bytes.extend_from_slice(b"RKPS");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(vault_id.as_bytes());
    bytes.push(u8::from(record.trust_installed));
    bytes.push(u8::from(record.bundle_activated));
    bytes.extend_from_slice(
        record
            .signer_id
            .as_ref()
            .map_or(&[0u8; 16], |id| id.as_bytes()),
    );
    bytes.extend_from_slice(&record.highest_version.unwrap_or(0).to_be_bytes());
    bytes.extend_from_slice(record.policy_digest.as_ref().unwrap_or(&[0u8; 32]));
    bytes.extend_from_slice(record.bundle_digest.as_ref().unwrap_or(&[0u8; 32]));
    bytes.extend_from_slice(&record.updated_at_ms.to_be_bytes());
    Ok(bytes)
}

pub fn canonical_trust(vault_id: VaultId, record: &PolicyTrustRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(76);
    bytes.extend_from_slice(b"RKPT");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(vault_id.as_bytes());
    bytes.extend_from_slice(record.signer_id.as_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&record.public_key);
    bytes.extend_from_slice(&record.installed_at_ms.to_be_bytes());
    bytes
}

pub fn canonical_bundle(vault_id: VaultId, record: &PolicyBundleRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(138);
    bytes.extend_from_slice(b"RKPB");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(vault_id.as_bytes());
    bytes.extend_from_slice(record.signer_id.as_bytes());
    bytes.extend_from_slice(&record.version.to_be_bytes());
    bytes.extend_from_slice(&record.expires_at_ms.to_be_bytes());
    bytes.extend_from_slice(&record.policy_digest);
    bytes.extend_from_slice(&record.bundle_digest);
    bytes.extend_from_slice(&record.activated_at_ms.to_be_bytes());
    bytes
}

pub fn seal_state(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &PolicyStateRecord,
) -> Result<LifecycleSeal, AuthorityError> {
    seal(
        key,
        aad(
            AadPurpose::PolicyState,
            vault_id,
            [0u8; 16],
            1,
            &canonical_state(vault_id, record)?,
        ),
    )
}

pub fn seal_trust(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &PolicyTrustRecord,
) -> Result<LifecycleSeal, AuthorityError> {
    seal(
        key,
        aad(
            AadPurpose::PolicyTrust,
            vault_id,
            *record.signer_id.as_bytes(),
            1,
            &canonical_trust(vault_id, record),
        ),
    )
}

pub fn seal_bundle(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &PolicyBundleRecord,
) -> Result<LifecycleSeal, AuthorityError> {
    seal(
        key,
        aad(
            AadPurpose::PolicyBundle,
            vault_id,
            *record.signer_id.as_bytes(),
            record.version,
            &canonical_bundle(vault_id, record),
        ),
    )
}

pub fn verify_state(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &PolicyStateRecord,
) -> Result<(), AuthorityError> {
    verify(
        key,
        aad(
            AadPurpose::PolicyState,
            vault_id,
            [0u8; 16],
            1,
            &canonical_state(vault_id, record)?,
        ),
        record.seal_nonce,
        record.seal_ciphertext,
    )
}

pub fn verify_trust(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &PolicyTrustRecord,
) -> Result<(), AuthorityError> {
    verify(
        key,
        aad(
            AadPurpose::PolicyTrust,
            vault_id,
            *record.signer_id.as_bytes(),
            1,
            &canonical_trust(vault_id, record),
        ),
        record.seal_nonce,
        record.seal_ciphertext,
    )
}

pub fn verify_bundle(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &PolicyBundleRecord,
) -> Result<(), AuthorityError> {
    verify(
        key,
        aad(
            AadPurpose::PolicyBundle,
            vault_id,
            *record.signer_id.as_bytes(),
            record.version,
            &canonical_bundle(vault_id, record),
        ),
        record.seal_nonce,
        record.seal_ciphertext,
    )
}

fn validate_state(record: &PolicyStateRecord) -> Result<(), AuthorityError> {
    let trust_fields = record.signer_id.is_some();
    let bundle_field_count = usize::from(record.highest_version.is_some())
        + usize::from(record.policy_digest.is_some())
        + usize::from(record.bundle_digest.is_some());
    let bundle_fields = bundle_field_count == 3;
    if record.trust_installed != trust_fields
        || record.bundle_activated != bundle_fields
        || record.bundle_activated && !record.trust_installed
        || !record.bundle_activated && bundle_field_count != 0
        || record
            .highest_version
            .is_some_and(|version| version == 0 || version >= i64::MAX as u64)
        || record
            .policy_digest
            .is_some_and(|digest| digest == [0u8; 32])
        || record
            .bundle_digest
            .is_some_and(|digest| digest == [0u8; 32])
        || record.updated_at_ms < 0
    {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}

fn aad(
    purpose: AadPurpose,
    vault_id: VaultId,
    object_id: [u8; 16],
    object_version: u64,
    canonical: &[u8],
) -> [u8; 84] {
    AadV1 {
        purpose,
        vault_id,
        object_id,
        object_version,
        credential_kind: 0,
        constraints_hash: Sha256::digest(canonical).into(),
    }
    .encode()
}

fn seal(key: &[u8; 32], aad: [u8; 84]) -> Result<LifecycleSeal, AuthorityError> {
    let sealed = aead::seal(key, &aad, &[])?;
    Ok(LifecycleSeal {
        nonce: sealed.nonce,
        ciphertext: sealed
            .ciphertext
            .try_into()
            .map_err(|_| AuthorityError::CryptoFailure)?,
    })
}

fn verify(
    key: &[u8; 32],
    aad: [u8; 84],
    nonce: [u8; 12],
    ciphertext: [u8; 16],
) -> Result<(), AuthorityError> {
    let plaintext = aead::open(key, &aad, &nonce, &ciphertext)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if !plaintext.is_empty() {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}
