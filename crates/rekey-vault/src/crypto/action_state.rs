//! Authentication of the complete persisted Action row, before normalization.
use rekey_domain::ids::VaultId;
use sha2::{Digest, Sha256};

use super::aad::{AadPurpose, AadV1};
use super::aead;
use crate::error::AuthorityError;
use crate::model::ActionRecord;

pub struct ActionSeal {
    pub nonce: [u8; 12],
    pub ciphertext: [u8; 16],
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn optional(out: &mut Vec<u8>, value: &Option<String>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes(out, value.as_bytes());
    }
}

// Raw stored strings are authenticated verbatim: parsing/normalization must not
// discard unknown JSON fields, duplicate keys, whitespace or lifecycle state.
// Only the nonce and seal itself are omitted. Lengths and integers are big endian.
fn canonical(vault_id: VaultId, record: &ActionRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"RKAS\0\x01");
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(record.action_id.as_bytes());
    out.extend_from_slice(&record.version.to_be_bytes());
    bytes(&mut out, record.name.as_bytes());
    bytes(&mut out, record.state.as_str().as_bytes());
    out.extend_from_slice(record.credential_id.as_bytes());
    bytes(&mut out, record.origin.as_bytes());
    bytes(&mut out, record.method.as_bytes());
    bytes(&mut out, record.target_json.as_bytes());
    bytes(&mut out, record.auth_header.as_bytes());
    bytes(&mut out, record.auth_prefix.as_bytes());
    out.extend_from_slice(&record.request_max_bytes.to_be_bytes());
    bytes(&mut out, record.allowed_extra_headers_json.as_bytes());
    out.extend_from_slice(&record.response_max_bytes.to_be_bytes());
    bytes(&mut out, record.allowed_response_headers_json.as_bytes());
    out.extend_from_slice(&record.timeout_ms.to_be_bytes());
    out.extend_from_slice(&record.created_at_ms.to_be_bytes());
    optional(&mut out, &record.native_plugin_json);
    optional(&mut out, &record.text_stream_json);
    out
}

fn aad(vault_id: VaultId, record: &ActionRecord) -> [u8; 84] {
    AadV1 {
        purpose: AadPurpose::ActionState,
        vault_id,
        object_id: *record.action_id.as_bytes(),
        object_version: record.version,
        credential_kind: 0,
        constraints_hash: Sha256::digest(canonical(vault_id, record)).into(),
    }
    .encode()
}

pub fn seal(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &ActionRecord,
) -> Result<ActionSeal, AuthorityError> {
    let sealed = aead::seal(key, &aad(vault_id, record), &[])?;
    Ok(ActionSeal {
        nonce: sealed.nonce,
        ciphertext: sealed
            .ciphertext
            .try_into()
            .map_err(|_| AuthorityError::CryptoFailure)?,
    })
}

pub fn verify(
    key: &[u8; 32],
    vault_id: VaultId,
    record: &ActionRecord,
) -> Result<(), AuthorityError> {
    let plain = aead::open(
        key,
        &aad(vault_id, record),
        &record.seal_nonce,
        &record.seal_ciphertext,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if !plain.is_empty() {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}
