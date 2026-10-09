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
fn canonical(vault_id: VaultId, record: &ActionRecord, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(b"RKAS\0\x01");
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(record.action_id.as_bytes());
    out.extend_from_slice(&record.version.to_be_bytes());
    bytes(out, record.name.as_bytes());
    bytes(out, record.state.as_str().as_bytes());
    out.extend_from_slice(record.credential_id.as_bytes());
    bytes(out, record.origin.as_bytes());
    bytes(out, record.method.as_bytes());
    bytes(out, record.target_json.as_bytes());
    bytes(out, record.auth_header.as_bytes());
    bytes(out, record.auth_prefix.as_bytes());
    out.extend_from_slice(&record.request_max_bytes.to_be_bytes());
    bytes(out, record.allowed_extra_headers_json.as_bytes());
    out.extend_from_slice(&record.response_max_bytes.to_be_bytes());
    bytes(out, record.allowed_response_headers_json.as_bytes());
    out.extend_from_slice(&record.timeout_ms.to_be_bytes());
    out.extend_from_slice(&record.created_at_ms.to_be_bytes());
    optional(out, &record.native_plugin_json);
    optional(out, &record.text_stream_json);
}

fn aad(vault_id: VaultId, record: &ActionRecord) -> [u8; 84] {
    let mut raw = Vec::new();
    canonical(vault_id, record, &mut raw);
    AadV1 {
        purpose: AadPurpose::ActionState,
        vault_id,
        object_id: *record.action_id.as_bytes(),
        object_version: record.version,
        credential_kind: 0,
        constraints_hash: Sha256::digest(raw).into(),
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

// Complete membership and raw seals are bound to the authenticated generation.
const COLLECTION_DOMAIN: &[u8] = b"RKHTTPACTIONSET\0\x01";
pub(crate) fn empty_collection_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(COLLECTION_DOMAIN);
    hash.update(0u64.to_be_bytes());
    hash.finalize().into()
}
pub(crate) fn collection_digest(vault_id: VaultId, actions: &[ActionRecord]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(COLLECTION_DOMAIN);
    let mut ordered: Vec<_> = actions.iter().collect();
    ordered.sort_by_key(|r| (r.action_id, r.version));
    hash.update((ordered.len() as u64).to_be_bytes());
    let mut raw = Vec::new();
    for record in ordered {
        canonical(vault_id, record, &mut raw);
        hash.update((raw.len() as u64).to_be_bytes());
        hash.update(&raw);
        hash.update(record.seal_nonce);
        hash.update(record.seal_ciphertext);
    }
    hash.finalize().into()
}
