//! Authenticates the complete, ordered request ledger, including raw JSON text.
use super::{
    aad::{AadPurpose, AadV1},
    aead,
};
use crate::{
    error::AuthorityError,
    model::{UsageRecord, UsageState},
};
use rekey_domain::ids::VaultId;
use sha2::{Digest, Sha256};

fn bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}
fn optional(hash: &mut Sha256, value: Option<&[u8]>) {
    hash.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        bytes(hash, value);
    }
}
fn digest(rows: &[UsageRecord]) -> Result<[u8; 32], AuthorityError> {
    let mut hash = Sha256::new();
    hash.update(b"RKUSAGE\0\x01");
    let mut previous = None;
    for row in rows {
        let id = row.request_id.as_bytes();
        if previous.is_some_and(|prior| prior >= id) {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        previous = Some(id);
        hash.update(id);
        hash.update(row.principal_id.as_bytes());
        bytes(&mut hash, row.instance_slug.as_bytes());
        hash.update(row.utc_day.to_be_bytes());
        hash.update(row.started_at_ms.to_be_bytes());
        bytes(&mut hash, row.context_json.as_bytes());
        optional(
            &mut hash,
            row.generation_max_output
                .map(u64::to_be_bytes)
                .as_ref()
                .map(|v| v.as_slice()),
        );
        optional(
            &mut hash,
            row.output_tokens
                .map(u64::to_be_bytes)
                .as_ref()
                .map(|v| v.as_slice()),
        );
        optional(&mut hash, row.source.as_deref().map(str::as_bytes));
        optional(&mut hash, row.terminal_json.as_deref().map(str::as_bytes));
        optional(
            &mut hash,
            row.settled_at_ms
                .map(i64::to_be_bytes)
                .as_ref()
                .map(|v| v.as_slice()),
        );
    }
    Ok(hash.finalize().into())
}
fn aad(vault: VaultId, state: &UsageState) -> [u8; 84] {
    let mut hash = Sha256::new();
    hash.update(b"RKUSAGESTATE\0\x01");
    hash.update(state.record_count.to_be_bytes());
    hash.update(state.records_digest);
    AadV1 {
        purpose: AadPurpose::ProfileUsage,
        vault_id: vault,
        object_id: [0; 16],
        object_version: state.revision,
        credential_kind: 0,
        constraints_hash: hash.finalize().into(),
    }
    .encode()
}
pub(crate) fn seal(
    key: &[u8; 32],
    vault: VaultId,
    rows: &[UsageRecord],
    revision: u64,
) -> Result<UsageState, AuthorityError> {
    if revision > i64::MAX as u64 {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    let mut state = UsageState {
        revision,
        record_count: rows.len() as u64,
        records_digest: digest(rows)?,
        seal_nonce: [0; 12],
        seal_ciphertext: [0; 16],
    };
    let sealed = aead::seal(key, &aad(vault, &state), &[])?;
    state.seal_nonce = sealed.nonce;
    state.seal_ciphertext = sealed
        .ciphertext
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)?;
    Ok(state)
}
pub(crate) fn verify(
    key: &[u8; 32],
    vault: VaultId,
    rows: &[UsageRecord],
    state: &UsageState,
) -> Result<(), AuthorityError> {
    if state.record_count != rows.len() as u64 || state.records_digest != digest(rows)? {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    let bytes = aead::open(
        key,
        &aad(vault, state),
        &state.seal_nonce,
        &state.seal_ciphertext,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if !bytes.is_empty() {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}
