//! Authenticates the complete, ordered request ledger, including raw JSON text.
use super::{
    aad::{AadPurpose, AadV1},
    aead,
};
use crate::{
    error::AuthorityError,
    model::{UsageRecord, UsageState},
};
use aws_lc_rs::digest::{Context, SHA256};
use rekey_domain::ids::VaultId;
use sha2::{Digest, Sha256};

fn bytes(hash: &mut Context, value: &[u8]) {
    hash.update(&(value.len() as u64).to_be_bytes());
    hash.update(value);
}
fn optional(hash: &mut Context, value: Option<&[u8]>) {
    hash.update(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        bytes(hash, value);
    }
}
fn digest(rows: &[UsageRecord]) -> Result<[u8; 32], AuthorityError> {
    let mut hash = Context::new(&SHA256);
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
        hash.update(&row.utc_day.to_be_bytes());
        hash.update(&row.started_at_ms.to_be_bytes());
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
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.finish().as_ref());
    Ok(digest)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rekey_domain::ids::{PrincipalId, RequestId};

    // Frozen pre-optimization sha2 implementation, independent of AWS-LC helpers.
    fn original_bytes(hash: &mut Sha256, value: &[u8]) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    fn original_optional(hash: &mut Sha256, value: Option<&[u8]>) {
        hash.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            original_bytes(hash, value);
        }
    }
    fn original_digest(rows: &[UsageRecord]) -> Result<[u8; 32], AuthorityError> {
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
            original_bytes(&mut hash, row.instance_slug.as_bytes());
            hash.update(row.utc_day.to_be_bytes());
            hash.update(row.started_at_ms.to_be_bytes());
            original_bytes(&mut hash, row.context_json.as_bytes());
            original_optional(
                &mut hash,
                row.generation_max_output
                    .map(u64::to_be_bytes)
                    .as_ref()
                    .map(|v| v.as_slice()),
            );
            original_optional(
                &mut hash,
                row.output_tokens
                    .map(u64::to_be_bytes)
                    .as_ref()
                    .map(|v| v.as_slice()),
            );
            original_optional(&mut hash, row.source.as_deref().map(str::as_bytes));
            original_optional(&mut hash, row.terminal_json.as_deref().map(str::as_bytes));
            original_optional(
                &mut hash,
                row.settled_at_ms
                    .map(i64::to_be_bytes)
                    .as_ref()
                    .map(|v| v.as_slice()),
            );
        }
        Ok(hash.finalize().into())
    }
    fn fixtures() -> Vec<UsageRecord> {
        vec![
            UsageRecord {
                request_id: RequestId::from_bytes([1; 16]).unwrap(),
                principal_id: PrincipalId::from_bytes([11; 16]).unwrap(),
                instance_slug: "sample-模型".into(),
                utc_day: 3,
                started_at_ms: 3 * 86_400_000 + 100,
                context_json: r#"{"z":2, "a":1}"#.into(),
                generation_max_output: Some(20),
                output_tokens: Some(7),
                source: Some("measured".into()),
                terminal_json: Some(
                    r#"["execution.finished","success","fixture",200,5,null]"#.into(),
                ),
                settled_at_ms: Some(4 * 86_400_000 + 100),
            },
            UsageRecord {
                request_id: RequestId::from_bytes([2; 16]).unwrap(),
                principal_id: PrincipalId::from_bytes([12; 16]).unwrap(),
                instance_slug: "b".into(),
                utc_day: 0,
                started_at_ms: 1,
                context_json: " {\n\"raw\":\"\\u0061\"} ".into(),
                generation_max_output: None,
                output_tokens: None,
                source: None,
                terminal_json: None,
                settled_at_ms: None,
            },
        ]
    }
    fn hex(value: [u8; 32]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    #[test]
    fn canonical_digest_matches_frozen_vectors_and_original_sha2() {
        assert_eq!(
            hex(digest(&[]).unwrap()),
            "bf71fd27870fd43770a6ad17dff3b07715cc4af9b0d6483a0a230ac67ef3b81a"
        );
        let rows = fixtures();
        assert_eq!(
            hex(digest(&rows).unwrap()),
            "792969e9a9a4b249c23549e53688dd8d68d0b38846b85fdce9278622ec12f266"
        );
        assert_eq!(digest(&rows).unwrap(), original_digest(&rows).unwrap());
    }
    #[test]
    fn randomized_ordered_rows_match_original_sha2_with_optional_and_raw_json() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(25);
        let raw = [
            r#"{"raw":"a"}"#,
            r#" {"raw":"\u0061"} "#,
            "{\n\"raw\":\"模型\"\n}",
            "",
            "null",
        ];
        for _ in 0..128 {
            let mut rows: Vec<_> = (1..=rng.random_range(0..=64u64))
                .map(|n| {
                    let mut id: [u8; 16] = rng.random();
                    id[8..].copy_from_slice(&n.to_be_bytes());
                    UsageRecord {
                        request_id: RequestId::from_bytes(id).unwrap(),
                        principal_id: PrincipalId::from_bytes([17; 16]).unwrap(),
                        instance_slug: format!("model-{}", rng.random::<u64>()),
                        utc_day: rng.random(),
                        started_at_ms: rng.random(),
                        context_json: raw[rng.random_range(0..raw.len())].into(),
                        generation_max_output: rng.random::<bool>().then(|| rng.random()),
                        output_tokens: rng.random::<bool>().then(|| rng.random()),
                        source: rng
                            .random::<bool>()
                            .then(|| raw[rng.random_range(0..raw.len())].into()),
                        terminal_json: rng
                            .random::<bool>()
                            .then(|| raw[rng.random_range(0..raw.len())].into()),
                        settled_at_ms: rng.random::<bool>().then(|| rng.random()),
                    }
                })
                .collect();
            rows.sort_by_key(|row| *row.request_id.as_bytes());
            assert_eq!(digest(&rows).unwrap(), original_digest(&rows).unwrap());
            let vault = VaultId::from_bytes([29; 16]).unwrap();
            let state = seal(&[31; 32], vault, &rows, 7).unwrap();
            assert_eq!(state.records_digest, original_digest(&rows).unwrap());
            verify(&[31; 32], vault, &rows, &state).unwrap();
            assert!(
                aead::open(
                    &[31; 32],
                    &aad(vault, &state),
                    &state.seal_nonce,
                    &state.seal_ciphertext
                )
                .unwrap()
                .is_empty()
            );
        }
    }
    #[test]
    fn old_seal_still_verifies_and_history_or_state_tampering_is_rejected() {
        let rows = fixtures();
        let key = [31; 32];
        let vault = VaultId::from_bytes([29; 16]).unwrap();
        // State assembled by the original digest and unchanged AAD/AEAD format.
        let mut state = UsageState {
            revision: 7,
            record_count: rows.len() as u64,
            records_digest: original_digest(&rows).unwrap(),
            seal_nonce: [0; 12],
            seal_ciphertext: [0; 16],
        };
        let sealed = aead::seal(&key, &aad(vault, &state), &[]).unwrap();
        state.seal_nonce = sealed.nonce;
        state.seal_ciphertext = sealed.ciphertext.try_into().unwrap();
        verify(&key, vault, &rows, &state).unwrap();
        let mut attacks = Vec::new();
        let mut changed = rows.clone();
        changed.pop();
        attacks.push(changed);
        let mut changed = rows.clone();
        changed.reverse();
        attacks.push(changed);
        let mut changed = rows.clone();
        changed.push(changed[1].clone());
        attacks.push(changed);
        let mut changed = rows.clone();
        changed[0].context_json = r#"{"a":1,"z":2}"#.into();
        attacks.push(changed);
        let mut changed = rows.clone();
        changed[0].terminal_json.as_mut().unwrap().push(' ');
        attacks.push(changed);
        let mut changed = rows.clone();
        changed[1].source = Some(String::new());
        attacks.push(changed);
        for changed in attacks {
            assert!(matches!(
                verify(&key, vault, &changed, &state),
                Err(AuthorityError::StorageIntegrityFailed)
            ));
        }
        for field in 0..5 {
            let mut changed = state.clone();
            match field {
                0 => changed.revision += 1,
                1 => changed.record_count += 1,
                2 => changed.records_digest[0] ^= 1,
                3 => changed.seal_nonce[0] ^= 1,
                _ => changed.seal_ciphertext[0] ^= 1,
            }
            assert!(matches!(
                verify(&key, vault, &rows, &changed),
                Err(AuthorityError::StorageIntegrityFailed)
            ));
        }
        assert!(matches!(
            seal(&key, vault, &rows, i64::MAX as u64 + 1),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }
}
