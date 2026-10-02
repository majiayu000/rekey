//! Concrete lease envelopes and authenticated-set seal. No credential token/value.
use super::{
    AAD_VERSION_V1, CRYPTO_SUITE_V1,
    aad::{AadPurpose, AadV1},
    aead,
    keys::DataKey,
};
use crate::{
    error::AuthorityError,
    model::{
        LeaseCleanupOutcome, LeaseJournalRecord, LeaseJournalState, LeasePhase, LeaseSourceRef,
    },
};
use rekey_domain::{credential::CredentialKind, ids::VaultId};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn bad<T>() -> Result<T, AuthorityError> {
    Err(AuthorityError::StorageIntegrityFailed)
}
fn field(out: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthorityError> {
    let len = u16::try_from(value.len()).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub fn validate_source(source: &LeaseSourceRef) -> Result<(), AuthorityError> {
    if source.origin.as_str().len() > 2048
        || [&source.mount, &source.role].iter().any(|value| {
            value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
    {
        return bad();
    }
    Ok(())
}
pub fn source_hash(source: &LeaseSourceRef) -> Result<[u8; 32], AuthorityError> {
    validate_source(source)?;
    let mut bytes = b"RKVSRC\0\x01".to_vec();
    for part in [source.origin.as_str(), &source.mount, &source.role] {
        field(&mut bytes, part.as_bytes())?;
    }
    Ok(Sha256::digest(bytes).into())
}
fn identity(r: &LeaseJournalRecord) -> Vec<u8> {
    let c = &r.context;
    let mut out = b"RKJLID\0\x01".to_vec();
    for id in [
        c.request_id.as_bytes(),
        c.session_id.as_bytes(),
        c.action_id.as_bytes(),
    ] {
        out.extend_from_slice(id);
    }
    out.extend_from_slice(&c.action_version.to_be_bytes());
    out.extend_from_slice(c.credential_id.as_bytes());
    out.extend_from_slice(&c.credential_version.to_be_bytes());
    out.extend_from_slice(&r.source_ref_hash);
    out
}
fn optional(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_be_bytes());
        }
        None => out.push(0),
    }
}
pub(crate) fn metadata(r: &LeaseJournalRecord) -> Result<Vec<u8>, AuthorityError> {
    if r.revision == 0
        || r.revision > i64::MAX as u64
        || r.context.action_version == 0
        || r.context.credential_version == 0
        || r.context.action_version > i64::MAX as u64
        || r.context.credential_version > i64::MAX as u64
        || r.created_at_ms < 0
        || r.updated_at_ms < r.created_at_ms
        || r.aad_version != AAD_VERSION_V1
        || r.crypto_suite != CRYPTO_SUITE_V1
    {
        return bad();
    }
    let issued = r.issued_at_ms.is_some();
    if issued != r.last_confirmed_expires_at_ms.is_some()
        || issued != r.renewable.is_some()
        || r.issued_at_ms
            .is_some_and(|v| v < r.created_at_ms || v > r.updated_at_ms)
        || r.last_confirmed_expires_at_ms
            .zip(r.issued_at_ms)
            .is_some_and(|(e, i)| e <= i)
        || (r.phase == LeasePhase::Complete) != r.completed_at_ms.is_some()
        || r.completed_at_ms.is_some_and(|v| v != r.updated_at_ms)
        || (r.phase == LeasePhase::AcquireIntent && issued)
        || (matches!(
            r.phase,
            LeasePhase::Issued | LeasePhase::Renewing | LeasePhase::CleanupStarted
        ) && !issued)
        || (r.phase == LeasePhase::Complete
            && ((issued && r.cleanup_outcome != LeaseCleanupOutcome::Confirmed)
                || (!issued && r.cleanup_outcome != LeaseCleanupOutcome::None)))
        || (r.phase != LeasePhase::Complete && r.cleanup_outcome == LeaseCleanupOutcome::Confirmed)
    {
        return bad();
    }
    let mut out = b"RKJLROW\0\x01".to_vec();
    out.extend_from_slice(r.registration_id.as_bytes());
    out.extend_from_slice(&identity(r));
    out.extend_from_slice(&r.revision.to_be_bytes());
    out.push(r.phase.code());
    out.extend_from_slice(&r.created_at_ms.to_be_bytes());
    out.extend_from_slice(&r.updated_at_ms.to_be_bytes());
    optional(&mut out, r.issued_at_ms);
    optional(&mut out, r.last_confirmed_expires_at_ms);
    out.push(match r.renewable {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
    out.push(r.cleanup_outcome.code());
    optional(&mut out, r.completed_at_ms);
    out.extend_from_slice(&r.last_audit_event_id);
    Ok(out)
}
fn aad(vault: VaultId, r: &LeaseJournalRecord, wrap: bool) -> Result<[u8; 84], AuthorityError> {
    Ok(AadV1 {
        purpose: if wrap {
            AadPurpose::LeaseJournalWrapDek
        } else {
            AadPurpose::LeaseJournalPayload
        },
        vault_id: vault,
        object_id: *r.registration_id.as_bytes(),
        object_version: if wrap { 1 } else { r.revision },
        credential_kind: CredentialKind::VaultDynamicSource.aad_code(),
        constraints_hash: Sha256::digest(if wrap { identity(r) } else { metadata(r)? }).into(),
    }
    .encode())
}
pub(crate) struct LeasePayload {
    pub source: LeaseSourceRef,
    pub lease_id: Option<Zeroizing<Vec<u8>>>,
}
fn encode(payload: &LeasePayload) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
    validate_source(&payload.source)?;
    let mut out = Zeroizing::new(b"RKJLP\0\x01".to_vec());
    for part in [
        payload.source.origin.as_str(),
        &payload.source.mount,
        &payload.source.role,
    ] {
        field(&mut out, part.as_bytes())?;
    }
    match &payload.lease_id {
        None => out.push(0),
        Some(id) => {
            if id.is_empty() || id.len() > 1024 || !id.iter().all(|b| (33..=126).contains(b)) {
                return bad();
            }
            out.push(1);
            field(&mut out, id)?;
        }
    }
    Ok(out)
}
fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], AuthorityError> {
    if input.len() < len {
        return bad();
    }
    let (v, rest) = input.split_at(len);
    *input = rest;
    Ok(v)
}
fn part<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], AuthorityError> {
    let len = u16::from_be_bytes(
        take(input, 2)?
            .try_into()
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
    ) as usize;
    take(input, len)
}
fn decode(bytes: &[u8]) -> Result<LeasePayload, AuthorityError> {
    let mut input = bytes;
    if take(&mut input, 7)? != b"RKJLP\0\x01" {
        return bad();
    }
    let origin = std::str::from_utf8(part(&mut input)?)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let origin = rekey_domain::action::HttpsOrigin::parse(origin)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let mount = std::str::from_utf8(part(&mut input)?)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?
        .to_owned();
    let role = std::str::from_utf8(part(&mut input)?)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?
        .to_owned();
    let lease_id = match take(&mut input, 1)?[0] {
        0 => None,
        1 => Some(Zeroizing::new(part(&mut input)?.to_vec())),
        _ => return bad(),
    };
    if !input.is_empty() {
        return bad();
    }
    let payload = LeasePayload {
        source: LeaseSourceRef {
            origin,
            mount,
            role,
        },
        lease_id,
    };
    encode(&payload)?;
    Ok(payload)
}
fn dek(root: &[u8; 32], vault: VaultId, r: &LeaseJournalRecord) -> Result<DataKey, AuthorityError> {
    let bytes = aead::open(root, &aad(vault, r, true)?, &r.dek_nonce, &r.wrapped_dek)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let mut array = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let key = DataKey::from_bytes(&mut array);
    drop(bytes);
    Ok(key)
}
pub(crate) fn open(
    root: &[u8; 32],
    vault: VaultId,
    r: &LeaseJournalRecord,
) -> Result<LeasePayload, AuthorityError> {
    let key = dek(root, vault, r)?;
    let bytes = aead::open(
        key.bytes(),
        &aad(vault, r, false)?,
        &r.payload_nonce,
        &r.encrypted_payload,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let payload = decode(&bytes)?;
    if source_hash(&payload.source)? != r.source_ref_hash
        || payload.lease_id.is_some()
            != matches!(
                r.phase,
                LeasePhase::Issued | LeasePhase::Renewing | LeasePhase::CleanupStarted
            )
    {
        return bad();
    }
    Ok(payload)
}
pub(crate) fn seal_new(
    root: &[u8; 32],
    vault: VaultId,
    r: &mut LeaseJournalRecord,
    payload: &LeasePayload,
) -> Result<(), AuthorityError> {
    let key = DataKey::generate()?;
    let wrapped = aead::seal(root, &aad(vault, r, true)?, key.bytes())?;
    let encrypted = aead::seal(key.bytes(), &aad(vault, r, false)?, &encode(payload)?)?;
    r.dek_nonce = wrapped.nonce;
    r.wrapped_dek = wrapped.ciphertext;
    r.payload_nonce = encrypted.nonce;
    r.encrypted_payload = encrypted.ciphertext;
    Ok(())
}
pub(crate) fn update(
    root: &[u8; 32],
    vault: VaultId,
    old: &LeaseJournalRecord,
    new: &mut LeaseJournalRecord,
    payload: &LeasePayload,
) -> Result<(), AuthorityError> {
    if identity(old) != identity(new) || old.registration_id != new.registration_id {
        return bad();
    }
    let key = dek(root, vault, old)?;
    let encrypted = aead::seal(key.bytes(), &aad(vault, new, false)?, &encode(payload)?)?;
    new.payload_nonce = encrypted.nonce;
    new.encrypted_payload = encrypted.ciphertext;
    Ok(())
}
pub(crate) fn set_digest(records: &[LeaseJournalRecord]) -> Result<[u8; 32], AuthorityError> {
    let mut ordered: Vec<_> = records.iter().collect();
    ordered.sort_by_key(|r| *r.registration_id.as_bytes());
    let mut h = Sha256::new();
    h.update(b"RKJLSET\0\x01");
    for r in ordered {
        h.update(metadata(r)?);
        h.update(r.aad_version.to_be_bytes());
        h.update((r.crypto_suite.len() as u16).to_be_bytes());
        h.update(r.crypto_suite.as_bytes());
        h.update(r.dek_nonce);
        h.update((r.wrapped_dek.len() as u64).to_be_bytes());
        h.update(&r.wrapped_dek);
        h.update(r.payload_nonce);
        h.update((r.encrypted_payload.len() as u64).to_be_bytes());
        h.update(&r.encrypted_payload);
    }
    Ok(h.finalize().into())
}
fn state_aad(vault: VaultId, state: &LeaseJournalState) -> [u8; 84] {
    let mut h = Sha256::new();
    h.update(b"RKJLSTATE\0\x01");
    h.update(state.record_count.to_be_bytes());
    h.update(state.records_digest);
    match state.last_audit_event_id {
        None => h.update([0]),
        Some(id) => {
            h.update([1]);
            h.update(id);
        }
    }
    AadV1 {
        purpose: AadPurpose::LeaseJournalState,
        vault_id: vault,
        object_id: [0; 16],
        object_version: state.revision,
        credential_kind: 0,
        constraints_hash: h.finalize().into(),
    }
    .encode()
}
pub(crate) fn seal_state(
    root: &[u8; 32],
    vault: VaultId,
    records: &[LeaseJournalRecord],
    revision: u64,
    last_audit_event_id: Option<[u8; 16]>,
) -> Result<LeaseJournalState, AuthorityError> {
    let mut state = LeaseJournalState {
        last_audit_event_id,
        revision,
        record_count: records.len() as u64,
        records_digest: set_digest(records)?,
        seal_nonce: [0; 12],
        seal_ciphertext: [0; 16],
    };
    let sealed = aead::seal(root, &state_aad(vault, &state), &[])?;
    state.seal_nonce = sealed.nonce;
    state.seal_ciphertext = sealed
        .ciphertext
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)?;
    Ok(state)
}
pub(crate) fn verify_state(
    root: &[u8; 32],
    vault: VaultId,
    records: &[LeaseJournalRecord],
    state: &LeaseJournalState,
) -> Result<(), AuthorityError> {
    if state.record_count != records.len() as u64 || state.records_digest != set_digest(records)? {
        return bad();
    }
    let bytes = aead::open(
        root,
        &state_aad(vault, state),
        &state.seal_nonce,
        &state.seal_ciphertext,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    if !bytes.is_empty() {
        return bad();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LeaseExecutionContext;
    use rekey_domain::ids::{ActionId, CredentialId, LeaseRegistrationId, RequestId, SessionId};
    fn fixture() -> (VaultId, LeaseJournalRecord, LeasePayload) {
        let source = LeaseSourceRef {
            origin: rekey_domain::action::HttpsOrigin::parse("https://vault.example.com").unwrap(),
            mount: "database".into(),
            role: "role".into(),
        };
        let row = LeaseJournalRecord {
            registration_id: LeaseRegistrationId::new_random(),
            context: LeaseExecutionContext {
                request_id: RequestId::new_random(),
                session_id: SessionId::new_random(),
                action_id: ActionId::new_random(),
                action_version: 1,
                credential_id: CredentialId::new_random(),
                credential_version: 1,
            },
            source_ref_hash: source_hash(&source).unwrap(),
            revision: 1,
            phase: LeasePhase::Issued,
            created_at_ms: 1000,
            updated_at_ms: 2000,
            issued_at_ms: Some(1500),
            last_confirmed_expires_at_ms: Some(61500),
            renewable: Some(true),
            cleanup_outcome: LeaseCleanupOutcome::None,
            completed_at_ms: None,
            last_audit_event_id: [3; 16],
            aad_version: AAD_VERSION_V1,
            crypto_suite: CRYPTO_SUITE_V1.into(),
            dek_nonce: [0; 12],
            wrapped_dek: vec![],
            payload_nonce: [0; 12],
            encrypted_payload: vec![],
        };
        (
            VaultId::new_random(),
            row,
            LeasePayload {
                source,
                lease_id: Some(Zeroizing::new(b"database/role/PRIVATE-LEASE-ID".to_vec())),
            },
        )
    }
    #[test]
    fn journal_authenticates_every_identity_metadata_and_ciphertext() {
        let (vault, mut row, payload) = fixture();
        seal_new(&[1; 32], vault, &mut row, &payload).unwrap();
        assert_eq!(
            open(&[1; 32], vault, &row)
                .unwrap()
                .lease_id
                .unwrap()
                .as_slice(),
            b"database/role/PRIVATE-LEASE-ID"
        );
        assert!(open(&[1; 32], VaultId::new_random(), &row).is_err());
        let mut variants = Vec::new();
        macro_rules! variant {
            ($field:ident,$value:expr) => {{
                let mut v = row.clone();
                v.$field = $value;
                variants.push(v);
            }};
        }
        variant!(registration_id, LeaseRegistrationId::new_random());
        variant!(source_ref_hash, [4; 32]);
        variant!(revision, 2);
        variant!(phase, LeasePhase::Renewing);
        variant!(created_at_ms, 999);
        variant!(updated_at_ms, 2001);
        variant!(issued_at_ms, Some(1501));
        variant!(last_confirmed_expires_at_ms, Some(61501));
        variant!(renewable, Some(false));
        variant!(cleanup_outcome, LeaseCleanupOutcome::Unconfirmed);
        variant!(last_audit_event_id, [5; 16]);
        variant!(aad_version, 2);
        variant!(crypto_suite, "wrong".into());
        variant!(dek_nonce, [1; 12]);
        variant!(wrapped_dek, vec![0; 48]);
        variant!(payload_nonce, [2; 12]);
        variant!(encrypted_payload, vec![0; 40]);
        for which in 0..6 {
            let mut v = row.clone();
            match which {
                0 => v.context.request_id = RequestId::new_random(),
                1 => v.context.session_id = SessionId::new_random(),
                2 => v.context.action_id = ActionId::new_random(),
                3 => v.context.action_version += 1,
                4 => v.context.credential_id = CredentialId::new_random(),
                _ => v.context.credential_version += 1,
            };
            variants.push(v);
        }
        for variant in variants {
            assert!(open(&[1; 32], vault, &variant).is_err());
        }
    }
    #[test]
    fn manifest_rejects_deleted_added_swapped_rows_and_other_vault_or_root() {
        let (vault, mut row, payload) = fixture();
        seal_new(&[1; 32], vault, &mut row, &payload).unwrap();
        let state = seal_state(
            &[1; 32],
            vault,
            &[row.clone()],
            1,
            Some(row.last_audit_event_id),
        )
        .unwrap();
        verify_state(&[1; 32], vault, &[row.clone()], &state).unwrap();
        assert!(verify_state(&[1; 32], vault, &[], &state).is_err());
        let (_, mut another, another_payload) = fixture();
        seal_new(&[1; 32], vault, &mut another, &another_payload).unwrap();
        assert!(verify_state(&[1; 32], vault, &[another.clone()], &state).is_err());
        assert!(verify_state(&[1; 32], vault, &[row.clone(), another], &state).is_err());
        assert!(verify_state(&[1; 32], VaultId::new_random(), &[row.clone()], &state).is_err());
        assert!(verify_state(&[2; 32], vault, &[row.clone()], &state).is_err());
        let mut changed = state.clone();
        changed.revision += 1;
        assert!(verify_state(&[1; 32], vault, &[row.clone()], &changed).is_err());
        let mut changed_anchor = state.clone();
        changed_anchor.last_audit_event_id = Some([9; 16]);
        assert!(verify_state(&[1; 32], vault, &[row.clone()], &changed_anchor).is_err());
        changed_anchor.last_audit_event_id = None;
        assert!(verify_state(&[1; 32], vault, &[row.clone()], &changed_anchor).is_err());
        let empty = seal_state(&[1; 32], vault, &[], 0, None).unwrap();
        verify_state(&[1; 32], vault, &[], &empty).unwrap();
    }
    #[test]
    fn complete_clears_active_id_and_independent_deks_rotate() {
        let (vault, mut row, mut payload) = fixture();
        seal_new(&[1; 32], vault, &mut row, &payload).unwrap();
        let mut fresh = row.clone();
        seal_new(&[1; 32], vault, &mut fresh, &payload).unwrap();
        assert_ne!(fresh.wrapped_dek, row.wrapped_dek);
        assert_ne!(fresh.encrypted_payload, row.encrypted_payload);
        let mut complete = row.clone();
        complete.revision += 1;
        complete.phase = LeasePhase::Complete;
        complete.cleanup_outcome = LeaseCleanupOutcome::Confirmed;
        complete.updated_at_ms = 3000;
        complete.completed_at_ms = Some(3000);
        payload.lease_id = None;
        update(&[1; 32], vault, &row, &mut complete, &payload).unwrap();
        assert!(open(&[1; 32], vault, &complete).unwrap().lease_id.is_none());
        seal_new(&[2; 32], vault, &mut complete, &payload).unwrap();
        assert!(open(&[1; 32], vault, &complete).is_err());
        open(&[2; 32], vault, &complete).unwrap();
    }
}
