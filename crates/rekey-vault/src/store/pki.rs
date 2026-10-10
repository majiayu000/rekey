//! Public certificate reservations, authenticated by the header generation MAC.
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::{
    SqliteRecordStore,
    generation::{GenerationAttempt, commit_generation},
    sqlite::{blob16, blob32, storage},
};
use crate::{
    AuthorityError,
    model::{
        AuditEvent, PkiCertificateRecord, PkiCertificateState, PkiCrlRecord, VaultHeaderRecord,
    },
};
use rekey_domain::ids::{CredentialId, RequestId};

fn integrity() -> AuthorityError {
    AuthorityError::StorageIntegrityFailed
}

fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

pub(crate) fn digest(records: &[PkiCertificateRecord], crls: &[PkiCrlRecord]) -> [u8; 32] {
    let mut ordered: Vec<_> = records.iter().collect();
    ordered.sort_by_key(|r| r.serial);
    let mut hash = Sha256::new();
    hash.update(b"RKPKISET\0\x03");
    hash.update((ordered.len() as u64).to_be_bytes());
    for r in ordered {
        hash.update(r.serial);
        hash.update(r.credential_id.as_bytes());
        hash.update(r.credential_version.to_be_bytes());
        hash.update(r.request_id.as_bytes());
        hash.update(r.request_digest);
        hash.update(r.created_at_ms.to_be_bytes());
        hash.update([r.state as u8]);
        for time in [r.finished_at_ms, r.revoked_at_ms] {
            match time {
                Some(t) => {
                    hash.update([1]);
                    hash.update(t.to_be_bytes());
                }
                None => hash.update([0]),
            }
        }
        for value in [&r.certificate_der, &r.issuer_der] {
            match value {
                Some(v) => {
                    hash.update([1]);
                    field(&mut hash, v);
                }
                None => hash.update([0]),
            }
        }
    }
    let mut ordered: Vec<_> = crls.iter().collect();
    ordered.sort_by_key(|r| r.number);
    hash.update((ordered.len() as u64).to_be_bytes());
    for r in ordered {
        hash.update(r.number.to_be_bytes());
        hash.update(r.credential_id.as_bytes());
        hash.update(r.credential_version.to_be_bytes());
        hash.update(r.request_id.as_bytes());
        hash.update(r.snapshot_digest);
        hash.update(r.created_at_ms.to_be_bytes());
        hash.update([r.state as u8]);
        match r.finished_at_ms {
            Some(t) => {
                hash.update([1]);
                hash.update(t.to_be_bytes());
            }
            None => hash.update([0]),
        }
        for value in [&r.crl_der, &r.issuer_der] {
            match value {
                Some(v) => {
                    hash.update([1]);
                    field(&mut hash, v);
                }
                None => hash.update([0]),
            }
        }
    }
    hash.finalize().into()
}

pub(crate) fn empty_digest() -> [u8; 32] {
    combined_digest(
        digest(&[], &[]),
        crate::crypto::action_state::empty_collection_digest(),
    )
}

fn records(conn: &Connection) -> Result<Vec<PkiCertificateRecord>, AuthorityError> {
    let mut stmt = conn.prepare("SELECT serial,credential_id,credential_version,request_id,request_digest,created_at_ms,state,finished_at_ms,certificate_der,issuer_der,revoked_at_ms FROM pki_certificates ORDER BY serial").map_err(storage)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((|| {
                let state = match r.get::<_, i64>(6).map_err(|_| integrity())? {
                    0 => PkiCertificateState::Reserved,
                    1 => PkiCertificateState::Issued,
                    2 => PkiCertificateState::Failed,
                    _ => return Err(integrity()),
                };
                let row = PkiCertificateRecord {
                    serial: blob16(r.get(0).map_err(|_| integrity())?)?,
                    credential_id: CredentialId::from_bytes(blob16(
                        r.get(1).map_err(|_| integrity())?,
                    )?)
                    .map_err(|_| integrity())?,
                    credential_version: r.get(2).map_err(|_| integrity())?,
                    request_id: RequestId::from_bytes(blob16(r.get(3).map_err(|_| integrity())?)?)
                        .map_err(|_| integrity())?,
                    request_digest: blob32(r.get(4).map_err(|_| integrity())?)?,
                    created_at_ms: r.get(5).map_err(|_| integrity())?,
                    state,
                    finished_at_ms: r.get(7).map_err(|_| integrity())?,
                    certificate_der: r.get(8).map_err(|_| integrity())?,
                    issuer_der: r.get(9).map_err(|_| integrity())?,
                    revoked_at_ms: r.get(10).map_err(|_| integrity())?,
                };
                if row.serial == [0; 16]
                    || row.serial[0] & 0x80 != 0
                    || row.credential_version == 0
                    || row.created_at_ms < 0
                    || row.finished_at_ms.is_some_and(|t| t < 0)
                    || row
                        .revoked_at_ms
                        .is_some_and(|t| t < 0 || row.state != PkiCertificateState::Issued)
                    || (row.state == PkiCertificateState::Reserved) != row.finished_at_ms.is_none()
                    || (row.state == PkiCertificateState::Issued)
                        != (row.certificate_der.is_some() && row.issuer_der.is_some())
                    || (row.state != PkiCertificateState::Issued
                        && (row.certificate_der.is_some() || row.issuer_der.is_some()))
                    || [&row.certificate_der, &row.issuer_der]
                        .iter()
                        .any(|v| v.as_ref().is_some_and(|b| b.is_empty() || b.len() > 65536))
                {
                    return Err(integrity());
                }
                Ok(row)
            })())
        })
        .map_err(storage)?;
    rows.map(|r| r.map_err(storage)?).collect()
}

fn crl_records(conn: &Connection) -> Result<Vec<PkiCrlRecord>, AuthorityError> {
    let mut stmt = conn.prepare("SELECT number,credential_id,credential_version,request_id,snapshot_digest,created_at_ms,state,finished_at_ms,crl_der,issuer_der FROM pki_crls ORDER BY number").map_err(storage)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((|| {
                let number: Vec<u8> = r.get(0).map_err(|_| integrity())?;
                let state = match r.get::<_, u8>(6).map_err(|_| integrity())? {
                    0 => PkiCertificateState::Reserved,
                    1 => PkiCertificateState::Issued,
                    2 => PkiCertificateState::Failed,
                    _ => return Err(integrity()),
                };
                let row = PkiCrlRecord {
                    number: u64::from_be_bytes(number.try_into().map_err(|_| integrity())?),
                    credential_id: CredentialId::from_bytes(blob16(
                        r.get(1).map_err(|_| integrity())?,
                    )?)
                    .map_err(|_| integrity())?,
                    credential_version: r.get(2).map_err(|_| integrity())?,
                    request_id: RequestId::from_bytes(blob16(r.get(3).map_err(|_| integrity())?)?)
                        .map_err(|_| integrity())?,
                    snapshot_digest: blob32(r.get(4).map_err(|_| integrity())?)?,
                    created_at_ms: r.get(5).map_err(|_| integrity())?,
                    state,
                    finished_at_ms: r.get(7).map_err(|_| integrity())?,
                    crl_der: r.get(8).map_err(|_| integrity())?,
                    issuer_der: r.get(9).map_err(|_| integrity())?,
                };
                if row.number == 0
                    || row.credential_version == 0
                    || row.created_at_ms < 0
                    || row.finished_at_ms.is_some_and(|t| t < 0)
                    || (row.state == PkiCertificateState::Reserved) != row.finished_at_ms.is_none()
                    || (row.state == PkiCertificateState::Issued)
                        != (row.crl_der.is_some() && row.issuer_der.is_some())
                    || (row.state != PkiCertificateState::Issued
                        && (row.crl_der.is_some() || row.issuer_der.is_some()))
                    || row.crl_der.as_ref().is_some_and(Vec::is_empty)
                    || row
                        .issuer_der
                        .as_ref()
                        .is_some_and(|b| b.is_empty() || b.len() > 65536)
                {
                    return Err(integrity());
                }
                Ok(row)
            })())
        })
        .map_err(storage)?;
    rows.map(|r| r.map_err(storage)?).collect()
}

// A single immutable snapshot supplies both reads and authorized transaction deltas.
#[derive(Clone)]
pub(crate) struct MetadataSet {
    pub(crate) certificates: Vec<PkiCertificateRecord>,
    pub(crate) crls: Vec<PkiCrlRecord>,
    pub(crate) actions: Vec<crate::model::ActionRecord>,
    vault_id: rekey_domain::ids::VaultId,
}

fn combined_digest(pki: [u8; 32], actions: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"RKPKISET\0\x04");
    hash.update(pki);
    hash.update(actions);
    hash.finalize().into()
}

impl MetadataSet {
    pub(crate) fn digest(&self) -> [u8; 32] {
        combined_digest(
            digest(&self.certificates, &self.crls),
            crate::crypto::action_state::collection_digest(self.vault_id, &self.actions),
        )
    }
    pub(super) fn replace_action(
        &mut self,
        record: &crate::model::ActionRecord,
    ) -> Result<(), AuthorityError> {
        let old = self
            .actions
            .iter_mut()
            .find(|r| r.action_id == record.action_id && r.version == record.version)
            .ok_or_else(integrity)?;
        *old = record.clone();
        Ok(())
    }
}

pub(super) fn verified_set(
    conn: &Connection,
    expected: &[u8; 32],
) -> Result<MetadataSet, AuthorityError> {
    let set = MetadataSet {
        certificates: records(conn)?,
        crls: crl_records(conn)?,
        actions: super::sqlite::all_actions(conn)?,
        vault_id: super::sqlite::load_header(conn)?.vault_id,
    };
    if set.digest() != *expected {
        return Err(integrity());
    }
    Ok(set)
}

pub(super) fn verified(
    conn: &Connection,
    expected: &[u8; 32],
) -> Result<Vec<PkiCertificateRecord>, AuthorityError> {
    verified_set(conn, expected).map(|set| set.certificates)
}

impl SqliteRecordStore {
    pub(crate) fn verified_metadata(
        &self,
        header: &VaultHeaderRecord,
    ) -> Result<MetadataSet, AuthorityError> {
        verified_set(&self.conn, &header.pki_digest)
    }

    /// The caller first authenticates this header with its VRK.
    pub(crate) fn verified_certificates(
        &self,
        header: &VaultHeaderRecord,
    ) -> Result<Vec<PkiCertificateRecord>, AuthorityError> {
        verified(&self.conn, &header.pki_digest)
    }

    pub(crate) fn revoke_certificate(
        &mut self,
        serial: [u8; 16],
        now: i64,
        mut audit: AuditEvent,
        key: &[u8; 32],
        attempt: &mut GenerationAttempt<'_>,
    ) -> Result<i64, AuthorityError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut set = verified_set(&tx, &attempt.prior_pki_digest)?;
        let expected = &mut set.certificates;
        let row = expected
            .iter_mut()
            .find(|r| r.serial == serial && r.state == PkiCertificateState::Issued)
            .ok_or_else(|| {
                AuthorityError::from(rekey_domain::DomainError::InvalidActionDefinition(
                    "invalid certificate revocation request".into(),
                ))
            })?;
        audit.credential_id = Some(row.credential_id);
        audit.credential_version = Some(row.credential_version);
        super::audit::insert(&tx, &audit)?;
        let revoked = match row.revoked_at_ms {
            Some(first) => first,
            None => {
                let changed = tx.execute("UPDATE pki_certificates SET revoked_at_ms=?1 WHERE serial=?2 AND state=1 AND revoked_at_ms IS NULL", params![now, serial.as_slice()]).map_err(storage)?;
                if changed != 1 {
                    return Err(integrity());
                }
                row.revoked_at_ms = Some(now);
                now
            }
        };
        // Repeated requests authenticate the unchanged set and commit a new audit/generation.
        attempt.bind_pki_digest(key, set.digest())?;
        commit_generation(tx, attempt)?;
        Ok(revoked)
    }

    pub(crate) fn commit_certificate(
        &mut self,
        row: &PkiCertificateRecord,
        audit: &AuditEvent,
        insert: bool,
        key: &[u8; 32],
        attempt: &mut GenerationAttempt<'_>,
    ) -> Result<(), AuthorityError> {
        // Lock before enumerating the authenticated set; the digest and UPDATE
        // must describe this transaction, not a pre-transaction snapshot.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut set = verified_set(&tx, &attempt.prior_pki_digest)?;
        let expected = &mut set.certificates;
        super::audit::insert(&tx, audit)?;
        let values = params![
            row.serial.as_slice(),
            row.credential_id.as_bytes().as_slice(),
            row.credential_version,
            row.request_id.as_bytes().as_slice(),
            row.request_digest.as_slice(),
            row.created_at_ms,
            row.state as u8,
            row.finished_at_ms,
            row.certificate_der.as_deref(),
            row.issuer_der.as_deref()
        ];
        let changed = if insert {
            tx.execute("INSERT INTO pki_certificates(serial,credential_id,credential_version,request_id,request_digest,created_at_ms,state,finished_at_ms,certificate_der,issuer_der) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", values)
        } else {
            tx.execute("UPDATE pki_certificates SET state=?7,finished_at_ms=?8,certificate_der=?9,issuer_der=?10 WHERE serial=?1 AND credential_id=?2 AND credential_version=?3 AND request_id=?4 AND request_digest=?5 AND created_at_ms=?6 AND state=0", values)
        }.map_err(storage)?;
        if changed != 1 {
            return Err(integrity());
        }
        // Authenticate only the authorized delta, never arbitrary trigger effects.
        if insert {
            expected.push(row.clone());
        } else {
            let prior = expected
                .iter_mut()
                .find(|r| r.serial == row.serial)
                .ok_or_else(integrity)?;
            *prior = row.clone();
        }
        attempt.bind_pki_digest(key, set.digest())?;
        commit_generation(tx, attempt)
    }
    pub(crate) fn commit_crl(
        &mut self,
        row: &PkiCrlRecord,
        audit: &AuditEvent,
        insert: bool,
        key: &[u8; 32],
        attempt: &mut GenerationAttempt<'_>,
    ) -> Result<(), AuthorityError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut set = verified_set(&tx, &attempt.prior_pki_digest)?;
        let expected = &mut set.crls;
        super::audit::insert(&tx, audit)?;
        let number = row.number.to_be_bytes();
        let values = params![
            number.as_slice(),
            row.credential_id.as_bytes().as_slice(),
            row.credential_version,
            row.request_id.as_bytes().as_slice(),
            row.snapshot_digest.as_slice(),
            row.created_at_ms,
            row.state as u8,
            row.finished_at_ms,
            row.crl_der.as_deref(),
            row.issuer_der.as_deref()
        ];
        let changed = if insert {
            tx.execute("INSERT INTO pki_crls(number,credential_id,credential_version,request_id,snapshot_digest,created_at_ms,state,finished_at_ms,crl_der,issuer_der) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", values)
        } else {
            tx.execute("UPDATE pki_crls SET state=?7,finished_at_ms=?8,crl_der=?9,issuer_der=?10 WHERE number=?1 AND credential_id=?2 AND credential_version=?3 AND request_id=?4 AND snapshot_digest=?5 AND created_at_ms=?6 AND state=0", values)
        }.map_err(storage)?;
        if changed != 1 {
            return Err(integrity());
        }
        if insert {
            expected.push(row.clone());
        } else {
            let prior = expected
                .iter_mut()
                .find(|r| r.number == row.number)
                .ok_or_else(integrity)?;
            *prior = row.clone();
        }
        attempt.bind_pki_digest(key, set.digest())?;
        commit_generation(tx, attempt)
    }
}
