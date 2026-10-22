//! Frozen reader for released vault layouts that upgrade migration accepts:
//! vault25 (0.3), vault26 (0.4) and vault27 (0.5). It reads a private copy of
//! the source database, never the source file itself, and only exact released
//! layouts. Formats older than 25 stay rejected.
//!
//! The tables read here kept identical columns from 25 to 27; only the header
//! gained `pki_digest` in 27. Each accepted layout is pinned by its
//! `sqlite_schema` digest, so a future column change in the shared row
//! decoders fails the fixture tests instead of silently reinterpreting rows.

use std::path::Path;

use rekey_domain::ids::VaultId;
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};

use super::integrity::schema_layout;
use super::schema::SCHEMA_SQL;
use super::sqlite::{
    blob12, blob16, blob32, credential_from_row, storage, version_from_row, wrapper_from_row,
};
use crate::command::PolicyMaterial;
use crate::crypto::CRYPTO_SUITE_V1;
use crate::error::AuthorityError;
use crate::model::{
    AuditRetentionRecord, CredentialRecord, CredentialVersionRecord, FORMAT_VERSION,
    KeyWrapperRecord, VaultHeaderRecord, WrapperKind,
};

/// `sqlite_schema` digests of the released 0.3 (vault25) and 0.4 (vault26)
/// layouts, computed by [`layout_digest`] from vaults the tagged releases created.
const LAYOUT_DIGEST_V25: &str = "7dc1aabda23b54b7c42d6c3d4e16349af5173b365fef3adcdfd20d42b977803d";
const LAYOUT_DIGEST_V26: &str = "5bf506dfa076227abfb4a184bb6310ad9c81308adaaf926a9e71a31acca54079";
/// Header `schema_digest` values the released binaries stored.
const SCHEMA_DIGEST_V25: &str = "470b1cccade61e730f7ab0fb7f79a05a84a7a9d8365c695fe2301468b037f582";
const SCHEMA_DIGEST_V26: &str = "896aeeee48f7aec2169495a4169d8380ffd6975dfcc7be534a06ba1196e30f5a";

/// Authenticated only after the caller verifies it with the source VRK.
pub(crate) struct LegacyVault {
    conn: Connection,
    pub header: VaultHeaderRecord,
}

pub(crate) struct LegacyCredential {
    pub record: CredentialRecord,
    pub versions: Vec<CredentialVersionRecord>,
}

impl LegacyVault {
    /// Opens a private copy. `path` must never be the source vault itself.
    pub(crate) fn open(path: &Path) -> Result<Self, AuthorityError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(AuthorityError::storage)?;
        let format: i64 = conn
            .query_row(
                "SELECT format_version FROM vault_header WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::UnsupportedVaultLayout)?;
        let format = u32::try_from(format).map_err(|_| AuthorityError::UnsupportedFormatVersion)?;
        let (layout, schema) = match format {
            25 => (LAYOUT_DIGEST_V25.to_owned(), SCHEMA_DIGEST_V25.to_owned()),
            26 => (LAYOUT_DIGEST_V26.to_owned(), SCHEMA_DIGEST_V26.to_owned()),
            FORMAT_VERSION => (
                current_layout_digest()?,
                data_encoding::HEXLOWER.encode(&super::schema::schema_digest()),
            ),
            _ => return Err(AuthorityError::UnsupportedFormatVersion),
        };
        let quick: String = conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if quick != "ok" {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        if layout_digest(&conn)? != layout {
            return Err(AuthorityError::UnsupportedVaultLayout);
        }
        let violation: Option<String> = conn
            .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if violation.is_some() {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        let header = load_header(&conn, format)?;
        if header.crypto_suite != CRYPTO_SUITE_V1
            || data_encoding::HEXLOWER.encode(&header.schema_digest) != schema
        {
            return Err(AuthorityError::UnsupportedVaultLayout);
        }
        Ok(Self { conn, header })
    }

    pub(crate) fn password_wrapper(&self) -> Result<KeyWrapperRecord, AuthorityError> {
        self.conn
            .query_row(
                "SELECT wrapper_id, wrapper_kind, state, kdf_algorithm, kdf_params_json, salt, nonce, wrapped_vrk, created_at_ms, disabled_at_ms
                 FROM key_wrappers WHERE wrapper_kind = ?1 AND state = 'active'",
                params![WrapperKind::Password.as_str()],
                wrapper_from_row,
            )
            .map_err(|_| AuthorityError::InvalidUnlockCredential)?
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    /// Row counts of state that migration refuses to drop silently.
    pub(crate) fn count(&self, table: LegacyTable) -> Result<i64, AuthorityError> {
        if table == LegacyTable::PkiCertificates && self.header.format_version < 27 {
            return Ok(0);
        }
        self.conn
            .query_row(table.count_sql(), [], |row| row.get(0))
            .map_err(storage)
    }

    pub(crate) fn credentials(&self) -> Result<Vec<LegacyCredential>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT credential_id, label, kind, state, current_version, created_at_ms, updated_at_ms, revoked_at_ms, state_nonce, state_ciphertext
                 FROM credentials ORDER BY created_at_ms, credential_id",
            )
            .map_err(storage)?;
        let records = stmt
            .query_map([], credential_from_row)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        let mut versions = self
            .conn
            .prepare(
                "SELECT credential_id, version, state, aad_version, crypto_suite, dek_nonce, wrapped_dek, payload_nonce, encrypted_payload, created_at_ms, retired_at_ms
                 FROM credential_versions WHERE credential_id = ?1 ORDER BY version",
            )
            .map_err(storage)?;
        let mut out = Vec::with_capacity(records.len());
        let mut seen_versions = 0usize;
        for record in records {
            let rows = versions
                .query_map(
                    params![record.credential_id.as_bytes().as_slice()],
                    version_from_row,
                )
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
            seen_versions += rows.len();
            out.push(LegacyCredential {
                record,
                versions: rows,
            });
        }
        let total: i64 = self
            .conn
            .query_row("SELECT count(*) FROM credential_versions", [], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        if usize::try_from(total).ok() != Some(seen_versions) {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(out)
    }

    pub(crate) fn verified_policy_material(
        &self,
        key: &[u8; 32],
        vault_id: VaultId,
    ) -> Result<PolicyMaterial, AuthorityError> {
        super::policy::verified_policy_material(&self.conn, key, vault_id)
    }

    pub(crate) fn verified_audit_retention(
        &self,
        key: &[u8; 32],
        vault_id: VaultId,
    ) -> Result<AuditRetentionRecord, AuthorityError> {
        let (days, updated_at_ms, nonce, ciphertext): (Option<i64>, i64, Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT days,updated_at_ms,seal_nonce,seal_ciphertext FROM audit_retention WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        let record = AuditRetentionRecord {
            days: days
                .map(u64::try_from)
                .transpose()
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            updated_at_ms,
            seal_nonce: blob12(nonce)?,
            seal_ciphertext: blob16(ciphertext)?,
        };
        crate::crypto::policy_state::verify_retention(key, vault_id, &record)?;
        Ok(record)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyTable {
    Actions,
    LeaseJournal,
    PkiCertificates,
}

impl LegacyTable {
    fn count_sql(self) -> &'static str {
        match self {
            Self::Actions => "SELECT count(*) FROM actions",
            Self::LeaseJournal => "SELECT count(*) FROM vault_lease_journal",
            Self::PkiCertificates => {
                "SELECT (SELECT count(*) FROM pki_certificates) + (SELECT count(*) FROM pki_crls)"
            }
        }
    }
}

/// Digest of the actual `sqlite_schema` rows, used to pin released layouts.
pub(crate) fn layout_digest(conn: &Connection) -> Result<String, AuthorityError> {
    let rows = schema_layout(conn).map_err(|_| AuthorityError::UnsupportedVaultLayout)?;
    let mut hash = Sha256::new();
    for (kind, name, table, sql) in rows {
        for part in [kind, name, table, sql] {
            hash.update(part.as_bytes());
            hash.update([0]);
        }
        hash.update(b"\n");
    }
    Ok(data_encoding::HEXLOWER.encode(&hash.finalize()))
}

fn current_layout_digest() -> Result<String, AuthorityError> {
    let conn = Connection::open_in_memory().map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    conn.execute_batch(SCHEMA_SQL)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    layout_digest(&conn)
}

fn integrity<E>(_: E) -> AuthorityError {
    AuthorityError::StorageIntegrityFailed
}

fn load_header(conn: &Connection, format: u32) -> Result<VaultHeaderRecord, AuthorityError> {
    let pki_column = if format >= 27 { "pki_digest" } else { "NULL" };
    let sql = format!(
        "SELECT format_version,vault_id,crypto_suite,created_at_ms,schema_digest,
                integrity_nonce,integrity_ciphertext,generation,generation_mac,{pki_column}
         FROM vault_header WHERE singleton=1"
    );
    conn.query_row(&sql, [], |row| {
        Ok((|| {
            let get = |index| row.get::<_, Vec<u8>>(index).map_err(integrity);
            let generation = u64::from_be_bytes(
                get(7)?
                    .try_into()
                    .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            );
            if generation == 0 {
                return Err(AuthorityError::StorageIntegrityFailed);
            }
            let pki: Option<Vec<u8>> = row.get(9).map_err(integrity)?;
            Ok(VaultHeaderRecord {
                format_version: row.get(0).map_err(integrity)?,
                vault_id: VaultId::from_bytes(blob16(get(1)?)?).map_err(integrity)?,
                crypto_suite: row.get(2).map_err(integrity)?,
                created_at_ms: row.get(3).map_err(integrity)?,
                schema_digest: blob32(get(4)?)?,
                integrity_nonce: blob12(get(5)?)?,
                integrity_ciphertext: get(6)?,
                generation,
                generation_mac: blob32(get(8)?)?,
                // Pre-27 headers have no PKI collection; the v1 MAC omits it.
                pki_digest: match pki {
                    Some(bytes) => blob32(bytes)?,
                    None => super::pki::empty_digest(),
                },
            })
        })())
    })
    .map_err(|_| AuthorityError::UnsupportedVaultLayout)?
}
