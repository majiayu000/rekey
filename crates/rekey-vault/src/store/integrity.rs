use rusqlite::{OptionalExtension, params};

use super::SqliteRecordStore;
use crate::crypto::kdf::{Argon2Params, KDF_ALGORITHM_ARGON2ID, KDF_ALGORITHM_HKDF_SHA256};
use crate::crypto::{AAD_VERSION_V1, CRYPTO_SUITE_V1};
use crate::error::AuthorityError;
use crate::model::FORMAT_VERSION;

impl SqliteRecordStore {
    pub(super) fn verify_required_layout(&self) -> Result<(), AuthorityError> {
        let table_count: u8 = self
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name IN (
                    'vault_header', 'key_wrappers', 'credentials',
                    'credential_versions', 'actions', 'audit_events'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if table_count != 6 {
            return Err(AuthorityError::UnsupportedVaultLayout);
        }
        Ok(())
    }

    pub fn quick_check(&self) -> Result<(), AuthorityError> {
        let result: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if result != "ok" {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(())
    }

    pub(super) fn foreign_key_check(&self) -> Result<(), AuthorityError> {
        let violation: Option<(String, i64, String, i64)> = self
            .conn
            .query_row("PRAGMA foreign_key_check", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .optional()
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if violation.is_some() {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(())
    }

    /// Rejects every persisted crypto discriminator before any row can be
    /// interpreted using the only suite implemented by this binary.
    pub(super) fn validate_format_discriminators(&self) -> Result<(), AuthorityError> {
        let unknown_header: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM vault_header
                    WHERE typeof(format_version) IS NOT 'integer'
                       OR format_version IS NOT ?1
                       OR typeof(crypto_suite) IS NOT 'text'
                       OR crypto_suite IS NOT ?2
                )",
                params![FORMAT_VERSION, CRYPTO_SUITE_V1],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        let unknown_wrappers: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM key_wrappers
                    WHERE typeof(wrapper_kind) IS NOT 'text'
                       OR typeof(kdf_algorithm) IS NOT 'text'
                       OR (wrapper_kind IS 'password' AND kdf_algorithm IS NOT ?1)
                       OR (wrapper_kind IS 'recovery' AND kdf_algorithm IS NOT ?2)
                       OR (wrapper_kind IS NOT 'password' AND wrapper_kind IS NOT 'recovery')
                )",
                params![KDF_ALGORITHM_ARGON2ID, KDF_ALGORITHM_HKDF_SHA256],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        let unknown_versions: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM credential_versions
                    WHERE typeof(aad_version) IS NOT 'integer'
                       OR aad_version IS NOT ?1
                       OR typeof(crypto_suite) IS NOT 'text'
                       OR crypto_suite IS NOT ?2
                )",
                params![AAD_VERSION_V1, CRYPTO_SUITE_V1],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if unknown_header || unknown_wrappers || unknown_versions {
            return Err(AuthorityError::UnsupportedFormatVersion);
        }
        let mut statement = self
            .conn
            .prepare("SELECT wrapper_kind, kdf_params_json FROM key_wrappers")
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        let params = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        for row in params {
            let (kind, value) = row.map_err(|_| AuthorityError::StorageIntegrityFailed)?;
            match kind.as_str() {
                "password" => {
                    Argon2Params::from_json(&value)
                        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                }
                "recovery" if value == "{}" => {}
                "recovery" => return Err(AuthorityError::StorageIntegrityFailed),
                _ => return Err(AuthorityError::StorageIntegrityFailed),
            }
        }
        Ok(())
    }

    /// Proves the cross-row state machine that runtime decryption assumes.
    pub fn validate_credential_version_invariants(&self) -> Result<(), AuthorityError> {
        let inconsistent: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM credentials c
                    LEFT JOIN credential_versions current
                      ON current.credential_id = c.credential_id
                     AND current.version = c.current_version
                    WHERE current.credential_id IS NULL
                       OR (c.state = 'active' AND current.state IS NOT 'active')
                       OR (c.state = 'revoked' AND current.state IS NOT 'revoked')
                    UNION ALL
                    SELECT 1
                    FROM credential_versions v
                    LEFT JOIN credentials c ON c.credential_id = v.credential_id
                    WHERE v.state = 'active'
                      AND (c.credential_id IS NULL
                           OR c.state IS NOT 'active'
                           OR c.current_version IS NOT v.version)
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if inconsistent {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(())
    }
}
