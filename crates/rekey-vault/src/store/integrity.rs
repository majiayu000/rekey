use rusqlite::{Connection, OptionalExtension, params};

use super::SqliteRecordStore;
use super::schema::SCHEMA_SQL;
use crate::crypto::kdf::{Argon2Params, KDF_ALGORITHM_ARGON2ID, KDF_ALGORITHM_HKDF_SHA256};
use crate::crypto::{AAD_VERSION_V1, CRYPTO_SUITE_V1, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::AuthorityError;
use crate::model::{FORMAT_VERSION, VAULT_INTEGRITY_CIPHERTEXT_LEN};

impl SqliteRecordStore {
    pub(super) fn verify_required_tables(&self) -> Result<(), AuthorityError> {
        let table_count: u8 = self
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name IN (
                    'vault_header', 'key_wrappers', 'credentials',
                    'credential_versions', 'actions', 'policy_state',
                    'policy_trust', 'policy_bundle', 'workload_token_uses',
                    'audit_events'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if table_count != 10 {
            return Err(AuthorityError::UnsupportedVaultLayout);
        }
        Ok(())
    }

    pub(super) fn verify_required_layout(&self) -> Result<(), AuthorityError> {
        let expected = Connection::open_in_memory()
            .and_then(|conn| {
                conn.execute_batch(SCHEMA_SQL)?;
                schema_layout(&conn)
            })
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        let actual =
            schema_layout(&self.conn).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if actual != expected {
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
        let malformed_header: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM vault_header
                    WHERE typeof(vault_id) IS NOT 'blob'
                       OR length(vault_id) IS NOT 16
                       OR typeof(created_at_ms) IS NOT 'integer'
                       OR typeof(schema_digest) IS NOT 'blob'
                       OR length(schema_digest) IS NOT 32
                       OR typeof(integrity_nonce) IS NOT 'blob'
                       OR length(integrity_nonce) IS NOT ?1
                       OR typeof(integrity_ciphertext) IS NOT 'blob'
                       OR length(integrity_ciphertext) IS NOT ?2
                )",
                params![NONCE_LEN, VAULT_INTEGRITY_CIPHERTEXT_LEN],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if malformed_header {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        let malformed_wrappers: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM key_wrappers
                    WHERE typeof(wrapper_id) IS NOT 'blob'
                       OR length(wrapper_id) IS NOT 16
                       OR typeof(state) IS NOT 'text'
                       OR typeof(kdf_params_json) IS NOT 'text'
                       OR typeof(salt) IS NOT 'blob'
                       OR length(salt) IS NOT ?1
                       OR typeof(nonce) IS NOT 'blob'
                       OR length(nonce) IS NOT ?2
                       OR typeof(wrapped_vrk) IS NOT 'blob'
                       OR length(wrapped_vrk) IS NOT ?3
                       OR typeof(created_at_ms) IS NOT 'integer'
                       OR (disabled_at_ms IS NOT NULL
                           AND typeof(disabled_at_ms) IS NOT 'integer')
                )",
                params![SALT_LEN, NONCE_LEN, KEY_LEN + 16],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if malformed_wrappers {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        let active_wrappers: (u8, u8) = self
            .conn
            .query_row(
                "SELECT
                    SUM(CASE WHEN wrapper_kind = 'password' AND state = 'active' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN wrapper_kind = 'recovery' AND state = 'active' THEN 1 ELSE 0 END)
                 FROM key_wrappers",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if active_wrappers != (1, 1) {
            return Err(AuthorityError::StorageIntegrityFailed);
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

    pub(super) fn validate_workload_replay_invariants(&self) -> Result<(), AuthorityError> {
        let malformed: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM workload_token_uses
                    WHERE typeof(replay_digest) IS NOT 'blob'
                       OR length(replay_digest) IS NOT 32
                       OR typeof(expires_at_ms) IS NOT 'integer'
                       OR typeof(created_at_ms) IS NOT 'integer'
                       OR created_at_ms < 0
                       OR expires_at_ms <= created_at_ms
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if malformed {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(())
    }
}

fn schema_layout(conn: &Connection) -> rusqlite::Result<Vec<(String, String, String, String)>> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*'
         ORDER BY type, name",
    )?;
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect()
}
