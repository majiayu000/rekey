use std::path::{Path, PathBuf};

use rekey_domain::credential::{CredentialKind, CredentialState, VersionState};
use rekey_domain::ids::{ActionId, CredentialId, VaultId, WrapperId};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};

use super::connection::{open_existing, open_new, secure_sqlite_bundle};
use super::schema::{SCHEMA_SQL, schema_digest};
use crate::error::AuthorityError;
use crate::model::{
    ActionRecord, ActionState, AuditEvent, CredentialRecord, CredentialVersionRecord,
    KeyWrapperRecord, VaultHeaderRecord, WrapperKind, WrapperState,
};

/// The only read/write connection to the vault database. Owned exclusively by
/// the AuthorityWorker thread (or an offline bootstrap process).
pub struct SqliteRecordStore {
    pub(super) conn: Connection,
    path: PathBuf,
}

pub(super) fn storage(err: rusqlite::Error) -> AuthorityError {
    AuthorityError::storage(err)
}

pub(super) fn blob16(v: Vec<u8>) -> Result<[u8; 16], AuthorityError> {
    v.try_into()
        .map_err(|_| AuthorityError::StorageIntegrityFailed)
}

fn blob12(v: Vec<u8>) -> Result<[u8; 12], AuthorityError> {
    v.try_into()
        .map_err(|_| AuthorityError::StorageIntegrityFailed)
}

pub(super) fn blob32(v: Vec<u8>) -> Result<[u8; 32], AuthorityError> {
    v.try_into()
        .map_err(|_| AuthorityError::StorageIntegrityFailed)
}

impl SqliteRecordStore {
    /// Creates a brand-new database file with schema v5. Fails if the file
    /// already exists.
    pub fn create(path: &Path) -> Result<Self, AuthorityError> {
        if path.exists() {
            return Err(AuthorityError::AlreadyInitialized);
        }
        let conn = open_new(path)?;
        conn.execute_batch(SCHEMA_SQL).map_err(storage)?;
        secure_sqlite_bundle(path)?;
        Ok(Self {
            conn,
            path: path.to_owned(),
        })
    }

    /// Opens an existing v5 database, verifying pragmas, integrity, format
    /// version, and schema digest. Never migrates and never creates.
    pub fn open(path: &Path) -> Result<Self, AuthorityError> {
        if !path.exists() {
            return Err(AuthorityError::NotInitialized);
        }
        let conn = open_existing(path)?;
        let store = Self {
            conn,
            path: path.to_owned(),
        };
        store.quick_check()?;
        store.verify_required_layout()?;
        store.foreign_key_check()?;
        store.validate_format_discriminators()?;
        store.validate_credential_version_invariants()?;
        let header = store.load_header()?;
        if header.schema_digest != schema_digest() {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn initialize(
        &mut self,
        header: &VaultHeaderRecord,
        wrappers: &[KeyWrapperRecord],
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            "INSERT INTO vault_header (singleton, format_version, vault_id, crypto_suite, created_at_ms, schema_digest, integrity_nonce, integrity_ciphertext)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                header.format_version,
                header.vault_id.as_bytes().as_slice(),
                header.crypto_suite,
                header.created_at_ms,
                header.schema_digest.as_slice(),
                header.integrity_nonce.as_slice(),
                header.integrity_ciphertext.as_slice(),
            ],
        )
        .map_err(storage)?;
        for w in wrappers {
            insert_wrapper(&tx, w)?;
        }
        super::audit::insert(&tx, &audit)?;
        tx.commit().map_err(storage)
    }

    pub fn load_header(&self) -> Result<VaultHeaderRecord, AuthorityError> {
        let row = self
            .conn
            .query_row(
                "SELECT format_version, vault_id, crypto_suite, created_at_ms, schema_digest,
                        integrity_nonce, integrity_ciphertext
                 FROM vault_header WHERE singleton = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, u32>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthorityError::UnsupportedVaultLayout)?
            .ok_or(AuthorityError::UnsupportedVaultLayout)?;
        Ok(VaultHeaderRecord {
            format_version: row.0,
            vault_id: VaultId::from_bytes(blob16(row.1)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            crypto_suite: row.2,
            created_at_ms: row.3,
            schema_digest: blob32(row.4)?,
            integrity_nonce: blob12(row.5)?,
            integrity_ciphertext: row.6,
        })
    }

    pub fn active_wrapper(&self, kind: WrapperKind) -> Result<KeyWrapperRecord, AuthorityError> {
        self.conn
            .query_row(
                "SELECT wrapper_id, wrapper_kind, state, kdf_algorithm, kdf_params_json, salt, nonce, wrapped_vrk, created_at_ms, disabled_at_ms
                 FROM key_wrappers WHERE wrapper_kind = ?1 AND state = 'active'",
                params![kind.as_str()],
                wrapper_from_row,
            )
            .optional()
            .map_err(storage)?
            .ok_or(AuthorityError::InvalidUnlockCredential)?
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    pub fn insert_credential(
        &mut self,
        record: &CredentialRecord,
        version: &CredentialVersionRecord,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO credentials (credential_id, label, kind, state, current_version, created_at_ms, updated_at_ms, revoked_at_ms, state_nonce, state_ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.credential_id.as_bytes().as_slice(),
                record.label,
                record.kind.as_str(),
                record.state.as_str(),
                record.current_version as i64,
                record.created_at_ms,
                record.updated_at_ms,
                record.revoked_at_ms,
                record.state_nonce.as_slice(),
                record.state_ciphertext.as_slice(),
            ],
        )
        .map_err(storage)?;
        if inserted == 0 {
            return Err(AuthorityError::CredentialConflict);
        }
        insert_version(&tx, version)?;
        super::audit::insert(&tx, &audit)?;
        tx.commit().map_err(storage)
    }

    pub fn rotate_credential(
        &mut self,
        updated_record: &CredentialRecord,
        new_version: &CredentialVersionRecord,
        now_ms: i64,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let credential_id = updated_record.credential_id;
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            "UPDATE credential_versions SET state = 'retired', retired_at_ms = ?2
             WHERE credential_id = ?1 AND state = 'active'",
            params![credential_id.as_bytes().as_slice(), now_ms],
        )
        .map_err(storage)?;
        insert_version(&tx, new_version)?;
        let updated = tx
            .execute(
                "UPDATE credentials SET current_version = ?2, updated_at_ms = ?3,
                        state_nonce = ?4, state_ciphertext = ?5
                 WHERE credential_id = ?1 AND state = 'active'",
                params![
                    credential_id.as_bytes().as_slice(),
                    updated_record.current_version as i64,
                    updated_record.updated_at_ms,
                    updated_record.state_nonce.as_slice(),
                    updated_record.state_ciphertext.as_slice(),
                ],
            )
            .map_err(storage)?;
        if updated == 0 {
            return Err(AuthorityError::CredentialNotFound);
        }
        super::audit::insert(&tx, &audit)?;
        tx.commit().map_err(storage)
    }

    pub fn revoke_credential(
        &mut self,
        updated_record: &CredentialRecord,
        now_ms: i64,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let credential_id = updated_record.credential_id;
        let tx = self.conn.transaction().map_err(storage)?;
        let updated = tx
            .execute(
                "UPDATE credentials SET state = 'revoked', revoked_at_ms = ?2, updated_at_ms = ?3,
                        state_nonce = ?4, state_ciphertext = ?5
                 WHERE credential_id = ?1 AND state = 'active'",
                params![
                    credential_id.as_bytes().as_slice(),
                    updated_record.revoked_at_ms,
                    updated_record.updated_at_ms,
                    updated_record.state_nonce.as_slice(),
                    updated_record.state_ciphertext.as_slice(),
                ],
            )
            .map_err(storage)?;
        if updated == 0 {
            return Err(AuthorityError::CredentialNotFound);
        }
        tx.execute(
            "UPDATE credential_versions SET state = 'revoked', retired_at_ms = ?2
             WHERE credential_id = ?1 AND state = 'active'",
            params![credential_id.as_bytes().as_slice(), now_ms],
        )
        .map_err(storage)?;
        super::audit::insert(&tx, &audit)?;
        tx.commit().map_err(storage)
    }

    pub fn get_credential(&self, id: CredentialId) -> Result<CredentialRecord, AuthorityError> {
        self.conn
            .query_row(
                "SELECT credential_id, label, kind, state, current_version, created_at_ms, updated_at_ms, revoked_at_ms, state_nonce, state_ciphertext
                 FROM credentials WHERE credential_id = ?1",
                params![id.as_bytes().as_slice()],
                credential_from_row,
            )
            .optional()
            .map_err(storage)?
            .ok_or(AuthorityError::CredentialNotFound)?
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT credential_id, label, kind, state, current_version, created_at_ms, updated_at_ms, revoked_at_ms, state_nonce, state_ciphertext
                 FROM credentials ORDER BY created_at_ms",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], credential_from_row)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    pub fn get_version(
        &self,
        id: CredentialId,
        version: u64,
    ) -> Result<CredentialVersionRecord, AuthorityError> {
        self.conn
            .query_row(
                "SELECT credential_id, version, state, aad_version, crypto_suite, dek_nonce, wrapped_dek, payload_nonce, encrypted_payload, created_at_ms, retired_at_ms
                 FROM credential_versions WHERE credential_id = ?1 AND version = ?2",
                params![id.as_bytes().as_slice(), version as i64],
                version_from_row,
            )
            .optional()
            .map_err(storage)?
            .ok_or(AuthorityError::CredentialNotFound)?
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    pub fn insert_action(
        &mut self,
        record: &ActionRecord,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            "UPDATE actions SET state = 'retired' WHERE action_id = ?1 AND state = 'active'",
            params![record.action_id.as_bytes().as_slice()],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO actions (action_id, version, name, state, credential_id, origin, method, exact_path, auth_header, auth_prefix, request_max_bytes, allowed_extra_headers_json, response_max_bytes, allowed_response_headers_json, timeout_ms, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                record.action_id.as_bytes().as_slice(),
                record.version as i64,
                record.name,
                record.state.as_str(),
                record.credential_id.as_bytes().as_slice(),
                record.origin,
                record.method,
                record.exact_path,
                record.auth_header,
                record.auth_prefix,
                record.request_max_bytes,
                record.allowed_extra_headers_json,
                record.response_max_bytes,
                record.allowed_response_headers_json,
                record.timeout_ms,
                record.created_at_ms,
            ],
        )
        .map_err(storage)?;
        super::audit::insert(&tx, &audit)?;
        tx.commit().map_err(storage)
    }

    pub fn disable_action(
        &mut self,
        action_id: ActionId,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        let updated = tx
            .execute(
                "UPDATE actions SET state = 'disabled' WHERE action_id = ?1 AND state = 'active'",
                params![action_id.as_bytes().as_slice()],
            )
            .map_err(storage)?;
        if updated == 0 {
            return Err(AuthorityError::ActionNotFound);
        }
        super::audit::insert(&tx, &audit)?;
        tx.commit().map_err(storage)
    }

    pub fn get_action(
        &self,
        action_id: ActionId,
        version: u64,
    ) -> Result<ActionRecord, AuthorityError> {
        self.conn
            .query_row(
                "SELECT action_id, version, name, state, credential_id, origin, method, exact_path, auth_header, auth_prefix, request_max_bytes, allowed_extra_headers_json, response_max_bytes, allowed_response_headers_json, timeout_ms, created_at_ms
                 FROM actions WHERE action_id = ?1 AND version = ?2",
                params![action_id.as_bytes().as_slice(), version as i64],
                action_from_row,
            )
            .optional()
            .map_err(storage)?
            .ok_or(AuthorityError::ActionNotFound)?
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    pub fn list_actions(&self) -> Result<Vec<ActionRecord>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT action_id, version, name, state, credential_id, origin, method, exact_path, auth_header, auth_prefix, request_max_bytes, allowed_extra_headers_json, response_max_bytes, allowed_response_headers_json, timeout_ms, created_at_ms
                 FROM actions WHERE state != 'retired' ORDER BY created_at_ms",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], action_from_row)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    pub fn list_active_actions_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<ActionRecord>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT action_id, version, name, state, credential_id, origin, method, exact_path, auth_header, auth_prefix, request_max_bytes, allowed_extra_headers_json, response_max_bytes, allowed_response_headers_json, timeout_ms, created_at_ms
                 FROM actions WHERE credential_id = ?1 AND state = 'active'",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map(
                params![credential_id.as_bytes().as_slice()],
                action_from_row,
            )
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthorityError::StorageIntegrityFailed)
    }

    /// Commits one audit event in its own transaction. Failure is a hard
    /// error for the caller to handle; never downgraded to a warning.
    pub fn append_audit(&mut self, event: &AuditEvent) -> Result<(), AuthorityError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|_| AuthorityError::AuditCommitFailed)?;
        super::audit::insert(&tx, event).map_err(|_| AuthorityError::AuditCommitFailed)?;
        tx.commit().map_err(|_| AuthorityError::AuditCommitFailed)
    }

    pub fn wal_checkpoint(&self) -> Result<(), AuthorityError> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(storage)
    }

    pub fn audit_event_types(&self) -> Result<Vec<String>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_type FROM audit_events ORDER BY sequence")
            .map_err(storage)?;
        stmt.query_map([], |r| r.get::<_, String>(0))
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }

    /// Every credential version plus its kind, for restore payload proofs.
    pub fn list_all_versions(
        &self,
    ) -> Result<Vec<(CredentialKind, CredentialVersionRecord)>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT v.credential_id, v.version, v.state, v.aad_version, v.crypto_suite,
                        v.dek_nonce, v.wrapped_dek, v.payload_nonce, v.encrypted_payload,
                        v.created_at_ms, v.retired_at_ms, c.kind
                 FROM credential_versions v
                 LEFT JOIN credentials c ON c.credential_id = v.credential_id
                 ORDER BY v.created_at_ms, v.version",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |r| {
                let version = version_from_row(r)?;
                let kind: String = r.get(11)?;
                Ok((kind, version))
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .map(|(kind, version)| {
                let version = version?;
                let kind = CredentialKind::parse(&kind)
                    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                Ok((kind, version))
            })
            .collect()
    }

    /// `(request_id bytes, event_type)` for execution.* rows, sequence order.
    pub fn audit_execution_log(&self) -> Result<Vec<(Vec<u8>, String)>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT request_id, event_type FROM audit_events
                 WHERE event_type LIKE 'execution.%' ORDER BY sequence",
            )
            .map_err(storage)?;
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
                r.get::<_, String>(1)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)
    }

    /// Consistent online snapshot via the SQLite Backup API; never a plain
    /// file copy of a live WAL database.
    pub fn backup_to(
        &self,
        dest: &Path,
        created_file: &std::fs::File,
    ) -> Result<(), AuthorityError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let name = dest.file_name().ok_or(AuthorityError::BackupFailed)?;
        let resolved = crate::durable::parent_dir(dest)
            .canonicalize()
            .map_err(|_| AuthorityError::BackupFailed)?
            .join(name);
        let mut dst = Connection::open_with_flags(&resolved, flags)
            .map_err(|_| AuthorityError::BackupFailed)?;
        if !crate::durable::same_file(created_file, &resolved)
            .map_err(|_| AuthorityError::BackupFailed)?
        {
            return Err(AuthorityError::BackupFailed);
        }
        let backup = rusqlite::backup::Backup::new(&self.conn, &mut dst)
            .map_err(|_| AuthorityError::BackupFailed)?;
        backup
            .run_to_completion(64, std::time::Duration::from_millis(5), None)
            .map_err(|_| AuthorityError::BackupFailed)?;
        Ok(())
    }
}

fn insert_wrapper(tx: &Transaction<'_>, w: &KeyWrapperRecord) -> Result<(), AuthorityError> {
    tx.execute(
        "INSERT INTO key_wrappers (wrapper_id, wrapper_kind, state, kdf_algorithm, kdf_params_json, salt, nonce, wrapped_vrk, created_at_ms, disabled_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            w.wrapper_id.as_bytes().as_slice(),
            w.kind.as_str(),
            w.state.as_str(),
            w.kdf_algorithm,
            w.kdf_params_json,
            w.salt.as_slice(),
            w.nonce.as_slice(),
            w.wrapped_vrk,
            w.created_at_ms,
            w.disabled_at_ms,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

fn insert_version(tx: &Transaction<'_>, v: &CredentialVersionRecord) -> Result<(), AuthorityError> {
    tx.execute(
        "INSERT INTO credential_versions (credential_id, version, state, aad_version, crypto_suite, dek_nonce, wrapped_dek, payload_nonce, encrypted_payload, created_at_ms, retired_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            v.credential_id.as_bytes().as_slice(),
            v.version as i64,
            v.state.as_str(),
            v.aad_version,
            v.crypto_suite,
            v.dek_nonce.as_slice(),
            v.wrapped_dek,
            v.payload_nonce.as_slice(),
            v.encrypted_payload,
            v.created_at_ms,
            v.retired_at_ms,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

type RowResult<T> = Result<Result<T, AuthorityError>, rusqlite::Error>;

fn wrapper_from_row(r: &rusqlite::Row<'_>) -> RowResult<KeyWrapperRecord> {
    let wrapper_id: Vec<u8> = r.get(0)?;
    let kind: String = r.get(1)?;
    let state: String = r.get(2)?;
    let kdf_algorithm: String = r.get(3)?;
    let kdf_params_json: String = r.get(4)?;
    let salt: Vec<u8> = r.get(5)?;
    let nonce: Vec<u8> = r.get(6)?;
    let wrapped_vrk: Vec<u8> = r.get(7)?;
    let created_at_ms: i64 = r.get(8)?;
    let disabled_at_ms: Option<i64> = r.get(9)?;
    Ok((|| {
        Ok(KeyWrapperRecord {
            wrapper_id: WrapperId::from_bytes(blob16(wrapper_id)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            kind: WrapperKind::parse(&kind).ok_or(AuthorityError::StorageIntegrityFailed)?,
            state: WrapperState::parse(&state).ok_or(AuthorityError::StorageIntegrityFailed)?,
            kdf_algorithm,
            kdf_params_json,
            salt: salt
                .try_into()
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            nonce: blob12(nonce)?,
            wrapped_vrk,
            created_at_ms,
            disabled_at_ms,
        })
    })())
}

fn credential_from_row(r: &rusqlite::Row<'_>) -> RowResult<CredentialRecord> {
    let credential_id: Vec<u8> = r.get(0)?;
    let label: String = r.get(1)?;
    let kind: String = r.get(2)?;
    let state: String = r.get(3)?;
    let current_version: i64 = r.get(4)?;
    let created_at_ms: i64 = r.get(5)?;
    let updated_at_ms: i64 = r.get(6)?;
    let revoked_at_ms: Option<i64> = r.get(7)?;
    let state_nonce: Vec<u8> = r.get(8)?;
    let state_ciphertext: Vec<u8> = r.get(9)?;
    Ok((|| {
        Ok(CredentialRecord {
            credential_id: CredentialId::from_bytes(blob16(credential_id)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            label,
            kind: CredentialKind::parse(&kind)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            state: CredentialState::parse(&state)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            current_version: current_version as u64,
            created_at_ms,
            updated_at_ms,
            revoked_at_ms,
            state_nonce: blob12(state_nonce)?,
            state_ciphertext: blob16(state_ciphertext)?,
        })
    })())
}

fn version_from_row(r: &rusqlite::Row<'_>) -> RowResult<CredentialVersionRecord> {
    let credential_id: Vec<u8> = r.get(0)?;
    let version: i64 = r.get(1)?;
    let state: String = r.get(2)?;
    let aad_version: u16 = r.get(3)?;
    let crypto_suite: String = r.get(4)?;
    let dek_nonce: Vec<u8> = r.get(5)?;
    let wrapped_dek: Vec<u8> = r.get(6)?;
    let payload_nonce: Vec<u8> = r.get(7)?;
    let encrypted_payload: Vec<u8> = r.get(8)?;
    let created_at_ms: i64 = r.get(9)?;
    let retired_at_ms: Option<i64> = r.get(10)?;
    Ok((|| {
        Ok(CredentialVersionRecord {
            credential_id: CredentialId::from_bytes(blob16(credential_id)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            version: version as u64,
            state: VersionState::parse(&state)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            aad_version,
            crypto_suite,
            dek_nonce: blob12(dek_nonce)?,
            wrapped_dek,
            payload_nonce: blob12(payload_nonce)?,
            encrypted_payload,
            created_at_ms,
            retired_at_ms,
        })
    })())
}

fn action_from_row(r: &rusqlite::Row<'_>) -> RowResult<ActionRecord> {
    let action_id: Vec<u8> = r.get(0)?;
    let version: i64 = r.get(1)?;
    let name: String = r.get(2)?;
    let state: String = r.get(3)?;
    let credential_id: Vec<u8> = r.get(4)?;
    let origin: String = r.get(5)?;
    let method: String = r.get(6)?;
    let exact_path: String = r.get(7)?;
    let auth_header: String = r.get(8)?;
    let auth_prefix: String = r.get(9)?;
    let request_max_bytes: u32 = r.get(10)?;
    let allowed_extra_headers_json: String = r.get(11)?;
    let response_max_bytes: u32 = r.get(12)?;
    let allowed_response_headers_json: String = r.get(13)?;
    let timeout_ms: u32 = r.get(14)?;
    let created_at_ms: i64 = r.get(15)?;
    Ok((|| {
        Ok(ActionRecord {
            action_id: ActionId::from_bytes(blob16(action_id)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            version: version as u64,
            name,
            state: ActionState::parse(&state).ok_or(AuthorityError::StorageIntegrityFailed)?,
            credential_id: CredentialId::from_bytes(blob16(credential_id)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            origin,
            method,
            exact_path,
            auth_header,
            auth_prefix,
            request_max_bytes,
            allowed_extra_headers_json,
            response_max_bytes,
            allowed_response_headers_json,
            timeout_ms,
            created_at_ms,
        })
    })())
}
