use rusqlite::{Transaction, params};

use super::SqliteRecordStore;
use super::sqlite::{commit_audited, storage};
use crate::crypto::{KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::AuthorityError;
use crate::model::{AuditEvent, KeyWrapperRecord, WrapperKind};

pub(super) fn insert_wrapper(
    tx: &Transaction<'_>,
    wrapper: &KeyWrapperRecord,
) -> Result<(), AuthorityError> {
    tx.execute(
        "INSERT INTO key_wrappers (wrapper_id, wrapper_kind, state, kdf_algorithm, kdf_params_json, salt, nonce, wrapped_vrk, created_at_ms, disabled_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            wrapper.wrapper_id.as_bytes().as_slice(),
            wrapper.kind.as_str(),
            wrapper.state.as_str(),
            wrapper.kdf_algorithm,
            wrapper.kdf_params_json,
            wrapper.salt.as_slice(),
            wrapper.nonce.as_slice(),
            wrapper.wrapped_vrk,
            wrapper.created_at_ms,
            wrapper.disabled_at_ms,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

impl SqliteRecordStore {
    pub fn replace_wrapper(
        &mut self,
        kind: WrapperKind,
        replacement: &KeyWrapperRecord,
        disabled_at_ms: i64,
        audit: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        let replaced = tx
            .execute(
                "UPDATE key_wrappers
                 SET state = 'disabled', disabled_at_ms = ?2,
                     salt = zeroblob(?3), nonce = zeroblob(?4),
                     wrapped_vrk = zeroblob(?5)
                 WHERE wrapper_kind = ?1 AND state = 'active'",
                params![
                    kind.as_str(),
                    disabled_at_ms,
                    SALT_LEN,
                    NONCE_LEN,
                    KEY_LEN + 16,
                ],
            )
            .map_err(storage)?;
        if replaced != 1 {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        insert_wrapper(&tx, replacement)?;
        super::audit::insert(&tx, &audit)?;
        commit_audited(tx)
    }
}
