//! Single import transaction for upgrade migration into a freshly
//! initialized vault. Records arrive already resealed under the new vault id.
use super::SqliteRecordStore;
use super::generation::{GenerationAttempt, commit_generation};
use super::sqlite::{insert_credential_row, insert_version, storage};
use crate::error::AuthorityError;
use crate::model::{
    AuditEvent, AuditRetentionRecord, CredentialRecord, CredentialVersionRecord, PolicyStateRecord,
    PolicyTrustRecord,
};

pub(crate) struct MigratedRecords<'a> {
    pub credentials: &'a [(CredentialRecord, Vec<CredentialVersionRecord>)],
    pub trust: Option<(&'a PolicyStateRecord, &'a PolicyTrustRecord)>,
    pub retention: &'a AuditRetentionRecord,
}

impl SqliteRecordStore {
    /// Only valid on a vault that still holds nothing but its init records.
    pub(crate) fn import_migrated(
        &mut self,
        records: MigratedRecords<'_>,
        audit: AuditEvent,
        generation: &mut GenerationAttempt<'_>,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        let existing: i64 = tx
            .query_row(
                "SELECT (SELECT count(*) FROM credentials) + (SELECT count(*) FROM policy_trust)",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if existing != 0 {
            return Err(AuthorityError::StateDirectoryNotEmpty);
        }
        for (record, versions) in records.credentials {
            insert_credential_row(&tx, record)?;
            for version in versions {
                insert_version(&tx, version)?;
            }
        }
        if let Some((state, trust)) = records.trust {
            super::policy::insert_trust(&tx, trust)?;
            super::policy::update_state(&tx, state)?;
        }
        let retention = records.retention;
        let changed = tx
            .execute(
                "UPDATE audit_retention SET days=?1,updated_at_ms=?2,seal_nonce=?3,seal_ciphertext=?4 WHERE singleton=1",
                rusqlite::params![
                    retention.days.map(|d| d as i64),
                    retention.updated_at_ms,
                    retention.seal_nonce.as_slice(),
                    retention.seal_ciphertext.as_slice()
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        super::audit::insert(&tx, &audit)?;
        commit_generation(tx, generation)
    }
}
