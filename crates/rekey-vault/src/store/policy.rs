use rekey_domain::ids::PolicySignerId;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::SqliteRecordStore;
use super::audit;
use super::sqlite::{blob12, blob16, blob32, commit_audited, positive_version, storage};
use crate::command::PolicyMaterial;
use crate::crypto::policy_state;
use crate::error::AuthorityError;
use crate::model::{AuditEvent, PolicyBundleRecord, PolicyStateRecord, PolicyTrustRecord};
use rekey_domain::ids::VaultId;

pub(super) fn insert_initial_state(
    tx: &Transaction<'_>,
    state: &PolicyStateRecord,
) -> Result<(), AuthorityError> {
    tx.execute(
        "INSERT INTO policy_state (singleton, trust_installed, bundle_activated,
            signer_id, highest_version, policy_digest, bundle_digest, updated_at_ms,
            seal_nonce, seal_ciphertext)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            state.trust_installed,
            state.bundle_activated,
            state.signer_id.as_ref().map(|id| id.as_bytes().as_slice()),
            state.highest_version.map(|version| version as i64),
            state.policy_digest.as_ref().map(|digest| digest.as_slice()),
            state.bundle_digest.as_ref().map(|digest| digest.as_slice()),
            state.updated_at_ms,
            state.seal_nonce.as_slice(),
            state.seal_ciphertext.as_slice(),
        ],
    )
    .map_err(storage)?;
    Ok(())
}

impl SqliteRecordStore {
    pub fn verified_policy_material(
        &self,
        key: &[u8; 32],
        vault_id: VaultId,
    ) -> Result<PolicyMaterial, AuthorityError> {
        let state = self.load_policy_state()?;
        policy_state::verify_state(key, vault_id, &state)?;
        let trust = self.load_policy_trust()?;
        let bundle = self.load_policy_bundle()?;
        if state.trust_installed != trust.is_some() || state.bundle_activated != bundle.is_some() {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        if let Some(trust) = &trust {
            policy_state::verify_trust(key, vault_id, trust)?;
            if state.signer_id != Some(trust.signer_id) {
                return Err(AuthorityError::StorageIntegrityFailed);
            }
        }
        if let Some(bundle) = &bundle {
            policy_state::verify_bundle(key, vault_id, bundle)?;
            if state.signer_id != Some(bundle.signer_id)
                || state.highest_version != Some(bundle.version)
                || state.policy_digest != Some(bundle.policy_digest)
                || state.bundle_digest != Some(bundle.bundle_digest)
                || Sha256::digest(&bundle.bundle_json).as_slice() != bundle.bundle_digest
            {
                return Err(AuthorityError::StorageIntegrityFailed);
            }
        }
        Ok(PolicyMaterial {
            state,
            trust,
            bundle,
        })
    }

    pub fn load_policy_state(&self) -> Result<PolicyStateRecord, AuthorityError> {
        self.conn
            .query_row(
                "SELECT trust_installed, bundle_activated, signer_id, highest_version,
                    policy_digest, bundle_digest, updated_at_ms, seal_nonce, seal_ciphertext
                 FROM policy_state WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or(AuthorityError::StorageIntegrityFailed)
            .and_then(|row| {
                Ok(PolicyStateRecord {
                    trust_installed: row.0,
                    bundle_activated: row.1,
                    signer_id: row
                        .2
                        .map(blob16)
                        .transpose()?
                        .map(PolicySignerId::from_bytes)
                        .transpose()
                        .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    highest_version: row.3.map(positive_version).transpose()?,
                    policy_digest: row.4.map(blob32).transpose()?,
                    bundle_digest: row.5.map(blob32).transpose()?,
                    updated_at_ms: row.6,
                    seal_nonce: blob12(row.7)?,
                    seal_ciphertext: blob16(row.8)?,
                })
            })
    }

    pub fn load_policy_trust(&self) -> Result<Option<PolicyTrustRecord>, AuthorityError> {
        self.conn
            .query_row(
                "SELECT signer_id, public_key, installed_at_ms, seal_nonce, seal_ciphertext
                 FROM policy_trust WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .map(|row| {
                Ok(PolicyTrustRecord {
                    signer_id: PolicySignerId::from_bytes(blob16(row.0)?)
                        .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    public_key: blob32(row.1)?,
                    installed_at_ms: row.2,
                    seal_nonce: blob12(row.3)?,
                    seal_ciphertext: blob16(row.4)?,
                })
            })
            .transpose()
    }

    pub fn load_policy_bundle(&self) -> Result<Option<PolicyBundleRecord>, AuthorityError> {
        self.conn
            .query_row(
                "SELECT signer_id, version, expires_at_ms, policy_digest, bundle_digest,
                    bundle_json, activated_at_ms, seal_nonce, seal_ciphertext
                 FROM policy_bundle WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .map(|row| {
                Ok(PolicyBundleRecord {
                    signer_id: PolicySignerId::from_bytes(blob16(row.0)?)
                        .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    version: positive_version(row.1)?,
                    expires_at_ms: row.2,
                    policy_digest: blob32(row.3)?,
                    bundle_digest: blob32(row.4)?,
                    bundle_json: row.5,
                    activated_at_ms: row.6,
                    seal_nonce: blob12(row.7)?,
                    seal_ciphertext: blob16(row.8)?,
                })
            })
            .transpose()
    }

    pub fn install_policy_trust(
        &mut self,
        state: &PolicyStateRecord,
        trust: &PolicyTrustRecord,
        event: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            "INSERT INTO policy_trust (singleton, signer_id, algorithm, public_key, installed_at_ms,
                seal_nonce, seal_ciphertext) VALUES (1, ?1, 'ed25519', ?2, ?3, ?4, ?5)",
            params![
                trust.signer_id.as_bytes().as_slice(),
                trust.public_key.as_slice(),
                trust.installed_at_ms,
                trust.seal_nonce.as_slice(),
                trust.seal_ciphertext.as_slice(),
            ],
        )
        .map_err(storage)?;
        update_state(&tx, state)?;
        audit::insert(&tx, &event)?;
        commit_audited(tx)
    }

    pub fn activate_policy_bundle(
        &mut self,
        state: &PolicyStateRecord,
        bundle: &PolicyBundleRecord,
        event: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            "INSERT INTO policy_bundle (singleton, signer_id, version, expires_at_ms,
                policy_digest, bundle_digest, bundle_json, activated_at_ms,
                seal_nonce, seal_ciphertext)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(singleton) DO UPDATE SET signer_id=excluded.signer_id,
                version=excluded.version, expires_at_ms=excluded.expires_at_ms,
                policy_digest=excluded.policy_digest, bundle_digest=excluded.bundle_digest,
                bundle_json=excluded.bundle_json, activated_at_ms=excluded.activated_at_ms,
                seal_nonce=excluded.seal_nonce, seal_ciphertext=excluded.seal_ciphertext",
            params![
                bundle.signer_id.as_bytes().as_slice(),
                bundle.version as i64,
                bundle.expires_at_ms,
                bundle.policy_digest.as_slice(),
                bundle.bundle_digest.as_slice(),
                bundle.bundle_json,
                bundle.activated_at_ms,
                bundle.seal_nonce.as_slice(),
                bundle.seal_ciphertext.as_slice(),
            ],
        )
        .map_err(storage)?;
        update_state(&tx, state)?;
        audit::insert(&tx, &event)?;
        commit_audited(tx)
    }
}

fn update_state(tx: &Transaction<'_>, state: &PolicyStateRecord) -> Result<(), AuthorityError> {
    let updated = tx
        .execute(
            "UPDATE policy_state SET trust_installed=?1, bundle_activated=?2,
                signer_id=?3, highest_version=?4, policy_digest=?5, bundle_digest=?6,
                updated_at_ms=?7, seal_nonce=?8, seal_ciphertext=?9 WHERE singleton=1",
            params![
                state.trust_installed,
                state.bundle_activated,
                state.signer_id.as_ref().map(|id| id.as_bytes().as_slice()),
                state.highest_version.map(|version| version as i64),
                state.policy_digest.as_ref().map(|digest| digest.as_slice()),
                state.bundle_digest.as_ref().map(|digest| digest.as_slice()),
                state.updated_at_ms,
                state.seal_nonce.as_slice(),
                state.seal_ciphertext.as_slice(),
            ],
        )
        .map_err(storage)?;
    if updated != 1 {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}
