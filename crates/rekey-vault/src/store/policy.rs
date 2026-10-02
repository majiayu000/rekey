use rekey_domain::authorization::{PolicyMode, PolicyTrustAlgorithm};
use rekey_domain::ids::PolicySignerId;
use rekey_policy::PolicyVerificationKey;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
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
            seal_nonce, seal_ciphertext, mode)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
            mode_name(state.mode),
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
        verified_policy_material(&self.conn, key, vault_id)
    }
    pub fn load_policy_state(&self) -> Result<PolicyStateRecord, AuthorityError> {
        load_policy_state(&self.conn)
    }
    pub fn load_policy_trust(&self) -> Result<Option<PolicyTrustRecord>, AuthorityError> {
        load_policy_trust(&self.conn)
    }
    pub fn load_policy_bundle(&self) -> Result<Option<PolicyBundleRecord>, AuthorityError> {
        load_policy_bundle(&self.conn)
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
                seal_nonce, seal_ciphertext) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                trust.signer_id.as_bytes().as_slice(),
                algorithm_name(trust.key.algorithm()),
                trust.key.as_bytes(),
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
        // Replay digests are scoped to the policy digest. A successful,
        // irreversible version roll-forward makes every prior digest
        // unverifiable, so this is the only safe bounded cleanup point under
        // wall-clock rollback. Exact same-bundle retries return before here.
        tx.execute("DELETE FROM workload_token_uses", [])
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
                updated_at_ms=?7, seal_nonce=?8, seal_ciphertext=?9 WHERE singleton=1 AND mode=?10",
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
                mode_name(state.mode),
            ],
        )
        .map_err(storage)?;
    if updated != 1 {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    Ok(())
}

fn mode_name(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Personal => "personal",
        PolicyMode::Team => "team",
    }
}
fn algorithm_name(algorithm: PolicyTrustAlgorithm) -> &'static str {
    match algorithm {
        PolicyTrustAlgorithm::Ed25519 => "ed25519",
        PolicyTrustAlgorithm::SecureEnclaveP256 => "secure-enclave-p256",
    }
}

/// One validation path for live records, the actual backup snapshot and restore.
pub(super) fn verified_policy_material(
    conn: &Connection,
    key: &[u8; 32],
    vault_id: VaultId,
) -> Result<PolicyMaterial, AuthorityError> {
    let state = load_policy_state(conn)?;
    policy_state::verify_state(key, vault_id, &state)?;
    let trust = load_policy_trust(conn)?;
    let bundle = load_policy_bundle(conn)?;
    if state.trust_installed != trust.is_some() || state.bundle_activated != bundle.is_some() {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    if let Some(trust) = &trust {
        policy_state::verify_trust(key, vault_id, trust)?;
        if state.signer_id != Some(trust.signer_id)
            || !matches!(
                (state.mode, trust.key.algorithm()),
                (
                    PolicyMode::Personal,
                    PolicyTrustAlgorithm::SecureEnclaveP256
                ) | (PolicyMode::Team, PolicyTrustAlgorithm::Ed25519)
            )
        {
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

fn load_policy_state(conn: &Connection) -> Result<PolicyStateRecord, AuthorityError> {
    conn.query_row(
        "SELECT trust_installed,bundle_activated,signer_id,highest_version,policy_digest,bundle_digest,updated_at_ms,seal_nonce,seal_ciphertext,mode FROM policy_state WHERE singleton=1",
        [], |row| {
            // Decode persisted columns into the inner integrity error. SQL query
            // and I/O failures retain the outer storage error contract.
            Ok((|| -> Result<_, AuthorityError> {
                let mode: String = row.get(9).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let mode = match mode.as_str() { "personal" => PolicyMode::Personal, "team" => PolicyMode::Team, _ => return Err(AuthorityError::StorageIntegrityFailed) };
                let signer: Option<Vec<u8>> = row.get(2).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let highest: Option<i64> = row.get(3).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let policy: Option<Vec<u8>> = row.get(4).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let bundle: Option<Vec<u8>> = row.get(5).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                Ok(PolicyStateRecord {
                    mode,
                    trust_installed: row.get(0).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    bundle_activated: row.get(1).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    signer_id: signer.map(blob16).transpose()?.map(PolicySignerId::from_bytes).transpose().map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    highest_version: highest.map(positive_version).transpose()?,
                    policy_digest: policy.map(blob32).transpose()?,
                    bundle_digest: bundle.map(blob32).transpose()?,
                    updated_at_ms: row.get(6).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    seal_nonce: blob12(row.get(7).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                    seal_ciphertext: blob16(row.get(8).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                })
            })())
        }).optional().map_err(storage)?.ok_or(AuthorityError::StorageIntegrityFailed)?
}
fn load_policy_trust(conn: &Connection) -> Result<Option<PolicyTrustRecord>, AuthorityError> {
    conn.query_row(
        "SELECT signer_id,algorithm,public_key,installed_at_ms,seal_nonce,seal_ciphertext FROM policy_trust WHERE singleton=1",
        [], |row| {
            Ok((|| -> Result<_, AuthorityError> {
                let algorithm: String = row.get(1).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let algorithm = match algorithm.as_str() { "ed25519" => PolicyTrustAlgorithm::Ed25519, "secure-enclave-p256" => PolicyTrustAlgorithm::SecureEnclaveP256, _ => return Err(AuthorityError::StorageIntegrityFailed) };
                let bytes: Vec<u8> = row.get(2).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let key = PolicyVerificationKey::from_bytes(algorithm, &bytes).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                Ok(PolicyTrustRecord {
                    signer_id: PolicySignerId::from_bytes(blob16(row.get(0).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    key,
                    installed_at_ms: row.get(3).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    seal_nonce: blob12(row.get(4).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                    seal_ciphertext: blob16(row.get(5).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                })
            })())
        }).optional().map_err(storage)?.transpose()
}
fn load_policy_bundle(conn: &Connection) -> Result<Option<PolicyBundleRecord>, AuthorityError> {
    conn.query_row(
        "SELECT signer_id,version,expires_at_ms,policy_digest,bundle_digest,bundle_json,activated_at_ms,seal_nonce,seal_ciphertext FROM policy_bundle WHERE singleton=1",
        [], |row| {
            Ok((|| -> Result<_, AuthorityError> {
                Ok(PolicyBundleRecord {
                    signer_id: PolicySignerId::from_bytes(blob16(row.get(0).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    version: positive_version(row.get(1).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                    expires_at_ms: row.get(2).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    policy_digest: blob32(row.get(3).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                    bundle_digest: blob32(row.get(4).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                    bundle_json: row.get(5).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    activated_at_ms: row.get(6).map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                    seal_nonce: blob12(row.get(7).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                    seal_ciphertext: blob16(row.get(8).map_err(|_| AuthorityError::StorageIntegrityFailed)?)?,
                })
            })())
        }).optional().map_err(storage)?.transpose()
}
