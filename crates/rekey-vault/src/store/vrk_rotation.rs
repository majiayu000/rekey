//! One transaction replaces all VRK dependencies without changing logical data.
use std::time::Instant;

use rekey_domain::credential::CredentialKind;
use rusqlite::params;

use super::SqliteRecordStore;
use super::sqlite::{commit_audited, storage};
use crate::command::PolicyMaterial;
use crate::error::AuthorityError;
use crate::model::{
    AuditEvent, CredentialRecord, CredentialVersionRecord, KeyWrapperRecord, VaultHeaderRecord,
};

fn one(changed: usize) -> Result<(), AuthorityError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(AuthorityError::StorageIntegrityFailed)
    }
}
fn current(deadline: Option<Instant>) -> Result<(), AuthorityError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(AuthorityError::AuthorityBusy)
    } else {
        Ok(())
    }
}

impl SqliteRecordStore {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn replace_root_ciphertexts(
        &mut self,
        header: &VaultHeaderRecord,
        versions: &[(CredentialKind, CredentialVersionRecord)],
        credentials: &[CredentialRecord],
        policy: &PolicyMaterial,
        wrappers: &[KeyWrapperRecord],
        audit: AuditEvent,
        not_after: Option<Instant>,
    ) -> Result<(), AuthorityError> {
        let tx = self.conn.transaction().map_err(storage)?;
        for (_, v) in versions {
            current(not_after)?;
            one(tx.execute("UPDATE credential_versions SET dek_nonce=?3, wrapped_dek=?4, payload_nonce=?5, encrypted_payload=?6 WHERE credential_id=?1 AND version=?2",
                params![v.credential_id.as_bytes().as_slice(), v.version as i64, v.dek_nonce.as_slice(), v.wrapped_dek, v.payload_nonce.as_slice(), v.encrypted_payload]).map_err(storage)?)?;
        }
        for c in credentials {
            current(not_after)?;
            one(tx.execute("UPDATE credentials SET state_nonce=?2, state_ciphertext=?3 WHERE credential_id=?1",
                params![c.credential_id.as_bytes().as_slice(), c.state_nonce.as_slice(), c.state_ciphertext.as_slice()]).map_err(storage)?)?;
        }
        one(tx
            .execute(
                "UPDATE policy_state SET seal_nonce=?1, seal_ciphertext=?2 WHERE singleton=1",
                params![
                    policy.state.seal_nonce.as_slice(),
                    policy.state.seal_ciphertext.as_slice()
                ],
            )
            .map_err(storage)?)?;
        if let Some(trust) = &policy.trust {
            one(tx.execute("UPDATE policy_trust SET seal_nonce=?1, seal_ciphertext=?2 WHERE singleton=1 AND signer_id=?3",
                params![trust.seal_nonce.as_slice(), trust.seal_ciphertext.as_slice(), trust.signer_id.as_bytes().as_slice()]).map_err(storage)?)?;
        }
        if let Some(bundle) = &policy.bundle {
            one(tx.execute("UPDATE policy_bundle SET seal_nonce=?1, seal_ciphertext=?2 WHERE singleton=1 AND version=?3",
                params![bundle.seal_nonce.as_slice(), bundle.seal_ciphertext.as_slice(), bundle.version as i64]).map_err(storage)?)?;
        }
        one(tx.execute("UPDATE vault_header SET integrity_nonce=?1, integrity_ciphertext=?2 WHERE singleton=1 AND vault_id=?3",
            params![header.integrity_nonce.as_slice(), header.integrity_ciphertext, header.vault_id.as_bytes().as_slice()]).map_err(storage)?)?;
        for wrapper in wrappers {
            current(not_after)?;
            one(tx.execute("UPDATE key_wrappers SET state='disabled', disabled_at_ms=?2, salt=zeroblob(16), nonce=zeroblob(12), wrapped_vrk=zeroblob(48) WHERE wrapper_kind=?1 AND state='active'",
                params![wrapper.kind.as_str(), wrapper.created_at_ms]).map_err(storage)?)?;
            // The shared helper also rejects an ignored (zero-row) INSERT.
            super::wrapper::insert_wrapper(&tx, wrapper)?;
        }
        super::audit::insert(&tx, &audit)?;
        current(not_after)?;
        commit_audited(tx)
    }
}
