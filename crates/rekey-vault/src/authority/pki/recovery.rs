//! Unlock from Locked finalizes PKI reservations that no running command owns.
use rekey_domain::ids::{CredentialId, RequestId};

use crate::authority::Worker;
use crate::command::AuditDraft;
use crate::crypto::keys::RootKey;
use crate::error::AuthorityError;
use crate::model::{PkiCertificateState, VaultHeaderRecord, event_type, outcome};
use crate::store::generation::GenerationAttempt;

fn abandoned(
    event_type: &'static str,
    request_id: RequestId,
    credential_id: CredentialId,
    credential_version: u64,
) -> AuditDraft {
    AuditDraft {
        request_id: Some(request_id),
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: Some(credential_id),
        credential_version: Some(credential_version),
        authorization: None,
        approval: None,
        usage: None,
        request_context: None,
        event_type,
        outcome: outcome::FAILURE,
        reason_code: "abandoned-on-unlock".into(),
        upstream_status: None,
        latency_ms: None,
    }
}

impl Worker {
    /// Verifies an authenticated unlock candidate's PKI set and generation.
    /// One command runs each issuance or CRL from reservation to terminal
    /// commit, and delivery follows that commit, so a reservation seen on
    /// unlock from Locked has no owner and was never delivered (a Worker crash,
    /// for example). Finalize every such row as Failed in one generation
    /// commit before unlocking.
    pub(crate) fn verify_unlock_generation(
        &mut self,
        header: &mut VaultHeaderRecord,
        root: &RootKey,
        from_locked: bool,
    ) -> Result<(), AuthorityError> {
        let set = self.store.verified_metadata(header);
        let set = self.fault_on_integrity(set)?;
        let observed = self.check_generation(header)?;
        if !from_locked {
            return Ok(());
        }
        let reserved = |state: PkiCertificateState| state == PkiCertificateState::Reserved;
        let mut certificates = Vec::new();
        for row in set.certificates.iter().filter(|r| reserved(r.state)) {
            let draft = abandoned(
                event_type::PKI_CERTIFICATE_FINISHED,
                row.request_id,
                row.credential_id,
                row.credential_version,
            );
            certificates.push((row.serial, self.audit_event_or_fault(draft)?));
        }
        let mut crls = Vec::new();
        for row in set.crls.iter().filter(|r| reserved(r.state)) {
            let draft = abandoned(
                event_type::PKI_CRL_FINISHED,
                row.request_id,
                row.credential_id,
                row.credential_version,
            );
            crls.push((row.number, self.audit_event_or_fault(draft)?));
        }
        if certificates.is_empty() && crls.is_empty() {
            return Ok(());
        }
        let finished_at_ms = crate::now_ms()?;
        let next = header
            .generation
            .checked_add(1)
            .ok_or(AuthorityError::StorageIntegrityFailed)?;
        let mut generation = GenerationAttempt::new(
            &self.anchors,
            header,
            observed,
            root.bytes(),
            next,
            None,
            None,
        )?;
        let result = self.store.finalize_reservations(
            &certificates,
            &crls,
            finished_at_ms,
            root.bytes(),
            &mut generation,
        );
        let completed = generation.finish();
        let result = self.complete_generation(result, completed);
        self.fault_on_audit_failure(result)?;
        header.generation = completed.0;
        header.generation_mac = completed.1;
        header.pki_digest = completed.3;
        Ok(())
    }
}
