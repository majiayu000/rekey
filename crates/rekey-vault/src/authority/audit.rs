use crate::command::AuditDraft;
use crate::crypto::random_array;
use crate::error::AuthorityError;
use crate::model::{AuditEvent, event_type, outcome};
use crate::now_ms;

use super::{VaultState, Worker};

impl Worker {
    pub(super) fn fault(&mut self, reason: &'static str) {
        self.state = VaultState::Faulted;
        if let (Ok(event_id), Ok(created_at_ms)) = (random_array(), now_ms()) {
            drop(self.store.append_audit(&AuditEvent {
                event_id,
                request_id: None,
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                approval: None,
                event_type: event_type::RUNTIME_FAULTED,
                outcome: outcome::FAILURE,
                reason_code: reason.to_owned(),
                upstream_status: None,
                latency_ms: None,
                created_at_ms,
            }));
        }
    }

    fn audit_event(&self, draft: AuditDraft) -> Result<AuditEvent, AuthorityError> {
        Ok(AuditEvent {
            event_id: random_array()?,
            request_id: draft.request_id,
            session_id: draft.session_id,
            action_id: draft.action_id,
            action_version: draft.action_version,
            credential_id: draft.credential_id,
            credential_version: draft.credential_version,
            authorization: draft.authorization.map(|evidence| *evidence),
            approval: draft.approval,
            event_type: draft.event_type,
            outcome: draft.outcome,
            reason_code: draft.reason_code,
            upstream_status: draft.upstream_status,
            latency_ms: draft.latency_ms,
            created_at_ms: now_ms()?,
        })
    }

    pub(super) fn audit_event_or_fault(
        &mut self,
        draft: AuditDraft,
    ) -> Result<AuditEvent, AuthorityError> {
        match self.audit_event(draft) {
            Ok(event) => Ok(event),
            Err(err) => {
                self.fault("audit-event-construction-failed");
                Err(err)
            }
        }
    }

    pub(super) fn fault_on_audit_failure<T>(
        &mut self,
        result: Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        if matches!(result, Err(AuthorityError::AuditCommitFailed)) {
            self.fault("audit-commit-failed");
        }
        result
    }

    /// Audit failure is fail-closed: the worker faults instead of continuing
    /// without evidence.
    pub(super) fn append_audit(&mut self, draft: AuditDraft) -> Result<(), AuthorityError> {
        let event = self.audit_event_or_fault(draft)?;
        match self.store.append_audit(&event) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.fault("audit-commit-failed");
                Err(err)
            }
        }
    }

    pub(super) fn append_audits(&mut self, drafts: Vec<AuditDraft>) -> Result<(), AuthorityError> {
        let events = drafts
            .into_iter()
            .map(|draft| self.audit_event_or_fault(draft))
            .collect::<Result<Vec<_>, _>>()?;
        match self.store.append_audits(&events) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.fault("audit-commit-failed");
                Err(err)
            }
        }
    }
}
