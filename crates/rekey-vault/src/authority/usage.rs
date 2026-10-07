use super::{Worker, ensure_mutation_current};
use crate::{
    command::{AuditDraft, ProfileUsageStart},
    error::AuthorityError,
    model::{UsageAdmission, UsageContext, UsageRecord, UsageTotals, event_type, outcome},
    now_ms,
};
use rekey_domain::{
    audit::{UsageEvidence, UsageSource},
    ids::{PrincipalId, RequestId},
};
use std::time::Instant;

pub(super) fn invalid(reason: &str) -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition(reason.to_owned()).into()
}
fn context(draft: &AuditDraft) -> Result<UsageContext, AuthorityError> {
    let context = UsageContext {
        request_context: draft.request_context.clone(),
        session_id: draft
            .session_id
            .ok_or_else(|| invalid("usage requires session"))?,
        action_id: draft
            .action_id
            .ok_or_else(|| invalid("usage requires action"))?,
        action_version: draft
            .action_version
            .filter(|v| *v > 0 && *v <= i64::MAX as u64)
            .ok_or_else(|| invalid("usage requires action version"))?,
        credential_id: draft
            .credential_id
            .ok_or_else(|| invalid("usage requires credential"))?,
        credential_version: draft.credential_version,
        authorization: draft
            .authorization
            .as_deref()
            .cloned()
            .ok_or_else(|| invalid("usage requires authorization"))?,
    };
    if context.authorization.policy_version == 0
        || context.authorization.policy_version > i64::MAX as u64
        || context.authorization.policy_rule_id.is_none()
        || context.authorization.resource_type.is_empty()
        || context.authorization.resource_id.is_empty()
        || context
            .credential_version
            .is_some_and(|v| v == 0 || v > i64::MAX as u64)
    {
        return Err(invalid("invalid usage context"));
    }
    Ok(context)
}
impl Worker {
    pub(super) fn begin_profile_execution(
        &mut self,
        usage: ProfileUsageStart,
        preceding: Vec<AuditDraft>,
        started: AuditDraft,
        not_after: Instant,
        wall_not_after_ms: Option<i64>,
    ) -> Result<UsageAdmission, AuthorityError> {
        self.require_unlocked()?;
        ensure_mutation_current(Some(not_after))?;
        let now = now_ms()?;
        if wall_not_after_ms.is_some_and(|v| now >= v) {
            return Err(AuthorityError::AuthorityBusy);
        }
        let ctx = context(&started)?;
        if ctx
            .request_context
            .as_ref()
            .is_some_and(|context| match context {
                rekey_domain::audit::RequestAuditContext::Profile(profile) => {
                    profile.instance_slug != usage.instance_slug
                }
                rekey_domain::audit::RequestAuditContext::Connection(connection) => {
                    connection.connection != usage.instance_slug
                }
                rekey_domain::audit::RequestAuditContext::Derived(_) => true,
            })
        {
            return Err(invalid("profile usage instance mismatch"));
        }
        let request_id = started
            .request_id
            .ok_or_else(|| invalid("usage requires request"))?;
        UsageEvidence {
            instance_slug: usage.instance_slug.clone(),
            utc_day: now / 86_400_000,
            output_tokens: 0,
            source: UsageSource::NotApplicable,
        }
        .validate()?;
        if [usage.max_requests_per_day, usage.max_output_tokens_per_day]
            .into_iter()
            .any(|v| v == 0 || v > i64::MAX as u64)
            || usage
                .generation_max_output
                .is_some_and(|v| v == 0 || v > i64::MAX as u64)
            || started.event_type != event_type::EXECUTION_STARTED
            || started.outcome != outcome::SUCCESS
            || started.usage.is_some()
            || started.approval.is_some()
            || started.reason_code.is_empty()
            || started.upstream_status.is_some()
            || started.latency_ms.is_some()
        {
            return Err(invalid("invalid profile execution start"));
        }
        for draft in &preceding {
            if draft.event_type != event_type::APPROVAL_ACCEPTED
                || draft.outcome != outcome::SUCCESS
                || draft.request_id != Some(request_id)
                || context(draft)? != ctx
                || draft.usage.is_some()
                || draft
                    .approval
                    .as_ref()
                    .is_none_or(|v| v.approval_id.is_none())
                || draft.upstream_status.is_some()
                || draft.latency_ms.is_some()
            {
                return Err(invalid("invalid preceding approval audit"));
            }
        }
        let row = UsageRecord {
            request_id,
            principal_id: ctx.authorization.principal_id,
            instance_slug: usage.instance_slug.clone(),
            utc_day: now / 86_400_000,
            started_at_ms: now,
            context_json: serde_json::to_string(&ctx)
                .map_err(|_| invalid("invalid usage context"))?,
            generation_max_output: usage.generation_max_output,
            output_tokens: None,
            source: None,
            terminal_json: None,
            settled_at_ms: None,
        };
        let mut events = preceding
            .into_iter()
            .map(|v| self.audit_event_or_fault(v))
            .collect::<Result<Vec<_>, _>>()?;
        events.push(self.audit_event_or_fault(started)?);
        let result = self.store.begin_profile_execution(
            match &self.state {
                super::VaultState::Unlocked { vrk } => vrk.bytes(),
                _ => return Err(AuthorityError::Locked),
            },
            self.header.vault_id,
            row,
            &usage,
            &events,
            not_after,
            wall_not_after_ms,
        );
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }
    pub(super) fn settle_profile_execution(
        &mut self,
        request_id: RequestId,
        measured: Option<u64>,
        terminal: AuditDraft,
    ) -> Result<(), AuthorityError> {
        self.require_unlocked()?;
        context(&terminal)?;
        if terminal.request_id != Some(request_id)
            || terminal.usage.is_some()
            || terminal.approval.is_some()
            || !matches!(
                terminal.event_type,
                event_type::EXECUTION_FINISHED
                    | event_type::EXECUTION_BLOCKED
                    | event_type::EXECUTION_INDETERMINATE
            )
            || !matches!(
                (terminal.event_type, terminal.outcome),
                (event_type::EXECUTION_FINISHED, outcome::SUCCESS)
                    | (event_type::EXECUTION_BLOCKED, outcome::DENIED)
                    | (event_type::EXECUTION_INDETERMINATE, outcome::UNKNOWN)
            )
            || terminal.reason_code.is_empty()
            || terminal.latency_ms.is_some_and(|v| v < 0)
            || measured.is_some_and(|v| v > i64::MAX as u64)
        {
            return Err(invalid("invalid profile execution terminal"));
        }
        let event = self.audit_event_or_fault(terminal)?;
        let result = self.store.settle_profile_execution(
            match &self.state {
                super::VaultState::Unlocked { vrk } => vrk.bytes(),
                _ => return Err(AuthorityError::Locked),
            },
            self.header.vault_id,
            request_id,
            measured,
            event,
        );
        let result = self.fault_on_integrity(result);
        self.fault_on_audit_failure(result)
    }
    pub(super) fn profile_usage(
        &mut self,
        principal: PrincipalId,
        instance: &str,
        day: i64,
    ) -> Result<UsageTotals, AuthorityError> {
        let key = self.require_unlocked()?;
        UsageEvidence {
            instance_slug: instance.to_owned(),
            utc_day: day,
            output_tokens: 0,
            source: UsageSource::NotApplicable,
        }
        .validate()?;
        let result =
            self.store
                .profile_usage(key.bytes(), self.header.vault_id, principal, instance, day);
        self.fault_on_integrity(result)
    }
}
