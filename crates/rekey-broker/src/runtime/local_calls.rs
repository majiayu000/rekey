//! Process-local request approvals. There is no local capability or session grant.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rekey_domain::ids::{ApprovalId, ApprovalRequestId};
use rekey_domain::ipc::{self, ApprovalChallenge, LocalApprovalState};
use tokio::sync::Notify;
use zeroize::{Zeroize, Zeroizing};

use crate::error::BrokerError;
use crate::lifecycle::ConnectionExecutionPermit;

#[derive(Default)]
pub(crate) struct LocalCalls {
    windows:
        Mutex<BTreeMap<(String, String, rekey_domain::ids::PolicyRuleId, String), WindowApproval>>,
    access: Mutex<BTreeMap<rekey_domain::ids::RequestId, AccessRequest>>,
    blocked: Mutex<BTreeSet<String>>,
    rates: Mutex<BTreeMap<String, (Instant, u32)>>,
    approvals: Mutex<BTreeMap<ApprovalRequestId, LocalCallApproval>>,
    pub(crate) changed: Notify,
}

#[derive(Clone)]
pub(crate) struct LocalCallApproval {
    pub(crate) challenge: ApprovalChallenge,
    pub(crate) caller: String,
    pub(crate) request_context: Option<rekey_domain::audit::RequestAuditContext>,
    pub(crate) review_sha256: String,
    pub(crate) review: Zeroizing<Vec<u8>>,
    pub(crate) deadline: Instant,
    pub(crate) state: LocalApprovalState,
    pub(crate) approval_id: Option<ApprovalId>,
    pub(crate) external_evidence: Vec<rekey_vault::model::ApprovalEvidence>,
    pub(crate) reserved: bool,
}
impl LocalCallApproval {
    pub(crate) fn response(&self) -> ipc::LocalApprovalStateResponse {
        ipc::LocalApprovalStateResponse {
            approval_request_id: self.challenge.approval_request_id,
            state: self.state,
            expires_at_ms: self.challenge.max_expires_at_ms,
        }
    }
    fn refresh(&mut self, now_ms: i64) {
        if matches!(
            self.state,
            LocalApprovalState::Pending | LocalApprovalState::Approved
        ) && (Instant::now() >= self.deadline
            || now_ms < self.challenge.created_at_ms
            || now_ms >= self.challenge.max_expires_at_ms)
        {
            self.state = LocalApprovalState::Expired;
            self.review.zeroize();
        }
    }
}
impl LocalCalls {
    pub(crate) fn admit_rate(
        &self,
        connection: &str,
        max: u32,
        window: Duration,
    ) -> Result<(), BrokerError> {
        self.take_rate(connection, max, window).map(|_| ())
    }

    fn take_rate(
        &self,
        connection: &str,
        max: u32,
        window: Duration,
    ) -> Result<Instant, BrokerError> {
        let mut rates = self.rates.lock().unwrap_or_else(|e| e.into_inner());
        let entry = rates
            .entry(connection.to_owned())
            .or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= window {
            *entry = (Instant::now(), 0);
        }
        if entry.1 >= max {
            return Err(BrokerError::BudgetExceeded {
                reset_at_ms: crate::now_ts()?.as_unix_ms()
                    + window.saturating_sub(entry.0.elapsed()).as_millis() as i64,
            });
        }
        entry.1 += 1;
        Ok(entry.0)
    }

    pub(crate) fn reserve_rate(
        self: &Arc<Self>,
        connection: &str,
        max: u32,
        window: Duration,
    ) -> Result<LocalRateReservation, BrokerError> {
        Ok(LocalRateReservation {
            calls: Arc::clone(self),
            connection: connection.into(),
            window_start: self.take_rate(connection, max, window)?,
            committed: false,
        })
    }
    pub(crate) fn clear(&self) {
        self.approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.windows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.changed.notify_waiters();
    }
    pub(crate) fn register(
        &self,
        approval: LocalCallApproval,
        now_ms: i64,
    ) -> Result<LocalCallApproval, BrokerError> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries.values_mut() {
            entry.refresh(now_ms);
        }
        if let Some(existing) = entries.values().find(|a| {
            a.caller == approval.caller
                && a.challenge.parameter_sha256 == approval.challenge.parameter_sha256
                && a.challenge.policy_sha256 == approval.challenge.policy_sha256
                && (approval.challenge.schema_id.as_str() != "rekey.ssh-sign.v1"
                    || a.challenge.session_id == approval.challenge.session_id)
                && a.state == LocalApprovalState::Pending
        }) {
            return Ok(existing.clone());
        }
        entries.retain(|_, a| {
            matches!(
                a.state,
                LocalApprovalState::Pending | LocalApprovalState::Approved
            )
        });
        if entries.len() >= ipc::APPROVAL_PENDING_MAX {
            return Err(BrokerError::Admission(
                rekey_vault::AuthorityError::AuthorityBusy,
            ));
        }
        entries.insert(approval.challenge.approval_request_id, approval.clone());
        self.changed.notify_waiters();
        Ok(approval)
    }
    pub(crate) fn get(
        &self,
        id: ApprovalRequestId,
        now_ms: i64,
    ) -> Result<LocalCallApproval, BrokerError> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("approval-request-unknown"))?;
        entry.refresh(now_ms);
        Ok(entry.clone())
    }
    pub(crate) fn pending(&self, now_ms: i64) -> Vec<ApprovalChallenge> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries.values_mut() {
            entry.refresh(now_ms);
        }
        let mut pending: Vec<_> = entries
            .values()
            .filter(|a| a.state == LocalApprovalState::Pending)
            .map(|a| a.challenge.clone())
            .collect();
        pending.sort_by_key(|a| (a.created_at_ms, a.approval_request_id));
        pending
    }
    pub(crate) fn review(
        &self,
        id: ApprovalRequestId,
        now_ms: i64,
    ) -> Result<(ipc::LocalApprovalReviewResponse, Zeroizing<Vec<u8>>), BrokerError> {
        let approval = self.get(id, now_ms)?;
        Ok((
            ipc::LocalApprovalReviewResponse {
                record_type: "rekey.approval.local-review.v1".into(),
                approval_request_id: id,
                review_sha256: approval.review_sha256,
                state: approval.state,
                body_len: approval.review.len() as u32,
            },
            approval.review,
        ))
    }
    pub(crate) fn decide(
        &self,
        id: ApprovalRequestId,
        hash: &str,
        approval_id: Option<ApprovalId>,
        now_ms: i64,
    ) -> Result<ipc::LocalApprovalStateResponse, BrokerError> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("approval-request-unknown"))?;
        entry.refresh(now_ms);
        if entry.review_sha256 != hash || entry.state != LocalApprovalState::Pending {
            return Err(BrokerError::Denied("approval-state-conflict"));
        }
        entry.approval_id = approval_id;
        entry.state = if approval_id.is_some() {
            LocalApprovalState::Approved
        } else {
            LocalApprovalState::Cancelled
        };
        let response = entry.response();
        self.changed.notify_waiters();
        Ok(response)
    }
    pub(crate) fn approve_external(
        &self,
        id: ApprovalRequestId,
        expected_review: &str,
        evidence: Vec<rekey_vault::model::ApprovalEvidence>,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<ipc::LocalApprovalStateResponse, BrokerError> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("approval-request-unknown"))?;
        entry.refresh(now_ms);
        if entry.state != LocalApprovalState::Pending
            || entry.review_sha256 != expected_review
            || evidence.is_empty()
            || now_ms >= expires_at_ms
        {
            return Err(BrokerError::Denied("approval-state-conflict"));
        }
        entry.approval_id = evidence[0].approval_id;
        entry.external_evidence = evidence;
        entry.challenge.max_expires_at_ms = entry.challenge.max_expires_at_ms.min(expires_at_ms);
        entry.deadline = entry
            .deadline
            .min(Instant::now() + Duration::from_millis((expires_at_ms - now_ms) as u64));
        entry.state = LocalApprovalState::Approved;
        self.changed.notify_waiters();
        Ok(entry.response())
    }
    pub(crate) fn consume(
        &self,
        id: ApprovalRequestId,
        caller: &str,
        parameter_hash: &str,
        policy_hash: &str,
        now_ms: i64,
    ) -> Result<LocalCallApproval, BrokerError> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("approval-request-unknown"))?;
        entry.refresh(now_ms);
        if entry.caller != caller
            || entry.challenge.parameter_sha256 != parameter_hash
            || entry.challenge.policy_sha256 != policy_hash
            || entry.state != LocalApprovalState::Approved
            || entry.reserved
        {
            return Err(BrokerError::Denied("approval-request-mismatch"));
        }
        entry.state = LocalApprovalState::Consumed;
        entry.review.zeroize();
        self.changed.notify_waiters();
        Ok(entry.clone())
    }

    pub(crate) fn reserve_approval(
        self: &Arc<Self>,
        id: ApprovalRequestId,
        caller: &str,
        parameter_hash: &str,
        policy_hash: &str,
        now_ms: i64,
    ) -> Result<LocalApprovalReservation, BrokerError> {
        let mut entries = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("approval-request-unknown"))?;
        entry.refresh(now_ms);
        if entry.caller != caller
            || entry.challenge.parameter_sha256 != parameter_hash
            || entry.challenge.policy_sha256 != policy_hash
            || entry.state != LocalApprovalState::Approved
        {
            return Err(BrokerError::Denied("approval-request-mismatch"));
        }
        if entry.reserved {
            return Err(BrokerError::Admission(
                rekey_vault::AuthorityError::AuthorityBusy,
            ));
        }
        entry.reserved = true;
        Ok(LocalApprovalReservation {
            calls: Arc::clone(self),
            approval: entry.clone(),
            committed: false,
        })
    }
    pub(crate) async fn await_state(
        &self,
        id: ApprovalRequestId,
        caller: &str,
        timeout_s: u16,
    ) -> Result<ipc::LocalApprovalStateResponse, BrokerError> {
        if timeout_s > 120 {
            return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_s as u64);
        loop {
            let changed = self.changed.notified();
            let entry = self.get(id, crate::now_ts()?.as_unix_ms())?;
            if entry.caller != caller {
                return Err(BrokerError::Denied("approval-owner-mismatch"));
            }
            if entry.state != LocalApprovalState::Pending || tokio::time::Instant::now() >= deadline
            {
                return Ok(entry.response());
            }
            let wake = deadline.min(tokio::time::Instant::from_std(entry.deadline));
            let _ = tokio::time::timeout_at(wake, changed).await;
        }
    }
    pub(crate) fn cancel(
        &self,
        id: ApprovalRequestId,
        caller: &str,
    ) -> Result<ipc::LocalApprovalStateResponse, BrokerError> {
        let entry = self.get(id, crate::now_ts()?.as_unix_ms())?;
        if entry.caller != caller {
            return Err(BrokerError::Denied("approval-owner-mismatch"));
        }
        self.decide(
            id,
            &entry.review_sha256,
            None,
            crate::now_ts()?.as_unix_ms(),
        )
    }
}

// These reservations cross the audit queue before the first durable await.
// If the original receiver disappears, the worker still commits consumption
// with started or rolls it back on rejection; it never re-inserts an approval.
pub(crate) struct LocalApprovalReservation {
    calls: Arc<LocalCalls>,
    pub(crate) approval: LocalCallApproval,
    committed: bool,
}

impl LocalApprovalReservation {
    pub(crate) fn validate(&self, now_ms: i64) -> Result<(), BrokerError> {
        let entry = self
            .calls
            .get(self.approval.challenge.approval_request_id, now_ms)?;
        if entry.reserved && entry.state == LocalApprovalState::Approved {
            Ok(())
        } else {
            Err(BrokerError::Denied("approval-request-mismatch"))
        }
    }

    fn commit(mut self) {
        let mut entries = self
            .calls
            .approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(&self.approval.challenge.approval_request_id) {
            // Authority already checked the approval's deadlines at commit.
            // Do not re-create entries cleared by a lock or policy change.
            if entry.reserved {
                entry.reserved = false;
                entry.state = LocalApprovalState::Consumed;
                entry.review.zeroize();
            }
        }
        self.committed = true;
        self.calls.changed.notify_waiters();
    }
}

impl Drop for LocalApprovalReservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut entries = self
                .calls
                .approvals
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = entries.get_mut(&self.approval.challenge.approval_request_id) {
                entry.reserved = false;
                if let Ok(now) = crate::now_ts() {
                    entry.refresh(now.as_unix_ms());
                }
            }
            self.calls.changed.notify_waiters();
        }
    }
}

pub(crate) struct LocalRateReservation {
    calls: Arc<LocalCalls>,
    connection: String,
    window_start: Instant,
    committed: bool,
}

impl Drop for LocalRateReservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut rates = self.calls.rates.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((window_start, count)) = rates.get_mut(&self.connection)
                && *window_start == self.window_start
            {
                *count = count.saturating_sub(1);
            }
        }
    }
}

pub(crate) struct ConnectionAdmission {
    pub(crate) approval: Option<LocalApprovalReservation>,
    pub(crate) rate: LocalRateReservation,
    pub(crate) permit: ConnectionExecutionPermit,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rekey_domain::authorization::{ApprovalMode, ApproverSpec, ResourceRef, SchemaId};
    use rekey_domain::ids::{ActionId, PolicyRuleId, PrincipalId, SessionId, TenantId};

    pub(crate) fn approved(calls: &Arc<LocalCalls>) -> LocalCallApproval {
        let now = crate::now_ts().unwrap().as_unix_ms();
        let approval = LocalCallApproval {
            challenge: ApprovalChallenge {
                record_type: "rekey.approval.challenge.v2".into(),
                approval_request_id: ApprovalRequestId::new_random(),
                tenant_id: TenantId::new_random(),
                principal_id: PrincipalId::new_random(),
                session_id: SessionId::new_random(),
                action_id: ActionId::new_random(),
                action_version: 1,
                resource: ResourceRef::new("connection".into(), "fixture".into()).unwrap(),
                schema_id: SchemaId::new("test/v1".into()).unwrap(),
                parameter_sha256: "11".repeat(32),
                policy_version: 1,
                policy_sha256: "22".repeat(32),
                policy_rule_id: PolicyRuleId::new_random(),
                mode: ApprovalMode::OneTime,
                approver: ApproverSpec::LocalPresence {},
                max_uses: 1,
                created_at_ms: now,
                max_expires_at_ms: now + 600_000,
            },
            caller: "fixture".into(),
            request_context: None,
            review_sha256: "33".repeat(32),
            review: b"review retained until started".to_vec().into(),
            deadline: Instant::now() + Duration::from_secs(600),
            state: LocalApprovalState::Approved,
            approval_id: Some(ApprovalId::new_random()),
            external_evidence: Vec::new(),
            reserved: false,
        };
        calls.register(approval, now).unwrap()
    }

    pub(crate) fn reserve(
        calls: &Arc<LocalCalls>,
        approval: &LocalCallApproval,
    ) -> Result<LocalApprovalReservation, BrokerError> {
        calls.reserve_approval(
            approval.challenge.approval_request_id,
            &approval.caller,
            &approval.challenge.parameter_sha256,
            &approval.challenge.policy_sha256,
            crate::now_ts().unwrap().as_unix_ms(),
        )
    }

    #[test]
    fn approval_retry_reservation_is_exclusive_and_consumption_is_final() {
        let calls = Arc::new(LocalCalls::default());
        let approval = approved(&calls);
        let first = reserve(&calls, &approval).unwrap();
        assert_eq!(
            reserve(&calls, &approval).err().unwrap().code(),
            "AUTHORITY_BUSY"
        );
        assert!(
            !calls
                .get(
                    approval.challenge.approval_request_id,
                    crate::now_ts().unwrap().as_unix_ms()
                )
                .unwrap()
                .review
                .is_empty()
        );
        drop(first);
        let retry = reserve(&calls, &approval).unwrap();
        retry.commit();
        let consumed = calls
            .get(
                approval.challenge.approval_request_id,
                crate::now_ts().unwrap().as_unix_ms(),
            )
            .unwrap();
        assert_eq!(consumed.state, LocalApprovalState::Consumed);
        assert!(consumed.review.is_empty());
        assert!(reserve(&calls, &approval).is_err());
    }

    #[test]
    fn rejected_reservations_never_revive_expired_cancelled_or_cleared_approvals() {
        for reason in ["expired", "cancelled", "cleared"] {
            let calls = Arc::new(LocalCalls::default());
            let approval = approved(&calls);
            let reservation = reserve(&calls, &approval).unwrap();
            match reason {
                "expired" => {
                    calls
                        .approvals
                        .lock()
                        .unwrap()
                        .get_mut(&approval.challenge.approval_request_id)
                        .unwrap()
                        .deadline = Instant::now();
                }
                "cancelled" => calls.cancel_unconfirmed(approval.challenge.approval_request_id),
                _ => calls.clear(),
            }
            assert!(
                reservation
                    .validate(crate::now_ts().unwrap().as_unix_ms())
                    .is_err()
            );
            drop(reservation);
            assert!(
                reserve(&calls, &approval).is_err(),
                "{reason} must remain invalid"
            );
        }
    }

    #[test]
    fn rejected_rate_reservation_returns_only_its_own_window_slot() {
        let calls = Arc::new(LocalCalls::default());
        let first = calls
            .reserve_rate("fixture", 1, Duration::from_secs(3600))
            .unwrap();
        assert_eq!(
            calls
                .reserve_rate("fixture", 1, Duration::from_secs(3600))
                .err()
                .unwrap()
                .code(),
            "BUDGET_EXCEEDED"
        );
        drop(first);
        let old = calls
            .reserve_rate("fixture", 1, Duration::from_secs(3600))
            .unwrap();
        let mut current = calls.reserve_rate("fixture", 1, Duration::ZERO).unwrap();
        current.committed = true;
        drop(current);
        drop(old);
        assert!(
            calls
                .reserve_rate("fixture", 1, Duration::from_secs(3600))
                .is_err(),
            "old rollback must not erase current window usage"
        );
    }
}

impl ConnectionAdmission {
    pub(crate) fn commit(mut self) -> ConnectionExecutionPermit {
        if let Some(approval) = self.approval.take() {
            approval.commit();
        }
        self.rate.committed = true;
        self.permit.started();
        self.permit
    }
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct AccessRequest {
    pub(crate) request_id: rekey_domain::ids::RequestId,
    pub(crate) caller: String,
    pub(crate) provider: Option<String>,
    pub(crate) connection: Option<String>,
    pub(crate) operation: Option<String>,
    pub(crate) reason: String,
    pub(crate) created_at_ms: i64,
    pub(crate) expires_at_ms: i64,
    pub(crate) status: ipc::AccessRequestStatus,
    #[serde(skip)]
    deadline: Instant,
}
#[derive(serde::Serialize)]
pub(crate) struct AccessList {
    pub(crate) requests: Vec<AccessRequest>,
    pub(crate) blocked_callers: Vec<String>,
}
impl AccessRequest {
    fn refresh(&mut self, now: i64) {
        if self.status == ipc::AccessRequestStatus::Pending
            && (Instant::now() >= self.deadline
                || now < self.created_at_ms
                || now >= self.expires_at_ms)
        {
            self.status = ipc::AccessRequestStatus::Expired;
        }
    }
}
impl LocalCalls {
    pub(crate) fn create_access(
        &self,
        caller: &str,
        request: ipc::RequestAccessMeta,
    ) -> Result<ipc::RequestAccessResponse, BrokerError> {
        if request.reason.is_empty()
            || request.reason.chars().count() > 500
            || request.provider.is_some() == request.connection.is_some()
            || request
                .provider
                .as_ref()
                .or(request.connection.as_ref())
                .is_none_or(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
            || request
                .operation
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
        {
            return Err(ipc::FrameError::InvalidField.into());
        }
        if self
            .blocked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(caller)
        {
            return Err(BrokerError::LocalCall(
                "DENIED",
                "access requests from this caller are blocked",
                "Ask the user to review the caller block in Rekey.",
            ));
        }
        self.admit_rate(&format!("access:{caller}"), 3, Duration::from_secs(60))
            .map_err(|error| {
                if matches!(error, BrokerError::LocalCall("BUDGET_EXCEEDED", _, _)) {
                    BrokerError::LocalCall(
                        "RATE_LIMITED",
                        "access request limit reached",
                        "Retry after the one-minute request window resets.",
                    )
                } else {
                    error
                }
            })?;
        let now = crate::now_ts()?.as_unix_ms();
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries.values_mut() {
            entry.refresh(now);
        }
        entries.retain(|_, a| Instant::now() < a.deadline);
        if entries.len() >= ipc::APPROVAL_PENDING_MAX {
            return Err(rekey_vault::AuthorityError::AuthorityBusy.into());
        }
        let id = crate::random_id(rekey_domain::ids::RequestId::from_random_bytes)?;
        let expires_at_ms = now + 600_000;
        entries.insert(
            id,
            AccessRequest {
                request_id: id,
                caller: caller.into(),
                provider: request.provider,
                connection: request.connection,
                operation: request.operation,
                reason: request.reason,
                created_at_ms: now,
                expires_at_ms,
                status: ipc::AccessRequestStatus::Pending,
                deadline: Instant::now() + Duration::from_secs(600),
            },
        );
        self.changed.notify_waiters();
        Ok(ipc::RequestAccessResponse {
            request_id: id,
            expires_at_ms,
        })
    }
    pub(crate) fn access_list(&self) -> Result<AccessList, BrokerError> {
        let now = crate::now_ts()?.as_unix_ms();
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries.values_mut() {
            entry.refresh(now);
        }
        Ok(AccessList {
            requests: entries.values().cloned().collect(),
            blocked_callers: self
                .blocked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect(),
        })
    }
    pub(crate) fn access_get(
        &self,
        id: rekey_domain::ids::RequestId,
    ) -> Result<AccessRequest, BrokerError> {
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("access-request-unknown"))?;
        entry.refresh(crate::now_ts()?.as_unix_ms());
        Ok(entry.clone())
    }
    pub(crate) fn resolve_access(
        &self,
        id: rekey_domain::ids::RequestId,
        granted: bool,
    ) -> Result<ipc::AwaitAccessResponse, BrokerError> {
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("access-request-unknown"))?;
        entry.refresh(crate::now_ts()?.as_unix_ms());
        if entry.status != ipc::AccessRequestStatus::Pending {
            return Err(BrokerError::Denied("access-request-not-pending"));
        }
        entry.status = if granted {
            ipc::AccessRequestStatus::Granted
        } else {
            ipc::AccessRequestStatus::Rejected
        };
        self.changed.notify_waiters();
        Ok(ipc::AwaitAccessResponse {
            status: entry.status,
        })
    }
    pub(crate) fn block_caller(&self, caller: String, blocked: bool) {
        let mut entries = self.blocked.lock().unwrap_or_else(|e| e.into_inner());
        if blocked {
            entries.insert(caller);
        } else {
            entries.remove(&caller);
        }
    }
    pub(crate) async fn await_access(
        &self,
        id: rekey_domain::ids::RequestId,
        caller: &str,
        timeout_s: u16,
    ) -> Result<ipc::AwaitAccessResponse, BrokerError> {
        if timeout_s > 120 {
            return Err(ipc::FrameError::InvalidField.into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_s as u64);
        loop {
            let changed = self.changed.notified();
            let entry = self.access_get(id)?;
            if entry.caller != caller {
                return Err(BrokerError::Denied("access-owner-mismatch"));
            }
            if entry.status != ipc::AccessRequestStatus::Pending
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(ipc::AwaitAccessResponse {
                    status: entry.status,
                });
            }
            let _ = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::from_std(entry.deadline)),
                changed,
            )
            .await;
        }
    }
}

#[derive(Clone)]
pub(crate) struct WindowApproval {
    pub(crate) request_id: ApprovalRequestId,
    pub(crate) approval_id: ApprovalId,
    pub(crate) deadline: Instant,
    pub(crate) expires_at_ms: i64,
}
impl LocalCalls {
    pub(crate) fn cancel_unconfirmed(&self, id: ApprovalRequestId) {
        if let Some(entry) = self
            .approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&id)
        {
            entry.state = LocalApprovalState::Cancelled;
            entry.review.zeroize();
        }
        self.changed.notify_waiters();
    }
    pub(crate) fn grant_window(
        &self,
        approval: &LocalCallApproval,
        approval_id: ApprovalId,
        seconds: u32,
        policy_expiry: i64,
    ) -> Result<(), BrokerError> {
        if seconds == 0 || seconds > 8 * 3600 {
            return Err(ipc::FrameError::InvalidField.into());
        }
        let Some(rekey_domain::audit::RequestAuditContext::Connection(context)) =
            &approval.request_context
        else {
            return Err(BrokerError::Denied("window-context-missing"));
        };
        let now = crate::now_ts()?.as_unix_ms();
        let expires_at_ms = (now + i64::from(seconds) * 1000).min(policy_expiry);
        let key = (
            approval.challenge.policy_sha256.clone(),
            context.connection.clone(),
            approval.challenge.policy_rule_id,
            approval.caller.clone(),
        );
        self.windows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                key,
                WindowApproval {
                    request_id: approval.challenge.approval_request_id,
                    approval_id,
                    deadline: Instant::now()
                        + Duration::from_millis(expires_at_ms.saturating_sub(now) as u64),
                    expires_at_ms,
                },
            );
        Ok(())
    }
    pub(crate) fn window(
        &self,
        policy: &str,
        connection: &str,
        rule: Option<rekey_domain::ids::PolicyRuleId>,
        caller: &str,
        now: i64,
    ) -> Option<WindowApproval> {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        windows.retain(|_, w| Instant::now() < w.deadline && now < w.expires_at_ms);
        windows
            .get(&(policy.into(), connection.into(), rule?, caller.into()))
            .cloned()
    }
}
