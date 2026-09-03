use super::vault_dynamic::{
    AcquisitionFailure, CLEANUP_BUDGET, VaultDynamicError, VaultDynamicPrepared,
    VaultDynamicProfile,
};
use super::*;

const MIN_ACTION_TIMEOUT_MS: u32 = 2_000;

impl ActionExecutor {
    pub(super) async fn run_vault_dynamic(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: VaultDynamicPrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let credential_version = prepared.credential_version;
        if action.timeout_ms < MIN_ACTION_TIMEOUT_MS {
            let reason = "vault-dynamic-timeout-too-short";
            started.blocked_until(effect_deadline, reason).await?;
            return Err(BrokerError::Denied(reason));
        }
        let profile = match prepared.profile {
            Ok(profile) => profile,
            Err(error) => {
                started
                    .blocked_until(effect_deadline, error.reason())
                    .await?;
                return Err(BrokerError::Denied(error.reason()));
            }
        };
        let Some(business_deadline) = effect_deadline.checked_sub(CLEANUP_BUDGET) else {
            started.submit_blocked(VaultDynamicError::Deadline.reason());
            return Err(BrokerError::Upstream(VaultDynamicError::Deadline.reason()));
        };
        let acquisition_timeout = business_deadline.saturating_duration_since(Instant::now());
        if acquisition_timeout.is_zero() {
            started.submit_blocked(VaultDynamicError::Deadline.reason());
            return Err(BrokerError::Upstream(VaultDynamicError::Deadline.reason()));
        }
        try_begin_remote_effect(&self.lifecycle, started, effect_deadline).await?;
        started.mark_remote_effect_started();
        effect_kind.store(EFFECT_REVOCABLE_CONNECTOR, Ordering::SeqCst);

        let acquired = profile
            .acquire(
                self.transport.as_ref(),
                acquisition_timeout,
                &prepared.needles,
            )
            .await;
        let acquired = match acquired {
            Ok(acquired) => acquired,
            Err(failure) => {
                return self
                    .finish_failed_acquisition(
                        started,
                        &profile,
                        failure,
                        prepared.needles,
                        business_deadline,
                        effect_deadline,
                    )
                    .await;
            }
        };

        let mut needles = prepared.needles;
        needles.extend(sealing_needles(
            acquired.lease_id.as_bytes(),
            acquired.lease_id.as_bytes(),
        ));
        let mut auth_value = Zeroizing::new(Vec::with_capacity(
            action.auth.prefix.as_str().len() + acquired.value.len(),
        ));
        auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
        auth_value.extend_from_slice(&acquired.value);
        needles.extend(sealing_needles(&acquired.value, &auth_value));

        let lease_ids = vec![acquired.lease_id];
        if let Err(error) = self
            .terminals
            .commit_until(
                business_deadline,
                connector_event(
                    started.context(),
                    rekey_vault::model::event_type::VAULT_LEASE_ISSUED,
                    rekey_vault::model::outcome::SUCCESS,
                    "success".to_owned(),
                ),
            )
            .await
        {
            let cleanup = self
                .revoke_and_audit(started, &profile, &lease_ids, effect_deadline, &needles)
                .await;
            started.submit_indeterminate("connector-audit-failed");
            cleanup?;
            return Err(error);
        }

        let lease_deadline = acquired
            .acquired_at
            .checked_add(acquired.lease_duration)
            .unwrap_or(effect_deadline);
        let final_deadline = effect_deadline.min(lease_deadline);
        let result = if let Some(io_deadline) = final_deadline.checked_sub(CLEANUP_BUDGET) {
            self.send_dynamic_action(request, action, auth_value, io_deadline, &needles)
                .await
        } else {
            DynamicActionResult::definite_error(
                BrokerError::Upstream(VaultDynamicError::Deadline.reason()),
                VaultDynamicError::Deadline.reason(),
            )
        };

        if let Err(error) = self
            .revoke_and_audit(started, &profile, &lease_ids, effect_deadline, &needles)
            .await
        {
            started.submit_indeterminate(cleanup_error_reason(&error));
            return Err(error);
        }

        match result.result {
            Ok((mut response, latency_ms)) => {
                let headers = filter_response_headers(action, &response.headers);
                if !response_metadata_fits(response.status, &headers, response.body.len()) {
                    started
                        .indeterminate_until(effect_deadline, "response-metadata-too-large")
                        .await?;
                    return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
                }
                started
                    .finished_until(
                        effect_deadline,
                        credential_version,
                        response.status,
                        latency_ms,
                    )
                    .await?;
                let body = std::mem::take(&mut *response.body);
                Ok(ExecuteOutcome {
                    upstream_status: response.status,
                    headers,
                    body,
                })
            }
            Err(error) => {
                if result.indeterminate {
                    started
                        .indeterminate_until(effect_deadline, result.reason)
                        .await?;
                } else {
                    started
                        .blocked_until(effect_deadline, result.reason)
                        .await?;
                }
                Err(error)
            }
        }
    }

    async fn finish_failed_acquisition(
        &self,
        started: &mut StartedAuditGuard,
        profile: &VaultDynamicProfile,
        failure: AcquisitionFailure,
        mut needles: Vec<Zeroizing<Vec<u8>>>,
        audit_deadline: Instant,
        effect_deadline: Instant,
    ) -> Result<ExecuteOutcome, BrokerError> {
        for lease_id in &failure.lease_ids {
            needles.extend(sealing_needles(lease_id.as_bytes(), lease_id.as_bytes()));
        }
        if !failure.lease_ids.is_empty() {
            let issued_audit = self
                .terminals
                .commit_until(
                    audit_deadline,
                    connector_event(
                        started.context(),
                        rekey_vault::model::event_type::VAULT_LEASE_ISSUED,
                        rekey_vault::model::outcome::FAILURE,
                        failure.error.reason().to_owned(),
                    ),
                )
                .await;
            if let Err(error) = self
                .revoke_and_audit(
                    started,
                    profile,
                    &failure.lease_ids,
                    effect_deadline,
                    &needles,
                )
                .await
            {
                started.submit_indeterminate(cleanup_error_reason(&error));
                return Err(error);
            }
            if let Err(error) = issued_audit {
                started.submit_indeterminate("connector-audit-failed");
                return Err(error);
            }
        }
        if failure.indeterminate {
            started
                .indeterminate_until(effect_deadline, failure.error.reason())
                .await?;
            if failure.error == VaultDynamicError::SourceReflected {
                Err(BrokerError::ResponseSecurityViolation)
            } else {
                Err(BrokerError::Indeterminate(failure.error.reason()))
            }
        } else {
            started
                .blocked_until(effect_deadline, failure.error.reason())
                .await?;
            if failure.error == VaultDynamicError::SourceReflected {
                Err(BrokerError::ResponseSecurityViolation)
            } else {
                Err(BrokerError::Upstream(failure.error.reason()))
            }
        }
    }

    async fn revoke_and_audit(
        &self,
        started: &mut StartedAuditGuard,
        profile: &VaultDynamicProfile,
        lease_ids: &[Zeroizing<String>],
        effect_deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        let revoke = profile
            .revoke_all(self.transport.as_ref(), lease_ids, effect_deadline, needles)
            .await;
        let (outcome, reason) = match revoke {
            Ok(()) => (rekey_vault::model::outcome::SUCCESS, "success"),
            Err(error) => (rekey_vault::model::outcome::FAILURE, error.reason()),
        };
        self.terminals
            .commit_until(
                effect_deadline,
                connector_event(
                    started.context(),
                    rekey_vault::model::event_type::VAULT_LEASE_REVOKED,
                    outcome,
                    reason.to_owned(),
                ),
            )
            .await?;
        revoke.map_err(|error| BrokerError::Indeterminate(error.reason()))
    }

    async fn send_dynamic_action(
        &self,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        auth_value: Zeroizing<Vec<u8>>,
        io_deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> DynamicActionResult {
        let timeout = io_deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return DynamicActionResult::definite_error(
                BrokerError::Upstream(VaultDynamicError::Deadline.reason()),
                VaultDynamicError::Deadline.reason(),
            );
        }
        let mut upstream = build_upstream(action, request, auth_value);
        upstream.timeout = timeout;
        if !outbound_headers_are_valid(&upstream) {
            return DynamicActionResult::definite_error(
                BrokerError::Denied("invalid-upstream-header"),
                "invalid-upstream-header",
            );
        }
        let send_started = Instant::now();
        let response = tokio::time::timeout_at(
            tokio::time::Instant::from_std(io_deadline),
            self.transport.send(upstream),
        )
        .await;
        let latency_ms = send_started.elapsed().as_millis() as i64;
        let response = match response {
            Err(_) => {
                return DynamicActionResult::indeterminate_error(
                    BrokerError::Indeterminate("upstream-timeout"),
                    "upstream-timeout",
                );
            }
            Ok(Err(error)) => {
                let reason = match &error {
                    crate::upstream::UpstreamError::Blocked(reason) => reason_static(reason),
                    crate::upstream::UpstreamError::ResponseTooLarge => "response-too-large",
                    crate::upstream::UpstreamError::Timeout => "upstream-timeout",
                    crate::upstream::UpstreamError::Transport => "upstream-transport",
                };
                let indeterminate = upstream_failure_is_indeterminate(&error);
                let broker_error = match error {
                    crate::upstream::UpstreamError::ResponseTooLarge => {
                        BrokerError::Domain(DomainError::ResponseTooLarge)
                    }
                    _ if indeterminate => BrokerError::Indeterminate(reason),
                    _ => BrokerError::Upstream(reason),
                };
                return DynamicActionResult {
                    result: Err(broker_error),
                    indeterminate,
                    reason,
                };
            }
            Ok(Ok(response)) => response,
        };
        if contains_secret(&response.body, needles)
            || headers_contain_secret(&response.headers, needles)
        {
            return DynamicActionResult::indeterminate_error(
                BrokerError::ResponseSecurityViolation,
                "reflected-secret",
            );
        }
        DynamicActionResult {
            result: Ok((response, latency_ms)),
            indeterminate: false,
            reason: "finished",
        }
    }
}

fn cleanup_error_reason(error: &BrokerError) -> &'static str {
    match error {
        BrokerError::Indeterminate(reason) | BrokerError::Upstream(reason) => reason,
        _ => "connector-audit-failed",
    }
}

struct DynamicActionResult {
    result: Result<(crate::upstream::UpstreamResponse, i64), BrokerError>,
    indeterminate: bool,
    reason: &'static str,
}

impl DynamicActionResult {
    fn definite_error(error: BrokerError, reason: &'static str) -> Self {
        Self {
            result: Err(error),
            indeterminate: false,
            reason,
        }
    }

    fn indeterminate_error(error: BrokerError, reason: &'static str) -> Self {
        Self {
            result: Err(error),
            indeterminate: true,
            reason,
        }
    }
}
