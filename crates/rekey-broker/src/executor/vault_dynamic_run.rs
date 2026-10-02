use super::vault_dynamic::{
    AcquisitionFailure, CLEANUP_BUDGET, VaultDynamicError, VaultDynamicPrepared,
    VaultDynamicProfile, lease_io_deadline,
};
use super::*;

const MIN_ACTION_TIMEOUT_MS: u32 = 2_000;

/// Limited wrapper: only the bound Vault-source entry receives endpoint audit.
pub(super) struct AuditedSourceTransport<'a> {
    inner: &'a dyn UpstreamTransport,
    terminals: &'a crate::audit::TerminalAuditTracker,
    draft: rekey_vault::command::AuditDraft,
    defer_acquire_audit: bool,
    acquisition_deadline: Option<Instant>,
    audit_error: std::sync::Mutex<Option<BrokerError>>,
    acquisition_audit: std::sync::Mutex<Option<rekey_vault::command::AuditDraft>>,
}
impl<'a> AuditedSourceTransport<'a> {
    pub(super) fn execution(
        executor: &'a ActionExecutor,
        ctx: &crate::audit::ExecutionAuditContext,
        version: u64,
        registration: Option<rekey_domain::ids::LeaseRegistrationId>,
        retain: bool,
        acquisition_deadline: Option<Instant>,
    ) -> Self {
        let mut draft = connector_event(
            ctx,
            "vault.source.endpoint",
            "unknown",
            registration
                .map(|id| format!("registration={id};"))
                .unwrap_or_default(),
        );
        draft.credential_version = Some(version);
        Self {
            inner: executor.transport.as_ref(),
            terminals: &executor.terminals,
            draft,
            defer_acquire_audit: retain,
            acquisition_deadline,
            audit_error: std::sync::Mutex::new(None),
            acquisition_audit: std::sync::Mutex::new(None),
        }
    }
    fn cleanup(executor: &'a ActionExecutor, receipt: &rekey_vault::model::LeaseReceipt) -> Self {
        Self {
            inner: executor.transport.as_ref(),
            terminals: &executor.terminals,
            draft: rekey_vault::command::AuditDraft {
                request_id: None,
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: Some(receipt.credential_id),
                credential_version: Some(receipt.credential_version),
                authorization: None,
                approval: None,
                event_type: "vault.source.endpoint",
                outcome: "unknown",
                reason_code: format!("registration={};", receipt.registration_id),
                upstream_status: None,
                latency_ms: None,
            },
            defer_acquire_audit: false,
            acquisition_deadline: None,
            audit_error: std::sync::Mutex::new(None),
            acquisition_audit: std::sync::Mutex::new(None),
        }
    }
    pub(super) async fn commit_acquisition(&self, deadline: Instant) {
        let draft = self.acquisition_audit.lock().unwrap().take();
        if let Some(draft) = draft {
            let _ = self
                .record_audit_result(self.terminals.commit_until(deadline, draft).await, deadline);
        }
    }
    fn record_audit_result(
        &self,
        result: Result<(), BrokerError>,
        deadline: Instant,
    ) -> Result<(), crate::upstream::UpstreamError> {
        let error = match result {
            Err(error) => Some(error),
            Ok(()) if Instant::now() >= deadline => Some(BrokerError::Upstream("upstream-timeout")),
            Ok(()) => None,
        };
        if let Some(error) = error {
            let transport_error = if matches!(error, BrokerError::Upstream("upstream-timeout")) {
                crate::upstream::UpstreamError::Timeout
            } else {
                crate::upstream::UpstreamError::Transport
            };
            *self.audit_error.lock().unwrap() = Some(error);
            Err(transport_error)
        } else {
            Ok(())
        }
    }
    pub(super) fn take_audit_error(&self) -> Option<BrokerError> {
        self.audit_error.lock().unwrap().take()
    }
    pub(super) fn failed(&self) -> bool {
        self.audit_error.lock().unwrap().is_some()
    }
}
impl Drop for AuditedSourceTransport<'_> {
    fn drop(&mut self) {
        if let Some(mut draft) = self.acquisition_audit.lock().unwrap().take() {
            draft.outcome = "unknown";
            self.terminals.submit(draft);
        }
    }
}
struct SourceAuditGuard<'a> {
    terminals: &'a crate::audit::TerminalAuditTracker,
    draft: Option<rekey_vault::command::AuditDraft>,
    trace: crate::upstream::SourceTrace,
    operation: &'static str,
}
impl SourceAuditGuard<'_> {
    fn draft(&mut self) -> rekey_vault::command::AuditDraft {
        let mut draft = self.draft.take().unwrap();
        let trace = self.trace.lock().unwrap();
        draft.outcome = trace.outcome;
        draft.reason_code.push_str(&format!(
            "operation={};phase={}",
            self.operation, trace.phase
        ));
        if let Some(ip) = trace.selected_ip {
            draft.reason_code.push_str(&format!(";selected_ip={ip}"));
        }
        draft
    }
}
impl Drop for SourceAuditGuard<'_> {
    fn drop(&mut self) {
        if self.draft.is_some() {
            self.trace.lock().unwrap().outcome = "unknown";
            let draft = self.draft();
            self.terminals.submit(draft);
        }
    }
}
impl UpstreamTransport for AuditedSourceTransport<'_> {
    fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        self.inner.send(request)
    }
    fn send_vault_source<'a>(
        &'a self,
        request: UpstreamRequest,
        binding: &'a crate::upstream::SourceEndpoint,
        deadline: Instant,
        trace: crate::upstream::SourceTrace,
    ) -> crate::upstream::UpstreamFuture<'a> {
        Box::pin(async move {
            let operation = match request.path.as_str() {
                "/v1/sys/leases/renew" => "renew",
                "/v1/sys/leases/revoke" => "revoke",
                "/v1/auth/token/revoke-self" => "revoke-self",
                _ if request.path.starts_with("/v1/auth/") && request.path.ends_with("/login") => {
                    "login"
                }
                _ if request.path.contains("/creds/") => "acquire",
                _ => "read",
            };
            let deadline = if matches!(operation, "acquire" | "login") {
                self.acquisition_deadline
                    .map(|end| end.min(deadline))
                    .unwrap_or(deadline)
            } else {
                deadline
            };
            let mut guard = SourceAuditGuard {
                terminals: self.terminals,
                draft: Some(self.draft.clone()),
                trace: trace.clone(),
                operation,
            };
            let result = if Instant::now() >= deadline {
                Err(crate::upstream::UpstreamError::Timeout)
            } else {
                tokio::time::timeout_at(
                    deadline.into(),
                    self.inner
                        .send_vault_source(request, binding, deadline, trace.clone()),
                )
                .await
                .unwrap_or(Err(crate::upstream::UpstreamError::Timeout))
            };
            if result.is_err() || Instant::now() >= deadline {
                trace.lock().unwrap().outcome =
                    if matches!(result, Err(crate::upstream::UpstreamError::Blocked(_))) {
                        "denied"
                    } else {
                        "unknown"
                    };
            }
            let draft = guard.draft();
            if self.defer_acquire_audit && matches!(operation, "acquire" | "login") {
                // Decode and retain lease candidates before the result-audit await.
                *self.acquisition_audit.lock().unwrap() = Some(draft);
                return result;
            }
            self.record_audit_result(self.terminals.commit_until(deadline, draft).await, deadline)?;
            result
        })
    }
}

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
        let ctx = started.context();
        let intent = deadline::await_authority(
            business_deadline,
            self.authority.lease_acquire_begin(
                rekey_vault::model::LeaseExecutionContext {
                    request_id: ctx.request_id,
                    session_id: ctx.session_id,
                    action_id: ctx.action.action_id,
                    action_version: ctx.action.version,
                    credential_id: ctx.credential_id,
                    credential_version,
                },
                profile.source_ref(),
                Some(business_deadline),
            ),
        )
        .await?;
        let registration_id = intent.registration_id;
        let acquisition_timeout = business_deadline.saturating_duration_since(Instant::now());
        if !self.lifecycle.try_begin_remote_effect() || acquisition_timeout.is_zero() {
            deadline::await_authority(
                effect_deadline,
                self.authority
                    .lease_abort_definite(registration_id, Some(effect_deadline)),
            )
            .await?;
            let reason = if acquisition_timeout.is_zero() {
                VaultDynamicError::Deadline.reason()
            } else {
                VaultDynamicError::Cancelled.reason()
            };
            started.blocked_until(effect_deadline, reason).await?;
            return Err(if acquisition_timeout.is_zero() {
                BrokerError::Upstream(reason)
            } else {
                BrokerError::Authority(AuthorityError::Draining)
            });
        }
        started.mark_remote_effect_started();
        effect_kind.store(EFFECT_REVOCABLE_CONNECTOR, Ordering::SeqCst);

        let source_transport = AuditedSourceTransport::execution(
            self,
            started.context(),
            credential_version,
            Some(registration_id),
            true,
            Some(business_deadline),
        );
        let acquired = profile
            .acquire(&source_transport, acquisition_timeout, &prepared.needles)
            .await;
        source_transport.commit_acquisition(business_deadline).await;
        let acquired = match acquired {
            Ok(acquired) if source_transport.failed() => {
                let ids = vec![acquired.lease_id];
                let mut needles = prepared.needles;
                needles.extend(sealing_needles(&acquired.value, &acquired.value));
                needles.extend(sealing_needles(ids[0].as_bytes(), ids[0].as_bytes()));
                let _ = profile
                    .revoke_all(&source_transport, &ids, effect_deadline, &needles)
                    .await;
                started.submit_indeterminate("connector-audit-failed");
                return Err(BrokerError::Indeterminate("connector-audit-failed"));
            }
            Ok(acquired) => acquired,
            Err(mut failure) => {
                if source_transport.failed() {
                    failure.indeterminate = true;
                    failure.error = VaultDynamicError::SourceTransport;
                }
                return self
                    .finish_failed_acquisition(
                        started,
                        (&profile, &source_transport),
                        registration_id,
                        failure,
                        prepared.needles,
                        effect_deadline,
                    )
                    .await;
            }
        };

        let mut needles = prepared.needles;
        let mut auth_value = Zeroizing::new(Vec::with_capacity(
            action.auth.prefix.as_str().len() + acquired.value.len(),
        ));
        auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
        auth_value.extend_from_slice(&acquired.value);
        needles.extend(sealing_needles(&acquired.value, &auth_value));
        let renewal_needles_len = needles.len();
        needles.extend(sealing_needles(
            acquired.lease_id.as_bytes(),
            acquired.lease_id.as_bytes(),
        ));

        let lease_ids = vec![acquired.lease_id];
        if deadline::await_authority(
            business_deadline,
            self.authority.lease_record_issued(
                registration_id,
                rekey_vault::secret::SecretInput::from_slice(lease_ids[0].as_bytes()),
                acquired.acquired_at_ms,
                acquired.lease_duration.as_secs(),
                acquired.renewable,
                Some(business_deadline),
            ),
        )
        .await
        .is_err()
        {
            // The ID is already held locally. A failed/unknown durable ACK
            // permits only the existing bounded emergency exact revoke.
            let cleanup = profile
                .revoke_all(&source_transport, &lease_ids, effect_deadline, &needles)
                .await;
            started.submit_indeterminate("connector-audit-failed");
            cleanup.map_err(|e| BrokerError::Indeterminate(e.reason()))?;
            return Err(BrokerError::Indeterminate("connector-audit-failed"));
        }

        let initial_io_deadline = lease_io_deadline(
            effect_deadline,
            acquired.acquired_at,
            acquired.lease_duration,
        );
        let io_deadline = match initial_io_deadline {
            Some(deadline) if acquired.renewable && deadline < business_deadline => {
                self.renew_dynamic_lease(
                    (&profile, &source_transport),
                    registration_id,
                    &lease_ids[0],
                    deadline,
                    effect_deadline,
                    &needles[..renewal_needles_len],
                )
                .await
            }
            Some(deadline) => Ok(deadline),
            None => Err(BrokerError::Indeterminate(
                VaultDynamicError::Deadline.reason(),
            )),
        };
        let result = match io_deadline {
            Ok(deadline) => {
                self.send_dynamic_action(request, action, auth_value, deadline, &needles)
                    .await
            }
            Err(error) => {
                let reason = cleanup_error_reason(&error);
                DynamicActionResult::indeterminate_error(error, reason)
            }
        };

        if let Err(error) = self
            .cleanup_registered(
                registration_id,
                &source_transport,
                &profile,
                &lease_ids,
                effect_deadline,
                &needles,
            )
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
                    stream_status: None,
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

    async fn renew_dynamic_lease(
        &self,
        source: (&VaultDynamicProfile, &AuditedSourceTransport<'_>),
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        lease_id: &str,
        initial_io_deadline: Instant,
        effect_deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<Instant, BrokerError> {
        let (profile, source_transport) = source;
        if initial_io_deadline <= Instant::now() {
            return Err(BrokerError::Indeterminate(
                VaultDynamicError::Deadline.reason(),
            ));
        }
        if !self.lifecycle.try_begin_remote_effect() {
            return Err(BrokerError::Indeterminate(
                VaultDynamicError::Cancelled.reason(),
            ));
        }
        deadline::await_authority(
            initial_io_deadline,
            self.authority
                .lease_renew_begin(registration_id, Some(initial_io_deadline)),
        )
        .await
        .map_err(|_| BrokerError::Indeterminate("connector-audit-failed"))?;

        let renew = if !self.lifecycle.try_begin_remote_effect() {
            Err(VaultDynamicError::Cancelled)
        } else {
            tokio::select! {
                biased;
                _ = wait_for_cancel(self.lifecycle.subscribe_cancel()) => Err(VaultDynamicError::Cancelled),
                result = profile.renew(source_transport, lease_id, initial_io_deadline, effect_deadline, needles) => result,
            }
        };
        let journal_deadline = effect_deadline
            .checked_sub(CLEANUP_BUDGET)
            .unwrap_or(effect_deadline);
        let (requested_at_ms, ttl, renewable) = match &renew {
            Ok(receipt) => (
                receipt.requested_at_ms,
                Some(receipt.lease_duration),
                receipt.renewable,
            ),
            Err(_) => (0, None, false),
        };
        deadline::await_authority(
            journal_deadline,
            self.authority.lease_record_renewal(
                registration_id,
                requested_at_ms,
                ttl,
                renewable,
                Some(journal_deadline),
            ),
        )
        .await
        .map_err(|_| BrokerError::Indeterminate("connector-audit-failed"))?;
        renew
            .map(|receipt| receipt.io_deadline)
            .map_err(|error| BrokerError::Indeterminate(error.reason()))
    }

    async fn finish_failed_acquisition(
        &self,
        started: &mut StartedAuditGuard,
        source: (&VaultDynamicProfile, &AuditedSourceTransport<'_>),
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        failure: AcquisitionFailure,
        mut needles: Vec<Zeroizing<Vec<u8>>>,
        effect_deadline: Instant,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let (profile, source_transport) = source;
        for id in &failure.lease_ids {
            needles.extend(sealing_needles(id.as_bytes(), id.as_bytes()));
        }
        if !failure.lease_ids.is_empty() {
            // Malformed responses do not prove a unique registered ID. Keep
            // the durable intent unknown while preserving bounded candidate cleanup.
            if let Err(error) = profile
                .revoke_all(
                    source_transport,
                    &failure.lease_ids,
                    effect_deadline,
                    &needles,
                )
                .await
            {
                started.submit_indeterminate(error.reason());
                return Err(BrokerError::Indeterminate(error.reason()));
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
            deadline::await_authority(
                effect_deadline,
                self.authority
                    .lease_abort_definite(registration_id, Some(effect_deadline)),
            )
            .await
            .map_err(|_| BrokerError::Indeterminate("connector-audit-failed"))?;
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

    async fn cleanup_registered(
        &self,
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        emergency_transport: &AuditedSourceTransport<'_>,
        emergency_profile: &VaultDynamicProfile,
        emergency_ids: &[Zeroizing<String>],
        effect_deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        let prepared = match deadline::await_authority(
            effect_deadline,
            self.authority
                .lease_prepare_cleanup(registration_id, Some(effect_deadline)),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(_) => {
                let cleanup = emergency_profile
                    .revoke_all(emergency_transport, emergency_ids, effect_deadline, needles)
                    .await;
                cleanup.map_err(|e| BrokerError::Indeterminate(e.reason()))?;
                return Err(BrokerError::Indeterminate("connector-audit-failed"));
            }
        };
        let historical_transport = AuditedSourceTransport::cleanup(self, prepared.receipt());
        let revoke = super::vault_dynamic::revoke_prepared(
            prepared,
            &historical_transport,
            effect_deadline,
            needles,
        )
        .await;
        deadline::await_authority(
            effect_deadline,
            self.authority.lease_finish_cleanup(
                registration_id,
                revoke.is_ok(),
                Some(effect_deadline),
            ),
        )
        .await
        .map_err(|_| BrokerError::Indeterminate("connector-audit-failed"))?;
        revoke.map_err(|error| BrokerError::Indeterminate(error.reason()))
    }

    pub(crate) async fn lease_journal_status(
        &self,
    ) -> Result<rekey_domain::ipc::LeaseJournalStatus, BrokerError> {
        Ok(journal_status(
            self.authority.lease_recovery_batch().await?.counts,
        ))
    }

    pub(crate) async fn recover_vault_leases(
        &self,
        perform: bool,
    ) -> Result<rekey_domain::ipc::LeaseRecoverySummary, BrokerError> {
        use rekey_domain::ipc::{LeaseRecoveryEntry, LeaseRecoveryOutcome, LeaseRecoverySummary};
        let total = Instant::now() + Duration::from_secs(8);
        let batch = deadline::await_authority(total, self.authority.lease_recovery_batch()).await?;
        if let Some(error) = batch.unavailable {
            return Err(error.into());
        }
        if !perform {
            return Ok(LeaseRecoverySummary {
                performed: false,
                journal: journal_status(batch.counts),
                deferred: 0,
                leases: Vec::new(),
            });
        }
        let known_count = batch.counts.pending.saturating_sub(batch.counts.unknown);
        let mut leases = Vec::new();
        for receipt in batch.known {
            let one = (Instant::now() + Duration::from_secs(1)).min(total);
            let provider_deadline = (Instant::now() + Duration::from_millis(500)).min(one);
            let mut outcome = LeaseRecoveryOutcome::Deferred;
            let mut updated_at_ms = receipt.updated_at_ms;
            if Instant::now() < provider_deadline {
                self.lifecycle.reject_if_busy()?;
                match deadline::await_authority(
                    provider_deadline,
                    self.authority
                        .lease_prepare_cleanup(receipt.registration_id, Some(provider_deadline)),
                )
                .await
                {
                    Ok(prepared) => {
                        updated_at_ms = prepared.receipt().updated_at_ms;
                        self.lifecycle.reject_if_busy()?;
                        let historical_transport =
                            AuditedSourceTransport::cleanup(self, prepared.receipt());
                        let revoke = tokio::time::timeout_at(
                            provider_deadline.into(),
                            super::vault_dynamic::revoke_prepared(
                                prepared,
                                &historical_transport,
                                provider_deadline,
                                &[],
                            ),
                        )
                        .await
                        .unwrap_or(Err(VaultDynamicError::Deadline));
                        if matches!(revoke, Err(VaultDynamicError::InvalidCredential)) {
                            self.authority.fault_integrity().await?;
                            return Err(BrokerError::Authority(
                                AuthorityError::StorageIntegrityFailed,
                            ));
                        }
                        outcome = LeaseRecoveryOutcome::Unconfirmed;
                        match deadline::await_authority(
                            one,
                            self.authority.lease_finish_cleanup(
                                receipt.registration_id,
                                revoke.is_ok(),
                                Some(one),
                            ),
                        )
                        .await
                        {
                            Ok(result) => {
                                updated_at_ms = result.updated_at_ms;
                                if revoke.is_ok() {
                                    outcome = LeaseRecoveryOutcome::Complete;
                                }
                            }
                            Err(error) if journal_deadline_error(&error) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) if journal_deadline_error(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            leases.push(LeaseRecoveryEntry {
                registration_id: receipt.registration_id,
                credential_id: receipt.credential_id,
                credential_version: receipt.credential_version,
                outcome,
                updated_at_ms,
            });
        }
        let attempted = leases
            .iter()
            .filter(|entry| entry.outcome != LeaseRecoveryOutcome::Deferred)
            .count() as u64;
        let final_batch =
            deadline::await_authority(total, self.authority.lease_recovery_batch()).await?;
        if let Some(error) = final_batch.unavailable {
            return Err(error.into());
        }
        let final_counts = final_batch.counts;
        Ok(LeaseRecoverySummary {
            performed: true,
            journal: journal_status(final_counts),
            deferred: known_count.saturating_sub(attempted),
            leases,
        })
    }

    async fn send_dynamic_action(
        &self,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        auth_value: Zeroizing<Vec<u8>>,
        io_deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> DynamicActionResult {
        if !self.lifecycle.try_begin_remote_effect() {
            return DynamicActionResult::definite_error(
                BrokerError::Authority(AuthorityError::Draining),
                VaultDynamicError::Cancelled.reason(),
            );
        }
        let timeout = io_deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return DynamicActionResult::definite_error(
                BrokerError::Upstream(VaultDynamicError::Deadline.reason()),
                VaultDynamicError::Deadline.reason(),
            );
        }
        let mut upstream = match build_upstream(action, request, auth_value) {
            Ok(upstream) => upstream,
            Err(reason) => {
                return DynamicActionResult::definite_error(BrokerError::Denied(reason), reason);
            }
        };
        upstream.timeout = timeout;
        if !outbound_headers_are_valid(&upstream) {
            return DynamicActionResult::definite_error(
                BrokerError::Denied("invalid-upstream-header"),
                "invalid-upstream-header",
            );
        }
        let send_started = Instant::now();
        let response = tokio::select! {
            biased;
            _ = wait_for_cancel(self.lifecycle.subscribe_cancel()) => {
                return DynamicActionResult::indeterminate_error(
                    BrokerError::Indeterminate("cancelled-after-remote-effect"),
                    "cancelled-after-remote-effect",
                );
            }
            response = tokio::time::timeout_at(
                tokio::time::Instant::from_std(io_deadline),
                self.transport.send(upstream),
            ) => response,
        };
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

pub(crate) fn journal_status(
    counts: rekey_vault::model::LeaseJournalCounts,
) -> rekey_domain::ipc::LeaseJournalStatus {
    rekey_domain::ipc::LeaseJournalStatus {
        verified: counts.verified,
        pending: counts.pending,
        unknown: counts.unknown,
        complete: counts.complete,
    }
}
fn journal_deadline_error(error: &BrokerError) -> bool {
    matches!(
        error,
        BrokerError::Authority(AuthorityError::AuthorityBusy)
            | BrokerError::Upstream("upstream-timeout")
    )
}
