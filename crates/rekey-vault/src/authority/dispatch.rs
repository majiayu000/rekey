use std::time::Instant;

use crate::command::{AuthorityCommand, StatusInfo, UnlockProof};
use crate::error::AuthorityError;
use crate::model::{event_type, outcome};
use crate::now_ms;

use super::{
    VaultState, Worker, credential_audit, ensure_mutation_current, mutation_expired, unlock_audit,
};

impl Worker {
    /// Returns true when the worker should stop.
    pub(super) fn handle(&mut self, cmd: AuthorityCommand) -> bool {
        match cmd {
            AuthorityCommand::OAuthGrantCreate {
                label,
                payload,
                proof,
                not_after,
                reply,
            } => {
                let result = self.oauth_grant_create(label, payload, proof, not_after);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::OAuthGrantUpdate {
                credential_id,
                expected_version,
                payload,
                proof,
                not_after,
                reply,
            } => {
                let result = self.oauth_grant_update(
                    credential_id,
                    expected_version,
                    payload,
                    proof,
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::RotateOAuthGrant {
                credential_id,
                expected_version,
                payload,
                reason,
                not_after,
                reply,
            } => {
                let result = self.rotate_oauth_grant(
                    credential_id,
                    expected_version,
                    payload,
                    reason,
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PrepareOAuthGrant {
                credential_id,
                reply,
            } => {
                let result = self.prepare_oauth_grant(credential_id);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PrepareAwsStatic {
                credential_id,
                reply,
            } => {
                let result = self.prepare_aws_static(credential_id);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::SshGenerate {
                label,
                mode,
                proof,
                not_after,
                reply,
            } => {
                let result = self.ssh_generate(label, mode, proof, not_after);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::SshImport {
                label,
                private_key,
                proof,
                not_after,
                reply,
            } => {
                let result = self.ssh_import(label, private_key, proof, not_after);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PrepareMtlsConnection {
                request_id,
                connection,
                policy_digest,
                not_after,
                reply,
            } => {
                let result =
                    self.prepare_mtls_connection(request_id, &connection, policy_digest, not_after);
                let result = self.fault_on_integrity(result);
                let _ = reply.send(result);
            }
            AuthorityCommand::SshSign {
                credential_id,
                public_key,
                data,
                started,
                approvals,
                not_after,
                reply,
            } => {
                let result = self.ssh_sign(
                    credential_id,
                    public_key,
                    data,
                    *started,
                    approvals,
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ScanCredentials {
                inputs,
                credentials,
                reply,
            } => {
                let result = self.scan_credentials(inputs, credentials);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ImportEnv {
                request,
                proof,
                not_after,
                reply,
            } => {
                let result = self.import_env(request, proof, not_after);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseAcquireBegin {
                context,
                source,
                not_after,
                reply,
            } => {
                let result = self.lease_begin(context, source, not_after);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseIssued {
                registration_id,
                lease_id,
                request_started_at_ms,
                actual_ttl_seconds,
                renewable,
                not_after,
                reply,
            } => {
                let result = self.lease_update(
                    registration_id,
                    super::lease_journal::LeaseChange::Issued {
                        lease_id,
                        request_started_at_ms,
                        actual_ttl_seconds,
                        renewable,
                    },
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseAcquireAbortDefinite {
                registration_id,
                not_after,
                reply,
            } => {
                let result = self.lease_update(
                    registration_id,
                    super::lease_journal::LeaseChange::AbortDefinite,
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseRenewBegin {
                registration_id,
                not_after,
                reply,
            } => {
                let result = self.lease_update(
                    registration_id,
                    super::lease_journal::LeaseChange::RenewBegin,
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseRenewResult {
                registration_id,
                request_started_at_ms,
                actual_ttl_seconds,
                renewable,
                not_after,
                reply,
            } => {
                let result = self.lease_update(
                    registration_id,
                    super::lease_journal::LeaseChange::RenewResult {
                        request_started_at_ms,
                        actual_ttl_seconds,
                        renewable,
                    },
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseCleanupPrepare {
                registration_id,
                not_after,
                reply,
            } => {
                let result = self.lease_cleanup_prepare(registration_id, not_after);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseCleanupFinish {
                registration_id,
                confirmed,
                not_after,
                reply,
            } => {
                let result = self.lease_update(
                    registration_id,
                    super::lease_journal::LeaseChange::CleanupFinish { confirmed },
                    not_after,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::LeaseRecoveryBatch { reply } => {
                let result = self.lease_batch();
                let _ = reply.send(result);
            }

            AuthorityCommand::DesktopRemember {
                proof,
                lifetime_ms,
                not_after,
                reply,
            } => {
                let result = self.remember_desktop(proof, not_after, lifetime_ms);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::DesktopLock {
                token,
                forget_remembered,
                not_after,
                reply,
            } => {
                let result = self.lock_desktop(token, forget_remembered, not_after);
                let _ = reply.send(result);
            }
            AuthorityCommand::DesktopResume {
                token,
                not_after,
                reply,
            } => {
                let result = self.resume_desktop(token, not_after);
                let _ = reply.send(result);
            }
            AuthorityCommand::DesktopIssue { reply } => {
                let result = self.require_unlocked().map(|_| ()).and_then(|_| {
                    let random = zeroize::Zeroizing::new(crate::crypto::random_array::<32>()?);
                    let token = zeroize::Zeroizing::new(
                        data_encoding::HEXLOWER.encode(&*random).into_bytes(),
                    );
                    self.desktop_session = Some((
                        token.clone(),
                        Instant::now() + self.desktop_session_duration()?,
                    ));
                    Ok(token)
                });
                let _ = reply.send(result);
            }
            AuthorityCommand::DesktopAdd {
                token,
                label,
                secret,
                not_after,
                reply,
            } => {
                let result = ensure_mutation_current(not_after)
                    .and_then(|_| self.verify_desktop(&token))
                    .and_then(|_| {
                        self.insert_credential(
                            label,
                            rekey_domain::credential::CredentialKind::OpaqueToken,
                            secret,
                            not_after,
                        )
                    });
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::DesktopReveal {
                proof,
                credential_id,
                not_after,
                reply,
            } => {
                let reason = match &proof {
                    UnlockProof::Password(_) => "step-up-password",
                    UnlockProof::Recovery(_) => "step-up-recovery",
                    UnlockProof::Presence(_) => "step-up-presence",
                };
                let result = ensure_mutation_current(not_after)
                    .and_then(|_| self.verify_proof(&proof))
                    .and_then(|_| {
                        let record = self.load_verified_credential(credential_id)?;
                        let audit = credential_audit(
                            "credential.reveal_started",
                            credential_id,
                            record.current_version,
                            reason,
                        );
                        self.append_audit(audit)?;
                        ensure_mutation_current(not_after)?;
                        let value = self
                            .prepare_credential(credential_id)?
                            .consume(|value| zeroize::Zeroizing::new(value.to_vec()));
                        self.append_audit(credential_audit(
                            "credential.revealed",
                            credential_id,
                            record.current_version,
                            reason,
                        ))?;
                        Ok(value)
                    });
                let result = match result {
                    Err(error) => {
                        let outcome = if matches!(
                            error,
                            AuthorityError::InvalidUnlockCredential
                                | AuthorityError::Locked
                                | AuthorityError::CredentialRevoked
                                | AuthorityError::CredentialNotFound
                        ) {
                            outcome::DENIED
                        } else {
                            outcome::FAILURE
                        };
                        let mut audit =
                            unlock_audit("credential.reveal_failed", outcome, error.code());
                        audit.credential_id = Some(credential_id);
                        self.append_audit(audit).and(Err(error))
                    }
                    other => other,
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::Status {
                refresh_activity,
                reply,
            } => {
                let policy_state = self.store.load_policy_state();
                let policy_state = self.fault_on_integrity(policy_state);
                let (policy_trust_installed, policy_bundle_persisted) = match policy_state {
                    Ok(state) => (state.trust_installed, state.bundle_activated),
                    Err(error) => {
                        drop(reply.send(Err(error)));
                        return false;
                    }
                };
                if refresh_activity && matches!(self.state, VaultState::Unlocked { .. }) {
                    self.last_activity = Instant::now();
                }
                let idle_for_ms = if matches!(self.state, VaultState::Unlocked { .. }) {
                    self.last_activity.elapsed().as_millis() as u64
                } else {
                    0
                };
                let _ = reply.send(Ok(StatusInfo {
                    state: self.state.name(),
                    rollback: match &self.state {
                        VaultState::RollbackSuspected(context) => Some(context.clone()),
                        _ => None,
                    },
                    vault_id: self.header.vault_id,
                    format_version: self.header.format_version,
                    idle_for_ms,
                    policy_trust_installed,
                    policy_bundle_persisted,
                }));
            }
            AuthorityCommand::ConfirmRollback {
                expected,
                proof,
                not_after,
                reply,
            } => {
                let result = self.confirm_rollback(expected, proof, not_after);
                let _ = reply.send(result);
            }
            AuthorityCommand::Unlock { proof, reply } => {
                let result = self.unlock(proof);
                let _ = reply.send(result);
            }
            AuthorityCommand::Lock {
                reason,
                preserve_desktop,
                reply,
            } => {
                let result = self.set_locked(reason, preserve_desktop);
                let _ = reply.send(result);
            }
            AuthorityCommand::CheckIdle => {
                if matches!(self.state, VaultState::Unlocked { .. })
                    && self.last_activity.elapsed() >= self.config.idle_lock
                {
                    let _ = self.lock("idle-timeout");
                }
            }
            AuthorityCommand::Shutdown { proof, reply } => {
                let result = match (&self.state, proof) {
                    (VaultState::Unlocked { .. }, Some(proof)) => self.verify_proof(&proof),
                    (VaultState::Unlocked { .. }, None) => {
                        Err(AuthorityError::AuthenticationFailed)
                    }
                    _ => Ok(()),
                };
                let ok = result.is_ok();
                if ok {
                    self.presence_grant = None;
                    self.desktop_session = None;
                    self.state = VaultState::Locked;
                }
                let _ = reply.send(result);
                return ok;
            }
            AuthorityCommand::VerifyShutdownProof { proof, reply } => {
                let result = self.verify_shutdown_proof(&proof);
                let result = self.fault_on_integrity(result);
                let _ = reply.send(result);
            }
            AuthorityCommand::VerifyProof { proof, reply } => {
                let result = self
                    .require_unlocked()
                    .map(|_| ())
                    .and_then(|_| self.verify_proof(&proof));
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::AuthorizeLocalApproval {
                proof,
                draft,
                not_after,
                wall_not_after_ms,
                reply,
            } => {
                let result =
                    self.authorize_local_approval(proof, draft, not_after, wall_not_after_ms);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::RotateVrk {
                password,
                recovery,
                not_after,
                reply,
            } => {
                let result = self.rotate_vrk(password, recovery, not_after);
                let _ = reply.send(result);
            }
            AuthorityCommand::RotateDek {
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.rotate_dek(proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PasswordChange {
                proof,
                new_password,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.password_change(proof, new_password, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::RecoveryRotate {
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.recovery_rotate(proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialAdd {
                label,
                kind,
                secret,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_add(label, kind, secret, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialList(reply) => {
                let result = self.credential_list();
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialRotate {
                credential_id,
                secret,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_rotate(credential_id, secret, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialRotateTyped {
                credential_id,
                expected_kind,
                expected_version,
                secret,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_rotate_typed(
                        credential_id,
                        expected_kind,
                        expected_version,
                        secret,
                        proof,
                        not_after,
                    )
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PkiGenerateCrl {
                input,
                proof,
                request_id,
                not_after,
                reply,
            } => {
                let result = self.pki_generate_crl(input, proof, request_id, not_after, &reply);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PkiRevokeCertificate {
                input,
                proof,
                request_id,
                not_after,
                reply,
            } => {
                let result =
                    self.pki_revoke_certificate(input, proof, request_id, not_after, &reply);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PkiIssueClientCsr {
                input,
                csr,
                proof,
                request_id,
                not_after,
                reply,
            } => {
                let result =
                    self.pki_issue_client_csr(input, csr, proof, request_id, not_after, &reply);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::CredentialRevoke {
                credential_id,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.credential_revoke(credential_id, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::TemplateCatalog {
                source,
                package,
                not_after,
                reply,
            } => {
                let result = ensure_mutation_current(not_after)
                    .and_then(|_| self.template_catalog(source, &package, not_after));
                let _ = reply.send(result);
            }
            AuthorityCommand::TemplateInstall {
                input,
                package,
                proof,
                request_id,
                not_after,
                reply,
            } => {
                let result = ensure_mutation_current(not_after).and_then(|_| {
                    self.template_install(*input, &package, proof, request_id, not_after)
                });
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionUpsert {
                existing,
                definition,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.action_upsert(existing, *definition, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionDisable {
                action_id,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.action_disable(action_id, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionList(reply) => {
                let result = self.action_list();
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ActionGet {
                action_id,
                version,
                reply,
            } => {
                let _ = reply.send(self.action_get(action_id, version));
            }
            AuthorityCommand::ActionIdsForCredential {
                credential_id,
                reply,
            } => {
                let result = self.verified_actions().map(|records| {
                    let mut action_ids = records
                        .into_iter()
                        .filter(|(record, _)| record.credential_id == credential_id)
                        .map(|(record, _)| record.action_id)
                        .collect::<Vec<_>>();
                    action_ids.sort_unstable();
                    action_ids.dedup();
                    action_ids
                });
                let _ = reply.send(result);
            }
            AuthorityCommand::PrepareExecutionCredential {
                credential_id,
                request_id,
                action_id,
                action_version,
                deadline,
                reply,
            } => {
                let result = self.prepare_execution_credential(
                    credential_id,
                    request_id,
                    action_id,
                    action_version,
                    deadline,
                );
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PrepareCredential {
                credential_id,
                reply,
            } => {
                let result = self.prepare_credential(credential_id);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::BeginProfileExecution {
                usage,
                preceding,
                started,
                not_after,
                wall_not_after_ms,
                reply,
            } => {
                let result = self.begin_profile_execution(
                    usage,
                    preceding,
                    started,
                    not_after,
                    wall_not_after_ms,
                );
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::SettleProfileExecution {
                request_id,
                measured_output_tokens,
                terminal,
                reply,
            } => {
                let result =
                    self.settle_profile_execution(request_id, measured_output_tokens, terminal);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::ProfileUsage {
                principal_id,
                instance_slug,
                utc_day,
                reply,
            } => {
                let result = self.profile_usage(principal_id, &instance_slug, utc_day);
                drop(reply.send(result));
            }
            AuthorityCommand::AppendAudit {
                draft,
                not_after,
                reply,
            } => {
                let refreshes_idle = matches!(
                    draft.event_type,
                    event_type::EXECUTION_FINISHED
                        | event_type::EXECUTION_BLOCKED
                        | event_type::EXECUTION_INDETERMINATE
                        | event_type::SESSION_CREATED
                        | event_type::SESSION_REVOKED
                        | event_type::POLICY_ACTIVATED
                );
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.append_audit(draft)
                };
                if refreshes_idle {
                    self.touch_if_ok(&result);
                }
                let _ = reply.send(result);
            }
            AuthorityCommand::AppendAudits {
                drafts,
                not_after,
                wall_not_after_ms,
                reply,
            } => {
                let refreshes_idle = drafts.iter().any(|draft| {
                    matches!(
                        draft.event_type,
                        event_type::EXECUTION_FINISHED
                            | event_type::EXECUTION_BLOCKED
                            | event_type::EXECUTION_INDETERMINATE
                            | event_type::SESSION_CREATED
                            | event_type::SESSION_REVOKED
                            | event_type::POLICY_ACTIVATED
                    )
                });
                let result = (|| {
                    if mutation_expired(not_after) {
                        return Err(AuthorityError::AuthorityBusy);
                    }
                    if let Some(deadline_ms) = wall_not_after_ms
                        && now_ms()? >= deadline_ms
                    {
                        return Err(AuthorityError::AuthorityBusy);
                    }
                    self.append_audits(drafts)
                })();
                if refreshes_idle {
                    self.touch_if_ok(&result);
                }
                drop(reply.send(result));
            }
            AuthorityCommand::ConsumeWorkloadToken {
                replay_digest,
                expires_at_ms,
                audit,
                not_after,
                reply,
            } => {
                let result = (|| {
                    if mutation_expired(not_after) {
                        return Err(AuthorityError::AuthorityBusy);
                    }
                    self.require_unlocked().map(|_| ())?;
                    let event = self.audit_event_or_fault(audit)?;
                    let result =
                        self.store
                            .consume_workload_token(replay_digest, expires_at_ms, event);
                    self.fault_on_audit_failure(result)
                })();
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::AuditRetentionSet {
                request,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.audit_retention_set(request, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::AuditRetentionStatus { reply } => {
                let result = self.audit_retention_status();
                let _ = reply.send(result);
            }
            AuthorityCommand::AuditRetentionMaintenance { not_after, reply } => {
                let result = if mutation_expired(Some(not_after)) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.audit_retention_maintenance(not_after)
                };
                let _ = reply.send(result);
            }
            AuthorityCommand::AuditPrune {
                request,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.audit_prune(request, proof, not_after)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::AuditQuery { query, reply } => {
                let result = if matches!(self.state, VaultState::Faulted) {
                    Err(AuthorityError::Faulted)
                } else {
                    let result = self.store.audit_query(&query);
                    self.fault_on_integrity(result)
                };
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::PolicyMaterial { reply } => {
                let result = self.policy_material();
                let result = self.fault_on_integrity(result);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::PolicyTrustInstall {
                input,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.policy_trust_install(input, proof, not_after)
                };
                let result = self.fault_on_integrity(result);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::PolicyBundleActivate {
                input,
                proof,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.policy_bundle_activate(input, proof, not_after)
                };
                let result = self.fault_on_integrity(result);
                self.touch_if_ok(&result);
                drop(reply.send(result));
            }
            AuthorityCommand::FaultIntegrity { reply } => {
                self.fault("persisted-policy-validation-failed");
                drop(reply.send(Err(AuthorityError::StorageIntegrityFailed)));
            }
            AuthorityCommand::Backup {
                output,
                proof,
                reply,
            } => {
                let result = self.backup(output, proof);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::ApprovalOriginPublicKey { reply } => {
                let result = self.approval_origin_public_key();
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
            AuthorityCommand::SignApprovalOrigin { message, reply } => {
                let result = self.sign_approval_origin(message);
                self.touch_if_ok(&result);
                let _ = reply.send(result);
            }
        }
        false
    }
}
