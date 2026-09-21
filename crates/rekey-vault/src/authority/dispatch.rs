use std::time::Instant;

use crate::command::{AuthorityCommand, StatusInfo};
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
            AuthorityCommand::DesktopRemember {
                proof,
                not_after,
                reply,
            } => {
                let result = self.remember_desktop(proof, not_after);
                self.touch_if_ok(&result);
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
                token,
                credential_id,
                not_after,
                reply,
            } => {
                let result = ensure_mutation_current(not_after)
                    .and_then(|_| self.verify_desktop(&token))
                    .and_then(|_| {
                        let record = self.load_verified_credential(credential_id)?;
                        let audit = credential_audit(
                            "credential.reveal_started",
                            credential_id,
                            record.current_version,
                            "desktop-session",
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
                            "desktop-session",
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
                    vault_id: self.header.vault_id,
                    format_version: self.header.format_version,
                    idle_for_ms,
                    policy_trust_installed,
                    policy_bundle_persisted,
                }));
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
                    self.desktop_session = None;
                    self.state = VaultState::Locked;
                }
                let _ = reply.send(result);
                return ok;
            }
            AuthorityCommand::VerifyProof { proof, reply } => {
                let result = self
                    .require_unlocked()
                    .map(|_| ())
                    .and_then(|_| self.verify_proof(&proof));
                self.touch_if_ok(&result);
                let _ = reply.send(result);
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
                password,
                not_after,
                reply,
            } => {
                let result = if mutation_expired(not_after) {
                    Err(AuthorityError::AuthorityBusy)
                } else {
                    self.recovery_rotate(password, not_after)
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
                let records = self.store.list_actions_for_credential(credential_id);
                let result = self.fault_on_integrity(records).map(|records| {
                    let mut action_ids = records
                        .into_iter()
                        .map(|record| record.action_id)
                        .collect::<Vec<_>>();
                    action_ids.sort_unstable();
                    action_ids.dedup();
                    action_ids
                });
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
