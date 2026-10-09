//! Admin channel: unlock, credential/action/session administration, backup,
//! lock, shutdown. Peer must be the state-owner UID; sensitive mutations
//! additionally require a step-up unlock proof in the frame body.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rekey_domain::Timestamp;
use rekey_domain::action::{
    ActionName, ExactPath, FixedHttpAction, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::authorization::Principal;
use rekey_domain::capability::SessionGrant;
use rekey_domain::credential::{CredentialKind, CredentialMetadata, CredentialState};
use rekey_domain::ids::{ActionId, CredentialId, PrincipalId, SessionId, TenantId};
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};
use rekey_vault::AuthorityError;
use rekey_vault::command::{ActionDefinition, AuditDraft, UnlockProof};
use rekey_vault::model::{ActionState, event_type, outcome};
use rekey_vault::secret::SecretInput;
use tokio::net::UnixStream;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::ipc::frame::{FrameIoError, IncomingFrame, read_frame, write_error, write_ok};
use crate::runtime::BrokerCtx;
use crate::session::CreateSessionError;

type AdminResponse = (Vec<u8>, Zeroizing<Vec<u8>>);

const ADMIN_MUTATION_TIMEOUT: Duration = Duration::from_secs(25);

mod audit_query;
mod credential_profiles;
mod github;
mod password_lifecycle;
mod profile;
#[cfg(feature = "lab")]
mod vault_kv;

fn admin_body_limit(message_type: u16, managed: bool) -> u32 {
    let base = match message_type {
        admin_msg::APPROVAL_EXTERNAL_SUBMIT => ipc::METADATA_MAX_BYTES,
        admin_msg::OIDC_LOGOUT => 43,
        admin_msg::DESKTOP_LOGIN
        | admin_msg::DESKTOP_REVEAL
        | admin_msg::DESKTOP_REMEMBER
        | admin_msg::DESKTOP_RESUME => ipc::ADMIN_PROOF_BODY_MAX_BYTES,
        admin_msg::DESKTOP_ADD | admin_msg::TEMPLATE_INSTALL | admin_msg::SSH_KEY => {
            ipc::ADMIN_SECRET_BODY_MAX_BYTES
        }
        admin_msg::TEMPLATE_CATALOG => ipc::ADMIN_SECRET_FIELD_MAX_BYTES,
        admin_msg::UNLOCK_PASSWORD | admin_msg::UNLOCK_RECOVERY => {
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES
        }
        admin_msg::CREDENTIAL_ADD
        | admin_msg::CREDENTIAL_ROTATE
        | admin_msg::CREDENTIAL_ROTATE_MTLS
        | admin_msg::PKI_ISSUE_CLIENT_CSR
        | admin_msg::CREDENTIAL_ROTATE_CA
        | admin_msg::PASSWORD_CHANGE
        | admin_msg::KEY_ROTATE_VRK => ipc::ADMIN_SECRET_BODY_MAX_BYTES,
        admin_msg::CREDENTIAL_ROTATE_GITHUB_APP
        | admin_msg::GITHUB_WEBHOOK_APPLY
        | admin_msg::CREDENTIAL_ROTATE_VAULT_KV
        | admin_msg::CREDENTIAL_ROTATE_KEYCLOAK
        | admin_msg::CREDENTIAL_ROTATE_GCP_SECRET_MANAGER
        | admin_msg::CREDENTIAL_ROTATE_AWS_SECRETS_MANAGER
        | admin_msg::CREDENTIAL_ROTATE_AZURE_KEY_VAULT
        | admin_msg::CREDENTIAL_ROTATE_MACOS_KEYCHAIN
        | admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT
        | admin_msg::CREDENTIAL_ROTATE_VAULT_DYNAMIC => ipc::ADMIN_SECRET_BODY_MAX_BYTES,
        admin_msg::OAUTH_LOGIN
        | admin_msg::ACCESS_RESOLVE
        | admin_msg::IMPORT_ENV
        | admin_msg::APPROVAL_LOCAL_APPROVE
        | admin_msg::APPROVAL_LOCAL_REJECT
        | admin_msg::CREDENTIAL_REVOKE
        | admin_msg::PKI_REVOKE_CERTIFICATE
        | admin_msg::PKI_GENERATE_CRL
        | admin_msg::ACTION_CREATE
        | admin_msg::ACTION_UPDATE
        | admin_msg::ACTION_DISABLE
        | admin_msg::SESSION_CREATE
        | admin_msg::PROFILE_SESSION_CREATE
        | admin_msg::SESSION_REVOKE
        | admin_msg::BACKUP
        | admin_msg::SHUTDOWN
        | admin_msg::POLICY_ACTIVATE
        | admin_msg::POLICY_TRUST_INSTALL
        | admin_msg::AUDIT_PRUNE
        | admin_msg::AUDIT_RETENTION_SET
        | admin_msg::KEY_ROTATE_DEK
        | admin_msg::RECOVERY_ROTATE
        | admin_msg::ROLLBACK_CONFIRM => ipc::ADMIN_PROOF_BODY_MAX_BYTES,
        _ => 0,
    };
    if managed && ipc::managed_admin_operation(message_type).unwrap_or(false) {
        base + ipc::ADMIN_MANAGEMENT_OVERHEAD
    } else {
        base
    }
}

fn proof_from(kind: ProofKind, bytes: &[u8]) -> UnlockProof {
    match kind {
        ProofKind::Password => UnlockProof::Password(SecretInput::from_slice(bytes)),
        ProofKind::Recovery => UnlockProof::Recovery(SecretInput::from_slice(bytes)),
        ProofKind::Presence => UnlockProof::Presence(SecretInput::from_slice(bytes)),
    }
}

fn meta<T: serde::de::DeserializeOwned>(frame: &IncomingFrame) -> Result<T, BrokerError> {
    serde_json::from_slice(&frame.metadata)
        .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))
}

fn empty_meta(frame: &IncomingFrame) -> Result<(), BrokerError> {
    let value: serde_json::Value = meta(frame)?;
    match value {
        serde_json::Value::Object(fields) if fields.is_empty() => Ok(()),
        _ => Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::InvalidField,
        )),
    }
}

fn empty_request(frame: &IncomingFrame) -> Result<(), BrokerError> {
    empty_meta(frame)?;
    if !frame.body.is_empty() {
        return Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::InvalidField,
        ));
    }
    Ok(())
}

fn json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, BrokerError> {
    let metadata = serde_json::to_vec(value)
        .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
    if metadata.len() > ipc::METADATA_MAX_BYTES as usize {
        return Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::SectionTooLarge,
        ));
    }
    Ok(metadata)
}

async fn write_admin_error(
    stream: &mut UnixStream,
    message_type: u16,
    request_id: rekey_domain::ids::RequestId,
    error: &BrokerError,
) -> Result<(), FrameIoError> {
    // A timeout can race with the single commit. Repeating an install creates
    // new Action IDs, so even pre-commit Busy failures conservatively deny retry.
    let unconfirmed_install = message_type == admin_msg::TEMPLATE_INSTALL
        && matches!(
            error,
            BrokerError::Authority(AuthorityError::AuthorityBusy)
                | BrokerError::Admission(AuthorityError::AuthorityBusy)
        );
    let message = if unconfirmed_install {
        "template installation outcome is unconfirmed; inspect Actions and audit; do not retry automatically".to_owned()
    } else {
        error.to_string()
    };
    write_error(
        stream,
        Channel::Admin,
        request_id,
        error.code(),
        &message,
        !unconfirmed_install && error.retryable(),
    )
    .await
}

pub async fn handle_admin_conn(
    mut stream: UnixStream,
    ctx: Arc<BrokerCtx>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        #[cfg(feature = "lab")]
        let managed = ctx.oidc_admin.is_some();
        #[cfg(not(feature = "lab"))]
        let managed = false;
        let frame = match tokio::select! {
            _ = shutdown.changed() => return,
            frame = read_frame(
                &mut stream,
                Channel::Admin,
                |message_type| admin_body_limit(message_type, managed),
            ) => frame,
        } {
            Ok(frame) => frame,
            Err(FrameIoError::Closed) => return,
            Err(_) => {
                #[cfg(feature = "lab")]
                ctx.metrics.admin.frame_failed();
                return;
            }
        };
        if frame.header.message_type == admin_msg::PROFILE_SESSION_CREATE {
            profile::handle_control(stream, frame, ctx, shutdown).await;
            return;
        }
        let request_id = frame.header.request_id;
        let is_shutdown = frame.header.message_type == admin_msg::SHUTDOWN;
        #[cfg(feature = "lab")]
        let metric = (frame.header.message_type != admin_msg::METRICS)
            .then(|| ctx.metrics.admin.dispatch.start());
        #[cfg(feature = "lab")]
        let backup_metric =
            (frame.header.message_type == admin_msg::BACKUP).then(|| ctx.metrics.backup.start());
        let response = if is_shutdown {
            dispatch(&frame, &ctx).await
        } else {
            tokio::select! {
                _ = shutdown.changed() => return,
                response = dispatch(&frame, &ctx) => response,
            }
        };
        #[cfg(feature = "lab")]
        if let Some(metric) = metric {
            metric.finish(response.is_err());
        }
        #[cfg(feature = "lab")]
        if let Some(metric) = backup_metric {
            metric.finish(response.is_err());
        }
        // Admission refusals did not queue Authority work: respond immediately.
        // Worker errors still reconcile under the coordinator, regardless of code.
        let fault_after_response = if matches!(&response, Err(BrokerError::Authority(_))) {
            ctx.settle_failed_admin().await
        } else {
            false
        };
        let write_response = async {
            match response {
                Ok((metadata, body)) => {
                    write_ok(&mut stream, Channel::Admin, request_id, &metadata, &body).await
                }
                Err(err) => {
                    write_admin_error(&mut stream, frame.header.message_type, request_id, &err)
                        .await
                }
            }
        };
        let io_result = if is_shutdown || fault_after_response {
            write_response.await
        } else {
            tokio::select! {
                _ = shutdown.changed() => return,
                result = write_response => result,
            }
        };
        if fault_after_response {
            ctx.request_fault();
        }
        if io_result.is_err() {
            return;
        }
        if ctx.shutdown_requested() {
            return;
        }
    }
}

#[cfg(feature = "lab")]
async fn prepare_admin_frame(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<(IncomingFrame, Option<crate::oidc_admin::Admission>), BrokerError> {
    let managed = ipc::managed_admin_operation(frame.header.message_type)?;
    if managed {
        if let Some(manager) = &ctx.oidc_admin {
            let (token, original) = ipc::parse_management_body(&frame.body)?;
            let admission = manager.admit(token, ctx, deadline).await?;
            return Ok((
                IncomingFrame {
                    header: frame.header,
                    metadata: frame.metadata.clone(),
                    body: Zeroizing::new(original.to_vec()),
                },
                Some(admission),
            ));
        }
        if frame.body.starts_with(b"RKAU") {
            return Err(ipc::FrameError::InvalidField.into());
        }
    }
    Ok((
        IncomingFrame {
            header: frame.header,
            metadata: frame.metadata.clone(),
            body: Zeroizing::new(frame.body.to_vec()),
        },
        None,
    ))
}

async fn dispatch(frame: &IncomingFrame, ctx: &BrokerCtx) -> Result<AdminResponse, BrokerError> {
    let deadline = admin_mutation_deadline();
    #[cfg(feature = "lab")]
    let (frame, admission) = prepare_admin_frame(frame, ctx, deadline).await?;
    #[cfg(feature = "lab")]
    let frame = &frame;
    #[cfg(not(feature = "lab"))]
    if frame.body.starts_with(b"RKAU") {
        return Err(ipc::FrameError::InvalidField.into());
    }
    dispatch_operation(
        frame,
        ctx,
        #[cfg(feature = "lab")]
        admission.as_ref(),
        deadline,
    )
    .await
}

async fn dispatch_operation(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    #[cfg(feature = "lab")] admission: Option<&crate::oidc_admin::Admission>,
    request_deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    if !cfg!(feature = "lab")
        && matches!(
            frame.header.message_type,
            admin_msg::DESKTOP_REVEAL
                | admin_msg::TEMPLATE_INSTALL
                | admin_msg::PROFILE_GET
                | admin_msg::PROFILE_SESSION_CREATE
                | admin_msg::SESSION_CREATE
                | admin_msg::SESSION_REVOKE
        )
    {
        return Err(ipc::FrameError::InvalidField.into());
    }
    match frame.header.message_type {
        #[cfg(feature = "lab")]
        admin_msg::OIDC_LOGIN_BEGIN => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate_until(request_deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let manager = ctx
                .oidc_admin
                .as_ref()
                .ok_or(BrokerError::Denied("OIDC profile is not enabled"))?;
            Ok((json(&manager.begin()?)?, Zeroizing::new(Vec::new())))
        }
        #[cfg(feature = "lab")]
        admin_msg::OIDC_LOGIN_FINISH | admin_msg::OIDC_LOGIN_CANCEL => {
            let flow: ipc::OidcFlowMeta = meta(frame)?;
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            let manager = ctx
                .oidc_admin
                .as_ref()
                .ok_or(BrokerError::Denied("OIDC profile is not enabled"))?;
            if frame.header.message_type == admin_msg::OIDC_LOGIN_CANCEL {
                manager.cancel(&flow.flow_id)?;
                Ok((
                    json(&serde_json::json!({"cancelled":true}))?,
                    Zeroizing::new(Vec::new()),
                ))
            } else {
                ctx.lifecycle.reject_if_not_running()?;
                let (response, token) = manager.finish(&flow.flow_id, ctx).await?;
                Ok((json(&response)?, token))
            }
        }
        #[cfg(feature = "lab")]
        admin_msg::OIDC_LOGOUT => {
            empty_meta(frame)?;
            let manager = ctx
                .oidc_admin
                .as_ref()
                .ok_or(BrokerError::Denied("OIDC profile is not enabled"))?;
            Ok((
                json(&manager.logout(&frame.body, ctx).await?)?,
                Zeroizing::new(Vec::new()),
            ))
        }
        #[cfg(feature = "lab")]
        admin_msg::METRICS => {
            empty_request(frame)?;
            let snapshot = ctx.metrics.snapshot(
                ctx.sessions.active_count(crate::now_ts()?),
                ctx.sessions.in_flight_total(),
            );
            Ok((json(&snapshot)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::DESKTOP_REMEMBER => {
            let deadline = request_deadline;
            empty_meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let (key, expires) = ctx
                .authority
                .desktop_remember(proof_from(kind, proof), Some(deadline.into_std()))
                .await?;
            Ok((json(&serde_json::json!({"expires_at_ms": expires}))?, key))
        }
        admin_msg::DESKTOP_RESUME => {
            empty_meta(frame)?;
            let (_, key) = ipc::parse_proof_body(&frame.body)?;
            let (token, expires, lease_recovery) =
                ctx.resume_desktop(SecretInput::from_slice(key)).await?;
            Ok((
                json(
                    &serde_json::json!({"expires_at_ms": expires,"lease_recovery":lease_recovery}),
                )?,
                token,
            ))
        }
        admin_msg::DESKTOP_LOGIN => {
            empty_meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let (token, lease_recovery) = ctx
                .unlock_with_desktop(proof_from(kind, proof), true)
                .await?;
            let token =
                token.ok_or(BrokerError::Authority(AuthorityError::AuthenticationFailed))?;
            Ok((
                json(
                    &serde_json::json!({"expires_in_seconds": 7 * 24 * 60 * 60,"lease_recovery":lease_recovery}),
                )?,
                token,
            ))
        }
        admin_msg::DESKTOP_ADD => {
            let deadline = request_deadline;
            let add: ipc::CredentialAddMeta = meta(frame)?;
            if add.kind != CredentialKind::OpaqueToken {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            let (_, token, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let credentials = authority_until(deadline, ctx.authority.credential_list()).await?;
            ensure_credential_catalog_fits(credentials, &add.label, add.kind)?;
            let result = authority_until(
                deadline,
                ctx.authority.desktop_add(
                    SecretInput::from_slice(token),
                    add.label,
                    SecretInput::from_slice(secret),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((json(&result)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::DESKTOP_REVEAL => {
            let deadline = request_deadline;
            let reference: ipc::CredentialRefMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let value = authority_until(
                deadline,
                ctx.authority.desktop_reveal(
                    proof_from(kind, proof),
                    reference.credential_id,
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((b"{}".to_vec(), value))
        }
        admin_msg::STATUS | admin_msg::PASSIVE_STATUS => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let status = if frame.header.message_type == admin_msg::PASSIVE_STATUS {
                ctx.authority.status().await?
            } else {
                ctx.authority.admin_status().await?
            };
            let response = ipc::StatusResponse {
                state: status.state.to_owned(),
                format_version: status.format_version,
                runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
                lab_enabled: cfg!(feature = "lab"),
                sessions_active: ctx.sessions.active_count(crate::now_ts()?),
                lease_journal: ctx.executor.lease_journal_status().await?,
                rollback: status.rollback,
            };
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::ROLLBACK_CONFIRM => {
            let metadata: ipc::RollbackConfirmMeta = meta(frame)?;
            let (kind, bytes) = ipc::parse_proof_body(&frame.body)?;
            let proof = match kind {
                ProofKind::Password => {
                    rekey_vault::bootstrap::RestoreProof::Password(SecretInput::from_slice(bytes))
                }
                ProofKind::Recovery => rekey_vault::bootstrap::RestoreProof::RecoveryKey(
                    SecretInput::from_slice(bytes),
                ),
                ProofKind::Presence => {
                    return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
                }
            };
            ctx.confirm_rollback(metadata.expected, proof, request_deadline)
                .await?;
            Ok((
                json(&serde_json::json!({"locked": true}))?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::UNLOCK_PASSWORD => {
            empty_meta(frame)?;
            let proof = UnlockProof::Password(SecretInput::from_slice(&frame.body));
            let lease_recovery = ctx.unlock(proof).await?;
            Ok((
                json(&ipc::UnlockResponse {
                    unlocked: true,
                    lease_recovery,
                })?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::UNLOCK_RECOVERY => {
            empty_meta(frame)?;
            let proof = UnlockProof::Recovery(SecretInput::from_slice(&frame.body));
            let lease_recovery = ctx.unlock(proof).await?;
            Ok((
                json(&ipc::UnlockResponse {
                    unlocked: true,
                    lease_recovery,
                })?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::KEY_ROTATE_VRK => password_lifecycle::handle_vrk_rotate(frame, ctx).await,
        admin_msg::KEY_ROTATE_DEK => password_lifecycle::handle_dek_rotate(frame, ctx).await,
        admin_msg::PASSWORD_CHANGE => password_lifecycle::handle_password_change(frame, ctx).await,
        admin_msg::RECOVERY_ROTATE => password_lifecycle::handle_recovery_rotate(frame, ctx).await,
        admin_msg::AUDIT_PRUNE => audit_query::handle_audit_prune(frame, ctx).await,
        admin_msg::AUDIT_RETENTION_SET => {
            audit_query::handle_retention_set(frame, ctx, request_deadline).await
        }
        admin_msg::AUDIT_RETENTION_STATUS => audit_query::handle_retention_status(frame, ctx).await,
        admin_msg::AUDIT_QUERY => audit_query::handle_audit_query(frame, ctx).await,
        admin_msg::CREDENTIAL_ADD => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let add_meta: ipc::CredentialAddMeta = meta(frame)?;
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            credential_profiles::validate_add(ctx, deadline, add_meta.kind, kind, proof, secret)
                .await?;
            let credentials = authority_until(deadline, ctx.authority.credential_list()).await?;
            ensure_credential_catalog_fits(credentials, &add_meta.label, add_meta.kind)?;
            let metadata = if add_meta.kind == CredentialKind::OAuthGrant {
                authority_until(
                    deadline,
                    ctx.authority.oauth_grant_create(
                        add_meta.label,
                        SecretInput::from_slice(secret),
                        proof_from(kind, proof),
                        Some(deadline.into_std()),
                    ),
                )
                .await?
            } else {
                authority_until(
                    deadline,
                    ctx.authority.credential_add_before(
                        add_meta.label,
                        add_meta.kind,
                        SecretInput::from_slice(secret),
                        proof_from(kind, proof),
                        Some(deadline.into_std()),
                    ),
                )
                .await?
            };
            Ok((json(&metadata)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::OAUTH_LOGIN => {
            let login: ipc::OAuthLoginMeta = meta(frame)?;
            let (kind, bytes) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(request_deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            authority_until(
                request_deadline,
                ctx.authority.verify_proof(proof_from(kind, bytes)),
            )
            .await?;
            let now = crate::now_ts()?;
            let active = ctx
                .policy
                .read()
                .await
                .clone()
                .filter(|p| !p.is_expired(now) && p.signer_id().is_some())
                .ok_or(rekey_policy::PolicyError::NotConfigured)?;
            let connection = active
                .snapshot()
                .connections()
                .iter()
                .find(|c| c.name == login.connection && c.enabled && c.oauth.is_some())
                .cloned()
                .ok_or(rekey_policy::PolicyError::NotConfigured)?;
            let audit =
                crate::runtime::oauth_audit("oauth.authorization_started", &connection, &active)?;
            ctx.authority.append_audit(audit.clone()).await?;
            let response = ctx
                .executor
                .oauth
                .begin(connection, login.redirect_uri.as_deref(), ctx, audit)
                .await?;
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::CREDENTIAL_LIST => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let credentials = ctx.authority.credential_list().await?;
            Ok((
                json(&ipc::CredentialListResponse { credentials })?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::CREDENTIAL_ROTATE => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let ref_meta: ipc::CredentialRefMeta = meta(frame)?;
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let metadata = ctx
                .authority
                .credential_list()
                .await?
                .into_iter()
                .find(|c| c.id == ref_meta.credential_id)
                .ok_or(AuthorityError::CredentialNotFound)?;
            let metadata = if metadata.kind == CredentialKind::OAuthGrant {
                authority_until(
                    deadline,
                    ctx.authority.oauth_grant_update(
                        metadata.id,
                        metadata.current_version,
                        SecretInput::from_slice(secret),
                        proof_from(kind, proof),
                        Some(deadline.into_std()),
                    ),
                )
                .await?
            } else {
                if metadata.kind == CredentialKind::GitHubAppInstallation {
                    credential_profiles::validate_add(
                        ctx,
                        deadline,
                        metadata.kind,
                        kind,
                        proof,
                        secret,
                    )
                    .await?;
                }
                authority_until(
                    deadline,
                    ctx.authority.credential_rotate_before(
                        ref_meta.credential_id,
                        SecretInput::from_slice(secret),
                        proof_from(kind, proof),
                        Some(deadline.into_std()),
                    ),
                )
                .await?
            };
            Ok((json(&metadata)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::CREDENTIAL_ROTATE_MTLS => {
            let deadline = request_deadline;
            let metadata: ipc::CredentialRotateMtlsMeta = meta(frame)?;
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let rotated = authority_until(
                deadline,
                ctx.authority.credential_rotate_typed_before(
                    metadata.credential_id,
                    CredentialKind::MtlsIdentity,
                    Some(metadata.expected_version),
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            ctx.lifecycle
                .cancel_private_credentials_until(Some(metadata.credential_id), deadline)
                .await?;
            Ok((json(&rotated)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::PKI_GENERATE_CRL => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let input: ipc::PkiGenerateCrlMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let (info, pem) = authority_until(
                deadline,
                ctx.authority.pki_generate_crl_before(
                    input,
                    proof_from(kind, proof),
                    frame.header.request_id,
                    deadline.into_std(),
                ),
            )
            .await?;
            Ok((json(&info)?, Zeroizing::new(pem)))
        }
        admin_msg::PKI_REVOKE_CERTIFICATE => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let input: ipc::PkiRevokeCertificateMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let revoked = authority_until(
                deadline,
                ctx.authority.pki_revoke_certificate_before(
                    input,
                    proof_from(kind, proof),
                    frame.header.request_id,
                    deadline.into_std(),
                ),
            )
            .await?;
            Ok((json(&revoked)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::PKI_ISSUE_CLIENT_CSR => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let input: ipc::PkiIssueClientCsrMeta = meta(frame)?;
            let (kind, proof, csr) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let certificate = authority_until(
                deadline,
                ctx.authority.pki_issue_client_csr_before(
                    input,
                    SecretInput::from_slice(csr),
                    proof_from(kind, proof),
                    frame.header.request_id,
                    deadline.into_std(),
                ),
            )
            .await?;
            Ok((json(&certificate)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::CREDENTIAL_ROTATE_CA => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let metadata: ipc::CredentialRotateCaMeta = meta(frame)?;
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let rotated = authority_until(
                deadline,
                ctx.authority.credential_rotate_typed_before(
                    metadata.credential_id,
                    CredentialKind::PkiCaSigner,
                    Some(metadata.expected_version),
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            drop(owner);
            Ok((json(&rotated)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::CREDENTIAL_ROTATE_GITHUB_APP => github::handle_rotate(frame, ctx).await,
        admin_msg::GITHUB_WEBHOOK_APPLY => github::handle_webhook(frame, ctx).await,
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_KEYCLOAK => vault_kv::handle_rotate_keycloak(frame, ctx).await,
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV => vault_kv::handle_rotate(frame, ctx).await,
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_GCP_SECRET_MANAGER => {
            vault_kv::handle_rotate_gcp(frame, ctx).await
        }
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_AZURE_KEY_VAULT => {
            vault_kv::handle_rotate_azure(frame, ctx).await
        }
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_MACOS_KEYCHAIN => {
            vault_kv::handle_rotate_keychain(frame, ctx).await
        }
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT => {
            vault_kv::handle_rotate_onepassword(frame, ctx).await
        }
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_AWS_SECRETS_MANAGER => {
            vault_kv::handle_rotate_aws(frame, ctx).await
        }
        #[cfg(feature = "lab")]
        admin_msg::CREDENTIAL_ROTATE_VAULT_DYNAMIC => {
            vault_kv::handle_rotate_dynamic(frame, ctx).await
        }
        admin_msg::CREDENTIAL_REVOKE => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let ref_meta: ipc::CredentialRefMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let action_ids = authority_until(
                deadline,
                ctx.authority
                    .action_ids_for_credential(ref_meta.credential_id),
            )
            .await?;
            let metadata = authority_until(
                deadline,
                ctx.authority.credential_revoke_before(
                    ref_meta.credential_id,
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            ctx.sessions.revoke_by_actions(&action_ids);
            ctx.lifecycle
                .cancel_private_credentials_until(Some(ref_meta.credential_id), deadline)
                .await?;
            Ok((json(&metadata)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::TEMPLATE_CATALOG
            if serde_json::from_slice::<serde_json::Value>(&frame.metadata)
                .is_ok_and(|v| v.get("preset").is_some()) =>
        {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct PresetMeta {
                preset: String,
                origin: Option<String>,
                header: Option<String>,
                prefix: Option<String>,
            }
            let request: PresetMeta = meta(frame)?;
            let preset = if matches!(request.preset.as_str(), "generic-bearer" | "generic-header") {
                rekey_policy::presets::generic_preset(
                    rekey_domain::action::HttpsOrigin::parse(
                        request
                            .origin
                            .as_deref()
                            .ok_or(ipc::FrameError::InvalidField)?,
                    )?,
                    request.header.as_deref().unwrap_or("authorization"),
                    request.prefix.as_deref().unwrap_or("Bearer "),
                )?
            } else {
                rekey_policy::presets::builtin_preset(&request.preset)?
            };
            Ok((b"{}".to_vec(), Zeroizing::new(json(&preset)?)))
        }
        admin_msg::TEMPLATE_CATALOG => {
            let metadata: ipc::TemplateCatalogMeta = meta(frame)?;
            let deadline = request_deadline;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_busy()?;
            let response = authority_until(
                deadline,
                ctx.authority.template_catalog_before(
                    metadata.source,
                    frame.body.to_vec(),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::TEMPLATE_INSTALL => {
            let metadata: ipc::TemplateInstallMeta = meta(frame)?;
            let (kind, proof, package) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let deadline = request_deadline;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let response = authority_until(
                deadline,
                ctx.authority.template_install_before(
                    metadata,
                    package.to_vec(),
                    proof_from(kind, proof),
                    frame.header.request_id,
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::ACTION_CREATE | admin_msg::ACTION_UPDATE => {
            let deadline = request_deadline;
            let (existing, definition_meta) =
                if frame.header.message_type == admin_msg::ACTION_UPDATE {
                    let update: ipc::ActionUpdateMeta = meta(frame)?;
                    (Some(update.action_id), update.definition)
                } else {
                    (None, meta::<ipc::ActionCreateMeta>(frame)?)
                };
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let definition = definition_from_meta(definition_meta)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let actions = authority_until(deadline, ctx.authority.action_list()).await?;
            ensure_action_catalog_fits(actions, existing, &definition)?;
            let action = authority_until(
                deadline,
                ctx.authority.action_upsert_before(
                    existing,
                    definition,
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((json(&action)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::ACTION_DISABLE => {
            let deadline = request_deadline;
            let ref_meta: ipc::ActionRefMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            authority_until(
                deadline,
                ctx.authority.action_disable_before(
                    ref_meta.action_id,
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            ctx.sessions.revoke_by_actions(&[ref_meta.action_id]);
            Ok((
                json(&serde_json::json!({"disabled": true}))?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::ACTION_LIST => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let actions = ctx.authority.action_list().await?;
            Ok((
                json(&ipc::ActionListResponse { actions })?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::PROFILE_LIST => {
            empty_request(frame)?;
            let response = ctx.profile_list_until(request_deadline).await?;
            Ok((b"{}".to_vec(), Zeroizing::new(json(&response)?)))
        }
        admin_msg::PROFILE_GET => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let request: ipc::ProfileNameMeta = meta(frame)?;
            let response = ctx
                .profile_get_until(
                    &request.profile,
                    #[cfg(feature = "lab")]
                    admission,
                    request_deadline,
                )
                .await?;
            Ok((b"{}".to_vec(), Zeroizing::new(json(&response)?)))
        }
        admin_msg::SESSION_CREATE => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let create: ipc::AdminSessionCreateMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            authority_until(
                deadline,
                ctx.authority.verify_proof(proof_from(kind, proof)),
            )
            .await?;
            // New sessions may pin only Active versions. Retired stays
            // executable for grants issued while it was Active.
            let mut action_timeouts = Vec::with_capacity(create.actions.len());
            for r in &create.actions {
                let pinned =
                    authority_until(deadline, ctx.authority.action_get(r.action_id, r.version))
                        .await?;
                if pinned.state != ActionState::Active {
                    return Err(BrokerError::Domain(
                        rekey_domain::DomainError::ActionDisabled,
                    ));
                }
                action_timeouts.push((*r, pinned.action.timeout_ms));
            }
            let session_id = crate::random_id(SessionId::from_random_bytes)?;
            #[cfg(feature = "lab")]
            let principal_id = match (admission, create.principal_id) {
                (Some(identity), requested) => {
                    if requested.is_some_and(|principal| principal != identity.principal) {
                        return Err(BrokerError::Denied("management principal mismatch"));
                    }
                    identity.principal
                }
                (None, Some(principal)) => principal,
                (None, None) => crate::random_id(PrincipalId::from_random_bytes)?,
            };
            #[cfg(not(feature = "lab"))]
            let principal_id = match create.principal_id {
                Some(principal) => principal,
                None => crate::random_id(PrincipalId::from_random_bytes)?,
            };
            let vault_id = authority_until(deadline, ctx.authority.status())
                .await?
                .vault_id;
            let principal = Principal {
                tenant_id: TenantId::from_bytes(*vault_id.as_bytes())
                    .map_err(BrokerError::Domain)?,
                principal_id,
                session_id,
            };
            let issued_at = crate::now_ts()?;
            let grant = SessionGrant::new(
                session_id,
                principal,
                create.actions,
                issued_at,
                #[cfg(feature = "lab")]
                admission.map_or(create.ttl_ms, |identity| {
                    create.ttl_ms.min(
                        identity
                            .expires_at_ms
                            .saturating_sub(issued_at.as_unix_ms()),
                    )
                }),
                #[cfg(not(feature = "lab"))]
                create.ttl_ms,
                create.max_uses,
            )
            .map_err(BrokerError::Domain)?;
            reject_if_deadline_elapsed(deadline)?;
            let expires_at_ms = grant.expires_at.as_unix_ms();
            let max_uses = grant.max_uses;
            let token = ctx
                .sessions
                .admit(grant, action_timeouts)
                .map_err(|err| match err {
                    CreateSessionError::Closed => {
                        BrokerError::Authority(rekey_vault::AuthorityError::Draining)
                    }
                    CreateSessionError::Domain(err) => BrokerError::Domain(err),
                })?;
            if let Err(err) = ctx
                .authority
                .commit_audit_before(
                    session_audit(event_type::SESSION_CREATED, session_id),
                    Some(deadline.into_std()),
                )
                .await
            {
                ctx.sessions.revoke(session_id);
                ctx.request_fault();
                return Err(err.into());
            }
            if let Err(expired) = reject_if_deadline_elapsed(deadline) {
                ctx.sessions.revoke(session_id);
                if let Err(err) = ctx
                    .authority
                    .commit_audit(session_audit(event_type::SESSION_REVOKED, session_id))
                    .await
                {
                    ctx.request_fault();
                    return Err(err.into());
                }
                return Err(expired);
            }
            #[cfg(feature = "lab")]
            if let (Some(manager), Some(identity)) = (&ctx.oidc_admin, admission) {
                match manager.publish(identity, ctx, || {
                    ctx.sessions
                        .bound_management_deadline(session_id, identity.deadline.into_std())
                }) {
                    Ok(true) => (),
                    Ok(false) => {
                        ctx.sessions.revoke(session_id);
                        return Err(BrokerError::Denied(
                            "management capability publication closed",
                        ));
                    }
                    Err(error) => {
                        ctx.sessions.revoke(session_id);
                        return Err(error);
                    }
                }
            }
            let response = ipc::SessionCreatedResponse {
                session_id,
                principal_id,
                capability_token: token,
                expires_at_ms,
                max_uses,
            };
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::SSH_KEY => ssh_admin(frame, ctx, request_deadline).await,
        admin_msg::IMPORT_ENV => import_admin(frame, ctx, request_deadline).await,
        admin_msg::ACCESS_RESOLVE => access_admin(frame, ctx, request_deadline).await,
        admin_msg::PERSONAL_POLICY_DRAFT => {
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            let request: ipc::PersonalPolicyDraftMeta = meta(frame)?;
            let (response, body) = ctx
                .personal_policy_draft_until(request, request_deadline)
                .await?;
            let metadata = json(&response)?;
            reject_if_deadline_elapsed(request_deadline)?;
            Ok((metadata, body))
        }
        admin_msg::POLICY_ACTIVATE => {
            let deadline = request_deadline;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let metadata: ipc::PolicyActivateMeta = meta(frame)?;
            ctx.activate_policy_until(metadata, proof_from(kind, proof), deadline)
                .await?;
            Ok((
                json(&ctx.policy_status().await?)?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::POLICY_TRUST_INSTALL => {
            let deadline = request_deadline;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let trust = rekey_policy::parse_policy_trust(&frame.metadata)?;
            ctx.install_policy_trust_until(trust, proof_from(kind, proof), deadline)
                .await?;
            Ok((
                json(&ctx.policy_status().await?)?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::POLICY_STATUS => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let response = ctx.policy_status().await?;
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::APPROVAL_ORIGIN => {
            empty_request(frame)?;
            ctx.lifecycle.reject_if_not_running()?;
            let _owner = ctx.lifecycle.coordinate().await;
            ctx.lifecycle.reject_if_not_running()?;
            let public_key = ctx.authority.approval_origin_public_key().await?;
            let response = ipc::ApprovalOriginResponse {
                algorithm: "ed25519".to_owned(),
                public_key: data_encoding::HEXLOWER.encode(&public_key),
            };
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::APPROVAL_EXTERNAL_SUBMIT => {
            let get: ipc::ApprovalGetMeta = meta(frame)?;
            let raw: Vec<Box<serde_json::value::RawValue>> =
                serde_json::from_slice(&frame.body).map_err(|_| ipc::FrameError::InvalidField)?;
            let _owner = ctx.lifecycle.coordinate_until(request_deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let now = crate::now_ts()?.as_unix_ms();
            let local = ctx.local_calls.get(get.approval_request_id, now)?;
            ctx.check_local_approval_policy(&local.challenge).await?;
            let active = ctx
                .policy
                .read()
                .await
                .clone()
                .ok_or(BrokerError::Denied("policy-changed"))?;
            let (evidence, expires) = crate::ssh_agent::verify_external_grants(
                &local.challenge,
                &raw,
                active.snapshot(),
                now,
            )?;
            let response = ctx.local_calls.approve_external(
                get.approval_request_id,
                &local.review_sha256,
                evidence,
                expires,
                now,
            )?;
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::APPROVAL_LOCAL_REVIEW => {
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            let get: ipc::ApprovalGetMeta = meta(frame)?;
            let _owner = ctx.lifecycle.coordinate_until(request_deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            let (metadata, body) = ctx
                .local_calls
                .review(get.approval_request_id, crate::now_ts()?.as_unix_ms())?;
            Ok((json(&metadata)?, body))
        }
        admin_msg::APPROVAL_LOCAL_APPROVE | admin_msg::APPROVAL_LOCAL_REJECT => {
            #[cfg(feature = "lab")]
            if ctx
                .local_calls
                .get(
                    meta::<ipc::LocalApprovalDecisionMeta>(frame)?.approval_request_id,
                    crate::now_ts()?.as_unix_ms(),
                )
                .is_err()
            {
                return local_approval_decision(frame, ctx, request_deadline).await;
            }
            connection_approval_decision(frame, ctx, request_deadline).await
        }
        admin_msg::APPROVAL_PENDING => {
            empty_request(frame)?;
            ctx.lifecycle.reject_if_not_running()?;
            let _owner = ctx.lifecycle.coordinate().await;
            ctx.lifecycle.reject_if_not_running()?;
            let challenges = ctx.local_calls.pending(crate::now_ts()?.as_unix_ms());
            let response = ipc::ApprovalPendingResponse {
                record_type: "rekey.approval.pending.v2".to_owned(),
                challenges: challenges
                    .iter()
                    .map(ipc::ApprovalPendingItem::from_challenge)
                    .collect(),
            };
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::APPROVAL_GET => {
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(
                    rekey_domain::ipc::FrameError::InvalidField,
                ));
            }
            ctx.lifecycle.reject_if_not_running()?;
            let get: ipc::ApprovalGetMeta = meta(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            ctx.lifecycle.reject_if_not_running()?;
            let challenge = match ctx
                .local_calls
                .get(get.approval_request_id, crate::now_ts()?.as_unix_ms())
            {
                Ok(local) => {
                    ctx.check_local_approval_policy(&local.challenge).await?;
                    local.challenge
                }
                Err(error) => {
                    #[cfg(not(feature = "lab"))]
                    return Err(error);
                    #[cfg(feature = "lab")]
                    {
                        let _ = error;
                        ctx.sessions
                            .approval_challenge(get.approval_request_id, crate::now_ts()?)
                            .map_err(|error| BrokerError::Denied(error.code()))?
                    }
                }
            };
            let envelope = ctx.executor.sign_challenge_envelope(challenge).await?;
            Ok((json(&envelope)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::SESSION_REVOKE => {
            let deadline = request_deadline;
            ctx.lifecycle.reject_if_not_running()?;
            let revoke: ipc::SessionRevokeMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            authority_until(
                deadline,
                ctx.authority.verify_proof(proof_from(kind, proof)),
            )
            .await?;
            reject_if_deadline_elapsed(deadline)?;
            let existed = ctx.sessions.revoke(revoke.session_id);
            if let Err(err) = ctx
                .authority
                .commit_audit_before(
                    session_audit(event_type::SESSION_REVOKED, revoke.session_id),
                    Some(deadline.into_std()),
                )
                .await
            {
                ctx.request_fault();
                return Err(err.into());
            }
            reject_if_deadline_elapsed(deadline)?;
            Ok((
                json(&serde_json::json!({"revoked": existed}))?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::BACKUP => {
            ctx.lifecycle.reject_if_not_running()?;
            let backup: ipc::BackupMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate().await;
            ctx.lifecycle.reject_if_not_running()?;
            let info = ctx
                .authority
                .backup(PathBuf::from(&backup.output_path), proof_from(kind, proof))
                .await?;
            let receipt = ipc::BackupReceipt {
                vault_id: info.vault_id.to_string(),
                generation: info.generation,
                format_version: info.format_version,
                created_at_ms: info.created_at_ms,
                sha256_hex: info.sha256_hex,
                output_path: info.output_path.display().to_string(),
                snapshot_cut: info.snapshot_cut,
            };
            Ok((json(&receipt)?, Zeroizing::new(Vec::new())))
        }
        admin_msg::LOCK => {
            empty_request(frame)?;
            ctx.drain_lock("admin").await?;
            Ok((
                json(&serde_json::json!({"locked": true}))?,
                Zeroizing::new(Vec::new()),
            ))
        }
        admin_msg::SHUTDOWN => {
            empty_meta(frame)?;
            if frame.body.is_empty() {
                return Err(BrokerError::Admission(AuthorityError::AuthenticationFailed));
            }
            let (kind, bytes) = ipc::parse_proof_body(&frame.body)?;
            let proof = proof_from(kind, bytes);
            ctx.request_admin_shutdown(proof).await?;
            Ok((
                json(&serde_json::json!({"shutdown": true}))?,
                Zeroizing::new(Vec::new()),
            ))
        }
        _ => Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::InvalidField,
        )),
    }
}

fn admin_mutation_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + ADMIN_MUTATION_TIMEOUT
}

async fn authority_until<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = Result<T, AuthorityError>>,
) -> Result<T, BrokerError> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?
        .map_err(BrokerError::Authority)
}

fn reject_if_deadline_elapsed(deadline: tokio::time::Instant) -> Result<(), BrokerError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
    }
    Ok(())
}

#[cfg(any(test, feature = "lab"))]
async fn local_approval_decision(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    let decision: ipc::LocalApprovalDecisionMeta = meta(frame)?;
    let proof = SecretInput::from_slice(ipc::parse_local_approval_proof_body(&frame.body)?);
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    let local = ctx
        .sessions
        .local_approval(decision.approval_request_id, crate::now_ts()?)?;
    if !matches!(
        local.challenge.approver,
        rekey_domain::authorization::ApproverSpec::LocalPresence {}
    ) {
        return Err(BrokerError::Denied("approval-authority-mismatch"));
    }
    if local.review_sha256 != decision.expected_review_sha256 {
        return Err(BrokerError::Denied("approval-review-mismatch"));
    }
    let approve = frame.header.message_type == admin_msg::APPROVAL_LOCAL_APPROVE;
    if local.state != ipc::LocalApprovalState::Pending
        && (approve || local.state != ipc::LocalApprovalState::Approved)
    {
        authority_until(
            deadline,
            ctx.authority.verify_proof(UnlockProof::Presence(proof)),
        )
        .await?;
        reject_if_deadline_elapsed(deadline)?;
        let current = ctx
            .sessions
            .local_approval(decision.approval_request_id, crate::now_ts()?)?;
        return Ok((json(&current.response())?, Zeroizing::new(Vec::new())));
    }
    ctx.check_local_approval_policy(&local.challenge).await?;
    let action = authority_until(
        deadline,
        ctx.authority
            .action_get(local.challenge.action_id, local.challenge.action_version),
    )
    .await?;
    if action.state == ActionState::Disabled || !action.action.enabled {
        return Err(rekey_domain::DomainError::ActionDisabled.into());
    }
    let approval_id = if approve {
        Some(crate::random_id(
            rekey_domain::ids::ApprovalId::from_random_bytes,
        )?)
    } else {
        None
    };
    let challenge = &local.challenge;
    let digest = |value: &str| -> Result<[u8; 32], BrokerError> {
        data_encoding::HEXLOWER
            .decode(value.as_bytes())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(BrokerError::Denied("approval-state-conflict"))
    };
    let draft = AuditDraft {
        request_id: None,
        session_id: Some(challenge.session_id),
        action_id: Some(challenge.action_id),
        action_version: Some(challenge.action_version),
        credential_id: None,
        credential_version: None,
        authorization: Some(Box::new(rekey_vault::model::AuthorizationEvidence {
            principal_id: challenge.principal_id,
            policy_version: challenge.policy_version,
            policy_digest: digest(&challenge.policy_sha256)?,
            policy_rule_id: Some(challenge.policy_rule_id),
            resource_type: challenge.resource.resource_type.clone(),
            resource_id: challenge.resource.id.clone(),
            parameter_hash: digest(&challenge.parameter_sha256)?,
        })),
        approval: Some(rekey_vault::model::ApprovalEvidence {
            approval_request_id: challenge.approval_request_id,
            approval_id,
            approver_id: None,
        }),
        request_context: local.request_context.clone(),
        usage: None,
        event_type: if approve {
            event_type::APPROVAL_APPROVED
        } else {
            event_type::APPROVAL_REJECTED
        },
        outcome: outcome::SUCCESS,
        reason_code: "local-presence".into(),
        upstream_status: None,
        latency_ms: None,
    };
    let not_after = deadline.into_std().min(local.deadline);
    let result = authority_until(
        deadline,
        ctx.authority.authorize_local_approval(
            proof,
            draft,
            not_after,
            challenge.max_expires_at_ms,
        ),
    )
    .await;
    if matches!(
        result,
        Err(BrokerError::Authority(AuthorityError::AuthorityBusy))
    ) {
        ctx.sessions
            .cancel_local_unconfirmed(challenge.approval_request_id);
        return Err(BrokerError::ApprovalOutcomeUnconfirmed);
    }
    result?;
    let publication = (|| {
        let now = crate::now_ts()?;
        if std::time::Instant::now() >= not_after
            || now.as_unix_ms() < challenge.created_at_ms
            || now.as_unix_ms() >= challenge.max_expires_at_ms
        {
            return Err(BrokerError::ApprovalOutcomeUnconfirmed);
        }
        ctx.sessions.decide_local(
            challenge.approval_request_id,
            &local.review_sha256,
            approval_id,
            now,
        )
    })();
    match publication {
        Ok(response) => Ok((json(&response)?, Zeroizing::new(Vec::new()))),
        Err(_) => {
            ctx.sessions
                .cancel_local_unconfirmed(challenge.approval_request_id);
            Err(BrokerError::ApprovalOutcomeUnconfirmed)
        }
    }
}

fn session_audit(event_type: &'static str, session_id: SessionId) -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: Some(session_id),
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        request_context: None,
        usage: None,
        event_type,
        outcome: outcome::SUCCESS,
        reason_code: "admin".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

fn definition_from_meta(meta: ipc::ActionCreateMeta) -> Result<ActionDefinition, BrokerError> {
    #[cfg(not(feature = "lab"))]
    if meta.native_plugin.is_some() {
        return Err(BrokerError::Denied("native plugins require lab"));
    }
    let mut allowed_extra_headers = std::collections::BTreeSet::new();
    for name in &meta.allowed_extra_headers {
        allowed_extra_headers.insert(HeaderName::new(name).map_err(BrokerError::Domain)?);
    }
    let mut allowed_response_headers = std::collections::BTreeSet::new();
    for name in &meta.allowed_response_headers {
        allowed_response_headers.insert(HeaderName::new(name).map_err(BrokerError::Domain)?);
    }
    Ok(ActionDefinition {
        native_plugin: meta.native_plugin,
        text_stream: meta.text_stream,
        name: ActionName::new(&meta.name).map_err(BrokerError::Domain)?,
        credential_id: meta.credential_id,
        origin: HttpsOrigin::parse(&meta.origin).map_err(BrokerError::Domain)?,
        method: FixedMethod::parse(&meta.method).map_err(BrokerError::Domain)?,
        target: rekey_domain::action::ActionTarget::Fixed {
            path: ExactPath::parse(&meta.exact_path).map_err(BrokerError::Domain)?,
        },
        auth: HeaderCredentialUse::new(
            HeaderName::new(&meta.auth_header).map_err(BrokerError::Domain)?,
            HeaderPrefix::new(&meta.auth_prefix).map_err(BrokerError::Domain)?,
        )
        .map_err(BrokerError::Domain)?,
        timeout_ms: meta.timeout_ms,
        request_policy: RequestPolicy {
            max_body_bytes: meta.request_max_bytes,
            allowed_extra_headers,
        },
        response_policy: ResponsePolicy {
            max_body_bytes: meta.response_max_bytes,
            allowed_headers: allowed_response_headers,
        },
    })
}

fn ensure_action_catalog_fits(
    mut actions: Vec<FixedHttpAction>,
    existing: Option<ActionId>,
    definition: &ActionDefinition,
) -> Result<(), BrokerError> {
    if let Some(existing) = existing {
        actions.retain(|action| action.id != existing);
    }
    let probe = FixedHttpAction {
        native_plugin: definition.native_plugin.clone(),
        text_stream: definition.text_stream.clone(),
        id: ActionId::from_random_bytes([0xff; 16]),
        name: definition.name.clone(),
        version: u64::MAX,
        enabled: true,
        credential_id: definition.credential_id,
        origin: definition.origin.clone(),
        method: definition.method,
        target: definition.target.clone(),
        auth: definition.auth.clone(),
        timeout_ms: definition.timeout_ms,
        request_policy: definition.request_policy.clone(),
        response_policy: definition.response_policy.clone(),
    };
    actions.push(probe);
    json(&ipc::ActionListResponse { actions }).map(|_| ())
}

fn ensure_credential_catalog_fits(
    mut credentials: Vec<CredentialMetadata>,
    label: &rekey_domain::credential::CredentialLabel,
    kind: CredentialKind,
) -> Result<(), BrokerError> {
    credentials.push(CredentialMetadata {
        id: CredentialId::from_random_bytes([0xff; 16]),
        label: label.clone(),
        kind,
        state: CredentialState::Active,
        current_version: u64::MAX,
        created_at: Timestamp::from_unix_ms(i64::MIN),
        updated_at: Timestamp::from_unix_ms(i64::MIN),
    });
    json(&ipc::CredentialListResponse { credentials }).map(|_| ())
}

async fn connection_approval_decision(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    let decision: ipc::LocalApprovalDecisionMeta = meta(frame)?;
    let approve = frame.header.message_type == admin_msg::APPROVAL_LOCAL_APPROVE;
    if decision
        .window_seconds
        .is_some_and(|s| !approve || s == 0 || s > 8 * 3600)
    {
        return Err(ipc::FrameError::InvalidField.into());
    }
    let proof = SecretInput::from_slice(ipc::parse_local_approval_proof_body(&frame.body)?);
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    let local = ctx
        .local_calls
        .get(decision.approval_request_id, crate::now_ts()?.as_unix_ms())?;
    if !matches!(
        local.challenge.approver,
        rekey_domain::authorization::ApproverSpec::LocalPresence {}
    ) {
        return Err(BrokerError::Denied("approval-authority-mismatch"));
    }
    if local.review_sha256 != decision.expected_review_sha256 {
        return Err(BrokerError::Denied("approval-review-mismatch"));
    }
    if local.state != ipc::LocalApprovalState::Pending {
        authority_until(
            deadline,
            ctx.authority.verify_proof(UnlockProof::Presence(proof)),
        )
        .await?;
        return Ok((json(&local.response())?, Zeroizing::new(Vec::new())));
    }
    ctx.check_local_approval_policy(&local.challenge).await?;
    if decision.window_seconds.is_some()
        && local.challenge.schema_id.as_str() == "rekey.ssh-sign.v1"
    {
        let review: serde_json::Value =
            serde_json::from_slice(&local.review).map_err(|_| ipc::FrameError::InvalidField)?;
        let active = ctx.policy.read().await;
        let valid = review["ssh"]["window_allowed"] == true
            && active.as_ref().is_some_and(|p| {
                p.snapshot().ssh_keys().iter().any(|k| {
                    k.name == local.challenge.resource.id
                        && k.hosts.iter().any(|h| {
                            h.rule_id == local.challenge.policy_rule_id
                                && h.effect == rekey_domain::connection::RuleEffect::Approve
                        })
                })
            });
        if !valid {
            return Err(ipc::FrameError::InvalidField.into());
        }
    }
    let approval_id = if approve {
        Some(crate::random_id(
            rekey_domain::ids::ApprovalId::from_random_bytes,
        )?)
    } else {
        None
    };
    let challenge = &local.challenge;
    let digest = |v: &str| -> Result<[u8; 32], BrokerError> {
        data_encoding::HEXLOWER
            .decode(v.as_bytes())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(BrokerError::Denied("approval-state-conflict"))
    };
    let draft = AuditDraft {
        request_id: Some(rekey_domain::ids::RequestId::from_random_bytes(
            *challenge.session_id.as_bytes(),
        )),
        session_id: Some(challenge.session_id),
        action_id: Some(challenge.action_id),
        action_version: Some(challenge.action_version),
        credential_id: None,
        credential_version: None,
        authorization: Some(Box::new(rekey_vault::model::AuthorizationEvidence {
            principal_id: challenge.principal_id,
            policy_version: challenge.policy_version,
            policy_digest: digest(&challenge.policy_sha256)?,
            policy_rule_id: Some(challenge.policy_rule_id),
            resource_type: challenge.resource.resource_type.clone(),
            resource_id: challenge.resource.id.clone(),
            parameter_hash: digest(&challenge.parameter_sha256)?,
        })),
        approval: Some(rekey_vault::model::ApprovalEvidence {
            approval_request_id: challenge.approval_request_id,
            approval_id,
            approver_id: None,
        }),
        request_context: local.request_context.clone(),
        usage: None,
        event_type: if approve {
            event_type::APPROVAL_APPROVED
        } else {
            event_type::APPROVAL_REJECTED
        },
        outcome: outcome::SUCCESS,
        reason_code: "local-presence".into(),
        upstream_status: None,
        latency_ms: None,
    };
    let mut window_audit = draft.clone();
    let not_after = deadline.into_std().min(local.deadline);
    let result = authority_until(
        deadline,
        ctx.authority.authorize_local_approval(
            proof,
            draft,
            not_after,
            challenge.max_expires_at_ms,
        ),
    )
    .await;
    if matches!(
        result,
        Err(BrokerError::Authority(AuthorityError::AuthorityBusy))
    ) {
        ctx.local_calls
            .cancel_unconfirmed(challenge.approval_request_id);
        return Err(BrokerError::ApprovalOutcomeUnconfirmed);
    }
    result?;
    if let Some(seconds) = decision.window_seconds {
        window_audit.event_type = "approval.window_granted";
        window_audit.reason_code = format!("seconds-{seconds}");
        if authority_until(
            deadline,
            ctx.authority
                .commit_audit_before(window_audit, Some(not_after)),
        )
        .await
        .is_err()
        {
            ctx.local_calls
                .cancel_unconfirmed(challenge.approval_request_id);
            ctx.request_fault();
            return Err(BrokerError::ApprovalOutcomeUnconfirmed);
        }
    }
    let now = crate::now_ts()?.as_unix_ms();
    let publication = (|| {
        if std::time::Instant::now() >= not_after
            || now < challenge.created_at_ms
            || now >= challenge.max_expires_at_ms
        {
            return Err(BrokerError::ApprovalOutcomeUnconfirmed);
        }
        let response = ctx.local_calls.decide(
            challenge.approval_request_id,
            &local.review_sha256,
            approval_id,
            now,
        )?;
        if let (Some(seconds), Some(approval_id)) = (decision.window_seconds, approval_id) {
            let active = ctx
                .policy
                .try_read()
                .map_err(|_| BrokerError::ApprovalOutcomeUnconfirmed)?;
            let expiry = active
                .as_ref()
                .ok_or(BrokerError::ApprovalOutcomeUnconfirmed)?
                .snapshot()
                .expires_at_ms();
            ctx.local_calls
                .grant_window(&local, approval_id, seconds, expiry)?;
        }
        Ok(response)
    })();
    let response = publication.map_err(|_| {
        ctx.local_calls
            .cancel_unconfirmed(challenge.approval_request_id);
        BrokerError::ApprovalOutcomeUnconfirmed
    })?;
    Ok((json(&response)?, Zeroizing::new(Vec::new())))
}

async fn access_admin(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    #[derive(serde::Deserialize)]
    #[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
    enum AccessAdmin {
        List,
        Resolve {
            request_id: rekey_domain::ids::RequestId,
            granted: bool,
            #[serde(default)]
            block_caller: bool,
        },
        Block {
            caller: String,
            blocked: bool,
        },
    }
    match meta::<AccessAdmin>(frame)? {
        AccessAdmin::List => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            Ok((
                b"{}".to_vec(),
                Zeroizing::new(json(&ctx.local_calls.access_list()?)?),
            ))
        }
        operation => {
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
            ctx.lifecycle.reject_if_not_running()?;
            authority_until(
                deadline,
                ctx.authority.verify_proof(proof_from(kind, proof)),
            )
            .await?;
            match operation {
                AccessAdmin::Resolve {
                    request_id,
                    granted,
                    block_caller,
                } => {
                    let request = ctx.local_calls.access_get(request_id)?;
                    if granted {
                        let active = ctx
                            .policy
                            .read()
                            .await
                            .clone()
                            .filter(|p| p.signer_id().is_some())
                            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
                        if active.is_expired(crate::now_ts()?)
                            || !active.snapshot().connections().iter().any(|c| {
                                c.enabled
                                    && request.connection.as_ref().is_none_or(|v| &c.name == v)
                                    && request.provider.as_ref().is_none_or(|v| &c.preset == v)
                                    && request
                                        .operation
                                        .as_ref()
                                        .is_none_or(|v| c.operations.iter().any(|o| &o.name == v))
                            })
                        {
                            return Err(BrokerError::Denied("access-connection-not-active"));
                        }
                    }
                    let mut audit = crate::runtime::call_audit(
                        "access_request.resolved",
                        "pending",
                        &request.caller,
                    )?;
                    audit.request_context = None;
                    audit.request_id = Some(request_id);
                    audit.reason_code = if granted {
                        "granted".into()
                    } else {
                        "rejected".into()
                    };
                    ctx.authority.append_audit(audit).await?;
                    let response = ctx.local_calls.resolve_access(request_id, granted)?;
                    if block_caller {
                        ctx.local_calls.block_caller(request.caller, true);
                    }
                    Ok((b"{}".to_vec(), Zeroizing::new(json(&response)?)))
                }
                AccessAdmin::Block { caller, blocked } => {
                    if caller.is_empty()
                        || caller.len() > 256
                        || caller.chars().any(char::is_control)
                    {
                        return Err(ipc::FrameError::InvalidField.into());
                    }
                    let mut audit = crate::runtime::call_audit(
                        "access_request.block_changed",
                        "pending",
                        &caller,
                    )?;
                    audit.request_context = None;
                    ctx.authority.append_audit(audit).await?;
                    ctx.local_calls.block_caller(caller, blocked);
                    Ok((
                        b"{}".to_vec(),
                        Zeroizing::new(json(&serde_json::json!({"blocked":blocked}))?),
                    ))
                }
                AccessAdmin::List => unreachable!(),
            }
        }
    }
}

async fn import_admin(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Selection {
        key: String,
        label: rekey_domain::credential::CredentialLabel,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Replacement {
        key: String,
        connection: String,
        base_url_variable: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ImportMeta {
        path: std::path::PathBuf,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        action: Option<String>,
        #[serde(default)]
        selections: Vec<Selection>,
        #[serde(default)]
        replacements: Vec<Replacement>,
    }
    let request: ImportMeta = meta(frame)?;
    if request.dry_run {
        if !frame.body.is_empty()
            || request.action.is_some()
            || !request.selections.is_empty()
            || !request.replacements.is_empty()
        {
            return Err(ipc::FrameError::InvalidField.into());
        }
        let response = rekey_vault::hygiene::env::preview_env(&request.path)?;
        return Ok((b"{}".to_vec(), Zeroizing::new(json(&response)?)));
    }
    let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    if request.action.as_deref() == Some("rewrite") {
        if !request.selections.is_empty() || request.replacements.is_empty() {
            return Err(ipc::FrameError::InvalidField.into());
        }
        authority_until(
            deadline,
            ctx.authority.verify_proof(proof_from(kind, proof)),
        )
        .await?;
        let active = ctx
            .policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some())
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        if active.is_expired(crate::now_ts()?) {
            return Err(rekey_policy::PolicyError::Expired.into());
        }
        let service = ctx
            .service_url()
            .ok_or(BrokerError::Denied("local-service-unavailable"))?;
        let mut replacements = Vec::new();
        for replacement in request.replacements {
            let connection = active
                .snapshot()
                .connections()
                .iter()
                .find(|c| c.enabled && c.name == replacement.connection)
                .ok_or(rekey_policy::PolicyError::NotConfigured)?;
            let suffix = match connection.preset.as_str() {
                "openai" => "/v1",
                "glm-responses" => "/api/v1",
                "glm" => "/api/anthropic",
                _ => "",
            };
            replacements.push(rekey_vault::hygiene::env::EnvReplacement {
                key: replacement.key,
                base_url_variable: replacement.base_url_variable,
                base_url: format!("{service}/c/{}{suffix}", connection.name),
            });
        }
        let mut started = crate::runtime::call_audit("env.rewrite_started", "import", "user")?;
        started.request_context = None;
        ctx.authority.append_audit(started).await?;
        let backup = rekey_vault::hygiene::env::rewrite_env(&request.path, &replacements)?;
        let mut audit = crate::runtime::call_audit("env.rewritten", "import", "user")?;
        audit.request_context = None;
        if ctx.authority.append_audit(audit).await.is_err() {
            ctx.request_fault();
            return Err(BrokerError::LocalCall(
                "ENV_REWRITE_OUTCOME_UNCONFIRMED",
                "dotenv rewrite occurred but its audit outcome is unconfirmed",
                "Inspect the file and its private backup before retrying.",
            ));
        }
        return Ok((
            b"{}".to_vec(),
            Zeroizing::new(json(&serde_json::json!({"backup":backup}))?),
        ));
    }
    if request.action.is_some() || !request.replacements.is_empty() || request.selections.is_empty()
    {
        return Err(ipc::FrameError::InvalidField.into());
    }
    let report = authority_until(
        deadline,
        ctx.authority.import_env(
            rekey_vault::hygiene::env::EnvImportRequest {
                path: request.path,
                selections: request
                    .selections
                    .into_iter()
                    .map(|s| rekey_vault::hygiene::env::EnvImportSelection {
                        key: s.key,
                        label: s.label,
                    })
                    .collect(),
            },
            proof_from(kind, proof),
            Some(deadline.into_std()),
        ),
    )
    .await?;
    Ok((b"{}".to_vec(), Zeroizing::new(json(&report)?)))
}

async fn ssh_admin(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    #[derive(serde::Deserialize)]
    #[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
    enum SshAdmin {
        Status,
        Generate {
            label: rekey_domain::credential::CredentialLabel,
            #[serde(default)]
            mode: WireMode,
        },
        Import {
            label: rekey_domain::credential::CredentialLabel,
        },
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(rename_all = "snake_case")]
    enum WireMode {
        #[default]
        Default,
        Ed25519Software,
        P256Software,
    }
    let operation: SshAdmin = meta(frame)?;
    if matches!(operation, SshAdmin::Status) {
        if !frame.body.is_empty() {
            return Err(ipc::FrameError::InvalidField.into());
        }
        let now = crate::now_ts()?;
        let active = ctx.policy.read().await;
        let keys = active
            .as_ref()
            .filter(|p| ctx.lifecycle.is_running() && !p.is_expired(now))
            .map(|p| p.snapshot().ssh_keys().to_vec())
            .unwrap_or_default();
        return Ok((
            b"{}".to_vec(),
            Zeroizing::new(json(
                &serde_json::json!({"socket":ctx.state_dir.join("ssh-agent.sock"),"ssh_keys":keys}),
            )?),
        ));
    }
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    let identity = match operation {
        SshAdmin::Status => unreachable!(),
        SshAdmin::Generate { label, mode } => {
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            authority_until(
                deadline,
                ctx.authority.ssh_generate(
                    label,
                    match mode {
                        WireMode::Default => rekey_vault::command::SshKeyMode::Default,
                        WireMode::Ed25519Software => {
                            rekey_vault::command::SshKeyMode::Ed25519Software
                        }
                        WireMode::P256Software => rekey_vault::command::SshKeyMode::P256Software,
                    },
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?
        }
        SshAdmin::Import { label } => {
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            authority_until(
                deadline,
                ctx.authority.ssh_import(
                    label,
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?
        }
    };
    Ok((
        b"{}".to_vec(),
        Zeroizing::new(json(
            &serde_json::json!({"credential":identity.credential,"public_key":data_encoding::BASE64.encode(&identity.public_key)}),
        )?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::ids::CredentialId;

    #[tokio::test]
    async fn queued_local_decision_timeout_cancels_nonretryably_and_late_commit_cannot_publish() {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
        use rekey_domain::authorization::{ApprovalMode, ApproverSpec, ResourceRef, SchemaId};
        use rekey_domain::ids::{ApprovalRequestId, PolicyRuleId, PolicySignerId};
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let proof = || UnlockProof::Password(SecretInput::from_slice(b"fixture-proof"));
        let credential = ctx
            .authority
            .credential_add(
                rekey_domain::credential::CredentialLabel::new("local-deadline").unwrap(),
                CredentialKind::OpaqueToken,
                SecretInput::from_slice(b"synthetic"),
                proof(),
            )
            .await
            .unwrap();
        let definition = definition_from_meta(serde_json::from_value(serde_json::json!({
            "name":"local-deadline", "credential_id":credential.id, "origin":"https://api.example.com", "method":"POST", "exact_path":"/test", "auth_header":"authorization", "auth_prefix":"Bearer ", "timeout_ms":1000, "request_max_bytes":1024, "allowed_extra_headers":[], "response_max_bytes":1024, "allowed_response_headers":[]
        })).unwrap()).unwrap();
        let action = ctx
            .authority
            .action_upsert(None, definition, proof())
            .await
            .unwrap();
        let document =
            Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let signer_id = PolicySignerId::new_random();
        let trust = rekey_policy::ValidatedPolicyTrust::from_parts(
            signer_id,
            rekey_policy::PolicyVerificationKey::from_bytes(
                rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519,
                signer.public_key().as_ref(),
            )
            .unwrap(),
        );
        ctx.install_policy_trust_until(trust.clone(), proof(), admin_mutation_deadline())
            .await
            .unwrap();
        let now = crate::now_ts().unwrap();
        let mut bundle = serde_json::json!({"format_version":1,"signer_id":signer_id,"snapshot":{"format_version":8,"version":1,"expires_at_ms":now.as_unix_ms()+60000,"approvers":[],"connections":[], "ssh_keys":[], "derived_credentials":[], "profiles": [], "workload_identities":[],"bindings":[],"rules":[]}});
        let mut message = b"RKPOLICY\0\x01".to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = data_encoding::BASE64URL_NOPAD
            .encode(signer.sign(&message).as_ref())
            .into();
        let status = ctx.authority.status().await.unwrap();
        ctx.activate_policy_until(
            ipc::PolicyActivateMeta {
                expected_vault_id: status.vault_id,
                expected_trust_sha256: data_encoding::HEXLOWER
                    .encode(&rekey_policy::policy_trust_sha256(signer_id, trust.key()).unwrap()),
                bundle_json: serde_json::from_value(bundle).unwrap(),
            },
            proof(),
            admin_mutation_deadline(),
        )
        .await
        .unwrap();
        let session_id = SessionId::new_random();
        let action_ref = rekey_domain::capability::ActionVersionRef {
            action_id: action.id,
            version: action.version,
        };
        let grant = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::from_bytes(*status.vault_id.as_bytes()).unwrap(),
                principal_id: PrincipalId::new_random(),
                session_id,
            },
            vec![action_ref],
            now,
            60000,
            1,
        )
        .unwrap();
        let token = ctx.sessions.create(grant.clone()).unwrap();
        let mut permit = ctx.sessions.acquire(&token, action_ref, now).unwrap();
        let policy = ctx
            .authority
            .policy_material()
            .await
            .unwrap()
            .bundle
            .unwrap();
        let id = ApprovalRequestId::new_random();
        let challenge = ipc::ApprovalChallenge {
            record_type: "rekey.approval.challenge.v2".into(),
            approval_request_id: id,
            tenant_id: grant.principal.tenant_id,
            principal_id: grant.principal.principal_id,
            session_id,
            action_id: action.id,
            action_version: action.version,
            resource: ResourceRef::new("test-action".into(), action.id.to_string()).unwrap(),
            schema_id: SchemaId::new("test/v1".into()).unwrap(),
            parameter_sha256: "00".repeat(32),
            policy_version: 1,
            policy_sha256: data_encoding::HEXLOWER.encode(&policy.policy_digest),
            policy_rule_id: PolicyRuleId::new_random(),
            mode: ApprovalMode::OneTime,
            approver: ApproverSpec::LocalPresence {},
            max_uses: 1,
            created_at_ms: now.as_unix_ms(),
            max_expires_at_ms: now.as_unix_ms() + 60000,
        };
        let hash = "11".repeat(32);
        ctx.sessions
            .publish_local_pending(
                &mut permit,
                challenge,
                b"{}".to_vec(),
                hash.clone(),
                std::time::Instant::now(),
                std::time::Instant::now() + Duration::from_secs(60),
                None,
            )
            .unwrap();
        drop(permit);
        let (key, _) = ctx.authority.desktop_remember(proof(), None).await.unwrap();
        let metadata = serde_json::to_vec(&ipc::LocalApprovalDecisionMeta {
            approval_request_id: id,
            expected_review_sha256: hash,
            window_seconds: None,
        })
        .unwrap();
        let mut body = Vec::new();
        ipc::encode_proof_body(ProofKind::Presence, &key, &mut body);
        let frame = IncomingFrame {
            header: ipc::FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: admin_msg::APPROVAL_LOCAL_APPROVE,
                request_id: rekey_domain::ids::RequestId::new_random(),
                metadata_len: metadata.len() as u32,
                body_len: body.len() as u32,
            },
            metadata,
            body: Zeroizing::new(body),
        };
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let error = local_approval_decision(
            &frame,
            &ctx,
            tokio::time::Instant::now() + Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "APPROVAL_OUTCOME_UNCONFIRMED");
        assert!(!error.retryable());
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let request_id = rekey_domain::ids::RequestId::new_random();
        let (sent, received) = tokio::join!(
            write_admin_error(
                &mut writer,
                admin_msg::APPROVAL_LOCAL_APPROVE,
                request_id,
                &error
            ),
            read_frame(&mut reader, Channel::Admin, |_| 0)
        );
        sent.unwrap();
        let envelope: ipc::ErrorEnvelope =
            serde_json::from_slice(&received.unwrap().metadata).unwrap();
        assert_eq!(envelope.code, "APPROVAL_OUTCOME_UNCONFIRMED");
        assert!(!envelope.retryable);
        assert!(envelope.approval.is_none());
        assert_eq!(
            ctx.sessions
                .local_approval(id, crate::now_ts().unwrap())
                .unwrap()
                .state,
            ipc::LocalApprovalState::Cancelled
        );
        db.execute_batch("ROLLBACK").unwrap();
        // The queued Worker command finishes after the caller timed out. Its own
        // commit deadline prevents a late audit/grant, and a query acts as a barrier.
        assert_eq!(ctx.authority.status().await.unwrap().state, "unlocked");
        let response = local_approval_decision(&frame, &ctx, admin_mutation_deadline())
            .await
            .unwrap();
        let state: ipc::LocalApprovalStateResponse = serde_json::from_slice(&response.0).unwrap();
        assert_eq!(state.state, ipc::LocalApprovalState::Cancelled);
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='approval.approved'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        ctx.authority.shutdown(Some(proof())).await.unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }

    #[tokio::test]
    async fn template_install_busy_wire_denies_retry_without_changing_other_operations() {
        for error in [
            BrokerError::Authority(AuthorityError::AuthorityBusy),
            BrokerError::Admission(AuthorityError::AuthorityBusy),
        ] {
            for (message_type, retryable) in [
                (admin_msg::TEMPLATE_INSTALL, false),
                (admin_msg::TEMPLATE_CATALOG, true),
                (admin_msg::ACTION_CREATE, true),
            ] {
                let (mut writer, mut reader) = UnixStream::pair().unwrap();
                let request_id = rekey_domain::ids::RequestId::new_random();
                let (sent, received) = tokio::join!(
                    write_admin_error(&mut writer, message_type, request_id, &error),
                    read_frame(&mut reader, Channel::Admin, |_| 0),
                );
                sent.unwrap();
                let received = received.unwrap();
                assert_eq!(received.header.message_type, ipc::resp_msg::ERROR);
                let envelope: ipc::ErrorEnvelope =
                    serde_json::from_slice(&received.metadata).unwrap();
                assert_eq!(envelope.code, "AUTHORITY_BUSY");
                assert_eq!(envelope.request_id, request_id);
                assert_eq!(envelope.retryable, retryable);
                if message_type == admin_msg::TEMPLATE_INSTALL {
                    assert!(envelope.message.contains("unconfirmed"));
                    assert!(envelope.message.contains("Actions and audit"));
                    assert!(envelope.message.contains("do not retry automatically"));
                } else {
                    assert_eq!(envelope.message, error.to_string());
                }
            }
        }
    }

    #[tokio::test]
    async fn proofless_shutdown_rejects_before_waiting_on_any_coordinator() {
        let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let owner = ctx.lifecycle.coordinate().await;
        ctx.lifecycle.enter_draining();
        let request = IncomingFrame {
            header: ipc::FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: admin_msg::SHUTDOWN,
                request_id: rekey_domain::ids::RequestId::new_random(),
                metadata_len: 2,
                body_len: 0,
            },
            metadata: b"{}".to_vec(),
            body: Zeroizing::new(Vec::new()),
        };
        let response = tokio::time::timeout(Duration::from_millis(100), dispatch(&request, &ctx))
            .await
            .unwrap();
        assert_eq!(response.unwrap_err().code(), "AUTHENTICATION_FAILED");
        assert!(!ctx.shutdown_requested());
        assert_eq!(
            ctx.lifecycle.phase(),
            crate::lifecycle::BrokerPhase::Draining
        );
        assert!(!ctx.lifecycle.try_begin_remote_effect());
        drop(owner);
        ctx.authority.lock("test-cleanup").await.unwrap();
        ctx.authority.shutdown(None).await.unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "lab")]
    async fn review_begin_waits_for_existing_owner_and_cannot_insert_after_lock() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        let (_directory, mut ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = crate::oidc_admin::tests::socketless_begin_fixture(
            ctx.authority.status().await.unwrap().vault_id,
        );
        Arc::get_mut(&mut ctx).unwrap().oidc_admin = Some(manager.clone());
        let owner = ctx.lifecycle.coordinate().await;
        let frame = IncomingFrame {
            header: ipc::FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: admin_msg::OIDC_LOGIN_BEGIN,
                request_id: rekey_domain::ids::RequestId::new_random(),
                metadata_len: 2,
                body_len: 0,
            },
            metadata: b"{}".to_vec(),
            body: Zeroizing::new(Vec::new()),
        };
        let mut pending = Box::pin(dispatch(&frame, &ctx));
        poll_fn(|cx| {
            assert!(
                pending.as_mut().poll(cx).is_pending(),
                "Begin must wait on the existing lifecycle owner"
            );
            Poll::Ready(())
        })
        .await;
        ctx.lifecycle.enter_draining();
        manager.clear();
        ctx.authority
            .lock("oidc-review-interleaving")
            .await
            .unwrap();
        ctx.lifecycle.enter_locked();
        drop(owner);
        assert_eq!(pending.await.err().unwrap().code(), "LOCKED");
        ctx.authority.shutdown(None).await.unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }

    #[test]
    fn oidc_envelope_limits_and_os_exceptions_are_closed() {
        assert_eq!(
            admin_body_limit(admin_msg::PKI_GENERATE_CRL, false),
            ipc::ADMIN_PROOF_BODY_MAX_BYTES
        );
        assert_eq!(
            admin_body_limit(admin_msg::PKI_GENERATE_CRL, true),
            ipc::ADMIN_PROOF_BODY_MAX_BYTES
        );

        for id in 1..=60 {
            let protected = ipc::managed_admin_operation(id).unwrap();
            if protected {
                assert!(admin_body_limit(id, true) >= 50);
            } else if id == admin_msg::OIDC_LOGOUT {
                assert_eq!(admin_body_limit(id, true), 43);
            }
        }
        assert_eq!(
            admin_body_limit(admin_msg::CREDENTIAL_ADD, true),
            ipc::ADMIN_SECRET_BODY_MAX_BYTES + 50
        );
        assert_eq!(
            admin_body_limit(admin_msg::UNLOCK_PASSWORD, true),
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES
        );
        assert_eq!(admin_body_limit(admin_msg::TEMPLATE_CATALOG, false), 65_536);
        assert_eq!(admin_body_limit(admin_msg::TEMPLATE_CATALOG, true), 65_586);
        assert_eq!(
            admin_body_limit(admin_msg::TEMPLATE_INSTALL, false),
            131_081
        );
        assert_eq!(admin_body_limit(admin_msg::TEMPLATE_INSTALL, true), 131_131);
        assert_eq!(
            admin_body_limit(admin_msg::PKI_REVOKE_CERTIFICATE, false),
            ipc::ADMIN_PROOF_BODY_MAX_BYTES
        );
        assert_eq!(
            admin_body_limit(admin_msg::PKI_REVOKE_CERTIFICATE, true),
            ipc::ADMIN_PROOF_BODY_MAX_BYTES
        );
        assert_eq!(admin_body_limit(admin_msg::AUDIT_QUERY, false), 0);
        assert_eq!(admin_body_limit(admin_msg::METRICS, false), 0);
    }

    #[tokio::test]
    async fn oidc_unconfigured_g1_rejects_envelope_unknown_and_preserves_plain_reads() {
        let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let request = |id, body: Vec<u8>| IncomingFrame {
            header: ipc::FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: id,
                request_id: rekey_domain::ids::RequestId::new_random(),
                metadata_len: 2,
                body_len: body.len() as u32,
            },
            metadata: b"{}".to_vec(),
            body: Zeroizing::new(body),
        };
        dispatch(&request(admin_msg::STATUS, Vec::new()), &ctx)
            .await
            .unwrap();
        let protected = ipc::encode_management_body(&[b'A'; 43], &[]).unwrap();
        assert_eq!(
            dispatch(&request(admin_msg::STATUS, protected), &ctx)
                .await
                .err()
                .unwrap()
                .code(),
            "INVALID_FRAME"
        );
        assert_eq!(
            dispatch(&request(49, Vec::new()), &ctx)
                .await
                .err()
                .unwrap()
                .code(),
            "INVALID_FRAME"
        );
        ctx.authority.lock("oidc-test-cleanup").await.unwrap();
        ctx.authority.shutdown(None).await.unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "lab")]
    async fn oidc_configured_all_managed_operations_require_body_token() {
        let (directory, mut ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let path = crate::oidc_admin::tests::protected_profile_file(
            directory.path(),
            ctx.authority.status().await.unwrap().vault_id,
        );
        Arc::get_mut(&mut ctx).unwrap().oidc_admin =
            Some(crate::oidc_admin::Manager::load(&path).unwrap());
        for id in 1..=60 {
            if !ipc::managed_admin_operation(id).unwrap() {
                continue;
            }
            let frame = IncomingFrame {
                header: ipc::FrameHeader {
                    channel: Channel::Admin,
                    flags: 0,
                    message_type: id,
                    request_id: rekey_domain::ids::RequestId::new_random(),
                    metadata_len: 2,
                    body_len: 0,
                },
                metadata: b"{}".to_vec(),
                body: Zeroizing::new(Vec::new()),
            };
            assert_eq!(
                dispatch(&frame, &ctx).await.err().unwrap().code(),
                "INVALID_FRAME",
                "message {id}"
            );
        }
        ctx.authority.lock("oidc-test-cleanup").await.unwrap();
        ctx.authority.shutdown(None).await.unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }

    #[test]
    fn oversized_action_response_is_rejected_before_upsert() {
        let headers = (0..4_096)
            .map(|index| HeaderName::new(&format!("x-header-{index:04}")).unwrap())
            .collect();
        let definition = ActionDefinition {
            native_plugin: None,
            text_stream: None,
            name: ActionName::new("large-response").unwrap(),
            credential_id: CredentialId::from_random_bytes([1; 16]),
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            method: FixedMethod::Post,
            target: rekey_domain::action::ActionTarget::Fixed {
                path: ExactPath::parse("/v1/action").unwrap(),
            },
            auth: HeaderCredentialUse::new(
                HeaderName::new("x-api-key").unwrap(),
                HeaderPrefix::new("Bearer ").unwrap(),
            )
            .unwrap(),
            timeout_ms: 1_000,
            request_policy: RequestPolicy {
                max_body_bytes: 1_024,
                allowed_extra_headers: headers,
            },
            response_policy: ResponsePolicy {
                max_body_bytes: 1_024,
                allowed_headers: Default::default(),
            },
        };

        assert!(matches!(
            ensure_action_catalog_fits(Vec::new(), None, &definition),
            Err(BrokerError::Frame(ipc::FrameError::SectionTooLarge))
        ));
    }

    #[test]
    fn aggregate_action_catalog_is_rejected_before_upsert() {
        let definition = ActionDefinition {
            native_plugin: None,
            text_stream: None,
            name: ActionName::new("catalog-entry").unwrap(),
            credential_id: CredentialId::from_random_bytes([1; 16]),
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            method: FixedMethod::Get,
            target: rekey_domain::action::ActionTarget::Fixed {
                path: ExactPath::parse("/v1/action").unwrap(),
            },
            auth: HeaderCredentialUse::new(
                HeaderName::new("x-api-key").unwrap(),
                HeaderPrefix::new("Bearer ").unwrap(),
            )
            .unwrap(),
            timeout_ms: 1_000,
            request_policy: RequestPolicy {
                max_body_bytes: 1_024,
                allowed_extra_headers: Default::default(),
            },
            response_policy: ResponsePolicy {
                max_body_bytes: 1_024,
                allowed_headers: Default::default(),
            },
        };
        let existing = FixedHttpAction {
            native_plugin: None,
            text_stream: None,
            id: ActionId::from_random_bytes([2; 16]),
            name: definition.name.clone(),
            version: 1,
            enabled: true,
            credential_id: definition.credential_id,
            origin: definition.origin.clone(),
            method: definition.method,
            target: definition.target.clone(),
            auth: definition.auth.clone(),
            timeout_ms: definition.timeout_ms,
            request_policy: definition.request_policy.clone(),
            response_policy: definition.response_policy.clone(),
        };

        assert!(matches!(
            ensure_action_catalog_fits(vec![existing; 256], None, &definition),
            Err(BrokerError::Frame(ipc::FrameError::SectionTooLarge))
        ));
    }

    #[test]
    fn action_update_replaces_the_existing_catalog_entry() {
        let headers = (0..2_200)
            .map(|index| HeaderName::new(&format!("x-update-{index:04}")).unwrap())
            .collect();
        let definition = ActionDefinition {
            native_plugin: None,
            text_stream: None,
            name: ActionName::new("large-update").unwrap(),
            credential_id: CredentialId::from_random_bytes([1; 16]),
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            method: FixedMethod::Post,
            target: rekey_domain::action::ActionTarget::Fixed {
                path: ExactPath::parse("/v1/action").unwrap(),
            },
            auth: HeaderCredentialUse::new(
                HeaderName::new("x-api-key").unwrap(),
                HeaderPrefix::new("Bearer ").unwrap(),
            )
            .unwrap(),
            timeout_ms: 1_000,
            request_policy: RequestPolicy {
                max_body_bytes: 1_024,
                allowed_extra_headers: headers,
            },
            response_policy: ResponsePolicy {
                max_body_bytes: 1_024,
                allowed_headers: Default::default(),
            },
        };
        let existing = FixedHttpAction {
            native_plugin: None,
            text_stream: None,
            id: ActionId::from_random_bytes([2; 16]),
            name: definition.name.clone(),
            version: 1,
            enabled: true,
            credential_id: definition.credential_id,
            origin: definition.origin.clone(),
            method: definition.method,
            target: definition.target.clone(),
            auth: definition.auth.clone(),
            timeout_ms: definition.timeout_ms,
            request_policy: definition.request_policy.clone(),
            response_policy: definition.response_policy.clone(),
        };

        assert!(ensure_action_catalog_fits(vec![existing.clone()], None, &definition).is_err());
        assert!(
            ensure_action_catalog_fits(vec![existing.clone()], Some(existing.id), &definition)
                .is_ok()
        );
    }

    #[test]
    fn aggregate_credential_catalog_is_rejected_before_add() {
        let label = rekey_domain::credential::CredentialLabel::new(&"x".repeat(128)).unwrap();
        let existing = CredentialMetadata {
            id: CredentialId::from_random_bytes([3; 16]),
            label: label.clone(),
            kind: CredentialKind::OpaqueToken,
            state: CredentialState::Active,
            current_version: 1,
            created_at: Timestamp::from_unix_ms(1_000_000_000_000),
            updated_at: Timestamp::from_unix_ms(1_000_000_000_000),
        };

        assert!(matches!(
            ensure_credential_catalog_fits(
                vec![existing; 256],
                &label,
                CredentialKind::OpaqueToken,
            ),
            Err(BrokerError::Frame(ipc::FrameError::SectionTooLarge))
        ));
    }
    fn exact3_set_frame(days: u64) -> IncomingFrame {
        let metadata =
            serde_json::to_vec(&rekey_domain::audit::AuditRetentionSet { days: Some(days) })
                .unwrap();
        let mut body = Vec::new();
        ipc::encode_proof_body(ProofKind::Password, b"fixture-proof", &mut body);
        IncomingFrame {
            header: ipc::FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: admin_msg::AUDIT_RETENTION_SET,
                request_id: rekey_domain::ids::RequestId::new_random(),
                metadata_len: metadata.len() as u32,
                body_len: body.len() as u32,
            },
            metadata,
            body: Zeroizing::new(body),
        }
    }

    #[tokio::test]
    async fn exact3_unknown_retention_reply_closes_queued_set_business_and_remote_before_stop_consumer()
     {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        let (dir, mut ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let mut stop = crate::runtime::tests::exact3_pause_stop_consumer(&mut ctx);
        ctx.authority
            .audit_retention_set_before(
                rekey_domain::audit::AuditRetentionSet { days: Some(1) },
                UnlockProof::Password(SecretInput::from_slice(b"fixture-proof")),
                None,
            )
            .await
            .unwrap();
        let initial = ctx.authority.audit_retention_status().await.unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        let before: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='audit.retention_changed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut blocked = Box::pin(ctx.authority.append_audit(AuditDraft {
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            request_context: None,
            usage: None,
            event_type: "fixture.blocked",
            outcome: "success",
            reason_code: "exact3".into(),
            upstream_status: None,
            latency_ms: None,
        }));
        poll_fn(|cx| {
            assert!(blocked.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let mut maintenance = Box::pin(crate::runtime::tests::exact3_maintenance(&ctx));
        poll_fn(|cx| {
            assert!(maintenance.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let frame = exact3_set_frame(2);
        let mut set = Box::pin(dispatch_operation(
            &frame,
            &ctx,
            #[cfg(feature = "lab")]
            None,
            admin_mutation_deadline(),
        ));
        poll_fn(|cx| {
            assert!(set.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let mut business = Box::pin(async {
            let _owner = ctx.lifecycle.coordinate().await;
            ctx.executor
                .admit(crate::executor::ExecuteRequest {
                    request_id: rekey_domain::ids::RequestId::new_random(),
                    capability_token: "unused-after-drain".into(),
                    action: rekey_domain::capability::ActionVersionRef {
                        action_id: rekey_domain::ids::ActionId::new_random(),
                        version: 1,
                    },
                    content_type: None,
                    extra_headers: Vec::new(),
                    params: Default::default(),
                    query: Default::default(),
                    body: Vec::new(),
                    approval_grants: Vec::new(),
                    local_approval_request_id: None,
                })
                .await
                .err()
                .unwrap()
                .code()
        });
        poll_fn(|cx| {
            assert!(business.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(maintenance.await.unwrap_err().code(), "FAULTED");
        let phase = ctx.lifecycle.phase();
        let remote_open = ctx.lifecycle.try_begin_remote_effect();
        db.execute_batch("COMMIT").unwrap();
        blocked.await.unwrap();
        let set_error = set.await.err().map(|e| e.code());
        let business_error = business.await;
        let owner = ctx.lifecycle.coordinate().await;
        let can_reopen = ctx.lifecycle.enter_running().is_ok();
        drop(owner);
        let after = ctx.authority.audit_retention_status().await.unwrap();
        let after_markers: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='audit.retention_changed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let signalled = stop();
        #[cfg(feature = "lab")]
        let calls_before = ctx
            .metrics
            .fault_signals
            .load(std::sync::atomic::Ordering::Relaxed);
        crate::runtime::tests::exact3_maintenance(&ctx)
            .await
            .unwrap();
        #[cfg(feature = "lab")]
        let no_retry = ctx
            .metrics
            .fault_signals
            .load(std::sync::atomic::Ordering::Relaxed)
            == calls_before;
        ctx.authority
            .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
                b"fixture-proof",
            ))))
            .await
            .unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
        assert_eq!(phase, crate::lifecycle::BrokerPhase::Draining);
        assert!(!remote_open && !can_reopen && signalled);
        #[cfg(feature = "lab")]
        assert!(no_retry);
        assert_eq!(set_error, Some("DRAINING"));
        assert_eq!(business_error, "DRAINING");
        assert_eq!(after, initial);
        assert_eq!(after_markers, before);
    }

    #[tokio::test]
    async fn exact3_retention_set_preserves_expired_and_near_expiry_dispatch_deadlines() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        let mut outcomes = Vec::new();
        for near_expiry in [false, true] {
            let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
            let initial = ctx.authority.audit_retention_status().await.unwrap();
            let frame = exact3_set_frame(2);
            let result = if near_expiry {
                let owner = ctx.lifecycle.coordinate().await;
                let original = tokio::time::Instant::now() + Duration::from_millis(100);
                let mut set = Box::pin(dispatch_operation(
                    &frame,
                    &ctx,
                    #[cfg(feature = "lab")]
                    None,
                    original,
                ));
                poll_fn(|cx| {
                    assert!(set.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                tokio::time::sleep(Duration::from_millis(120)).await;
                drop(owner);
                set.await
            } else {
                dispatch_operation(
                    &frame,
                    &ctx,
                    #[cfg(feature = "lab")]
                    None,
                    tokio::time::Instant::now() - Duration::from_millis(1),
                )
                .await
            };
            let after = ctx.authority.audit_retention_status().await.unwrap();
            let db =
                rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                    .unwrap();
            let changed: i64 = db
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='audit.retention_changed'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            outcomes.push((result.err().map(|e| e.code()), initial == after, changed));
            ctx.authority
                .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
                    b"fixture-proof",
                ))))
                .await
                .unwrap();
            drop(ctx);
            terminal.await.unwrap();
            join.join().unwrap();
        }
        assert_eq!(
            outcomes,
            vec![
                (Some("AUTHORITY_BUSY"), true, 0),
                (Some("AUTHORITY_BUSY"), true, 0)
            ]
        );
    }
}
