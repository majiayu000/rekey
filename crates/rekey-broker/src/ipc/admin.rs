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
#[cfg(feature = "lab")]
mod vault_kv;

fn admin_body_limit(message_type: u16, managed: bool) -> u32 {
    let base = match message_type {
        admin_msg::OIDC_LOGOUT => 43,
        admin_msg::DESKTOP_LOGIN
        | admin_msg::DESKTOP_REVEAL
        | admin_msg::DESKTOP_REMEMBER
        | admin_msg::DESKTOP_RESUME => ipc::ADMIN_PROOF_BODY_MAX_BYTES,
        admin_msg::DESKTOP_ADD | admin_msg::TEMPLATE_INSTALL => ipc::ADMIN_SECRET_BODY_MAX_BYTES,
        admin_msg::TEMPLATE_CATALOG => ipc::ADMIN_SECRET_FIELD_MAX_BYTES,
        admin_msg::UNLOCK_PASSWORD | admin_msg::UNLOCK_RECOVERY => {
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES
        }
        admin_msg::CREDENTIAL_ADD
        | admin_msg::CREDENTIAL_ROTATE
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
        admin_msg::CREDENTIAL_REVOKE
        | admin_msg::ACTION_CREATE
        | admin_msg::ACTION_UPDATE
        | admin_msg::ACTION_DISABLE
        | admin_msg::SESSION_CREATE
        | admin_msg::SESSION_REVOKE
        | admin_msg::BACKUP
        | admin_msg::SHUTDOWN
        | admin_msg::POLICY_ACTIVATE
        | admin_msg::POLICY_TRUST_INSTALL
        | admin_msg::AUDIT_PRUNE
        | admin_msg::AUDIT_RETENTION_SET
        | admin_msg::KEY_ROTATE_DEK
        | admin_msg::RECOVERY_ROTATE => ipc::ADMIN_PROOF_BODY_MAX_BYTES,
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
        && matches!(error, BrokerError::Authority(AuthorityError::AuthorityBusy));
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
        let io_result = if is_shutdown {
            write_response.await
        } else {
            tokio::select! {
                _ = shutdown.changed() => return,
                result = write_response => result,
            }
        };
        if io_result.is_err() {
            return;
        }
        if ctx.shutdown_requested() {
            return;
        }
    }
}

#[cfg(feature = "lab")]
async fn dispatch(frame: &IncomingFrame, ctx: &BrokerCtx) -> Result<AdminResponse, BrokerError> {
    let deadline = admin_mutation_deadline();
    let managed = ipc::managed_admin_operation(frame.header.message_type)?;
    if !managed {
        return dispatch_operation(frame, ctx, None, deadline).await;
    }
    match &ctx.oidc_admin {
        Some(manager) => {
            let (token, original) = ipc::parse_management_body(&frame.body)?;
            let admission = manager.admit(token, ctx, deadline).await?;
            let original = IncomingFrame {
                header: frame.header,
                metadata: frame.metadata.clone(),
                body: Zeroizing::new(original.to_vec()),
            };
            dispatch_operation(&original, ctx, Some(&admission), deadline).await
        }
        None => {
            if frame.body.starts_with(b"RKAU") {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            dispatch_operation(frame, ctx, None, deadline).await
        }
    }
}

#[cfg(not(feature = "lab"))]
async fn dispatch(frame: &IncomingFrame, ctx: &BrokerCtx) -> Result<AdminResponse, BrokerError> {
    if frame.body.starts_with(b"RKAU") {
        return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
    }
    dispatch_operation(frame, ctx, admin_mutation_deadline()).await
}

async fn dispatch_operation(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    #[cfg(feature = "lab")] admission: Option<&crate::oidc_admin::Admission>,
    request_deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
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
            };
            Ok((json(&response)?, Zeroizing::new(Vec::new())))
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
            let metadata = authority_until(
                deadline,
                ctx.authority.credential_add_before(
                    add_meta.label,
                    add_meta.kind,
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((json(&metadata)?, Zeroizing::new(Vec::new())))
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
            let metadata = authority_until(
                deadline,
                ctx.authority.credential_rotate_before(
                    ref_meta.credential_id,
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                    Some(deadline.into_std()),
                ),
            )
            .await?;
            Ok((json(&metadata)?, Zeroizing::new(Vec::new())))
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
            Ok((json(&metadata)?, Zeroizing::new(Vec::new())))
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
        admin_msg::APPROVAL_PENDING => {
            empty_request(frame)?;
            ctx.lifecycle.reject_if_not_running()?;
            let _owner = ctx.lifecycle.coordinate().await;
            ctx.lifecycle.reject_if_not_running()?;
            let challenges = ctx
                .sessions
                .pending_approval_challenges(crate::now_ts()?)
                .map_err(|error| BrokerError::Denied(error.code()))?;
            let response = ipc::ApprovalPendingResponse {
                record_type: "rekey.approval.pending.v1".to_owned(),
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
            let challenge = ctx
                .sessions
                .approval_challenge(get.approval_request_id, crate::now_ts()?)
                .map_err(|error| BrokerError::Denied(error.code()))?;
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
                return Err(BrokerError::Authority(AuthorityError::AuthenticationFailed));
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

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::ids::CredentialId;

    #[tokio::test]
    async fn template_install_busy_wire_denies_retry_without_changing_other_operations() {
        for (message_type, retryable) in [
            (admin_msg::TEMPLATE_INSTALL, false),
            (admin_msg::TEMPLATE_CATALOG, true),
            (admin_msg::ACTION_CREATE, true),
        ] {
            let (mut writer, mut reader) = UnixStream::pair().unwrap();
            let request_id = rekey_domain::ids::RequestId::new_random();
            let error = BrokerError::Authority(AuthorityError::AuthorityBusy);
            let (sent, received) = tokio::join!(
                write_admin_error(&mut writer, message_type, request_id, &error),
                read_frame(&mut reader, Channel::Admin, |_| 0),
            );
            sent.unwrap();
            let received = received.unwrap();
            assert_eq!(received.header.message_type, ipc::resp_msg::ERROR);
            let envelope: ipc::ErrorEnvelope = serde_json::from_slice(&received.metadata).unwrap();
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
        for id in 1..=54 {
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
        for id in 1..=54 {
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
