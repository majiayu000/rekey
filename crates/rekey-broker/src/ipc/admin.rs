//! Admin channel: unlock, credential/action/session administration, backup,
//! lock, shutdown. Peer must be the state-owner UID; sensitive mutations
//! additionally require a step-up unlock proof in the frame body.

use std::path::PathBuf;
use std::sync::Arc;

use rekey_domain::Timestamp;
use rekey_domain::action::{
    ActionName, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName, HeaderPrefix, HttpsOrigin,
    RequestPolicy, ResponsePolicy,
};
use rekey_domain::capability::SessionGrant;
use rekey_domain::ids::SessionId;
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};
use rekey_vault::command::{ActionDefinition, AuditDraft, UnlockProof};
use rekey_vault::model::{ActionState, event_type, outcome};
use rekey_vault::secret::SecretInput;
use tokio::net::UnixStream;

use crate::error::BrokerError;
use crate::ipc::frame::{FrameIoError, IncomingFrame, read_frame, write_error, write_ok};
use crate::ipc::peer;
use crate::runtime::BrokerCtx;
use crate::session::CreateSessionError;

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

fn json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, BrokerError> {
    serde_json::to_vec(value)
        .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))
}

fn now_ts() -> Timestamp {
    Timestamp::from_unix_ms(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
    )
}

pub async fn handle_admin_conn(mut stream: UnixStream, ctx: Arc<BrokerCtx>) {
    match peer::peer_uid(&stream) {
        Ok(uid) if uid == peer::current_uid() => {}
        _ => return,
    }
    loop {
        let frame = match read_frame(
            &mut stream,
            Channel::Admin,
            ipc::ADMIN_SECRET_BODY_MAX_BYTES,
        )
        .await
        {
            Ok(frame) => frame,
            Err(FrameIoError::Closed) => return,
            Err(_) => return,
        };
        let request_id = frame.header.request_id;
        let response = dispatch(&frame, &ctx).await;
        let io_result = match response {
            Ok((metadata, body)) => {
                write_ok(&mut stream, Channel::Admin, request_id, &metadata, &body).await
            }
            Err(err) => {
                write_error(
                    &mut stream,
                    Channel::Admin,
                    request_id,
                    err.code(),
                    &err.to_string(),
                    err.retryable(),
                )
                .await
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

async fn dispatch(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    match frame.header.message_type {
        admin_msg::STATUS => {
            empty_meta(frame)?;
            let status = ctx.authority.status().await?;
            let response = ipc::StatusResponse {
                state: status.state.to_owned(),
                format_version: status.format_version,
                runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
                sessions_active: ctx.sessions.active_count(now_ts()),
            };
            Ok((json(&response)?, Vec::new()))
        }
        admin_msg::UNLOCK_PASSWORD => {
            empty_meta(frame)?;
            let proof = UnlockProof::Password(SecretInput::from_slice(&frame.body));
            ctx.unlock(proof).await?;
            Ok((json(&serde_json::json!({"unlocked": true}))?, Vec::new()))
        }
        admin_msg::UNLOCK_RECOVERY => {
            empty_meta(frame)?;
            let proof = UnlockProof::Recovery(SecretInput::from_slice(&frame.body));
            ctx.unlock(proof).await?;
            Ok((json(&serde_json::json!({"unlocked": true}))?, Vec::new()))
        }
        admin_msg::CREDENTIAL_ADD => {
            ctx.lifecycle.reject_if_not_running()?;
            let add_meta: ipc::CredentialAddMeta = meta(frame)?;
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let metadata = ctx
                .authority
                .credential_add(
                    add_meta.label,
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                )
                .await?;
            Ok((json(&metadata)?, Vec::new()))
        }
        admin_msg::CREDENTIAL_LIST => {
            empty_meta(frame)?;
            let credentials = ctx.authority.credential_list().await?;
            Ok((
                json(&ipc::CredentialListResponse { credentials })?,
                Vec::new(),
            ))
        }
        admin_msg::CREDENTIAL_ROTATE => {
            ctx.lifecycle.reject_if_not_running()?;
            let ref_meta: ipc::CredentialRefMeta = meta(frame)?;
            let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
            let metadata = ctx
                .authority
                .credential_rotate(
                    ref_meta.credential_id,
                    SecretInput::from_slice(secret),
                    proof_from(kind, proof),
                )
                .await?;
            Ok((json(&metadata)?, Vec::new()))
        }
        admin_msg::CREDENTIAL_REVOKE => {
            ctx.lifecycle.reject_if_not_running()?;
            let ref_meta: ipc::CredentialRefMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let metadata = ctx
                .authority
                .credential_revoke(ref_meta.credential_id, proof_from(kind, proof))
                .await?;
            // Revocation commits first; then in-memory sessions bound to the
            // credential's actions are invalidated. Lease resolution re-checks
            // persisted state anyway, so this is defense in depth.
            let action_ids = ctx
                .authority
                .action_ids_for_credential(ref_meta.credential_id)
                .await?;
            ctx.sessions.revoke_by_actions(&action_ids);
            Ok((json(&metadata)?, Vec::new()))
        }
        admin_msg::ACTION_CREATE | admin_msg::ACTION_UPDATE => {
            ctx.lifecycle.reject_if_not_running()?;
            let (existing, definition_meta) =
                if frame.header.message_type == admin_msg::ACTION_UPDATE {
                    let update: ipc::ActionUpdateMeta = meta(frame)?;
                    (Some(update.action_id), update.definition)
                } else {
                    (None, meta::<ipc::ActionCreateMeta>(frame)?)
                };
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let definition = definition_from_meta(definition_meta)?;
            let action = ctx
                .authority
                .action_upsert(existing, definition, proof_from(kind, proof))
                .await?;
            Ok((json(&action)?, Vec::new()))
        }
        admin_msg::ACTION_DISABLE => {
            ctx.lifecycle.reject_if_not_running()?;
            let ref_meta: ipc::ActionRefMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            ctx.authority
                .action_disable(ref_meta.action_id, proof_from(kind, proof))
                .await?;
            ctx.sessions.revoke_by_actions(&[ref_meta.action_id]);
            Ok((json(&serde_json::json!({"disabled": true}))?, Vec::new()))
        }
        admin_msg::ACTION_LIST => {
            empty_meta(frame)?;
            let actions = ctx.authority.action_list().await?;
            Ok((json(&ipc::ActionListResponse { actions })?, Vec::new()))
        }
        admin_msg::SESSION_CREATE => {
            ctx.lifecycle.reject_if_not_running()?;
            let create: ipc::SessionCreateMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            ctx.authority.verify_proof(proof_from(kind, proof)).await?;
            ctx.lifecycle.reject_if_not_running()?;
            // New sessions may pin only Active versions. Retired stays
            // executable for grants issued while it was Active.
            for r in &create.actions {
                let pinned = ctx.authority.action_get(r.action_id, r.version).await?;
                if pinned.state != ActionState::Active {
                    return Err(BrokerError::Domain(
                        rekey_domain::DomainError::ActionDisabled,
                    ));
                }
            }
            let session_id = SessionId::new_random();
            let grant = SessionGrant::new(
                session_id,
                create.actions,
                now_ts(),
                create.ttl_ms,
                create.max_uses,
            )
            .map_err(BrokerError::Domain)?;
            let expires_at_ms = grant.expires_at.as_unix_ms();
            let max_uses = grant.max_uses;
            let token = ctx.sessions.admit(grant).map_err(|err| match err {
                CreateSessionError::Closed => {
                    BrokerError::Authority(rekey_vault::AuthorityError::Draining)
                }
                CreateSessionError::Domain(err) => BrokerError::Domain(err),
            })?;
            ctx.authority
                .append_audit(session_audit(event_type::SESSION_CREATED, session_id))
                .await?;
            let response = ipc::SessionCreatedResponse {
                session_id,
                capability_token: token,
                expires_at_ms,
                max_uses,
            };
            Ok((json(&response)?, Vec::new()))
        }
        admin_msg::SESSION_REVOKE => {
            ctx.lifecycle.reject_if_not_running()?;
            let revoke: ipc::SessionRevokeMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            ctx.authority.verify_proof(proof_from(kind, proof)).await?;
            let existed = ctx.sessions.revoke(revoke.session_id);
            ctx.authority
                .append_audit(session_audit(
                    event_type::SESSION_REVOKED,
                    revoke.session_id,
                ))
                .await?;
            Ok((json(&serde_json::json!({"revoked": existed}))?, Vec::new()))
        }
        admin_msg::BACKUP => {
            ctx.lifecycle.reject_if_not_running()?;
            let backup: ipc::BackupMeta = meta(frame)?;
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
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
            };
            Ok((json(&receipt)?, Vec::new()))
        }
        admin_msg::LOCK => {
            empty_meta(frame)?;
            ctx.drain_lock("admin").await?;
            Ok((json(&serde_json::json!({"locked": true}))?, Vec::new()))
        }
        admin_msg::SHUTDOWN => {
            empty_meta(frame)?;
            let proof = if frame.body.is_empty() {
                None
            } else {
                let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
                Some(proof_from(kind, proof))
            };
            ctx.drain_and_shutdown(proof).await?;
            Ok((json(&serde_json::json!({"shutdown": true}))?, Vec::new()))
        }
        _ => Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::InvalidField,
        )),
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
        event_type,
        outcome: outcome::SUCCESS,
        reason_code: "admin".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

fn definition_from_meta(meta: ipc::ActionCreateMeta) -> Result<ActionDefinition, BrokerError> {
    let mut allowed_extra_headers = std::collections::BTreeSet::new();
    for name in &meta.allowed_extra_headers {
        allowed_extra_headers.insert(HeaderName::new(name).map_err(BrokerError::Domain)?);
    }
    let mut allowed_response_headers = std::collections::BTreeSet::new();
    for name in &meta.allowed_response_headers {
        allowed_response_headers.insert(HeaderName::new(name).map_err(BrokerError::Domain)?);
    }
    Ok(ActionDefinition {
        name: ActionName::new(&meta.name).map_err(BrokerError::Domain)?,
        credential_id: meta.credential_id,
        origin: HttpsOrigin::parse(&meta.origin).map_err(BrokerError::Domain)?,
        method: FixedMethod::parse(&meta.method).map_err(BrokerError::Domain)?,
        exact_path: ExactPath::parse(&meta.exact_path).map_err(BrokerError::Domain)?,
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
