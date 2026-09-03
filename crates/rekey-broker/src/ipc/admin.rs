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

const ADMIN_MUTATION_TIMEOUT: Duration = Duration::from_secs(25);

mod audit_query;
mod credential_profiles;
mod github;
mod password_lifecycle;
mod vault_kv;

fn admin_body_limit(message_type: u16) -> u32 {
    match message_type {
        admin_msg::UNLOCK_PASSWORD | admin_msg::UNLOCK_RECOVERY => {
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES
        }
        admin_msg::CREDENTIAL_ADD | admin_msg::CREDENTIAL_ROTATE | admin_msg::PASSWORD_CHANGE => {
            ipc::ADMIN_SECRET_BODY_MAX_BYTES
        }
        admin_msg::CREDENTIAL_ROTATE_GITHUB_APP
        | admin_msg::GITHUB_WEBHOOK_APPLY
        | admin_msg::CREDENTIAL_ROTATE_VAULT_KV => ipc::ADMIN_SECRET_BODY_MAX_BYTES,
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
        | admin_msg::RECOVERY_ROTATE => ipc::ADMIN_PROOF_BODY_MAX_BYTES,
        _ => 0,
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

pub async fn handle_admin_conn(
    mut stream: UnixStream,
    ctx: Arc<BrokerCtx>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let frame = match tokio::select! {
            _ = shutdown.changed() => return,
            frame = read_frame(
                &mut stream,
                Channel::Admin,
                admin_body_limit,
            ) => frame,
        } {
            Ok(frame) => frame,
            Err(FrameIoError::Closed) => return,
            Err(_) => return,
        };
        let request_id = frame.header.request_id;
        let is_shutdown = frame.header.message_type == admin_msg::SHUTDOWN;
        let response = if is_shutdown {
            dispatch(&frame, &ctx).await
        } else {
            tokio::select! {
                _ = shutdown.changed() => return,
                response = dispatch(&frame, &ctx) => response,
            }
        };
        let write_response = async {
            match response {
                Ok((metadata, body)) => {
                    let body = Zeroizing::new(body);
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

async fn dispatch(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    match frame.header.message_type {
        admin_msg::STATUS => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let status = ctx.authority.admin_status().await?;
            let response = ipc::StatusResponse {
                state: status.state.to_owned(),
                format_version: status.format_version,
                runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
                sessions_active: ctx.sessions.active_count(crate::now_ts()?),
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
        admin_msg::PASSWORD_CHANGE => password_lifecycle::handle_password_change(frame, ctx).await,
        admin_msg::RECOVERY_ROTATE => password_lifecycle::handle_recovery_rotate(frame, ctx).await,
        admin_msg::AUDIT_QUERY => audit_query::handle_audit_query(frame, ctx).await,
        admin_msg::CREDENTIAL_ADD => {
            let deadline = admin_mutation_deadline();
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
            Ok((json(&metadata)?, Vec::new()))
        }
        admin_msg::CREDENTIAL_LIST => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let credentials = ctx.authority.credential_list().await?;
            Ok((
                json(&ipc::CredentialListResponse { credentials })?,
                Vec::new(),
            ))
        }
        admin_msg::CREDENTIAL_ROTATE => {
            let deadline = admin_mutation_deadline();
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
            Ok((json(&metadata)?, Vec::new()))
        }
        admin_msg::CREDENTIAL_ROTATE_GITHUB_APP => github::handle_rotate(frame, ctx).await,
        admin_msg::GITHUB_WEBHOOK_APPLY => github::handle_webhook(frame, ctx).await,
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV => vault_kv::handle_rotate(frame, ctx).await,
        admin_msg::CREDENTIAL_REVOKE => {
            let deadline = admin_mutation_deadline();
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
            Ok((json(&metadata)?, Vec::new()))
        }
        admin_msg::ACTION_CREATE | admin_msg::ACTION_UPDATE => {
            let deadline = admin_mutation_deadline();
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
            Ok((json(&action)?, Vec::new()))
        }
        admin_msg::ACTION_DISABLE => {
            let deadline = admin_mutation_deadline();
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
            Ok((json(&serde_json::json!({"disabled": true}))?, Vec::new()))
        }
        admin_msg::ACTION_LIST => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let actions = ctx.authority.action_list().await?;
            Ok((json(&ipc::ActionListResponse { actions })?, Vec::new()))
        }
        admin_msg::SESSION_CREATE => {
            let deadline = admin_mutation_deadline();
            ctx.lifecycle.reject_if_not_running()?;
            let create: ipc::SessionCreateMeta = meta(frame)?;
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
            let principal_id = crate::random_id(PrincipalId::from_random_bytes)?;
            let vault_id = authority_until(deadline, ctx.authority.status())
                .await?
                .vault_id;
            let principal = Principal {
                tenant_id: TenantId::from_bytes(*vault_id.as_bytes())
                    .map_err(BrokerError::Domain)?,
                principal_id,
                session_id,
            };
            let grant = SessionGrant::new(
                session_id,
                principal,
                create.actions,
                crate::now_ts()?,
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
            let response = ipc::SessionCreatedResponse {
                session_id,
                principal_id,
                capability_token: token,
                expires_at_ms,
                max_uses,
            };
            Ok((json(&response)?, Vec::new()))
        }
        admin_msg::POLICY_ACTIVATE => {
            let deadline = admin_mutation_deadline();
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            ctx.activate_policy_until(&frame.metadata, proof_from(kind, proof), deadline)
                .await?;
            Ok((json(&ctx.policy_status().await?)?, Vec::new()))
        }
        admin_msg::POLICY_TRUST_INSTALL => {
            let deadline = admin_mutation_deadline();
            let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
            let trust = rekey_policy::parse_policy_trust(&frame.metadata)?;
            ctx.install_policy_trust_until(trust, proof_from(kind, proof), deadline)
                .await?;
            Ok((json(&ctx.policy_status().await?)?, Vec::new()))
        }
        admin_msg::POLICY_STATUS => {
            empty_request(frame)?;
            let _owner = ctx.lifecycle.coordinate().await;
            let response = ctx.policy_status().await?;
            Ok((json(&response)?, Vec::new()))
        }
        admin_msg::SESSION_REVOKE => {
            let deadline = admin_mutation_deadline();
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
            Ok((json(&serde_json::json!({"revoked": existed}))?, Vec::new()))
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
            };
            Ok((json(&receipt)?, Vec::new()))
        }
        admin_msg::LOCK => {
            empty_request(frame)?;
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
            ctx.request_admin_shutdown(proof).await?;
            Ok((json(&serde_json::json!({"shutdown": true}))?, Vec::new()))
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

fn ensure_action_catalog_fits(
    mut actions: Vec<FixedHttpAction>,
    existing: Option<ActionId>,
    definition: &ActionDefinition,
) -> Result<(), BrokerError> {
    if let Some(existing) = existing {
        actions.retain(|action| action.id != existing);
    }
    let probe = FixedHttpAction {
        id: ActionId::from_random_bytes([0xff; 16]),
        name: definition.name.clone(),
        version: u64::MAX,
        enabled: true,
        credential_id: definition.credential_id,
        origin: definition.origin.clone(),
        method: definition.method,
        exact_path: definition.exact_path.clone(),
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

    #[test]
    fn oversized_action_response_is_rejected_before_upsert() {
        let headers = (0..4_096)
            .map(|index| HeaderName::new(&format!("x-header-{index:04}")).unwrap())
            .collect();
        let definition = ActionDefinition {
            name: ActionName::new("large-response").unwrap(),
            credential_id: CredentialId::from_random_bytes([1; 16]),
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            method: FixedMethod::Post,
            exact_path: ExactPath::parse("/v1/action").unwrap(),
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
            name: ActionName::new("catalog-entry").unwrap(),
            credential_id: CredentialId::from_random_bytes([1; 16]),
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            method: FixedMethod::Get,
            exact_path: ExactPath::parse("/v1/action").unwrap(),
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
            id: ActionId::from_random_bytes([2; 16]),
            name: definition.name.clone(),
            version: 1,
            enabled: true,
            credential_id: definition.credential_id,
            origin: definition.origin.clone(),
            method: definition.method,
            exact_path: definition.exact_path.clone(),
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
            name: ActionName::new("large-update").unwrap(),
            credential_id: CredentialId::from_random_bytes([1; 16]),
            origin: HttpsOrigin::parse("https://example.com").unwrap(),
            method: FixedMethod::Post,
            exact_path: ExactPath::parse("/v1/action").unwrap(),
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
            id: ActionId::from_random_bytes([2; 16]),
            name: definition.name.clone(),
            version: 1,
            enabled: true,
            credential_id: definition.credential_id,
            origin: definition.origin.clone(),
            method: definition.method,
            exact_path: definition.exact_path.clone(),
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
}
