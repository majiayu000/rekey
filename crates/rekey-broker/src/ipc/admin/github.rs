//! GitHub App-specific Admin mutations.

use rekey_domain::DomainError;
use rekey_domain::credential::CredentialKind;
use rekey_domain::ipc;
use rekey_vault::secret::SecretInput;

use super::{IncomingFrame, admin_mutation_deadline, authority_until, json, meta, proof_from};
use crate::error::BrokerError;
use crate::github_app::{GitHubAppCredential, GitHubError};
use crate::runtime::BrokerCtx;

pub(super) async fn handle_rotate(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let deadline = admin_mutation_deadline();
    ctx.lifecycle.reject_if_not_running()?;
    let reference: ipc::CredentialRefMeta = meta(frame)?;
    let (kind, proof, secret) = ipc::parse_proof_and_secret_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    authority_until(
        deadline,
        ctx.authority.verify_proof(proof_from(kind, proof)),
    )
    .await?;
    let credentials = authority_until(deadline, ctx.authority.credential_list()).await?;
    if credentials
        .iter()
        .find(|credential| credential.id == reference.credential_id)
        .is_none_or(|credential| credential.kind != CredentialKind::GitHubAppInstallation)
    {
        return Err(admin_error(GitHubError::InvalidCredential));
    }
    GitHubAppCredential::validate_profile(secret).map_err(admin_error)?;
    let metadata = authority_until(
        deadline,
        ctx.authority.credential_rotate_typed_before(
            reference.credential_id,
            CredentialKind::GitHubAppInstallation,
            None,
            SecretInput::from_slice(secret),
            proof_from(kind, proof),
            Some(deadline.into_std()),
        ),
    )
    .await?;
    Ok((json(&metadata)?, Vec::new()))
}

pub(super) async fn handle_webhook(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let deadline = admin_mutation_deadline();
    ctx.lifecycle.reject_if_not_running()?;
    let metadata: ipc::GitHubWebhookApplyMeta = meta(frame)?;
    let (kind, proof, payload) = ipc::parse_proof_and_secret_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    authority_until(
        deadline,
        ctx.authority.verify_proof(proof_from(kind, proof)),
    )
    .await?;
    if metadata.expected_version == 0
        || metadata.event != "installation_repositories"
        || !valid_uuid(&metadata.delivery)
    {
        return Err(admin_error(GitHubError::WebhookPayload));
    }
    let prepared = authority_until(
        deadline,
        ctx.authority.prepare_credential(metadata.credential_id),
    )
    .await?;
    if prepared.kind() != CredentialKind::GitHubAppInstallation
        || prepared.version() != metadata.expected_version
    {
        return Err(admin_error(GitHubError::WebhookPayload));
    }
    let mut profile = prepared
        .consume(GitHubAppCredential::parse_profile)
        .map_err(admin_error)?;
    profile
        .verify_webhook(payload, &metadata.signature)
        .map_err(admin_error)?;
    profile
        .apply_repository_webhook(payload)
        .map_err(admin_error)?;
    let secret = profile.to_secret_json().map_err(admin_error)?;
    let result = authority_until(
        deadline,
        ctx.authority.credential_rotate_typed_before(
            metadata.credential_id,
            CredentialKind::GitHubAppInstallation,
            Some(metadata.expected_version),
            SecretInput::from_slice(&secret),
            proof_from(kind, proof),
            Some(deadline.into_std()),
        ),
    )
    .await?;
    Ok((json(&result)?, Vec::new()))
}

fn admin_error(error: GitHubError) -> BrokerError {
    BrokerError::Domain(DomainError::InvalidActionDefinition(
        error.reason().to_owned(),
    ))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
