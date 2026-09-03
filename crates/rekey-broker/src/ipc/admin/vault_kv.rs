use rekey_domain::DomainError;
use rekey_domain::credential::CredentialKind;
use rekey_domain::ipc;
use rekey_vault::secret::SecretInput;

use super::{IncomingFrame, admin_mutation_deadline, authority_until, json, meta, proof_from};
use crate::error::BrokerError;
use crate::executor::vault_source::VaultKvProfile;
use crate::runtime::BrokerCtx;

pub(super) async fn handle_rotate(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    handle_rotate_kind(
        frame,
        ctx,
        CredentialKind::VaultKvV2Source,
        VaultKvProfile::validate_profile,
        "invalid Vault KV credential profile",
    )
    .await
}

pub(super) async fn handle_rotate_dynamic(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    handle_rotate_kind(
        frame,
        ctx,
        CredentialKind::VaultDynamicSource,
        crate::executor::vault_dynamic::VaultDynamicProfile::validate_profile,
        "invalid Vault dynamic credential profile",
    )
    .await
}

async fn handle_rotate_kind<E>(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    expected_kind: CredentialKind,
    validate: fn(&[u8]) -> Result<(), E>,
    error_message: &'static str,
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
        .is_none_or(|credential| credential.kind != expected_kind)
        || validate(secret).is_err()
    {
        return Err(BrokerError::Domain(DomainError::InvalidActionDefinition(
            error_message.to_owned(),
        )));
    }
    let metadata = authority_until(
        deadline,
        ctx.authority.credential_rotate_typed_before(
            reference.credential_id,
            expected_kind,
            None,
            SecretInput::from_slice(secret),
            proof_from(kind, proof),
            Some(deadline.into_std()),
        ),
    )
    .await?;
    Ok((json(&metadata)?, Vec::new()))
}
