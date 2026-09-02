use rekey_domain::ipc::{self, ProofKind};
use rekey_vault::secret::SecretInput;

use super::{admin_mutation_deadline, authority_until, empty_meta, json, proof_from};
use crate::error::BrokerError;
use crate::ipc::frame::IncomingFrame;
use crate::runtime::BrokerCtx;

pub(super) async fn handle_password_change(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let deadline = admin_mutation_deadline();
    ctx.lifecycle.reject_if_not_running()?;
    empty_meta(frame)?;
    let (kind, proof, new_password) = ipc::parse_proof_and_secret_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    authority_until(
        deadline,
        ctx.authority.password_change_before(
            proof_from(kind, proof),
            SecretInput::from_slice(new_password),
            Some(deadline.into_std()),
        ),
    )
    .await?;
    Ok((json(&serde_json::json!({"changed": true}))?, Vec::new()))
}

pub(super) async fn handle_recovery_rotate(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let deadline = admin_mutation_deadline();
    ctx.lifecycle.reject_if_not_running()?;
    empty_meta(frame)?;
    let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
    if kind != ProofKind::Password {
        return Err(BrokerError::Domain(
            rekey_domain::DomainError::InvalidActionDefinition(
                "recovery rotation requires password proof".to_owned(),
            ),
        ));
    }
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    let recovery = authority_until(
        deadline,
        ctx.authority
            .recovery_rotate_before(SecretInput::from_slice(proof), Some(deadline.into_std())),
    )
    .await?;
    Ok((
        json(&serde_json::json!({"rotated": true}))?,
        recovery.as_bytes().to_vec(),
    ))
}
