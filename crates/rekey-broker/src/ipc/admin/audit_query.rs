use rekey_domain::audit::{AuditPruneRequest, AuditQuery};
use rekey_domain::ipc;

use super::{IncomingFrame, admin_mutation_deadline, json, meta, proof_from};
use crate::error::BrokerError;
use crate::runtime::BrokerCtx;

pub(super) async fn handle_audit_query(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    if !frame.body.is_empty() {
        return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
    }
    let query: AuditQuery = meta(frame)?;
    let _owner = ctx.lifecycle.coordinate().await;
    let page = ctx.authority.audit_query(query).await?;
    let body =
        serde_json::to_vec(&page).map_err(|_| BrokerError::Frame(ipc::FrameError::InvalidField))?;
    if body.len() > ipc::RESPONSE_BODY_MAX_BYTES as usize {
        return Err(BrokerError::Domain(
            rekey_domain::DomainError::ResponseTooLarge,
        ));
    }
    Ok((b"{}".to_vec(), body))
}

pub(super) async fn handle_audit_prune(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let deadline = admin_mutation_deadline();
    ctx.lifecycle.reject_if_not_running()?;
    let request: AuditPruneRequest = meta(frame)?;
    let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    let receipt = ctx
        .authority
        .audit_prune_before(request, proof_from(kind, proof), Some(deadline.into_std()))
        .await?;
    Ok((json(&receipt)?, Vec::new()))
}
