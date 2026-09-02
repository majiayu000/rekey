use rekey_domain::audit::AuditQuery;
use rekey_domain::ipc;

use super::{IncomingFrame, meta};
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
