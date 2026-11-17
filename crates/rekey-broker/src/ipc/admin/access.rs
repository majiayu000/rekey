//! ACCESS_RESOLVE: list, decide or block Agent access requests (§7.2).
//! Decisions and block changes need a fresh step-up proof; the list is public.
use rekey_domain::ipc;

use super::{AdminResponse, IncomingFrame, Zeroizing, authority_until, json, meta, proof_from};
use crate::error::BrokerError;
use crate::runtime::BrokerCtx;

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

pub(super) async fn handle(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<AdminResponse, BrokerError> {
    let operation = meta::<AccessAdmin>(frame)?;
    if let AccessAdmin::List = operation {
        if !frame.body.is_empty() {
            return Err(ipc::FrameError::InvalidField.into());
        }
        return Ok((
            b"{}".to_vec(),
            Zeroizing::new(json(&ctx.local_calls.access_list()?)?),
        ));
    }
    let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    authority_until(
        deadline,
        ctx.authority.verify_proof(proof_from(kind, proof)),
    )
    .await?;
    let response = match operation {
        AccessAdmin::Resolve {
            request_id,
            granted,
            block_caller,
        } => json(
            &ctx.resolve_access_request(request_id, granted, block_caller)
                .await?,
        )?,
        AccessAdmin::Block { caller, blocked } => {
            if caller.is_empty() || caller.len() > 256 || caller.chars().any(char::is_control) {
                return Err(ipc::FrameError::InvalidField.into());
            }
            ctx.set_access_block(caller, blocked).await?;
            json(&serde_json::json!({ "blocked": blocked }))?
        }
        AccessAdmin::List => unreachable!("answered before the proof check"),
    };
    Ok((b"{}".to_vec(), Zeroizing::new(response)))
}
