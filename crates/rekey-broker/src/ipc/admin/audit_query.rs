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

pub(super) async fn handle_retention_set(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    ctx.lifecycle.reject_if_not_running()?;
    let request: rekey_domain::audit::AuditRetentionSet = meta(frame)?;
    let (kind, proof) = ipc::parse_proof_body(&frame.body)?;
    let _owner = ctx.lifecycle.coordinate_until(deadline).await?;
    ctx.lifecycle.reject_if_not_running()?;
    let receipt = ctx
        .authority
        .audit_retention_set_before(request, proof_from(kind, proof), Some(deadline.into_std()))
        .await?;
    Ok((json(&receipt)?, Vec::new()))
}
pub(super) async fn handle_retention_status(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    super::empty_request(frame)?;
    let _owner = ctx.lifecycle.coordinate().await;
    ctx.lifecycle.reject_if_busy()?;
    let receipt = ctx.authority.audit_retention_status().await?;
    Ok((json(&receipt)?, Vec::new()))
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use rekey_domain::ids::RequestId;
    use rekey_domain::ipc::{Channel, FrameHeader, admin_msg};
    use rekey_vault::command::UnlockProof;
    use rekey_vault::secret::SecretInput;
    fn frame(op: u16, metadata: &[u8], proof: Option<&[u8]>) -> IncomingFrame {
        let mut body = Vec::new();
        if let Some(proof) = proof {
            ipc::encode_proof_body(ipc::ProofKind::Password, proof, &mut body);
        }
        IncomingFrame {
            header: FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: op,
                request_id: RequestId::new_random(),
                metadata_len: metadata.len() as u32,
                body_len: body.len() as u32,
            },
            metadata: metadata.to_vec(),
            body: zeroize::Zeroizing::new(body),
        }
    }
    #[tokio::test]
    async fn retention_handlers_strict_metadata_individual_proof_and_lock_order() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        for metadata in [b"{}".as_slice(), b"{\"days\":1,\"extra\":true}"] {
            assert!(
                handle_retention_set(
                    &frame(
                        admin_msg::AUDIT_RETENTION_SET,
                        metadata,
                        Some(b"fixture-proof")
                    ),
                    &ctx,
                    admin_mutation_deadline()
                )
                .await
                .is_err()
            );
        }
        assert_eq!(
            handle_retention_set(
                &frame(
                    admin_msg::AUDIT_RETENTION_SET,
                    b"{\"days\":1}",
                    Some(b"wrong")
                ),
                &ctx,
                admin_mutation_deadline()
            )
            .await
            .unwrap_err()
            .code(),
            "INVALID_UNLOCK_CREDENTIAL"
        );
        let (metadata, body) = handle_retention_set(
            &frame(
                admin_msg::AUDIT_RETENTION_SET,
                b"{\"days\":1}",
                Some(b"fixture-proof"),
            ),
            &ctx,
            admin_mutation_deadline(),
        )
        .await
        .unwrap();
        assert!(body.is_empty());
        let receipt: rekey_domain::audit::AuditRetentionStatus =
            serde_json::from_slice(&metadata).unwrap();
        assert_eq!(receipt.days, Some(1));
        assert!(
            handle_retention_set(
                &frame(admin_msg::AUDIT_RETENTION_SET, b"{\"days\":null}", None),
                &ctx,
                admin_mutation_deadline()
            )
            .await
            .is_err(),
            "SET cannot reuse an earlier proof"
        );
        assert!(
            handle_retention_status(
                &frame(admin_msg::AUDIT_RETENTION_STATUS, b"{\"extra\":true}", None),
                &ctx
            )
            .await
            .is_err()
        );
        let owner = ctx.lifecycle.coordinate().await;
        let input = frame(
            admin_msg::AUDIT_RETENTION_SET,
            b"{\"days\":null}",
            Some(b"fixture-proof"),
        );
        let mut pending = Box::pin(handle_retention_set(
            &input,
            &ctx,
            admin_mutation_deadline(),
        ));
        poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        ctx.authority.lock("test").await.unwrap();
        ctx.lifecycle.enter_locked();
        drop(owner);
        assert_eq!(pending.await.unwrap_err().code(), "LOCKED");
        ctx.authority
            .unlock(UnlockProof::Password(SecretInput::from_slice(
                b"fixture-proof",
            )))
            .await
            .unwrap();
        assert_eq!(
            ctx.authority.audit_retention_status().await.unwrap(),
            receipt,
            "a set waiting behind lock cannot change the row"
        );
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
}
