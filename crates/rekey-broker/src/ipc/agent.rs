//! Agent channel: fixed action execution and a redacted status subset. No
//! admin messages, no secret reads, no target/auth inputs.

use std::sync::Arc;

use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{self, Channel, agent_msg};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::error::BrokerError;
use crate::executor::ExecuteRequest;
use crate::ipc::frame::{IncomingFrame, read_frame, write_error, write_ok};
use crate::ipc::peer;
use crate::runtime::BrokerCtx;

/// Agents must not distinguish credential-layer failures.
fn agent_code(err: &BrokerError) -> &'static str {
    match err.code() {
        "CRYPTO_FAILURE" | "STORAGE_INTEGRITY_FAILED" | "CREDENTIAL_CONFLICT" => {
            "CREDENTIAL_UNAVAILABLE"
        }
        code => code,
    }
}

pub async fn handle_agent_conn(
    mut stream: UnixStream,
    ctx: Arc<BrokerCtx>,
    mut shutdown: watch::Receiver<bool>,
) {
    match peer::peer_uid(&stream) {
        Ok(uid) if ctx.agent_uid_allowed(uid) => {}
        _ => return,
    }
    loop {
        if *shutdown.borrow() {
            return;
        }
        let frame = match tokio::select! {
            _ = shutdown.changed() => return,
            frame = read_frame(&mut stream, Channel::Agent, |message_type| {
                if message_type == agent_msg::EXECUTE_FIXED_HTTP_ACTION {
                    ipc::AGENT_BODY_MAX_BYTES
                } else {
                    0
                }
            }) => frame,
        } {
            Ok(frame) => frame,
            Err(crate::ipc::frame::FrameIoError::InboundSectionTooLarge(request_id)) => {
                if let Err(error) = write_error(
                    &mut stream,
                    Channel::Agent,
                    request_id,
                    "INVALID_FRAME",
                    "frame section exceeds limit",
                    false,
                )
                .await
                {
                    tracing::debug!(event = "agent.invalid_frame_reply_failed", %error);
                }
                return;
            }
            Err(_) => return,
        };
        let request_id = frame.header.request_id;
        let response = tokio::select! {
            _ = shutdown.changed() => return,
            response = dispatch(&frame, &ctx) => response,
        };
        let write_response = async {
            match response {
                Ok((metadata, body)) => {
                    write_ok(&mut stream, Channel::Agent, request_id, &metadata, &body).await
                }
                Err(err) => {
                    write_error(
                        &mut stream,
                        Channel::Agent,
                        request_id,
                        agent_code(&err),
                        &err.agent_message(),
                        err.retryable(),
                    )
                    .await
                }
            }
        };
        let io_result = tokio::select! {
            _ = shutdown.changed() => return,
            result = write_response => result,
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
        agent_msg::EXECUTE_FIXED_HTTP_ACTION => {
            let meta: ipc::ExecuteMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            let request = ExecuteRequest {
                // The frame ID is untrusted transport correlation only. Audit
                // lifecycle identity is minted by the Broker per execution.
                request_id: crate::random_id(RequestId::from_random_bytes)?,
                capability_token: meta.capability_token,
                action: ActionVersionRef {
                    action_id: meta.action_id,
                    version: meta.action_version,
                },
                content_type: meta.content_type,
                extra_headers: meta.extra_headers,
                body: frame.body.to_vec(),
            };
            let outcome = ctx
                .executions
                .submit(request)
                .await?
                .await
                .map_err(|_| BrokerError::Authority(rekey_vault::AuthorityError::Faulted))??;
            let response_meta = ipc::ExecuteResponseMeta {
                upstream_status: outcome.upstream_status,
                headers: outcome.headers,
                body_len: outcome.body.len() as u32,
            };
            let metadata = serde_json::to_vec(&response_meta)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            Ok((metadata, outcome.body))
        }
        agent_msg::AGENT_STATUS => {
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(
                    rekey_domain::ipc::FrameError::InvalidField,
                ));
            }
            let metadata: serde_json::Value = serde_json::from_slice(&frame.metadata)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            if !matches!(metadata, serde_json::Value::Object(ref fields) if fields.is_empty()) {
                return Err(BrokerError::Frame(
                    rekey_domain::ipc::FrameError::InvalidField,
                ));
            }
            // Redacted subset: state only. No vault id, no counts, no config.
            let status = ctx.authority.status().await?;
            let metadata = serde_json::to_vec(&serde_json::json!({ "state": status.state }))
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            Ok((metadata, Vec::new()))
        }
        _ => Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::InvalidField,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_vault::AuthorityError;

    #[test]
    fn storage_integrity_failures_are_credential_unavailable_to_agents() {
        let error = BrokerError::Authority(AuthorityError::StorageIntegrityFailed);
        assert_eq!(agent_code(&error), "CREDENTIAL_UNAVAILABLE");
        assert_eq!(error.agent_message(), "credential unavailable");
    }
}
