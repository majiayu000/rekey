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
    loop {
        if *shutdown.borrow() {
            return;
        }
        let frame = match tokio::select! {
            _ = shutdown.changed() => return,
            frame = read_frame(&mut stream, Channel::Agent, |message_type| {
                if matches!(
                    message_type,
                    agent_msg::EXECUTE_FIXED_HTTP_ACTION | agent_msg::PREPARE_APPROVAL | agent_msg::EXECUTE_TEXT_STREAM
                ) {
                    ipc::AGENT_BODY_MAX_BYTES
                } else if message_type == agent_msg::WORKLOAD_SESSION_CREATE {
                    ipc::WORKLOAD_TOKEN_MAX_BYTES
                } else {
                    0
                }
            }) => frame,
        } {
            Ok(frame) => frame,
            Err(crate::ipc::frame::FrameIoError::InboundSectionTooLarge(request_id)) => {
                ctx.metrics.agent.frame_failed();
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
            Err(crate::ipc::frame::FrameIoError::Closed) => return,
            Err(_) => {
                ctx.metrics.agent.frame_failed();
                return;
            }
        };
        let request_id = frame.header.request_id;
        let metric = ctx.metrics.agent.dispatch.start();
        if frame.header.message_type == agent_msg::EXECUTE_TEXT_STREAM {
            let result = tokio::select! {
                _ = shutdown.changed() => return,
                result = dispatch_stream(&frame, &ctx, &mut stream) => result,
            };
            metric.finish(!matches!(result, Ok(ipc::TextStreamStatus::Completed)));
            if let Err(error) = result {
                // Never append a legacy ERROR after CHUNKs. A closed stream
                // without its terminal is failure for all streaming clients.
                tracing::debug!(event = "agent.stream_closed", code = error.code());
                return;
            }
            continue;
        }
        let response = tokio::select! {
            _ = shutdown.changed() => return,
            response = dispatch(&frame, &ctx) => response,
        };
        metric.finish(response.is_err());
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
            let request = execute_request(frame)?;
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
        agent_msg::PREPARE_APPROVAL => {
            let meta: ipc::PrepareApprovalMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            let request = ExecuteRequest {
                request_id: crate::random_id(RequestId::from_random_bytes)?,
                capability_token: meta.capability_token,
                action: ActionVersionRef {
                    action_id: meta.action_id,
                    version: meta.action_version,
                },
                content_type: meta.content_type,
                extra_headers: meta.extra_headers,
                body: frame.body.to_vec(),
                approval_grants: Vec::new(),
            };
            let envelope = ctx.executor.prepare_approval(request).await?;
            let metadata = serde_json::to_vec(&envelope)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            Ok((metadata, Vec::new()))
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
        agent_msg::WORKLOAD_SESSION_CREATE => {
            let create: ipc::SessionCreateMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            let response = ctx
                .create_workload_session(create, frame.body.to_vec())
                .await?;
            let metadata = serde_json::to_vec(&response)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            Ok((metadata, Vec::new()))
        }
        _ => Err(BrokerError::Frame(
            rekey_domain::ipc::FrameError::InvalidField,
        )),
    }
}

fn execute_request(frame: &IncomingFrame) -> Result<ExecuteRequest, BrokerError> {
    let meta: ipc::ExecuteMeta = serde_json::from_slice(&frame.metadata)
        .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
    Ok(ExecuteRequest {
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
        approval_grants: meta.approval_grants,
    })
}

async fn dispatch_stream(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    stream: &mut UnixStream,
) -> Result<ipc::TextStreamStatus, BrokerError> {
    use crate::executor::text_stream::TextStreamEvent;
    use crate::ipc::frame::write_frame;
    let submission = async { ctx.executions.submit_stream(execute_request(frame)?).await }.await;
    let mut events = match submission {
        Ok(events) => events,
        Err(error) => {
            // No stream has been admitted or written yet. Preserve the Agent
            // protocol's explicit error response for malformed requests.
            write_error(
                stream,
                Channel::Agent,
                frame.header.request_id,
                agent_code(&error),
                &error.agent_message(),
                error.retryable(),
            )
            .await
            .map_err(|_| BrokerError::Upstream("stream-client-disconnected"))?;
            return Ok(ipc::TextStreamStatus::Failed);
        }
    };
    let mut sequence = 0u32;
    let mut admitted = false;
    let mut deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(rekey_domain::action::ACTION_TIMEOUT_HARD_MAX_MS as u64);
    while let Some(event) = tokio::time::timeout_at(deadline, events.recv())
        .await
        .map_err(|_| BrokerError::Upstream("stream-deadline"))?
    {
        if let TextStreamEvent::Admitted {
            deadline: effect_deadline,
        } = event
        {
            if admitted {
                return Err(BrokerError::Upstream("invalid-stream"));
            }
            admitted = true;
            deadline = tokio::time::Instant::from_std(effect_deadline);
            continue;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(BrokerError::Upstream("stream-deadline"));
        }
        let (message, metadata, body, terminal) = match event {
            TextStreamEvent::Admitted { .. } => unreachable!("admission handled above"),
            TextStreamEvent::Chunk(body) => (
                ipc::resp_msg::STREAM_CHUNK,
                serde_json::to_vec(&ipc::TextStreamChunkMeta { sequence }),
                body,
                None,
            ),
            TextStreamEvent::Terminal(status) => (
                ipc::resp_msg::STREAM_TERMINAL,
                serde_json::to_vec(&ipc::TextStreamTerminalMeta { sequence, status }),
                Vec::new(),
                Some(status),
            ),
        };
        let metadata = metadata.map_err(|_| BrokerError::Frame(ipc::FrameError::InvalidField))?;
        tokio::time::timeout_at(
            deadline,
            write_frame(
                stream,
                Channel::Agent,
                message,
                frame.header.request_id,
                &metadata,
                &body,
            ),
        )
        .await
        .map_err(|_| BrokerError::Upstream("stream-deadline"))?
        .map_err(|_| BrokerError::Upstream("stream-client-disconnected"))?;
        if let Some(status) = terminal {
            return Ok(status);
        }
        sequence = sequence
            .checked_add(1)
            .ok_or(BrokerError::Frame(ipc::FrameError::InvalidField))?;
    }
    Err(BrokerError::Upstream("stream-terminal-missing"))
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
