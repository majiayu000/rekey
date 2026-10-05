//! Agent channel: fixed action execution and a redacted status subset. No
//! admin messages, no secret reads, no target/auth inputs.

use std::sync::Arc;

use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{self, Channel, agent_msg};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::error::BrokerError;
use crate::executor::ExecuteRequest;
use crate::ipc::frame::{
    IncomingFrame, read_frame, write_approval_required, write_error, write_error_with_next,
    write_ok,
};
use crate::runtime::BrokerCtx;

/// Agents must not distinguish credential-layer failures.
pub(crate) fn local_agent_code(err: &BrokerError) -> &'static str {
    match err.code() {
        "RESPONSE_SECURITY_VIOLATION" => "RESPONSE_BLOCKED",
        "UPSTREAM_FAILED" => "UPSTREAM_ERROR",
        "REQUEST_DENIED" => "DENIED",
        "POLICY_INVALID"
            if matches!(err, BrokerError::Policy(rekey_policy::PolicyError::Expired)) =>
        {
            "DENIED"
        }
        "POLICY_INVALID"
            if matches!(
                err,
                BrokerError::Policy(rekey_policy::PolicyError::NotConfigured)
            ) =>
        {
            "NOT_CONFIGURED"
        }
        "POLICY_INVALID"
            if matches!(
                err,
                BrokerError::Policy(rekey_policy::PolicyError::InvalidParameters)
            ) =>
        {
            "INVALID_INPUT"
        }
        "CRYPTO_FAILURE" | "STORAGE_INTEGRITY_FAILED" | "CREDENTIAL_CONFLICT" => {
            "CREDENTIAL_UNAVAILABLE"
        }
        code => code,
    }
}

fn agent_code(err: &BrokerError) -> &'static str {
    if cfg!(feature = "lab") {
        match err.code() {
            "CRYPTO_FAILURE" | "STORAGE_INTEGRITY_FAILED" | "CREDENTIAL_CONFLICT" => {
                "CREDENTIAL_UNAVAILABLE"
            }
            code => code,
        }
    } else {
        local_agent_code(err)
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
                    agent_msg::CALL | agent_msg::EXECUTE_FIXED_HTTP_ACTION | agent_msg::PREPARE_APPROVAL | agent_msg::EXECUTE_TEXT_STREAM
                ) {
                    ipc::AGENT_BODY_MAX_BYTES
                } else if message_type == agent_msg::SCAN {
                    10 * 1024 * 1024
                } else if cfg!(feature = "lab") && message_type == agent_msg::WORKLOAD_SESSION_CREATE {
                    ipc::WORKLOAD_TOKEN_MAX_BYTES
                } else {
                    0
                }
            }) => frame,
        } {
            Ok(frame) => frame,
            Err(crate::ipc::frame::FrameIoError::InboundSectionTooLarge(request_id)) => {
                #[cfg(feature = "lab")]
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
                #[cfg(feature = "lab")]
                ctx.metrics.agent.frame_failed();
                return;
            }
        };
        let request_id = frame.header.request_id;
        #[cfg(feature = "lab")]
        let metric = ctx.metrics.agent.dispatch.start();
        if cfg!(feature = "lab") && frame.header.message_type == agent_msg::EXECUTE_TEXT_STREAM {
            let result = tokio::select! {
                _ = shutdown.changed() => return,
                result = dispatch_stream(&frame, &ctx, &mut stream) => result,
            };
            #[cfg(feature = "lab")]
            metric.finish(!matches!(result, Ok(ipc::TextStreamStatus::Completed)));
            if let Err(error) = result {
                // Never append a legacy ERROR after CHUNKs. A closed stream
                // without its terminal is failure for all streaming clients.
                tracing::debug!(event = "agent.stream_closed", code = error.code());
                return;
            }
            continue;
        }
        let caller = super::caller::unix_caller(&stream);
        let response = if frame.header.message_type == agent_msg::AWAIT_APPROVAL {
            let mut extra = [0u8; 1];
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = stream.read(&mut extra) => return,
                response = dispatch_local(&frame, &ctx, &caller) => response,
            }
        } else {
            tokio::select! {
                _ = shutdown.changed() => return,
                response = dispatch_local(&frame, &ctx, &caller) => response,
            }
        };
        #[cfg(feature = "lab")]
        metric.finish(response.is_err());
        let write_response = async {
            match response {
                Ok((metadata, body)) => {
                    write_ok(&mut stream, Channel::Agent, request_id, &metadata, &body).await
                }
                Err(BrokerError::ApprovalRequired(approval)) => {
                    write_approval_required(&mut stream, Channel::Agent, request_id, approval).await
                }
                Err(err) => {
                    write_error_with_next(
                        &mut stream,
                        Channel::Agent,
                        request_id,
                        local_agent_code(&err),
                        &err.agent_message(),
                        err.retryable(),
                        &err.agent_next(),
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
        agent_msg::PROFILE_INVENTORY => {
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            let request: ipc::ProfileInventoryMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            let body = ctx
                .profile_inventory_until(
                    &request.capability_token,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(25),
                )
                .await?;
            Ok((b"{}".to_vec(), body))
        }
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
                params: meta.params,
                query: meta.query,
                body: frame.body.to_vec(),
                approval_grants: Vec::new(),
                local_approval_request_id: None,
            };
            let envelope = ctx.executor.prepare_approval(request).await?;
            let metadata = serde_json::to_vec(&envelope)
                .map_err(|_| BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField))?;
            Ok((metadata, Vec::new()))
        }
        agent_msg::AWAIT_APPROVAL | agent_msg::CANCEL_APPROVAL => {
            if !frame.body.is_empty() {
                return Err(BrokerError::Frame(ipc::FrameError::InvalidField));
            }
            let request: ipc::LocalApprovalRequestMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| BrokerError::Frame(ipc::FrameError::InvalidField))?;
            if frame.header.message_type == agent_msg::CANCEL_APPROVAL {
                let _owner = ctx
                    .lifecycle
                    .coordinate_until(
                        tokio::time::Instant::now() + std::time::Duration::from_secs(25),
                    )
                    .await?;
                ctx.lifecycle.reject_if_not_running()?;
                let local = ctx.sessions.local_state_for_owner(
                    &request.capability_token,
                    request.approval_request_id,
                    crate::now_ts()?,
                )?;
                let response = ctx.sessions.decide_local(
                    request.approval_request_id,
                    &local.review_sha256,
                    None,
                    crate::now_ts()?,
                )?;
                return Ok((
                    serde_json::to_vec(&response)
                        .map_err(|_| BrokerError::Frame(ipc::FrameError::InvalidField))?,
                    Vec::new(),
                ));
            }
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
            loop {
                let notified = ctx.sessions.approval_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                ctx.lifecycle.reject_if_not_running()?;
                let now = crate::now_ts()?;
                let local = ctx.sessions.local_state_for_owner(
                    &request.capability_token,
                    request.approval_request_id,
                    now,
                )?;
                if local.state != ipc::LocalApprovalState::Pending
                    || tokio::time::Instant::now() >= deadline
                {
                    return Ok((
                        serde_json::to_vec(&local.response())
                            .map_err(|_| BrokerError::Frame(ipc::FrameError::InvalidField))?,
                        Vec::new(),
                    ));
                }
                let wall_remaining = local
                    .challenge
                    .max_expires_at_ms
                    .saturating_sub(now.as_unix_ms())
                    .max(0) as u64;
                let wake = deadline.min(local.deadline.into()).min(
                    tokio::time::Instant::now() + std::time::Duration::from_millis(wall_remaining),
                );
                let _ = tokio::time::timeout_at(wake, notified).await;
            }
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
        #[cfg(feature = "lab")]
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
        params: meta.params,
        query: meta.query,
        body: frame.body.to_vec(),
        approval_grants: meta.approval_grants,
        local_approval_request_id: meta.local_approval_request_id,
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
        if let TextStreamEvent::AdmissionError(error) = event {
            if admitted || sequence != 0 {
                return Err(BrokerError::Upstream("invalid-stream"));
            }
            match error {
                BrokerError::ApprovalRequired(approval) => {
                    write_approval_required(
                        stream,
                        Channel::Agent,
                        frame.header.request_id,
                        approval,
                    )
                    .await
                }
                error => {
                    write_error(
                        stream,
                        Channel::Agent,
                        frame.header.request_id,
                        agent_code(&error),
                        &error.agent_message(),
                        error.retryable(),
                    )
                    .await
                }
            }
            .map_err(|_| BrokerError::Upstream("stream-client-disconnected"))?;
            return Ok(ipc::TextStreamStatus::Failed);
        }
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
            TextStreamEvent::Buffered(_) => return Err(BrokerError::Upstream("invalid-stream")),
            TextStreamEvent::Admitted { .. } | TextStreamEvent::AdmissionError(_) => {
                unreachable!("admission handled above")
            }
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

async fn dispatch_local(
    frame: &IncomingFrame,
    ctx: &BrokerCtx,
    caller: &str,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    match frame.header.message_type {
        agent_msg::LIST_CAPABILITIES => {
            require_empty(frame)?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&ctx.list_capabilities(caller).await?)
                    .map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::DESCRIBE => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let meta: ipc::DescribeMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&ctx.describe_operation(&meta.operation).await?)
                    .map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::CALL => {
            let meta: ipc::CallMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            if meta.dry_run {
                let dry = ctx.dry_run_call(&meta, &frame.body, caller).await?;
                return Ok((
                    b"{}".to_vec(),
                    serde_json::to_vec(&dry).map_err(|_| ipc::FrameError::InvalidField)?,
                ));
            }
            let receiver = ctx
                .executions
                .submit_local(crate::executor::LocalExecuteRequest {
                    request_id: frame.header.request_id,
                    meta,
                    body: frame.body.clone(),
                    caller: caller.to_owned(),
                })
                .await?;
            let result = receiver
                .await
                .map_err(|_| rekey_vault::AuthorityError::Faulted)??;
            let result = match result {
                crate::execution_supervisor::HttpExecution::Buffered(outcome) => outcome,
                crate::execution_supervisor::HttpExecution::Stream(mut stream) => {
                    let mut body = Vec::new();
                    while let Some(event) = stream.recv().await {
                        match event {
                            crate::executor::text_stream::TextStreamEvent::Chunk(bytes) => {
                                if body.len() + bytes.len() > ipc::RESPONSE_BODY_MAX_BYTES as usize
                                {
                                    return Err(rekey_domain::DomainError::ResponseTooLarge.into());
                                }
                                body.extend_from_slice(&bytes);
                            }
                            crate::executor::text_stream::TextStreamEvent::Buffered(outcome) => {
                                return call_response(outcome);
                            }
                            crate::executor::text_stream::TextStreamEvent::AdmissionError(
                                error,
                            ) => return Err(error),
                            crate::executor::text_stream::TextStreamEvent::Terminal(
                                ipc::TextStreamStatus::Completed,
                            ) => {
                                return call_response(crate::executor::ExecuteOutcome {
                                    stream_status: None,
                                    upstream_status: 200,
                                    headers: vec![(
                                        "content-type".into(),
                                        "text/event-stream".into(),
                                    )],
                                    body,
                                });
                            }
                            crate::executor::text_stream::TextStreamEvent::Terminal(_) => {
                                return Err(BrokerError::Upstream("stream-incomplete"));
                            }
                            _ => {}
                        }
                    }
                    return Err(BrokerError::Upstream("stream-incomplete"));
                }
            };
            call_response(result)
        }
        agent_msg::REQUEST_ACCESS => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let meta: ipc::RequestAccessMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            let request = ctx.local_calls.create_access(caller, meta)?;
            let mut audit =
                super::super::runtime::call_audit("access_request.created", "pending", caller)?;
            audit.request_context = None;
            audit.request_id = Some(request.request_id);
            ctx.authority.append_audit(audit).await?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&request).map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::AWAIT_ACCESS => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let meta: ipc::AwaitAccessMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            let response = ctx
                .local_calls
                .await_access(meta.request_id, caller, meta.timeout_s)
                .await?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&response).map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::DERIVE_CREDENTIAL => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            ctx.derive_credential(
                serde_json::from_slice(&frame.metadata)
                    .map_err(|_| ipc::FrameError::InvalidField)?,
                caller,
            )
            .await
        }
        agent_msg::SCAN => {
            let meta: ipc::ScanMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            ctx.lifecycle.reject_if_not_running()?;
            ctx.local_calls
                .admit_rate("scan:local-uid", 60, std::time::Duration::from_secs(60))?;
            let active = ctx
                .policy
                .read()
                .await
                .clone()
                .filter(|p| p.signer_id().is_some())
                .ok_or(rekey_policy::PolicyError::NotConfigured)?;
            if active.is_expired(crate::now_ts()?) {
                return Err(rekey_policy::PolicyError::Expired.into());
            }
            let credentials = active
                .snapshot()
                .connections()
                .iter()
                .filter(|c| c.enabled)
                .map(|c| rekey_vault::hygiene::ScanCredential {
                    connection: c.name.clone(),
                    credential_id: c.credential_id,
                })
                .chain(active.snapshot().ssh_keys().iter().map(|c| {
                    rekey_vault::hygiene::ScanCredential {
                        connection: c.name.clone(),
                        credential_id: c.credential_id,
                    }
                }))
                .chain(active.snapshot().derived_credentials().iter().map(|c| {
                    rekey_vault::hygiene::ScanCredential {
                        connection: c.name.clone(),
                        credential_id: c.credential_id,
                    }
                }))
                .collect();
            let findings = ctx
                .authority
                .scan_credentials(
                    vec![rekey_vault::hygiene::ScanInput::new(
                        meta.path,
                        frame.body.to_vec(),
                    )],
                    credentials,
                )
                .await?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&ipc::ScanResponse { findings })
                    .map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::AWAIT_UNLOCK => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let meta: ipc::AwaitUnlockMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&ctx.await_unlock(meta.timeout_s).await?)
                    .map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::AWAIT_APPROVAL => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let meta: ipc::LocalAwaitApprovalMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(
                    &ctx.local_calls
                        .await_state(meta.request_id, caller, meta.timeout_s)
                        .await?,
                )
                .map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::CANCEL_APPROVAL => {
            if !frame.body.is_empty() {
                return Err(ipc::FrameError::InvalidField.into());
            }
            let meta: ipc::LocalCancelApprovalMeta = serde_json::from_slice(&frame.metadata)
                .map_err(|_| ipc::FrameError::InvalidField)?;
            Ok((
                b"{}".to_vec(),
                serde_json::to_vec(&ctx.local_calls.cancel(meta.request_id, caller)?)
                    .map_err(|_| ipc::FrameError::InvalidField)?,
            ))
        }
        agent_msg::AGENT_STATUS => dispatch(frame, ctx).await,
        _ if cfg!(feature = "lab") => dispatch(frame, ctx).await,
        _ => Err(ipc::FrameError::InvalidField.into()),
    }
}
fn require_empty(frame: &IncomingFrame) -> Result<(), BrokerError> {
    let metadata: serde_json::Value =
        serde_json::from_slice(&frame.metadata).map_err(|_| ipc::FrameError::InvalidField)?;
    if !frame.body.is_empty() || metadata != serde_json::json!({}) {
        return Err(ipc::FrameError::InvalidField.into());
    }
    Ok(())
}
fn call_response(
    outcome: crate::executor::ExecuteOutcome,
) -> Result<(Vec<u8>, Vec<u8>), BrokerError> {
    let encoding = if std::str::from_utf8(&outcome.body).is_ok() {
        "text"
    } else {
        "base64"
    };
    let metadata = ipc::CallResponseMetadata {
        status: outcome.upstream_status,
        headers: outcome.headers,
        body_encoding: encoding.into(),
    };
    Ok((
        serde_json::to_vec(&metadata).map_err(|_| ipc::FrameError::InvalidField)?,
        outcome.body,
    ))
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
