use std::sync::Arc;
use std::time::Duration;

use rekey_domain::ipc::{self, Channel, FRAME_HEADER_LEN, FrameHeader};
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use super::BrokerCtx;
use crate::error::BrokerError;

const CAPACITY_REPLY_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_CAPACITY_REPLY_TASKS: usize = 128;

pub(super) async fn accept_loop(
    listener: UnixListener,
    ctx: Arc<BrokerCtx>,
    slots: Arc<tokio::sync::Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    admin: bool,
) -> Result<(), BrokerError> {
    let mut conns = JoinSet::new();
    let mut capacity_replies = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept(), if capacity_replies.len() < MAX_CAPACITY_REPLY_TASKS => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::error!(
                            event = "runtime.listener_fault",
                            channel = if admin { "admin" } else { "agent" },
                            code = "IPC_UNAVAILABLE"
                        );
                        ctx.request_fault();
                        return Err(BrokerError::Io(err));
                    }
                };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    capacity_replies.spawn(reject_over_capacity(
                        stream,
                        if admin { Channel::Admin } else { Channel::Agent },
                    ));
                    continue;
                };
                let ctx = Arc::clone(&ctx);
                let conn_shutdown = shutdown.clone();
                conns.spawn(async move {
                    if admin {
                        crate::ipc::admin::handle_admin_conn(stream, ctx, conn_shutdown).await;
                    } else {
                        crate::ipc::agent::handle_agent_conn(stream, ctx, conn_shutdown).await;
                    }
                    drop(permit);
                });
            }
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            Some(_) = capacity_replies.join_next(), if !capacity_replies.is_empty() => {}
        }
    }
    while conns.join_next().await.is_some() {}
    capacity_replies.abort_all();
    while capacity_replies.join_next().await.is_some() {}
    Ok(())
}

async fn reject_over_capacity(mut stream: UnixStream, channel: Channel) {
    let deadline = tokio::time::Instant::now() + CAPACITY_REPLY_TIMEOUT;
    let body_limit = if channel == Channel::Agent {
        ipc::AGENT_BODY_MAX_BYTES
    } else {
        ipc::ADMIN_SECRET_BODY_MAX_BYTES
    };
    let header = match read_rejected_header(&mut stream, channel, body_limit, deadline).await {
        Ok(header) => header,
        Err(error) => {
            tracing::debug!(event = "runtime.capacity_reply_read_failed", %error);
            return;
        }
    };
    match tokio::time::timeout_at(
        deadline,
        crate::ipc::frame::write_error(
            &mut stream,
            channel,
            header.request_id,
            "AUTHORITY_BUSY",
            "connection capacity exhausted",
            true,
        ),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::debug!(event = "runtime.capacity_reply_write_failed", %error);
        }
        Err(_) => {
            tracing::debug!(event = "runtime.capacity_reply_write_timeout");
        }
    }
    let drain_deadline = tokio::time::Instant::now() + crate::ipc::frame::FRAME_IO_TIMEOUT;
    let mut buffer = Zeroizing::new([0u8; 8 * 1024]);
    if let Err(error) = drain_exact_until(
        &mut stream,
        header.metadata_len,
        &mut buffer[..],
        drain_deadline,
    )
    .await
    {
        tracing::debug!(event = "runtime.capacity_reply_metadata_drain_failed", %error);
        return;
    }
    if let Err(error) = drain_exact_until(
        &mut stream,
        header.body_len,
        &mut buffer[..],
        drain_deadline,
    )
    .await
    {
        tracing::debug!(event = "runtime.capacity_reply_body_drain_failed", %error);
    }
}

async fn read_rejected_header(
    stream: &mut UnixStream,
    channel: Channel,
    body_limit: u32,
    deadline: tokio::time::Instant,
) -> std::io::Result<FrameHeader> {
    let mut header_bytes = [0u8; FRAME_HEADER_LEN];
    read_exact_until(stream, &mut header_bytes, deadline).await?;
    let header = FrameHeader::decode(&header_bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if header.channel != channel
        || header.metadata_len > ipc::METADATA_MAX_BYTES
        || header.body_len > body_limit
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rejected frame exceeds its channel contract",
        ));
    }

    Ok(header)
}

async fn drain_exact_until(
    stream: &mut UnixStream,
    mut remaining: u32,
    buffer: &mut [u8],
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    while remaining > 0 {
        let chunk = usize::min(remaining as usize, buffer.len());
        read_exact_until(stream, &mut buffer[..chunk], deadline).await?;
        remaining -= chunk as u32;
    }
    Ok(())
}

async fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    match tokio::time::timeout_at(deadline, stream.read_exact(buffer)).await {
        Ok(result) => result.map(|_| ()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "capacity reply read timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use rekey_domain::ids::RequestId;
    use rekey_domain::ipc::{self, ErrorEnvelope, FRAME_HEADER_LEN, FrameHeader};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn over_capacity_connection_gets_a_bounded_protocol_error() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let request_id = RequestId::new_random();
        let request = FrameHeader {
            channel: Channel::Agent,
            flags: 0,
            message_type: ipc::agent_msg::AGENT_STATUS,
            request_id,
            metadata_len: 2,
            body_len: 0,
        };
        let rejection = tokio::spawn(reject_over_capacity(server, Channel::Agent));
        client.write_all(&request.encode()).await.unwrap();
        client.write_all(b"{}").await.unwrap();

        let mut response_bytes = [0u8; FRAME_HEADER_LEN];
        client.read_exact(&mut response_bytes).await.unwrap();
        let response = FrameHeader::decode(&response_bytes).unwrap();
        assert_eq!(response.channel, Channel::Agent);
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.message_type, ipc::resp_msg::ERROR);
        let mut metadata = vec![0u8; response.metadata_len as usize];
        client.read_exact(&mut metadata).await.unwrap();
        let error: ErrorEnvelope = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(error.code, "AUTHORITY_BUSY");
        assert!(error.retryable);
        rejection.await.unwrap();
    }

    #[tokio::test]
    async fn over_capacity_connection_drains_a_large_legal_request() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let request_id = RequestId::new_random();
        let body = vec![b'x'; ipc::AGENT_BODY_MAX_BYTES as usize];
        let request = FrameHeader {
            channel: Channel::Agent,
            flags: 0,
            message_type: ipc::agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            request_id,
            metadata_len: 2,
            body_len: body.len() as u32,
        };
        let rejection = tokio::spawn(reject_over_capacity(server, Channel::Agent));
        let client_task = tokio::spawn(async move {
            client.write_all(&request.encode()).await.unwrap();
            client.write_all(b"{}").await.unwrap();
            tokio::time::sleep(CAPACITY_REPLY_TIMEOUT + Duration::from_millis(50)).await;
            client.write_all(&body).await.unwrap();

            let mut response_bytes = [0u8; FRAME_HEADER_LEN];
            client.read_exact(&mut response_bytes).await.unwrap();
            let response = FrameHeader::decode(&response_bytes).unwrap();
            assert_eq!(response.request_id, request_id);
            let mut metadata = vec![0u8; response.metadata_len as usize];
            client.read_exact(&mut metadata).await.unwrap();
            let error: ErrorEnvelope = serde_json::from_slice(&metadata).unwrap();
            assert_eq!(error.code, "AUTHORITY_BUSY");
            assert!(error.retryable);
        });

        tokio::time::timeout(Duration::from_secs(2), client_task)
            .await
            .expect("large legal request did not receive a bounded capacity reply")
            .unwrap();
        rejection.await.unwrap();
    }
}
