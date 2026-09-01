//! Async frame IO over Unix sockets, built on the pure codec in
//! rekey-domain. One in-flight frame per connection; 30s deadline per read
//! and write; every malformed input closes the connection.

use std::time::Duration;

use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{
    Channel, ErrorEnvelope, FRAME_HEADER_LEN, FrameError, FrameHeader, METADATA_MAX_BYTES,
    RESPONSE_BODY_MAX_BYTES,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum FrameIoError {
    #[error("connection closed")]
    Closed,
    #[error("frame io timeout")]
    Timeout,
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("frame io failure")]
    Io(#[source] std::io::Error),
}

pub struct IncomingFrame {
    pub header: FrameHeader,
    pub metadata: Vec<u8>,
    /// Bodies may carry secrets; zeroized on drop.
    pub body: Zeroizing<Vec<u8>>,
}

async fn timed_until<T>(
    deadline: tokio::time::Instant,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T, FrameIoError> {
    match tokio::time::timeout_at(deadline, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(FrameIoError::Closed)
        }
        Ok(Err(err)) => Err(FrameIoError::Io(err)),
        Err(_) => Err(FrameIoError::Timeout),
    }
}

pub async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    expected_channel: Channel,
    max_body: u32,
) -> Result<IncomingFrame, FrameIoError> {
    let deadline = tokio::time::Instant::now() + FRAME_IO_TIMEOUT;
    let mut header_buf = [0u8; FRAME_HEADER_LEN];
    timed_until(deadline, stream.read_exact(&mut header_buf)).await?;
    let header = FrameHeader::decode(&header_buf)?;
    if header.channel != expected_channel {
        return Err(FrameIoError::Frame(FrameError::UnknownChannel));
    }
    if header.metadata_len > METADATA_MAX_BYTES || header.body_len > max_body {
        return Err(FrameIoError::Frame(FrameError::SectionTooLarge));
    }
    let mut metadata = vec![0u8; header.metadata_len as usize];
    timed_until(deadline, stream.read_exact(&mut metadata)).await?;
    let mut body = Zeroizing::new(vec![0u8; header.body_len as usize]);
    timed_until(deadline, stream.read_exact(&mut body)).await?;
    Ok(IncomingFrame {
        header,
        metadata,
        body,
    })
}

pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    channel: Channel,
    message_type: u16,
    request_id: RequestId,
    metadata: &[u8],
    body: &[u8],
) -> Result<(), FrameIoError> {
    let metadata_len = u32::try_from(metadata.len())
        .map_err(|_| FrameIoError::Frame(FrameError::SectionTooLarge))?;
    let body_len =
        u32::try_from(body.len()).map_err(|_| FrameIoError::Frame(FrameError::SectionTooLarge))?;
    if metadata_len > METADATA_MAX_BYTES || body_len > RESPONSE_BODY_MAX_BYTES {
        return Err(FrameIoError::Frame(FrameError::SectionTooLarge));
    }
    let deadline = tokio::time::Instant::now() + FRAME_IO_TIMEOUT;
    let header = FrameHeader {
        channel,
        flags: 0,
        message_type,
        request_id,
        metadata_len,
        body_len,
    };
    let header_bytes = header.encode();
    timed_until(deadline, stream.write_all(&header_bytes)).await?;
    timed_until(deadline, stream.write_all(metadata)).await?;
    if !body.is_empty() {
        timed_until(deadline, stream.write_all(body)).await?;
    }
    timed_until(deadline, stream.flush()).await?;
    Ok(())
}

pub async fn write_ok<S: AsyncWrite + Unpin>(
    stream: &mut S,
    channel: Channel,
    request_id: RequestId,
    metadata: &[u8],
    body: &[u8],
) -> Result<(), FrameIoError> {
    write_frame(
        stream,
        channel,
        rekey_domain::ipc::resp_msg::OK,
        request_id,
        metadata,
        body,
    )
    .await
}

pub async fn write_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    channel: Channel,
    request_id: RequestId,
    code: &str,
    message: &str,
    retryable: bool,
) -> Result<(), FrameIoError> {
    let envelope = ErrorEnvelope {
        request_id,
        code: code.to_owned(),
        message: message.to_owned(),
        retryable,
    };
    let metadata =
        serde_json::to_vec(&envelope).map_err(|_| FrameIoError::Frame(FrameError::InvalidField))?;
    write_frame(
        stream,
        channel,
        rekey_domain::ipc::resp_msg::ERROR,
        request_id,
        &metadata,
        &[],
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn oversized_metadata_is_rejected_before_any_frame_bytes() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let metadata = vec![0u8; METADATA_MAX_BYTES as usize + 1];
        let result = write_ok(
            &mut writer,
            Channel::Admin,
            RequestId::new_random(),
            &metadata,
            &[],
        )
        .await;
        assert!(matches!(
            result,
            Err(FrameIoError::Frame(FrameError::SectionTooLarge))
        ));

        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.read_exact(&mut byte))
                .await
                .is_err()
        );
    }
}
