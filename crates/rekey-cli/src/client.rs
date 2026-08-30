//! Blocking Unix-socket IPC client. This binary never opens the database and
//! never derives keys; it only frames requests to the broker.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{
    ADMIN_SECRET_BODY_MAX_BYTES, AGENT_BODY_MAX_BYTES, Channel, ErrorEnvelope, FRAME_HEADER_LEN,
    FrameHeader, METADATA_MAX_BYTES, RESPONSE_BODY_MAX_BYTES,
};
use zeroize::Zeroizing;

pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct CliError {
    pub code: String,
    pub message: String,
}

impl CliError {
    pub fn local(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }

    /// Exit codes per the CLI contract.
    pub fn exit_code(&self) -> i32 {
        match self.code.as_str() {
            "INVALID_INPUT" | "INVALID_FRAME" | "USAGE" => 2,
            "INVALID_UNLOCK_CREDENTIAL"
            | "UNLOCK_RATE_LIMITED"
            | "AUTHENTICATION_FAILED"
            | "LOCKED" => 3,
            "ACTION_DENIED"
            | "ACTION_DISABLED"
            | "ACTION_NOT_FOUND"
            | "INVALID_CAPABILITY"
            | "CAPABILITY_EXPIRED"
            | "CAPABILITY_EXHAUSTED"
            | "REQUEST_DENIED"
            | "REQUEST_TOO_LARGE"
            | "CREDENTIAL_UNAVAILABLE"
            | "CREDENTIAL_CONFLICT" => 4,
            "STORAGE_UNAVAILABLE"
            | "STORAGE_INTEGRITY_FAILED"
            | "CRYPTO_FAILURE"
            | "NOT_INITIALIZED"
            | "ALREADY_INITIALIZED"
            | "STATE_DIRECTORY_NOT_EMPTY"
            | "UNSUPPORTED_VAULT_LAYOUT"
            | "UNSUPPORTED_FORMAT_VERSION"
            | "INSECURE_STATE_PERMISSIONS"
            | "AUDIT_COMMIT_FAILED"
            | "BACKUP_FAILED"
            | "RESTORE_FAILED"
            | "ENTROPY_UNAVAILABLE"
            | "FAULTED" => 5,
            "UPSTREAM_FAILED" | "RESPONSE_TOO_LARGE" => 6,
            "RESPONSE_SECURITY_VIOLATION" | "AUDIT_COMMIT_FAILED_AFTER_EXECUTION" => 8,
            _ => 7,
        }
    }
}

pub struct Client {
    stream: UnixStream,
    channel: Channel,
}

fn io_err(err: std::io::Error) -> CliError {
    CliError::local("IPC_UNAVAILABLE", format!("broker unreachable: {err}"))
}

impl Client {
    pub fn connect(socket: &Path, channel: Channel) -> Result<Self, CliError> {
        let stream = UnixStream::connect(socket).map_err(io_err)?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(io_err)?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io_err)?;
        Ok(Self { stream, channel })
    }

    /// Sends one frame and reads one response. `body` may carry secrets and
    /// is zeroized by the caller's ownership.
    pub fn call(
        &mut self,
        message_type: u16,
        metadata: &[u8],
        body: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CliError> {
        let metadata_len = u32::try_from(metadata.len())
            .map_err(|_| CliError::local("INVALID_FRAME", "request metadata is too large"))?;
        if metadata_len > METADATA_MAX_BYTES {
            return Err(CliError::local(
                "INVALID_FRAME",
                "request metadata is too large",
            ));
        }
        let body_len = u32::try_from(body.len())
            .map_err(|_| CliError::local("INVALID_FRAME", "request body is too large"))?;
        let request_body_max = match self.channel {
            Channel::Admin => ADMIN_SECRET_BODY_MAX_BYTES,
            Channel::Agent => AGENT_BODY_MAX_BYTES,
        };
        if body_len > request_body_max {
            return Err(CliError::local(
                "INVALID_FRAME",
                "request body is too large",
            ));
        }
        let request_id = RequestId::new_random();
        let header = FrameHeader {
            channel: self.channel,
            flags: 0,
            message_type,
            request_id,
            metadata_len,
            body_len,
        };
        self.stream.write_all(&header.encode()).map_err(io_err)?;
        self.stream.write_all(metadata).map_err(io_err)?;
        if !body.is_empty() {
            self.stream.write_all(body).map_err(io_err)?;
        }
        self.stream.flush().map_err(io_err)?;

        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        self.stream.read_exact(&mut header_buf).map_err(io_err)?;
        let response = FrameHeader::decode(&header_buf)
            .map_err(|err| CliError::local("INVALID_FRAME", err.to_string()))?;
        if response.channel != self.channel || response.request_id != request_id {
            return Err(CliError::local(
                "INVALID_FRAME",
                "response does not match request",
            ));
        }
        if response.body_len > RESPONSE_BODY_MAX_BYTES {
            return Err(CliError::local(
                "INVALID_FRAME",
                "response body is too large",
            ));
        }
        let mut response_meta = vec![0u8; response.metadata_len as usize];
        self.stream.read_exact(&mut response_meta).map_err(io_err)?;
        let mut response_body = Zeroizing::new(vec![0u8; response.body_len as usize]);
        self.stream.read_exact(&mut response_body).map_err(io_err)?;

        match response.message_type {
            rekey_domain::ipc::resp_msg::OK => Ok((response_meta, response_body.to_vec())),
            rekey_domain::ipc::resp_msg::ERROR => {
                if !response_body.is_empty() {
                    return Err(CliError::local(
                        "INVALID_FRAME",
                        "error response body must be empty",
                    ));
                }
                let envelope: ErrorEnvelope = serde_json::from_slice(&response_meta)
                    .map_err(|_| CliError::local("INVALID_FRAME", "malformed error envelope"))?;
                if envelope.request_id != request_id {
                    return Err(CliError::local(
                        "INVALID_FRAME",
                        "error response does not match request",
                    ));
                }
                Err(CliError {
                    code: envelope.code,
                    message: envelope.message,
                })
            }
            _ => Err(CliError::local("INVALID_FRAME", "unexpected response type")),
        }
    }
}
