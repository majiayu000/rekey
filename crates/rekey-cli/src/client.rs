//! Blocking Unix-socket IPC client. This binary never opens the database and
//! never derives keys; it only frames requests to the broker.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use rand::TryRngCore;
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
            "INVALID_INPUT" | "INVALID_FRAME" | "POLICY_INVALID" | "USAGE" => 2,
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
            | "CLOCK_UNAVAILABLE"
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
    response_timeout: Duration,
}

fn io_err(err: std::io::Error) -> CliError {
    CliError::local("IPC_UNAVAILABLE", format!("broker unreachable: {err}"))
}

fn read_exact_until(
    stream: &UnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), CliError> {
    while !buffer.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io_err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "broker response deadline exceeded",
                ))
            })?;
        let timeout_nanos = remaining.as_nanos().saturating_add(999_999);
        let timeout_millis = (timeout_nanos / 1_000_000).min(i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_millis) };
        if ready == 0 {
            return Err(io_err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "broker response deadline exceeded",
            )));
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io_err(error));
        }

        let read = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if read == 0 {
            return Err(io_err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "broker closed a partial response",
            )));
        }
        if read < 0 {
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => continue,
                _ => return Err(io_err(error)),
            }
        } else {
            let read = usize::try_from(read).map_err(|_| {
                io_err(std::io::Error::other(
                    "broker returned an invalid response length",
                ))
            })?;
            if read > buffer.len() {
                return Err(io_err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "broker returned an oversized response fragment",
                )));
            }
            buffer = &mut buffer[read..];
        }
    }
    Ok(())
}

fn random_request_id() -> Result<RequestId, CliError> {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CliError::local("ENTROPY_UNAVAILABLE", "cannot create request id"))?;
    Ok(RequestId::from_random_bytes(bytes))
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(if rc != 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::other("unexpected SO_PEERCRED length")
        });
    }
    Ok(cred.uid)
}

fn verify_cross_uid_ancestors(
    mut ancestor: &Path,
    socket_device: u64,
    agent_uid: u32,
) -> Result<(), CliError> {
    loop {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(io_err)?;
        // A device change marks the mount boundary. The Agent cannot rename
        // the mounted runtime directory through a writable directory above
        // that boundary; the deployment supplies the mount itself.
        if metadata.dev() != socket_device {
            return Ok(());
        }
        let mode = metadata.permissions().mode();
        if !metadata.is_dir()
            || mode & 0o022 != 0
            || (metadata.uid() == agent_uid && mode & 0o200 != 0)
        {
            return Err(CliError::local(
                "IPC_UNAVAILABLE",
                "broker socket has a replaceable runtime ancestor",
            ));
        }
        let Some(parent) = ancestor.parent() else {
            return Ok(());
        };
        ancestor = parent;
    }
}

fn verify_socket_contract(socket: &Path, channel: Channel) -> Result<std::fs::Metadata, CliError> {
    let socket_metadata = std::fs::symlink_metadata(socket).map_err(io_err)?;
    let socket_mode = socket_metadata.permissions().mode() & 0o777;
    let caller_uid = unsafe { libc::geteuid() };
    let insecure = !socket_metadata.file_type().is_socket()
        || !socket_access_is_secure(channel, socket_mode, socket_metadata.uid(), caller_uid);
    if insecure {
        return Err(CliError::local(
            "IPC_UNAVAILABLE",
            "broker socket type or permissions are insecure",
        ));
    }
    let parent = socket.parent().ok_or_else(|| {
        CliError::local("IPC_UNAVAILABLE", "broker socket has no parent directory")
    })?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(io_err)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != socket_metadata.uid()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(CliError::local(
            "IPC_UNAVAILABLE",
            "broker runtime directory ownership or permissions are insecure",
        ));
    }
    if socket_metadata.uid() != caller_uid {
        verify_cross_uid_ancestors(parent, socket_metadata.dev(), caller_uid)?;
    }
    Ok(socket_metadata)
}

fn socket_access_is_secure(channel: Channel, mode: u32, socket_uid: u32, caller_uid: u32) -> bool {
    match channel {
        Channel::Admin => socket_uid == caller_uid && mode == 0o600,
        Channel::Agent => mode & 0o007 == 0,
    }
}

fn verify_connected_peer(
    stream: &UnixStream,
    socket: &Path,
    before: &std::fs::Metadata,
    channel: Channel,
) -> Result<(), CliError> {
    let after = verify_socket_contract(socket, channel)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || peer_uid(stream).map_err(io_err)? != after.uid()
    {
        return Err(CliError::local(
            "IPC_UNAVAILABLE",
            "connected peer is not the Broker that owns the protected socket",
        ));
    }
    Ok(())
}

impl Client {
    pub fn connect(socket: &Path, channel: Channel) -> Result<Self, CliError> {
        Self::connect_with_response_timeout(socket, channel, IO_TIMEOUT)
    }

    pub fn connect_with_response_timeout(
        socket: &Path,
        channel: Channel,
        response_timeout: Duration,
    ) -> Result<Self, CliError> {
        let socket_metadata = verify_socket_contract(socket, channel)?;
        let stream = UnixStream::connect(socket).map_err(io_err)?;
        verify_connected_peer(&stream, socket, &socket_metadata, channel)?;
        stream
            .set_read_timeout(Some(response_timeout))
            .map_err(io_err)?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io_err)?;
        Ok(Self {
            stream,
            channel,
            response_timeout,
        })
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
        let request_id = random_request_id()?;
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

        let response_deadline = Instant::now()
            .checked_add(self.response_timeout)
            .ok_or_else(|| CliError::local("IPC_UNAVAILABLE", "invalid response timeout"))?;
        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        read_exact_until(&self.stream, &mut header_buf, response_deadline)?;
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
        read_exact_until(&self.stream, &mut response_meta, response_deadline)?;
        let mut response_body = Zeroizing::new(vec![0u8; response.body_len as usize]);
        read_exact_until(&self.stream, &mut response_body, response_deadline)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn protected_listener() -> (tempfile::TempDir, std::path::PathBuf, UnixListener) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        (dir, socket, listener)
    }

    #[test]
    fn connect_accepts_owner_peer_in_protected_runtime() {
        let (_dir, socket, listener) = protected_listener();
        let accept = std::thread::spawn(move || listener.accept().unwrap());
        let client = Client::connect(&socket, Channel::Agent).unwrap();
        drop(client);
        drop(accept.join().unwrap());
    }

    #[test]
    fn admin_contract_requires_caller_owned_mode_0600() {
        let (_dir, socket, _listener) = protected_listener();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let err = Client::connect(&socket, Channel::Admin).err().unwrap();
        assert_eq!(err.code, "IPC_UNAVAILABLE");
        assert!(err.message.contains("socket type or permissions"));

        let caller_uid = unsafe { libc::geteuid() };
        let foreign_uid = if caller_uid == 0 { 1 } else { 0 };
        assert!(!socket_access_is_secure(
            Channel::Admin,
            0o600,
            foreign_uid,
            caller_uid,
        ));
        assert!(socket_access_is_secure(
            Channel::Agent,
            0o660,
            foreign_uid,
            caller_uid,
        ));
    }

    #[test]
    fn connect_rejects_group_writable_runtime() {
        let (_dir, socket, _listener) = protected_listener();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        let err = Client::connect(&socket, Channel::Agent).err().unwrap();
        assert_eq!(err.code, "IPC_UNAVAILABLE");
        assert!(err.message.contains("runtime directory"));
    }

    #[test]
    fn connect_rejects_symlinked_socket() {
        let (dir, socket, _listener) = protected_listener();
        let alias = dir.path().join("runtime/alias.sock");
        std::os::unix::fs::symlink(&socket, &alias).unwrap();
        let err = Client::connect(&alias, Channel::Agent).err().unwrap();
        assert_eq!(err.code, "IPC_UNAVAILABLE");
        assert!(err.message.contains("socket type"));
    }

    #[test]
    fn cross_uid_contract_rejects_agent_owned_writable_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(dir.path()).unwrap();
        let err = verify_cross_uid_ancestors(dir.path(), metadata.dev(), metadata.uid())
            .err()
            .unwrap();
        assert_eq!(err.code, "IPC_UNAVAILABLE");
        assert!(err.message.contains("replaceable runtime ancestor"));
    }

    #[test]
    fn cross_uid_contract_rejects_group_writable_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let metadata = std::fs::metadata(dir.path()).unwrap();
        let foreign_uid = metadata.uid().wrapping_add(1);
        let err = verify_cross_uid_ancestors(dir.path(), metadata.dev(), foreign_uid)
            .err()
            .unwrap();
        assert_eq!(err.code, "IPC_UNAVAILABLE");
        assert!(err.message.contains("replaceable runtime ancestor"));
    }

    #[test]
    fn response_sections_share_one_absolute_deadline() {
        let (_dir, socket, listener) = protected_listener();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_header = [0u8; FRAME_HEADER_LEN];
            stream.read_exact(&mut request_header).unwrap();
            let request = FrameHeader::decode(&request_header).unwrap();
            let mut payload = vec![0u8; (request.metadata_len + request.body_len) as usize];
            stream.read_exact(&mut payload).unwrap();

            let response = FrameHeader {
                channel: Channel::Agent,
                flags: 0,
                message_type: rekey_domain::ipc::resp_msg::OK,
                request_id: request.request_id,
                metadata_len: 2,
                body_len: 0,
            };
            stream.write_all(&response.encode()).unwrap();
            std::thread::sleep(Duration::from_millis(20));
            let _ = stream.write_all(b"{");
            std::thread::sleep(Duration::from_millis(20));
            let _ = stream.write_all(b"}");
        });

        let mut client = Client::connect_with_response_timeout(
            &socket,
            Channel::Agent,
            Duration::from_millis(30),
        )
        .unwrap();
        let started = Instant::now();
        let error = client.call(1, b"{}", &[]).unwrap_err();
        assert_eq!(error.code, "IPC_UNAVAILABLE");
        assert!(started.elapsed() < Duration::from_millis(100));
        server.join().unwrap();
    }
}
