//! Process-level framing test: a same-UID listener sends forged RKIP responses.
//! Broker peer-identity authentication is covered by the Linux G2 harness;
//! this test covers response binding and strict parsing only.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{
    Channel, FRAME_HEADER_LEN, FrameHeader, RESPONSE_BODY_MAX_BYTES, resp_msg,
};

#[derive(Clone, Copy, Debug)]
enum Attack {
    WrongChannel,
    WrongRequestId,
    OversizedBody,
    MismatchedErrorEnvelope,
    UnknownErrorField,
    ErrorWithBody,
    InvalidOkMetadata,
    MissingOkFields,
    UnknownOkField,
}

fn rekey_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rekey"))
}

fn run_attack(attack: Attack) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let runtime_dir = state_dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))
        .expect("protect runtime dir");
    let socket = runtime_dir.join("admin.sock");
    let listener = UnixListener::bind(&socket).expect("bind fake broker");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("protect fake broker socket");

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept CLI");
        let mut header_bytes = [0u8; FRAME_HEADER_LEN];
        stream.read_exact(&mut header_bytes).expect("read request");
        let request = FrameHeader::decode(&header_bytes).expect("valid CLI request");
        let mut request_payload = vec![0u8; (request.metadata_len + request.body_len) as usize];
        stream
            .read_exact(&mut request_payload)
            .expect("read request payload");

        let forged_id = RequestId::new_random();
        let (channel, request_id, message_type, metadata, body_len, body) = match attack {
            Attack::WrongChannel => (
                Channel::Agent,
                request.request_id,
                resp_msg::OK,
                br#"{"state":"locked"}"#.to_vec(),
                0,
                Vec::new(),
            ),
            Attack::WrongRequestId => (
                Channel::Admin,
                forged_id,
                resp_msg::OK,
                br#"{"state":"locked"}"#.to_vec(),
                0,
                Vec::new(),
            ),
            Attack::OversizedBody => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                b"{}".to_vec(),
                RESPONSE_BODY_MAX_BYTES + 1,
                Vec::new(),
            ),
            Attack::MismatchedErrorEnvelope => (
                Channel::Admin,
                request.request_id,
                resp_msg::ERROR,
                serde_json::json!({
                    "request_id": forged_id,
                    "code": "LOCKED",
                    "message": "locked",
                    "retryable": false
                })
                .to_string()
                .into_bytes(),
                0,
                Vec::new(),
            ),
            Attack::UnknownErrorField => (
                Channel::Admin,
                request.request_id,
                resp_msg::ERROR,
                serde_json::json!({
                    "request_id": request.request_id,
                    "code": "LOCKED",
                    "message": "locked",
                    "retryable": false,
                    "secret_hint": "must-not-be-accepted"
                })
                .to_string()
                .into_bytes(),
                0,
                Vec::new(),
            ),
            Attack::ErrorWithBody => (
                Channel::Admin,
                request.request_id,
                resp_msg::ERROR,
                serde_json::json!({
                    "request_id": request.request_id,
                    "code": "LOCKED",
                    "message": "locked",
                    "retryable": false
                })
                .to_string()
                .into_bytes(),
                1,
                vec![b'x'],
            ),
            Attack::InvalidOkMetadata => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                b"not-json".to_vec(),
                0,
                Vec::new(),
            ),
            Attack::MissingOkFields => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                b"{}".to_vec(),
                0,
                Vec::new(),
            ),
            Attack::UnknownOkField => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                br#"{"state":"locked","format_version":5,"runtime_version":"2.0.0-dev","sessions_active":0,"secret_hint":"forged"}"#.to_vec(),
                0,
                Vec::new(),
            ),
        };

        let response = FrameHeader {
            channel,
            flags: 0,
            message_type,
            request_id,
            metadata_len: metadata.len() as u32,
            body_len,
        };
        let mut forged_frame = Vec::with_capacity(FRAME_HEADER_LEN + metadata.len() + body.len());
        forged_frame.extend_from_slice(&response.encode());
        forged_frame.extend_from_slice(&metadata);
        forged_frame.extend_from_slice(&body);
        stream
            .write_all(&forged_frame)
            .expect("write forged response");
        stream.flush().expect("flush forged response");
    });

    let output = Command::new(rekey_bin())
        .args([
            "--state-dir",
            state_dir.to_str().expect("utf8 path"),
            "status",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run rekey");
    server.join().expect("fake broker thread");
    output
}

#[test]
fn cli_rejects_forged_broker_responses() {
    for attack in [
        Attack::WrongChannel,
        Attack::WrongRequestId,
        Attack::OversizedBody,
        Attack::MismatchedErrorEnvelope,
        Attack::UnknownErrorField,
        Attack::ErrorWithBody,
        Attack::InvalidOkMetadata,
        Attack::MissingOkFields,
        Attack::UnknownOkField,
    ] {
        let output = run_attack(attack);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{attack:?} must fail as INVALID_FRAME; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
