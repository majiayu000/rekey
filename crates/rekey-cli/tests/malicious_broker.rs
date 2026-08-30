//! Process-level attack test: a real `rekey` binary must fail closed when a
//! same-user process impersonates the Broker and sends a forged RKIP response.

use std::io::{Read, Write};
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
}

fn rekey_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rekey"))
}

fn run_attack(attack: Attack) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let runtime_dir = state_dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    let listener = UnixListener::bind(runtime_dir.join("admin.sock")).expect("bind fake broker");

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
        };

        let response = FrameHeader {
            channel,
            flags: 0,
            message_type,
            request_id,
            metadata_len: metadata.len() as u32,
            body_len,
        };
        stream
            .write_all(&response.encode())
            .expect("write forged header");
        stream.write_all(&metadata).expect("write forged metadata");
        if !body.is_empty() {
            stream.write_all(&body).expect("write forged body");
        }
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
