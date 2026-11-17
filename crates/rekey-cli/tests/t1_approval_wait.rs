//! T1 adapters wait for local approval like `rekey call`, then retry exactly
//! once with the same approval ID. A synthetic same-UID IPC peer stands in for
//! the daemon; the issued values are synthetic STS / ExecCredential / token
//! output, never real credentials.
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Output};
use std::time::Duration;

use rekey_domain::ids::ApprovalRequestId;
use rekey_domain::ipc::{Channel, FRAME_HEADER_LEN, FrameHeader, agent_msg, resp_msg};
use serde_json::{Value, json};

const ADAPTERS: [(&str, &str, &[u8]); 3] = [
    (
        "aws-credentials",
        "aws-assume-role",
        br#"{"Version":1,"AccessKeyId":"ASIASYNTHETICTEMP1234","SecretAccessKey":"SYNTHETIC-TEMP-SECRET","SessionToken":"SYNTHETIC-TEMP-SESSION","Expiration":"2026-11-17T12:00:00Z"}"#,
    ),
    (
        "kubectl-credentials",
        "kubernetes-eks",
        br#"{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"k8s-aws-v1.SYNTHETIC-TEMP-TOKEN","expirationTimestamp":"2026-11-17T12:00:00Z"}}"#,
    ),
    (
        "github-token",
        "github-app",
        b"SYNTHETIC-TEMP-INSTALLATION-TOKEN",
    ),
];

/// A missing CLI connection fails the test instead of blocking the peer forever.
fn accept(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // macOS may inherit O_NONBLOCK from the listener on accept.
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the CLI did not open the expected connection"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn receive(stream: &mut UnixStream) -> (FrameHeader, Value) {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut raw = [0; FRAME_HEADER_LEN];
    stream.read_exact(&mut raw).unwrap();
    let header = FrameHeader::decode(&raw).unwrap();
    assert_eq!(header.channel, Channel::Agent);
    let mut metadata = vec![0; header.metadata_len as usize];
    let mut body = vec![0; header.body_len as usize];
    stream.read_exact(&mut metadata).unwrap();
    stream.read_exact(&mut body).unwrap();
    assert!(body.is_empty(), "T1 requests carry no body");
    (header, serde_json::from_slice(&metadata).unwrap())
}

fn reply(stream: &mut UnixStream, header: FrameHeader, metadata: Value, body: &[u8], error: bool) {
    let metadata = metadata.to_string();
    stream
        .write_all(
            &FrameHeader {
                channel: Channel::Agent,
                flags: 0,
                message_type: if error { resp_msg::ERROR } else { resp_msg::OK },
                request_id: header.request_id,
                metadata_len: metadata.len() as u32,
                body_len: body.len() as u32,
            }
            .encode(),
        )
        .unwrap();
    stream.write_all(metadata.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn approval_required(stream: &mut UnixStream, header: FrameHeader, id: ApprovalRequestId) {
    reply(
        stream,
        header,
        json!({"request_id":header.request_id,"code":"APPROVAL_REQUIRED","message":"local approval required","retryable":false,"next":"Call await_approval","approval":{"challenge_id":id,"expires_at_ms":1234567}}),
        &[],
        true,
    );
}

/// Expects the original derivation request without an approval ID.
fn expect_derive(listener: &UnixListener) -> (UnixStream, FrameHeader) {
    let mut stream = accept(listener);
    let (header, metadata) = receive(&mut stream);
    assert_eq!(header.message_type, agent_msg::DERIVE_CREDENTIAL);
    assert_eq!(metadata, json!({"connection":"deployment"}));
    (stream, header)
}

/// Expects one bounded wait for exactly the challenged approval ID.
fn expect_await(listener: &UnixListener, id: ApprovalRequestId, state: &str) {
    let mut stream = accept(listener);
    let (header, metadata) = receive(&mut stream);
    assert_eq!(header.message_type, agent_msg::AWAIT_APPROVAL);
    assert_eq!(metadata, json!({"request_id":id,"timeout_s":120}));
    let decision = json!({"approval_request_id":id,"state":state,"expires_at_ms":1234567});
    reply(
        &mut stream,
        header,
        json!({}),
        decision.to_string().as_bytes(),
        false,
    );
}

/// Runs the real CLI against a synthetic peer; afterwards no further
/// connection may be pending, so a hidden second retry is detected.
fn run(
    args: &[&str],
    output_mode: &str,
    peer: impl FnOnce(&UnixListener) + Send + 'static,
) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let worker = std::thread::spawn(move || {
        peer(&listener);
        listener
    });
    let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
        .arg("--state-dir")
        .arg(dir.path())
        .args(args)
        .env("REKEY_OUTPUT", output_mode)
        .output()
        .unwrap();
    let listener = worker.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "{args:?}: the CLI opened an unexpected extra connection"
    );
    // Issued values reach stdout only, never progress or error output.
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC-TEMP-"));
    output
}

#[test]
fn t1_adapters_wait_for_local_approval_and_retry_once_with_the_same_id() {
    for (command, kind, issued) in ADAPTERS {
        for mode in ["json", "human"] {
            let id = ApprovalRequestId::new_random();
            let output = run(&[command, "deployment"], mode, move |listener| {
                let (mut stream, header) = expect_derive(listener);
                approval_required(&mut stream, header, id);
                expect_await(listener, id, "approved");
                let mut stream = accept(listener);
                let (header, metadata) = receive(&mut stream);
                assert_eq!(header.message_type, agent_msg::DERIVE_CREDENTIAL);
                assert_eq!(
                    metadata,
                    json!({"connection":"deployment","approval_request_id":id})
                );
                reply(
                    &mut stream,
                    header,
                    json!({"connection":"deployment","kind":kind,"expires_at_ms":1234567}),
                    issued,
                    false,
                );
            });
            assert!(
                output.status.success(),
                "{command} {mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            // stdout is exactly the consumer's credential document or token.
            assert_eq!(output.stdout, issued, "{command} {mode}");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains("T1"), "{command} {mode}: {stderr}");
            assert_eq!(
                stderr.contains(&id.to_string()),
                mode == "human",
                "{command} {mode}: progress is for people at a terminal: {stderr}"
            );
        }
    }
}

#[test]
fn t1_unapproved_decisions_return_the_original_challenge_without_reissuing() {
    for (command, _, _) in ADAPTERS {
        // A local rejection is reported as cancelled; pending means the wait timed out.
        for state in ["cancelled", "expired", "pending", "consumed"] {
            let id = ApprovalRequestId::new_random();
            let output = run(&[command, "deployment"], "json", move |listener| {
                let (mut stream, header) = expect_derive(listener);
                approval_required(&mut stream, header, id);
                expect_await(listener, id, state);
            });
            assert_eq!(output.status.code(), Some(4), "{command} {state}");
            assert!(output.stdout.is_empty());
            // A pipe keeps the one-line structured error contract.
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_eq!(stderr.trim_end().lines().count(), 1, "{stderr}");
            let error: Value = serde_json::from_str(&stderr).unwrap();
            assert_eq!(error["code"], "APPROVAL_REQUIRED");
            assert_eq!(error["approval"]["challenge_id"], id.to_string());
        }
    }
}

#[test]
fn t1_retry_happens_once_and_no_wait_keeps_the_immediate_refusal() {
    for (command, _, _) in ADAPTERS {
        let (first, second) = (
            ApprovalRequestId::new_random(),
            ApprovalRequestId::new_random(),
        );
        let output = run(&[command, "deployment"], "json", move |listener| {
            let (mut stream, header) = expect_derive(listener);
            approval_required(&mut stream, header, first);
            expect_await(listener, first, "approved");
            // The single retry is challenged again; it must not wait or retry again.
            let mut stream = accept(listener);
            let (header, metadata) = receive(&mut stream);
            assert_eq!(metadata["approval_request_id"], first.to_string());
            approval_required(&mut stream, header, second);
        });
        assert_eq!(output.status.code(), Some(4), "{command}");
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["approval"]["challenge_id"], second.to_string());

        let id = ApprovalRequestId::new_random();
        let output = run(
            &[command, "deployment", "--no-wait"],
            "json",
            move |listener| {
                let (mut stream, header) = expect_derive(listener);
                approval_required(&mut stream, header, id);
            },
        );
        assert_eq!(output.status.code(), Some(4), "{command} --no-wait");
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["approval"]["challenge_id"], id.to_string());
    }
}
