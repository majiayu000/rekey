//! Synthetic same-UID IPC only: no vault, credentials, platform prompt or signing.
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use rekey_domain::ipc::{
    self, Channel, FRAME_HEADER_LEN, FrameHeader, admin_msg, agent_msg, resp_msg,
};
use serde_json::{Value, json};

const ID: &str = "00112233-4455-4677-8899-aabbccddeeff";
const OTHER_ID: &str = "00112233-4455-4677-8899-aabbccddee00";
const ACTION: &str = "00112233-4455-4677-8899-aabbccddeeff@1";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PRESENCE: &[u8] = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
const CAPABILITY: &[u8] = b"synthetic-capability\n";

enum Reply {
    Ok(Value, Vec<u8>),
    Error(Value),
    OversizedBody,
    OversizedMetadata,
    Disconnect,
}

fn exchange(
    channel: Channel,
    args: &[&str],
    stdin: &[u8],
    reply: impl FnOnce(FrameHeader, Value, Vec<u8>) -> Reply + Send + 'static,
) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join(if channel == Channel::Admin {
        "admin.sock"
    } else {
        "agent.sock"
    });
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let body_file = dir.path().join("body.json");
    std::fs::write(&body_file, b"{\"input\":1}").unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI did not connect");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        // macOS may inherit O_NONBLOCK from the listener on accept.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut raw = [0; FRAME_HEADER_LEN];
        stream.read_exact(&mut raw).unwrap();
        let request = FrameHeader::decode(&raw).unwrap();
        assert_eq!(request.channel, channel);
        let mut metadata = vec![0; request.metadata_len as usize];
        let mut body = vec![0; request.body_len as usize];
        stream.read_exact(&mut metadata).unwrap();
        stream.read_exact(&mut body).unwrap();
        let response = reply(request, serde_json::from_slice(&metadata).unwrap(), body);
        if !matches!(response, Reply::Disconnect) {
            let (kind, metadata, body, advertised_metadata, advertised_body) = match response {
                Reply::Ok(metadata, body) => (
                    resp_msg::OK,
                    serde_json::to_vec(&metadata).unwrap(),
                    body,
                    None,
                    None,
                ),
                Reply::Error(metadata) => (
                    resp_msg::ERROR,
                    serde_json::to_vec(&metadata).unwrap(),
                    Vec::new(),
                    None,
                    None,
                ),
                Reply::OversizedBody => (
                    resp_msg::OK,
                    Vec::new(),
                    Vec::new(),
                    None,
                    Some(ipc::RESPONSE_BODY_MAX_BYTES + 1),
                ),
                Reply::OversizedMetadata => (
                    resp_msg::OK,
                    Vec::new(),
                    Vec::new(),
                    Some(ipc::METADATA_MAX_BYTES + 1),
                    None,
                ),
                Reply::Disconnect => unreachable!(),
            };
            let header = FrameHeader {
                channel,
                flags: 0,
                message_type: kind,
                request_id: request.request_id,
                metadata_len: advertised_metadata.unwrap_or(metadata.len() as u32),
                body_len: advertised_body.unwrap_or(body.len() as u32),
            };
            stream.write_all(&header.encode()).unwrap();
            let _ = stream.write_all(&metadata);
            let _ = stream.write_all(&body);
        }
        drop(stream);
        // A lost decision reply must not make the client open a second request.
        let deadline = Instant::now() + Duration::from_millis(80);
        while Instant::now() < deadline {
            assert!(
                matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_rekey"));
    command.arg("--state-dir").arg(dir.path());
    for arg in args {
        if *arg == "BODY" {
            command.arg(&body_file);
        } else {
            command.arg(arg);
        }
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    output
}

fn review() -> Value {
    json!({
        "record_type":"rekey.approval.review.v1",
        "challenge":{
            "record_type":"rekey.approval.challenge.v2", "approval_request_id":ID,
            "tenant_id":ID, "principal_id":ID, "session_id":ID, "action_id":ID,
            "action_version":1, "resource":{"type":"fixture","id":"owner/repo"},
            "schema_id":"fixture.v1", "parameter_sha256":DIGEST,
            "policy_version":1, "policy_sha256":DIGEST, "policy_rule_id":ID,
            "mode":"one-time", "approver":{"kind":"local-presence"}, "max_uses":1,
            "created_at_ms":1, "max_expires_at_ms":600001
        },
        "action_name":"Create issue", "origin":"https://api.github.com", "method":"POST",
        "canonical_request":{"target":{"path":"/repos/owner/repo/issues","params":{},"query":{}},"body":null,"content_type":"application/json","headers":[]}
    })
}

fn review_metadata(state: &str, len: usize) -> Value {
    json!({"record_type":"rekey.approval.local-review.v1", "approval_request_id":ID,
        "review_sha256":DIGEST, "state":state, "body_len":len})
}

fn state(state: &str) -> Value {
    json!({"approval_request_id":ID, "state":state, "expires_at_ms":600001})
}

fn assert_invalid(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("INVALID_FRAME"));
}

#[test]
fn review_preserves_complete_utf8_bytes_and_terminal_null() {
    let body = serde_json::to_string(&review())
        .unwrap()
        .replace(
            "\"body\":null",
            r#""body":{"n":9007199254740993,"escaped":"\u4e2d","float":1.0}"#,
        )
        .into_bytes();
    let expected = body.clone();
    let output = exchange(
        Channel::Admin,
        &["approval", "review", ID],
        &[],
        move |request, meta, input| {
            assert_eq!(request.message_type, admin_msg::APPROVAL_LOCAL_REVIEW);
            assert_eq!(meta, json!({"approval_request_id":ID}));
            assert!(input.is_empty());
            Reply::Ok(review_metadata("pending", body.len()), body)
        },
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["review_json"].as_str().unwrap().as_bytes(), expected);
    for terminal in ["consumed", "cancelled", "expired"] {
        let output = exchange(
            Channel::Admin,
            &["approval", "review", ID],
            &[],
            move |_, _, _| Reply::Ok(review_metadata(terminal, 0), Vec::new()),
        );
        assert!(output.status.success());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value["review_json"].is_null());
        assert_eq!(value["metadata"]["state"], terminal);
    }
}

#[test]
fn review_rejects_mismatched_typed_context_and_empty_live_body() {
    for case in [
        "metadata-id",
        "metadata-record",
        "metadata-hash",
        "metadata-length",
        "metadata-extra",
        "review-id",
        "review-record",
        "review-extra",
        "challenge-record",
        "challenge-version",
        "external",
        "unknown-kind",
        "invalid-time",
        "utf8",
        "empty-pending",
        "empty-approved",
    ] {
        let output = exchange(
            Channel::Admin,
            &["approval", "review", ID],
            &[],
            move |_, _, _| {
                let mut review = review();
                match case {
                    "review-id" => review["challenge"]["approval_request_id"] = json!(OTHER_ID),
                    "review-record" => review["record_type"] = json!("wrong"),
                    "review-extra" => review["unexpected"] = json!(true),
                    "challenge-record" => {
                        review["challenge"]["record_type"] = json!("rekey.approval.challenge.v1")
                    }
                    "challenge-version" => review["challenge"]["action_version"] = json!(0),
                    "external" => {
                        review["challenge"]["approver"] =
                            json!({"kind":"ed25519","keys":[DIGEST],"threshold":1})
                    }
                    "unknown-kind" => review["challenge"]["approver"] = json!({"kind":"unknown"}),
                    "invalid-time" => review["challenge"]["max_expires_at_ms"] = json!(1),
                    _ => {}
                }
                let body = match case {
                    "utf8" => vec![0xff],
                    "empty-pending" | "empty-approved" => Vec::new(),
                    _ => serde_json::to_vec(&review).unwrap(),
                };
                let mut meta = review_metadata(
                    if case == "empty-approved" {
                        "approved"
                    } else {
                        "pending"
                    },
                    body.len(),
                );
                match case {
                    "metadata-id" => meta["approval_request_id"] = json!(OTHER_ID),
                    "metadata-record" => meta["record_type"] = json!("wrong"),
                    "metadata-hash" => meta["review_sha256"] = json!("A".repeat(64)),
                    "metadata-length" => meta["body_len"] = json!(body.len() + 1),
                    "metadata-extra" => meta["unexpected"] = json!(true),
                    _ => {}
                }
                Reply::Ok(meta, body)
            },
        );
        assert_invalid(output);
    }
}

#[test]
fn review_accepts_full_body_limit_without_truncation_and_rejects_oversized_frames() {
    let mut body = serde_json::to_string(&review())
        .unwrap()
        .replace("\"body\":null", r#""body":"""#);
    let padding = "x".repeat(ipc::RESPONSE_BODY_MAX_BYTES as usize - body.len());
    body = body.replace(r#""body":"""#, &format!(r#""body":"{padding}""#));
    assert_eq!(body.len(), ipc::RESPONSE_BODY_MAX_BYTES as usize);
    let output = exchange(
        Channel::Admin,
        &["approval", "review", ID],
        &[],
        move |_, _, _| Reply::Ok(review_metadata("approved", body.len()), body.into_bytes()),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["review_json"].as_str().unwrap().len(),
        ipc::RESPONSE_BODY_MAX_BYTES as usize
    );
    assert_invalid(exchange(
        Channel::Admin,
        &["approval", "review", ID],
        &[],
        |_, _, _| Reply::OversizedBody,
    ));
    assert_invalid(exchange(
        Channel::Admin,
        &["approval", "review", ID],
        &[],
        |_, _, _| Reply::OversizedMetadata,
    ));
}

#[test]
fn explicit_presence_decisions_bind_hash_and_only_send_proof_in_body() {
    for (command, opcode, result) in [
        ("approve", admin_msg::APPROVAL_LOCAL_APPROVE, "approved"),
        ("reject", admin_msg::APPROVAL_LOCAL_REJECT, "cancelled"),
    ] {
        let output = exchange(
            Channel::Admin,
            &[
                "approval",
                command,
                ID,
                "--review-sha256",
                DIGEST,
                "--presence",
                "--password-stdin",
            ],
            PRESENCE,
            move |request, meta, body| {
                assert_eq!(request.message_type, opcode);
                assert_eq!(
                    meta,
                    json!({"approval_request_id":ID,"expected_review_sha256":DIGEST})
                );
                assert_eq!(
                    ipc::parse_local_approval_proof_body(&body).unwrap(),
                    &PRESENCE[..PRESENCE.len() - 1]
                );
                Reply::Ok(state(result), Vec::new())
            },
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            state(result)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("bbbbbbbb"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("bbbbbbbb"));
    }
}

#[test]
fn await_and_cancel_use_owner_token_and_return_only_typed_bound_state() {
    for (command, opcode, result) in [
        ("await", agent_msg::AWAIT_APPROVAL, "pending"),
        ("cancel", agent_msg::CANCEL_APPROVAL, "cancelled"),
    ] {
        let output = exchange(
            Channel::Agent,
            &["approval", command, ID, "--capability", "-"],
            CAPABILITY,
            move |request, meta, body| {
                assert_eq!(request.message_type, opcode);
                assert!(body.is_empty());
                assert_eq!(
                    meta,
                    json!({"approval_request_id":ID,"capability_token":"synthetic-capability"})
                );
                Reply::Ok(state(result), Vec::new())
            },
        );
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            state(result)
        );
    }
    for case in ["id", "expiry", "state", "extra", "body"] {
        assert_invalid(exchange(
            Channel::Agent,
            &["approval", "await", ID, "--capability", "fixture"],
            &[],
            move |_, _, _| {
                let mut meta = state("approved");
                match case {
                    "id" => meta["approval_request_id"] = json!(OTHER_ID),
                    "expiry" => meta["expires_at_ms"] = json!(0),
                    "state" => meta["state"] = json!("invalid"),
                    "extra" => meta["unexpected"] = json!(true),
                    _ => {}
                }
                Reply::Ok(
                    meta,
                    if case == "body" {
                        b"unexpected".to_vec()
                    } else {
                        Vec::new()
                    },
                )
            },
        ));
    }
}

fn execute_args(stream: bool) -> Vec<&'static str> {
    if stream {
        vec![
            "execute-text-stream",
            ACTION,
            "--capability",
            "-",
            "--body-file",
            "BODY",
        ]
    } else {
        vec!["execute", ACTION, "--capability", "-"]
    }
}

#[test]
fn execute_and_stream_preserve_structured_approval_required_and_challenge() {
    for stream in [false, true] {
        let mut args = execute_args(stream);
        args.extend(["--challenge", ID]);
        let output = exchange(
            Channel::Agent,
            &args,
            CAPABILITY,
            move |request, meta, _| {
                assert_eq!(
                    request.message_type,
                    if stream {
                        agent_msg::EXECUTE_TEXT_STREAM
                    } else {
                        agent_msg::EXECUTE_FIXED_HTTP_ACTION
                    }
                );
                assert_eq!(meta["local_approval_request_id"], ID);
                assert_eq!(meta["approval_grants"], json!([]));
                Reply::Error(
                    json!({"request_id":request.request_id,"code":"APPROVAL_REQUIRED","message":"local approval required","retryable":false,"approval":{"challenge_id":ID,"expires_at_ms":600001}}),
                )
            },
        );
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["code"], "APPROVAL_REQUIRED");
        assert_eq!(error["retryable"], false);
        assert_eq!(
            error["approval"],
            json!({"challenge_id":ID,"expires_at_ms":600001})
        );
        assert!(error["request_id"].as_str().is_some());
    }
}

#[test]
fn malformed_approval_required_is_rejected_for_buffered_and_stream() {
    for stream in [false, true] {
        for case in ["missing", "retryable", "message", "id", "other-code"] {
            assert_invalid(exchange(
                Channel::Agent,
                &execute_args(stream),
                CAPABILITY,
                move |request, _, _| {
                    let mut error = json!({"request_id":request.request_id,"code":"APPROVAL_REQUIRED","message":"local approval required","retryable":false,"approval":{"challenge_id":ID,"expires_at_ms":600001}});
                    match case {
                        "missing" => {
                            error.as_object_mut().unwrap().remove("approval");
                        }
                        "retryable" => error["retryable"] = json!(true),
                        "message" => error["message"] = json!("wrong"),
                        "id" => error["request_id"] = json!(OTHER_ID),
                        "other-code" => error["code"] = json!("LOCKED"),
                        _ => unreachable!(),
                    }
                    Reply::Error(error)
                },
            ));
        }
    }
}

#[test]
fn unknown_decision_result_and_busy_never_resend_or_report_success() {
    for disconnect in [false, true] {
        let output = exchange(
            Channel::Admin,
            &[
                "approval",
                "approve",
                ID,
                "--review-sha256",
                DIGEST,
                "--presence",
                "--password-stdin",
            ],
            PRESENCE,
            move |request, _, _| {
                if disconnect {
                    Reply::Disconnect
                } else {
                    Reply::Error(
                        json!({"request_id":request.request_id,"code":"AUTHORITY_BUSY","message":"local approval decision unavailable","retryable":false}),
                    )
                }
            },
        );
        assert_eq!(output.status.code(), Some(7));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("bbbbbbbb"));
        assert!(error.contains(if disconnect {
            "IPC_UNAVAILABLE"
        } else {
            "AUTHORITY_BUSY"
        }));
    }
}

#[test]
fn invalid_decision_and_conflicting_execution_flags_fail_before_stdin_or_connect() {
    for command in ["approve", "reject"] {
        for proof_args in [
            vec![],
            vec!["--presence"],
            vec!["--password-stdin"],
            vec!["--presence", "--password-stdin", "--recovery"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
                .args(["approval", command, ID, "--review-sha256", DIGEST])
                .args(proof_args)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
        }
        let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
            .args([
                "--state-dir",
                "/nonexistent/rekey-local-fixture",
                "approval",
                command,
                ID,
                "--review-sha256",
                "BAD",
                "--presence",
                "--password-stdin",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("review digest"));
    }
    for stream in [false, true] {
        let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
            .args(execute_args(stream))
            .args(["--challenge", ID, "--approval", "/nonexistent/grant"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
    }
}
