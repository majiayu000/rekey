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
    InvalidPolicyStatus,
    InvalidApprovalChallenge,
    AuditNonEmptyMetadata,
    AuditUnknownPageField,
    AuditMalformedRecord,
    WorkloadResponseBody,
    WorkloadUnknownResponseField,
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
    let workload_attack = matches!(
        attack,
        Attack::WorkloadResponseBody | Attack::WorkloadUnknownResponseField
    );
    let socket = runtime_dir.join(
        if matches!(attack, Attack::InvalidApprovalChallenge) || workload_attack {
            "agent.sock"
        } else {
            "admin.sock"
        },
    );
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
            Attack::InvalidPolicyStatus => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                br#"{"trust_installed":true,"bundle_persisted":true,"status":"active","signer_id":null,"version":null,"expires_at_ms":null,"policy_sha256":null,"bundle_sha256":null}"#.to_vec(),
                0,
                Vec::new(),
            ),
            Attack::InvalidApprovalChallenge => (
                Channel::Agent,
                request.request_id,
                resp_msg::OK,
                serde_json::json!({
                    "record_type": "rekey.approval.challenge.v1",
                    "approval_request_id": "00000000-0000-4000-8000-000000000001",
                    "tenant_id": "00000000-0000-4000-8000-000000000002",
                    "principal_id": "00000000-0000-4000-8000-000000000003",
                    "session_id": "00000000-0000-4000-8000-000000000004",
                    "action_id": "00000000-0000-4000-8000-000000000005",
                    "action_version": 1,
                    "resource": {"type": "test.resource", "id": "one"},
                    "schema_id": "test/v1",
                    "parameter_sha256": "00".repeat(32),
                    "policy_version": 1,
                    "policy_sha256": "11".repeat(32),
                    "policy_rule_id": "00000000-0000-4000-8000-000000000006",
                    "mode": "one-time",
                    "quorum": 1,
                    "approver_ids": [
                        "00000000-0000-4000-8000-000000000008",
                        "00000000-0000-4000-8000-000000000007"
                    ],
                    "max_uses": 1,
                    "created_at_ms": 1,
                    "max_expires_at_ms": 2,
                })
                .to_string()
                .into_bytes(),
                0,
                Vec::new(),
            ),
            Attack::AuditNonEmptyMetadata => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                br#"{"unexpected":true}"#.to_vec(),
                valid_empty_audit_page().len() as u32,
                valid_empty_audit_page(),
            ),
            Attack::AuditUnknownPageField => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                b"{}".to_vec(),
                br#"{"schema":"rekey.audit.v2","snapshot_max_sequence":1,"events":[],"next_before_sequence":null,"secret_hint":"forged"}"#.len() as u32,
                br#"{"schema":"rekey.audit.v2","snapshot_max_sequence":1,"events":[],"next_before_sequence":null,"secret_hint":"forged"}"#.to_vec(),
            ),
            Attack::AuditMalformedRecord => (
                Channel::Admin,
                request.request_id,
                resp_msg::OK,
                b"{}".to_vec(),
                malformed_audit_page().len() as u32,
                malformed_audit_page(),
            ),
            Attack::WorkloadResponseBody => (
                Channel::Agent,
                request.request_id,
                resp_msg::OK,
                valid_session_response(),
                1,
                vec![b'x'],
            ),
            Attack::WorkloadUnknownResponseField => (
                Channel::Agent,
                request.request_id,
                resp_msg::OK,
                serde_json::json!({
                    "session_id":"00000000-0000-4000-8000-000000000001",
                    "principal_id":"00000000-0000-4000-8000-000000000002",
                    "capability_token":"test-capability",
                    "expires_at_ms":1000,
                    "max_uses":1,
                    "secret_hint":"forged"
                }).to_string().into_bytes(),
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

    let mut args = vec!["--state-dir", state_dir.to_str().expect("utf8 path")];
    if matches!(attack, Attack::InvalidPolicyStatus) {
        args.extend(["policy", "status"]);
    } else if matches!(attack, Attack::InvalidApprovalChallenge) {
        args.extend([
            "--agent-socket",
            socket.to_str().expect("utf8 socket"),
            "approval",
            "prepare",
            "00000000-0000-4000-8000-000000000005@1",
            "--capability",
            "test-token",
        ]);
    } else if workload_attack {
        args.extend([
            "--agent-socket",
            socket.to_str().expect("utf8 socket"),
            "session",
            "create",
            "--action",
            "00000000-0000-4000-8000-000000000005@1",
            "--workload-token-stdin",
        ]);
    } else if matches!(
        attack,
        Attack::AuditNonEmptyMetadata
            | Attack::AuditUnknownPageField
            | Attack::AuditMalformedRecord
    ) {
        args.extend(["audit", "list", "--limit", "1"]);
    } else {
        args.push("status");
    }
    let mut command = Command::new(rekey_bin());
    command
        .args(args)
        .stdin(if workload_attack {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = if workload_attack {
        let mut child = command.spawn().expect("run rekey");
        child.stdin.as_mut().unwrap().write_all(b"a.b.c\n").unwrap();
        child.wait_with_output().expect("wait for rekey")
    } else {
        command.output().expect("run rekey")
    };
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
        Attack::InvalidPolicyStatus,
        Attack::InvalidApprovalChallenge,
        Attack::AuditNonEmptyMetadata,
        Attack::AuditUnknownPageField,
        Attack::AuditMalformedRecord,
        Attack::WorkloadResponseBody,
        Attack::WorkloadUnknownResponseField,
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

fn valid_session_response() -> Vec<u8> {
    serde_json::json!({
        "session_id":"00000000-0000-4000-8000-000000000001",
        "principal_id":"00000000-0000-4000-8000-000000000002",
        "capability_token":"test-capability",
        "expires_at_ms":1000,
        "max_uses":1
    })
    .to_string()
    .into_bytes()
}

#[test]
fn audit_export_continues_after_an_empty_scan_window() {
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

    let pages = [
        serde_json::json!({
            "schema": "rekey.audit.v2",
            "snapshot_max_sequence": 3,
            "events": [],
            "next_before_sequence": 2,
        })
        .to_string()
        .into_bytes(),
        valid_audit_page_with_one_event(),
    ];
    let server = std::thread::spawn(move || {
        for (index, page) in pages.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().expect("accept CLI");
            let mut header_bytes = [0u8; FRAME_HEADER_LEN];
            stream.read_exact(&mut header_bytes).expect("read request");
            let request = FrameHeader::decode(&header_bytes).expect("valid CLI request");
            let mut request_payload = vec![0u8; request.metadata_len as usize];
            stream
                .read_exact(&mut request_payload)
                .expect("read request metadata");
            let query: serde_json::Value =
                serde_json::from_slice(&request_payload).expect("valid audit query");
            if index == 0 {
                assert_eq!(query["snapshot_max_sequence"], serde_json::Value::Null);
                assert_eq!(query["before_sequence"], serde_json::Value::Null);
            } else {
                assert_eq!(query["snapshot_max_sequence"], 3);
                assert_eq!(query["before_sequence"], 2);
            }

            let response = FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: resp_msg::OK,
                request_id: request.request_id,
                metadata_len: 2,
                body_len: page.len() as u32,
            };
            stream.write_all(&response.encode()).expect("write header");
            stream.write_all(b"{}").expect("write metadata");
            stream.write_all(&page).expect("write page");
            stream.flush().expect("flush response");
        }
    });

    let output_path = dir.path().join("audit.jsonl");
    let output = Command::new(rekey_bin())
        .args([
            "--state-dir",
            state_dir.to_str().expect("utf8 state path"),
            "audit",
            "export",
            "--output",
            output_path.to_str().expect("utf8 output path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run rekey audit export");
    server.join().expect("fake broker thread");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).expect("receipt");
    assert_eq!(receipt["row_count"], 1);
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(output_path)
        .expect("export")
        .lines()
        .map(|line| serde_json::from_str(line).expect("jsonl"))
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[1]["sequence"], 1);
}

fn valid_empty_audit_page() -> Vec<u8> {
    br#"{"schema":"rekey.audit.v2","snapshot_max_sequence":1,"events":[],"next_before_sequence":null}"#.to_vec()
}

fn malformed_audit_page() -> Vec<u8> {
    serde_json::json!({
        "schema": "rekey.audit.v2",
        "snapshot_max_sequence": 1,
        "events": [{
            "record_type": "rekey.audit.v2", "sequence": 1, "event_id": "ABC",
            "request_id": null, "session_id": null, "action_id": null,
            "action_version": null, "credential_id": null, "credential_version": null,
            "principal_id": null, "policy_version": null, "policy_digest_hex": null,
            "policy_rule_id": null, "event_type": "test", "outcome": "success",
            "reason_code": "test", "upstream_status": null, "latency_ms": null,
            "created_at_ms": 1
        }],
        "next_before_sequence": 1
    })
    .to_string()
    .into_bytes()
}

fn valid_audit_page_with_one_event() -> Vec<u8> {
    serde_json::json!({
        "schema": "rekey.audit.v2",
        "snapshot_max_sequence": 3,
        "events": [{
            "record_type": "rekey.audit.v2", "sequence": 1,
            "event_id": "0123456789abcdef0123456789abcdef",
            "request_id": null, "session_id": null, "action_id": null,
            "action_version": null, "credential_id": null, "credential_version": null,
            "principal_id": null, "policy_version": null, "policy_digest_hex": null,
            "policy_rule_id": null, "event_type": "test", "outcome": "success",
            "reason_code": "test", "upstream_status": null, "latency_ms": null,
            "created_at_ms": 1
        }],
        "next_before_sequence": null
    })
    .to_string()
    .into_bytes()
}
