//! Token-free CLI contracts against a synthetic, private same-UID IPC peer.
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Output};
use std::time::Duration;

use rekey_domain::ipc::{Channel, FRAME_HEADER_LEN, FrameHeader, agent_msg, resp_msg};
use serde_json::{Value, json};

fn receive(stream: &mut UnixStream) -> (FrameHeader, Value, Vec<u8>) {
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
    let metadata: Value = serde_json::from_slice(&metadata).unwrap();
    assert!(metadata.get("capability_token").is_none());
    (header, metadata, body)
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
fn exchange(args: &[&str], handler: impl FnOnce(UnixListener) + Send + 'static) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let worker = std::thread::spawn(move || handler(listener));
    let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
        .arg("--state-dir")
        .arg(dir.path())
        .args(args)
        .env("REKEY_CAPABILITY", "synthetic-token-must-not-be-read")
        .output()
        .unwrap();
    worker.join().unwrap();
    output
}
fn output_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)))
}
#[test]
fn list_and_named_call_are_token_free_and_parameter_flags_reach_the_daemon() {
    let output = exchange(&["list", "--json"], |listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let (header, meta, body) = receive(&mut stream);
        assert_eq!(header.message_type, agent_msg::LIST_CAPABILITIES);
        assert_eq!(meta, json!({}));
        assert!(body.is_empty());
        reply(
            &mut stream,
            header,
            json!({}),
            br#"{"connections":[],"derived_credentials":[],"service_url":"http://127.0.0.1:7787"}"#,
            false,
        );
    });
    assert!(output.status.success());
    assert_eq!(output_json(&output)["connections"], json!([]));
    let output = exchange(
        &[
            "call",
            "github.create_issue",
            "--owner",
            "example",
            "--repo",
            "project",
            "--title",
            "Bug report",
            "--no-wait",
        ],
        |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            let (header, meta, body) = receive(&mut stream);
            assert_eq!(header.message_type, agent_msg::CALL);
            assert_eq!(meta["operation"], "github.create_issue");
            assert_eq!(
                meta["args"],
                json!({"owner":"example","repo":"project","title":"Bug report"})
            );
            assert!(body.is_empty());
            reply(
                &mut stream,
                header,
                json!({"status":201,"headers":[],"body_encoding":"text"}),
                b"created",
                false,
            );
        },
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output_json(&output)["status"], 201);
}
#[test]
fn t1_discovery_is_public_and_text_states_that_the_agent_receives_temporary_values() {
    for args in [vec!["list", "--json"], vec!["list"]] {
        let output = exchange(&args, |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            let (header, metadata, body) = receive(&mut stream);
            assert_eq!(header.message_type, agent_msg::LIST_CAPABILITIES);
            assert_eq!(metadata, json!({}));
            assert!(body.is_empty());
            let inventory = json!({"connections":[],"derived_credentials":[{
                "connection":"deployment","kind":"aws-assume-role","grade":"T1","effect":"approve","max_ttl_seconds":900,
                "target":{"kind":"aws-assume-role","role_arn":"arn:aws:iam::123456789012:role/synthetic","region":"us-east-1","session_policy":{}}
            }],"service_url":null});
            reply(
                &mut stream,
                header,
                json!({}),
                inventory.to_string().as_bytes(),
                false,
            );
        });
        assert!(output.status.success());
        if args.len() == 2 {
            let grant = &output_json(&output)["derived_credentials"][0];
            assert_eq!(grant["connection"], "deployment");
            assert_eq!(grant["target"]["region"], "us-east-1");
            assert!(grant.get("credential_id").is_none());
        } else {
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("deployment  T1 aws-assume-role"));
            assert!(text.contains("Agent receives temporary credentials"));
        }
    }
}
#[test]
fn http_sends_json_as_frame_body_and_dry_run_outputs_the_public_preview() {
    let output = exchange(
        &[
            "http",
            "github",
            "POST",
            "/repos/example/project/issues",
            "--json",
            "{\"title\":\"Bug\"}",
            "--dry-run",
        ],
        |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            let (header, meta, body) = receive(&mut stream);
            assert_eq!(meta["dry_run"], true);
            assert!(meta.get("body").is_none());
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"title":"Bug"})
            );
            reply(
                &mut stream,
                header,
                json!({}),
                br#"{"effect":"approve","credential_placeholder":"rekey:github"}"#,
                false,
            );
        },
    );
    assert!(output.status.success());
    assert_eq!(output_json(&output)["effect"], "approve");
}
#[test]
fn default_call_waits_and_replays_once_only_after_matching_approval() {
    let approval = rekey_domain::ids::ApprovalRequestId::new_random();
    let output = exchange(
        &["call", "github.create_issue", "--title", "Bug"],
        move |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            let (header, original, body) = receive(&mut stream);
            assert!(body.is_empty());
            reply(
                &mut stream,
                header,
                json!({"request_id":header.request_id,"code":"APPROVAL_REQUIRED","message":"local approval required","retryable":false,"next":"Call await_approval","approval":{"challenge_id":approval,"expires_at_ms":1234}}),
                &[],
                true,
            );
            let (mut stream, _) = listener.accept().unwrap();
            let (header, wait, _) = receive(&mut stream);
            assert_eq!(header.message_type, agent_msg::AWAIT_APPROVAL);
            assert_eq!(wait["request_id"], approval.to_string());
            reply(
                &mut stream,
                header,
                json!({}),
                json!({"approval_request_id":approval,"state":"approved","expires_at_ms":1234})
                    .to_string()
                    .as_bytes(),
                false,
            );
            let (mut stream, _) = listener.accept().unwrap();
            let (header, replay, _) = receive(&mut stream);
            assert_eq!(replay["args"], original["args"]);
            assert_eq!(replay["approval_request_id"], approval.to_string());
            reply(
                &mut stream,
                header,
                json!({"status":201,"headers":[],"body_encoding":"text"}),
                b"created",
                false,
            );
        },
    );
    assert!(output.status.success());
    assert_eq!(output_json(&output)["body"], "created");
}
#[test]
fn public_requests_and_errors_preserve_agent_next_step() {
    let output = exchange(
        &[
            "request",
            "stripe",
            "--op",
            "list_customers",
            "--reason",
            "Need billing data",
        ],
        |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            let (header, meta, body) = receive(&mut stream);
            assert!(body.is_empty());
            assert_eq!(header.message_type, agent_msg::REQUEST_ACCESS);
            assert_eq!(meta["reason"], "Need billing data");
            reply(
                &mut stream,
                header,
                json!({}),
                br#"{"request_id":"00112233-4455-4677-8899-aabbccddeeff","expires_at_ms":1234}"#,
                false,
            );
        },
    );
    assert!(output.status.success());
    assert_eq!(output_json(&output)["expires_at_ms"], 1234);
    let output = exchange(&["call", "github.create_issue", "--no-wait"], |listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let (header, _, _) = receive(&mut stream);
        reply(
            &mut stream,
            header,
            json!({"request_id":header.request_id,"code":"DENIED","message":"Rule denied","next":"Call request_access with a reason","retryable":false}),
            &[],
            true,
        );
    });
    assert_eq!(output.status.code(), Some(4));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["next"], "Call request_access with a reason");
}
#[test]
#[cfg(not(feature = "lab"))]
fn removed_personal_session_commands_and_excessive_waits_are_rejected() {
    for args in [
        vec!["run", "profile", "--", "true"],
        vec!["profile", "list"],
        vec!["action", "list"],
        vec!["template", "catalog", "--builtin", "github-pat"],
        vec!["session", "create"],
        vec!["execute", "action", "--capability", "token"],
        vec!["desktop-reveal", "00112233-4455-4677-8899-aabbccddeeff"],
        vec!["await-unlock", "--timeout", "121"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}
