//! Real CLI + synthetic same-UID Unix service, never a real vault or Keychain.
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use rekey_domain::ipc::{
    self, Channel, FRAME_HEADER_LEN, FrameHeader, ProofKind, admin_msg, resp_msg,
};
use serde_json::{Value, json};

const ID: &str = "00112233-4455-4677-8899-aabbccddeeff";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN: &str = "synthetic-profile-capability-never-print";
const AMBIENT_KEY: &str = "synthetic-ambient-credential-never-print";

fn profile(confirm: bool) -> Value {
    json!({"name":"writer","principal_id":ID,"grants":[{"instance":"repo","capabilities":[{"capability":"issues.create","rule":"template-default","actions":[{"action_id":ID,"version":1}]}]}],"session":{"ttl_ms":60000,"max_uses":3},"confirm_each_run":confirm,"isolation":"none","egress":"allow","llm_limits":[]})
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn get(p: Value) -> Value {
    json!({"profile":p,"policy_sha256":HASH,"expires_at_ms":now()+120000})
}
fn created(p: Value) -> Value {
    json!({"profile":p,"policy_sha256":HASH,"gateway":null,"session":{"session_id":ID,"principal_id":ID,"capability_token":TOKEN,"expires_at_ms":now()+60000,"max_uses":3}})
}
fn accept(listener: &UnixListener) -> UnixStream {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < end, "CLI did not connect");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}
fn request(stream: &mut UnixStream, op: u16, managed: bool) -> (FrameHeader, Vec<u8>) {
    let mut header = [0; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).unwrap();
    let h = FrameHeader::decode(&header).unwrap();
    assert_eq!(h.channel, Channel::Admin);
    assert_eq!(h.message_type, op);
    let mut meta = vec![0; h.metadata_len as usize];
    let mut body = vec![0; h.body_len as usize];
    stream.read_exact(&mut meta).unwrap();
    stream.read_exact(&mut body).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&meta).unwrap(),
        json!({"profile":"writer"})
    );
    if managed {
        let (token, inner) = ipc::parse_management_body(&body).unwrap();
        assert_eq!(token, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        (h, inner.to_vec())
    } else {
        (h, body)
    }
}
fn reply(stream: &mut UnixStream, h: FrameHeader, value: Value) {
    let body = serde_json::to_vec(&value).unwrap();
    stream
        .write_all(
            &FrameHeader {
                channel: Channel::Admin,
                flags: 0,
                message_type: resp_msg::OK,
                request_id: h.request_id,
                metadata_len: 2,
                body_len: body.len() as u32,
            }
            .encode(),
        )
        .unwrap();
    stream.write_all(b"{}").unwrap();
    stream.write_all(&body).unwrap();
}
enum Control {
    UntilExit,
    Disconnect,
    Byte,
    InsecureBeforeProof,
}

fn fixture(
    before: Value,
    after: Option<Value>,
    proof: Vec<u8>,
    flags: &[&str],
    input: &[u8],
    mode: &str,
    control: Control,
) -> Output {
    fixture_command(
        before,
        after,
        proof,
        flags,
        input,
        (mode, &[], &[]),
        control,
    )
}

fn fixture_command(
    before: Value,
    after: Option<Value>,
    proof: Vec<u8>,
    flags: &[&str],
    input: &[u8],
    child: (&str, &[&str], &[&str]),
    control: Control,
) -> Output {
    let (mode, client_args, expected_args) = child;
    let adapter = flags
        .windows(2)
        .find(|pair| pair[0] == "--client")
        .map_or("", |pair| pair[1]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("admin.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A valid-looking but stale discovery cache must never select the token destination.
    std::fs::write(dir.path().join("gateway.port"), "65534\n").unwrap();
    let expected_gateway = after
        .as_ref()
        .and_then(|v| v.get("gateway"))
        .cloned()
        .unwrap_or(Value::Null);
    let marker = dir.path().join("child-pid");
    let marker_server = marker.clone();
    let managed = mode == "managed";
    let check_cloexec = mode == "cloexec";
    let server = std::thread::spawn(move || {
        let mut first = accept(&listener);
        let (h, body) = request(&mut first, admin_msg::PROFILE_GET, managed);
        assert!(body.is_empty());
        if matches!(control, Control::InsecureBeforeProof) {
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        reply(&mut first, h, before);
        drop(first);
        let Some(after) = after else { return };
        let mut owner = accept(&listener);
        let (h, body) = request(&mut owner, admin_msg::PROFILE_SESSION_CREATE, managed);
        assert_eq!(body, proof);
        reply(&mut owner, h, after);
        if check_cloexec {
            owner
                .set_read_timeout(Some(Duration::from_millis(750)))
                .unwrap();
        }
        match control {
            Control::UntilExit => {
                let mut byte = [0];
                assert_eq!(
                    owner.read(&mut byte).unwrap(),
                    0,
                    "owner fd leaked or control bytes sent"
                );
            }
            Control::Disconnect | Control::Byte => {
                let end = Instant::now() + Duration::from_secs(4);
                while !marker_server.exists() {
                    assert!(Instant::now() < end, "child did not start");
                    std::thread::sleep(Duration::from_millis(5));
                }
                if matches!(control, Control::Byte) {
                    owner.write_all(b"unexpected").unwrap();
                    let mut byte = [0];
                    let result = owner.read(&mut byte);
                    assert!(matches!(result, Ok(0)) || result.is_err());
                }
            }
            Control::InsecureBeforeProof => unreachable!(),
        }
    });
    // This synthetic helper proves CLI delegation and failure propagation only;
    // the real Seatbelt boundary is exercised by sandbox_macos and joined E2E.
    let isolated = mode.starts_with("isolated-");
    let _agent_listener = isolated.then(|| UnixListener::bind(runtime.join("agent.sock")).unwrap());
    let binary = if isolated {
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_rekey"), bin.join("rekey")).unwrap();
        let mut script = String::from(
            r#"#!/bin/sh
set -eu
[ "$1" = profile-child ]; shift
[ "$1" = --state-dir ]; [ -d "$2" ]; shift 2
[ "$1" = --agent-socket ]; [ -S "$2" ]; shift 2
[ "$1" = --isolation ]; [ "$2" = seatbelt ]; shift 2
[ "$REKEY_CAPABILITY" = synthetic-profile-capability-never-print ]
[ -z "${HOME+x}" ]
[ -z "${UNRELATED_RUN_SETTING+x}" ]
[ -z "${REKEY_RUN_FIXTURE_MODE+x}" ]
[ -z "${ANTHROPIC_CUSTOM_HEADERS+x}" ]
[ -z "${OPENAI_CUSTOM_HEADERS+x}" ]
[ -z "${CLAUDE_CODE_USE_BEDROCK+x}" ]
"#,
        );
        if expected_gateway.is_null() {
            script.push_str(
                r#"[ -z "${ANTHROPIC_API_KEY+x}" ]
[ -z "${ANTHROPIC_AUTH_TOKEN+x}" ]
[ -z "${OPENAI_API_KEY+x}" ]
"#,
            );
        } else {
            script.push_str(
                r#"[ "$1" = --gateway-port ]; [ "$2" = 43127 ]; shift 2
[ "$ANTHROPIC_BASE_URL" = http://127.0.0.1:43127/p/Anthropic-West_1 ]
[ "$ANTHROPIC_API_KEY" = "rkc_$REKEY_CAPABILITY" ]
[ -z "${ANTHROPIC_AUTH_TOKEN+x}" ]
[ "$OPENAI_BASE_URL" = http://127.0.0.1:43127/p/OpenAI-East_2/v1 ]
[ "$OPENAI_API_KEY" = "rkc_$REKEY_CAPABILITY" ]
"#,
            );
        }
        script.push_str(
            r#"[ "$1" = -- ]; shift
[ "$#" -eq 5 ]; case "$1" in /*) ;; *) exit 90;; esac; shift
[ "$1" = '' ]; [ "$2" = 'two words' ]; [ "$3" = -- ]; [ "$4" = --share-net ]
IFS= read -r input
[ "$input" = child-input ]
"#,
        );
        if mode == "isolated-control" {
            script.push_str("trap 'echo done > helper-terminated; exit 143' TERM\necho $$ > child-pid\nwhile :; do /bin/sleep 0.02; done\n");
        } else if mode == "isolated-default-term" {
            script.push_str("echo $$ > child-pid\nwhile :; do /bin/sleep 0.02; done\n");
        } else if mode == "isolated-ignore-term" {
            script
                .push_str("trap '' TERM\necho $$ > child-pid\nwhile :; do /bin/sleep 0.02; done\n");
        } else if mode == "isolated-fail" {
            script.push_str("exit 37\n");
        } else {
            script.push_str("printf 'isolated-helper-ok\\n'\nexit 23\n");
        }
        if mode != "isolated-missing" {
            std::fs::write(bin.join("rekeyd"), script).unwrap();
            std::fs::set_permissions(bin.join("rekeyd"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        bin.join("rekey")
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_rekey"))
    };
    let mut cmd = Command::new(binary);
    if managed {
        let file = dir.path().join("management-session");
        std::fs::write(&file, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        cmd.arg("--admin-session-file")
            .arg(file.canonicalize().unwrap());
    }
    cmd.arg("--state-dir")
        .arg(dir.path())
        .arg("run")
        .args(flags)
        .arg("writer")
        .arg("--");
    if isolated {
        cmd.args(["/bin/echo", "", "two words", "--", "--share-net"]);
    } else if mode == "spawn-error" {
        cmd.arg(dir.path().join("missing-command"));
    } else if mode == "cloexec" {
        cmd.args(["/bin/sh", "-c", "sleep 2 >/dev/null 2>&1 & exit 0"]);
    } else if !adapter.is_empty() {
        // A synthetic executable captures argv without parsing third-party flags,
        // then execs the real child fixture so stdio/PID/exit behavior stays real.
        let wrapper = dir.path().join("synthetic-client");
        std::fs::write(&wrapper, b"#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$REKEY_RUN_FIXTURE_ARGV\"\nexec \"$REKEY_RUN_FIXTURE_TEST_BIN\" --exact profile_child --nocapture\n").unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        cmd.arg(wrapper).args(client_args);
    } else {
        cmd.arg(std::env::current_exe().unwrap())
            .args(["--exact", "profile_child", "--nocapture"]);
    }
    cmd.current_dir(dir.path())
        .env("REKEY_RUN_FIXTURE_MODE", mode)
        .env("REKEY_RUN_FIXTURE_ADAPTER", adapter)
        .env("REKEY_RUN_FIXTURE_ARGV", dir.path().join("client-argv"))
        .env(
            "REKEY_RUN_FIXTURE_TEST_BIN",
            std::env::current_exe().unwrap(),
        )
        .env(
            "REKEY_RUN_FIXTURE_EXPECTED_ARGS",
            serde_json::to_string(expected_args).unwrap(),
        )
        .env("CLAUDE_CODE_USE_BEDROCK", "1")
        .env("CLAUDE_CODE_USE_VERTEX", "1")
        .env("CLAUDE_CODE_USE_FOUNDRY", "1")
        .env(
            "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
            "external-value-preserved",
        )
        .env("REKEY_RUN_FIXTURE_CWD", dir.path())
        .env("REKEY_RUN_FIXTURE_MARKER", &marker)
        .env("REKEY_RUN_FIXTURE_SOCKET", runtime.join("agent.sock"))
        .env("REKEY_RUN_FIXTURE_GATEWAY", expected_gateway.to_string())
        .env("ANTHROPIC_BASE_URL", "https://ambient.invalid/anthropic")
        .env("OPENAI_BASE_URL", "https://ambient.invalid/openai")
        .env("ANTHROPIC_API_KEY", AMBIENT_KEY)
        .env("OPENAI_API_KEY", AMBIENT_KEY)
        .env("ANTHROPIC_AUTH_TOKEN", AMBIENT_KEY)
        .env(
            "ANTHROPIC_CUSTOM_HEADERS",
            "Authorization: Bearer synthetic-ambient-credential-never-print",
        )
        .env(
            "OPENAI_CUSTOM_HEADERS",
            "Authorization: Bearer synthetic-ambient-credential-never-print",
        )
        .env("UNRELATED_RUN_SETTING", "preserve-me")
        .env("REKEY_CAPABILITY", "stale-token")
        .env("REKEY_AGENT_SOCKET", "stale-socket")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    // Deliberately leave stdin open: no-proof and invalid-peer must not wait for input/EOF.
    let deadline = Instant::now() + Duration::from_secs(6);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("CLI did not finish");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        server.join().is_ok(),
        "fixture failed; CLI stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if mode == "isolated-control" {
        assert!(
            dir.path().join("helper-terminated").exists(),
            "helper must handle TERM before CLI returns"
        );
    }
    if marker.exists() && mode == "idle" {
        let pid: i32 = std::fs::read_to_string(marker).unwrap().parse().unwrap();
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "supervised child was not reaped"
        );
    }
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(AMBIENT_KEY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(AMBIENT_KEY));
    output
}

#[test]
fn profile_child() {
    let Ok(mode) = std::env::var("REKEY_RUN_FIXTURE_MODE") else {
        return;
    };
    let adapter = std::env::var("REKEY_RUN_FIXTURE_ADAPTER").unwrap();
    if !adapter.is_empty() {
        let bytes = std::fs::read(std::env::var_os("REKEY_RUN_FIXTURE_ARGV").unwrap()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
        let args: Vec<_> = bytes
            .strip_suffix(&[0])
            .unwrap()
            .split(|b| *b == 0)
            .map(|v| std::str::from_utf8(v).unwrap())
            .collect();
        let expected: Vec<String> =
            serde_json::from_str(&std::env::var("REKEY_RUN_FIXTURE_EXPECTED_ARGS").unwrap())
                .unwrap();
        assert_eq!(args, expected);
    }
    for key in [
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    ] {
        if adapter == "claude-code" {
            assert!(std::env::var_os(key).is_none());
        } else {
            assert_eq!(std::env::var(key).unwrap(), "1");
        }
    }
    assert_eq!(
        std::env::var("CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST").unwrap(),
        "external-value-preserved"
    );
    assert!(std::env::var("REKEY_CAPABILITY").unwrap() == TOKEN);
    assert_eq!(
        std::env::var_os("REKEY_AGENT_SOCKET"),
        std::env::var_os("REKEY_RUN_FIXTURE_SOCKET")
    );
    assert_eq!(
        std::env::current_dir().unwrap(),
        PathBuf::from(std::env::var_os("REKEY_RUN_FIXTURE_CWD").unwrap())
            .canonicalize()
            .unwrap()
    );
    assert!(std::env::args_os().all(|a| !a.to_string_lossy().contains(TOKEN)));
    let gateway: Value =
        serde_json::from_str(&std::env::var("REKEY_RUN_FIXTURE_GATEWAY").unwrap()).unwrap();
    for (provider, prefix, suffix, ambient_url) in [
        (
            "anthropic",
            "ANTHROPIC",
            "",
            "https://ambient.invalid/anthropic",
        ),
        ("openai", "OPENAI", "/v1", "https://ambient.invalid/openai"),
    ] {
        let mapping = gateway["instances"].as_array().and_then(|instances| {
            instances
                .iter()
                .find(|mapping| mapping["provider"] == provider)
        });
        let key = std::env::var(format!("{prefix}_API_KEY"));
        if let Some(mapping) = mapping {
            // Boolean assertions deliberately never render a capability on failure.
            if provider == "anthropic" && adapter == "claude-code" {
                assert!(key.is_err());
                assert!(std::env::var("ANTHROPIC_AUTH_TOKEN").unwrap() == format!("rkc_{TOKEN}"));
            } else {
                assert!(key.unwrap() == format!("rkc_{TOKEN}"));
            }
            assert_eq!(
                std::env::var(format!("{prefix}_BASE_URL")).unwrap(),
                format!(
                    "http://127.0.0.1:{}/p/{}{suffix}",
                    gateway["port"].as_u64().unwrap(),
                    mapping["instance"].as_str().unwrap()
                )
            );
            assert!(std::env::var_os(format!("{prefix}_CUSTOM_HEADERS")).is_none());
            if provider == "anthropic" && adapter != "claude-code" {
                assert!(std::env::var_os("ANTHROPIC_AUTH_TOKEN").is_none());
            }
        } else {
            assert!(key.unwrap() == AMBIENT_KEY);
            assert_eq!(
                std::env::var(format!("{prefix}_BASE_URL")).unwrap(),
                ambient_url
            );
            assert!(
                std::env::var(format!("{prefix}_CUSTOM_HEADERS"))
                    .unwrap()
                    .contains(AMBIENT_KEY)
            );
            if provider == "anthropic" {
                assert!(std::env::var("ANTHROPIC_AUTH_TOKEN").unwrap() == AMBIENT_KEY);
            }
        }
    }
    assert_eq!(
        std::env::var("UNRELATED_RUN_SETTING").unwrap(),
        "preserve-me"
    );
    if mode == "idle" {
        std::fs::write(
            std::env::var_os("REKEY_RUN_FIXTURE_MARKER").unwrap(),
            std::process::id().to_string(),
        )
        .unwrap();
        // Bound the fixture lifetime even if a broken launcher ignores EOF.
        std::thread::sleep(Duration::from_secs(4));
        std::process::exit(99);
    }
    if mode == "signal" {
        unsafe { libc::raise(libc::SIGTERM) };
        unreachable!();
    }
    let mut input = String::new();
    std::io::stdin().lock().read_line(&mut input).unwrap();
    assert_eq!(input, "child-input\n");
    println!("child-output-preserved");
    eprintln!("child-stderr-preserved");
    std::process::exit(23);
}

#[test]
fn no_proof_preserves_child_environment_cwd_stdio_and_exit() {
    let p = profile(false);
    let out = fixture(
        get(p.clone()),
        Some(created(p)),
        vec![],
        &[],
        b"child-input\n",
        "normal",
        Control::UntilExit,
    );
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stdout).contains("child-output-preserved"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("child-stderr-preserved"));
}

#[test]
fn explicit_proofs_use_only_create_body_and_preserve_following_stdin() {
    for (kind, flags, secret) in [
        (
            ProofKind::Password,
            vec!["--password-stdin"],
            "fixture-password",
        ),
        (
            ProofKind::Recovery,
            vec!["--recovery", "--password-stdin"],
            "fixture-recovery",
        ),
        (
            ProofKind::Presence,
            vec!["--presence", "--password-stdin"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ] {
        let p = profile(true);
        let mut proof = vec![];
        ipc::encode_proof_body(kind, secret.as_bytes(), &mut proof);
        let out = fixture(
            get(p.clone()),
            Some(created(p)),
            proof,
            &flags,
            format!("{secret}\nchild-input\n").as_bytes(),
            "normal",
            Control::UntilExit,
        );
        assert_eq!(
            out.status.code(),
            Some(23),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
    }
}

#[test]
fn changed_profile_or_hash_closes_owner_without_launch() {
    for change_hash in [false, true] {
        let p = profile(false);
        let mut after = created(p.clone());
        if change_hash {
            after["policy_sha256"] = json!("b".repeat(64));
        } else {
            after["profile"]["session"]["max_uses"] = json!(2);
        }
        let out = fixture(
            get(p),
            Some(after),
            vec![],
            &[],
            b"",
            "idle",
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn unsupported_requirements_and_unneeded_proof_never_create() {
    for (field, value) in [
        ("isolation", json!("seatbelt")),
        ("isolation", json!("netns")),
        ("egress", json!("deny-other")),
    ] {
        let mut p = profile(false);
        p[field] = value;
        let out = fixture(get(p), None, vec![], &[], b"", "idle", Control::UntilExit);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    let out = fixture(
        get(profile(false)),
        None,
        vec![],
        &["--password-stdin"],
        b"",
        "idle",
        Control::UntilExit,
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn create_peer_is_checked_before_reading_proof() {
    let out = fixture(
        get(profile(true)),
        None,
        vec![],
        &["--password-stdin"],
        b"",
        "idle",
        Control::InsecureBeforeProof,
    );
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn control_eof_or_unexpected_bytes_terminates_and_reaps_child() {
    for mode in [Control::Disconnect, Control::Byte] {
        let p = profile(false);
        let out = fixture(
            get(p.clone()),
            Some(created(p)),
            vec![],
            &[],
            b"",
            "idle",
            mode,
        );
        assert_eq!(out.status.code(), Some(7));
    }
}

#[test]
fn spawn_failure_and_child_signal_close_control() {
    for (mode, exit) in [
        ("spawn-error", 5),
        ("signal", 128 + libc::SIGTERM),
        ("cloexec", 0),
    ] {
        let p = profile(false);
        let out = fixture(
            get(p.clone()),
            Some(created(p)),
            vec![],
            &[],
            b"",
            mode,
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(exit));
    }
}

#[test]
fn invalid_proof_options_are_rejected_before_connection() {
    for flags in [
        vec!["--presence"],
        vec!["--presence", "--recovery", "--password-stdin"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_rekey"))
            .args(["--state-dir", "/not-a-rekey-state", "run", "writer"])
            .args(flags)
            .args(["--", "/bin/true"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
    }
}

#[cfg(feature = "lab")]
#[test]
fn lab_management_envelope_preserves_both_profile_operations() {
    let p = profile(false);
    let out = fixture(
        get(p.clone()),
        Some(created(p)),
        vec![],
        &[],
        b"child-input\n",
        "managed",
        Control::UntilExit,
    );
    assert_eq!(
        out.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn expired_or_malformed_get_never_reads_proof_or_creates() {
    for (field, value, code) in [
        ("expires_at_ms", json!(0), 4),
        ("policy_sha256", json!("BAD"), 2),
    ] {
        let mut before = get(profile(true));
        before[field] = value;
        let out = fixture(
            before,
            None,
            vec![],
            &["--password-stdin"],
            b"",
            "idle",
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(code));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn invalid_session_scope_closes_control_without_launch() {
    for (field, value) in [
        (
            "principal_id",
            json!("00112233-4455-4677-8899-aabbccddee00"),
        ),
        ("expires_at_ms", json!(0)),
        ("max_uses", json!(4)),
    ] {
        let p = profile(false);
        let mut after = created(p.clone());
        after["session"][field] = value;
        let out = fixture(
            get(p),
            Some(after),
            vec![],
            &[],
            b"",
            "idle",
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
}

fn llm_profile(confirm: bool, instances: &[&str]) -> Value {
    let mut p = profile(confirm);
    p["grants"] = json!(
        instances
            .iter()
            .enumerate()
            .map(|(index, instance)| {
                json!({"instance":instance,"capabilities":[{"capability":"generate","rule":"template-default","actions":[{
                    "action_id":format!("00112233-4455-4677-8899-{index:012x}"),"version":1
                }]}]})
            })
            .collect::<Vec<_>>()
    );
    p["llm_limits"] =
        json!(instances.iter().map(|instance| json!({
        "instance":instance,"models":["fixture-model"],"max_output_tokens_per_request":1,
        "max_requests_per_day":2,"max_output_tokens_per_day":3
    })).collect::<Vec<_>>());
    p
}

fn gateway(instances: &[(&str, &str)]) -> Value {
    json!({"port":43127,"instances":instances.iter().map(|(instance,provider)|
        json!({"instance":instance,"provider":provider})
    ).collect::<Vec<_>>()})
}

#[test]
fn sdk_environment_uses_authenticated_endpoint_aliases_and_one_prefix_only() {
    for mappings in [
        vec![("Anthropic-West_1", "anthropic")],
        vec![("OpenAI-East_2", "openai")],
        vec![
            ("OpenAI-East_2", "openai"),
            ("Anthropic-West_1", "anthropic"),
        ],
    ] {
        let names: Vec<_> = mappings.iter().map(|(instance, _)| *instance).collect();
        let p = llm_profile(false, &names);
        let mut after = created(p.clone());
        after["gateway"] = gateway(&mappings);
        let out = fixture(
            get(p),
            Some(after),
            vec![],
            &[],
            b"child-input\n",
            "normal",
            Control::UntilExit,
        );
        assert_eq!(
            out.status.code(),
            Some(23),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn sdk_endpoint_unavailable_or_malformed_never_launches() {
    let p = llm_profile(false, &["llm"]);
    for (endpoint, exit) in [
        (Value::Null, 5),
        (
            json!({"port":0,"instances":[{"instance":"llm","provider":"anthropic"}]}),
            2,
        ),
        (
            json!({"port":65536,"instances":[{"instance":"llm","provider":"anthropic"}]}),
            2,
        ),
        (gateway(&[]), 2),
        (gateway(&[("llm", "other")]), 2),
        (gateway(&[("unknown", "anthropic")]), 2),
        (gateway(&[("llm", "anthropic"), ("extra", "openai")]), 2),
        (
            json!({"port":43127,"instances":[{"instance":"llm","provider":"anthropic"}],"origin":"https://untrusted.invalid"}),
            2,
        ),
    ] {
        let mut after = created(p.clone());
        after["gateway"] = endpoint;
        let out = fixture(
            get(p.clone()),
            Some(after),
            vec![],
            &[],
            b"",
            "idle",
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(exit));
        assert!(out.stdout.is_empty());
    }
    let mut after = created(p.clone());
    after.as_object_mut().unwrap().remove("gateway");
    let out = fixture(
        get(p),
        Some(after),
        vec![],
        &[],
        b"",
        "idle",
        Control::UntilExit,
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn sdk_duplicate_unknown_mapping_or_ambiguous_provider_never_launches() {
    let p = llm_profile(false, &["a", "b"]);
    for (mappings, exit) in [
        (vec![("a", "anthropic"), ("a", "openai")], 2),
        (vec![("a", "anthropic"), ("other", "openai")], 2),
        (vec![("a", "anthropic"), ("b", "anthropic")], 2),
        (vec![("a", "openai"), ("b", "openai")], 2),
    ] {
        let mut after = created(p.clone());
        after["gateway"] = gateway(&mappings);
        let out = fixture(
            get(p.clone()),
            Some(after),
            vec![],
            &[],
            b"",
            "idle",
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(exit));
        assert!(out.stdout.is_empty());
    }
    let p = profile(false);
    let mut after = created(p.clone());
    after["gateway"] = gateway(&[("repo", "openai")]);
    let out = fixture(
        get(p),
        Some(after),
        vec![],
        &[],
        b"",
        "idle",
        Control::UntilExit,
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn malformed_profile_is_rejected_before_proof_or_create() {
    for p in [
        llm_profile(true, &["bad/route"]),
        llm_profile(true, &["duplicate", "duplicate"]),
        {
            let mut p = llm_profile(true, &["llm"]);
            p["session"]["max_uses"] = json!(0);
            p
        },
    ] {
        let out = fixture(
            get(p),
            None,
            vec![],
            &["--password-stdin"],
            b"",
            "idle",
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn sdk_requires_same_policy_scope_and_explicit_proof_then_still_obeys_control_eof() {
    let p = llm_profile(true, &["llm"]);
    let secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut proof = vec![];
    ipc::encode_proof_body(ProofKind::Presence, secret.as_bytes(), &mut proof);
    let mut after = created(p.clone());
    after["gateway"] = gateway(&[("llm", "anthropic")]);
    let out = fixture(
        get(p.clone()),
        Some(after.clone()),
        proof.clone(),
        &["--presence", "--password-stdin"],
        format!("{secret}\nchild-input\n").as_bytes(),
        "normal",
        Control::UntilExit,
    );
    assert_eq!(out.status.code(), Some(23));
    after["profile"]["llm_limits"][0]["models"] = json!(["changed-model"]);
    let out = fixture(
        get(p),
        Some(after),
        proof,
        &["--presence", "--password-stdin"],
        format!("{secret}\n").as_bytes(),
        "idle",
        Control::UntilExit,
    );
    assert_eq!(out.status.code(), Some(4));
    assert!(out.stdout.is_empty());
    let p = llm_profile(false, &["llm"]);
    let mut after = created(p.clone());
    after["gateway"] = gateway(&[("llm", "openai")]);
    let out = fixture(
        get(p),
        Some(after),
        vec![],
        &[],
        b"",
        "idle",
        Control::Disconnect,
    );
    assert_eq!(out.status.code(), Some(7));
}

const CODEX_SELECT: &str = "model_provider=\"rekey_00112233445546778899aabbccddeeff\"";
const CODEX_CONFIG: &str = "model_providers.rekey_00112233445546778899aabbccddeeff={name=\"Rekey\",base_url=\"http://127.0.0.1:43127/p/OpenAI-2/v1\",env_key=\"OPENAI_API_KEY\",wire_api=\"responses\",requires_openai_auth=false,supports_websockets=false}";

#[test]
fn explicit_claude_adapter_uses_only_bearer_and_preserves_user_args_and_policy_env() {
    let p = llm_profile(false, &["Anthropic-1", "OpenAI-2"]);
    let mut after = created(p.clone());
    after["gateway"] = gateway(&[("Anthropic-1", "anthropic"), ("OpenAI-2", "openai")]);
    let args = [
        "-p",
        "literal prompt",
        "",
        "中文 prompt\nsecond line",
        "--",
        "--no-daemon",
        "--remote=prompt",
    ];
    let out = fixture_command(
        get(p),
        Some(after),
        vec![],
        &["--client", "claude-code"],
        b"child-input\n",
        ("normal", &args, &args),
        Control::UntilExit,
    );
    assert_eq!(
        out.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn codex_adapter_has_final_session_provider_overrides_and_one_root_no_daemon() {
    for (args, expected) in [
        (
            vec![
                "--no-daemon",
                "-c",
                "model_provider=\"ambient\"",
                "exec",
                "-c",
                "model_provider=\"user\"",
                "--no-daemon",
                "--",
                "prompt text",
                "",
                "中文 prompt\nsecond line",
                "--no-daemon",
                "--oss",
                "--remote=prompt",
            ],
            vec![
                "--no-daemon",
                "-c",
                "model_provider=\"ambient\"",
                "exec",
                "-c",
                "model_provider=\"user\"",
                "-c",
                CODEX_SELECT,
                "-c",
                CODEX_CONFIG,
                "--",
                "prompt text",
                "",
                "中文 prompt\nsecond line",
                "--no-daemon",
                "--oss",
                "--remote=prompt",
            ],
        ),
        (
            vec![
                "exec",
                "--no-daemon=leave-literal",
                "--model",
                "fixture-model",
                "prompt text",
            ],
            vec![
                "--no-daemon",
                "exec",
                "--no-daemon=leave-literal",
                "--model",
                "fixture-model",
                "prompt text",
                "-c",
                CODEX_SELECT,
                "-c",
                CODEX_CONFIG,
            ],
        ),
        (
            vec![
                "-c",
                "model_providers.rekey.http_headers.Authorization=\"ambient\"",
                "exec",
            ],
            vec![
                "--no-daemon",
                "-c",
                "model_providers.rekey.http_headers.Authorization=\"ambient\"",
                "exec",
                "-c",
                CODEX_SELECT,
                "-c",
                CODEX_CONFIG,
            ],
        ),
    ] {
        let p = llm_profile(false, &["OpenAI-2"]);
        let mut after = created(p.clone());
        after["gateway"] = gateway(&[("OpenAI-2", "openai")]);
        let out = fixture_command(
            get(p),
            Some(after),
            vec![],
            &["--client", "codex"],
            b"child-input\n",
            ("normal", &args, &expected),
            Control::UntilExit,
        );
        assert_eq!(
            out.status.code(),
            Some(23),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn codex_provider_id_uses_current_session_and_control_eof_still_reaps() {
    let p = llm_profile(false, &["OpenAI-2"]);
    let mut after = created(p.clone());
    after["gateway"] = gateway(&[("OpenAI-2", "openai")]);
    after["session"]["session_id"] = json!("abcdef00-1234-4567-890a-123456789abc");
    let expected = [
        "--no-daemon",
        "exec",
        "-c",
        "model_provider=\"rekey_abcdef0012344567890a123456789abc\"",
        "-c",
        "model_providers.rekey_abcdef0012344567890a123456789abc={name=\"Rekey\",base_url=\"http://127.0.0.1:43127/p/OpenAI-2/v1\",env_key=\"OPENAI_API_KEY\",wire_api=\"responses\",requires_openai_auth=false,supports_websockets=false}",
    ];
    let out = fixture_command(
        get(p),
        Some(after),
        vec![],
        &["--client", "codex"],
        b"",
        ("idle", &["exec"], &expected),
        Control::Disconnect,
    );
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn explicit_client_missing_required_provider_closes_owner_without_launch() {
    for (client, names, mappings) in [
        ("claude-code", vec!["llm"], vec![("llm", "openai")]),
        ("codex", vec!["llm"], vec![("llm", "anthropic")]),
        ("claude-code", vec![], vec![]),
        ("codex", vec![], vec![]),
    ] {
        let p = if names.is_empty() {
            profile(false)
        } else {
            llm_profile(false, &names)
        };
        let mut after = created(p.clone());
        if !mappings.is_empty() {
            after["gateway"] = gateway(&mappings);
        }
        let out = fixture_command(
            get(p),
            Some(after),
            vec![],
            &["--client", client],
            b"",
            ("idle", &[], &[]),
            Control::UntilExit,
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn codex_conflicting_routes_are_rejected_before_connecting_or_reading_proof() {
    for args in [
        vec!["--oss"],
        vec!["exec", "--local-provider", "ollama"],
        vec!["--local-provider=lmstudio"],
        vec!["--remote", "remote-host"],
        vec!["exec", "--remote=remote-host"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_rekey"))
            .args([
                "--state-dir",
                "/not-a-rekey-state",
                "run",
                "writer",
                "--client",
                "codex",
                "--password-stdin",
                "--",
                "synthetic-client",
            ])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("conflicts with the Profile gateway")
        );
    }
    let out = Command::new(env!("CARGO_BIN_EXE_rekey"))
        .args([
            "--state-dir",
            "/not-a-rekey-state",
            "run",
            "writer",
            "--client",
            "unknown",
            "--",
            "synthetic-client",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
#[cfg(target_os = "macos")]
fn seatbelt_profile_delegates_with_only_explicit_session_environment() {
    for sdk in [false, true] {
        let mut p = if sdk {
            llm_profile(false, &["Anthropic-West_1", "OpenAI-East_2"])
        } else {
            profile(false)
        };
        p["isolation"] = json!("seatbelt");
        p["egress"] = json!("deny-other");
        let mut after = created(p.clone());
        if sdk {
            after["gateway"] = gateway(&[
                ("Anthropic-West_1", "anthropic"),
                ("OpenAI-East_2", "openai"),
            ]);
        }
        let out = fixture(
            get(p),
            Some(after),
            vec![],
            &[],
            b"child-input\n",
            "isolated-ok",
            Control::UntilExit,
        );
        assert_eq!(
            out.status.code(),
            Some(23),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"isolated-helper-ok\n");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn isolated_helper_error_or_absence_closes_control_without_bare_child_fallback() {
    for (mode, expected) in [("isolated-fail", 37), ("isolated-missing", 5)] {
        let mut p = profile(false);
        p["isolation"] = json!("seatbelt");
        p["egress"] = json!("deny-other");
        let out = fixture(
            get(p.clone()),
            Some(created(p)),
            vec![],
            &[],
            b"child-input\n",
            mode,
            Control::UntilExit,
        );
        assert_eq!(
            out.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "bare echo command must never start");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn isolated_control_loss_requests_cleanup_and_reports_unconfirmed_timeout() {
    for (mode, code) in [
        ("isolated-control", 7),
        ("isolated-ignore-term", 5),
        ("isolated-default-term", 5),
    ] {
        let mut p = profile(false);
        p["isolation"] = json!("seatbelt");
        p["egress"] = json!("deny-other");
        let out = fixture(
            get(p.clone()),
            Some(created(p)),
            vec![],
            &[],
            b"child-input\n",
            mode,
            Control::Disconnect,
        );
        assert_eq!(
            out.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
        if mode != "isolated-control" {
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("cleanup could not be confirmed")
            );
        }
    }
}
