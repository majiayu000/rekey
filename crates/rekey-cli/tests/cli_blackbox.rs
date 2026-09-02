//! Process-level blackbox: real `rekeyd` and `rekey` binaries, tempdir state,
//! secrets only via stdin flags — never argv or environment.
//!
//! Requires both binaries to be built (`cargo test --workspace` builds them).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const PASSWORD: &str = "blackbox horse battery staple";
const SECRET: &str = "CLI-CANARY-SECRET-0x5eed";

fn rekey_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rekey"))
}

fn rekeyd_bin() -> PathBuf {
    let sibling = rekey_bin().parent().unwrap().join("rekeyd");
    assert!(
        sibling.exists(),
        "rekeyd binary not built; run `cargo build --workspace` (or `cargo test --workspace`) first"
    );
    sibling
}

struct Output {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(binary: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().expect("wait");
    Output {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

struct ServeGuard(Child);

impl Drop for ServeGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cli_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let state = state_dir.to_str().unwrap();

    // init via rekeyd with --password-stdin; recovery key goes to stdout.
    let output = run(
        &rekeyd_bin(),
        &["init", "--state-dir", state, "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "init failed: {}", output.stderr);
    assert!(output.stdout.contains("RKREC1-"), "recovery key not shown");
    assert!(!output.stdout.contains(PASSWORD));
    let recovery_key = output
        .stdout
        .lines()
        .find(|line| line.starts_with("RKREC1-"))
        .expect("recovery key line")
        .to_owned();

    // Second init must refuse.
    let output = run(
        &rekeyd_bin(),
        &["init", "--state-dir", state, "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_ne!(output.status, 0);

    // serve in the background (foreground process, no daemon mode).
    let child = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", state, "--idle-lock", "15m"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rekeyd serve");
    let _guard = ServeGuard(child);
    let admin_sock = state_dir.join("runtime").join("admin.sock");
    for _ in 0..300 {
        if admin_sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(admin_sock.exists(), "broker did not start");

    // status: locked, exit 0.
    let output = run(&rekey_bin(), &["--state-dir", state, "status"], None);
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(output.stdout.contains("locked"));

    // wrong password: exit 3.
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some("wrong-password\n"),
    );
    assert_eq!(output.status, 3, "stderr: {}", output.stderr);

    // correct unlock.
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

    // Recovery step-up works for a mutation with a second Secret body.
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "credential",
            "add",
            "cli-cred",
            "--recovery",
            "--stdin-secrets",
        ],
        Some(&format!("{recovery_key}\n{SECRET}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    let credential_id = serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // list shows metadata, never the value.
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "credential", "list"],
        None,
    );
    assert_eq!(output.status, 0);
    assert!(output.stdout.contains("cli-cred"));
    assert!(!output.stdout.contains(SECRET));

    // action create from file.
    let action_file = dir.path().join("action.json");
    std::fs::write(
        &action_file,
        serde_json::json!({
            "name": "cli-action",
            "credential_id": credential_id,
            "origin": "https://api.example.com",
            "method": "GET",
            "exact_path": "/v1/ping",
            "auth_header": "authorization",
            "auth_prefix": "Bearer ",
            "timeout_ms": 10000,
            "request_max_bytes": 1024,
            "allowed_extra_headers": [],
            "response_max_bytes": 4096,
            "allowed_response_headers": ["content-type"],
        })
        .to_string(),
    )
    .unwrap();
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "action",
            "create",
            "--file",
            action_file.to_str().unwrap(),
            "--password-stdin",
        ],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    let action = serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap();
    let action_ref = format!("{}@{}", action["id"].as_str().unwrap(), action["version"]);

    // session create prints the capability token exactly once.
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "session",
            "create",
            "--action",
            &action_ref,
            "--ttl",
            "10m",
            "--max-uses",
            "5",
            "--password-stdin",
        ],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(output.stdout.contains("capability_token"));

    // execute with a garbage capability: policy denial, exit 4, no panic.
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "execute",
            &action_ref,
            "--capability",
            "bm90LWEtcmVhbC10b2tlbg",
        ],
        None,
    );
    assert_eq!(output.status, 4, "stderr: {}", output.stderr);

    // Capability tokens use base64url and may legitimately begin with '-'.
    // They must reach the broker instead of being parsed as another CLI flag.
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "execute",
            &action_ref,
            "--capability",
            "-m90LWEtcmVhbC10b2tlbg",
        ],
        None,
    );
    assert_eq!(output.status, 4, "stderr: {}", output.stderr);

    // No secret ever reaches stdout/stderr of any command after add.
    assert!(!output.stdout.contains(SECRET) && !output.stderr.contains(SECRET));

    // Recovery step-up also works for a proof-only mutation.
    let backup_path = dir.path().join("out.rkbackup");
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "backup",
            "--output",
            backup_path.to_str().unwrap(),
            "--recovery",
            "--password-stdin",
        ],
        Some(&format!("{recovery_key}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(backup_path.exists());
    let backup_stdout = output.stdout.clone();
    let backup_bytes = std::fs::read(&backup_path).unwrap();
    assert!(
        !backup_bytes
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
    );

    // shutdown with step-up proof (broker unlocked).
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "shutdown", "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

    // IPC gone after shutdown: exit 7.
    std::thread::sleep(Duration::from_millis(300));
    let output = run(&rekey_bin(), &["--state-dir", state, "status"], None);
    assert_eq!(output.status, 7);

    let receipt: serde_json::Value = serde_json::from_str(&backup_stdout).unwrap();
    let hash = receipt["sha256_hex"].as_str().expect("backup receipt hash");
    let restored = dir.path().join("restored");
    let restored_s = restored.to_str().unwrap();
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            restored_s,
            "restore",
            "--input",
            backup_path.to_str().unwrap(),
            "--sha256",
            hash,
            "--password-stdin",
        ],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "restore failed: {}", output.stderr);

    let child = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", restored_s, "--idle-lock", "15m"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn restored rekeyd");
    let _restored_guard = ServeGuard(child);
    let restored_admin = restored.join("runtime").join("admin.sock");
    for _ in 0..300 {
        if restored_admin.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(restored_admin.exists(), "restored broker did not start");
    let output = run(
        &rekey_bin(),
        &["--state-dir", restored_s, "unlock", "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    let output = run(
        &rekey_bin(),
        &["--state-dir", restored_s, "credential", "list"],
        None,
    );
    assert_eq!(output.status, 0);
    assert!(output.stdout.contains("cli-cred"));
    assert!(!output.stdout.contains(SECRET));
}

#[test]
fn cli_rejects_oversized_file_and_stdin_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("missing-state");
    let body_file = dir.path().join("oversized-body");
    std::fs::write(&body_file, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let action = format!("{}@1", rekey_domain::ids::ActionId::new_random());

    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state_dir.to_str().unwrap(),
            "execute",
            &action,
            "--capability",
            "test-capability",
            "--body-file",
            body_file.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(output.status, 2, "stderr: {}", output.stderr);
    assert!(output.stderr.contains("INVALID_FRAME"));

    let oversized_stdin = format!("{}\n", "x".repeat(64 * 1024 + 1));
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state_dir.to_str().unwrap(),
            "unlock",
            "--password-stdin",
        ],
        Some(&oversized_stdin),
    );
    assert_eq!(output.status, 2, "stderr: {}", output.stderr);
    assert!(output.stderr.contains("INVALID_FRAME"));
}
