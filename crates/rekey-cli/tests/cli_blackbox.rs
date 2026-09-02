//! Process-level blackbox: real `rekeyd` and `rekey` binaries, tempdir state,
//! secrets only via stdin flags — never argv or environment.
//!
//! Requires both binaries to be built (`cargo test --workspace` builds them).

use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const PASSWORD: &str = "blackbox horse battery staple";
const NEW_PASSWORD: &str = "blackbox replacement battery staple";
const FINAL_PASSWORD: &str = "blackbox recovered battery staple";
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

fn run_audit(state_dir: &str, args: &[&str]) -> Output {
    let mut command = vec!["--state-dir", state_dir, "audit"];
    command.extend_from_slice(args);
    run(&rekey_bin(), &command, None)
}

fn run_with_process_boundary(
    binary: &Path,
    args: &[&str],
    stdin: &str,
    secret_canaries: &[&str],
) -> Output {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let process = Command::new("ps")
        .args(["-eww", "-o", "command=", "-p", &child.id().to_string()])
        .output()
        .expect("inspect process boundary");
    assert!(process.status.success(), "cannot inspect CLI process");
    for canary in secret_canaries {
        assert!(
            !process
                .stdout
                .windows(canary.len())
                .any(|part| part == canary.as_bytes()),
            "secret appeared in CLI argv or environment"
        );
    }
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait");
    Output {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn assert_files_exclude(root: &Path, secret_canaries: &[&str]) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_files_exclude(&path, secret_canaries);
        } else if let Ok(bytes) = std::fs::read(&path) {
            for canary in secret_canaries {
                assert!(
                    !bytes
                        .windows(canary.len())
                        .any(|part| part == canary.as_bytes()),
                    "secret appeared in Rekey-created file {}",
                    path.display()
                );
            }
        }
    }
}

struct ServeGuard(Option<Child>);

impl ServeGuard {
    fn finish(mut self) -> std::process::Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
    let guard = ServeGuard(Some(child));
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
            "origin": "https://127.0.0.1",
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
            "200",
            "--password-stdin",
        ],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    let session = serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap();
    let capability = session["capability_token"].as_str().unwrap().to_owned();

    for _ in 0..105 {
        let output = run(
            &rekey_bin(),
            &[
                "--state-dir",
                state,
                "execute",
                &action_ref,
                "--capability",
                &capability,
            ],
            None,
        );
        assert_ne!(output.status, 0, "loopback target must be screened");
        assert!(!output.stdout.contains(SECRET) && !output.stderr.contains(SECRET));
    }

    let first = run_audit(state, &["list", "--limit", "1"]);
    assert_eq!(first.status, 0, "{}", first.stderr);
    let first_page: serde_json::Value = serde_json::from_str(&first.stdout).unwrap();
    let snapshot = first_page["snapshot_max_sequence"].as_u64().unwrap();
    let before = first_page["next_before_sequence"].as_u64().unwrap();
    let sample = &first_page["events"][0];
    let request_id = sample["request_id"].as_str().unwrap();
    let session_id = sample["session_id"].as_str().unwrap();
    let action_id = sample["action_id"].as_str().unwrap();
    let audit_credential_id = sample["credential_id"].as_str().unwrap();
    let audit_outcome = sample["outcome"].as_str().unwrap();
    let audit_time = sample["created_at_ms"].as_i64().unwrap().to_string();

    let output = run(&rekey_bin(), &["--state-dir", state, "lock"], None);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let snapshot_text = snapshot.to_string();
    let before_text = before.to_string();
    let continued = run_audit(
        state,
        &[
            "list",
            "--snapshot-max-sequence",
            &snapshot_text,
            "--before-sequence",
            &before_text,
            "--limit",
            "100",
        ],
    );
    assert_eq!(continued.status, 0, "{}", continued.stderr);
    let continued_page: serde_json::Value = serde_json::from_str(&continued.stdout).unwrap();
    assert_eq!(continued_page["snapshot_max_sequence"], snapshot);
    assert!(
        continued_page["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| {
                event["sequence"].as_u64().unwrap() < before
                    && event["sequence"].as_u64().unwrap() <= snapshot
            })
    );

    let filter_cases: [Vec<&str>; 7] = [
        vec!["--request", request_id],
        vec!["--session", session_id],
        vec!["--action", action_id],
        vec!["--credential", audit_credential_id],
        vec!["--outcome", audit_outcome],
        vec!["--since-ms", &audit_time],
        vec!["--until-ms", &audit_time],
    ];
    for filter in filter_cases {
        let mut args = vec!["list", "--limit", "100"];
        args.extend(filter);
        let output = run_audit(state, &args);
        assert_eq!(output.status, 0, "{}", output.stderr);
        let page: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert!(!page["events"].as_array().unwrap().is_empty());
    }
    let intersection = run_audit(
        state,
        &[
            "list",
            "--request",
            request_id,
            "--session",
            session_id,
            "--action",
            action_id,
            "--credential",
            audit_credential_id,
            "--outcome",
            audit_outcome,
            "--since-ms",
            &audit_time,
            "--until-ms",
            &audit_time,
        ],
    );
    assert_eq!(intersection.status, 0, "{}", intersection.stderr);
    assert!(
        !serde_json::from_str::<serde_json::Value>(&intersection.stdout).unwrap()["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let empty = run_audit(
        state,
        &["list", "--request", "ffffffff-ffff-4fff-bfff-ffffffffffff"],
    );
    assert_eq!(empty.status, 0, "{}", empty.stderr);
    assert!(
        serde_json::from_str::<serde_json::Value>(&empty.stdout).unwrap()["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let export_path = dir.path().join("audit.jsonl");
    let export = run_audit(
        state,
        &["export", "--output", export_path.to_str().unwrap()],
    );
    assert_eq!(export.status, 0, "{}", export.stderr);
    let receipt: serde_json::Value = serde_json::from_str(&export.stdout).unwrap();
    assert!(receipt["row_count"].as_u64().unwrap() > 100);
    let metadata = std::fs::metadata(&export_path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let export_text = std::fs::read_to_string(&export_path).unwrap();
    let lines: Vec<serde_json::Value> = export_text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines.first().unwrap()["record_type"],
        "rekey.audit.export.v1"
    );
    assert_eq!(
        lines.last().unwrap()["record_type"],
        "rekey.audit.export.complete.v1"
    );
    assert_eq!(lines.last().unwrap()["row_count"], (lines.len() - 2) as u64);
    for needle in [
        SECRET,
        PASSWORD,
        capability.as_str(),
        "resource_id",
        "parameter_hash",
    ] {
        assert!(
            !export_text.contains(needle),
            "audit export leaked {needle}"
        );
    }

    let existing = run_audit(
        state,
        &["export", "--output", export_path.to_str().unwrap()],
    );
    assert_ne!(existing.status, 0);
    assert!(!existing.stdout.contains("\"exported\": true"));
    let symlink_path = dir.path().join("audit-link.jsonl");
    let symlink_target = dir.path().join("must-stay-empty");
    std::fs::write(&symlink_target, b"").unwrap();
    symlink(&symlink_target, &symlink_path).unwrap();
    let linked = run_audit(
        state,
        &["export", "--output", symlink_path.to_str().unwrap()],
    );
    assert_ne!(linked.status, 0);
    assert!(!linked.stdout.contains("\"exported\": true"));
    assert_eq!(std::fs::read(&symlink_target).unwrap(), b"");

    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

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

    // Replace the password without changing the root key or stored credential.
    let output = run_with_process_boundary(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "password",
            "change",
            "--stdin-secrets",
        ],
        &format!("{PASSWORD}\n{NEW_PASSWORD}\n"),
        &[PASSWORD, NEW_PASSWORD],
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap()["changed"],
        true
    );
    assert!(!output.stdout.contains(PASSWORD) && !output.stdout.contains(NEW_PASSWORD));

    let output = run(&rekey_bin(), &["--state-dir", state, "lock"], None);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(output.status, 3, "stderr: {}", output.stderr);
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some(&format!("{NEW_PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

    // Recovery rotation requires the current password and prints only the new
    // recovery material, exactly once.
    let output = run_with_process_boundary(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "recovery",
            "rotate",
            "--password-stdin",
        ],
        &format!("{NEW_PASSWORD}\n"),
        &[NEW_PASSWORD],
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(!output.stdout.contains(NEW_PASSWORD));
    let new_recovery = output
        .stdout
        .lines()
        .find(|line| line.starts_with("RKREC1-"))
        .expect("rotated recovery key line")
        .to_owned();
    assert_eq!(
        output
            .stdout
            .lines()
            .filter(|line| line.starts_with("RKREC1-"))
            .count(),
        1
    );
    assert!(!output.stderr.contains(&new_recovery));

    let output = run(&rekey_bin(), &["--state-dir", state, "lock"], None);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "unlock",
            "--recovery",
            "--password-stdin",
        ],
        Some(&format!("{recovery_key}\n")),
    );
    assert_eq!(output.status, 3, "stderr: {}", output.stderr);
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "unlock",
            "--recovery",
            "--password-stdin",
        ],
        Some(&format!("{new_recovery}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

    // The rotated recovery key can replace a lost password.
    let output = run_with_process_boundary(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "password",
            "change",
            "--recovery",
            "--stdin-secrets",
        ],
        &format!("{new_recovery}\n{FINAL_PASSWORD}\n"),
        &[&new_recovery, FINAL_PASSWORD],
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(!output.stdout.contains(&new_recovery) && !output.stdout.contains(FINAL_PASSWORD));

    let output = run(&rekey_bin(), &["--state-dir", state, "lock"], None);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some(&format!("{NEW_PASSWORD}\n")),
    );
    assert_eq!(output.status, 3, "stderr: {}", output.stderr);
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "unlock", "--password-stdin"],
        Some(&format!("{FINAL_PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

    // shutdown with step-up proof (broker unlocked).
    let output = run(
        &rekey_bin(),
        &["--state-dir", state, "shutdown", "--password-stdin"],
        Some(&format!("{FINAL_PASSWORD}\n")),
    );
    assert_eq!(output.status, 0, "{}", output.stderr);

    let serve_output = guard.finish();
    assert!(serve_output.status.success());
    let canaries = [
        PASSWORD,
        NEW_PASSWORD,
        FINAL_PASSWORD,
        recovery_key.as_str(),
        new_recovery.as_str(),
    ];
    for canary in canaries {
        assert!(
            !serve_output
                .stdout
                .windows(canary.len())
                .any(|part| part == canary.as_bytes())
        );
        assert!(
            !serve_output
                .stderr
                .windows(canary.len())
                .any(|part| part == canary.as_bytes())
        );
    }
    assert_files_exclude(&state_dir, &canaries);

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
    let _restored_guard = ServeGuard(Some(child));
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
