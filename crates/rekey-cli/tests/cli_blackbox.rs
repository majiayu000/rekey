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
        &[
            "init",
            "--mode",
            "team",
            "--state-dir",
            state,
            "--password-stdin",
        ],
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
        &[
            "init",
            "--mode",
            "team",
            "--state-dir",
            state,
            "--password-stdin",
        ],
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

    // DEK rotation reads step-up only from stdin, returns counts only, and
    // accepts both existing unlock factors without changing credential data.
    let rotate_args = [
        "--state-dir",
        state,
        "key",
        "rotate-dek",
        "--password-stdin",
    ];
    let denied = run(&rekey_bin(), &rotate_args, Some("wrong-dek-proof\n"));
    assert_eq!(denied.status, 3);
    assert!(!denied.stderr.contains("wrong-dek-proof"));
    let rotated = run_with_process_boundary(
        &rekey_bin(),
        &rotate_args,
        &format!("{PASSWORD}\n"),
        &[PASSWORD, SECRET],
    );
    assert_eq!(rotated.status, 0, "{}", rotated.stderr);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&rotated.stdout).unwrap(),
        serde_json::json!({"rotated_versions": 1})
    );
    let recovered = run_with_process_boundary(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "key",
            "rotate-dek",
            "--recovery",
            "--password-stdin",
        ],
        &format!("{recovery_key}\n"),
        &[&recovery_key, SECRET],
    );
    assert_eq!(recovered.status, 0, "{}", recovered.stderr);
    for output in [&rotated, &recovered] {
        for canary in [PASSWORD, SECRET, recovery_key.as_str()] {
            assert!(!output.stdout.contains(canary));
            assert!(!output.stderr.contains(canary));
        }
    }

    assert_files_exclude(&state_dir, &[PASSWORD, SECRET, recovery_key.as_str()]);

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
        "rekey.audit.export.v2"
    );
    assert_eq!(
        lines.last().unwrap()["record_type"],
        "rekey.audit.export.complete.v2"
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

#[test]
fn agent_run_rejects_the_default_colocated_socket() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let output = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state_dir.to_str().unwrap(),
            "agent-run",
            "--",
            "/bin/echo",
            "blocked",
        ],
        None,
    );
    assert_eq!(output.status, 2, "stderr: {}", output.stderr);
    assert!(
        output.stderr.contains("disjoint")
            || output.stderr.contains("INVALID_INPUT")
            || output.stderr.contains("invalid launch plan"),
        "stderr: {}",
        output.stderr
    );
    assert!(!output.stdout.contains("blocked"));
}

#[test]
fn cli_vrk_rotation_two_stdin_factors_keep_broker_locked_and_leave_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let state = state_dir.to_str().unwrap();
    let initialized = run(
        &rekeyd_bin(),
        &[
            "init",
            "--mode",
            "team",
            "--state-dir",
            state,
            "--password-stdin",
        ],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(initialized.status, 0, "{}", initialized.stderr);
    let recovery = initialized
        .stdout
        .lines()
        .find(|l| l.starts_with("RKREC1-"))
        .unwrap()
        .to_owned();
    let child = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", state, "--idle-lock", "15m"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let guard = ServeGuard(Some(child));
    for _ in 0..300 {
        if state_dir.join("runtime/admin.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(state_dir.join("runtime/admin.sock").exists());
    let mut outputs = Vec::new();
    let rotated = run_with_process_boundary(
        &rekey_bin(),
        &["--state-dir", state, "key", "rotate-vrk", "--stdin-secrets"],
        &format!("{PASSWORD}\n{recovery}\n"),
        &[PASSWORD, &recovery],
    );
    assert_eq!(rotated.status, 0, "{}", rotated.stderr);
    let receipt: rekey_domain::ipc::VrkRotatedResponse =
        serde_json::from_str(&rotated.stdout).unwrap();
    receipt.validate().unwrap();
    assert_eq!(receipt.rotated_versions, 0);
    outputs.push(rotated);
    let status = run(&rekey_bin(), &["--state-dir", state, "status"], None);
    assert_eq!(status.status, 0);
    assert!(status.stdout.contains("locked"));
    outputs.push(status);
    for (flag, factor) in [
        ("--password-stdin", PASSWORD),
        ("--recovery", recovery.as_str()),
    ] {
        let mut args = vec!["--state-dir", state, "unlock", flag];
        if flag == "--recovery" {
            args.push("--password-stdin");
        }
        let unlock = run(&rekey_bin(), &args, Some(&format!("{factor}\n")));
        assert_eq!(unlock.status, 0, "{}", unlock.stderr);
        outputs.push(unlock);
        let origin = run(
            &rekey_bin(),
            &["--state-dir", state, "approval", "origin"],
            None,
        );
        assert_eq!(origin.status, 0, "{}", origin.stderr);
        assert!(origin.stdout.contains(&receipt.approval_origin.public_key));
        outputs.push(origin);
        let lock = run(&rekey_bin(), &["--state-dir", state, "lock"], None);
        assert_eq!(lock.status, 0);
        outputs.push(lock);
    }
    let stopped = run(
        &rekey_bin(),
        &["--state-dir", state, "shutdown", "--password-stdin"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(stopped.status, 0, "{}", stopped.stderr);
    outputs.push(stopped);
    let server = guard.finish();
    assert!(server.status.success());
    for output in outputs {
        for canary in [PASSWORD, recovery.as_str()] {
            assert!(!output.stdout.contains(canary));
            assert!(!output.stderr.contains(canary));
        }
    }
    for bytes in [&server.stdout, &server.stderr] {
        for canary in [PASSWORD, recovery.as_str()] {
            assert!(!bytes.windows(canary.len()).any(|w| w == canary.as_bytes()));
        }
    }
    assert_files_exclude(&state_dir, &[PASSWORD, &recovery]);
}

#[test]
fn desktop_reveal_and_locked_shutdown_require_each_step_up() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let state = state_dir.to_str().unwrap();
    let init = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "init",
            "--mode",
            "personal",
            "--password-stdin",
        ],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(init.status, 0, "{}", init.stderr);
    let recovery = init
        .stdout
        .lines()
        .find(|line| line.starts_with("RKREC1-"))
        .unwrap();
    let server = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", state])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let guard = ServeGuard(Some(server));
    for _ in 0..300 {
        if state_dir.join("runtime/admin.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let login = run(
        &rekey_bin(),
        &["--state-dir", state, "desktop-login"],
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(login.status, 0, "{}", login.stderr);
    let personal_status = run(
        &rekey_bin(),
        &["--state-dir", state, "policy", "status"],
        None,
    );
    assert_eq!(personal_status.status, 0, "{}", personal_status.stderr);
    let personal: rekey_domain::ipc::PolicyStatusResponse =
        serde_json::from_str(&personal_status.stdout).unwrap();
    personal.validate().unwrap();
    assert_eq!(
        personal.mode,
        Some(rekey_domain::authorization::PolicyMode::Personal)
    );
    assert!(personal.algorithm.is_none());
    let token = login.stdout;
    let added = run(
        &rekey_bin(),
        &["--state-dir", state, "desktop-add", "step-up-canary"],
        Some(&format!("{token}\n{SECRET}\n")),
    );
    assert_eq!(added.status, 0, "{}", added.stderr);
    let metadata: serde_json::Value = serde_json::from_str(&added.stdout).unwrap();
    let id = metadata["id"].as_str().unwrap();
    for (factor, recovery_factor) in [(PASSWORD, false), (recovery, true)] {
        let mut args = vec![
            "--state-dir",
            state,
            "desktop-reveal",
            id,
            "--password-stdin",
        ];
        if recovery_factor {
            args.push("--recovery");
        }
        let revealed = run(&rekey_bin(), &args, Some(&format!("{factor}\n")));
        assert_eq!(revealed.status, 0, "{}", revealed.stderr);
        assert_eq!(revealed.stdout, SECRET);
        assert!(!revealed.stderr.contains(SECRET));
        let denied = run(
            &rekey_bin(),
            &[
                "--state-dir",
                state,
                "desktop-reveal",
                id,
                "--password-stdin",
            ],
            Some(&format!("{token}\n")),
        );
        assert_ne!(denied.status, 0);
        assert!(denied.stdout.is_empty());
        assert!(!denied.stderr.contains(SECRET));
        assert!(!denied.stderr.contains(&token));
    }
    assert_eq!(
        run(&rekey_bin(), &["--state-dir", state, "lock"], None).status,
        0
    );
    for input in ["\n", "incorrect-proof\n"] {
        let denied = run(
            &rekey_bin(),
            &["--state-dir", state, "shutdown", "--password-stdin"],
            Some(input),
        );
        assert_ne!(denied.status, 0);
        assert!(denied.stdout.is_empty());
        let status = run(&rekey_bin(), &["--state-dir", state, "status"], None);
        assert_eq!(status.status, 0);
        assert!(status.stdout.contains("locked"));
    }
    let stopped = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "shutdown",
            "--password-stdin",
            "--recovery",
        ],
        Some(&format!("{recovery}\n")),
    );
    assert_eq!(stopped.status, 0, "{}", stopped.stderr);
    assert!(guard.finish().status.success());
}

#[test]
fn template_cli_installs_bound_actions_atomically_without_exposing_proof() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let state = state_dir.to_str().unwrap();
    let proof = format!("{PASSWORD}\n");
    let initialized = run(
        &rekeyd_bin(),
        &[
            "init",
            "--mode",
            "team",
            "--state-dir",
            state,
            "--password-stdin",
        ],
        Some(&proof),
    );
    assert_eq!(initialized.status, 0, "{}", initialized.stderr);
    let server = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", state])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let guard = ServeGuard(Some(server));
    for _ in 0..300 {
        if state_dir.join("runtime/admin.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let call = |args: &[&str], input: Option<&str>| {
        let mut all = vec!["--state-dir", state];
        all.extend_from_slice(args);
        let result = run(&rekey_bin(), &all, input);
        for canary in [PASSWORD, SECRET] {
            assert!(!result.stdout.contains(canary));
            assert!(!result.stderr.contains(canary));
        }
        result
    };
    assert_eq!(
        call(&["unlock", "--password-stdin"], Some(&proof)).status,
        0
    );
    let catalog = call(&["template", "catalog", "--builtin", "github-pat"], None);
    assert_eq!(catalog.status, 0, "{}", catalog.stderr);
    let catalog: serde_json::Value = serde_json::from_str(&catalog.stdout).unwrap();
    assert_eq!(catalog["template"]["template"], "github-pat@1");
    assert!(catalog["signer_id"].is_null());
    // A synthetic public Ed25519 key exercises the same anonymous trust input
    // used by the app; the daemon's origin key is never used to sign policy here.
    let origin = call(&["approval", "origin"], None);
    assert_eq!(origin.status, 0, "{}", origin.stderr);
    let origin: serde_json::Value = serde_json::from_str(&origin.stdout).unwrap();
    let trust = serde_json::json!({"format_version": 1,
        "signer_id": rekey_domain::ids::PolicySignerId::new_random(),
        "algorithm": "ed25519", "public_key": origin["public_key"]});
    let installed_trust = call(
        &[
            "policy",
            "trust",
            "install",
            "--stdin-request",
            "--step-up-stdin",
        ],
        Some(&format!("{proof}{trust}\n")),
    );
    assert_eq!(installed_trust.status, 0, "{}", installed_trust.stderr);
    let trust_status: rekey_domain::ipc::PolicyStatusResponse =
        serde_json::from_str(&installed_trust.stdout).unwrap();
    trust_status.validate().unwrap();
    assert_eq!(
        trust_status.mode,
        Some(rekey_domain::authorization::PolicyMode::Team)
    );
    assert_eq!(
        trust_status.algorithm,
        Some(rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519)
    );
    let added = call(
        &["credential", "add", "template key", "--stdin-secrets"],
        Some(&format!("{PASSWORD}\n{SECRET}\n")),
    );
    assert_eq!(added.status, 0, "{}", added.stderr);
    let credential: serde_json::Value = serde_json::from_str(&added.stdout).unwrap();
    let request_file = dir.path().join("install.json");
    let mut request = serde_json::json!({
        "source": {"kind": "github-pat"}, "credential_id": credential["id"],
        "bindings": [{"owner": "example", "repo": "one"}, {"owner": "example", "repo": "two"}],
        "capabilities": ["read-repo", "create-issue"], "name_prefix": "CLI template",
        "timeout_ms": 30000, "request_max_bytes": 65536, "allowed_extra_headers": [],
        "response_max_bytes": 262144, "allowed_response_headers": ["content-type"]
    });
    std::fs::write(&request_file, serde_json::to_vec(&request).unwrap()).unwrap();
    let args = [
        "template",
        "install",
        "--file",
        request_file.to_str().unwrap(),
        "--password-stdin",
    ];
    let denied = call(&args, Some("incorrect proof\n"));
    assert_eq!(denied.status, 3);
    let empty = call(&["action", "list"], None);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&empty.stdout).unwrap()["actions"],
        serde_json::json!([])
    );
    let snapshot = format!("{proof}{request}\n");
    let stdin_args = ["template", "install", "--stdin-request", "--password-stdin"];
    // Once captured for stdin, a changed request file cannot replace the scope.
    std::fs::write(&request_file, b"{}").unwrap();
    let installed = call(&stdin_args, Some(&snapshot));
    assert_eq!(installed.status, 0, "{}", installed.stderr);
    let result: serde_json::Value = serde_json::from_str(&installed.stdout).unwrap();
    let actions = result["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 16);
    assert_ne!(
        call(&["template", "install", "--stdin-request"], None).status,
        0
    );
    assert_ne!(
        call(
            &[
                "template",
                "install",
                "--stdin-request",
                "--file",
                request_file.to_str().unwrap(),
                "--password-stdin"
            ],
            Some(&snapshot)
        )
        .status,
        0
    );
    assert_ne!(call(&stdin_args, Some(&proof)).status, 0);
    assert_ne!(
        call(
            &stdin_args,
            Some(&format!("{proof}{}\n", "x".repeat(65_537)))
        )
        .status,
        0
    );
    let mut ids = std::collections::BTreeSet::new();
    for item in actions {
        let action = &item["action"];
        assert!(ids.insert(action["id"].as_str().unwrap()));
        assert_eq!(action["version"], 1);
        assert_eq!(action["target"]["kind"], "template");
        assert_eq!(action["target"]["source"]["template"], "github-pat@1");
        let repository = if item["binding_index"] == 0 {
            "one"
        } else {
            "two"
        };
        assert!(
            action["target"]["target"]["path"]
                .as_str()
                .unwrap()
                .starts_with(&format!("/repos/example/{repository}"))
        );
    }
    request["bindings"][1]["repo"] = serde_json::json!("bad/path");
    std::fs::write(&request_file, serde_json::to_vec(&request).unwrap()).unwrap();
    assert_ne!(call(&args, Some(&proof)).status, 0);
    let unchanged = call(&["action", "list"], None);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&unchanged.stdout).unwrap()["actions"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
    assert_eq!(
        call(&["shutdown", "--password-stdin"], Some(&proof)).status,
        0
    );
    assert!(guard.finish().status.success());
}

#[test]
fn personal_policy_draft_sign_and_activate_over_anonymous_stdin() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
    use serde_json::{Value, json};

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("personal");
    let state = state_dir.to_str().unwrap();
    let proof = format!("{PASSWORD}\n");
    let initialized = run(
        &rekey_bin(),
        &[
            "--state-dir",
            state,
            "init",
            "--mode",
            "personal",
            "--password-stdin",
        ],
        Some(&proof),
    );
    assert_eq!(initialized.status, 0, "{}", initialized.stderr);
    let server = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", state])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let guard = ServeGuard(Some(server));
    for _ in 0..300 {
        if state_dir.join("runtime/admin.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let call = |args: &[&str], input: Option<&str>| {
        let mut all = vec!["--state-dir", state];
        all.extend_from_slice(args);
        let result = run(&rekey_bin(), &all, input);
        for canary in [PASSWORD, SECRET] {
            assert!(!result.stdout.contains(canary));
            assert!(!result.stderr.contains(canary));
        }
        result
    };
    let success = |output: Output| -> Value {
        assert_eq!(output.status, 0, "{}", output.stderr);
        serde_json::from_str(&output.stdout).unwrap()
    };
    assert_eq!(
        call(&["unlock", "--password-stdin"], Some(&proof)).status,
        0
    );
    // Real signature/verification, but a software test key: not evidence of SE provenance.
    let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key.as_ref()).unwrap();
    let trust = json!({"format_version":1,"signer_id":rekey_domain::ids::PolicySignerId::new_random(),
        "algorithm":"secure-enclave-p256","public_key":HEXLOWER.encode(key.public_key().as_ref())});
    let status = success(call(
        &[
            "policy",
            "trust",
            "install",
            "--stdin-request",
            "--step-up-stdin",
        ],
        Some(&format!("{proof}{trust}\n")),
    ));
    let vault = status["vault_id"].as_str().unwrap();
    let trust_digest = status["trust_sha256"].as_str().unwrap();
    let credential = success(call(
        &["credential", "add", "personal fixture", "--stdin-secrets"],
        Some(&format!("{proof}{SECRET}\n")),
    ));
    let install = json!({"source":{"kind":"openai"},"credential_id":credential["id"],"bindings":[{}],
        "capabilities":["models"],"name_prefix":"Personal model list","timeout_ms":30000,
        "request_max_bytes":65536,"allowed_extra_headers":[],"response_max_bytes":262144,"allowed_response_headers":["content-type"]});
    let installed = success(call(
        &["template", "install", "--stdin-request", "--password-stdin"],
        Some(&format!("{proof}{install}\n")),
    ));
    let action = &installed["actions"][0]["action"];
    let action_ref = format!(
        "{}@{}",
        action["id"].as_str().unwrap(),
        action["version"].as_u64().unwrap()
    );
    let principal = rekey_domain::ids::PrincipalId::new_random().to_string();
    let expires = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        + 600_000) as i64;
    let expires = expires.to_string();
    let draft = |selected: bool| {
        let mut args = vec![
            "policy",
            "draft",
            "--principal",
            &principal,
            "--expires-at-ms",
            &expires,
        ];
        if selected {
            args.extend(["--action", &action_ref]);
        }
        success(call(&args, None))
    };
    let sign = |draft: &Value| {
        let bytes = draft["sign_bytes"].as_str().unwrap().as_bytes();
        assert!(bytes.starts_with(b"RKPOLICY\0\x01"));
        let mut unsigned: Value = serde_json::from_slice(&bytes[10..]).unwrap();
        assert_eq!(&bytes[10..], serde_jcs::to_vec(&unsigned).unwrap());
        let changes = draft["metadata"]["changes"].as_array().unwrap();
        for change in changes {
            assert_eq!(
                change["after"],
                unsigned["snapshot"][change["field"].as_str().unwrap()]
            );
        }
        let signature = key.sign(&SystemRandom::new(), bytes).unwrap();
        unsigned["signature"] = BASE64URL_NOPAD.encode(signature.as_ref()).into();
        unsigned.to_string()
    };
    let activate = |bundle: &str| {
        call(
            &[
                "policy",
                "activate",
                "--stdin-request",
                "--expected-vault-id",
                vault,
                "--expected-trust-sha256",
                trust_digest,
                "--step-up-stdin",
            ],
            Some(&format!("{proof}{bundle}\n")),
        )
    };
    let first = draft(true);
    assert_eq!(first["metadata"]["base_version"], Value::Null);
    assert_eq!(first["metadata"]["next_version"], 1);
    assert_eq!(first["metadata"]["actions"].as_array().unwrap().len(), 1);
    let first_bundle = sign(&first);
    assert_eq!(success(activate(&first_bundle))["version"], 1);
    // Exact same signed bytes are idempotent; no ECDSA resign/retry required.
    assert_eq!(success(activate(&first_bundle))["version"], 1);
    let stale = sign(&draft(false));
    let second = sign(&draft(true));
    assert_eq!(success(activate(&second))["version"], 2);
    let rejected = activate(&stale);
    assert_ne!(rejected.status, 0);
    assert!(rejected.stderr.contains("POLICY_VERSION_CONFLICT"));
    let retired_draft = sign(&draft(true));
    success(call(
        &[
            "action",
            "disable",
            action["id"].as_str().unwrap(),
            "--password-stdin",
        ],
        Some(&proof),
    ));
    assert_ne!(activate(&retired_draft).status, 0);
    assert_eq!(success(call(&["policy", "status"], None))["version"], 2);
    let empty = draft(false);
    assert!(empty["metadata"]["actions"].as_array().unwrap().is_empty());
    let revoke_bundle = sign(&empty);
    let revoke: Value = serde_json::from_str(&revoke_bundle).unwrap();
    assert_eq!(revoke["snapshot"]["rules"], json!([]));
    assert_eq!(success(activate(&revoke_bundle))["version"], 3);
    let audit = call(&["audit", "list"], None);
    assert_eq!(audit.status, 0);
    assert_eq!(
        call(&["shutdown", "--password-stdin"], Some(&proof)).status,
        0
    );
    drop(guard);
}
