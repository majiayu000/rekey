//! Typed source commands remain a pure IPC client and use protected files/stdin.
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PASSWORD: &str = "gcp-cli-fixture-proof";
const TOKEN: &str = "gcp-cli-fixture-bootstrap-secret";
fn run(args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rekey"))
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    for secret in [TOKEN, PASSWORD] {
        assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
    }
    out
}
fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn profile() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    serde_json::to_vec(&serde_json::json!({"credential_type":"gcp-secret-manager-source-v1","origin":"https://secretmanager.googleapis.com","secret_version":"projects/123456/secrets/fixture_key/versions/7","access_token":TOKEN,"access_token_expires_at_ms":now+3_500_000})).unwrap()
}
#[test]
fn protected_file_and_cli_surface_reject_unsafe_inputs_before_ipc() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("profile.json");
    let link = dir.path().join("link.json");
    let f = file.to_str().unwrap();
    let l = link.to_str().unwrap();
    private(&file, &profile());
    symlink(&file, &link).unwrap();
    let state = dir.path().join("absent");
    let state = state.to_str().unwrap();
    let args = |path| {
        vec![
            "--state-dir",
            state,
            "credential",
            "add-gcp-secret-manager",
            "fixture",
            "--file",
            path,
            "--password-stdin",
        ]
    };
    assert!(!run(&args(l), Some("fixture-proof\n")).status.success());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(!run(&args(f), Some("fixture-proof\n")).status.success());
    private(
        &file,
        b"{\"credential_type\":\"wrong\",\"access_token\":\"gcp-cli-fixture-bootstrap-secret\"}",
    );
    assert!(!run(&args(f), Some("fixture-proof\n")).status.success());
    private(&file, &vec![b'x'; 65537]);
    assert!(!run(&args(f), Some("fixture-proof\n")).status.success());
    private(&file, &profile());
    let unsafe_argument = run(
        &[
            "credential",
            "add-gcp-secret-manager",
            "fixture",
            "--access-token",
            "synthetic-argv-rejection",
        ],
        None,
    );
    assert!(!unsafe_argument.status.success());
    for command in ["add-gcp-secret-manager", "rotate-gcp-secret-manager"] {
        assert!(
            run(&["credential", command, "--help"], None)
                .status
                .success()
        );
    }
}
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn real_cli_typed_add_rotate_step_up_and_no_credential_process_or_output_leak() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state");
    let state = state_path.to_str().unwrap();
    let bin = Path::new(env!("CARGO_BIN_EXE_rekey"));
    let daemon_bin = bin.parent().unwrap().join("rekeyd");
    assert!(daemon_bin.is_file(), "build workspace binaries first");
    let mut init = Command::new(&daemon_bin)
        .args(["init", "--state-dir", state, "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    init.stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let initialized = init.wait_with_output().unwrap();
    assert!(initialized.status.success(), "fixture init failed");
    let mut daemon = Daemon(
        Command::new(&daemon_bin)
            .args(["serve", "--state-dir", state])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let socket = state_path.join("runtime/admin.sock");
    for _ in 0..300 {
        if socket.exists() {
            break;
        }
        if daemon.0.try_wait().unwrap().is_some() {
            panic!("strict broker listener failed to start");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "strict real UDS listener");
    assert!(
        run(
            &["--state-dir", state, "unlock", "--password-stdin"],
            Some(&format!("{PASSWORD}\n"))
        )
        .status
        .success()
    );
    let file = dir.path().join("profile.json");
    private(&file, &profile());
    let f = file.to_str().unwrap();
    let args = [
        "--state-dir",
        state,
        "credential",
        "add-gcp-secret-manager",
        "fixture",
        "--file",
        f,
        "--password-stdin",
    ];
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let process = Command::new("ps")
        .args(["-eww", "-o", "command=", "-p", &child.id().to_string()])
        .output()
        .unwrap();
    assert!(process.status.success());
    for secret in [PASSWORD, TOKEN] {
        assert!(!String::from_utf8_lossy(&process.stdout).contains(secret));
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let added = child.wait_with_output().unwrap();
    assert!(added.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&added.stdout).unwrap();
    assert_eq!(metadata["kind"], "gcp-secret-manager-source");
    let id = metadata["id"].as_str().unwrap();
    for bytes in [&added.stdout, &added.stderr] {
        for secret in [PASSWORD, TOKEN] {
            assert!(!String::from_utf8_lossy(bytes).contains(secret));
        }
    }
    private(&file, &profile());
    let args = [
        "--state-dir",
        state,
        "credential",
        "rotate-gcp-secret-manager",
        id,
        "--file",
        f,
        "--password-stdin",
    ];
    let wrong = run(&args, Some("wrong-proof\n"));
    assert_eq!(wrong.status.code(), Some(3));
    let rotated = run(&args, Some(&format!("{PASSWORD}\n")));
    assert!(rotated.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&rotated.stdout).unwrap();
    assert_eq!(metadata["current_version"], 2);
    let generic = run(
        &[
            "--state-dir",
            state,
            "credential",
            "rotate",
            id,
            "--stdin-secrets",
        ],
        Some(&format!("{PASSWORD}\nraw-fixture-value\n")),
    );
    assert!(!generic.status.success());
    fn exclude(path: &Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            let p = entry.path();
            if kind.is_socket() {
                continue; // Runtime IPC sockets do not contain persisted bytes.
            }
            assert!(
                kind.is_dir() || kind.is_file(),
                "unexpected vault entry type"
            );
            if kind.is_dir() {
                exclude(&p)
            } else {
                let bytes = std::fs::read(p).unwrap();
                for secret in [TOKEN, PASSWORD] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
                }
            }
        }
    }
    exclude(&state_path);
    assert!(
        run(
            &["--state-dir", state, "shutdown", "--password-stdin"],
            Some(&format!("{PASSWORD}\n"))
        )
        .status
        .success()
    );
    let exited = daemon.0.wait().unwrap();
    assert!(exited.success());
}
