//! `rekey unlock --remember` bounds the lifetime to 1s..=30d before any
//! password is read or sent. Real `rekeyd` and `rekey` binaries, tempdir
//! state, synthetic password on stdin only.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

const PASSWORD: &str = "remember horse battery staple";

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

struct Serve(Child);

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn rekey(state: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(rekey_bin())
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .env("REKEY_OUTPUT", "json")
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
        // A usage error may exit before stdin is read.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    }
    child.wait_with_output().unwrap()
}

fn state_of(state: &Path) -> String {
    let output = rekey(state, &["status"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    status["state"].as_str().unwrap().to_owned()
}

#[test]
fn out_of_range_remember_is_a_usage_error_and_never_unlocks() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let mut init = Command::new(rekeyd_bin())
        .args([
            "init",
            "--mode",
            "personal",
            "--password-stdin",
            "--state-dir",
        ])
        .arg(&state)
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
    let init = init.wait_with_output().unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    // Keep the loopback service off any fixed port.
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    std::fs::write(
        state.join("service.json"),
        serde_json::to_vec(&serde_json::json!({ "port": port })).unwrap(),
    )
    .unwrap();
    drop(reservation);
    let _serve = Serve(
        Command::new(rekeyd_bin())
            .arg("serve")
            .arg("--state-dir")
            .arg(&state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..500 {
        if state.join("runtime/admin.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(state_of(&state), "locked");
    let password = format!("{PASSWORD}\n");
    for remember in ["31d", "0s", "2592001s", "721h"] {
        let output = rekey(
            &state,
            &["unlock", "--password-stdin", "--remember", remember],
            Some(&password),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{remember}: {stderr}");
        assert!(output.stdout.is_empty(), "{remember}: unlock reply printed");
        let envelope: serde_json::Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|error| panic!("{remember}: {error}: {stderr}"));
        assert_eq!(envelope["code"], "USAGE", "{remember}: {stderr}");
        assert!(
            envelope["message"].as_str().unwrap().contains("--remember"),
            "{stderr}"
        );
        assert_eq!(state_of(&state), "locked", "{remember} unlocked the vault");
        assert!(!state.join("remembered-unlock.key").exists());
    }
    // The inclusive upper bound still unlocks and remembers.
    let output = rekey(
        &state,
        &["unlock", "--password-stdin", "--remember", "30d"],
        Some(&password),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(state_of(&state), "unlocked");
    assert!(state.join("remembered-unlock.key").exists());
    let forgotten = rekey(&state, &["lock", "--forget-remembered"], None);
    assert!(
        forgotten.status.success(),
        "{}",
        String::from_utf8_lossy(&forgotten.stderr)
    );
    assert!(!state.join("remembered-unlock.key").exists());
}
