//! Process-level blackbox for two public status contracts: `rekey status`
//! reports `protection_level` apart from the `peer_security` identity label,
//! and saving a credential shorter than 16 bytes warns without failing.
//! Real `rekeyd` and `rekey`; secrets only via stdin. Build the workspace
//! binaries first (`cargo build --workspace`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "status labels horse battery staple";

fn rekey_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rekey"))
}

fn rekeyd_bin() -> PathBuf {
    let sibling = rekey_bin().parent().unwrap().join("rekeyd");
    assert!(
        sibling.exists(),
        "build rekeyd first: cargo build --workspace"
    );
    sibling
}

struct Output {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(state: &Path, args: &[&str], stdin: &str, human: bool) -> Output {
    let mut command = Command::new(rekey_bin());
    command
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .env("REKEY_OUTPUT", if human { "human" } else { "json" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let output = Output {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    assert!(
        !output.stdout.contains(PASSWORD) && !output.stderr.contains(PASSWORD),
        "password reached public output"
    );
    output
}

fn status(state: &Path) -> serde_json::Value {
    let output = run(state, &["status"], "", false);
    assert_eq!(output.status, 0, "{}", output.stderr);
    serde_json::from_str(&output.stdout).unwrap()
}

fn warnings(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|line| line["warnings"].as_array().cloned())
        .flatten()
        .filter_map(|code| code.as_str().map(str::to_owned))
        .collect()
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn status_level_is_separate_from_identity_and_short_keys_warn() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let init = Command::new(rekeyd_bin())
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
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{PASSWORD}\n").as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(init.status.success(), "{init:?}");
    let reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    std::fs::write(state.join("service.json"), format!("{{\"port\":{port}}}")).unwrap();
    let mut daemon = Daemon(
        Command::new(rekeyd_bin())
            .args(["serve", "--state-dir"])
            .arg(&state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while run(&state, &["status", "--passive"], "", false).status != 0 {
        assert!(daemon.0.try_wait().unwrap().is_none(), "rekeyd exited");
        assert!(Instant::now() < deadline, "rekeyd did not start");
        std::thread::sleep(Duration::from_millis(50));
    }

    let locked = status(&state);
    assert_eq!(locked["state"], "locked");
    assert_eq!(locked["sessions_active"], 0);
    assert_eq!(locked["protection_level"], "L0");
    // An unsigned test build cannot verify the service signature; the label
    // names identity only and never borrows a protection-level name.
    assert_eq!(locked["peer_security"], "unverified");

    let unlock = run(
        &state,
        &["unlock", "--password-stdin"],
        &format!("{PASSWORD}\n"),
        false,
    );
    assert_eq!(unlock.status, 0, "{}", unlock.stderr);
    let unlocked = status(&state);
    assert_eq!(unlocked["state"], "unlocked");
    assert_eq!(unlocked["protection_level"], "L1-dev");
    assert_eq!(unlocked["peer_security"], "unverified");

    let add = |label: &str, secret: &str, human: bool| {
        let output = run(
            &state,
            &["credential", "add", label, "--stdin-secrets"],
            &format!("{PASSWORD}\n{secret}\n"),
            human,
        );
        assert_eq!(output.status, 0, "{}", output.stderr);
        assert!(!output.stdout.contains(secret) && !output.stderr.contains(secret));
        let saved: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(saved["label"], label);
        output
    };
    let short = add("short-key", "short-canary", false);
    assert!(
        warnings(&short.stderr).contains(&"SHORT_CREDENTIAL".to_owned()),
        "{}",
        short.stderr
    );
    let complete = add("complete-key", "complete-synthetic-canary-0001", false);
    assert!(!warnings(&complete.stderr).contains(&"SHORT_CREDENTIAL".to_owned()));
    let human = add("short-human", "tiny-canary", true);
    assert!(
        human.stderr.contains("shorter than 16 bytes"),
        "{}",
        human.stderr
    );

    let lock = run(&state, &["lock"], "", false);
    assert_eq!(lock.status, 0, "{}", lock.stderr);
    assert_eq!(status(&state)["protection_level"], "L0");
    let stop = run(
        &state,
        &["shutdown", "--password-stdin"],
        &format!("{PASSWORD}\n"),
        false,
    );
    assert_eq!(stop.status, 0, "{}", stop.stderr);
    let deadline = Instant::now() + Duration::from_secs(60);
    while daemon.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "rekeyd did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }
}
