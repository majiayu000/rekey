#![cfg(target_os = "macos")]

//! Opt-in test of the real CLI before it can send an unlock proof.
//! The coordinator supplies pre-signed artifacts; this test never signs code:
//! REKEY_PEER_TEST_CLIENT: trusted signed rekey CLI
//! REKEY_PEER_TEST_WRONG_SERVER: peer_probe signed by the same team, wrong ID
//! REKEY_PEER_TEST_ADHOC_SERVER: ad-hoc peer_probe
//! Run: cargo test -p rekey-cli --test macos_peer_identity -- --ignored

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Running(Child);
impl Running {
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.0.try_wait().expect("child status") {
                return status;
            }
            assert!(Instant::now() < deadline, "peer test child timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
#[ignore = "requires coordinator-provided signed CLI and wrong-ID/ad-hoc peer_probe controls"]
fn signed_cli_rejects_wrong_and_adhoc_before_proof() {
    let cli = std::env::var_os("REKEY_PEER_TEST_CLIENT").expect("signed CLI artifact path");
    for variable in [
        "REKEY_PEER_TEST_WRONG_SERVER",
        "REKEY_PEER_TEST_ADHOC_SERVER",
    ] {
        let server_path = std::env::var_os(variable).expect("peer_probe control artifact path");
        // Keep sockaddr_un paths short even when the host TMPDIR is deeply nested.
        let state = tempfile::Builder::new()
            .prefix("rk-peer-")
            .tempdir_in("/tmp")
            .unwrap();
        let runtime = state.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("admin.sock");
        let mut server = Running(
            Command::new(server_path)
                .args(["server", "--socket"])
                .arg(&socket)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        // peer_probe itself has a 15-second deadline, including accept/read.
        let mut output = BufReader::new(server.0.stdout.take().unwrap());
        let mut ready = String::new();
        output.read_line(&mut ready).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&ready).unwrap()["event"],
            "ready"
        );
        // Reach signature validation through the same owner-only socket boundary
        // as rekeyd; a same-uid counterfeit can also set these permissions.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut client = Running(
            Command::new(&cli)
                .arg("--state-dir")
                .arg(state.path())
                .args(["unlock", "--password-stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        // This is intentionally public synthetic data, not a real credential.
        client
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(b"REKEY_SYNTHETIC_PEER_PROOF_ONLY\n")
            .unwrap();
        assert_eq!(
            client.wait().code(),
            Some(7),
            "existing IPC_UNAVAILABLE exit contract"
        );
        let mut errors = String::new();
        client
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        assert!(
            errors.contains("peer SecCode"),
            "must reach peer identity rejection: {errors}"
        );
        assert!(server.wait().success());
        let mut observation = String::new();
        output.read_to_string(&mut observation).unwrap();
        let observation: serde_json::Value = serde_json::from_str(&observation).unwrap();
        assert_eq!(observation["outcome"], "observed");
        assert_eq!(observation["eof"], true);
        assert_eq!(
            observation["received_bytes"], 0,
            "{variable}: no header, metadata, or proof may be sent"
        );
    }
}
