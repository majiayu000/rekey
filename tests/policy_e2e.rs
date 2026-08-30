//! The P1 authorization acceptance is intentionally a process test. Unit
//! evaluators and FakeTransport cannot stand in for release binaries, UDS,
//! SQLite audit durability, or the local CA/TLS hop.

use std::process::Command;

#[test]
fn release_process_policy_acceptance() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("p1-policy-acceptance.sh");
    let status = Command::new(&script)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run P1 policy acceptance script");
    assert!(status.success(), "P1 policy acceptance failed: {status}");
}
