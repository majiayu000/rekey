//! Remembered-unlock help must say how the one shared ticket is replaced and
//! revoked. Runs the real CLI binary's `--help`; no broker, vault or network.

use std::process::Command;

/// Help text with whitespace collapsed, so wrapping cannot split a phrase.
fn help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success(), "rekey {args:?} --help failed");
    let text = String::from_utf8(output.stdout).unwrap();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn remembered_unlock_help_states_replacement_and_revocation() {
    let lock = help(&["lock"]);
    assert!(
        lock.contains("forget any remembered unlock (App or CLI)"),
        "{lock}"
    );
    assert!(
        lock.contains("the lock alone keeps restarts locked"),
        "{lock}"
    );

    let unlock = help(&["unlock"]);
    assert!(
        unlock.contains("Replaces an App remembered unlock"),
        "{unlock}"
    );
    assert!(unlock.contains("full or idle locks forget it"), "{unlock}");

    let remember = help(&["desktop-remember"]);
    assert!(
        remember.contains("replaces any App/CLI remembered unlock"),
        "{remember}"
    );
    assert!(remember.contains("--presence Always refused"), "{remember}");
}
