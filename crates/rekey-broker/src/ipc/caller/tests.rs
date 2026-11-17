use super::*;

fn processes(pid: i32) -> Option<(String, i32)> {
    let (path, parent) = match pid {
        7 => ("/synthetic/rekey-mcp", 8),
        8 => ("/synthetic/claude", 1),
        9 => ("/synthetic/script", 7),
        20 => ("/usr/local/bin/rekey", 21),
        21 => ("/opt/homebrew/bin/python3", 22),
        22 => ("/bin/zsh", 1),
        30 => ("/opt/homebrew/bin/rekey-mcp", 31),
        31 => ("/opt/homebrew/bin/node", 1),
        40 => ("/opt/homebrew/bin/rekey-mcp", 41),
        41 => ("/Users/u/.local/share/claude/versions/2.1.326", 22),
        50 => ("/usr/local/bin/rekey", 41),
        60 => ("/usr/local/bin/rekey", 1),
        70 => ("/usr/local/bin/rekey", 71),
        71 => ("/bin/sh", 72),
        72 => ("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", 1),
        _ => return None,
    };
    Some((path.into(), parent))
}

fn unsigned(_: i32, _: &str) -> Option<&'static str> {
    None
}

#[test]
fn untrusted_mcp_cannot_borrow_its_agent_parents_label() {
    let mut checked = Vec::new();
    assert_eq!(
        caller_from_processes(7, processes, unsigned, |pid| {
            checked.push(pid);
            false
        }),
        "script:rekey-mcp"
    );
    assert_eq!(checked, vec![7]);
    assert_eq!(
        caller_from_processes(7, processes, unsigned, |pid| pid == 7),
        "claude-code"
    );
}

#[test]
fn an_audit_token_for_a_child_does_not_attest_an_mcp_ancestor() {
    assert_eq!(
        caller_from_processes(9, processes, unsigned, |pid| pid == 9),
        "script:rekey-mcp"
    );
    // Linux keeps its existing best-effort process-chain attribution.
    assert_eq!(
        caller_from_processes(9, processes, unsigned, |_| true),
        "claude-code"
    );
    assert_eq!(
        caller_from_processes(10, processes, unsigned, |_| true),
        "unknown"
    );
}

#[test]
fn script_labels_name_the_first_program_that_is_not_rekey() {
    // python3 -> rekey CLI.
    assert_eq!(
        caller_from_processes(20, processes, unsigned, |_| true),
        "script:python3"
    );
    // node -> trusted rekey-mcp; an untrusted copy keeps its own name.
    assert_eq!(
        caller_from_processes(30, processes, unsigned, |_| true),
        "script:node"
    );
    assert_eq!(
        caller_from_processes(30, processes, unsigned, |_| false),
        "script:rekey-mcp"
    );
    // A chain of only Rekey's own binaries falls back to the peer's name.
    assert_eq!(
        caller_from_processes(60, processes, unsigned, |_| true),
        "script:rekey"
    );
}

#[test]
fn native_claude_code_is_matched_by_its_versioned_install_path() {
    // The native installer's executable is named after its version.
    assert_eq!(
        caller_from_processes(40, processes, unsigned, |_| true),
        "claude-code"
    );
    assert_eq!(
        caller_from_processes(50, processes, unsigned, |_| true),
        "claude-code"
    );
    assert_eq!(
        caller_from_processes(40, processes, unsigned, |_| false),
        "script:rekey-mcp"
    );
}

#[test]
fn signatures_label_agents_whose_path_is_not_in_the_table() {
    let mut queried = Vec::new();
    let label = caller_from_processes(
        70,
        processes,
        |pid, path| {
            queried.push(pid);
            (path == "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT").then_some("codex")
        },
        |_| true,
    );
    assert_eq!(label, "codex");
    // Rekey's own binaries are never signature candidates.
    assert_eq!(queried, vec![71, 72]);
    assert_eq!(
        caller_from_processes(70, processes, unsigned, |_| true),
        "script:sh"
    );
}

#[test]
fn script_labels_remain_valid_audit_callers() {
    let long = "x".repeat(300);
    for name in ["bad\nname\u{7}", long.as_str(), "日本語のスクリプト"] {
        let path = format!("/synthetic/{name}");
        let label = caller_from_processes(
            1000,
            |pid| (pid == 1000).then(|| (path.clone(), 1)),
            unsigned,
            |_| true,
        );
        assert!(label.starts_with("script:"));
        assert!(label.len() <= SCRIPT_LABEL_BYTES);
        assert!(!label.chars().any(char::is_control));
        let context = rekey_domain::audit::RequestAuditContext::Connection(
            rekey_domain::connection::ConnectionRequestAuditContext {
                connection: "fixture".into(),
                caller: label,
                method_class: rekey_domain::connection::MethodClass::Read,
                normalized_path: "/".into(),
                rule_id: None,
            },
        );
        context.validate().unwrap();
    }
    assert_eq!(script_label("bad\nname"), "script:bad_name");
}

#[tokio::test]
async fn a_unix_peer_in_this_process_gets_this_process_label() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let own = std::process::id() as i32;
    let label = unix_caller(&stream).await;
    assert_ne!(label, "unknown");
    assert_eq!(label, process_caller(own, |_| cfg!(target_os = "linux")));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn kernel_audit_token_is_captured_whole_and_cannot_be_supplied_by_metadata() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let (pid, token) = peer_identity(&stream).unwrap();
    assert_eq!(pid as u32, std::process::id());
    assert_eq!(token[5], std::process::id());
    assert!(!rekey_vault::generation_anchor::peer_has_own_team([0; 8]));
}
