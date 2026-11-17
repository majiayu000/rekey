//! Caller labels for CLI, MCP and loopback HTTP calls (agent-call model §4.3,
//! acceptance C4). Renamed copies of this test binary forge Agent parents;
//! signed caller rules may still only tighten the default decision.
use super::*;
use std::path::{Path, PathBuf};

use rekey_domain::connection::{ConnectionRule, MethodClass, MethodSelector};
use rekey_domain::ids::PolicyRuleId;

use crate::renamed_agent::{self, Child};

/// Workspace binaries share this build's target directory.
fn sibling(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_rekeyd")).with_file_name(name);
    assert!(
        path.is_file(),
        "build {name} first: cargo build --workspace --bins"
    );
    path
}

fn every(methods: MethodClass, effect: RuleEffect) -> ConnectionRule {
    ConnectionRule {
        id: PolicyRuleId::new_random(),
        methods: MethodSelector::Class(methods),
        path: "/**".into(),
        effect,
    }
}

/// Defaults: reads allow, writes approve. `codex` denies reads (tighter);
/// `claude-code` "allows" writes, which must never widen the approval.
async fn activate_caller_rules(f: &Fixture) -> u16 {
    let mut connection = f.seed().await;
    connection.caller_overrides.insert(
        "codex".into(),
        vec![every(MethodClass::Read, RuleEffect::Deny)],
    );
    connection.caller_overrides.insert(
        "claude-code".into(),
        vec![every(MethodClass::Write, RuleEffect::Allow)],
    );
    let draft = f.draft(vec![connection]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    list.service_url
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

async fn audited(f: &Fixture, event: &str) -> Vec<String> {
    renamed_agent::audited_callers(&f.socket(), event).await
}

fn dry_run_args(state: &Path, method: &str) -> Vec<String> {
    let mut args: Vec<String> = ["--state-dir", state.to_str().unwrap(), "http", "fixture"]
        .map(String::from)
        .into();
    args.extend([
        method.into(),
        "/repos/a/b/issues".into(),
        "--dry-run".into(),
    ]);
    if method == "POST" {
        args.extend(["--json".into(), "{}".into()]);
    }
    args
}

fn effect(status: i32, stdout: &[u8], stderr: &[u8]) -> String {
    assert_eq!(status, 0, "{}", String::from_utf8_lossy(stderr));
    let preview: Value = serde_json::from_slice(stdout).unwrap();
    preview["effect"].as_str().unwrap().to_owned()
}

/// The signed decision for a label under `activate_caller_rules`.
fn decision(label: &str, method: &str) -> &'static str {
    match method {
        "GET" if label == "codex" => "deny",
        "GET" => "allow",
        _ => "approve",
    }
}

#[tokio::test]
async fn forged_agent_parents_label_cli_calls_but_caller_rules_only_tighten() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    activate_caller_rules(&f).await;
    let cli = sibling("rekey");
    // The runner's own ancestry: a known Agent if one runs this test suite,
    // otherwise this test binary (the first program above the CLI).
    let state = f.state.clone();
    let direct = tokio::task::spawn_blocking(move || {
        std::process::Command::new(sibling("rekey"))
            .args(dry_run_args(&state, "GET"))
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let ancestry = audited(&f, "call.dry_run").await.pop().unwrap();
    assert!(!ancestry.starts_with("script:rekey"), "{ancestry}");
    assert_eq!(
        effect(
            direct.status.code().unwrap(),
            &direct.stdout,
            &direct.stderr
        ),
        decision(&ancestry, "GET")
    );
    let script = if ancestry.starts_with("script:") {
        "script:fixture-script".to_owned()
    } else {
        ancestry.clone()
    };
    let agents = tempfile::tempdir().unwrap();
    let mut expected = vec![ancestry];
    for (relative, label) in [
        ("codex", "codex"),
        ("claude", "claude-code"),
        // The native installer names its executable after the version.
        (".local/share/claude/versions/9.9.9", "claude-code"),
        ("fixture-script", script.as_str()),
    ] {
        let agent = renamed_agent::install(agents.path(), relative);
        for method in ["GET", "POST"] {
            let child = Child {
                program: Some(cli.clone()),
                args: dry_run_args(&f.state, method),
                ..Child::default()
            };
            let output = renamed_agent::run(&agent, child).await;
            assert_eq!(
                effect(output.status, &output.stdout, &output.stderr),
                decision(label, method),
                "{relative} {method}"
            );
            expected.push(label.to_owned());
        }
    }
    assert_eq!(audited(&f, "call.dry_run").await, expected);
    assert!(f.fake.take_requests().is_empty());
    f.finish().await;
}

#[tokio::test]
async fn mcp_under_a_forged_parent_is_labelled_without_widening_rules() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    activate_caller_rules(&f).await;
    let agents = tempfile::tempdir().unwrap();
    let agent = renamed_agent::install(agents.path(), "codex");
    let socket = f.state.join("runtime/agent.sock");
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"caller-labels","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"http","arguments":{"connection":"fixture","method":"GET","path":"/repos/a/b/issues","dry_run":true}}}),
    ];
    let child = Child {
        program: Some(env!("CARGO_BIN_EXE_rekey-mcp").into()),
        args: vec!["--agent-socket".into(), socket.to_str().unwrap().into()],
        stdin: requests
            .iter()
            .map(|request| format!("{request}\n"))
            .collect::<String>()
            .into_bytes(),
        ..Child::default()
    };
    let output = renamed_agent::run(&agent, child).await;
    assert_eq!(
        output.status,
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|response| response["id"] == 2)
        .unwrap();
    // macOS: this unsigned rekey-mcp has no daemon-team signature and keeps
    // its own name. Linux cannot verify signatures and labels the chain.
    let label = if cfg!(target_os = "macos") {
        "script:rekey-mcp"
    } else {
        "codex"
    };
    assert_eq!(audited(&f, "call.dry_run").await, vec![label]);
    assert_eq!(
        response["result"]["structuredContent"]["effect"],
        decision(label, "GET"),
        "{response}"
    );
    f.finish().await;
}

fn http(port: u16, method: &str, challenge: Option<&str>) -> String {
    let mut head = format!(
        "{method} /c/fixture/repos/a/b{} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nauthorization: Bearer rekey\r\nconnection: close\r\n",
        if method == "POST" { "/issues" } else { "" }
    );
    if let Some(id) = challenge {
        head.push_str(&format!("x-rekey-approval-challenge: {id}\r\n"));
    }
    if method == "POST" {
        head.push_str("content-type: application/json\r\ncontent-length: 2\r\n\r\n{}");
    } else {
        head.push_str("\r\n");
    }
    head
}

async fn http_from(agent: &Path, port: u16, method: &str, challenge: Option<&str>) -> String {
    let child = Child {
        http: Some((port, http(port, method, challenge))),
        ..Child::default()
    };
    String::from_utf8(renamed_agent::run(agent, child).await.stdout).unwrap()
}

#[tokio::test]
async fn loopback_http_callers_are_labelled_and_own_their_approvals() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let port = activate_caller_rules(&f).await;
    let agents = tempfile::tempdir().unwrap();
    let codex = renamed_agent::install(agents.path(), "codex");
    // The codex read override now reaches HTTP callers.
    let denied = http_from(&codex, port, "GET", None).await;
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
    assert!(denied.contains("DENIED"), "{denied}");
    assert_eq!(audited(&f, "execution.blocked").await, vec!["codex"]);

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://127.0.0.1:{port}/c/fixture/repos/a/b/issues");
    let post = |challenge: Option<String>| {
        let request = client
            .post(&url)
            .bearer_auth("rekey")
            .header("content-type", "application/json")
            .body("{}");
        match challenge {
            Some(id) => request.header("x-rekey-approval-challenge", id),
            None => request,
        }
    };
    let pending = post(None).send().await.unwrap();
    assert_eq!(pending.status(), 403);
    let pending: Value = serde_json::from_slice(&pending.bytes().await.unwrap()).unwrap();
    assert_eq!(pending["code"], "APPROVAL_REQUIRED");
    let id = pending["approval"]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let own = audited(&f, "approval.requested").await;
    assert_eq!(own.len(), 1);
    // This process is identifiable, so it is no longer the shared `unknown`.
    assert_ne!(own[0], "unknown");
    // A second client with a different label (this suite may run under Codex).
    let other = if own[0] == "codex" {
        renamed_agent::install(agents.path(), "claude")
    } else {
        codex
    };

    let review = f
        .call(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":id}),
            &[],
        )
        .await;
    review.ok();
    let remembered = f
        .call(
            admin_msg::DESKTOP_REMEMBER,
            json!({"lifetime_ms":604800000}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    remembered.ok();
    let mut presence = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut presence);
    f.call(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        json!({"approval_request_id":id,"expected_review_sha256":review.metadata["review_sha256"],"window_seconds":1800}),
        &presence,
    )
    .await
    .ok();

    // Another client can neither consume this approval nor use its window.
    let stolen = http_from(&other, port, "POST", Some(&id)).await;
    assert!(stolen.starts_with("HTTP/1.1 403"), "{stolen}");
    let windowed = http_from(&other, port, "POST", None).await;
    assert!(windowed.contains("APPROVAL_REQUIRED"), "{windowed}");
    assert!(f.fake.take_requests().is_empty());
    // The approving client retries with the challenge header and succeeds,
    // then reuses its own time window.
    let replay = post(Some(id)).send().await.unwrap();
    assert_eq!(replay.status(), 200);
    let window = post(None).send().await.unwrap();
    assert_eq!(window.status(), 200);
    assert_eq!(f.fake.take_requests().len(), 2);
    f.finish().await;
}
