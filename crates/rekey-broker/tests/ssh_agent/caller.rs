//! SSH agent caller labels (agent-call model §4.3): the Unix peer's process
//! chain, as for the CLI, instead of one label shared by every SSH client.
use super::*;

use crate::renamed_agent::{self, Child};

#[tokio::test]
async fn ssh_signing_is_labelled_by_the_unix_peer_like_the_cli() {
    let f = Fixture::new(RuleEffect::Deny).await;
    let dir = f.broker.dir.path();
    let public = dir.join("synthetic.pub");
    std::fs::write(
        &public,
        format!("ssh-ed25519 {} synthetic-only\n", BASE64.encode(&f.public)),
    )
    .unwrap();
    let socket = f.broker.state_dir.join("ssh-agent.sock");
    let sign = |message: &str| {
        let input = dir.join(message);
        std::fs::write(&input, b"synthetic git message").unwrap();
        ["-Y", "sign", "-q", "-n", "git", "-f"]
            .map(String::from)
            .into_iter()
            .chain([
                public.to_str().unwrap().into(),
                input.to_str().unwrap().into(),
            ])
            .collect::<Vec<String>>()
    };
    let agents = tempfile::tempdir().unwrap();
    let codex = renamed_agent::install(agents.path(), "codex");
    let output = renamed_agent::run(
        &codex,
        Child {
            program: Some("ssh-keygen".into()),
            args: sign("forged-parent"),
            env: vec![("SSH_AUTH_SOCK".into(), socket.to_str().unwrap().into())],
            ..Child::default()
        },
    )
    .await;
    assert_eq!(
        output.status,
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let direct = tokio::process::Command::new("ssh-keygen")
        .args(sign("direct"))
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .await
        .unwrap();
    assert!(
        direct.status.success(),
        "{}",
        String::from_utf8_lossy(&direct.stderr)
    );
    let callers = renamed_agent::audited_callers(&f.broker.admin_sock(), "execution.started").await;
    assert_eq!(callers.len(), 2);
    // ssh-keygen is not an Agent; its forged `codex` parent is.
    assert_eq!(callers[0], "codex");
    assert!(
        callers[1] != "ssh-agent" && callers[1] != "unknown",
        "{callers:?}"
    );
    f.verify_audit_page(2).await;
    f.broker.shutdown().await;
}
