//! Agent-facing guidance may only name `rekey` subcommands that exist.
//! Runs the real CLI binary's `--help`; no broker, vault or network.

use std::process::Command;

const GUIDANCE: [(&str, &str); 4] = [
    (
        "plugins/rekey/skills/rekey/SKILL.md",
        include_str!("../../../plugins/rekey/skills/rekey/SKILL.md"),
    ),
    (
        "plugins/rekey/commands/rekey-list.md",
        include_str!("../../../plugins/rekey/commands/rekey-list.md"),
    ),
    (
        "plugins/rekey/commands/rekey-request.md",
        include_str!("../../../plugins/rekey/commands/rekey-request.md"),
    ),
    (
        "rekey connect managed section",
        include_str!("../src/commands/connect.rs"),
    ),
];

/// First word after `rekey ` or the `{rekey} ` placeholder written by connect.
fn subcommands(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for marker in ["`rekey ", "{rekey} ", "\nrekey "] {
        for (index, _) in text.match_indices(marker) {
            let rest = &text[index + marker.len()..];
            let word: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '-')
                .collect();
            if !word.is_empty() {
                found.push(word);
            }
        }
    }
    found
}

#[test]
fn every_rekey_subcommand_named_in_agent_guidance_exists() {
    let mut checked = 0;
    for (source, text) in GUIDANCE {
        let text = if source.starts_with("rekey connect") {
            let start = text.find("<!-- rekey:begin -->").unwrap();
            let end = text.find("<!-- rekey:end -->").unwrap();
            &text[start..end]
        } else {
            text
        };
        for subcommand in subcommands(text) {
            let output = Command::new(env!("CARGO_BIN_EXE_rekey"))
                .args([subcommand.as_str(), "--help"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{source} names `rekey {subcommand}`, which is not a rekey subcommand"
            );
            checked += 1;
        }
    }
    assert!(checked >= 5, "guidance should name the core commands");
}
