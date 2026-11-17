//! Agent-facing guidance shipped with Rekey. Every tool-like word it quotes in
//! backticks must be a real rekey-mcp tool or a listed argument or value, so an
//! Agent following it never calls a missing tool. Quoted `rekey <subcommand>`
//! spans are checked against the CLI by crates/rekey-cli/tests/guidance_contract.rs.
use std::collections::BTreeSet;

const GUIDANCE: [(&str, &str); 4] = [
    (
        "plugins/rekey/skills/rekey/SKILL.md",
        include_str!("../../../../../plugins/rekey/skills/rekey/SKILL.md"),
    ),
    (
        "plugins/rekey/commands/rekey-list.md",
        include_str!("../../../../../plugins/rekey/commands/rekey-list.md"),
    ),
    (
        "plugins/rekey/commands/rekey-request.md",
        include_str!("../../../../../plugins/rekey/commands/rekey-request.md"),
    ),
    (
        "rekey connect managed section",
        include_str!("../../../../rekey-cli/src/commands/connect.rs"),
    ),
];
/// Quoted words that are arguments, fields or the placeholder Key, not tools.
const NOT_TOOLS: [&str; 3] = ["request_id", "approval_request_id", "rekey"];

/// The connect source carries its managed section between the markers.
fn section<'a>(source: &str, text: &'a str) -> &'a str {
    if source.starts_with("rekey connect") {
        let start = text.find("<!-- rekey:begin -->").unwrap();
        let end = text.find("<!-- rekey:end -->").unwrap();
        &text[start..end]
    } else {
        text
    }
}

/// Backticked spans, cut at a call's parenthesis, that look like a tool name:
/// lowercase identifiers such as `call` or `await_access(...)`.
fn tool_like_words(text: &str) -> Vec<&str> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(|quoted| quoted.split('(').next().unwrap_or(quoted))
        .filter(|word| {
            word.starts_with(|c: char| c.is_ascii_lowercase())
                && word
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        .collect()
}

fn tool_names() -> Vec<String> {
    super::generic_tools()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

/// Tool-like words that are neither a rekey-mcp tool nor a listed non-tool.
fn unknown_tools<'a>(text: &'a str, tools: &[String]) -> Vec<&'a str> {
    tool_like_words(text)
        .into_iter()
        .filter(|word| !NOT_TOOLS.contains(word) && !tools.iter().any(|tool| tool == word))
        .collect()
}

#[test]
fn every_tool_like_word_in_agent_guidance_is_a_real_tool() {
    let tools = tool_names();
    let mut seen = BTreeSet::new();
    for (source, text) in GUIDANCE {
        let text = section(source, text);
        assert_eq!(
            unknown_tools(text, &tools),
            Vec::<&str>::new(),
            "{source} names MCP tools that rekey-mcp does not provide"
        );
        seen.extend(tool_like_words(text));
    }
    for tool in [
        "list_capabilities",
        "describe",
        "call",
        "request_access",
        "await_access",
        "await_approval",
        "await_unlock",
    ] {
        assert!(seen.contains(tool), "guidance should name `{tool}`");
    }
    for word in NOT_TOOLS {
        assert!(seen.contains(word), "`{word}` is no longer quoted; drop it");
        assert!(
            !tools.iter().any(|tool| tool == word),
            "`{word}` is a tool; do not exempt it"
        );
    }
}

#[test]
fn single_word_and_unknown_tool_names_are_checked() {
    let text = "Use `call` or `describe(operation)`, then `lookup_secret`, `fetch`, \
        `rekey list`, `approval.challenge_id` and `APPROVAL_REQUIRED`.";
    assert_eq!(
        tool_like_words(text),
        ["call", "describe", "lookup_secret", "fetch"]
    );
    assert_eq!(
        unknown_tools(text, &tool_names()),
        ["lookup_secret", "fetch"]
    );
}
