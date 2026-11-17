//! Known-Agent table for best-effort caller labels (§4.3). A match records who
//! appears to call; it never authenticates and can only select tightening rules.
use std::path::{Component, Path};

pub(super) struct KnownAgent {
    pub(super) label: &'static str,
    /// macOS Developer ID team. A signed process matches only after its
    /// signature validates against this team. Linux has no signatures.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(super) team: &'static str,
    /// Signing identifier prefixes; empty accepts every identifier of the team.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    identifiers: &'static [&'static str],
    /// Exact executable file names (real path, after symlink resolution).
    names: &'static [&'static str],
    /// macOS app bundle directories anywhere in the real path.
    bundles: &'static [&'static str],
    /// Consecutive directories of versioned installs, e.g. the native Claude
    /// Code installer's `~/.local/share/claude/versions/<version>`.
    dirs: &'static [&'static str],
}

const AGENTS: &[KnownAgent] = &[
    KnownAgent {
        label: "claude-code",
        team: "Q6L2SF6YDW",
        identifiers: &["com.anthropic.claude-code"],
        names: &["claude"],
        bundles: &[],
        dirs: &[".local/share/claude/versions"],
    },
    KnownAgent {
        label: "codex",
        team: "2DC432GLL2",
        // The CLI (`codex`, `codex-*` helpers) and the desktop app with its
        // `com.openai.codex.*` helpers. Other OpenAI apps are not Codex.
        identifiers: &["codex", "com.openai.codex"],
        names: &["codex"],
        bundles: &["Codex.app", "CodexCLI.app"],
        dirs: &[],
    },
    KnownAgent {
        label: "cursor",
        team: "VDXQ22DGB9",
        // Cursor's helpers keep Electron's generic identifier.
        identifiers: &[],
        names: &["cursor", "Cursor", "cursor-agent"],
        bundles: &["Cursor.app"],
        dirs: &[".local/share/cursor-agent/versions"],
    },
    KnownAgent {
        label: "vscode",
        team: "UBF8T346G9",
        // Covers VSCode, VSCodeInsiders and their helpers; not other
        // Microsoft-signed apps.
        identifiers: &["com.microsoft.VSCode"],
        names: &["code", "code-insiders", "codium", "codium-insiders"],
        bundles: &[
            "Visual Studio Code.app",
            "Visual Studio Code - Insiders.app",
            "VSCodium.app",
            "VSCodium - Insiders.app",
        ],
        dirs: &[],
    },
];

/// Matches a real executable path. Same-UID code can place any binary at
/// such a path, which is why a label is a record and not an identity.
pub(super) fn by_path(path: &str) -> Option<&'static str> {
    let path = Path::new(path);
    let name = path.file_name()?.to_str()?;
    let parents: Vec<&str> = path
        .parent()?
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect();
    AGENTS
        .iter()
        .find(|agent| {
            agent.names.contains(&name)
                || agent.bundles.iter().any(|bundle| parents.contains(bundle))
                || agent.dirs.iter().any(|dirs| {
                    let dirs: Vec<&str> = dirs.split('/').collect();
                    parents.windows(dirs.len()).any(|window| window == dirs)
                })
        })
        .map(|agent| agent.label)
}

/// Selects the table entry a claimed signature names. The caller must still
/// validate the code against `KnownAgent::team` before using the label.
#[cfg(any(target_os = "macos", test))]
pub(super) fn by_signature(team: &str, identifier: &str) -> Option<&'static KnownAgent> {
    AGENTS.iter().find(|agent| {
        agent.team == team
            && (agent.identifiers.is_empty()
                || agent
                    .identifiers
                    .iter()
                    .any(|prefix| identifier.starts_with(prefix)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_paths_of_supported_installs_match_without_relying_on_the_file_name() {
        for (path, label) in [
            (
                "/Users/u/.local/share/claude/versions/2.1.326",
                "claude-code",
            ),
            (
                "/home/u/.local/share/claude/versions/2.1.326",
                "claude-code",
            ),
            (
                "/opt/homebrew/Caskroom/claude-code/2.1.0/claude",
                "claude-code",
            ),
            (
                "/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex",
                "codex",
            ),
            ("/Applications/Codex.app/Contents/MacOS/Codex", "codex"),
            ("/Applications/Cursor.app/Contents/MacOS/Cursor", "cursor"),
            (
                "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)",
                "cursor",
            ),
            (
                "/Users/u/.local/share/cursor-agent/versions/2026.10.22-27dcf5f/node",
                "cursor",
            ),
            ("/usr/share/cursor/cursor", "cursor"),
            (
                "/Applications/Visual Studio Code.app/Contents/MacOS/Code",
                "vscode",
            ),
            (
                "/Applications/Visual Studio Code - Insiders.app/Contents/Frameworks/Code - Insiders Helper (Plugin).app/Contents/MacOS/Code - Insiders Helper (Plugin)",
                "vscode",
            ),
            (
                "/Applications/VSCodium.app/Contents/MacOS/Electron",
                "vscode",
            ),
            ("/usr/share/code/code", "vscode"),
            ("/usr/share/code-insiders/code-insiders", "vscode"),
            ("/usr/share/codium/codium", "vscode"),
        ] {
            assert_eq!(by_path(path), Some(label), "{path}");
        }
        for path in [
            "/Users/u/.local/share/claude/2.1.326",
            "/Users/u/claude-versions/2.1.326",
            "/usr/bin/python3",
            "/bin/zsh",
            "/Applications/Claude.app/Contents/MacOS/Claude",
            "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
            "/usr/local/bin/rekey",
            "/",
        ] {
            assert_eq!(by_path(path), None, "{path}");
        }
    }

    #[test]
    fn signatures_need_the_agent_team_and_identifier_family() {
        for (team, identifier, label) in [
            ("Q6L2SF6YDW", "com.anthropic.claude-code", "claude-code"),
            ("2DC432GLL2", "codex", "codex"),
            ("2DC432GLL2", "codex-exec-server", "codex"),
            ("2DC432GLL2", "com.openai.codex", "codex"),
            ("2DC432GLL2", "com.openai.codex.helper", "codex"),
            ("VDXQ22DGB9", "com.todesktop.230313mzl4w4u92", "cursor"),
            ("VDXQ22DGB9", "com.github.Electron.helper", "cursor"),
            ("UBF8T346G9", "com.microsoft.VSCode", "vscode"),
            ("UBF8T346G9", "com.microsoft.VSCode.helper", "vscode"),
            ("UBF8T346G9", "com.microsoft.VSCodeInsiders", "vscode"),
        ] {
            assert_eq!(
                by_signature(team, identifier).map(|agent| agent.label),
                Some(label),
                "{team} {identifier}"
            );
        }
        for (team, identifier) in [
            // Same publisher, different product.
            ("Q6L2SF6YDW", "com.anthropic.claudefordesktop"),
            ("2DC432GLL2", "com.openai.chat"),
            ("UBF8T346G9", "com.microsoft.teams2"),
            // A known identifier from another team.
            ("ABCDE12345", "com.anthropic.claude-code"),
            ("", "codex"),
        ] {
            assert!(
                by_signature(team, identifier).is_none(),
                "{team} {identifier}"
            );
        }
    }
}
