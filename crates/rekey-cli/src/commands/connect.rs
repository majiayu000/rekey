//! Project MCP configuration and marked instructions. No credentials are involved.
use std::collections::{BTreeMap, HashSet};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize, de, ser::SerializeMap};
use serde_json::value::RawValue;
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::client::CliError;

mod edit;
use edit::{Edit, MAX_CONFIG, marked};

const LOCAL_PATH_WARNING: &str =
    "Warning: this file will contain the absolute path of a non-default vault; do not commit it.";

#[derive(Clone, Copy, ValueEnum)]
pub enum ConnectClient {
    ClaudeCode,
    Codex,
    Cursor,
}
/// How generated files name the vault. The default `~/.rekey` stays implicit,
/// so project files carry no local path; any other vault is bound explicitly.
struct Vault {
    path: PathBuf,
    custom: Option<String>,
    rekey: String,
}
impl Vault {
    fn resolve(state_dir: &Path) -> Result<Self, CliError> {
        let path = std::path::absolute(state_dir)
            .map_err(|e| io_error("cannot resolve state directory", e))?;
        let state = path
            .to_str()
            .ok_or_else(|| invalid("state directory must be UTF-8"))?;
        let default = super::resolve_state_dir(None)
            .ok()
            .and_then(|dir| std::path::absolute(dir).ok());
        let custom = (default.as_deref() != Some(&*path)).then(|| state.to_owned());
        let rekey = custom.as_deref().map_or_else(
            || "rekey".into(),
            |state| format!("rekey --state-dir '{}'", state.replace('\'', "'\"'\"'")),
        );
        Ok(Self {
            path,
            custom,
            rekey,
        })
    }
}
impl ConnectClient {
    fn instruction_file(self) -> &'static str {
        match self {
            Self::ClaudeCode => "CLAUDE.md",
            _ => "AGENTS.md",
        }
    }
    fn location(self) -> (Option<&'static str>, &'static str) {
        match self {
            Self::ClaudeCode => (None, ".mcp.json"),
            Self::Codex => (Some(".codex"), "config.toml"),
            Self::Cursor => (Some(".cursor"), "mcp.json"),
        }
    }
}
fn invalid(message: &str) -> CliError {
    CliError::local("USAGE", message)
}
fn io_error(operation: &str, error: io::Error) -> CliError {
    CliError::local("IO", format!("{operation}: {error}"))
}

// Parse only the edited object levels. RawValue preserves all unrelated numbers
// and values, including integers beyond f64 precision; errors never echo content.
#[derive(Default)]
struct Object(Vec<(String, Box<RawValue>)>);
impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Object;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object with unique keys")
            }
            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Object, M::Error> {
                let mut entries = Vec::new();
                let mut keys = HashSet::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    entries.push((key, value));
                }
                Ok(Object(entries))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
impl Serialize for Object {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}
impl Object {
    fn parse(bytes: &[u8]) -> Result<Self, CliError> {
        serde_json::from_slice(bytes).map_err(|_| {
            invalid("invalid or duplicate JSON configuration keys; JSONC is not supported")
        })
    }
    fn get(&self, key: &str) -> Option<&RawValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| &**v)
    }
    fn set(&mut self, key: &str, value: Box<RawValue>) {
        if let Some((_, old)) = self.0.iter_mut().find(|(k, _)| k == key) {
            *old = value;
        } else {
            self.0.push((key.into(), value));
        }
    }
}
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct JsonServer {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<Vec<String>>,
}
fn json_server(executable: &str, state_dir: Option<&str>) -> JsonServer {
    JsonServer {
        command: executable.into(),
        args: state_dir.map(|state| vec!["--state-dir".into(), state.into()]),
    }
}
fn encode_raw(value: &impl Serialize) -> Result<Box<RawValue>, CliError> {
    serde_json::value::to_raw_value(value).map_err(|_| invalid("cannot encode MCP configuration"))
}
fn preview_fields<'a>(keys: impl Iterator<Item = &'a str>) -> Result<String, CliError> {
    let fields: BTreeMap<_, _> = keys.map(|key| (key, "<existing value hidden>")).collect();
    serde_json::to_string_pretty(&fields).map_err(|_| invalid("cannot encode MCP preview"))
}
// (new bytes, existing subtree field comparison with values hidden, already equal)
// `state_dir` is set only for a non-default vault.
fn prepare(
    client: ConnectClient,
    original: &[u8],
    executable: &str,
    state_dir: Option<&str>,
) -> Result<(Vec<u8>, String, bool), CliError> {
    if matches!(client, ConnectClient::Codex) {
        let text = std::str::from_utf8(original)
            .map_err(|_| invalid("TOML configuration must be UTF-8"))?;
        let mut doc = text
            .parse::<DocumentMut>()
            .map_err(|_| invalid("invalid TOML configuration"))?;
        if !doc.contains_key("mcp_servers") {
            doc["mcp_servers"] = Item::Table(Table::new());
        }
        let servers = doc["mcp_servers"]
            .as_table_like_mut()
            .ok_or_else(|| invalid("mcp_servers must be a TOML table"))?;
        let old = servers.get("rekey");
        let same = old.and_then(Item::as_table_like).is_some_and(|t| {
            t.len() == 1 + usize::from(state_dir.is_some())
                && t.get("command").and_then(Item::as_str) == Some(executable)
                && state_dir.is_none_or(|state| {
                    t.get("args").and_then(Item::as_array).is_some_and(|args| {
                        args.len() == 2
                            && args.get(0).and_then(toml_edit::Value::as_str) == Some("--state-dir")
                            && args.get(1).and_then(toml_edit::Value::as_str) == Some(state)
                    })
                })
        });
        let before = match old {
            Some(old) => match old.as_table_like() {
                Some(table) => preview_fields(table.iter().map(|(key, _)| key))?,
                None => "<existing non-table value hidden>".into(),
            },
            None => "<no rekey subtree>".into(),
        };
        let mut server = Table::new();
        server["command"] = value(executable);
        if let Some(state) = state_dir {
            server["args"] = value(Array::from_iter(["--state-dir", state]));
        }
        servers.insert("rekey", Item::Table(server));
        Ok((doc.to_string().into_bytes(), before, same))
    } else {
        let mut doc = if original.is_empty() {
            Object::default()
        } else {
            Object::parse(original)?
        };
        let mut servers = doc
            .get("mcpServers")
            .map(|r| Object::parse(r.get().as_bytes()))
            .transpose()?
            .unwrap_or_default();
        let server = json_server(executable, state_dir);
        let mut before = "<no rekey subtree>".into();
        let same = if let Some(old) = servers.get("rekey") {
            let object = Object::parse(old.get().as_bytes())?;
            before = preview_fields(object.0.iter().map(|(key, _)| key.as_str()))?;
            if let Some(env) = object.get("env") {
                Object::parse(env.get().as_bytes())?;
            }
            serde_json::from_str::<JsonServer>(old.get()).is_ok_and(|old| old == server)
        } else {
            false
        };
        servers.set("rekey", encode_raw(&server)?);
        doc.set("mcpServers", encode_raw(&servers)?);
        let mut bytes = serde_json::to_vec_pretty(&doc)
            .map_err(|_| invalid("cannot encode MCP configuration"))?;
        bytes.push(b'\n');
        Ok((bytes, before, same))
    }
}

const INSTRUCTIONS: &str = "<!-- rekey:begin -->
## 使用密钥
- 需要调用外部 API、git push 或使用任何凭据时，使用 Rekey：MCP 工具 `list_capabilities` / `call`，或命令 `{rekey} list` / `{rekey} call`。
- 不要向用户索要 API Key，不要读取或写入 .env 中的密钥，不要把密钥写进代码。
- 缺少权限或连接时调用 `request_access` 并说明理由；收到 APPROVAL_REQUIRED 时用错误里的 `approval.challenge_id`（不是顶层 `request_id`）调用 `await_approval`，批准后带同一个 ID 重试原请求。
- Agent 写的程序使用 `{rekey} list` 给出的本机服务地址和占位 Key `rekey`。
<!-- rekey:end -->
";

pub fn connect(
    client: ConnectClient,
    print: bool,
    project: Option<PathBuf>,
    with_hooks: bool,
    ssh_hosts: Vec<String>,
    state_dir: &Path,
) -> Result<(), CliError> {
    let vault = Vault::resolve(state_dir)?;
    let (rekey, state) = (&vault.rekey, vault.custom.as_deref());
    let warning = state.map(|_| LOCAL_PATH_WARNING);
    let instruction_text = INSTRUCTIONS.replace("{rekey}", rekey);
    let project_path = std::path::absolute(
        project
            .unwrap_or(std::env::current_dir().map_err(|e| io_error("cannot resolve project", e))?),
    )
    .map_err(|e| io_error("cannot resolve project", e))?;
    let (subdir, filename) = client.location();
    let mut config = Edit::load(project_path.clone(), subdir, filename)?;
    if !matches!(client, ConnectClient::Codex)
        && config.original.is_some()
        && config.bytes().is_empty()
    {
        return Err(invalid("existing JSON configuration is empty"));
    }
    let (updated, before, same) = prepare(client, config.bytes(), "rekey-mcp", state)?;
    config.updated = if same {
        config.bytes().to_vec()
    } else {
        updated
    };
    config.before = before;
    config.after =
        String::from_utf8(prepare(client, &[], "rekey-mcp", state)?.0).expect("generated UTF-8");
    config.warning = warning;
    let mut instructions = Edit::load(project_path, None, client.instruction_file())?;
    instructions.updated = marked(
        instructions.bytes(),
        &instruction_text,
        "<!-- rekey:begin -->",
        "<!-- rekey:end -->",
    )?;
    let begin = b"<!-- rekey:begin -->";
    instructions.before = if instructions
        .bytes()
        .windows(begin.len())
        .any(|s| s == begin)
    {
        "<existing Rekey instructions; values hidden>"
    } else {
        "<no Rekey instructions>"
    }
    .into();
    instructions.after = instruction_text;
    instructions.warning = warning;
    let mut edits = vec![config, instructions];
    if with_hooks {
        let result = std::process::Command::new("git")
            .args([
                "-C",
                edits[0]
                    .root_path
                    .to_str()
                    .ok_or_else(|| invalid("project path must be UTF-8"))?,
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "hooks",
            ])
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|_| invalid("cannot locate Git hooks directory"))?;
        if !result.status.success() {
            return Err(invalid("--with-hooks requires a Git repository"));
        }
        let path = std::str::from_utf8(&result.stdout)
            .map_err(|_| invalid("Git hooks path must be UTF-8"))?
            .trim_end_matches('\n');
        let hooks = std::path::absolute(path)
            .map_err(|e| io_error("cannot resolve Git hooks directory", e))?;
        let hooks_parent = hooks
            .parent()
            .ok_or_else(|| invalid("Git hooks directory has no parent"))?
            .to_owned();
        let mut hook = if hooks.is_dir() {
            Edit::load(hooks, None, "pre-commit")?
        } else if hooks.file_name().and_then(|s| s.to_str()) == Some("hooks") {
            Edit::load(hooks_parent, Some("hooks"), "pre-commit")?
        } else {
            return Err(invalid("custom Git hooks directories must already exist"));
        };
        let old = if hook.bytes().is_empty() {
            b"#!/bin/sh\n".as_slice()
        } else {
            hook.bytes()
        };
        let block = format!("# rekey:begin\n{rekey} scan --staged || exit $?\n# rekey:end\n");
        hook.updated = marked(old, &block, "# rekey:begin", "# rekey:end")?;
        hook.before = "<existing hook retained outside Rekey markers>".into();
        hook.after = block;
        edits.push(hook);
    }
    if !ssh_hosts.is_empty() {
        if ssh_hosts.iter().any(|h| {
            h.is_empty()
                || !h
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        }) {
            return Err(invalid(
                "SSH host must be a concrete hostname, without wildcards or whitespace",
            ));
        }
        let home = std::env::home_dir().ok_or_else(|| invalid("cannot resolve home directory"))?;
        let mut ssh = Edit::load(home, Some(".ssh"), "config")?;
        let socket = vault.path.join("ssh-agent.sock");
        let socket = socket
            .to_str()
            .ok_or_else(|| invalid("SSH socket must be UTF-8"))?;
        if socket.contains(['\n', '\r', '"']) {
            return Err(invalid("SSH socket path cannot be quoted safely"));
        }
        let block = format!(
            "# rekey:begin\nHost {}\n    IdentityAgent \"{}\"\n# rekey:end\n",
            ssh_hosts.join(" "),
            socket
        );
        let unmanaged = marked(ssh.bytes(), "", "# rekey:begin", "# rekey:end")?;
        ssh.updated = block
            .as_bytes()
            .iter()
            .chain(unmanaged.iter())
            .copied()
            .collect();
        ssh.before = "<existing SSH configuration retained outside Rekey markers>".into();
        ssh.after = block;
        edits.push(ssh);
    }
    let mut output = io::stdout().lock();
    for edit in &edits {
        if edit.updated.len() > MAX_CONFIG {
            return Err(invalid("updated configuration exceeds 1 MiB"));
        }
        writeln!(
            output,
            "Target: {}\n--- before\n- {}\n+++ after",
            edit.path().display(),
            edit.before
        )
        .map_err(|e| io_error("cannot write preview", e))?;
        for line in edit.after.lines() {
            writeln!(output, "+ {line}").map_err(|e| io_error("cannot write preview", e))?;
        }
        if let Some(warning) = edit.warning {
            writeln!(output, "{warning}").map_err(|e| io_error("cannot write preview", e))?;
        }
    }
    if print {
        return Ok(());
    }
    if !edits.iter().any(Edit::changed) {
        writeln!(output, "Already configured; no files changed.")
            .map_err(|e| io_error("cannot write result", e))?;
        return Ok(());
    }
    output
        .flush()
        .map_err(|e| io_error("cannot write preview", e))?;
    if !io::stdin().is_terminal() {
        return Err(invalid(
            "TTY confirmation is required; use --print to preview without writing",
        ));
    }
    write!(
        io::stderr(),
        "Apply Rekey configuration and instructions? [y/N] "
    )
    .and_then(|()| io::stderr().flush())
    .map_err(|e| io_error("cannot write confirmation", e))?;
    let mut answer = String::new();
    io::stdin()
        .lock()
        .take(32)
        .read_line(&mut answer)
        .map_err(|e| io_error("cannot read confirmation", e))?;
    if answer.len() == 32 || !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        return Ok(());
    }
    for edit in &edits {
        edit.verify()?;
    }
    for edit in edits.iter_mut().filter(|e| e.changed()) {
        edit.apply()?;
    }
    writeln!(
        output,
        "Rekey configured. Start your Agent normally; no token is required."
    )
    .map_err(|e| io_error("cannot write result", e))
}
