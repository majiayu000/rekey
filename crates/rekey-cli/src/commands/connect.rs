//! Project MCP configuration and marked instructions. No credentials are involved.
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize, de, ser::SerializeMap};
use serde_json::value::RawValue;
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::client::CliError;

mod edit;
mod hooks;
use edit::{Edit, marked, review};
pub use hooks::{HooksCommand, hooks};

const LOCAL_PATH_WARNING: &str =
    "Warning: this file will contain the absolute path of a non-default vault; do not commit it.";

#[derive(Clone, Copy, ValueEnum)]
pub enum ConnectClient {
    ClaudeCode,
    Codex,
    Cursor,
}
#[derive(clap::Args)]
pub struct ConnectArgs {
    client: ConnectClient,
    #[arg(long)]
    print: bool,
    #[arg(long)]
    project: Option<PathBuf>,
    /// Install the marked pre-commit secret scan (same as `rekey hooks install`).
    #[arg(long)]
    with_hooks: bool,
    /// Configure SSH IdentityAgent for explicit --ssh-host targets.
    #[arg(long, requires = "ssh_hosts")]
    with_ssh: bool,
    #[arg(long = "ssh-host", requires = "with_ssh")]
    ssh_hosts: Vec<String>,
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
/// Generated files name `rekey` and `rekey-mcp` for PATH lookup (SPEC §6.5).
/// Warn when PATH would start a different binary than the one beside this
/// CLI, e.g. an older installed release next to a source build.
fn path_warning(name: &str, beside: Option<&Path>, path: Option<&OsStr>) -> Option<String> {
    let here = beside?.join(name).canonicalize().ok()?;
    let found = path.and_then(|path| {
        std::env::split_paths(path)
            .filter(|directory| directory.is_absolute())
            .find_map(|directory| {
                let candidate = directory.join(name).canonicalize().ok()?;
                candidate.is_file().then_some(candidate)
            })
    });
    match found {
        Some(found) if found == here => None,
        Some(found) => Some(format!(
            "Warning: Agents will start `{name}` from PATH, which is {}, not {} beside this rekey. Use the matching rekey, or put {} first on PATH.",
            found.display(),
            here.display(),
            here.parent().unwrap_or(&here).display(),
        )),
        None => Some(format!(
            "Warning: `{name}` is not on PATH, so Agents cannot start it. Add {} to PATH.",
            here.parent().unwrap_or(&here).display(),
        )),
    }
}
fn warnings(local_path: bool, name: &str, beside: Option<&Path>) -> Option<String> {
    let lines: Vec<String> = local_path
        .then(|| LOCAL_PATH_WARNING.to_owned())
        .into_iter()
        .chain(path_warning(
            name,
            beside,
            std::env::var_os("PATH").as_deref(),
        ))
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}
fn project_dir(project: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let project = match project {
        Some(project) => project,
        None => std::env::current_dir().map_err(|e| io_error("cannot resolve project", e))?,
    };
    std::path::absolute(project).map_err(|e| io_error("cannot resolve project", e))
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
    fn done_message(self) -> &'static str {
        match self {
            Self::Codex => {
                "Rekey configured. Codex reads .codex/config.toml only in a trusted project: when Codex asks whether to trust this folder, choose yes. Rekey tools then run without a Codex prompt per call; Rekey still asks you to approve writes. Inside the Codex sandbox the `rekey` command cannot reach Rekey, so the Agent uses the Rekey MCP tools. No token is required."
            }
            _ => "Rekey configured. Start your Agent normally; no token is required.",
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
// Rekey enforces signed rules and write approvals itself, so Codex does not
// add a second prompt for every Rekey tool call.
const CODEX_APPROVAL_KEY: &str = "default_tools_approval_mode";
const CODEX_APPROVAL: &str = "approve";
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
            t.len() == 2 + usize::from(state_dir.is_some())
                && t.get("command").and_then(Item::as_str) == Some(executable)
                && t.get(CODEX_APPROVAL_KEY).and_then(Item::as_str) == Some(CODEX_APPROVAL)
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
        server[CODEX_APPROVAL_KEY] = value(CODEX_APPROVAL);
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
- 沙箱里 `{rekey}` 命令连不上 Rekey（Operation not permitted）时改用 MCP 工具。
- 缺少权限或连接时调用 `request_access` 并说明理由，先告诉用户在等什么；等一次仍未处理就问用户是否继续等。上游返回 401/403 说明 Key 无效或权限不足，请用户在 Rekey 里更换 Key，不要用 `request_access`。收到 APPROVAL_REQUIRED 时用错误里的 `approval.challenge_id`（不是顶层 `request_id`）调用 `await_approval`，批准后带同一个 ID 重试原请求。
- Agent 写的程序使用 `{rekey} list` 给出的本机服务地址和占位 Key `rekey`。
<!-- rekey:end -->
";

pub fn connect(args: ConnectArgs, state_dir: &Path) -> Result<(), CliError> {
    let client = args.client;
    let vault = Vault::resolve(state_dir)?;
    let state = vault.custom.as_deref();
    let beside = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let instruction_text = INSTRUCTIONS.replace("{rekey}", &vault.rekey);
    let project_path = project_dir(args.project)?;
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
    config.warning = warnings(state.is_some(), "rekey-mcp", beside.as_deref());
    let mut instructions = Edit::load(project_path.clone(), None, client.instruction_file())?;
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
    instructions.warning = warnings(state.is_some(), "rekey", beside.as_deref());
    let mut edits = vec![config, instructions];
    if args.with_hooks {
        edits.extend(hooks::install(&project_path, &vault)?);
    }
    if args.with_ssh {
        edits.push(ssh_config(&args.ssh_hosts, &vault.path)?);
    }
    review(
        edits,
        args.print,
        "Apply Rekey configuration and instructions?",
        client.done_message(),
    )
}

/// The managed `Host` block at the top of ~/.ssh/config for explicit hosts.
fn ssh_config(hosts: &[String], state_dir: &Path) -> Result<Edit, CliError> {
    if hosts.iter().any(|h| {
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
    let socket = state_dir.join("ssh-agent.sock");
    let socket = socket
        .to_str()
        .ok_or_else(|| invalid("SSH socket must be UTF-8"))?;
    if socket.contains(['\n', '\r', '"']) {
        return Err(invalid("SSH socket path cannot be quoted safely"));
    }
    // First, so this IdentityAgent wins for the selected hosts; `Match all` then
    // ends the Host block, so directives after it keep their original scope.
    let block = format!(
        "# rekey:begin\nHost {}\n    IdentityAgent \"{}\"\nMatch all\n# rekey:end\n",
        hosts.join(" "),
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
    Ok(ssh)
}

#[cfg(test)]
mod path_tests {
    use super::path_warning;
    use std::ffi::OsString;

    fn binary(dir: &std::path::Path, name: &str) {
        std::fs::write(dir.join(name), b"").unwrap();
    }

    #[test]
    fn path_warning_names_a_different_or_missing_binary() {
        let root = tempfile::tempdir().unwrap();
        let (here, other) = (root.path().join("here"), root.path().join("other"));
        std::fs::create_dir_all(&here).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        binary(&here, "rekey-mcp");
        binary(&other, "rekey-mcp");
        let path = |dirs: &[&std::path::Path]| -> OsString { std::env::join_paths(dirs).unwrap() };

        let same = path(&[&here, &other]);
        assert_eq!(path_warning("rekey-mcp", Some(&here), Some(&same)), None);

        let shadowed = path(&[&other, &here]);
        let warning = path_warning("rekey-mcp", Some(&here), Some(&shadowed)).unwrap();
        let other = other.canonicalize().unwrap();
        assert!(warning.contains(&other.join("rekey-mcp").display().to_string()));
        assert!(warning.contains("not "), "{warning}");

        let missing = path(&[root.path()]);
        let warning = path_warning("rekey-mcp", Some(&here), Some(&missing)).unwrap();
        assert!(warning.contains("not on PATH"), "{warning}");

        // No sibling (for example a test binary): nothing to compare.
        assert_eq!(
            path_warning("rekey-mcp", Some(root.path()), Some(&same)),
            None
        );
    }
}
