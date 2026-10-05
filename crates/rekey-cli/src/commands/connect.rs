//! Project MCP configuration and marked instructions. No credentials are involved.
use std::collections::{BTreeMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use clap::ValueEnum;
use rand::TryRngCore;
use serde::{Deserialize, Serialize, de, ser::SerializeMap};
use serde_json::value::RawValue;
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::client::CliError;

const MAX_CONFIG: usize = 1024 * 1024;

#[derive(Clone, Copy, ValueEnum)]
pub enum ConnectClient {
    ClaudeCode,
    Codex,
    Cursor,
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
    args: Vec<String>,
}
fn json_server(executable: &str, state_dir: &str) -> JsonServer {
    JsonServer {
        command: executable.into(),
        args: vec!["--state-dir".into(), state_dir.into()],
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
fn prepare(
    client: ConnectClient,
    original: &[u8],
    executable: &str,
    state_dir: &str,
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
            t.len() == 2
                && t.get("command").and_then(Item::as_str) == Some(executable)
                && t.get("args").and_then(Item::as_array).is_some_and(|args| {
                    args.len() == 2
                        && args.get(0).and_then(toml_edit::Value::as_str) == Some("--state-dir")
                        && args.get(1).and_then(toml_edit::Value::as_str) == Some(state_dir)
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
        server["args"] = value(Array::from_iter(["--state-dir", state_dir]));
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

fn name(value: &std::ffi::OsStr) -> Result<CString, CliError> {
    CString::new(value.as_bytes()).map_err(|_| invalid("configuration path contains NUL"))
}
fn open_at(dir: &File, entry: &CStr, flags: i32, mode: libc::c_uint) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            entry.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn directory(path: &Path) -> Result<File, CliError> {
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")
        .map_err(|e| io_error("cannot open filesystem root", e))?;
    for component in path.components() {
        let part = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(part) => part,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            _ => return Err(invalid("project must have an absolute Unix path")),
        };
        dir = open_at(&dir, &name(part)?, libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(|e| {
            io_error(
                "cannot open project directory without following symlinks",
                e,
            )
        })?;
    }
    Ok(dir)
}
fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn id(file: &File) -> Result<(u64, u64), CliError> {
    file.metadata()
        .map(|m| identity(&m))
        .map_err(|e| io_error("cannot inspect configuration identity", e))
}
fn parent(project: &File, subdir: Option<&str>) -> Result<Option<File>, CliError> {
    match subdir {
        None => project
            .try_clone()
            .map(Some)
            .map_err(|e| io_error("cannot retain project directory", e)),
        Some(part) => match open_at(
            project,
            &name(part.as_ref())?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(dir) => Ok(Some(dir)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(
                "cannot open client directory without following symlinks",
                e,
            )),
        },
    }
}
#[derive(PartialEq)]
struct Snapshot {
    identity: (u64, u64),
    bytes: Vec<u8>,
}
fn read(dir: Option<&File>, target: &CStr) -> Result<Option<Snapshot>, CliError> {
    let Some(dir) = dir else { return Ok(None) };
    let file = match open_at(dir, target, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(io_error(
                "cannot open configuration without following symlinks",
                e,
            ));
        }
    };
    let meta = file
        .metadata()
        .map_err(|e| io_error("cannot inspect configuration", e))?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.len() > MAX_CONFIG as u64
    {
        return Err(invalid(
            "configuration must be an owned regular file no larger than 1 MiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("cannot read configuration", e))?;
    if bytes.len() > MAX_CONFIG {
        return Err(invalid("configuration exceeds 1 MiB"));
    }
    Ok(Some(Snapshot {
        identity: identity(&meta),
        bytes,
    }))
}
fn unchanged(
    path: &Path,
    project: &File,
    subdir: Option<&str>,
    dir: Option<&File>,
    target: &CStr,
    original: &Option<Snapshot>,
) -> Result<(), CliError> {
    let current_project = directory(path)?;
    let current_parent = parent(&current_project, subdir)?;
    if id(&current_project)? != id(project)?
        || current_parent.as_ref().map(id).transpose()? != dir.map(id).transpose()?
        || &read(current_parent.as_ref(), target)? != original
    {
        return Err(invalid(
            "configuration changed after preview; nothing was replaced",
        ));
    }
    Ok(())
}
fn create_sibling(dir: &File, target: &str, role: &str) -> Result<(CString, File), CliError> {
    let mut random = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| invalid("cannot generate a private staging filename"))?;
    let entry = CString::new(format!(
        ".{target}.rekey-{role}-{:032x}",
        u128::from_ne_bytes(random)
    ))
    .expect("static filename has no NUL");
    let file = open_at(
        dir,
        &entry,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(|e| io_error("cannot create exclusive configuration staging file", e))?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io_error(
            &format!(
                "cannot protect configuration staging file; {} may remain",
                entry.to_string_lossy()
            ),
            io::Error::last_os_error(),
        ));
    }
    Ok((entry, file))
}
fn publish(dir: &File, stage: &CStr, target: &CStr, replace: bool) -> io::Result<()> {
    // POSIX rename has no inode-CAS: the immediate recheck detects observed
    // races, but cannot prevent an uncooperative last-instant replacement.
    let rc = unsafe {
        if replace {
            libc::renameat(
                dir.as_raw_fd(),
                stage.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
            )
        } else {
            libc::linkat(
                dir.as_raw_fd(),
                stage.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if !replace && unsafe { libc::unlinkat(dir.as_raw_fd(), stage.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.sync_all()
}

const INSTRUCTIONS: &str = "<!-- rekey:begin -->
## 使用密钥
- 需要调用外部 API、git push 或使用任何凭据时，使用 Rekey：MCP 工具 `list_capabilities` / `call`，或命令 `{rekey} list` / `{rekey} call`。
- 不要向用户索要 API Key，不要读取或写入 .env 中的密钥，不要把密钥写进代码。
- 缺少权限或连接时调用 `request_access` 并说明理由；收到 APPROVAL_REQUIRED 时调用 `await_approval`。
- Agent 写的程序使用 `{rekey} list` 给出的本机服务地址和占位 Key `rekey`。
<!-- rekey:end -->
";

fn marked(original: &[u8], replacement: &str, begin: &str, end: &str) -> Result<Vec<u8>, CliError> {
    let text = std::str::from_utf8(original).map_err(|_| invalid("managed text must be UTF-8"))?;
    let starts: Vec<_> = text.match_indices(begin).map(|(i, _)| i).collect();
    let ends: Vec<_> = text.match_indices(end).map(|(i, _)| i).collect();
    let updated = match (starts.as_slice(), ends.as_slice()) {
        ([], []) if replacement.is_empty() => text.to_owned(),
        ([], []) => format!(
            "{text}{}{replacement}",
            if text.is_empty() || text.ends_with("\n\n") {
                ""
            } else if text.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            }
        ),
        ([start], [finish]) if start < finish => {
            let finish = finish + end.len();
            let finish = finish + usize::from(text[finish..].starts_with('\n'));
            format!("{}{}{}", &text[..*start], replacement, &text[finish..])
        }
        _ => {
            return Err(invalid(
                "Rekey markers are malformed or duplicated; repair them before connecting",
            ));
        }
    };
    Ok(updated.into_bytes())
}

struct Edit {
    root_path: PathBuf,
    root: File,
    subdir: Option<&'static str>,
    filename: &'static str,
    parent: Option<File>,
    original: Option<Snapshot>,
    updated: Vec<u8>,
    before: String,
    after: String,
}
impl Edit {
    fn load(
        root_path: PathBuf,
        subdir: Option<&'static str>,
        filename: &'static str,
    ) -> Result<Self, CliError> {
        let root = directory(&root_path)?;
        let parent = parent(&root, subdir)?;
        let original = read(parent.as_ref(), &name(filename.as_ref())?)?;
        Ok(Self {
            root_path,
            root,
            subdir,
            filename,
            parent,
            original,
            updated: Vec::new(),
            before: String::new(),
            after: String::new(),
        })
    }
    fn bytes(&self) -> &[u8] {
        self.original.as_ref().map_or(&[], |s| &s.bytes)
    }
    fn changed(&self) -> bool {
        self.original
            .as_ref()
            .is_none_or(|s| s.bytes != self.updated)
    }
    fn path(&self) -> PathBuf {
        self.subdir
            .map_or_else(|| self.root_path.clone(), |d| self.root_path.join(d))
            .join(self.filename)
    }
    fn verify(&self) -> Result<(), CliError> {
        unchanged(
            &self.root_path,
            &self.root,
            self.subdir,
            self.parent.as_ref(),
            &name(self.filename.as_ref())?,
            &self.original,
        )
    }
    fn apply(&mut self) -> Result<(), CliError> {
        self.verify()?;
        if self.parent.is_none() {
            let part = name(
                self.subdir
                    .expect("missing parent has a subdirectory")
                    .as_ref(),
            )?;
            if unsafe { libc::mkdirat(self.root.as_raw_fd(), part.as_ptr(), 0o700) } != 0 {
                return Err(io_error(
                    "cannot create client directory",
                    io::Error::last_os_error(),
                ));
            }
            self.root
                .sync_all()
                .map_err(|e| io_error("cannot sync project directory", e))?;
            self.parent = parent(&self.root, self.subdir)?;
        }
        let dir = self
            .parent
            .as_ref()
            .ok_or_else(|| invalid("client directory disappeared"))?;
        let mut retained = Vec::new();
        let result = (|| {
            if let Some(old) = &self.original {
                let (backup, mut file) = create_sibling(dir, self.filename, "backup")?;
                retained.push(backup.to_string_lossy().into_owned());
                file.write_all(&old.bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|e| io_error("cannot sync exact configuration backup", e))?;
            }
            let (stage, mut file) = create_sibling(dir, self.filename, "staging")?;
            retained.push(stage.to_string_lossy().into_owned());
            file.write_all(&self.updated)
                .and_then(|()| file.sync_all())
                .map_err(|e| io_error("cannot sync new configuration", e))?;
            if self.filename == "pre-commit"
                && unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0
            {
                return Err(io_error(
                    "cannot make pre-commit executable",
                    io::Error::last_os_error(),
                ));
            }
            self.verify()?;
            publish(dir, &stage, &name(self.filename.as_ref())?, self.original.is_some()).map_err(|e| io_error("configuration publication or directory sync failed; inspect targets before retrying", e))?;
            retained.pop();
            Ok(())
        })();
        let report = if retained.is_empty() {
            Ok(())
        } else {
            writeln!(
                io::stderr(),
                "Private backup/staging files beside {} (may remain on failure): {}",
                self.path().display(),
                retained.join(", ")
            )
            .map_err(|e| io_error("cannot report backup paths", e))
        };
        result?;
        report
    }
}

pub fn connect(
    client: ConnectClient,
    print: bool,
    project: Option<PathBuf>,
    with_hooks: bool,
    ssh_hosts: Vec<String>,
    state_dir: &Path,
) -> Result<(), CliError> {
    let state_dir = std::path::absolute(state_dir)
        .map_err(|e| io_error("cannot resolve state directory", e))?;
    let state = state_dir
        .to_str()
        .ok_or_else(|| invalid("state directory must be UTF-8"))?;
    let rekey = format!("rekey --state-dir '{}'", state.replace('\'', "'\"'\"'"));
    let instruction_text = INSTRUCTIONS.replace("{rekey}", &rekey);
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
    let mut instructions = Edit::load(project_path, None, client.instruction_file())?;
    instructions.updated = marked(
        instructions.bytes(),
        &instruction_text,
        "<!-- rekey:begin -->",
        "<!-- rekey:end -->",
    )?;
    instructions.before = if instructions
        .bytes()
        .windows(19)
        .any(|s| s == b"<!-- rekey:begin -->")
    {
        "<existing Rekey instructions; values hidden>"
    } else {
        "<no Rekey instructions>"
    }
    .into();
    instructions.after = instruction_text;
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
        let socket = state_dir.join("ssh-agent.sock");
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publish_new_file_never_clobbers_racing_creator() {
        let temp = tempfile::tempdir().unwrap();
        let dir = File::open(temp.path()).unwrap();
        std::fs::write(temp.path().join("stage"), b"new").unwrap();
        std::fs::write(temp.path().join("target"), b"racer").unwrap();
        let error = publish(&dir, c"stage", c"target", false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(temp.path().join("target")).unwrap(), b"racer");
        assert_eq!(std::fs::read(temp.path().join("stage")).unwrap(), b"new");
    }
}
