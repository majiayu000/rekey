//! Project MCP configuration only. No credentials or client processes are involved.
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
    fn session_guidance(self) -> &'static str {
        match self {
            Self::ClaudeCode => {
                "Start with rekey run <profile> --client claude-code -- claude. The Profile must include Anthropic access. Gateway settings and credentials are supplied only to that process."
            }
            Self::Codex => {
                "Start with rekey run <profile> --client codex -- codex. The Profile must include OpenAI Responses access. Gateway settings and credentials are supplied only to that process."
            }
            Self::Cursor => {
                "For MCP access, start with rekey run <profile> -- cursor. Cursor provider settings are not configured."
            }
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
    #[serde(rename = "type")]
    kind: String,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}
fn json_server(client: ConnectClient, executable: &str) -> JsonServer {
    let reference = |key| match client {
        ConnectClient::Cursor => format!("${{env:{key}}}"),
        _ => format!("${{{key}}}"),
    };
    JsonServer {
        kind: "stdio".into(),
        command: executable.into(),
        args: vec![],
        env: ["REKEY_CAPABILITY", "REKEY_AGENT_SOCKET"]
            .into_iter()
            .map(|key| (key.into(), reference(key)))
            .collect(),
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
            t.len() == 3
                && t.get("command").and_then(Item::as_str) == Some(executable)
                && t.get("args")
                    .and_then(Item::as_array)
                    .is_some_and(Array::is_empty)
                && t.get("env_vars").and_then(Item::as_array).is_some_and(|a| {
                    a.len() == 2
                        && a.iter().any(|v| v.as_str() == Some("REKEY_CAPABILITY"))
                        && a.iter().any(|v| v.as_str() == Some("REKEY_AGENT_SOCKET"))
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
        server["args"] = value(Array::new());
        let mut env = Array::new();
        env.push("REKEY_CAPABILITY");
        env.push("REKEY_AGENT_SOCKET");
        server["env_vars"] = value(env);
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
        let server = json_server(client, executable);
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

pub fn connect(
    client: ConnectClient,
    print: bool,
    project: Option<PathBuf>,
) -> Result<(), CliError> {
    let project_path = std::path::absolute(
        project
            .unwrap_or(std::env::current_dir().map_err(|e| io_error("cannot resolve project", e))?),
    )
    .map_err(|e| io_error("cannot resolve project", e))?;
    let executable = std::env::current_exe()
        .map_err(|e| io_error("cannot locate rekey executable", e))?
        .with_file_name("rekey-mcp");
    if !executable
        .metadata()
        .is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
    {
        return Err(invalid("existing sibling rekey-mcp executable is required"));
    }
    let executable = executable
        .to_str()
        .ok_or_else(|| invalid("rekey-mcp path must be UTF-8"))?;
    let (subdir, filename) = client.location();
    let target_path = subdir
        .map_or_else(|| project_path.clone(), |part| project_path.join(part))
        .join(filename);
    let fragment = prepare(client, &[], executable)?.0;
    let mut output = io::stdout().lock();
    let session_guidance = client.session_guidance();
    writeln!(
        output,
        "Target: {}\n{session_guidance}",
        target_path.display()
    )
    .map_err(|e| io_error("cannot write preview", e))?;
    if print {
        output
            .write_all(&fragment)
            .map_err(|e| io_error("cannot write preview", e))?;
        return Ok(());
    }
    let project = directory(&project_path)?;
    let mut dir = parent(&project, subdir)?;
    let target = name(filename.as_ref())?;
    let original = read(dir.as_ref(), &target)?;
    if !matches!(client, ConnectClient::Codex)
        && original.as_ref().is_some_and(|s| s.bytes.is_empty())
    {
        return Err(invalid("existing JSON configuration is empty"));
    }
    let (updated, before, same) = prepare(
        client,
        original.as_ref().map_or(&[], |s| &s.bytes),
        executable,
    )?;
    if updated.len() > MAX_CONFIG {
        return Err(invalid("updated configuration exceeds 1 MiB"));
    }
    if same {
        writeln!(output, "Already configured; no files changed.")
            .map_err(|e| io_error("cannot write result", e))?;
        return Ok(());
    }
    writeln!(
        output,
        "Before (existing rekey fields; values hidden):\n{before}\nAfter (replacement rekey subtree; unrelated entries retained):"
    )
    .map_err(|e| io_error("cannot write preview", e))?;
    output
        .write_all(&fragment)
        .and_then(|()| output.flush())
        .map_err(|e| io_error("cannot write preview", e))?;
    if !io::stdin().is_terminal() {
        return Err(invalid(
            "TTY confirmation is required; use --print to preview without writing",
        ));
    }
    write!(io::stderr(), "Apply project MCP configuration? [y/N] ")
        .map_err(|e| io_error("cannot write confirmation", e))?;
    io::stderr()
        .flush()
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
    unchanged(
        &project_path,
        &project,
        subdir,
        dir.as_ref(),
        &target,
        &original,
    )?;
    if dir.is_none() {
        let part = name(
            subdir
                .expect("missing parent requires subdirectory")
                .as_ref(),
        )?;
        if unsafe { libc::mkdirat(project.as_raw_fd(), part.as_ptr(), 0o700) } != 0 {
            return Err(io_error(
                "cannot create client directory",
                io::Error::last_os_error(),
            ));
        }
        project
            .sync_all()
            .map_err(|e| io_error("cannot sync project directory", e))?;
        dir = parent(&project, subdir)?;
    }
    let dir = dir.ok_or_else(|| invalid("client directory disappeared"))?;
    let mut retained = Vec::new();
    let result = (|| {
        if let Some(old) = &original {
            let (backup, mut file) = create_sibling(&dir, filename, "backup")?;
            retained.push(backup.to_string_lossy().into_owned());
            file.write_all(&old.bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| io_error("cannot sync exact configuration backup", e))?;
        }
        let (stage, mut file) = create_sibling(&dir, filename, "staging")?;
        retained.push(stage.to_string_lossy().into_owned());
        file.write_all(&updated)
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error("cannot sync new configuration", e))?;
        unchanged(
            &project_path,
            &project,
            subdir,
            Some(&dir),
            &target,
            &original,
        )?;
        publish(&dir, &stage, &target, original.is_some()).map_err(|e| io_error("configuration publication, staging cleanup, or final directory sync failed; inspect the target before retrying", e))?;
        retained.pop();
        Ok(())
    })();
    let report = if retained.is_empty() {
        Ok(())
    } else {
        writeln!(
            io::stderr(),
            "Private backup/staging files beside the target (may remain on failure): {}",
            retained.join(", ")
        )
        .map_err(|e| io_error("cannot report backup/staging paths", e))
    };
    result?;
    report?;
    writeln!(output, "Project configuration saved. {session_guidance}")
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
