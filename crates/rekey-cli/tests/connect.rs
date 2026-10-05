//! Temporary project fixtures only; never launch a client or read user config.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

const CANARY: &str = "synthetic-existing-secret-do-not-print";
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_rekey"), bin.join("rekey")).unwrap();
        fs::write(
            bin.join("rekey-mcp"),
            b"synthetic executable; never launched",
        )
        .unwrap();
        fs::set_permissions(bin.join("rekey-mcp"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("project")).unwrap();
        Self {
            _dir: dir,
            root,
            bin,
        }
    }
    fn project(&self) -> PathBuf {
        self.root.join("project")
    }
    fn command(&self, client: &str) -> Command {
        let mut command = Command::new(self.bin.join("rekey"));
        command
            .args(["connect", client, "--project"])
            .arg(self.project())
            .env("REKEY_CAPABILITY", CANARY)
            .env("REKEY_AGENT_SOCKET", CANARY);
        command
    }
    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.project().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
}
fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
static PTY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct Tty {
    _guard: std::sync::MutexGuard<'static, ()>,
    child: Child,
    master: File,
    text: String,
}
impl Tty {
    fn start(mut command: Command) -> Self {
        let guard = PTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        let child = command.spawn().unwrap();
        let mut tty = Self {
            _guard: guard,
            child,
            master,
            text: String::new(),
        };
        let end = Instant::now() + Duration::from_secs(10);
        while !tty.text.contains("[y/N]") {
            assert!(Instant::now() < end, "no prompt: {}", tty.text);
            tty.read();
            assert!(
                tty.child.try_wait().unwrap().is_none(),
                "exited before prompt: {}",
                tty.text
            );
        }
        tty
    }
    fn read(&mut self) {
        let mut fd = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut fd, 1, 100) };
        assert!(result >= 0);
        if result > 0 {
            let mut buffer = [0; 4096];
            match self.master.read(&mut buffer) {
                Ok(n) => self.text.push_str(&String::from_utf8_lossy(&buffer[..n])),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
                Err(e) => panic!("PTY read: {e}"),
            }
        }
    }
    fn finish(mut self, answer: &[u8]) -> (ExitStatus, String) {
        self.master.write_all(answer).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            self.read();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.read();
                return (status, std::mem::take(&mut self.text));
            }
            assert!(
                Instant::now() < end,
                "command did not finish: {}",
                self.text
            );
        }
    }
}
impl Drop for Tty {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }
}
fn siblings(path: &Path, role: &str) -> Vec<PathBuf> {
    fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(&format!(".rekey-{role}-"))
        })
        .collect()
}

#[test]
fn print_all_formats_is_public_and_creates_nothing() {
    let f = Fixture::new();
    for (client, path) in [
        ("claude-code", ".mcp.json"),
        ("cursor", ".cursor/mcp.json"),
        ("codex", ".codex/config.toml"),
    ] {
        let output = f.command(client).arg("--print").output().unwrap();
        assert!(output.status.success(), "{}", output_text(&output));
        let text = output_text(&output);
        assert!(text.contains(f.project().join(path).to_str().unwrap()));
        assert!(text.contains("rekey-mcp"));
        assert!(text.contains("<!-- rekey:begin -->"));
        assert!(!text.contains(CANARY));
        assert!(!text.contains("[y/N]"));
        assert!(!text.contains("REKEY_CAPABILITY"));
        assert!(!text.contains("env_vars"));
        assert!(!f.project().join(path).exists());
    }
    assert_eq!(fs::read_dir(f.project()).unwrap().count(), 0);
}
#[test]
fn nontty_cancel_and_eof_leave_missing_directory_untouched() {
    let f = Fixture::new();
    let output = f.command("cursor").stdin(Stdio::null()).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!f.project().join(".cursor").exists());
    assert!(Tty::start(f.command("cursor")).finish(b"n\n").0.success());
    assert!(!f.project().join(".cursor").exists());
    assert!(Tty::start(f.command("cursor")).finish(b"\x04").0.success());
    assert!(!f.project().join(".cursor").exists());
}
#[test]
fn sigint_before_confirmation_creates_nothing() {
    let f = Fixture::new();
    let mut tty = Tty::start(f.command("codex"));
    assert_eq!(
        unsafe { libc::kill(tty.child.id() as i32, libc::SIGINT) },
        0
    );
    assert!(!tty.child.wait().unwrap().success());
    assert_eq!(fs::read_dir(f.project()).unwrap().count(), 0);
}
#[test]
fn json_replacement_preserves_raw_values_and_exact_private_backup() {
    for client in ["claude-code", "cursor"] {
        let f = Fixture::new();
        let relative = if client == "cursor" {
            ".cursor/mcp.json"
        } else {
            ".mcp.json"
        };
        let original = format!(
            "{{\n  \"large\":9007199254740993,\"fraction\":1.0000000000000001,\"secret\":\"{CANARY}\",\"mcpServers\":{{\"other\":{{\"env\":{{\"TOKEN\":\"{CANARY}\"}}}},\"rekey\":{{\"command\":\"{CANARY}\"}}}}}}\n"
        );
        let path = f.write(relative, original.as_bytes());
        let (status, text) = Tty::start(f.command(client)).finish(b"y\n");
        assert!(status.success(), "{text}");
        assert!(!text.contains(CANARY));
        let bytes = fs::read(&path).unwrap();
        let new = String::from_utf8(bytes.clone()).unwrap();
        assert!(new.contains("9007199254740993"));
        assert!(new.contains("1.0000000000000001"));
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["secret"], CANARY);
        assert_eq!(parsed["mcpServers"]["other"]["env"]["TOKEN"], CANARY);
        let server = &parsed["mcpServers"]["rekey"];
        assert_eq!(server, &serde_json::json!({"command":"rekey-mcp"}));
        let instructions = f.project().join(if client == "claude-code" {
            "CLAUDE.md"
        } else {
            "AGENTS.md"
        });
        let instructions_before = fs::read(&instructions).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&instructions_before)
                .matches("<!-- rekey:begin -->")
                .count(),
            1
        );
        let backups = siblings(&path, "backup");
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), original.as_bytes());
        for p in [&path, &backups[0]] {
            assert_eq!(fs::metadata(p).unwrap().mode() & 0o777, 0o600);
        }
        assert!(siblings(&path, "staging").is_empty());
        let before = fs::metadata(&path).unwrap();
        let output = f.command(client).stdin(Stdio::null()).output().unwrap();
        assert!(output.status.success());
        assert!(!output_text(&output).contains(CANARY));
        let after = fs::metadata(&path).unwrap();
        assert_eq!(
            (before.ino(), before.mtime(), before.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec())
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(siblings(&path, "backup").len(), 1);
    }
}
#[test]
fn codex_retains_comments_other_tables_and_supports_inline_servers() {
    for inline in [false, true] {
        let f = Fixture::new();
        let original = if inline {
            format!(
                "# comment stays\nsecret = \"{CANARY}\"\nlarge = 9007199254740993\nmcp_servers = {{ other = {{ command = \"other\" }}, rekey = {{ command = \"{CANARY}\" }} }}\n"
            )
        } else {
            format!(
                "# comment stays\nsecret = \"{CANARY}\"\nlarge = 9007199254740993\n[mcp_servers.other]\ncommand = \"other\" # keep this\n[mcp_servers.rekey]\ncommand = \"{CANARY}\"\n"
            )
        };
        let path = f.write(".codex/config.toml", original.as_bytes());
        let (status, text) = Tty::start(f.command("codex")).finish(b"yes\n");
        assert!(status.success(), "{text}");
        assert!(!text.contains(CANARY));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("# comment stays"));
        assert!(text.contains("9007199254740993"));
        let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(doc["secret"].as_str(), Some(CANARY));
        assert_eq!(
            doc["mcp_servers"]["other"]["command"].as_str(),
            Some("other")
        );
        assert_eq!(
            doc["mcp_servers"]["rekey"]["command"].as_str(),
            Some("rekey-mcp")
        );
        assert_eq!(
            doc["mcp_servers"]["rekey"].as_table_like().unwrap().len(),
            1
        );
        assert_eq!(
            fs::read(siblings(&path, "backup").pop().unwrap()).unwrap(),
            original.as_bytes()
        );
        assert!(
            f.command("codex")
                .stdin(Stdio::null())
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}
#[test]
fn invalid_duplicate_json_and_non_tables_fail_before_prompt_without_content() {
    let f = Fixture::new();
    for bad in [
        "",
        "// comment\n{}",
        "{",
        "{\"mcpServers\":{},\"mcpServers\":{}}",
        "{\"mcpServers\":{\"rekey\":{},\"rekey\":{}}}",
        "{\"mcpServers\":{\"rekey\":{\"command\":\"a\",\"command\":\"b\"}}}",
        "{\"mcpServers\":{\"rekey\":{\"env\":{\"K\":1,\"K\":2}}}}",
        "{\"mcpServers\":[]}",
    ] {
        let path = f.write(".mcp.json", bad.as_bytes());
        let output = f.command("claude-code").output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
        assert!(!output_text(&output).contains("[y/N]"));
        assert_eq!(fs::read_to_string(path).unwrap(), bad);
    }
    let bad = format!("mcp_servers = \"{CANARY}\"\n");
    let path = f.write(".codex/config.toml", bad.as_bytes());
    let output = f.command("codex").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!output_text(&output).contains(CANARY));
    assert_eq!(fs::read_to_string(path).unwrap(), bad);
}
#[test]
fn symlink_target_parent_and_project_are_rejected() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let sentinel = outside.join("sentinel");
    fs::write(&sentinel, b"{}").unwrap();
    symlink(&sentinel, f.project().join(".mcp.json")).unwrap();
    assert!(!f.command("claude-code").output().unwrap().status.success());
    symlink(&outside, f.project().join(".cursor")).unwrap();
    assert!(!f.command("cursor").output().unwrap().status.success());
    let project_link = f.root.join("alias");
    symlink(f.project(), &project_link).unwrap();
    let output = Command::new(f.bin.join("rekey"))
        .args(["connect", "codex", "--project"])
        .arg(project_link)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(sentinel).unwrap(), b"{}");
    assert_eq!(fs::read_dir(outside).unwrap().count(), 1);
}
#[test]
fn oversized_and_nonregular_configs_are_rejected_without_waiting() {
    let f = Fixture::new();
    let path = f.write(".mcp.json", &vec![b' '; 1024 * 1024 + 1]);
    assert_eq!(
        f.command("claude-code").output().unwrap().status.code(),
        Some(2)
    );
    fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert_eq!(
        f.command("claude-code").output().unwrap().status.code(),
        Some(2)
    );
}
#[test]
fn post_preview_content_inode_and_parent_changes_are_not_overwritten() {
    for race in ["content", "inode", "parent", "creator"] {
        let f = Fixture::new();
        let path = f.project().join(".cursor/mcp.json");
        if race != "creator" {
            f.write(".cursor/mcp.json", b"{}");
        }
        let tty = Tty::start(f.command("cursor"));
        match race {
            "content" => fs::write(&path, b"{\"changed\":true}").unwrap(),
            "inode" => {
                let tmp = path.with_extension("replacement");
                fs::write(&tmp, b"{}").unwrap();
                fs::rename(tmp, &path).unwrap();
            }
            "parent" => {
                fs::rename(path.parent().unwrap(), f.project().join("old-dir")).unwrap();
                f.write(".cursor/mcp.json", b"{}");
            }
            _ => {
                f.write(".cursor/mcp.json", b"{\"racer\":true}");
            }
        }
        let wanted = fs::read(&path).unwrap();
        let (status, text) = tty.finish(b"y\n");
        assert!(!status.success(), "{race}: {text}");
        assert!(text.contains("changed after preview"));
        assert_eq!(fs::read(&path).unwrap(), wanted);
        assert!(siblings(&path, "backup").is_empty());
        assert!(siblings(&path, "staging").is_empty());
    }
}
#[test]
fn fresh_target_creation_is_private_and_does_not_require_a_manifest() {
    let f = Fixture::new();
    let (status, text) = Tty::start(f.command("cursor")).finish(b"y\n");
    assert!(status.success(), "{text}");
    assert!(!text.contains(CANARY));
    let target = f.project().join(".cursor/mcp.json");
    assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(target.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    assert!(siblings(&target, "backup").is_empty());
    assert!(siblings(&target, "staging").is_empty());
    assert!(f.command("cursor").output().unwrap().status.success());
}
#[test]
fn stable_command_does_not_depend_on_a_developer_binary_path() {
    let f = Fixture::new();
    fs::remove_file(f.bin.join("rekey-mcp")).unwrap();
    let output = f.command("claude-code").arg("--print").output().unwrap();
    assert!(output.status.success());
    assert!(output_text(&output).contains("rekey-mcp"));
    assert!(!output_text(&output).contains(f.bin.to_str().unwrap()));
    assert_eq!(fs::read_dir(f.project()).unwrap().count(), 0);
}

#[test]
fn default_project_is_cwd_and_no_confirmation_shortcut_exists() {
    let f = Fixture::new();
    let output = Command::new(f.bin.join("rekey"))
        .args(["connect", "claude-code", "--print"])
        .current_dir(f.project())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output_text(&output).contains(f.project().join(".mcp.json").to_str().unwrap()));
    assert_eq!(
        f.command("claude-code")
            .arg("--yes")
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(fs::read_dir(f.project()).unwrap().count(), 0);
}
#[test]
fn cancelling_existing_subtree_keeps_exact_original_without_backup() {
    let f = Fixture::new();
    let old = format!("{{\"mcpServers\":{{\"rekey\":{{\"command\":\"{CANARY}\"}}}}}}");
    let path = f.write(".mcp.json", old.as_bytes());
    let (status, text) = Tty::start(f.command("claude-code")).finish(b"no\n");
    assert!(status.success());
    assert!(!text.contains(CANARY));
    assert_eq!(fs::read(&path).unwrap(), old.as_bytes());
    assert!(siblings(&path, "backup").is_empty());
    assert!(siblings(&path, "staging").is_empty());
}
#[test]
fn preview_shows_removed_fields_before_replacement_without_printing_old_credentials() {
    for (client, relative, old) in [
        (
            "claude-code",
            ".mcp.json",
            format!(
                "{{\"mcpServers\":{{\"rekey\":{{\"command\":\"{CANARY}\",\"legacy\":\"{CANARY}\",\"env\":{{\"TOKEN\":\"{CANARY}\"}}}}}}}}"
            ),
        ),
        (
            "cursor",
            ".cursor/mcp.json",
            format!(
                "{{\"mcpServers\":{{\"rekey\":{{\"command\":\"{CANARY}\",\"legacy\":\"{CANARY}\"}}}}}}"
            ),
        ),
        (
            "codex",
            ".codex/config.toml",
            format!("[mcp_servers.rekey]\ncommand=\"{CANARY}\"\nlegacy=\"{CANARY}\"\n"),
        ),
    ] {
        let f = Fixture::new();
        let path = f.write(relative, old.as_bytes());
        let (status, text) = Tty::start(f.command(client)).finish(b"n\n");
        assert!(status.success(), "{text}");
        let (before, after) = text.split_once("+++ after").unwrap();
        assert!(before.contains("--- before"));
        assert!(before.contains("\"legacy\""));
        assert!(before.contains("\"command\""));
        assert!(before.contains("<existing value hidden>"));
        assert!(!after.contains("legacy"));
        assert!(after.contains("rekey-mcp"));
        assert!(!text.contains(CANARY));
        assert_eq!(fs::read(&path).unwrap(), old.as_bytes());
        assert!(siblings(&path, "backup").is_empty());
    }
}
#[test]
fn instructions_preserve_unrelated_text_and_replace_markers_once() {
    let f = Fixture::new();
    let old = "User rules before\n\n<!-- rekey:begin -->\nold instructions\n<!-- rekey:end -->\n\nUser rules after\n";
    let path = f.write("AGENTS.md", old.as_bytes());
    let (status, text) = Tty::start(f.command("codex")).finish(b"y\n");
    assert!(status.success(), "{text}");
    let new = fs::read_to_string(&path).unwrap();
    assert!(new.starts_with("User rules before\n\n"));
    assert!(new.ends_with("\nUser rules after\n"));
    assert!(!new.contains("old instructions"));
    assert_eq!(new.matches("<!-- rekey:begin -->").count(), 1);
    assert_eq!(
        fs::read(siblings(&path, "backup").pop().unwrap()).unwrap(),
        old.as_bytes()
    );
    assert!(f.command("codex").output().unwrap().status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), new);
}
#[test]
fn malformed_instruction_markers_and_instruction_races_fail_before_any_write() {
    let f = Fixture::new();
    let instructions = f.write("CLAUDE.md", b"<!-- rekey:begin -->\nmissing end");
    let output = f.command("claude-code").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!f.project().join(".mcp.json").exists());
    fs::write(&instructions, b"rules").unwrap();
    let tty = Tty::start(f.command("claude-code"));
    fs::write(&instructions, b"rules changed after preview").unwrap();
    let (status, text) = tty.finish(b"y\n");
    assert!(!status.success(), "{text}");
    assert!(!f.project().join(".mcp.json").exists());
    assert!(siblings(&instructions, "backup").is_empty());
}
#[test]
fn command_only_codex_config_is_a_semantic_noop_after_instructions_installed() {
    let f = Fixture::new();
    let (status, text) = Tty::start(f.command("codex")).finish(b"y\n");
    assert!(status.success(), "{text}");
    let old = "# preserve this exact layout\n[mcp_servers.rekey]\ncommand='rekey-mcp'\n";
    let path = f.write(".codex/config.toml", old.as_bytes());
    let output = f.command("codex").output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(fs::read(&path).unwrap(), old.as_bytes());
    assert!(siblings(&path, "backup").is_empty());
}

#[test]
fn optional_hook_preserves_existing_shell_and_uses_the_staged_scanner() {
    let f = Fixture::new();
    assert!(
        Command::new("git")
            .args(["init"])
            .current_dir(f.project())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let path = f.write(
        ".git/hooks/pre-commit",
        b"#!/bin/sh\n# existing operator hook\ntrue\n",
    );
    let original = fs::read(&path).unwrap();
    let mut command = f.command("claude-code");
    command.arg("--with-hooks");
    let (status, text) = Tty::start(command).finish(b"y\n");
    assert!(status.success(), "{text}");
    let new = fs::read_to_string(&path).unwrap();
    assert!(new.starts_with("#!/bin/sh\n# existing operator hook\ntrue\n"));
    assert!(new.contains("rekey scan --staged || exit $?"));
    assert_eq!(new.matches("# rekey:begin").count(), 1);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::read(siblings(&path, "backup").pop().unwrap()).unwrap(),
        original
    );
    let mut command = f.command("claude-code");
    command.arg("--with-hooks");
    assert!(command.output().unwrap().status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), new);
}
