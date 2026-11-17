//! Shared fixtures for the `rekey connect` / `rekey hooks` black-box tests.
//! Temporary projects and homes only; never launch a client or read user config.
#![allow(dead_code)]
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

pub const CANARY: &str = "synthetic-existing-secret-do-not-print";
pub const LOCAL_PATH_WARNING: &str =
    "Warning: this file will contain the absolute path of a non-default vault; do not commit it.";
pub struct Fixture {
    _dir: tempfile::TempDir,
    pub root: PathBuf,
    pub bin: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
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
        fs::create_dir(root.join("home")).unwrap();
        Self {
            _dir: dir,
            root,
            bin,
        }
    }
    pub fn project(&self) -> PathBuf {
        self.root.join("project")
    }
    /// Isolated HOME; its `.rekey` is the default vault for commands run here.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }
    pub fn command(&self, client: &str) -> Command {
        self.command_for_state(client, &self.root.join("vault"))
    }
    pub fn command_for_state(&self, client: &str, state: &Path) -> Command {
        let mut command = self.rekey(&["connect", client]);
        command.arg("--state-dir").arg(state);
        command
    }
    /// `rekey connect` without --state-dir, so the isolated HOME's default vault applies.
    pub fn command_default(&self, client: &str) -> Command {
        self.rekey(&["connect", client])
    }
    /// `rekey hooks <action>` for the fixture project with the fixture vault.
    pub fn hooks(&self, action: &str) -> Command {
        let mut command = self.rekey(&["hooks", action]);
        command.arg("--state-dir").arg(self.root.join("vault"));
        command
    }
    fn rekey(&self, words: &[&str]) -> Command {
        let mut command = Command::new(self.bin.join("rekey"));
        command
            .args(words)
            .arg("--project")
            .arg(self.project())
            .env("HOME", self.home())
            // Keep hook discovery inside the fixture, including Git spawned by the CLI.
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true")
            .env("REKEY_CAPABILITY", CANARY)
            .env("REKEY_AGENT_SOCKET", CANARY);
        command
    }
    pub fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.project().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
    pub fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(self.project())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    pub fn git_init(&self) {
        let output = self.git(&["init", "-q"]);
        assert!(output.status.success(), "{}", output_text(&output));
    }
}
pub fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
static PTY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub struct Tty {
    _guard: std::sync::MutexGuard<'static, ()>,
    pub child: Child,
    master: File,
    text: String,
}
impl Tty {
    pub fn start(mut command: Command) -> Self {
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
    pub fn finish(mut self, answer: &[u8]) -> (ExitStatus, String) {
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
/// Confirm one interactive run and require success.
pub fn confirm(command: Command) -> String {
    let (status, text) = Tty::start(command).finish(b"y\n");
    assert!(status.success(), "{text}");
    text
}
pub fn siblings(path: &Path, role: &str) -> Vec<PathBuf> {
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
