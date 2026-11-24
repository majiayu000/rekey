//! Shared fixtures for the `rekey connect` / `rekey hooks` black-box tests.
//! Temporary projects and homes only; never launch a client or read user config.
#![allow(dead_code)]
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
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
            // PATH finds the fixture's own binaries first, never a host install.
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
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
/// Liveness bound for one PTY child wait. A passing run returns as soon as the
/// prompt or exit arrives; the bound only turns a hang into a failure. Starting
/// a freshly copied binary can take many seconds on a loaded host.
const PTY_LIVENESS: Duration = Duration::from_secs(60);
/// Wall-clock fixture bounds scale with `REKEY_TEST_TIMEOUT_SCALE` (a positive
/// integer, default 1). Product deadlines are never scaled.
fn test_timeout(base: Duration) -> Duration {
    let scale = match std::env::var("REKEY_TEST_TIMEOUT_SCALE") {
        Err(std::env::VarError::NotPresent) => 1,
        value => value
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .expect("REKEY_TEST_TIMEOUT_SCALE must be a positive integer"),
    };
    base.checked_mul(scale).expect("scaled test timeout")
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
        // A terminal user's Ctrl-C, even when the harness itself ignores SIGINT
        // (a background job in a script). `signal` is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let mut tty = Self {
            _guard: guard,
            child,
            master,
            text: String::new(),
        };
        let started = Instant::now();
        let limit = test_timeout(PTY_LIVENESS);
        while !tty.text.contains("[y/N]") {
            let waited = started.elapsed();
            assert!(waited < limit, "no prompt after {waited:?}: {}", tty.text);
            tty.read(100);
            assert!(
                tty.child.try_wait().unwrap().is_none(),
                "exited before prompt: {}",
                tty.text
            );
        }
        tty
    }
    /// Appends what the child wrote, waiting at most `wait_ms` for it; returns
    /// the number of bytes read (0 on timeout or once the child side closed).
    fn read(&mut self, wait_ms: i32) -> usize {
        let mut fd = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut fd, 1, wait_ms) };
        assert!(result >= 0);
        if result == 0 {
            return 0;
        }
        let mut buffer = [0; 4096];
        match self.master.read(&mut buffer) {
            Ok(n) => {
                self.text.push_str(&String::from_utf8_lossy(&buffer[..n]));
                n
            }
            Err(e) if e.raw_os_error() == Some(libc::EIO) => 0,
            Err(e) => panic!("PTY read: {e}"),
        }
    }
    pub fn finish(mut self, answer: &[u8]) -> (ExitStatus, String) {
        self.master.write_all(answer).unwrap();
        self.exit()
    }
    /// Waits, within the liveness bound, for the child to exit and drains its output.
    pub fn exit(mut self) -> (ExitStatus, String) {
        let started = Instant::now();
        let limit = test_timeout(PTY_LIVENESS);
        loop {
            self.read(100);
            if let Some(status) = self.child.try_wait().unwrap() {
                // A loaded host can run the child to exit between two polls.
                while self.read(0) > 0 {}
                return (status, std::mem::take(&mut self.text));
            }
            let waited = started.elapsed();
            assert!(
                waited < limit,
                "command did not finish after {waited:?}: {}",
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
/// Backup or staging files that belong to `path` itself, not to its neighbours.
pub fn siblings(path: &Path, role: &str) -> Vec<PathBuf> {
    let prefix = format!(
        ".{}.rekey-{role}-",
        path.file_name().unwrap().to_string_lossy()
    );
    fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&prefix)
        })
        .collect()
}
