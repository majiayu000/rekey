//! Real `rekeyd` and `rekey` binaries with an activated signed Connection.
//! A Git pre-commit hook that runs `rekey scan --staged` exactly as
//! `rekey connect --with-hooks` writes it blocks complete canary variants
//! without printing them; cannot-scan states pass with a warning; the SCAN
//! byte budget is shared per system user.
//!
//! Requires `rekeyd` and `rekey-policy-sign` beside `rekey`
//! (`cargo test --workspace` builds them). Synthetic vault and canary only.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{Channel, FRAME_HEADER_LEN, FrameHeader, agent_msg, resp_msg};
use serde_json::{Value, json};

const PASSWORD: &str = "scan daemon horse battery staple";
const CANARY: &str = "rekey-d1-scan-canary-7f3a9c2e5b41";
const CONNECTION: &str = "github-pat";
const FRAME: usize = 10 * 1024 * 1024;

fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_rekey"))
        .parent()
        .unwrap()
        .to_owned()
}

fn json_escaped(value: &str) -> String {
    value.bytes().map(|byte| format!("\\u{byte:04x}")).collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Parses the daemon's `Retry after <UTC date time> UTC.` guidance.
fn reset_ms(next: &str) -> i64 {
    let stamp = next
        .strip_prefix("Retry after ")
        .and_then(|rest| rest.strip_suffix(" +00:00:00 UTC."))
        .unwrap_or_else(|| panic!("unexpected next: {next}"));
    let (date, clock) = stamp.split_once(' ').unwrap();
    let d: Vec<i64> = date.split('-').map(|p| p.parse().unwrap()).collect();
    let (hms, fraction) = clock.split_once('.').unwrap_or((clock, "0"));
    let t: Vec<i64> = hms.split(':').map(|p| p.parse().unwrap()).collect();
    let millis: i64 = format!("{fraction:0<3}")[..3].parse().unwrap();
    let (y, m) = if d[1] <= 2 {
        (d[0] - 1, d[1] + 9)
    } else {
        (d[0], d[1] - 3)
    };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let days =
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + d[2] - 1 - 719_468;
    ((days * 24 + t[0]) * 60 + t[1]) * 60_000 + t[2] * 1000 + millis
}

fn warning(output: &Output, kind: &str) -> Value {
    text(&output.stderr)
        .lines()
        .chain(text(&output.stdout).lines())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["warnings"] == json!([kind]))
        .unwrap_or_else(|| panic!("no {kind} warning: {}", text(&output.stderr)))
}

struct Daemon {
    dir: tempfile::TempDir,
    state: PathBuf,
    project: PathBuf,
    child: Option<Child>,
    transcript: Vec<u8>,
}

impl Daemon {
    fn start() -> Self {
        for tool in ["rekeyd", "rekey-policy-sign"] {
            assert!(
                bin_dir().join(tool).exists(),
                "{tool} not built; run `cargo build --workspace` first"
            );
        }
        // A short state path keeps the Unix socket paths below SUN_LEN.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("s");
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let mut daemon = Self {
            dir,
            state,
            project,
            child: None,
            transcript: Vec::new(),
        };
        let input = format!("{PASSWORD}\n");
        daemon.rekey_ok(&["init", "--mode", "personal", "--password-stdin"], &input);
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        std::fs::write(
            daemon.state.join("service.json"),
            json!({"port": port}).to_string(),
        )
        .unwrap();
        let log = std::fs::File::create(daemon.dir.path().join("serve.log")).unwrap();
        let child = Command::new(bin_dir().join("rekeyd"))
            .arg("serve")
            .arg("--state-dir")
            .arg(&daemon.state)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        daemon.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !(daemon.state.join("runtime/admin.sock").exists() && daemon.agent_socket().exists())
        {
            assert!(Instant::now() < deadline, "rekeyd did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        daemon.rekey_ok(&["unlock", "--password-stdin"], &input);
        daemon.git(&["init", "-q"]);
        let state = daemon.state.to_str().unwrap().replace('\'', "'\"'\"'");
        let hook = daemon.project.join(".git/hooks/pre-commit");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\n# rekey:begin\nrekey --state-dir '{state}' scan --staged </dev/null || exit $?\n# rekey:end\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        daemon
    }

    fn agent_socket(&self) -> PathBuf {
        self.state.join("runtime/agent.sock")
    }

    fn record(&mut self, output: Output) -> Output {
        self.transcript.extend_from_slice(&output.stdout);
        self.transcript.extend_from_slice(&output.stderr);
        output
    }

    fn run(&mut self, program: &Path, args: &[&str], input: &str, human: bool) -> Output {
        let mut child = Command::new(program)
            .args(args)
            .current_dir(&self.project)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true")
            .env("GIT_AUTHOR_NAME", "Rekey Test")
            .env("GIT_AUTHOR_EMAIL", "rekey-test@example.invalid")
            .env("GIT_COMMITTER_NAME", "Rekey Test")
            .env("GIT_COMMITTER_EMAIL", "rekey-test@example.invalid")
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("REKEY_OUTPUT", if human { "human" } else { "json" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A command may exit before it reads stdin.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        let output = child.wait_with_output().unwrap();
        self.record(output)
    }

    fn rekey(&mut self, args: &[&str], input: &str) -> Output {
        let state = self.state.to_str().unwrap().to_owned();
        let mut all = vec!["--state-dir", state.as_str()];
        all.extend_from_slice(args);
        self.run(&bin_dir().join("rekey"), &all, input, false)
    }

    fn rekey_ok(&mut self, args: &[&str], input: &str) -> Value {
        let output = self.rekey(args, input);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
    }

    fn git(&mut self, args: &[&str]) -> Output {
        let output = self.run(Path::new("git"), args, "", false);
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            text(&output.stderr)
        );
        output
    }

    fn stage(&mut self, name: &str, contents: &str) {
        std::fs::write(self.project.join(name), contents).unwrap();
        self.git(&["add", name]);
    }

    /// Stages one file and runs `git commit`, which runs the pre-commit hook.
    fn commit(&mut self, name: &str, contents: &str, human: bool) -> Output {
        self.stage(name, contents);
        self.run(Path::new("git"), &["commit", "-q", "-m", name], "", human)
    }

    fn committed(&mut self) -> String {
        text(&self.git(&["ls-tree", "-r", "--name-only", "HEAD"]).stdout)
    }

    fn add_connection(&mut self) -> String {
        let input = format!("{PASSWORD}\n{CANARY}\n");
        self.rekey_ok(&["add", CONNECTION, "--stdin-secrets"], &input);
        let listed = self.rekey_ok(&["credential", "list"], "");
        listed["credentials"][0]["id"].as_str().unwrap().to_owned()
    }

    fn revoke(&mut self, id: &str) {
        self.rekey_ok(
            &["credential", "revoke", id, "--password-stdin"],
            &format!("{PASSWORD}\n"),
        );
    }

    fn shutdown(&mut self) {
        self.rekey_ok(&["shutdown", "--password-stdin"], &format!("{PASSWORD}\n"));
        let mut child = self.child.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "rekeyd did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// No command output, daemon log or vault file carries the canary.
    fn assert_never_printed(&self) {
        let log = std::fs::read(self.dir.path().join("serve.log")).unwrap();
        let truncated = &CANARY[..CANARY.len() - 1];
        let canary = CANARY.as_bytes();
        let variants = [
            truncated.to_owned(),
            BASE64.encode(canary),
            BASE64_NOPAD.encode(canary),
            BASE64URL.encode(canary),
            BASE64URL_NOPAD.encode(canary),
            HEXLOWER.encode(canary),
            HEXUPPER.encode(canary),
            json_escaped(CANARY),
        ];
        let mut files = vec![log, self.transcript.clone()];
        let mut pending = vec![self.state.clone()];
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    files.push(bytes);
                }
            }
        }
        for bytes in &files {
            for variant in &variants {
                let needle = variant.as_bytes();
                assert!(!bytes.windows(needle.len()).any(|part| part == needle));
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn hook_blocks_complete_canary_variants_and_passes_cannot_scan_states_with_a_warning() {
    let mut d = Daemon::start();
    // No signed policy yet: nothing can be scanned and the commit proceeds.
    let first = d.commit("first.txt", "clean\n", false);
    assert!(first.status.success(), "{}", text(&first.stderr));
    assert_eq!(
        warning(&first, "SCAN_NOT_PERFORMED")["code"],
        "NOT_CONFIGURED"
    );

    let credential = d.add_connection();
    let leaks = [
        ("raw.txt", format!("token = {CANARY}\n")),
        (
            "encoded.txt",
            format!("{}\n", BASE64.encode(CANARY.as_bytes())),
        ),
        (
            "escaped.json",
            format!("{{\"token\":\"{}\"}}\n", json_escaped(CANARY)),
        ),
    ];
    for (name, contents) in &leaks {
        let human = name.ends_with(".json");
        let blocked = d.commit(name, contents, human);
        assert!(!blocked.status.success(), "{name} must be blocked");
        // Git forwards hook stdout to stderr; read both.
        let stderr = text(&blocked.stderr) + &text(&blocked.stdout);
        if human {
            assert!(
                stderr.contains(&format!(
                    "检测到 {CONNECTION} 的密钥出现在 {name}:1；请改用 rekey call 或本机服务地址"
                )),
                "{stderr}"
            );
        } else {
            assert!(stderr.contains("LEAK_DETECTED"), "{stderr}");
            assert!(stderr.contains(&format!("\"connection\": \"{CONNECTION}\"")));
        }
        d.git(&["rm", "--cached", "-q", name]);
        std::fs::remove_file(d.project.join(name)).unwrap();
    }
    // A partial value is not a complete match.
    let partial = d.commit("partial.txt", &CANARY[..CANARY.len() - 1], false);
    assert!(partial.status.success(), "{}", text(&partial.stderr));

    d.rekey_ok(&["lock"], "");
    let locked = d.commit("locked.txt", "clean\n", false);
    assert!(locked.status.success(), "{}", text(&locked.stderr));
    assert_eq!(warning(&locked, "SCAN_NOT_PERFORMED")["code"], "LOCKED");
    d.stage("strict.txt", "clean\n");
    let strict = d.rekey(&["scan", "--staged", "--strict"], "");
    assert_eq!(strict.status.code(), Some(3), "{}", text(&strict.stderr));
    d.rekey_ok(&["unlock", "--password-stdin"], &format!("{PASSWORD}\n"));

    // A revoked credential is skipped and counted; the scan itself succeeds.
    d.revoke(&credential);
    let revoked = d.rekey(&["scan", "--stdin"], CANARY);
    assert!(revoked.status.success(), "{}", text(&revoked.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&revoked.stdout).unwrap(),
        json!([])
    );
    let skipped = warning(&revoked, "SCAN_CREDENTIALS_UNAVAILABLE");
    assert!(
        skipped["message"]
            .as_str()
            .unwrap()
            .contains("1 个凭据不可用")
    );

    d.shutdown();
    let stopped = d.commit("stopped.txt", "clean\n", false);
    assert!(stopped.status.success(), "{}", text(&stopped.stderr));
    assert_eq!(
        warning(&stopped, "SCAN_NOT_PERFORMED")["code"],
        "IPC_UNAVAILABLE"
    );

    let committed = d.committed();
    for name in [
        "first.txt",
        "partial.txt",
        "locked.txt",
        "strict.txt",
        "stopped.txt",
    ] {
        assert!(committed.lines().any(|line| line == name), "{committed}");
    }
    for (name, _) in &leaks {
        assert!(!committed.lines().any(|line| line == *name), "{committed}");
    }
    d.assert_never_printed();
}

/// A symlink replaced by a regular file is a type change (`T`); the hook
/// scans it like any other staged change.
#[test]
fn hook_scans_a_symlink_replaced_by_a_file() {
    let mut d = Daemon::start();
    d.add_connection();
    std::os::unix::fs::symlink("target.txt", d.project.join("link")).unwrap();
    d.git(&["add", "link"]);
    let base = d.commit("target.txt", "clean\n", false);
    assert!(base.status.success(), "{}", text(&base.stderr));
    std::fs::remove_file(d.project.join("link")).unwrap();
    let blocked = d.commit("link", &format!("token = {CANARY}\n"), false);
    assert!(!blocked.status.success(), "a type change must be scanned");
    let output = text(&blocked.stderr) + &text(&blocked.stdout);
    assert!(output.contains("LEAK_DETECTED"), "{output}");
    assert!(output.contains("\"path\": \"link\""), "{output}");
    d.assert_never_printed();
}

/// A staged submodule pointer (gitlink) has no content in this repository,
/// so it is not scan input and never blocks the commit.
#[test]
fn hook_commits_a_staged_submodule_pointer() {
    let mut d = Daemon::start();
    d.add_connection();
    let base = d.commit("base.txt", "clean\n", false);
    assert!(base.status.success(), "{}", text(&base.stderr));
    let head = text(&d.git(&["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_owned();
    let entry = format!("160000,{head},vendor/sub");
    d.git(&["update-index", "--add", "--cacheinfo", &entry]);
    let pointer = d.commit("next.txt", "clean\n", false);
    assert!(pointer.status.success(), "{}", text(&pointer.stderr));
    let committed = d.committed();
    assert!(
        committed.lines().any(|line| line == "vendor/sub"),
        "{committed}"
    );
    assert!(
        committed.lines().any(|line| line == "next.txt"),
        "{committed}"
    );
}

/// Sends one SCAN frame directly; returns the response type, metadata and body.
fn raw_scan(socket: &Path, body: &[u8]) -> (u16, Value, Vec<u8>) {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let metadata = br#"{"path":"budget.bin"}"#;
    let header = FrameHeader {
        channel: Channel::Agent,
        flags: 0,
        message_type: agent_msg::SCAN,
        request_id: RequestId::new_random(),
        metadata_len: metadata.len() as u32,
        body_len: body.len() as u32,
    };
    stream.write_all(&header.encode()).unwrap();
    stream.write_all(metadata).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = [0; FRAME_HEADER_LEN];
    stream.read_exact(&mut raw).unwrap();
    let response = FrameHeader::decode(&raw).unwrap();
    assert_eq!(response.request_id, header.request_id);
    let mut metadata = vec![0; response.metadata_len as usize];
    let mut body = vec![0; response.body_len as usize];
    stream.read_exact(&mut metadata).unwrap();
    stream.read_exact(&mut body).unwrap();
    (
        response.message_type,
        serde_json::from_slice(&metadata).unwrap(),
        body,
    )
}

/// Eight connections send 10 MiB frames until each is refused.
fn exhaust(socket: &Path) -> (usize, Vec<i64>) {
    let body = Arc::new(vec![b' '; FRAME]);
    let accepted = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let (socket, body, accepted) =
                (socket.to_owned(), Arc::clone(&body), Arc::clone(&accepted));
            std::thread::spawn(move || {
                loop {
                    let (kind, metadata, response) = raw_scan(&socket, &body);
                    if kind == resp_msg::OK {
                        let report: Value = serde_json::from_slice(&response).unwrap();
                        assert_eq!(
                            report,
                            json!({"findings": [], "unavailable_credentials": 1})
                        );
                        accepted.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    assert_eq!(metadata["code"], "RATE_LIMITED", "{metadata}");
                    assert_eq!(
                        metadata["message"],
                        "scan byte budget for this system user is exhausted"
                    );
                    return reset_ms(metadata["next"].as_str().unwrap());
                }
            })
        })
        .collect();
    let resets = workers.into_iter().map(|w| w.join().unwrap()).collect();
    (accepted.load(Ordering::SeqCst), resets)
}

#[test]
fn scan_byte_budget_is_per_system_user_and_renamed_callers_share_it() {
    let mut d = Daemon::start();
    // Matching 600 MiB in a debug build outlasts the one-minute window. The
    // revoked credential is skipped, so only the byte budget is exercised.
    let credential = d.add_connection();
    d.revoke(&credential);
    let mut reset = None;
    for _ in 0..3 {
        let started = unix_ms();
        let (accepted, resets) = exhaust(&d.agent_socket());
        let finished = unix_ms();
        // Within one window exactly 600 MiB of 10 MiB frames is admitted.
        if finished - started < 59_000 {
            assert_eq!(accepted, 60);
        } else {
            assert!(accepted >= 60, "{accepted}");
        }
        for value in &resets {
            assert!((value - resets[0]).abs() <= 2, "{resets:?}");
        }
        assert!(
            resets[0] >= started + 59_000 && resets[0] <= finished + 60_001,
            "{started} {resets:?} {finished}"
        );
        if resets[0] - unix_ms() >= 15_000 {
            reset = Some(resets[0]);
            break;
        }
        // Too little of the window is left for the checks below; start over.
        std::thread::sleep(Duration::from_millis(
            (resets[0] - unix_ms()).max(0) as u64 + 200,
        ));
    }
    let reset = reset.expect("could not exhaust the budget with 15 s of the window left");

    // Copies named like known Agents get different caller labels; the budget
    // is still the same system user's window.
    let renamed = d.dir.path().join("renamed");
    std::fs::create_dir(&renamed).unwrap();
    for name in ["codex", "claude"] {
        let copy = renamed.join(name);
        std::fs::copy(bin_dir().join("rekey"), &copy).unwrap();
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = d.state.to_str().unwrap().to_owned();
        let output = d.run(
            &copy,
            &["--state-dir", &state, "scan", "--stdin"],
            "x",
            false,
        );
        assert_eq!(output.status.code(), Some(4), "{}", text(&output.stderr));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["code"], "RATE_LIMITED");
        assert!((reset_ms(error["next"].as_str().unwrap()) - reset).abs() <= 2);
    }

    let limited = d.commit("limited.txt", "clean\n", false);
    assert!(limited.status.success(), "{}", text(&limited.stderr));
    let skipped = warning(&limited, "SCAN_NOT_PERFORMED");
    assert_eq!(skipped["code"], "RATE_LIMITED");
    assert!(skipped["next"].as_str().unwrap().contains("Retry after "));
    d.stage("strict.txt", "clean\n");
    let strict = d.rekey(&["scan", "--staged", "--strict"], "");
    assert_eq!(strict.status.code(), Some(4), "{}", text(&strict.stderr));
    d.shutdown();
    d.assert_never_printed();
}
