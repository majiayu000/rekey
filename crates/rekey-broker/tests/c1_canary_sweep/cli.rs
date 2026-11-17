//! CLI surface: the workspace `rekey` binary against the in-process daemon.
//! Agent commands, one admin status view and the offline `connect --print`.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::Value;

use super::{CANARY, Fixture, Sweep, common, reflections};

const CALL_ISSUE: &[&str] = &[
    "call",
    "github.get_issue",
    "--owner",
    "octo",
    "--repo",
    "widgets",
    "--number",
    "7",
];
const PATH: &str = "/repos/octo/widgets/issues/7";

fn rekey_bin() -> PathBuf {
    let bin = Path::new(env!("CARGO_BIN_EXE_rekeyd")).with_file_name("rekey");
    assert!(
        bin.is_file(),
        "the C1 sweep runs the workspace CLI; build it first \
         (`cargo build --workspace --bins` or `cargo test --workspace`)"
    );
    bin
}

struct Cli<'a> {
    f: &'a Fixture,
    bin: PathBuf,
    home: PathBuf,
}

impl Cli<'_> {
    /// Runs one command and checks both of its streams. `human` selects the
    /// localized error rendering instead of the JSON envelope.
    fn run(&self, sweep: &mut Sweep, args: &[&str], stdin: Option<&[u8]>, human: bool) -> Output {
        let mut command = Command::new(&self.bin);
        command
            .arg("--state-dir")
            .arg(&self.f.state)
            .args(args)
            .env("HOME", &self.home)
            .env("REKEY_OUTPUT", if human { "human" } else { "json" })
            .env_remove("REKEY_AGENT_SOCKET")
            .env_remove("REKEY_CAPABILITY")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let pid = child.id() as libc::pid_t;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(child.wait_with_output()));
        let output = match receiver.recv_timeout(common::test_timeout(Duration::from_secs(60))) {
            Ok(output) => output.unwrap(),
            Err(_) => {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                panic!("`rekey {}` did not finish", args.join(" "));
            }
        };
        let what = args.join(" ");
        sweep.check("cli", &what, &output.stdout);
        sweep.check("cli", &what, &output.stderr);
        output
    }

    fn ok(&self, sweep: &mut Sweep, args: &[&str]) -> Value {
        let output = self.run(sweep, args, None, false);
        assert!(
            output.status.success(),
            "`rekey {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
    }

    /// Returns the JSON error code; human mode only checks the exit status.
    fn error(&self, sweep: &mut Sweep, args: &[&str], human: bool) -> String {
        let output = self.run(sweep, args, None, human);
        assert!(!output.status.success(), "`rekey {}`", args.join(" "));
        if human {
            return String::new();
        }
        let envelope: Value = serde_json::from_slice(&output.stderr).unwrap_or_else(|_| {
            panic!(
                "`rekey {}` printed no JSON error: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        envelope["code"].as_str().unwrap_or_default().to_owned()
    }
}

pub(super) fn sweep(f: &Fixture, sweep: &mut Sweep) {
    let home = f.dir.path().join("cli-home");
    let project = f.dir.path().join("cli-project");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&project).unwrap();
    let cli = Cli {
        f,
        bin: rekey_bin(),
        home,
    };
    // Discovery.
    let listed = cli.ok(sweep, &["list", "--json"]);
    assert_eq!(listed["connections"][0]["connection"], "fixture");
    cli.ok(sweep, &["list"]);
    cli.ok(sweep, &["describe", "github.get_issue"]);
    assert_ne!(cli.error(sweep, &["describe", "github.missing"], false), "");
    // Dry runs reach no upstream.
    let preview = cli.ok(sweep, &[CALL_ISSUE, &["--dry-run"][..]].concat());
    assert_eq!(preview["path"], PATH);
    let preview = cli.ok(sweep, &["http", "fixture", "GET", PATH, "--dry-run"]);
    assert_eq!(preview["effect"], "allow");
    assert_eq!(f.upstream_requests(), 0);
    // Calls that succeed.
    let called = cli.ok(sweep, CALL_ISSUE);
    assert_eq!(called["status"], 200);
    let called = cli.ok(sweep, &["http", "fixture", "GET", PATH]);
    assert_eq!(called["body"], r#"{"ok":true}"#);
    assert_eq!(f.upstream_requests(), 2);
    // Every reflection is sealed, as a named call, a raw HTTP call and for people.
    for (index, (name, response)) in reflections().into_iter().enumerate() {
        f.fake.push_response(Ok(response));
        let args = if index % 2 == 0 {
            vec!["http", "fixture", "GET", PATH]
        } else {
            CALL_ISSUE.to_vec()
        };
        assert_eq!(cli.error(sweep, &args, false), "RESPONSE_BLOCKED", "{name}");
        assert_eq!(f.upstream_requests(), 1, "{name}");
    }
    f.fake.push_response(Ok(reflections().remove(0).1));
    cli.error(sweep, &["http", "fixture", "GET", PATH], true);
    assert_eq!(f.upstream_requests(), 1);
    // Refusals and errors, in both renderings, never reach the upstream.
    for human in [false, true] {
        let delete = ["http", "fixture", "DELETE", "/repos/octo/widgets"];
        let code = cli.error(sweep, &delete, human);
        assert!(human || code == "DENIED", "{code}");
        let create = [
            "call",
            "github.create_issue",
            "--owner",
            "octo",
            "--repo",
            "widgets",
            "--title",
            "sweep",
            "--no-wait",
        ];
        let code = cli.error(sweep, &create, human);
        assert!(human || code == "APPROVAL_REQUIRED", "{code}");
        cli.error(sweep, &["http", "nowhere", "GET", "/x"], human);
        cli.error(sweep, &["http", "fixture", "GET", "/repos/../user"], human);
        cli.error(
            sweep,
            &["call", "github.get_issue", "--owner", "octo"],
            human,
        );
    }
    assert_eq!(f.upstream_requests(), 0);
    // Access requests and waits.
    let request = cli.ok(sweep, &["request", "github-pat", "--reason", "C1 sweep"]);
    let id = request["request_id"].as_str().unwrap().to_owned();
    cli.ok(sweep, &["await", &id, "--timeout", "1"]);
    cli.ok(sweep, &["await-unlock", "--timeout", "1"]);
    // Leak scanning reports places, never content.
    let scanned = cli.run(
        sweep,
        &["scan", "--stdin"],
        Some(&[b"before\nTOKEN=".as_slice(), CANARY, b"\nafter\n"].concat()),
        false,
    );
    assert_eq!(scanned.status.code(), Some(4));
    let findings: Value = serde_json::from_slice(&scanned.stdout).unwrap();
    assert_eq!(findings[0]["connection"], "fixture");
    // Public SSH status and the offline client configuration.
    let status = cli.ok(sweep, &["ssh-agent", "status"]);
    assert_eq!(status["ssh_keys"][0]["name"], super::SSH_KEY_NAME);
    // `connect` refuses a project path with a symlinked component (macOS /var).
    let project = project.canonicalize().unwrap();
    let project = project.to_str().unwrap();
    for client in ["claude-code", "cursor", "codex"] {
        let printed = cli.run(
            sweep,
            &["connect", client, "--print", "--project", project],
            None,
            false,
        );
        assert!(
            printed.status.success(),
            "connect {client}: {}",
            String::from_utf8_lossy(&printed.stderr)
        );
    }
    assert_eq!(f.upstream_requests(), 0);
}
