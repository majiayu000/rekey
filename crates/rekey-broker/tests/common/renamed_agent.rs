//! Runs a command (or one loopback HTTP request) from a copy of this test
//! binary placed at a chosen path, so the daemon sees a parent process named
//! like a known Agent. Any same-UID program can do this; caller labels are
//! records and caller rules may only tighten (agent-call model §4.3, C4).
//! Include at the crate root as `mod renamed_agent` so the entry name holds.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const REQUEST: &str = "REKEY_RENAMED_AGENT_REQUEST";
const ENTRY: &str = "renamed_agent::renamed_agent_child";

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Child {
    pub program: Option<PathBuf>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    /// A raw request the renamed process itself sends to 127.0.0.1:port.
    pub http: Option<(u16, String)>,
}

pub struct Output {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Copies this test binary to `dir/relative` and returns the new path.
pub fn install(dir: &Path, relative: &str) -> PathBuf {
    let path = dir.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    path
}

/// Runs `child` under `agent` from the blocking pool, so an in-process
/// broker keeps serving while the child calls it.
pub async fn run(agent: &Path, child: Child) -> Output {
    let agent = agent.to_owned();
    tokio::task::spawn_blocking(move || {
        let work = tempfile::tempdir().unwrap();
        let request = work.path().join("request.json");
        std::fs::write(&request, serde_json::to_vec(&child).unwrap()).unwrap();
        let harness = Command::new(&agent)
            .args(["--exact", ENTRY, "--test-threads=1", "--quiet"])
            .env(REQUEST, &request)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            harness.status.success(),
            "renamed agent {} failed: {}{}",
            agent.display(),
            String::from_utf8_lossy(&harness.stdout),
            String::from_utf8_lossy(&harness.stderr)
        );
        let read = |name: &str| std::fs::read(work.path().join(name)).unwrap();
        Output {
            status: String::from_utf8(read("status")).unwrap().parse().unwrap(),
            stdout: read("stdout"),
            stderr: read("stderr"),
        }
    })
    .await
    .unwrap()
}

/// Caller labels recorded for one audit event type, oldest first.
pub async fn audited_callers(admin: &Path, event: &str) -> Vec<String> {
    let query = rekey_domain::audit::AuditQuery {
        request_id: None,
        session_id: None,
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit: 100,
    };
    let reply = crate::common::call(
        admin,
        rekey_domain::ipc::Channel::Admin,
        rekey_domain::ipc::admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&query).unwrap(),
        &[],
    )
    .await;
    reply.ok();
    let page: rekey_domain::audit::AuditPage = serde_json::from_slice(&reply.body).unwrap();
    let mut events: Vec<_> = page
        .events
        .into_iter()
        .filter(|record| record.event_type == event)
        .collect();
    events.sort_by_key(|record| record.sequence);
    events
        .into_iter()
        .filter_map(|record| match record.request_context {
            Some(rekey_domain::audit::RequestAuditContext::Connection(context)) => {
                Some(context.caller)
            }
            _ => None,
        })
        .collect()
}

/// The child half: a no-op in normal test runs.
#[test]
fn renamed_agent_child() {
    let Some(request) = std::env::var_os(REQUEST).map(PathBuf::from) else {
        return;
    };
    let child: Child = serde_json::from_slice(&std::fs::read(&request).unwrap()).unwrap();
    let (status, stdout, stderr) = if let Some((port, raw)) = child.http {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        (0, response, Vec::new())
    } else {
        let mut process = Command::new(child.program.unwrap())
            .args(&child.args)
            .envs(child.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = process.stdin.take().unwrap();
        let bytes = child.stdin;
        // A child that exits without reading its input is reported by status.
        let writer = std::thread::spawn(move || input.write_all(&bytes));
        let output = process.wait_with_output().unwrap();
        let _ = writer.join();
        (
            output.status.code().unwrap_or(-1),
            output.stdout,
            output.stderr,
        )
    };
    let dir = request.parent().unwrap();
    std::fs::write(dir.join("status"), status.to_string()).unwrap();
    std::fs::write(dir.join("stdout"), stdout).unwrap();
    std::fs::write(dir.join("stderr"), stderr).unwrap();
}
