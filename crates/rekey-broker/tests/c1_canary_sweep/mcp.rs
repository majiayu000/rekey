//! MCP surface: the `rekey-mcp` stdio transport against the in-process daemon.
//! Every stdout line and the complete stderr stream are checked.
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use serde_json::{Value, json};

use super::{Fixture, Sweep, common, reflections};

pub(super) struct Mcp {
    child: Child,
    input: ChildStdin,
    lines: Receiver<String>,
    stderr: std::thread::JoinHandle<Vec<u8>>,
    next_id: u64,
}

impl Mcp {
    /// Starts `rekey-mcp` and completes the initialize handshake.
    pub(super) fn initialized(f: &Fixture, sweep: &mut Sweep) -> Self {
        let mut mcp = Self::start(f);
        let init = mcp.request(
            sweep,
            "initialize",
            json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c1-sweep","version":"1"}}),
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
        writeln!(
            mcp.input,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .unwrap();
        mcp
    }

    fn start(f: &Fixture) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rekey-mcp"))
            .arg("--agent-socket")
            .arg(f.socket("agent.sock"))
            .env_remove("REKEY_AGENT_SOCKET")
            .env_remove("REKEY_CAPABILITY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let stderr = std::thread::spawn(move || {
            let mut all = Vec::new();
            stderr.read_to_end(&mut all).unwrap();
            all
        });
        Self {
            child,
            input,
            lines,
            stderr,
            next_id: 1,
        }
    }

    /// Sends one raw line and returns the checked, parsed answer.
    pub(super) fn line(&mut self, sweep: &mut Sweep, what: &str, line: &str) -> Value {
        writeln!(self.input, "{line}").unwrap();
        let answer = self
            .lines
            .recv_timeout(common::test_timeout(Duration::from_secs(60)))
            .unwrap_or_else(|_| panic!("MCP did not answer `{what}`"));
        sweep.check("mcp", what, answer.as_bytes());
        serde_json::from_str(&answer).unwrap()
    }

    pub(super) fn request(&mut self, sweep: &mut Sweep, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        self.line(sweep, method, &request.to_string())
    }

    pub(super) fn tool(&mut self, sweep: &mut Sweep, name: &str, arguments: Value) -> Value {
        let answer = self.request(
            sweep,
            "tools/call",
            json!({"name":name,"arguments":arguments}),
        );
        answer["result"].clone()
    }

    pub(super) fn ok(&mut self, sweep: &mut Sweep, name: &str, arguments: Value) -> Value {
        let result = self.tool(sweep, name, arguments);
        assert_eq!(result["isError"], false, "{name}: {result}");
        result["structuredContent"].clone()
    }

    pub(super) fn error(&mut self, sweep: &mut Sweep, name: &str, arguments: Value) -> Value {
        let result = self.tool(sweep, name, arguments);
        assert_eq!(result["isError"], true, "{name}: {result}");
        result["structuredContent"].clone()
    }

    pub(super) fn finish(mut self, sweep: &mut Sweep) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stderr = self.stderr.join().unwrap();
        sweep.check("mcp", "stderr", &stderr);
    }
}

fn issue() -> Value {
    json!({"owner":"octo","repo":"widgets","number":7})
}

fn get() -> Value {
    json!({"connection":"fixture","method":"GET","path":"/repos/octo/widgets/issues/7"})
}

pub(super) fn sweep(f: &Fixture, sweep: &mut Sweep) {
    let mut mcp = Mcp::initialized(f, sweep);
    // Discovery, generic and named.
    let tools = mcp.request(sweep, "tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"github_get_issue"), "{names:?}");
    mcp.ok(sweep, "list_capabilities", json!({}));
    mcp.ok(sweep, "describe", json!({"operation":"github.get_issue"}));
    mcp.error(sweep, "describe", json!({"operation":"github.missing"}));
    // Dry runs reach no upstream.
    let mut dry = issue();
    dry["dry_run"] = true.into();
    let preview = mcp.ok(sweep, "github_get_issue", dry);
    assert_eq!(preview["path"], "/repos/octo/widgets/issues/7");
    let mut dry = get();
    dry["dry_run"] = true.into();
    mcp.ok(sweep, "http", dry);
    assert_eq!(f.upstream_requests(), 0);
    // Calls that succeed: named tool, generic call and generic http.
    for (name, arguments) in [
        ("github_get_issue", issue()),
        (
            "call",
            json!({"operation":"github.get_issue","args":issue()}),
        ),
        ("http", get()),
    ] {
        assert_eq!(mcp.ok(sweep, name, arguments)["status"], 200, "{name}");
    }
    assert_eq!(f.upstream_requests(), 3);
    // Every reflection is sealed.
    for (index, (name, response)) in reflections().into_iter().enumerate() {
        f.fake.push_response(Ok(response));
        let (tool, arguments) = match index % 3 {
            0 => ("http", get()),
            1 => ("github_get_issue", issue()),
            _ => (
                "call",
                json!({"operation":"github.get_issue","args":issue()}),
            ),
        };
        let error = mcp.error(sweep, tool, arguments);
        assert_eq!(error["code"], "RESPONSE_BLOCKED", "{name}");
        assert_eq!(f.upstream_requests(), 1, "{name}");
    }
    // Refusals, approvals, access requests and waits never reach the upstream.
    let denied = json!({"connection":"fixture","method":"DELETE","path":"/repos/octo/widgets"});
    assert_eq!(mcp.error(sweep, "http", denied)["code"], "DENIED");
    let pending = mcp.error(
        sweep,
        "github_create_issue",
        json!({"owner":"octo","repo":"widgets","title":"sweep"}),
    );
    assert_eq!(pending["code"], "APPROVAL_REQUIRED");
    let challenge = pending["approval"]["challenge_id"].clone();
    mcp.tool(
        sweep,
        "await_approval",
        json!({"request_id":challenge,"timeout_s":1}),
    );
    mcp.tool(sweep, "cancel_approval", json!({"request_id":challenge}));
    let access = mcp.ok(
        sweep,
        "request_access",
        json!({"provider":"github-pat","reason":"C1 sweep"}),
    );
    mcp.tool(
        sweep,
        "await_access",
        json!({"request_id":access["request_id"],"timeout_s":1}),
    );
    mcp.ok(sweep, "await_unlock", json!({"timeout_s":1}));
    for (name, arguments) in [
        (
            "http",
            json!({"connection":"nowhere","method":"GET","path":"/x"}),
        ),
        (
            "http",
            json!({"connection":"fixture","method":"GET","path":"/repos/../user"}),
        ),
        ("github_get_issue", json!({"owner":"octo"})),
        ("call", json!({"operation":"github.missing","args":{}})),
        ("list_capabilities", json!({"unexpected":true})),
        ("no_such_tool", json!({})),
    ] {
        mcp.error(sweep, name, arguments);
    }
    let broken = mcp.line(sweep, "malformed JSON-RPC", "{broken");
    assert_eq!(broken["error"]["code"], -32700);
    assert_eq!(f.upstream_requests(), 0);
    mcp.finish(sweep);
}
