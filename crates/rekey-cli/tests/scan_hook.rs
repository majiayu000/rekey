//! Pre-commit (`scan --staged`) outcomes against a synthetic same-UID Agent
//! peer: cannot-scan states warn and pass unless --strict, findings always
//! block, and people get one localized line per finding.
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use rekey_domain::ipc::{Channel, FRAME_HEADER_LEN, FrameHeader, agent_msg, resp_msg};
use serde_json::{Value, json};

type Reply = Box<dyn FnOnce(Value, Vec<u8>) -> (Value, Vec<u8>, bool) + Send>;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        let runtime = root.join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            _dir: dir,
            root,
            project,
        };
        fixture.git(&["init", "-q"]);
        fixture
    }

    fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.project)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn stage(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.project.join(name), bytes).unwrap();
        self.git(&["add", name]);
    }

    /// Runs `rekey scan` while a peer answers exactly one frame per reply.
    fn scan(&self, args: &[&str], human: bool, replies: Vec<Reply>) -> Output {
        let socket = self.root.join("runtime/agent.sock");
        let server = (!replies.is_empty()).then(|| serve(&socket, replies));
        let mut command = Command::new(env!("CARGO_BIN_EXE_rekey"));
        command
            .arg("--state-dir")
            .arg(&self.root)
            .arg("scan")
            .args(args)
            .current_dir(&self.project)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true")
            .env("REKEY_OUTPUT", if human { "human" } else { "json" });
        let output = command.output().unwrap();
        if let Some(server) = server {
            server.join().unwrap();
            std::fs::remove_file(socket).unwrap();
        }
        output
    }
}

fn serve(socket: &Path, replies: Vec<Reply>) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("expected another scan frame: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut raw = [0; FRAME_HEADER_LEN];
            stream.read_exact(&mut raw).unwrap();
            let header = FrameHeader::decode(&raw).unwrap();
            assert_eq!(header.message_type, agent_msg::SCAN);
            let mut metadata = vec![0; header.metadata_len as usize];
            let mut body = vec![0; header.body_len as usize];
            stream.read_exact(&mut metadata).unwrap();
            stream.read_exact(&mut body).unwrap();
            let (mut metadata, body, error) =
                reply(serde_json::from_slice(&metadata).unwrap(), body);
            if error {
                metadata["request_id"] = json!(header.request_id);
            }
            let metadata = metadata.to_string();
            let response = FrameHeader {
                channel: Channel::Agent,
                flags: 0,
                message_type: if error { resp_msg::ERROR } else { resp_msg::OK },
                request_id: header.request_id,
                metadata_len: metadata.len() as u32,
                body_len: body.len() as u32,
            };
            stream.write_all(&response.encode()).unwrap();
            stream.write_all(metadata.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        }
    })
}

fn findings(findings: Value, unavailable: u32) -> Reply {
    Box::new(move |_, _| {
        let body = json!({"findings": findings, "unavailable_credentials": unavailable});
        (json!({}), body.to_string().into_bytes(), false)
    })
}

fn refuse(code: &'static str, message: &'static str, next: &'static str) -> Reply {
    Box::new(move |_, _| {
        let error = json!({"code": code, "message": message, "retryable": false, "next": next});
        (error, Vec::new(), true)
    })
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

const RESET: &str = "Retry after 2026-11-17 10:31:05.123 +00:00:00 UTC.";

#[test]
fn every_cannot_scan_state_warns_and_passes_unless_strict() {
    let f = Fixture::new();
    f.stage("source.txt", b"clean\n");
    let cases: [(&str, &str, &str); 4] = [
        ("IPC_UNAVAILABLE", "", "连不上 Rekey 后台服务"),
        ("LOCKED", "vault is locked", "保险库已锁定"),
        (
            "NOT_CONFIGURED",
            "the signed policy expired; nothing was scanned",
            "没有生效的签名连接规则",
        ),
        (
            "RATE_LIMITED",
            "scan byte budget for this system user is exhausted",
            "每分钟 600 MiB 的扫描额度已用完",
        ),
    ];
    for (code, message, reason) in cases {
        let replies = |count: usize| -> Vec<Reply> {
            if code == "IPC_UNAVAILABLE" {
                Vec::new()
            } else {
                (0..count).map(|_| refuse(code, message, RESET)).collect()
            }
        };
        let passed = f.scan(&["--staged"], false, replies(1));
        assert!(passed.status.success(), "{code}: {}", text(&passed.stderr));
        assert_eq!(
            serde_json::from_slice::<Value>(&passed.stdout).unwrap(),
            json!([])
        );
        let warning: Value = serde_json::from_slice(&passed.stderr).unwrap();
        assert_eq!(warning["warnings"], json!(["SCAN_NOT_PERFORMED"]));
        assert_eq!(warning["code"], code);
        let summary = warning["message"].as_str().unwrap();
        assert!(
            summary.contains(reason) && summary.contains("1 个暂存文件"),
            "{summary}"
        );
        assert!(warning["next"].as_str().unwrap().contains("--strict"));

        let human = text(&f.scan(&["--staged"], true, replies(1)).stderr);
        assert!(human.starts_with("警告："), "{human}");
        assert!(
            human.contains(reason) && human.contains("提交照常进行"),
            "{human}"
        );
        assert_eq!(human.contains(RESET), code == "RATE_LIMITED", "{human}");

        let blocked = f.scan(&["--staged", "--strict"], false, replies(1));
        assert!(!blocked.status.success(), "{code}");
        let error: Value = serde_json::from_slice(&blocked.stderr).unwrap();
        assert_eq!(error["code"], code);
    }
}

#[test]
fn oversized_staged_file_is_skipped_by_the_hook_and_blocks_only_when_strict() {
    let f = Fixture::new();
    f.stage("a-large.bin", &vec![b' '; 10 * 1024 * 1024 + 1]);
    f.stage("b-small.txt", b"clean\n");
    let reply: Reply = Box::new(|metadata, body| {
        assert_eq!(metadata, json!({"path": "b-small.txt"}));
        assert_eq!(body, b"clean\n");
        let body = json!({"findings": [], "unavailable_credentials": 0});
        (json!({}), body.to_string().into_bytes(), false)
    });
    let passed = f.scan(&["--staged"], false, vec![reply]);
    assert!(passed.status.success(), "{}", text(&passed.stderr));
    let warning: Value = serde_json::from_slice(&passed.stderr).unwrap();
    assert_eq!(warning["warnings"], json!(["SCAN_FILE_SKIPPED"]));
    assert!(warning["message"].as_str().unwrap().contains("a-large.bin"));

    // Refused before any frame: no peer is listening.
    let blocked = f.scan(&["--staged", "--strict"], false, Vec::new());
    assert_eq!(blocked.status.code(), Some(2), "{}", text(&blocked.stderr));
    let error: Value = serde_json::from_slice(&blocked.stderr).unwrap();
    assert_eq!(error["code"], "INVALID_FRAME");
    assert!(error["message"].as_str().unwrap().contains("a-large.bin"));
}

#[test]
fn findings_block_and_people_get_one_line_per_finding_with_escaped_paths() {
    let f = Fixture::new();
    f.stage("source.txt", b"x\n");
    let hits = json!([
        {"path": "source.txt", "line": 1, "column": 1, "connection": "github"},
        {"path": "src/\u{1b}[2Jx.txt", "line": 3, "column": 7, "connection": "openai"}
    ]);
    let machine = f.scan(&["--staged"], false, vec![findings(hits.clone(), 0)]);
    assert_eq!(machine.status.code(), Some(4));
    assert_eq!(
        serde_json::from_slice::<Value>(&machine.stdout).unwrap(),
        hits
    );
    let error: Value = serde_json::from_slice(&machine.stderr).unwrap();
    assert_eq!(error["code"], "LEAK_DETECTED");
    assert!(!text(&machine.stderr).contains("检测到"));

    let person = f.scan(&["--staged"], true, vec![findings(hits.clone(), 0)]);
    assert_eq!(person.status.code(), Some(4));
    assert_eq!(
        serde_json::from_slice::<Value>(&person.stdout).unwrap(),
        hits
    );
    let stderr = text(&person.stderr);
    assert!(
        stderr.contains(
            "检测到 github 的密钥出现在 source.txt:1；请改用 rekey call 或本机服务地址\n"
        )
    );
    assert!(stderr.contains(
        "检测到 openai 的密钥出现在 src/\\u{1b}[2Jx.txt:3；请改用 rekey call 或本机服务地址\n"
    ));
    assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
    assert!(stderr.contains("错误：扫描的内容里有 Rekey 保存的密钥。"));
    assert!(stderr.trim_end().ends_with("(LEAK_DETECTED)"));
}

#[test]
fn a_cannot_scan_state_mid_batch_never_hides_earlier_findings() {
    let f = Fixture::new();
    f.stage("a.txt", b"first\n");
    f.stage("b.txt", b"second\n");
    let limited = || refuse("RATE_LIMITED", "scan byte budget exhausted", RESET);
    let hit = json!([{"path": "a.txt", "line": 1, "column": 1, "connection": "github"}]);
    let blocked = f.scan(
        &["--staged"],
        false,
        vec![findings(hit.clone(), 0), limited()],
    );
    assert_eq!(blocked.status.code(), Some(4), "{}", text(&blocked.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&blocked.stdout).unwrap(),
        hit
    );
    let stderr = text(&blocked.stderr);
    let mut lines = stderr.lines();
    let warning: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(warning["code"], "RATE_LIMITED");
    assert!(
        warning["message"]
            .as_str()
            .unwrap()
            .contains("1 个暂存文件")
    );
    let error: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(error["code"], "LEAK_DETECTED");

    let passed = f.scan(
        &["--staged"],
        false,
        vec![findings(json!([]), 0), limited()],
    );
    assert!(passed.status.success(), "{}", text(&passed.stderr));
}

#[test]
fn unavailable_credentials_are_counted_without_failing_the_scan() {
    let f = Fixture::new();
    let output = f.scan(&["--stdin"], false, vec![findings(json!([]), 2)]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let warning: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(warning["warnings"], json!(["SCAN_CREDENTIALS_UNAVAILABLE"]));
    assert!(
        warning["message"]
            .as_str()
            .unwrap()
            .contains("2 个凭据不可用")
    );
}
