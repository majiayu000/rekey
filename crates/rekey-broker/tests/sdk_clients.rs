//! Opt-in installed-client acceptance. All state and upstream responses are synthetic.
//! Supply REKEY_SDK_LIVE_{REKEY,CLAUDE,CODEX,PYTHON,ARTIFACTS}; no user config is used.
#![cfg(target_os = "macos")]
mod common;

use std::collections::{BTreeSet, VecDeque};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    UpstreamBody, UpstreamChunkFuture, UpstreamError, UpstreamFuture, UpstreamRequest,
    UpstreamStreamFuture, UpstreamStreamResponse, UpstreamTransport,
};
use rekey_domain::action::FixedHttpAction;
use rekey_domain::ids::{PolicyRuleId, PrincipalId};
use rekey_domain::ipc::{Channel, admin_msg};
use rekey_domain::template::TemplateValues;
use serde_json::{Value, json};
use zeroize::Zeroize;

const SECRET: &[u8] = b"SDK-LIVE-SYNTHETIC-CREDENTIAL-ONLY";
const MARKER: &str = "REKEY_LIVE_SYNTHETIC_OK";
const PROBE: &str = r#"import socket,sys,pathlib,json
result={}
for name,host,port in [('allowed','127.0.0.1',int(sys.argv[1])),('other','127.0.0.1',int(sys.argv[2])),('external','1.1.1.1',443)]:
 s=socket.socket();s.settimeout(2)
 try:s.connect((host,port));result[name]=True
 except OSError as e:result[name]=False;result[name+'_errno']=e.errno
 finally:s.close()
try:pathlib.Path(sys.argv[3]).read_bytes();result['protected_file']=True
except OSError as e:result['protected_file']=False;result['protected_errno']=e.errno
print(json.dumps(result))
"#;

struct Capture {
    path: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    credential_matches: bool,
}
struct Transport {
    anthropic: bool,
    captures: Mutex<Vec<Capture>>,
}
struct Stream(VecDeque<Vec<u8>>);
impl UpstreamBody for Stream {
    fn next_chunk(&mut self) -> UpstreamChunkFuture<'_> {
        Box::pin(async { Ok(self.0.pop_front().map(Into::into)) })
    }
}
impl UpstreamTransport for Transport {
    fn send(&self, _: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async { Err(UpstreamError::Transport) })
    }
    fn open_stream(&self, request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        Box::pin(async move {
            let expected = if self.anthropic {
                SECRET.to_vec()
            } else {
                [b"Bearer ".as_slice(), SECRET].concat()
            };
            let credential_matches = request.auth_header.1.as_slice() == expected
                && request.auth_header.0
                    == if self.anthropic {
                        "x-api-key"
                    } else {
                        "authorization"
                    };
            self.captures.lock().unwrap().push(Capture {
                path: request.path.clone(),
                body: request.body.to_vec(),
                headers: request.headers.clone(),
                credential_matches,
            });
            if !credential_matches {
                return Err(UpstreamError::Transport);
            }
            let data = sse(self.anthropic);
            Ok(UpstreamStreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())].into(),
                body: Box::new(Stream(data.chunks(37).map(<[u8]>::to_vec).collect())),
            })
        })
    }
}
fn sse(anthropic: bool) -> Vec<u8> {
    let events = if anthropic {
        vec![
            json!({"type":"message_start","message":{"id":"msg_synthetic","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"usage":{"input_tokens":1,"output_tokens":0}}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":MARKER}}),
            json!({"type":"content_block_stop","index":0}),
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}),
            json!({"type":"message_stop"}),
        ]
    } else {
        let item = json!({"id":"msg_synthetic","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":MARKER,"annotations":[]}]});
        vec![
            json!({"type":"response.created","response":{"id":"resp_synthetic","object":"response","status":"in_progress","output":[]}}),
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"msg_synthetic","type":"message","status":"in_progress","role":"assistant","content":[]}}),
            json!({"type":"response.content_part.added","output_index":0,"content_index":0,"item_id":"msg_synthetic","part":{"type":"output_text","text":"","annotations":[]}}),
            json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"item_id":"msg_synthetic","delta":MARKER}),
            json!({"type":"response.output_text.done","output_index":0,"content_index":0,"item_id":"msg_synthetic","text":MARKER}),
            json!({"type":"response.content_part.done","output_index":0,"content_index":0,"item_id":"msg_synthetic","part":item["content"][0]}),
            json!({"type":"response.output_item.done","output_index":0,"item":item}),
            json!({"type":"response.completed","response":{"id":"resp_synthetic","object":"response","created_at":1,"model":"gpt-5.4","status":"completed","output":[item],"usage":{"input_tokens":1,"output_tokens":3,"total_tokens":4}}}),
        ]
    };
    events
        .iter()
        .map(|v| format!("event: {}\ndata: {}\n\n", v["type"].as_str().unwrap(), v))
        .collect::<String>()
        .into_bytes()
}
fn binary(name: &str) -> PathBuf {
    std::fs::canonicalize(
        std::env::var_os(name).expect("explicit installed-client fixture path required"),
    )
    .unwrap()
}
fn has_secret(bytes: &[u8]) -> bool {
    bytes.windows(SECRET.len()).any(|w| w == SECRET) || bytes.windows(4).any(|w| w == b"rkc_")
}
struct Group(Child, bool);
impl Drop for Group {
    fn drop(&mut self) {
        // This group was created exclusively for this invocation. Never wait unboundedly.
        if self.1 {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
        }
        let _ = self.0.try_wait();
    }
}
fn pipe(reader: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut data = Vec::new();
        if reader
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .is_ok()
        {
            let _ = tx.send(data);
        }
    });
    rx
}
async fn run(mut command: Command, seconds: u64) -> (Value, Vec<u8>) {
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut group = Group(
        command.spawn().expect("spawn isolated fixture process"),
        true,
    );
    let stdout = pipe(group.0.stdout.take().unwrap());
    let stderr = pipe(group.0.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = group.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    unsafe {
        libc::kill(-(group.0.id() as i32), libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let gone = loop {
        let _ = group.0.try_wait();
        let result = unsafe { libc::kill(-(group.0.id() as i32), 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    if gone {
        group.1 = false;
    }
    let out = stdout
        .recv_timeout(Duration::from_secs(2))
        .expect("stdout closed after own group cleanup");
    let mut err = stderr
        .recv_timeout(Duration::from_secs(2))
        .expect("stderr closed after own group cleanup");
    let markers: Vec<_> = [
        "REQUEST_DENIED",
        "INVALID_FRAME",
        "APPROVAL_REQUIRED",
        "Operation not permitted",
        "Failed to synchronize managed preferences",
    ]
    .into_iter()
    .filter(|s| err.windows(s.len()).any(|w| w == s.as_bytes()))
    .collect();
    let receipt = json!({"exit_code":status.and_then(|s|s.code()),"timed_out":status.is_none(),"group_absent":gone,
        "output_secret_free":!has_secret(&out)&&!has_secret(&err),"diagnostic_markers":markers,"raw_stderr_not_saved":true});
    err.zeroize();
    (receipt, out)
}
fn sandbox(
    root: &Path,
    broker: &common::TestBroker,
    port: u16,
    executables: &[&Path],
    codex: bool,
) -> PathBuf {
    let mut policy = String::from(
        r#"(version 1)
(deny default)
(allow process-exec process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow file-read* (literal "/") (subpath "/System/Library") (subpath "/usr/lib") (subpath "/usr/share") (subpath "/bin") (subpath "/usr/bin") (subpath "/usr/libexec") (subpath "/opt/homebrew/Cellar") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random"))
(allow file-write-data (literal "/dev/null"))
(allow sysctl-read (sysctl-name-prefix "hw.") (sysctl-name "kern.osrelease") (sysctl-name "kern.osversion") (sysctl-name "kern.ostype") (sysctl-name "kern.osproductversion") (sysctl-name "kern.argmax"))
(allow system-socket (socket-domain AF_UNIX) (socket-domain AF_INET) (socket-domain AF_INET6))
"#,
    );
    let quote = |p: &Path| serde_json::to_string(p.to_str().unwrap()).unwrap();
    let state = std::fs::canonicalize(&broker.state_dir).unwrap();
    let admin = state.join("runtime/admin.sock");
    let mut ancestors = BTreeSet::new();
    for path in executables.iter().copied().chain([root, admin.as_path()]) {
        ancestors.extend(path.ancestors().map(Path::to_path_buf));
    }
    policy.push_str("(allow file-read-metadata ");
    for path in ancestors {
        policy.push_str(&format!("(literal {})", quote(&path)));
    }
    policy.push_str(")\n");
    for executable in executables {
        policy.push_str(&format!(
            "(allow file-read* (literal {}))\n",
            quote(executable)
        ));
    }
    policy.push_str(&format!("(allow file-read* file-write* (subpath {}))\n(allow network-outbound (remote unix-socket (literal {})))\n(allow network-outbound (remote tcp \"localhost:{port}\"))\n",quote(root),quote(&admin)));
    if codex {
        // Approved test-only routing scenario. Preferences IPC exceeds filesystem
        // roots: this MUST NOT be used as evidence for Home or L2 isolation.
        policy.push_str(r#"(allow file-read-metadata (literal "/etc") (literal "/private") (literal "/private/etc") (literal "/etc/codex") (literal "/private/etc/codex"))
(allow file-read* (literal "/etc/codex/requirements.toml") (literal "/private/etc/codex/requirements.toml"))
(allow ipc-posix-shm-read* (ipc-posix-name-prefix "apple.cfprefs."))
(allow mach-lookup (global-name "com.apple.cfprefsd.daemon") (global-name "com.apple.cfprefsd.agent") (local-name "com.apple.cfprefsd.agent"))
(allow user-preference-read)
"#);
    }
    let path = root.join("sandbox.sb");
    std::fs::write(&path, policy).unwrap();
    path
}
fn isolated(root: &Path, policy: &Path) -> Command {
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-f", policy.to_str().unwrap(), "--"])
        .env_clear()
        .current_dir(root.join("project"))
        .env("HOME", root.join("home"))
        .env("CODEX_HOME", root.join("codex"))
        .env("CLAUDE_CONFIG_DIR", root.join("claude"))
        .env("CLAUDE_CODE_TMPDIR", root.join("tmp"))
        .env("TMPDIR", root.join("tmp"))
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
        .env("LANG", "en_US.UTF-8")
        .env("LC_ALL", "en_US.UTF-8")
        .env("TERM", "dumb");
    command
}
fn scratch_clean(root: &Path) -> bool {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if !scratch_clean(&entry.path()) {
                return false;
            }
        } else if kind.is_file() && has_secret(&std::fs::read(entry.path()).unwrap()) {
            return false;
        }
    }
    true
}
async fn acceptance(anthropic: bool) {
    let label = if anthropic { "claude" } else { "codex" };
    let cli = binary("REKEY_SDK_LIVE_REKEY");
    let client = binary(if anthropic {
        "REKEY_SDK_LIVE_CLAUDE"
    } else {
        "REKEY_SDK_LIVE_CODEX"
    });
    let python = binary("REKEY_SDK_LIVE_PYTHON");
    let artifacts = binary("REKEY_SDK_LIVE_ARTIFACTS");
    let transport = Arc::new(Transport {
        anthropic,
        captures: Mutex::new(Vec::new()),
    });
    let broker = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        Arc::new(FakeUpstreamTransport::new()),
        transport.clone(),
    )
    .await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "sdk-synthetic", SECRET).await;
    let provider = if anthropic { "anthropic" } else { "openai" };
    let capability = if anthropic { "messages" } else { "responses" };
    let model = if anthropic {
        "claude-sonnet-4-6"
    } else {
        "gpt-5.4"
    };
    let ceiling = if anthropic { 32768 } else { 4096 };
    let install = json!({"source":{"kind":provider},"credential_id":credential,"bindings":[{}],"capabilities":[capability],"name_prefix":"sdk","timeout_ms":5000,"request_max_bytes":1048576,"allowed_extra_headers":["anthropic-beta"],"response_max_bytes":65536,"allowed_response_headers":["content-type"]});
    let installed = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::TEMPLATE_INSTALL,
        &serde_json::to_vec(&install).unwrap(),
        &common::proof_and_secret_body(common::PASSWORD, b""),
    )
    .await;
    let action: FixedHttpAction =
        serde_json::from_value(installed.ok()["actions"][0]["action"].clone()).unwrap();
    let principal = PrincipalId::new_random();
    let snapshot = json!({"format_version":7,"version":1,"expires_at_ms":4_102_444_800_000_i64,"approvers":[],"workload_identities":[],
        "connections":[], "ssh_keys":[], "profiles":[{"name":"sdk-live","principal_id":principal,"grants":[{"instance":"work","capabilities":[{"rule":"template-default","capability":capability,"actions":[{"action_id":action.id,"version":action.version}]}]}],"session":{"ttl_ms":60000,"max_uses":10},"confirm_each_run":false,"isolation":"none","egress":"allow","llm_limits":[{"instance":"work","models":[model],"max_output_tokens_per_request":ceiling,"max_requests_per_day":10,"max_output_tokens_per_day":65536}]}],
        "bindings":[{"action_id":action.id,"version":action.version,"resource":{"type":"sdk","id":action.id},"parameter_schema_id":"sdk/v1","parameter_schema":{}}],
        "rules":[{"id":PolicyRuleId::new_random(),"effect":"permit","principal_id":principal,"action_id":action.id,"version":action.version,"resource":{"type":"sdk","id":action.id},"parameters":{"kind":"any_validated"}}]});
    common::policy::activate_snapshot(&broker, snapshot.clone()).await;
    // Harness only: the real launcher still obtains the authenticated Admin59 endpoint.
    let port: u16 = std::fs::read_to_string(broker.state_dir.join("gateway.port"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    for sub in ["home", "codex", "claude", "tmp", "project"] {
        let path = root.join(sub);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let policy = sandbox(&root, &broker, port, &[&cli, &client, &python], !anthropic);
    let protected = broker.dir.path().join("protected-canary");
    std::fs::write(&protected, b"synthetic-outside-root").unwrap();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut probe = isolated(&root, &policy);
    probe
        .arg(&python)
        .args(["-c", PROBE])
        .arg(port.to_string())
        .arg(other.local_addr().unwrap().port().to_string())
        .arg(&protected);
    let (preflight, mut raw) = run(probe, 10).await;
    let controls: Value =
        serde_json::from_slice(&raw).expect("sandbox probe emitted only boolean controls");
    raw.zeroize();
    assert_eq!(preflight["exit_code"], 0);
    assert_eq!(controls["allowed"], true);
    for key in ["other", "external", "protected_file"] {
        assert_eq!(controls[key], false);
    }
    assert_eq!(controls["other_errno"], libc::EPERM);
    assert_eq!(controls["external_errno"], libc::EPERM);
    assert_eq!(controls["protected_errno"], libc::EPERM);
    drop(other);
    let mut command = isolated(&root, &policy);
    command
        .arg(&cli)
        .arg("--state-dir")
        .arg(std::fs::canonicalize(&broker.state_dir).unwrap())
        .args([
            "run",
            "sdk-live",
            "--client",
            if anthropic { "claude-code" } else { "codex" },
            "--",
        ])
        .arg(&client);
    if anthropic {
        command.args([
            "--safe-mode",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--tools",
            "",
            "--no-session-persistence",
            "--print",
            "--output-format",
            "json",
            "--model",
            model,
        ]);
    } else {
        command.args([
            "exec",
            "--ignore-user-config",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--json",
            "--model",
            model,
        ]);
    }
    command.arg("Reply with the synthetic fixture marker. Do not call any tools.");
    let (client_result, mut output) = run(command, 60).await;
    let marker = output.windows(MARKER.len()).any(|w| w == MARKER.as_bytes());
    output.zeroize();
    let clean = scratch_clean(&root);
    // Delete any client-generated managed-policy caches; never archive their contents.
    scratch.close().unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        let status = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::STATUS,
            b"{}",
            b"",
        )
        .await;
        let revoked: u64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='session.revoked'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if revoked > 0 && status.ok()["sessions_active"] == 0 {
            break status.metadata;
        }
        if Instant::now() >= deadline {
            break status.metadata;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let sessions_match:bool=db.query_row("SELECT count(*)=1 FROM audit_events c JOIN audit_events r ON c.session_id=r.session_id WHERE c.event_type='session.created' AND r.event_type='session.revoked'",[],|r|r.get(0)).unwrap();
    let usage:(u64,u64,u64)=db.query_row("SELECT count(*),coalesce(sum(output_tokens),0),coalesce(sum(output_tokens IS NULL),0) FROM profile_usage",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    let mut stmt=db.prepare("SELECT event_type,reason_code,coalesce(metadata_json,'') FROM audit_events ORDER BY sequence").unwrap();
    let audit = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let audit_clean = audit.iter().all(|(e, r, m)| {
        !has_secret(e.as_bytes()) && !has_secret(r.as_bytes()) && !has_secret(m.as_bytes())
    });
    let (canonical_matches, model_bound, max_bound, path_bound, auth_bound, request_count) = {
        let captures = transport.captures.lock().unwrap();
        let mut canonical_matches = false;
        let mut model_bound = false;
        let mut max_bound = false;
        let mut path_bound = false;
        let mut auth_bound = false;
        if captures.len() == 1 {
            let sent = &captures[0];
            let body: Value = serde_json::from_slice(&sent.body).unwrap();
            model_bound = body["model"] == model;
            max_bound = body[if anthropic {
                "max_tokens"
            } else {
                "max_output_tokens"
            }] == if anthropic { 32000 } else { 4096 };
            path_bound = sent.path
                == if anthropic {
                    "/v1/messages?beta=true"
                } else {
                    "/v1/responses"
                };
            auth_bound = sent.credential_matches;
            let query = if anthropic {
                TemplateValues::from([("beta".into(), "true".into())])
            } else {
                TemplateValues::new()
            };
            let headers: Vec<_> = sent
                .headers
                .iter()
                .filter(|(name, _)| name == "anthropic-beta")
                .cloned()
                .collect();
            let snapshot = rekey_policy::parse_and_validate_snapshot(
                &serde_json::to_vec(&snapshot).unwrap(),
                rekey_domain::Timestamp::from_unix_ms(1),
            )
            .unwrap();
            let (_, canonical, _) = snapshot
                .canonicalize(
                    &action,
                    rekey_policy::ActionRequest {
                        params: &TemplateValues::new(),
                        query: &query,
                        content_type: Some("application/json"),
                        headers: &headers,
                        body: &sent.body,
                    },
                )
                .unwrap();
            let matching:u64=db.query_row("SELECT count(*) FROM audit_events s JOIN audit_events f ON s.request_id=f.request_id WHERE s.event_type='execution.started' AND f.event_type='execution.finished' AND s.parameter_hash=?1 AND f.parameter_hash=s.parameter_hash",[canonical.canonical_hash.as_slice()],|r|r.get(0)).unwrap();
            canonical_matches = matching == 1;
        }
        (
            canonical_matches,
            model_bound,
            max_bound,
            path_bound,
            auth_bound,
            captures.len(),
        )
    };
    let report = json!({"client":label,"real_broker":true,"fake_upstream":true,"preferences_routing_only":!anthropic,"proves_l2_isolation":false,"preflight":preflight,"network_controls":controls,"client_result":client_result,"completion_marker":marker,"scratch_canary_free":clean,"scratch_removed":true,"upstream_requests":request_count,"canonical_audit_hash_matches":canonical_matches,"model_bound":model_bound,"max_bound":max_bound,"path_bound":path_bound,"injected_credential_matches":auth_bound,"usage":{"requests":usage.0,"output_tokens":usage.1,"pending":usage.2},"audit_secret_free":audit_clean,"session_created_revoked_match":sessions_match,"sessions_active":status["sessions_active"],"audit_events":audit.iter().map(|(event,reason,_)|json!({"event":event,"reason":reason})).collect::<Vec<_>>()});
    std::fs::write(
        artifacts.join(format!("{label}-observed.json")),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    drop(stmt);
    drop(db);
    broker.shutdown().await;
    assert_eq!(
        report["client_result"]["exit_code"], 0,
        "installed client failed; inspect sanitized artifact"
    );
    assert_eq!(report["client_result"]["group_absent"], true);
    assert_eq!(report["client_result"]["output_secret_free"], true);
    assert!(
        marker
            && clean
            && audit_clean
            && sessions_match
            && canonical_matches
            && model_bound
            && max_bound
            && path_bound
            && auth_bound
    );
    assert_eq!(usage, (1, 3, 0));
    assert_eq!(status["sessions_active"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "installed Claude Code; explicit paths and isolated synthetic acceptance only"]
async fn claude_code_through_real_gateway() {
    acceptance(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "installed Codex; test-only managed-preferences routing, not L2 isolation"]
async fn codex_through_real_gateway() {
    acceptance(false).await;
}
