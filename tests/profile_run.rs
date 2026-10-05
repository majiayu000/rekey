#![cfg(feature = "lab")]
//! Actual `rekey run` owners over real Broker/Authority/SQLite and signed policy.
//! Only the fixed upstream transport is synthetic; no Keychain or network IO.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream as BlockingUnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId, RequestId};
use rekey_domain::ipc::{self, Channel, FrameHeader, admin_msg, agent_msg};
use rekey_integration::harness::{self, PASSWORD, TestBroker};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

const SECRET: &[u8] = b"PROFILE-RUN-E2E-SYNTHETIC-CREDENTIAL";
const PROFILE: &str = "run-e2e";
const BOUND: Duration = Duration::from_secs(5);

fn cli_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().unwrap().parent().unwrap().join("rekey");
    assert!(
        path.is_file(),
        "build rekey in this target before this test"
    );
    path
}

struct Fixture {
    broker: TestBroker,
    action: String,
    version: u64,
}

impl Fixture {
    async fn new() -> Self {
        let broker = harness::start_broker().await;
        harness::unlock(&broker).await;
        let credential = harness::add_credential(&broker, "run fixture", SECRET).await;
        let install = json!({
            "source":{"kind":"generic-bearer","origin":"https://api.example.com",
                "actions":[{"method":"POST","path":"/profile-run"}]},
            "credential_id":credential,"bindings":[{}],"capabilities":["fixed-actions"],
            "name_prefix":"run fixture","timeout_ms":2000,"request_max_bytes":4096,
            "allowed_extra_headers":[],"response_max_bytes":4096,"allowed_response_headers":[]
        });
        let installed = harness::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::TEMPLATE_INSTALL,
            &serde_json::to_vec(&install).unwrap(),
            &harness::proof_and_secret_body(PASSWORD, b""),
        )
        .await;
        let action = installed.ok()["actions"][0]["action"].clone();
        let key_doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(key_doc.as_ref()).unwrap();
        let signer = PolicySignerId::new_random();
        let trust = json!({"format_version":1,"signer_id":signer,"algorithm":"ed25519",
            "public_key":HEXLOWER.encode(key.public_key().as_ref())});
        harness::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::POLICY_TRUST_INSTALL,
            &serde_json::to_vec(&trust).unwrap(),
            &harness::proof_body(PASSWORD),
        )
        .await
        .ok();
        let principal = PrincipalId::new_random();
        let resource = json!({"type":"run-fixture","id":action["id"]});
        let mut bundle = json!({"format_version":1,"signer_id":signer,"snapshot":{
            "format_version":7,"version":1,"expires_at_ms":4_102_444_800_000_i64,
            "approvers":[],"workload_identities":[],
            "connections":[], "ssh_keys":[], "profiles":[{"name":PROFILE,"principal_id":principal,
                "grants":[{"instance":"run-fixture","capabilities":[{"capability":"fixed-actions","rule":"template-default",
                    "actions":[{"action_id":action["id"],"version":action["version"]}]}]}],
                "session":{"ttl_ms":120000,"max_uses":100},"confirm_each_run":false,
                "isolation":"none","egress":"allow","llm_limits":[]}],
            "bindings":[{"action_id":action["id"],"version":action["version"],"resource":resource,
                "parameter_schema_id":"run-fixture/v1","parameter_schema":{}}],
            "rules":[{"id":PolicyRuleId::new_random(),"effect":"permit","principal_id":principal,
                "action_id":action["id"],"version":action["version"],"resource":resource,
                "parameters":{"kind":"any_validated"}}]
        }});
        let mut signed = b"RKPOLICY\0\x01".to_vec();
        signed.extend(serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = BASE64URL_NOPAD.encode(key.sign(&signed).as_ref()).into();
        let status = harness::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::POLICY_STATUS,
            b"{}",
            &[],
        )
        .await;
        let activate = ipc::PolicyActivateMeta {
            expected_vault_id: serde_json::from_value(status.ok()["vault_id"].clone()).unwrap(),
            expected_trust_sha256: status.ok()["trust_sha256"].as_str().unwrap().into(),
            bundle_json: serde_json::from_slice(&serde_jcs::to_vec(&bundle).unwrap()).unwrap(),
        };
        harness::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::POLICY_ACTIVATE,
            &serde_json::to_vec(&activate).unwrap(),
            &harness::proof_body(PASSWORD),
        )
        .await
        .ok();
        Self {
            broker,
            action: action["id"].as_str().unwrap().into(),
            version: action["version"].as_u64().unwrap(),
        }
    }

    async fn execute(&self, capability: &str) -> harness::WireResponse {
        let meta = harness::execute_meta(capability, &self.action, self.version);
        harness::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            &serde_json::to_vec(&meta).unwrap(),
            b"{}",
        )
        .await
    }

    fn upstream_count(&self) -> usize {
        self.broker.fake.requests.lock().unwrap().len()
    }

    fn assert_upstream(&self) {
        let requests = self.broker.fake.requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert_eq!(request.host, "api.example.com");
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/profile-run");
            assert_eq!(request.auth_name, "authorization");
            assert!(request.auth_value == [b"Bearer ".as_slice(), SECRET].concat());
            assert_eq!(request.body, b"{}");
        }
    }
}

// Fixture-only IPC carries the synthetic capability as a length-delimited body,
// never stdout, argv or a file. Parent sends only nonsecret test commands.
struct RunOwner {
    cli: Child,
    control: UnixStream,
    capability: Zeroizing<String>,
    _stdin: ChildStdin,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl RunOwner {
    async fn start(fixture: &Fixture, label: &str) -> Self {
        let socket = fixture.broker.dir.path().join(format!("{label}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let stdout = fixture.broker.dir.path().join(format!("{label}.stdout"));
        let stderr = fixture.broker.dir.path().join(format!("{label}.stderr"));
        let mut cli = Command::new(cli_binary())
            .arg("--state-dir")
            .arg(&fixture.broker.state_dir)
            .args(["run", PROFILE, "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "profile_run_child", "--nocapture"])
            .env("REKEY_RUN_E2E_CONTROL", &socket)
            .env("REKEY_RUN_E2E_ACTION", &fixture.action)
            .env("REKEY_RUN_E2E_VERSION", fixture.version.to_string())
            .env_remove("REKEY_CAPABILITY")
            .env_remove("REKEY_AGENT_SOCKET")
            .current_dir(fixture.broker.dir.path())
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        // No proof flag/input; leaving the pipe open detects accidental prompts
        // or reads that would otherwise finish on EOF and mask a regression.
        let stdin = cli.stdin.take().unwrap();
        let accepted = tokio::time::timeout(BOUND, listener.accept()).await;
        let mut control = match accepted {
            Ok(Ok((stream, _))) => stream,
            _ => {
                let _ = cli.kill();
                let _ = cli.wait();
                panic!(
                    "real run did not start child: {}",
                    std::fs::read_to_string(&stderr).unwrap()
                );
            }
        };
        let capability = Zeroizing::new(read_private(&mut control).await);
        assert!(!capability.is_empty());
        Self {
            cli,
            control,
            capability,
            _stdin: stdin,
            stdout,
            stderr,
        }
    }

    async fn command(&mut self, command: u8) -> String {
        tokio::time::timeout(BOUND, async {
            self.control.write_all(&[command]).await.unwrap();
            read_private(&mut self.control).await
        })
        .await
        .expect("descendant stopped responding")
    }

    async fn exit_normally(&mut self) {
        assert_eq!(self.command(b'x').await, "exiting");
        let deadline = Instant::now() + BOUND;
        loop {
            if let Some(status) = self.cli.try_wait().unwrap() {
                assert_eq!(status.code(), Some(23));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "run failed to preserve child exit"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.assert_output_is_redacted();
    }

    fn assert_output_is_redacted(&self) {
        for path in [&self.stdout, &self.stderr] {
            let output = std::fs::read(path).unwrap();
            for canary in [PASSWORD, SECRET, self.capability.as_bytes()] {
                assert!(!output.windows(canary.len()).any(|window| window == canary));
            }
        }
    }
}

impl Drop for RunOwner {
    fn drop(&mut self) {
        if matches!(self.cli.try_wait(), Ok(None)) {
            let _ = self.cli.kill();
            let _ = self.cli.wait();
        }
        // Dropping fixture control also releases an orphaned child after panic.
    }
}

async fn read_private(stream: &mut UnixStream) -> String {
    let length = tokio::time::timeout(BOUND, stream.read_u32())
        .await
        .unwrap()
        .unwrap();
    assert!(length <= 4096);
    let mut bytes = Zeroizing::new(vec![0; length as usize]);
    tokio::time::timeout(BOUND, stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn write_private(stream: &mut BlockingUnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

fn child_execute(stream: &mut BlockingUnixStream, capability: &str) -> String {
    let version: u64 = std::env::var("REKEY_RUN_E2E_VERSION")
        .unwrap()
        .parse()
        .unwrap();
    let metadata = harness::execute_meta(
        capability,
        &std::env::var("REKEY_RUN_E2E_ACTION").unwrap(),
        version,
    );
    let metadata = Zeroizing::new(serde_json::to_vec(&metadata).unwrap());
    let header = FrameHeader {
        channel: Channel::Agent,
        flags: 0,
        message_type: agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        request_id: RequestId::new_random(),
        metadata_len: metadata.len() as u32,
        body_len: 2,
    };
    stream.write_all(&header.encode()).unwrap();
    stream.write_all(&metadata).unwrap();
    stream.write_all(b"{}").unwrap();
    let mut bytes = [0; ipc::FRAME_HEADER_LEN];
    stream.read_exact(&mut bytes).unwrap();
    let response = FrameHeader::decode(&bytes).unwrap();
    assert_eq!(response.request_id, header.request_id);
    let mut metadata = vec![0; response.metadata_len as usize];
    let mut body = vec![0; response.body_len as usize];
    stream.read_exact(&mut metadata).unwrap();
    stream.read_exact(&mut body).unwrap();
    for bytes in [&metadata, &body] {
        for canary in [PASSWORD, SECRET, capability.as_bytes()] {
            assert!(!bytes.windows(canary.len()).any(|window| window == canary));
        }
    }
    let metadata: Value = serde_json::from_slice(&metadata).unwrap();
    if response.message_type == ipc::resp_msg::OK {
        assert_eq!(metadata["upstream_status"], 200);
        assert_eq!(body, br#"{"ok":true}"#);
        "OK".into()
    } else {
        assert_eq!(response.message_type, ipc::resp_msg::ERROR);
        metadata["code"].as_str().unwrap().into()
    }
}

fn connect_agent(socket: &Path) -> BlockingUnixStream {
    let stream = BlockingUnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(BOUND)).unwrap();
    stream.set_write_timeout(Some(BOUND)).unwrap();
    stream
}

#[test]
fn profile_run_child() {
    let Some(control) = std::env::var_os("REKEY_RUN_E2E_CONTROL") else {
        return;
    };
    let mut control = BlockingUnixStream::connect(control).unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(90)))
        .unwrap();
    let capability = Zeroizing::new(std::env::var("REKEY_CAPABILITY").unwrap());
    let socket = PathBuf::from(std::env::var_os("REKEY_AGENT_SOCKET").unwrap());
    assert!(std::env::args_os().all(|arg| !arg.to_string_lossy().contains(capability.as_str())));
    let mut agent = connect_agent(&socket);
    write_private(&mut control, capability.as_bytes());
    let mut command = [0];
    while control.read_exact(&mut command).is_ok() {
        match command[0] {
            b'e' => write_private(
                &mut control,
                child_execute(&mut agent, &capability).as_bytes(),
            ),
            b'r' => {
                // Agent frame idle timeout is independent of the owner control.
                agent = connect_agent(&socket);
                write_private(&mut control, b"reconnected");
            }
            b'p' => write_private(&mut control, b"alive"),
            b'x' => {
                write_private(&mut control, b"exiting");
                std::process::exit(23);
            }
            _ => panic!("unknown private fixture command"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_run_false_needs_no_input_survives_31_seconds_and_normal_exit_revokes() {
    let fixture = Fixture::new().await;
    let mut owner = RunOwner::start(&fixture, "idle").await;
    assert_eq!(owner.command(b'e').await, "OK");
    assert_eq!(fixture.upstream_count(), 1);
    // No heartbeats or input during the entire original frame-timeout window.
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(owner.cli.try_wait().unwrap().is_none());
    assert_eq!(owner.command(b'r').await, "reconnected");
    assert_eq!(owner.command(b'e').await, "OK");
    assert_eq!(fixture.upstream_count(), 2);
    owner.exit_normally().await;
    let deadline = Instant::now() + BOUND;
    loop {
        let response = fixture.execute(&owner.capability).await;
        if response.message_type == ipc::resp_msg::ERROR {
            assert_eq!(response.err_code(), "INVALID_CAPABILITY");
            break;
        }
        assert!(Instant::now() < deadline, "normal run exit did not revoke");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let calls = fixture.upstream_count();
    assert_eq!(
        fixture.execute(&owner.capability).await.err_code(),
        "INVALID_CAPABILITY"
    );
    assert_eq!(fixture.upstream_count(), calls);
    fixture.assert_upstream();
    drop(owner);
    fixture.broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_run_sigkill_revokes_retained_capability_and_socket_without_harming_other_owner() {
    let fixture = Fixture::new().await;
    let mut first = RunOwner::start(&fixture, "first").await;
    let mut second = RunOwner::start(&fixture, "second").await;
    assert_eq!(first.command(b'e').await, "OK");
    assert_eq!(second.command(b'e').await, "OK");
    // Child retains the capability and the same agent socket. The genuine CLI
    // control FD is CLOEXEC, so this E2E does not claim to isolate EOF from the
    // OS owner event; retained-control-FD causality is covered by owner tests.
    let killed_at = Instant::now();
    first.cli.kill().unwrap();
    assert_eq!(first.cli.wait().unwrap().signal(), Some(9));
    assert_eq!(first.command(b'p').await, "alive");
    loop {
        let code = first.command(b'e').await;
        if code == "INVALID_CAPABILITY" {
            break;
        }
        assert_eq!(code, "OK");
        assert!(
            killed_at.elapsed() < BOUND,
            "SIGKILL failed to revoke within five seconds"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(killed_at.elapsed() < BOUND);
    let calls = fixture.upstream_count();
    assert_eq!(first.command(b'e').await, "INVALID_CAPABILITY");
    assert_eq!(fixture.upstream_count(), calls);
    assert_eq!(first.command(b'p').await, "alive");
    assert!(second.cli.try_wait().unwrap().is_none());
    assert_eq!(second.command(b'e').await, "OK");
    assert_eq!(fixture.upstream_count(), calls + 1);
    assert_eq!(first.command(b'x').await, "exiting");
    first.assert_output_is_redacted();
    second.exit_normally().await;
    fixture.assert_upstream();
    drop((first, second));
    fixture.broker.shutdown_keep_dir().await;
}
