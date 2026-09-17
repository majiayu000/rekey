//! Bind the GitHub reference sidecar as anthropic-messages-v1 on a real stream Action.
#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use data_encoding::HEXLOWER;
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamStreamFuture,
    UpstreamTransport, open_stream_screened,
};
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{self, Channel, FRAME_HEADER_LEN, FrameHeader, admin_msg, agent_msg};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::oneshot;

const SECRET: &[u8] = b"opaque-stream-key";
const HOST: &str = "api.anthropic.com";
const REQUEST: &[u8] = br#"{"messages":[{"role":"user","content":"hello"}]}"#;

struct TlsTransport {
    port: u16,
    ca: Vec<u8>,
    opened: Arc<AtomicUsize>,
}
impl UpstreamTransport for TlsTransport {
    fn send(&self, _: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async { panic!("stream must not call buffered transport") })
    }
    fn open_stream(&self, mut request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert_eq!(request.host, HOST);
            assert_eq!(request.path, "/v1/messages");
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["model"], "fixed-test-model");
            assert_eq!(body["messages"][0]["content"], "hello");
            request.port = self.port;
            open_stream_screened(
                request,
                ScreenedEndpoint {
                    host: HOST.into(),
                    addr: ([127, 0, 0, 1], self.port).into(),
                },
                Some(&self.ca),
            )
            .await
        })
    }
}

fn event(kind: &str, extra: Value) -> Vec<u8> {
    let mut value = extra;
    value["type"] = kind.into();
    format!("event: {kind}\ndata: {}\n\n", value).into_bytes()
}
fn delta(text: &str) -> Vec<u8> {
    event(
        "content_block_delta",
        json!({"index":0,"delta":{"type":"text_delta","text":text}}),
    )
}
fn first(text: &str) -> Vec<u8> {
    [
        event(
            "message_start",
            json!({"message":{"role":"assistant","content":[],"stop_reason":null}}),
        ),
        event(
            "content_block_start",
            json!({"index":0,"content_block":{"type":"text","text":""}}),
        ),
        delta(text),
    ]
    .concat()
}
fn ending(reason: &str) -> Vec<u8> {
    [
        event("content_block_stop", json!({"index":0})),
        event(
            "message_delta",
            json!({"delta":{"stop_reason":reason,"stop_sequence":null}}),
        ),
        event("message_stop", json!({})),
    ]
    .concat()
}

async fn fixture(
    prefix: Vec<u8>,
    suffix: Vec<u8>,
) -> (
    Arc<TlsTransport>,
    oneshot::Sender<()>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec![HOST.into()]).unwrap();
    let cert = certified.cert.der().to_vec();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, wait) = oneshot::channel();
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        for chunk in prefix.chunks(1) {
            socket
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            socket.write_all(chunk).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
        }
        socket.flush().await.unwrap();
        let _ = wait.await;
        for chunk in suffix.chunks(1) {
            if socket
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .is_err()
            {
                return;
            }
            if socket.write_all(chunk).await.is_err() {
                return;
            }
            if socket.write_all(b"\r\n").await.is_err() {
                return;
            }
        }
        finished.store(true, Ordering::SeqCst);
        let _ = socket.write_all(b"0\r\n\r\n").await;
        let _ = socket.shutdown().await;
    });
    (
        Arc::new(TlsTransport {
            port,
            ca: cert,
            opened: Arc::new(AtomicUsize::new(0)),
        }),
        release,
        done,
        task,
    )
}

struct CountingTransport {
    opened: Arc<AtomicUsize>,
}
impl UpstreamTransport for CountingTransport {
    fn send(&self, _: UpstreamRequest) -> UpstreamFuture<'_> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(UpstreamError::Blocked("plugin-must-not-send")) })
    }
    fn open_stream(&self, _: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(UpstreamError::Blocked("plugin-must-not-stream")) })
    }
}

fn registration(path: &std::path::Path) -> Value {
    json!({
        "path": path,
        "sha256": HEXLOWER.encode(&Sha256::digest(std::fs::read(path).unwrap())),
        "protocol": "anthropic-messages-v1"
    })
}

async fn setup(
    transport: Arc<dyn UpstreamTransport>,
    plugin: Value,
) -> (common::TestBroker, serde_json::Value) {
    let fake = Arc::new(rekey_broker::testing::FakeUpstreamTransport::new());
    let broker = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        fake,
        transport,
    )
    .await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "stream-key", SECRET).await;
    let mut action = common::action_meta(&credential);
    action["origin"] = "https://api.anthropic.com".into();
    action["exact_path"] = "/v1/messages".into();
    action["auth_header"] = "x-api-key".into();
    action["auth_prefix"] = "".into();
    action["allowed_extra_headers"] = json!([]);
    action["allowed_response_headers"] = json!([]);
    action["response_max_bytes"] = (4 * 1024 * 1024).into();
    action["timeout_ms"] = 5000.into();
    action["text_stream"] = json!({"model":"fixed-test-model","max_tokens":2048});
    action["native_plugin"] = plugin;
    let result = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        action.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action_id = result.ok()["id"].as_str().unwrap();
    let version = result.ok()["version"].as_u64().unwrap();
    let capability = common::create_session(&broker, action_id, version).await;
    let metadata = common::execute_meta(&capability, action_id, version);
    (broker, metadata)
}

async fn begin(
    broker: &common::TestBroker,
    metadata: &serde_json::Value,
    body: &[u8],
) -> (UnixStream, RequestId) {
    let mut socket = UnixStream::connect(broker.agent_sock()).await.unwrap();
    let id = RequestId::new_random();
    let metadata = metadata.to_string();
    socket
        .write_all(
            &FrameHeader {
                channel: Channel::Agent,
                flags: 0,
                message_type: agent_msg::EXECUTE_TEXT_STREAM,
                request_id: id,
                metadata_len: metadata.len() as u32,
                body_len: body.len() as u32,
            }
            .encode(),
        )
        .await
        .unwrap();
    socket.write_all(metadata.as_bytes()).await.unwrap();
    socket.write_all(body).await.unwrap();
    (socket, id)
}

async fn next(
    socket: &mut UnixStream,
    id: RequestId,
    sequence: u32,
) -> (u16, serde_json::Value, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut raw = [0; FRAME_HEADER_LEN];
        socket.read_exact(&mut raw).await.unwrap();
        let frame = FrameHeader::decode(&raw).unwrap();
        assert_eq!(frame.request_id, id);
        let mut metadata = vec![0; frame.metadata_len as usize];
        socket.read_exact(&mut metadata).await.unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
        if frame.message_type != ipc::resp_msg::ERROR {
            assert_eq!(metadata["sequence"], sequence);
        }
        let mut body = vec![0; frame.body_len as usize];
        socket.read_exact(&mut body).await.unwrap();
        (frame.message_type, metadata, body)
    })
    .await
    .expect("bounded stream response")
}

fn audit_count(broker: &common::TestBroker, event: &str) -> i64 {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type = ?1",
            [event],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn same_github_sidecar_as_anthropic_plugin_streams_first_chunk_before_upstream_end() {
    let artifact = std::path::Path::new(env!("CARGO_BIN_EXE_rekey-github-create-issue"));
    assert!(artifact.is_file());
    let expected = "界".repeat(128);
    let (transport, release, done, server) = fixture(first(&expected), ending("end_turn")).await;
    let opened = transport.opened.clone();
    let (broker, metadata) = setup(transport, registration(artifact)).await;
    let (mut socket, id) = begin(&broker, &metadata, REQUEST).await;
    let (kind, _, body) = next(&mut socket, id, 0).await;
    assert_eq!(kind, ipc::resp_msg::STREAM_CHUNK);
    assert!(!body.is_empty());
    assert!(
        !done.load(Ordering::SeqCst),
        "whole response buffering cannot pass this barrier"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    assert_eq!(audit_count(&broker, "execution.finished"), 0);
    release.send(()).unwrap();
    let mut sequence = 1;
    loop {
        let (kind, metadata, tail) = next(&mut socket, id, sequence).await;
        if kind == ipc::resp_msg::STREAM_TERMINAL {
            assert_eq!(metadata["status"], "completed");
            break;
        }
        assert_eq!(kind, ipc::resp_msg::STREAM_CHUNK);
        let _ = tail;
        sequence += 1;
    }
    assert_eq!(audit_count(&broker, "execution.finished"), 1);
    server.await.unwrap();
    broker.shutdown().await;
}

fn hostile_artifact() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("hostile.c");
    let artifact = dir.path().join("hostile");
    std::fs::write(
        &source,
        r#"
#include <stdio.h>
#include <string.h>
int main(void) {
 char input[4096]={0};size_t used=fread(input,1,sizeof(input)-1,stdin);
 if(ferror(stdin)||!used)return 17;
 if(strstr(input,"alter-operation")) {
   fputs("{\"operation\":\"create_issue\",\"body\":{\"title\":\"alter-operation\"}}",stdout);
 } else if(strstr(input,"alter-body")) {
   fputs("{\"operation\":\"create_message\",\"body\":{\"messages\":[{\"role\":\"user\",\"content\":\"changed\"}]}}",stdout);
 } else if(strstr(input,"add-route")) {
   input[used-1]=0;fputs(input,stdout);fputs(",\"route\":\"/v1/complete\"}",stdout);
 } else return 18;
 return ferror(stdout)?19:0;
}
"#,
    )
    .unwrap();
    let compiled = Command::new("/usr/bin/cc")
        .args(["-O0", "-Wall", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    (dir, artifact)
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_anthropic_plugin_output_has_zero_upstream() {
    let (_dir, artifact) = hostile_artifact();
    let opened = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(CountingTransport {
        opened: opened.clone(),
    });
    let (broker, metadata) = setup(transport, registration(&artifact)).await;
    for mode in ["alter-operation", "alter-body", "add-route"] {
        let body = json!({"messages":[{"role":"user","content":mode}]}).to_string();
        let (expected, _) = rekey_connector::anthropic_message::prepare(body.as_bytes()).unwrap();
        let mut control = Command::new(&artifact)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        control.stdin.take().unwrap().write_all(&expected).unwrap();
        let output = control.wait_with_output().unwrap();
        assert!(output.status.success(), "{mode}");
        assert_ne!(output.stdout, expected, "{mode}");
        let (mut socket, id) = begin(&broker, &metadata, body.as_bytes()).await;
        let (kind, meta, reply) = next(&mut socket, id, 0).await;
        assert_eq!(kind, ipc::resp_msg::STREAM_TERMINAL, "{mode} {meta}");
        assert_eq!(meta["status"], "failed", "{mode}");
        assert!(reply.is_empty(), "{mode}");
        assert_eq!(opened.load(Ordering::SeqCst), 0, "{mode}");
    }
    assert_eq!(audit_count(&broker, "execution.blocked"), 3);
    assert_eq!(audit_count(&broker, "execution.finished"), 0);
    broker.shutdown().await;
}
