//! Deterministic real TLS -> production streaming transport -> Broker -> Agent UDS.
mod common;

use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamFuture, UpstreamRequest, UpstreamStreamFuture, UpstreamTransport,
    open_stream_screened,
};
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{self, Channel, FRAME_HEADER_LEN, FrameHeader, admin_msg, agent_msg};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::oneshot;

const SECRET: &[u8] = b"opaque-stream-key";
const HOST: &str = "api.anthropic.com";
const REQUEST: &[u8] = br#"{"messages":[{"role":"user","content":"hello"}]}"#;

struct TlsTransport {
    port: u16,
    ca: Vec<u8>,
}
impl UpstreamTransport for TlsTransport {
    fn send(&self, _: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async { panic!("stream must not call buffered transport") })
    }
    fn open_stream(&self, mut request: UpstreamRequest) -> UpstreamStreamFuture<'_> {
        Box::pin(async move {
            assert_eq!(request.host, HOST);
            assert_eq!(request.port, 443);
            assert_eq!(request.path, "/v1/messages");
            assert_eq!(request.auth_header.0, "x-api-key");
            assert!(request.auth_header.1.as_slice() == SECRET);
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["model"], "fixed-test-model");
            assert_eq!(body["max_tokens"], 2048);
            assert_eq!(body["stream"], true);
            assert_eq!(body["messages"][0]["content"], "hello");
            // Only the deterministic fixture injects a screened local socket.
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

fn event(kind: &str, extra: serde_json::Value) -> Vec<u8> {
    let mut value = extra;
    value["type"] = kind.into();
    format!("event: {kind}\ndata: {}\n\n", value).into_bytes()
}
fn delta(text: &str) -> Vec<u8> {
    event(
        "content_block_delta",
        serde_json::json!({"index":0,"delta":{"type":"text_delta","text":text}}),
    )
}
fn first(text: &str) -> Vec<u8> {
    [
        event(
            "message_start",
            serde_json::json!({"message":{"role":"assistant","content":[],"stop_reason":null}}),
        ),
        event(
            "content_block_start",
            serde_json::json!({"index":0,"content_block":{"type":"text","text":""}}),
        ),
        delta(text),
    ]
    .concat()
}
fn ending(reason: &str) -> Vec<u8> {
    [
        event("content_block_stop", serde_json::json!({"index":0})),
        event(
            "message_delta",
            serde_json::json!({"delta":{"stop_reason":reason,"stop_sequence":null}}),
        ),
        event("message_stop", serde_json::json!({})),
    ]
    .concat()
}

async fn fixture(
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    bytewise: bool,
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
        socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n").await.unwrap();
        let piece = if bytewise { 1 } else { 4096 };
        for chunk in prefix.chunks(piece) {
            socket
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            socket.write_all(chunk).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
        }
        socket.flush().await.unwrap();
        let _ = wait.await;
        for chunk in suffix.chunks(piece) {
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
        Arc::new(TlsTransport { port, ca: cert }),
        release,
        done,
        task,
    )
}

async fn setup(
    transport: Arc<TlsTransport>,
    timeout: u32,
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
    action["allowed_extra_headers"] = serde_json::json!([]);
    action["allowed_response_headers"] = serde_json::json!([]);
    action["response_max_bytes"] = (4 * 1024 * 1024).into();
    action["timeout_ms"] = timeout.into();
    action["text_stream"] = serde_json::json!({"model":"fixed-test-model","max_tokens":2048});
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
                body_len: REQUEST.len() as u32,
            }
            .encode(),
        )
        .await
        .unwrap();
    socket.write_all(metadata.as_bytes()).await.unwrap();
    socket.write_all(REQUEST).await.unwrap();
    (socket, id)
}
async fn next(
    socket: &mut UnixStream,
    id: RequestId,
    sequence: u32,
) -> (u16, serde_json::Value, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(4), async {
        let mut raw = [0; FRAME_HEADER_LEN];
        socket.read_exact(&mut raw).await.unwrap();
        let frame = FrameHeader::decode(&raw).unwrap();
        assert_eq!(frame.request_id, id);
        assert_eq!(frame.channel, Channel::Agent);
        let mut metadata = vec![0; frame.metadata_len as usize];
        socket.read_exact(&mut metadata).await.unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["sequence"], sequence);
        let mut body = vec![0; frame.body_len as usize];
        socket.read_exact(&mut body).await.unwrap();
        (frame.message_type, metadata, body)
    })
    .await
    .expect("bounded stream response")
}
async fn rest(socket: &mut UnixStream, id: RequestId, mut sequence: u32) -> (String, Vec<u8>) {
    let mut text = Vec::new();
    loop {
        let (kind, metadata, body) = next(socket, id, sequence).await;
        if kind == ipc::resp_msg::STREAM_TERMINAL {
            assert!(body.is_empty());
            return (metadata["status"].as_str().unwrap().into(), text);
        }
        assert_eq!(kind, ipc::resp_msg::STREAM_CHUNK);
        assert!(!body.is_empty());
        assert!(std::str::from_utf8(&body).is_ok());
        text.extend(body);
        sequence += 1;
    }
}
fn audit_count(broker: &common::TestBroker, event: &str) -> i64 {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    db.query_row(
        "SELECT count(*) FROM audit_events WHERE event_type = ?1",
        [event],
        |r| r.get(0),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn real_tls_first_checked_chunk_precedes_upstream_finish_and_audit_precedes_success() {
    let expected = "界".repeat(2048);
    let (transport, release, done, server) =
        fixture(first(&expected), ending("end_turn"), true).await;
    let (broker, metadata) = setup(transport, 5000).await;
    let (mut socket, id) = begin(&broker, &metadata).await;
    let (kind, _, body) = next(&mut socket, id, 0).await;
    assert_eq!(kind, ipc::resp_msg::STREAM_CHUNK);
    assert!(!body.is_empty());
    assert!(
        !done.load(Ordering::SeqCst),
        "whole response buffering cannot pass this barrier"
    );
    assert_eq!(audit_count(&broker, "execution.finished"), 0);
    release.send(()).unwrap();
    let (status, tail) = rest(&mut socket, id, 1).await;
    assert_eq!(status, "completed");
    assert_eq!([body, tail].concat(), expected.as_bytes());
    assert_eq!(audit_count(&broker, "execution.finished"), 1);
    server.await.unwrap();
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn late_secret_truncation_error_and_incomplete_never_report_success_or_flush_tail() {
    for (suffix,wanted) in [
        ([delta("opaque-"),delta("stream-key"),ending("end_turn")].concat(),"failed"),
        (b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\\u006fpaque-stream-key\"}}\n\n".to_vec(),"failed"),
        (Vec::new(),"failed"),
        (event("error",serde_json::json!({"error":{"message":"private-provider-error"}})),"failed"),
        (ending("max_tokens"),"incomplete"),
        (ending("refusal"),"incomplete"),
    ] {
        let (transport,release,_,server)=fixture(first(&"z".repeat(4096)),suffix,false).await;
        let (broker,metadata)=setup(transport,3000).await;
        let (mut socket,id)=begin(&broker,&metadata).await;
        let (kind,_,prefix)=next(&mut socket,id,0).await;
        assert_eq!(kind,ipc::resp_msg::STREAM_CHUNK);assert!(prefix.iter().all(|b|*b==b'z'));
        release.send(()).unwrap();let (status,tail)=rest(&mut socket,id,1).await;
        assert_eq!(status,wanted);assert!(tail.iter().all(|b|*b==b'z'));
        assert!(prefix.len()+tail.len()<4096,"failed/incomplete must not flush retained suffix");
        assert_eq!(audit_count(&broker,"execution.finished"),0);
        server.await.unwrap();broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_after_prefix_is_failed_and_drain_cleans_up() {
    let (transport, release, _, server) =
        fixture(first(&"z".repeat(4096)), ending("end_turn"), false).await;
    let (broker, metadata) = setup(transport, 200).await;
    let (mut socket, id) = begin(&broker, &metadata).await;
    next(&mut socket, id, 0).await;
    // The same absolute deadline closes IPC: no late chunk or completed
    // terminal may be written after upstream timeout. EOF is failure.
    let mut raw = [0; FRAME_HEADER_LEN];
    let result = tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut raw))
        .await
        .unwrap();
    if result.is_ok() {
        let frame = FrameHeader::decode(&raw).unwrap();
        assert_eq!(frame.message_type, ipc::resp_msg::STREAM_TERMINAL);
        let mut meta = vec![0; frame.metadata_len as usize];
        socket.read_exact(&mut meta).await.unwrap();
        let meta: ipc::TextStreamTerminalMeta = serde_json::from_slice(&meta).unwrap();
        assert_ne!(meta.status, ipc::TextStreamStatus::Completed);
    }
    let _ = release.send(());
    server.await.unwrap();
    assert_eq!(audit_count(&broker, "execution.finished"), 0);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnected_client_cannot_abandon_runtime_audit() {
    let (transport, release, _, server) = fixture(
        first(&"z".repeat(4096)),
        [delta(&"z".repeat(4096)), ending("end_turn")].concat(),
        false,
    )
    .await;
    let (broker, metadata) = setup(transport, 3000).await;
    let (mut socket, id) = begin(&broker, &metadata).await;
    next(&mut socket, id, 0).await;
    drop(socket);
    release.send(()).unwrap();
    server.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if audit_count(&broker, "execution.finished") == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn finished_audit_fault_prevents_completed_terminal_after_checked_prefix() {
    let (transport, release, _, server) =
        fixture(first(&"z".repeat(4096)), ending("end_turn"), false).await;
    let (broker, metadata) = setup(transport, 3000).await;
    let (mut socket, id) = begin(&broker, &metadata).await;
    next(&mut socket, id, 0).await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_stream_finished BEFORE INSERT ON audit_events WHEN NEW.event_type = 'execution.finished' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    drop(db);
    release.send(()).unwrap();
    let (status, _) = rest(&mut socket, id, 1).await;
    assert_eq!(status, "failed");
    assert_eq!(audit_count(&broker, "execution.finished"), 0);
    server.await.unwrap();
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn old_execute_rejects_stream_action_with_empty_error() {
    let (transport, release, _, server) = fixture(Vec::new(), Vec::new(), false).await;
    let (broker, metadata) = setup(transport, 3000).await;
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        metadata.to_string().as_bytes(),
        REQUEST,
    )
    .await;
    assert_eq!(response.err_code(), "REQUEST_DENIED");
    assert!(response.body.is_empty());
    drop(release);
    server.abort();
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_consumer_cannot_extend_effect_deadline_or_receive_completed() {
    use std::os::fd::AsRawFd;
    let (transport, release, _, server) = fixture(
        first(&"z".repeat(4096)),
        [delta(&"z".repeat(2 * 1024 * 1024)), ending("end_turn")].concat(),
        false,
    )
    .await;
    let (broker, metadata) = setup(transport, 1000).await;
    let (mut socket, id) = begin(&broker, &metadata).await;
    next(&mut socket, id, 0).await;
    let size: libc::c_int = 1024;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if audit_count(&broker, "execution.indeterminate") > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("backpressured execution must audit deadline failure");
    assert_eq!(audit_count(&broker, "execution.finished"), 0);
    drop(socket);
    server.await.unwrap();
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_crlf_lf_events_work_coalesced_and_bytewise_over_tls() {
    for bytewise in [false, true] {
        let expected = "z".repeat(4096);
        let prefix = String::from_utf8(first(&expected)).unwrap();
        let first_end = prefix.find("\n\n").unwrap() + 2;
        let prefix = [
            prefix[..first_end].replace('\n', "\r\n").as_bytes(),
            &prefix.as_bytes()[first_end..],
        ]
        .concat();
        let (transport, release, done, server) =
            fixture(prefix, ending("end_turn"), bytewise).await;
        let (broker, metadata) = setup(transport, 5000).await;
        let (mut socket, id) = begin(&broker, &metadata).await;
        let (kind, _, prefix) = next(&mut socket, id, 0).await;
        assert_eq!(kind, ipc::resp_msg::STREAM_CHUNK);
        assert!(!done.load(Ordering::SeqCst));
        release.send(()).unwrap();
        let (status, tail) = rest(&mut socket, id, 1).await;
        assert_eq!(status, "completed");
        assert_eq!([prefix, tail].concat(), expected.as_bytes());
        server.await.unwrap();
        broker.shutdown().await;
    }
}
