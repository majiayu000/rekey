//! Ordinary HTTP effects that reach a TLS upstream but lose their response
//! must be audited as unknown, never denied.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamFuture, UpstreamRequest, UpstreamTransport, send_screened,
};
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const HOST: &str = "api.effect.test";

struct TimeoutTlsTransport {
    endpoint: ScreenedEndpoint,
    ca_der: Vec<u8>,
}

impl UpstreamTransport for TimeoutTlsTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(
            async move { send_screened(request, self.endpoint.clone(), Some(&self.ca_der)).await },
        )
    }
}

struct TlsFixture {
    port: u16,
    ca_der: Vec<u8>,
    request_observed: Arc<AtomicBool>,
}

fn test_tls() -> (Vec<u8>, rustls::ServerConfig) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rekey-effect-test-ca");
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec![HOST.to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf cert");
    let certs = vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    (ca_cert.der().to_vec(), server)
}

fn request_is_complete(bytes: &[u8]) -> bool {
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    bytes.len() >= header_end + 4 + content_length
}

async fn spawn_timeout_tls() -> TlsFixture {
    let (ca_der, server) = test_tls();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let request_observed = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let request_observed = Arc::clone(&request_observed);
        async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(stream).await.expect("tls accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while request.len() <= 16 * 1024 && !request_is_complete(&request) {
                let read = tls.read(&mut chunk).await.expect("read request");
                assert_ne!(read, 0, "request closed before its body completed");
                request.extend_from_slice(&chunk[..read]);
            }
            assert!(request_is_complete(&request), "incomplete HTTP request");
            request_observed.store(true, Ordering::SeqCst);
            // Keep the TLS connection open without returning a response. The
            // real reqwest timeout must fire after the server saw the effect.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    TlsFixture {
        port,
        ca_der,
        request_observed,
    }
}

async fn create_timeout_action(
    broker: &common::TestBroker,
    credential_id: &str,
    port: u16,
) -> (String, u64) {
    let mut metadata = common::action_meta(credential_id);
    metadata["origin"] = format!("https://{HOST}:{port}").into();
    metadata["timeout_ms"] = 200.into();
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        metadata.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let ok = response.ok();
    (
        ok["id"].as_str().unwrap().to_owned(),
        ok["version"].as_u64().unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn post_side_effect_timeout_is_indeterminate() {
    let fixture = spawn_timeout_tls().await;
    let fake = Arc::new(FakeUpstreamTransport::new());
    let transport = Arc::new(TimeoutTlsTransport {
        endpoint: ScreenedEndpoint {
            host: HOST.to_owned(),
            addr: format!("127.0.0.1:{}", fixture.port).parse().unwrap(),
        },
        ca_der: fixture.ca_der,
    });
    let broker = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        fake,
        transport,
    )
    .await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "timeout-effect", b"secret").await;
    let (action_id, version) = create_timeout_action(&broker, &credential_id, fixture.port).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "UPSTREAM_FAILED");
    assert!(
        fixture.request_observed.load(Ordering::SeqCst),
        "TLS upstream must receive the complete request before timeout"
    );

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let conn = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT event_type, outcome, reason_code FROM audit_events
             WHERE event_type LIKE 'execution.%' ORDER BY sequence",
        )
        .unwrap();
    let events = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        events,
        vec![
            (
                "execution.started".into(),
                "success".into(),
                "started".into()
            ),
            (
                "execution.indeterminate".into(),
                "unknown".into(),
                "upstream-timeout".into(),
            ),
        ]
    );
}
