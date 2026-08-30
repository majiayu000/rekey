//! Layer-2 transport: TLS/SNI, redirect, size limit, and read error against
//! a local HTTPS fixture. Screening stays production-strict; tests inject a
//! ScreenedEndpoint instead of relaxing private-IP rules.

use std::sync::Arc;
use std::time::Duration;

use rekey_broker::upstream::{ScreenedEndpoint, UpstreamError, UpstreamRequest, send_screened};
use rekey_domain::action::FixedMethod;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const HOST: &str = "api.test.local";

struct Fixture {
    port: u16,
    ca_der: Vec<u8>,
}

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn test_tls() -> (Vec<u8>, rustls::ServerConfig) {
    install_crypto();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rekey-test-ca");
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

async fn spawn_https(response: Vec<u8>, drop_after_write: bool) -> Fixture {
    let (ca_der, server) = test_tls();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
        let _ = tls.read(&mut buf).await;
        let _ = tls.write_all(&response).await;
        let _ = tls.flush().await;
        if !drop_after_write {
            let _ = tls.shutdown().await;
        }
    });
    Fixture { port, ca_der }
}

fn request(port: u16, max_bytes: u32) -> UpstreamRequest {
    UpstreamRequest {
        host: HOST.to_owned(),
        port,
        method: FixedMethod::Get,
        path: "/v1/ok".to_owned(),
        headers: vec![],
        auth_header: (
            "authorization".to_owned(),
            Zeroizing::new(b"Bearer test-token".to_vec()),
        ),
        body: vec![],
        timeout: Duration::from_secs(5),
        response_max_bytes: max_bytes,
    }
}

fn endpoint(port: u16) -> ScreenedEndpoint {
    ScreenedEndpoint {
        host: HOST.to_owned(),
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

fn http_response(status: u16, reason: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn screened_tls_roundtrip() {
    let body = br#"{"ok":true}"#;
    let fixture = spawn_https(
        http_response(200, "OK", &[("content-type", "application/json")], body),
        false,
    )
    .await;
    let response = send_screened(
        request(fixture.port, 1024),
        endpoint(fixture.port),
        Some(&fixture.ca_der),
    )
    .await
    .expect("tls send");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, body);
    assert!(
        response
            .headers
            .iter()
            .any(|(n, v)| n == "content-type" && v == "application/json")
    );
}

#[tokio::test]
async fn screened_redirect_is_blocked() {
    let fixture = spawn_https(
        http_response(
            302,
            "Found",
            &[("location", "https://evil.example/exfil")],
            b"",
        ),
        false,
    )
    .await;
    match send_screened(
        request(fixture.port, 1024),
        endpoint(fixture.port),
        Some(&fixture.ca_der),
    )
    .await
    {
        Err(UpstreamError::Blocked("redirect")) => {}
        Err(err) => panic!("expected redirect, got {err:?}"),
        Ok(_) => panic!("expected redirect, got success"),
    }
}

#[tokio::test]
async fn screened_oversize_body_is_rejected() {
    let body = vec![b'x'; 128];
    let fixture = spawn_https(
        http_response(200, "OK", &[("content-type", "text/plain")], &body),
        false,
    )
    .await;
    match send_screened(
        request(fixture.port, 32),
        endpoint(fixture.port),
        Some(&fixture.ca_der),
    )
    .await
    {
        Err(UpstreamError::ResponseTooLarge) => {}
        Err(err) => panic!("expected ResponseTooLarge, got {err:?}"),
        Ok(_) => panic!("expected ResponseTooLarge, got success"),
    }
}

#[tokio::test]
async fn screened_truncated_body_is_transport_error() {
    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort".to_vec();
    let fixture = spawn_https(response, true).await;
    match send_screened(
        request(fixture.port, 1024),
        endpoint(fixture.port),
        Some(&fixture.ca_der),
    )
    .await
    {
        Err(UpstreamError::Transport | UpstreamError::Timeout) => {}
        Err(err) => panic!("expected transport/timeout, got {err:?}"),
        Ok(_) => panic!("expected transport/timeout, got success"),
    }
}
