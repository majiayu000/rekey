//! Release-build acceptance fixture. It runs the real broker runtime and UDS
//! against a local CA/TLS server through the same screened HTTPS transport.
//! Production `rekeyd` never trusts this CA or permits loopback destinations.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamFuture, UpstreamRequest, UpstreamTransport, send_screened,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const HOST: &str = "api.test.local";

struct LocalTlsTransport {
    address: SocketAddr,
    ca_der: Arc<Vec<u8>>,
}

impl UpstreamTransport for LocalTlsTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        let endpoint = ScreenedEndpoint {
            host: request.host.clone(),
            addr: self.address,
        };
        let ca_der = Arc::clone(&self.ca_der);
        Box::pin(async move { send_screened(request, endpoint, Some(&ca_der)).await })
    }
}

fn tls_config() -> Result<(Vec<u8>, rustls::ServerConfig), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rekey-p1-acceptance-ca");
    let ca_key = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut leaf_params = rcgen::CertificateParams::new(vec![HOST.to_owned()])?;
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    let leaf_key = rcgen::KeyPair::generate()?;
    let leaf = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;
    let certs = vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((ca_cert.der().to_vec(), server))
}

fn write_hits(path: &Path, hits: u64) -> std::io::Result<()> {
    std::fs::write(path, format!("{hits}\n"))
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    hits: Arc<AtomicU64>,
    hits_path: PathBuf,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let hits = Arc::clone(&hits);
        let hits_path = hits_path.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let mut request = Vec::new();
            let mut chunk = [0u8; 2048];
            while request.len() <= 64 * 1024 {
                let Ok(read) = tls.read(&mut chunk).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let count = hits.fetch_add(1, Ordering::SeqCst) + 1;
            if write_hits(&hits_path, count).is_err() {
                return;
            }
            let body = br#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            if tls.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            let _ = tls.write_all(body).await;
            let _ = tls.shutdown().await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let state_dir = PathBuf::from(args.next().ok_or("missing state dir")?);
    let ready_path = PathBuf::from(args.next().ok_or("missing ready path")?);
    let hits_path = PathBuf::from(args.next().ok_or("missing hits path")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }

    let (ca_der, server) = tls_config()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    write_hits(&hits_path, 0)?;
    std::fs::write(&ready_path, format!("{}\n", address.port()))?;
    tokio::spawn(serve_tls(
        listener,
        TlsAcceptor::from(Arc::new(server)),
        Arc::new(AtomicU64::new(0)),
        hits_path,
    ));

    let mut config = BrokerConfig::new(state_dir);
    config.idle_lock = Duration::from_secs(15 * 60);
    config.transport = Some(Arc::new(LocalTlsTransport {
        address,
        ca_der: Arc::new(ca_der),
    }));
    config.unlock_backoff_base = Duration::from_millis(250);
    config.drain_timeout = Duration::from_secs(30);
    serve(config).await?;
    Ok(())
}
