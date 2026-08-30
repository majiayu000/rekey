//! Release-build acceptance fixture. It runs the real broker runtime and UDS
//! against a local CA/TLS server through the same screened HTTPS transport.
//! Production `rekeyd` never trusts this CA or permits loopback destinations.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use data_encoding::{BASE64, BASE64URL_NOPAD};
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

struct FixtureRequest {
    path: String,
    mode: Option<String>,
    secret: Vec<u8>,
}

async fn read_request(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> std::io::Result<FixtureRequest> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 2048];
    let header_end = loop {
        if request.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
        let read = tls.read(&mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request truncated",
            ));
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
    };

    let headers = std::str::from_utf8(&request[..header_end])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid headers"))?;
    let request_line = headers.lines().next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line")
    })?;
    let path = request_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing path"))?
        .to_owned();
    let mut content_length = 0usize;
    let mut secret = None;
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "bad content length")
            })?;
        } else if name.eq_ignore_ascii_case("authorization") {
            secret = Some(
                value
                    .trim()
                    .strip_prefix("Bearer ")
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "missing bearer prefix",
                        )
                    })?
                    .as_bytes()
                    .to_vec(),
            );
        }
    }
    while request.len() < header_end + content_length {
        let read = tls.read(&mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request body truncated",
            ));
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let body = &request[header_end..header_end + content_length];
    let mode = if path == "/v1/sealing" {
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request json")
        })?;
        Some(
            value
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing mode")
                })?
                .to_owned(),
        )
    } else {
        None
    };
    Ok(FixtureRequest {
        path,
        mode,
        secret: secret.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing credential")
        })?,
    })
}

async fn write_fragmented(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    bytes: &[u8],
) -> std::io::Result<()> {
    for fragment in bytes.chunks(3) {
        tls.write_all(fragment).await?;
        tls.flush().await?;
        tokio::task::yield_now().await;
    }
    Ok(())
}

async fn write_chunk(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    bytes: &[u8],
) -> std::io::Result<()> {
    write_fragmented(tls, format!("{:x}\r\n", bytes.len()).as_bytes()).await?;
    write_fragmented(tls, bytes).await?;
    write_fragmented(tls, b"\r\n").await
}

async fn write_chunked_headers(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> std::io::Result<()> {
    write_fragmented(
        tls,
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
    )
    .await
}

fn fixture_percent_encode(bytes: &[u8]) -> Vec<u8> {
    let mut output = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(*byte as char);
        } else {
            output.push_str(&format!("%{byte:02x}"));
        }
    }
    output.into_bytes()
}

async fn write_reflection(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    variant: &[u8],
) -> std::io::Result<()> {
    write_chunked_headers(tls).await?;
    let split = (variant.len() / 2).max(1).min(variant.len());
    let mut first = b"before:".to_vec();
    first.extend_from_slice(&variant[..split]);
    let mut second = variant[split..].to_vec();
    second.extend_from_slice(b":after");
    write_chunk(tls, &first).await?;
    write_chunk(tls, &second).await?;
    write_fragmented(tls, b"0\r\n\r\n").await?;
    tls.shutdown().await
}

async fn write_sealing_response(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    mode: &str,
    secret: &[u8],
) -> std::io::Result<()> {
    match mode {
        "raw" => write_reflection(tls, secret).await,
        "base64" => write_reflection(tls, BASE64.encode(secret).as_bytes()).await,
        "base64url" => write_reflection(tls, BASE64URL_NOPAD.encode(secret).as_bytes()).await,
        "percent" => write_reflection(tls, &fixture_percent_encode(secret)).await,
        "clean" => {
            write_chunked_headers(tls).await?;
            write_chunk(tls, b"{\"ok\":").await?;
            write_chunk(tls, b"true}").await?;
            write_fragmented(tls, b"0\r\n\r\n").await?;
            tls.shutdown().await
        }
        "oversize" => {
            write_chunked_headers(tls).await?;
            write_chunk(tls, &vec![b'x'; 768]).await?;
            write_chunk(tls, &vec![b'y'; 768]).await?;
            write_fragmented(tls, b"0\r\n\r\n").await?;
            tls.shutdown().await
        }
        "midstream" => {
            write_chunked_headers(tls).await?;
            write_fragmented(tls, b"40\r\npartial-agent-body").await?;
            tls.shutdown().await
        }
        "slow" => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            write_chunked_headers(tls).await?;
            write_chunk(tls, b"{\"ok\":true}").await?;
            write_fragmented(tls, b"0\r\n\r\n").await?;
            tls.shutdown().await
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unknown sealing mode",
        )),
    }
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
            let Ok(request) = read_request(&mut tls).await else {
                return;
            };
            let count = hits.fetch_add(1, Ordering::SeqCst) + 1;
            if write_hits(&hits_path, count).is_err() {
                return;
            }
            if request.path == "/v1/sealing" {
                let Some(mode) = request.mode else {
                    return;
                };
                let _ = write_sealing_response(&mut tls, &mode, &request.secret).await;
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
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .init();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (state_dir, ready_path, hits_path) = if args.len() == 3 && args[0] == "serve" {
        if args[1] != "--state-dir" {
            return Err("expected --state-dir".into());
        }
        let state = PathBuf::from(&args[2]);
        (
            state.clone(),
            state.join("fixture.port"),
            state.join("fixture.hits"),
        )
    } else if args.len() == 3 {
        (
            PathBuf::from(&args[0]),
            PathBuf::from(&args[1]),
            PathBuf::from(&args[2]),
        )
    } else {
        return Err("expected STATE READY HITS or serve --state-dir STATE".into());
    };

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
    tracing::info!(event = "runtime.starting");
    match serve(config).await {
        Ok(()) => {
            tracing::info!(event = "runtime.stopped");
            Ok(())
        }
        Err(error) => {
            tracing::error!(event = "rekeyd.command_failed", code = error.code());
            Err(error.into())
        }
    }
}
