//! Layer A fixture: real BrokerRuntime and UDS. Vault OSS is reached through
//! the same post-screen address injection as P-07; the Action host stays a
//! local CA/TLS mock. Production rekeyd is never pointed at 127.0.0.1.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamTransport,
    send_screened,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const VAULT_HOST: &str = "vault.test.local";
const ACTION_HOST: &str = "api.test.local";

struct SplitTlsTransport {
    vault: SocketAddr,
    vault_ca: Arc<Vec<u8>>,
    action: SocketAddr,
    action_ca: Arc<Vec<u8>>,
}

impl UpstreamTransport for SplitTlsTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        let (addr, ca) = if request.host == VAULT_HOST {
            (self.vault, Arc::clone(&self.vault_ca))
        } else if request.host == ACTION_HOST {
            (self.action, Arc::clone(&self.action_ca))
        } else {
            return Box::pin(async { Err(UpstreamError::Blocked("private-address")) });
        };
        let endpoint = ScreenedEndpoint {
            host: request.host.clone(),
            addr,
        };
        Box::pin(async move { send_screened(request, endpoint, Some(&ca)).await })
    }
}

fn action_tls() -> Result<(Vec<u8>, rustls::ServerConfig), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let leaf_params = rcgen::CertificateParams::new(vec![ACTION_HOST.to_owned()])?;
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

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_request(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> std::io::Result<HttpRequest> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    let header_end = loop {
        if bytes.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
        let read = tls.read(&mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request truncated",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid headers"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line")
    })?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "content length"))?
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let read = tls.read(&mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "body truncated",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

async fn respond(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    status: &str,
    body: &[u8],
) -> std::io::Result<()> {
    tls.write_all(
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await?;
    tls.write_all(body).await?;
    tls.shutdown().await
}

fn append_trace(path: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
}

fn bearer_from(req: &HttpRequest) -> Option<&str> {
    req.headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn bearer_ok(req: &HttpRequest, expected: &str) -> bool {
    let Some(token) = bearer_from(req) else {
        return false;
    };
    if expected == "*" {
        !token.is_empty() && token.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
    } else {
        token == expected
    }
}

fn write_seen(path: &Path, req: &HttpRequest) {
    let token = bearer_from(req).unwrap_or("");
    if std::fs::write(path, token).is_err() {
        eprintln!("p7oss cannot record seen bearer");
    }
}

async fn serve_action(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    expected_path: PathBuf,
    seen_path: PathBuf,
    trace_path: PathBuf,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let expected_path = expected_path.clone();
        let seen_path = seen_path.clone();
        let trace_path = trace_path.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let Ok(req) = read_request(&mut tls).await else {
                return;
            };
            write_seen(&seen_path, &req);
            let expected = std::fs::read_to_string(&expected_path)
                .unwrap_or_default()
                .trim()
                .to_owned();
            let ok = req.method == "POST"
                && req.path == "/v1/things"
                && req.body == br#"{"operation":"bounded"}"#
                && bearer_ok(&req, &expected);
            let result = if ok {
                if append_trace(&trace_path, "p7oss.action.ok").is_err() {
                    return;
                }
                respond(&mut tls, "200 OK", br#"{"result":"p7oss-ok"}"#).await
            } else {
                if append_trace(&trace_path, "p7oss.action.deny").is_err() {
                    return;
                }
                respond(&mut tls, "400 Bad Request", br#"{"error":"action"}"#).await
            };
            if result.is_err() {
                eprintln!("p7oss action fixture response failed");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let state_dir = PathBuf::from(args.next().ok_or("missing state dir")?);
    let ready_path = PathBuf::from(args.next().ok_or("missing ready path")?);
    let trace_path = PathBuf::from(args.next().ok_or("missing trace path")?);
    let vault_addr: SocketAddr = args
        .next()
        .ok_or("missing vault address")?
        .to_string_lossy()
        .parse()?;
    let vault_ca = Arc::new(std::fs::read(args.next().ok_or("missing vault CA DER")?)?);
    let expected_path = PathBuf::from(args.next().ok_or("missing expected-bearer path")?);
    let seen_path = PathBuf::from(args.next().ok_or("missing seen-bearer path")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }

    let (action_ca, server) = action_tls()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let action_addr = listener.local_addr()?;
    tokio::spawn(serve_action(
        listener,
        TlsAcceptor::from(Arc::new(server)),
        expected_path,
        seen_path,
        trace_path,
    ));
    std::fs::write(&ready_path, format!("{}\n", action_addr.port()))?;

    let mut config = BrokerConfig::new(state_dir);
    config.idle_lock = Duration::from_secs(15 * 60);
    config.transport = Some(Arc::new(SplitTlsTransport {
        vault: vault_addr,
        vault_ca,
        action: action_addr,
        action_ca: Arc::new(action_ca),
    }));
    config.unlock_backoff_base = Duration::from_millis(250);
    config.drain_timeout = Duration::from_millis(100);
    serve(config).await?;
    Ok(())
}
