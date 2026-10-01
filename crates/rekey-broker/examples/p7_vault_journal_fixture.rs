//! Test-only process fixture. Provider survives Broker SIGKILL; TLS CA/address
//! injection stays in this example, outside production transport configuration.
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamTransport,
    select_public_endpoint, send_screened,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const TOKEN: &str = "JOURNAL-SOURCE-TOKEN-ONE-CANARY";
const VALUE: &str = "JOURNAL-DYNAMIC-VALUE-CANARY";
const ID: &str = "database/creds/journal-role/JOURNAL-LEASE-ID-CANARY";
#[derive(Deserialize, Serialize)]
struct Endpoint {
    addr: SocketAddr,
    ca: PathBuf,
}
#[derive(Default, Serialize)]
struct Ledger {
    acquired: u64,
    business: u64,
    revoked: u64,
    active: bool,
    exact_requests: bool,
    historical_token: bool,
}
fn tls() -> Result<(Vec<u8>, rustls::ServerConfig), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = params.self_signed(&ca_key)?;
    let leaf_key = rcgen::KeyPair::generate()?;
    let leaf =
        rcgen::CertificateParams::new(vec!["vault.test.local".into(), "api.test.local".into()])?
            .signed_by(&leaf_key, &ca, &ca_key)?;
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((ca.der().to_vec(), server))
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

async fn provider(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (ca, server) = tls()?;
    let ca_path = root.join("ca.der");
    std::fs::write(&ca_path, ca)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    std::fs::write(
        root.join("provider-ready.json"),
        serde_json::to_vec(&Endpoint {
            addr: listener.local_addr()?,
            ca: ca_path,
        })?,
    )?;
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let ledger = Arc::new(Mutex::new(Ledger {
        exact_requests: true,
        historical_token: true,
        ..Default::default()
    }));
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let ledger = Arc::clone(&ledger);
        let root = root.to_owned();
        tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let Ok(req) = read_request(&mut stream).await else {
                return;
            };
            let (status, body) = {
                let mut ledger = ledger.lock().unwrap();
                let mode = std::fs::read_to_string(root.join("provider-mode")).unwrap_or_default();
                let token_ok = req.headers.get("x-vault-token").is_some_and(|s| s == TOKEN);
                let result = match req.path.as_str() {
                    "/v1/database/creds/journal-role" if req.method == "GET" && token_ok => {
                        ledger.acquired += 1;
                        ledger.active = true;
                        if mode.trim() == "unknown" {
                            ("200 OK", br#"{"data":{}}"#.to_vec())
                        } else {
                            ("200 OK",serde_json::to_vec(&serde_json::json!({"lease_id":ID,"lease_duration":60,"renewable":true,"data":{"token":VALUE}})).unwrap())
                        }
                    }
                    "/v1/things"
                        if req.method == "POST"
                            && req.body == br#"{"operation":"bounded"}"#
                            && req
                                .headers
                                .get("authorization")
                                .is_some_and(|s| s == &format!("Bearer {VALUE}")) =>
                    {
                        ledger.business += 1;
                        ("200 OK", br#"{"result":"journal-ok"}"#.to_vec())
                    }
                    "/v1/sys/leases/revoke"
                        if req.method == "POST"
                            && token_ok
                            && req.body
                                == format!(r#"{{"lease_id":"{ID}","sync":true}}"#).as_bytes() =>
                    {
                        ledger.revoked += 1;
                        if mode.trim() == "reject" {
                            ("403 Forbidden", Vec::new())
                        } else {
                            ledger.active = false;
                            ("204 No Content", Vec::new())
                        }
                    }
                    _ => {
                        ledger.exact_requests = false;
                        ledger.historical_token &= token_ok;
                        ("400 Bad Request", Vec::new())
                    }
                };
                std::fs::write(
                    root.join("ledger.json"),
                    serde_json::to_vec(&*ledger).unwrap(),
                )
                .expect("persist provider evidence");
                result
            };
            let _ = respond(&mut stream, status, &body).await;
        });
    }
}
struct Transport {
    endpoint: Endpoint,
    ca: Vec<u8>,
    root: PathBuf,
    gate: String,
}
impl UpstreamTransport for Transport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            if !matches!(request.host.as_str(), "vault.test.local" | "api.test.local") {
                return Err(UpstreamError::Blocked("private-address"));
            }
            let public =
                select_public_endpoint(&request.host, &[SocketAddr::from(([1, 1, 1, 1], 443))])?;
            if select_public_endpoint(&request.host, &[self.endpoint.addr]).is_ok() {
                return Err(UpstreamError::Blocked("private-address"));
            }
            let revoke = request.path == "/v1/sys/leases/revoke";
            if (self.gate == "issued_before_business" && request.path == "/v1/things")
                || (self.gate == "business_before_revoke" && revoke)
            {
                self.stop_at_gate().await?;
            }
            let response = send_screened(
                request,
                ScreenedEndpoint {
                    host: public.host,
                    addr: self.endpoint.addr,
                },
                Some(&self.ca),
            )
            .await?;
            if self.gate == "revoke_response_before_complete" && revoke && response.status == 204 {
                self.stop_at_gate().await?;
            }
            Ok(response)
        })
    }
}
impl Transport {
    async fn stop_at_gate(&self) -> Result<(), UpstreamError> {
        std::fs::write(self.root.join("gate-ready"), self.gate.as_bytes())
            .map_err(|_| UpstreamError::Transport)?;
        std::future::pending::<()>().await;
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("fixture mode missing")?;
    let root = PathBuf::from(args.next().ok_or("fixture directory missing")?);
    if mode == "provider" {
        return provider(&root).await;
    }
    if mode != "broker" {
        return Err("unknown fixture mode".into());
    }
    let state = PathBuf::from(args.next().ok_or("state missing")?);
    let gate = args
        .next()
        .ok_or("gate missing")?
        .to_str()
        .ok_or("invalid gate")?
        .to_owned();
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let endpoint: Endpoint =
        serde_json::from_slice(&std::fs::read(root.join("provider-ready.json"))?)?;
    let ca = std::fs::read(&endpoint.ca)?;
    let mut config = BrokerConfig::new(state);
    config.idle_lock = Duration::from_secs(900);
    config.transport = Some(Arc::new(Transport {
        endpoint,
        ca,
        root,
        gate,
    }));
    config.drain_timeout = Duration::from_millis(100);
    serve(config).await?;
    Ok(())
}
