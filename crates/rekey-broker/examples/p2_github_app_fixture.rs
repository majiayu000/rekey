//! Release-build P2.1 fixture: real BrokerRuntime and UDS, with a local
//! CA/TLS GitHub mock injected after public-address screening.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use data_encoding::BASE64URL_NOPAD;
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamFuture, UpstreamRequest, UpstreamTransport, send_screened,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const HOST: &str = "api.github.com";
const CLIENT_ID: &str = "Iv1.8a61f9b3a7aba766";
const INSTALLATION_ID: u64 = 515_151;
const REPOSITORY_ID: u64 = 616_161;
const P6_INSTALLATION_ID: u64 = 818_180;
const P6_REPOSITORY_ID: u64 = 818_181;
const P6_SECOND_REPOSITORY_ID: u64 = 818_182;
const STATELESS_TOKEN_CANARY: &str = "P2-STATELESS-INSTALLATION-TOKEN-CANARY";

fn installation_token(mode: &str) -> String {
    if mode == "stateless-token" {
        return format!(
            "ghs_424242_{}.{}{}.{}",
            "a".repeat(160),
            STATELESS_TOKEN_CANARY,
            "b".repeat(160),
            "c".repeat(160)
        );
    }
    format!("P2-INSTALLATION-TOKEN-CANARY-{mode}")
}

fn expected_exchange(mode: &str) -> (u64, Vec<u64>, Value) {
    match mode {
        "p6-list" => (
            P6_INSTALLATION_ID,
            vec![P6_REPOSITORY_ID, P6_SECOND_REPOSITORY_ID],
            json!({"metadata":"read"}),
        ),
        "p6-issue" => (
            P6_INSTALLATION_ID,
            vec![P6_SECOND_REPOSITORY_ID],
            json!({"metadata":"read","issues":"write"}),
        ),
        "p6-rotated-list" => (
            P6_INSTALLATION_ID,
            vec![P6_REPOSITORY_ID],
            json!({"metadata":"read"}),
        ),
        "p6-webhook-list" => (
            P6_INSTALLATION_ID,
            vec![P6_REPOSITORY_ID, P6_SECOND_REPOSITORY_ID],
            json!({"metadata":"read"}),
        ),
        _ => (
            INSTALLATION_ID,
            vec![REPOSITORY_ID],
            json!({"metadata":"read"}),
        ),
    }
}

fn repositories_for(mode: &str) -> Vec<Value> {
    match mode {
        "p6-list" | "p6-webhook-list" => vec![
            json!({"id":P6_SECOND_REPOSITORY_ID,"full_name":"p6-owner/beta"}),
            json!({"id":P6_REPOSITORY_ID,"full_name":"p6-owner/alpha"}),
        ],
        "p6-rotated-list" => {
            vec![json!({"id":P6_REPOSITORY_ID,"full_name":"p6-owner/alpha"})]
        }
        _ => vec![json!({"id":REPOSITORY_ID,"full_name":"fixture-owner/fixture"})],
    }
}

fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

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
    let ca_key = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let leaf_params = rcgen::CertificateParams::new(vec![HOST.to_owned()])?;
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

fn bearer(req: &HttpRequest) -> Result<&str, &'static str> {
    req.headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or("missing bearer")
}

fn verify_jwt(jwt: &str, public_key_der: &[u8]) -> Result<(), &'static str> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("jwt parts");
    }
    let header: Value = serde_json::from_slice(
        &BASE64URL_NOPAD
            .decode(parts[0].as_bytes())
            .map_err(|_| "jwt header")?,
    )
    .map_err(|_| "jwt header")?;
    if header != json!({"alg":"RS256","typ":"JWT"}) {
        return Err("jwt algorithm");
    }
    let claims: Value = serde_json::from_slice(
        &BASE64URL_NOPAD
            .decode(parts[1].as_bytes())
            .map_err(|_| "jwt claims")?,
    )
    .map_err(|_| "jwt claims")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_secs();
    let iat = claims.get("iat").and_then(Value::as_u64).ok_or("iat")?;
    let exp = claims.get("exp").and_then(Value::as_u64).ok_or("exp")?;
    if claims.get("iss").and_then(Value::as_str) != Some(CLIENT_ID)
        || iat > now
        || now.saturating_sub(iat) > 120
        || exp <= now
        || exp.saturating_sub(iat) > 600
    {
        return Err("jwt claims invalid");
    }
    let signature = BASE64URL_NOPAD
        .decode(parts[2].as_bytes())
        .map_err(|_| "jwt signature")?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| "jwt verify")
}

fn append_trace(path: &Path, event: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{event}")?;
    file.sync_all()
}

fn append_jwt_canary(path: &Path, jwt: &str) -> std::io::Result<()> {
    let signature = jwt
        .rsplit('.')
        .next()
        .filter(|value| value.len() >= 32)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "JWT signature too short")
        })?;
    append_trace(path, &format!("jwt.canary={}", &signature[..32]))
}

async fn serve_mock(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    public_key_der: Arc<Vec<u8>>,
    mode_path: PathBuf,
    trace_path: PathBuf,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let public_key_der = Arc::clone(&public_key_der);
        let mode_path = mode_path.clone();
        let trace_path = trace_path.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let Ok(req) = read_request(&mut tls).await else {
                return;
            };
            let mode = std::fs::read_to_string(&mode_path)
                .unwrap_or_default()
                .trim()
                .to_owned();
            let api_headers_ok = req.headers.get("x-github-api-version").map(String::as_str)
                == Some("2022-11-28")
                && req.headers.get("accept").map(String::as_str)
                    == Some("application/vnd.github+json")
                && req.headers.get("user-agent").map(String::as_str)
                    == Some(concat!("rekey/", env!("CARGO_PKG_VERSION")));
            let (expected_installation, expected_repositories, expected_permissions) =
                expected_exchange(&mode);
            let result = if req.method == "POST"
                && req.path == format!("/app/installations/{expected_installation}/access_tokens")
            {
                let jwt_value = bearer(&req);
                let jwt = jwt_value.and_then(|jwt| verify_jwt(jwt, &public_key_der));
                if jwt.is_ok() {
                    let Ok(jwt_value) = jwt_value else {
                        return;
                    };
                    if append_jwt_canary(&trace_path, jwt_value).is_err() {
                        return;
                    }
                }
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                let scope_ok = body
                    == json!({
                        "repository_ids":expected_repositories,
                        "permissions":expected_permissions
                    });
                if jwt.is_err() || !scope_ok || !api_headers_ok {
                    respond(&mut tls, "400 Bad Request", br#"{"error":"invalid"}"#).await
                } else if mode == "exchange-error" {
                    if append_trace(&trace_path, "exchange.error").is_err() {
                        return;
                    }
                    respond(
                        &mut tls,
                        "500 Internal Server Error",
                        br#"{"error":"exchange"}"#,
                    )
                    .await
                } else {
                    if append_trace(&trace_path, "exchange.ok").is_err() {
                        return;
                    }
                    let permissions = if mode == "bad-scope" {
                        json!({"metadata":"read","contents":"write"})
                    } else if mode == "malformed-scope" {
                        json!("malformed")
                    } else {
                        expected_permissions
                    };
                    let token = installation_token(&mode);
                    let mut body = serde_json::to_vec(&json!({
                        "token": token,
                        "expires_at": "2099-01-01T00:00:00Z",
                        "permissions": permissions,
                        "repositories": expected_repositories
                            .iter()
                            .map(|id| json!({"id":id}))
                            .collect::<Vec<_>>(),
                        "repository_selection": "selected"
                    }))
                    .unwrap_or_default();
                    if mode == "trailing-token" {
                        body.extend_from_slice(b" trailing-garbage");
                    } else if mode == "duplicate-token" {
                        body = format!(
                            "{{\"token\":\"{token}\",\"token\":\"{token}\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"permissions\":{{\"metadata\":\"read\"}},\"repositories\":[{{\"id\":{REPOSITORY_ID}}}],\"repository_selection\":\"selected\"}}"
                        )
                        .into_bytes();
                    }
                    let status = if mode == "exchange-status-token" {
                        "500 Internal Server Error"
                    } else {
                        "201 Created"
                    };
                    respond(&mut tls, status, &body).await
                }
            } else if req.method == "GET" && req.path == "/installation/repositories" {
                let token_ok = bearer(&req)
                    .map(|token| token == installation_token(&mode))
                    .unwrap_or(false);
                if !token_ok || !api_headers_ok {
                    respond(&mut tls, "401 Unauthorized", br#"{"error":"token"}"#).await
                } else if mode == "resource-error" {
                    if append_trace(&trace_path, "resource.error").is_err() {
                        return;
                    }
                    respond(
                        &mut tls,
                        "500 Internal Server Error",
                        br#"{"error":"resource"}"#,
                    )
                    .await
                } else {
                    if append_trace(&trace_path, "resource.ok").is_err() {
                        return;
                    }
                    if mode == "slow-resource" {
                        tokio::time::sleep(Duration::from_millis(600)).await;
                    } else if mode == "deadline-resource" {
                        tokio::time::sleep(Duration::from_millis(4800)).await;
                    }
                    let mut repositories = repositories_for(&mode);
                    if mode == "wrong-repository" {
                        repositories[0]["id"] = json!(REPOSITORY_ID + 1);
                    }
                    let name = if mode == "reflect-token" {
                        format!("P2-INSTALLATION-TOKEN-CANARY-{mode}")
                    } else {
                        "fixture".to_owned()
                    };
                    let mut body = json!({
                        "total_count": repositories.len(),
                        "repositories": repositories
                    });
                    body["repositories"][0]["name"] = json!(name);
                    if mode == "provider-extra" {
                        body["debug_hex"] = json!(hex(&installation_token(&mode)));
                    }
                    let body = serde_json::to_vec(&body).unwrap_or_default();
                    respond(&mut tls, "200 OK", &body).await
                }
            } else if req.method == "POST" && req.path == "/repos/p6-owner/beta/issues" {
                let token_ok = bearer(&req)
                    .map(|token| token == installation_token(&mode))
                    .unwrap_or(false);
                let issue: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                if mode != "p6-issue"
                    || !token_ok
                    || !api_headers_ok
                    || req.headers.get("content-type").map(String::as_str)
                        != Some("application/json")
                    || issue != json!({"title":"P6 issue","body":"P6 issue body canary"})
                {
                    respond(&mut tls, "400 Bad Request", br#"{"error":"issue"}"#).await
                } else {
                    if append_trace(&trace_path, "issue.ok").is_err() {
                        return;
                    }
                    respond(
                        &mut tls,
                        "201 Created",
                        br#"{"id":919191,"number":7,"repository_url":"https://api.github.com/repos/p6-owner/beta","html_url":"https://github.com/p6-owner/beta/issues/7","provider_extra":"removed"}"#,
                    )
                    .await
                }
            } else if req.method == "DELETE" && req.path == "/installation/token" {
                let token_ok = bearer(&req)
                    .map(|token| token == installation_token(&mode))
                    .unwrap_or(false);
                if !token_ok || !api_headers_ok {
                    respond(&mut tls, "401 Unauthorized", br#"{"error":"token"}"#).await
                } else if mode == "revoke-error" {
                    if append_trace(&trace_path, "revoke.error").is_err() {
                        return;
                    }
                    respond(
                        &mut tls,
                        "500 Internal Server Error",
                        br#"{"error":"revoke"}"#,
                    )
                    .await
                } else {
                    if append_trace(&trace_path, "revoke.ok").is_err() {
                        return;
                    }
                    respond(&mut tls, "204 No Content", b"").await
                }
            } else {
                respond(&mut tls, "404 Not Found", br#"{"error":"path"}"#).await
            };
            if result.is_err() {
                eprintln!("fixture response failed");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let state_dir = PathBuf::from(args.next().ok_or("missing state dir")?);
    let ready_path = PathBuf::from(args.next().ok_or("missing ready path")?);
    let mode_path = PathBuf::from(args.next().ok_or("missing mode path")?);
    let trace_path = PathBuf::from(args.next().ok_or("missing trace path")?);
    let public_key_path = PathBuf::from(args.next().ok_or("missing public key path")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let public_key_der = Arc::new(std::fs::read(public_key_path)?);
    let (ca_der, server) = tls_config()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(serve_mock(
        listener,
        TlsAcceptor::from(Arc::new(server)),
        public_key_der,
        mode_path,
        trace_path,
    ));
    std::fs::write(&ready_path, format!("{}\n", address.port()))?;

    let mut config = BrokerConfig::new(state_dir);
    config.idle_lock = Duration::from_secs(15 * 60);
    config.transport = Some(Arc::new(LocalTlsTransport {
        address,
        ca_der: Arc::new(ca_der),
    }));
    config.unlock_backoff_base = Duration::from_millis(250);
    config.drain_timeout = Duration::from_millis(100);
    serve(config).await?;
    Ok(())
}
