use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use rekey_vault::crypto::MasterKey;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceExt;

pub struct ProxyServer {
    ca: Arc<CertificateAuthority>,
    leaf_cache: Arc<LeafCertCache>,
    master_key: Arc<MasterKey>,
    db_path: String,
    addr: SocketAddr,
}

impl ProxyServer {
    pub fn new(
        ca: CertificateAuthority,
        master_key: MasterKey,
        db_path: String,
        port: u16,
    ) -> Self {
        Self {
            ca: Arc::new(ca),
            leaf_cache: Arc::new(LeafCertCache::new()),
            master_key: Arc::new(master_key),
            db_path,
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!("rekey proxy listening on {}", self.addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let ca = self.ca.clone();
            let leaf_cache = self.leaf_cache.clone();
            let master_key = self.master_key.clone();
            let db_path = self.db_path.clone();

            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);

                let service = service_fn(move |req: Request<Incoming>| {
                    let ca = ca.clone();
                    let leaf_cache = leaf_cache.clone();
                    let master_key = master_key.clone();
                    let db_path = db_path.clone();

                    async move {
                        if req.method() == Method::CONNECT {
                            handle_connect(req, ca, leaf_cache, master_key, db_path).await
                        } else {
                            handle_http(req, master_key, db_path).await
                        }
                    }
                });

                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::error!("connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    leaf_cache: Arc<LeafCertCache>,
    master_key: Arc<MasterKey>,
    db_path: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_default();
    let (hostname, port) = parse_host_port(&host_port);

    tracing::debug!("CONNECT {hostname}:{port}");

    // Check if we have injection rules for this host
    let has_rules = match rusqlite::Connection::open(&db_path) {
        Ok(conn) => rekey_vault::rules::find_rules_for_host(&conn, &hostname)
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        Err(_) => false,
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if has_rules {
                    handle_mitm_tunnel(
                        upgraded,
                        &hostname,
                        port,
                        &ca,
                        &leaf_cache,
                        &master_key,
                        &db_path,
                    )
                    .await;
                } else {
                    handle_passthrough_tunnel(upgraded, &hostname, port).await;
                }
            }
            Err(e) => tracing::error!("upgrade failed: {e}"),
        }
    });

    // Return 200 to signal tunnel established
    Ok(Response::new(Full::new(Bytes::new())))
}

async fn handle_mitm_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    hostname: &str,
    port: u16,
    ca: &CertificateAuthority,
    leaf_cache: &LeafCertCache,
    master_key: &MasterKey,
    db_path: &str,
) {
    let io = hyper_util::rt::TokioIo::new(upgraded);
    let (reader, writer) = tokio::io::split(io);
    let stream = tokio::io::join(reader, writer);

    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB open failed: {e}");
            return;
        }
    };
    let rules = match rekey_vault::rules::find_rules_for_host(&conn, hostname) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("rules lookup failed: {e}");
            return;
        }
    };
    drop(conn);

    if let Err(e) = crate::mitm::mitm_intercept(
        stream, hostname, port, ca, leaf_cache, &rules, master_key, db_path,
    )
    .await
    {
        tracing::error!("MITM error for {hostname}: {e}");
    }
}

async fn handle_passthrough_tunnel(upgraded: hyper::upgrade::Upgraded, hostname: &str, port: u16) {
    let mut upstream = match tokio::net::TcpStream::connect(format!("{hostname}:{port}")).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("tunnel connect failed for {hostname}:{port}: {e}");
            return;
        }
    };
    let mut client_io = hyper_util::rt::TokioIo::new(upgraded);
    if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream).await {
        tracing::debug!("tunnel closed for {hostname}:{port}: {e}");
    }
}

async fn handle_http(
    req: Request<Incoming>,
    master_key: Arc<MasterKey>,
    db_path: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    // API gateway: /proxy/{provider}/{path}
    if path.starts_with("/proxy/") {
        return crate::gateway::handle_gateway_request(req, &master_key, &db_path).await;
    }

    // Dashboard / API placeholder
    if path.starts_with("/dashboard") || path.starts_with("/api/") {
        return handle_web_request(req, db_path).await;
    }

    Ok(Response::builder()
        .status(404)
        .body(Full::new(Bytes::from("not found")))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("not found")))))
}

async fn handle_web_request(
    req: Request<Incoming>,
    db_path: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            return Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("body read error: {error}"))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("body error")))));
        }
    };

    let request = http::Request::from_parts(parts, axum::body::Body::from(body_bytes));
    let state = Arc::new(rekey_web::routes::WebState { db_path });
    let router = rekey_web::routes::api_router(state);
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(Response::builder()
                .status(500)
                .body(Full::new(Bytes::from(format!(
                    "dashboard response error: {error}"
                ))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal error")))));
        }
    };

    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers {
        if let Some(name) = name {
            builder = builder.header(name, value);
        }
    }

    Ok(builder
        .body(Full::new(body_bytes))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal error")))))
}

fn parse_host_port(authority: &str) -> (String, u16) {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn run_accepts_local_connections() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let ca = CertificateAuthority::generate(tmp.path())?;
        let db_path = tmp.path().join("vault");
        let conn = rusqlite::Connection::open(&db_path)?;
        rekey_vault::db::init_db(&conn)?;
        drop(conn);

        let master_key =
            rekey_vault::crypto::derive_master_key("test-password", b"0123456789abcdef")?;
        let addr = SocketAddr::from(([127, 0, 0, 1], unused_local_port()?));
        let server = ProxyServer::new(
            ca,
            master_key,
            db_path.to_string_lossy().to_string(),
            addr.port(),
        );

        let server_task = tokio::spawn(async move { server.run().await });
        let stream =
            tokio::time::timeout(Duration::from_secs(2), connect_when_ready(addr)).await??;
        drop(stream);

        server_task.abort();
        match server_task.await {
            Err(error) if error.is_cancelled() => {}
            result => panic!("proxy server task ended unexpectedly: {result:?}"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn run_serves_dashboard_and_api_routes() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let ca = CertificateAuthority::generate(tmp.path())?;
        let db_path = tmp.path().join("vault");
        let conn = rusqlite::Connection::open(&db_path)?;
        rekey_vault::db::init_db(&conn)?;
        drop(conn);

        let master_key =
            rekey_vault::crypto::derive_master_key("test-password", b"0123456789abcdef")?;
        let addr = SocketAddr::from(([127, 0, 0, 1], unused_local_port()?));
        let server = ProxyServer::new(
            ca,
            master_key,
            db_path.to_string_lossy().to_string(),
            addr.port(),
        );

        let server_task = tokio::spawn(async move { server.run().await });
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        let dashboard = tokio::time::timeout(
            Duration::from_secs(2),
            get_when_ready(&client, &format!("{base_url}/dashboard/index.html")),
        )
        .await??;
        assert_eq!(dashboard.status(), reqwest::StatusCode::OK);
        assert!(
            dashboard
                .text()
                .await?
                .contains("<title>rekey dashboard</title>")
        );

        let secrets = client.get(format!("{base_url}/api/secrets")).send().await?;
        assert_eq!(secrets.status(), reqwest::StatusCode::OK);
        assert_eq!(secrets.text().await?, "[]");

        server_task.abort();
        match server_task.await {
            Err(error) if error.is_cancelled() => {}
            result => panic!("proxy server task ended unexpectedly: {result:?}"),
        }

        Ok(())
    }

    async fn connect_when_ready(addr: SocketAddr) -> std::io::Result<TcpStream> {
        let mut last_error = None;
        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| std::io::Error::other("proxy listener was not ready")))
    }

    async fn get_when_ready(
        client: &reqwest::Client,
        url: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut last_error = None;
        for _ in 0..50 {
            match client.get(url).send().await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }

        match last_error {
            Some(error) => Err(error),
            None => client.get(url).send().await,
        }
    }

    fn unused_local_port() -> std::io::Result<u16> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        Ok(listener.local_addr()?.port())
    }
}
