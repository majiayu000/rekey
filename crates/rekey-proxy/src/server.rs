use anyhow::Result;
use axum::{Router, body::Body as AxumBody};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use rekey_vault::crypto::MasterKey;
use rekey_web::routes::WebState;
use rekey_web::sse::{TrafficBroadcaster, new_broadcaster};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::util::ServiceExt;

pub struct ProxyServer {
    ca: Arc<CertificateAuthority>,
    leaf_cache: Arc<LeafCertCache>,
    master_key: Arc<MasterKey>,
    db_path: String,
    addr: SocketAddr,
    web_router: Arc<Router>,
    traffic_tx: TrafficBroadcaster,
}

impl ProxyServer {
    pub fn new(
        ca: CertificateAuthority,
        master_key: MasterKey,
        db_path: String,
        port: u16,
    ) -> Self {
        let traffic_tx = new_broadcaster(1024);
        let web_state = Arc::new(WebState::new(db_path.clone(), traffic_tx.clone()));
        let web_router = rekey_web::routes::api_router(web_state);

        Self {
            ca: Arc::new(ca),
            leaf_cache: Arc::new(LeafCertCache::new()),
            master_key: Arc::new(master_key),
            db_path,
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            web_router: Arc::new(web_router),
            traffic_tx,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!("rekey proxy listening on {}", self.addr);

        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("received shutdown signal");
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let ca = self.ca.clone();
                    let leaf_cache = self.leaf_cache.clone();
                    let master_key = self.master_key.clone();
                    let db_path = self.db_path.clone();
                    let web_router = self.web_router.clone();
                    let traffic_tx = self.traffic_tx.clone();

                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);

                        let service = service_fn(move |req: Request<Incoming>| {
                            let ca = ca.clone();
                            let leaf_cache = leaf_cache.clone();
                            let master_key = master_key.clone();
                            let db_path = db_path.clone();
                            let web_router = web_router.clone();
                            let traffic_tx = traffic_tx.clone();

                            async move {
                                if req.method() == Method::CONNECT {
                                    handle_connect(req, ca, leaf_cache, master_key, db_path, traffic_tx).await
                                } else {
                                    handle_http(req, master_key, db_path, web_router, traffic_tx).await
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
        Ok(())
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    leaf_cache: Arc<LeafCertCache>,
    master_key: Arc<MasterKey>,
    db_path: String,
    traffic_tx: TrafficBroadcaster,
) -> Result<Response<AxumBody>, hyper::Error> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_default();
    let (hostname, port) = parse_host_port(&host_port);

    tracing::debug!("CONNECT {hostname}:{port}");

    let lookup_path = db_path.clone();
    let lookup_host = hostname.clone();
    let has_rules = tokio::task::spawn_blocking(move || {
        let conn = rekey_vault::db::open_connection(&lookup_path)?;
        let rules = rekey_vault::rules::find_rules_for_host(&conn, &lookup_host)?;
        Ok::<bool, anyhow::Error>(!rules.is_empty())
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(false);

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
                        master_key,
                        &db_path,
                        traffic_tx,
                    )
                    .await;
                } else {
                    handle_passthrough_tunnel(upgraded, &hostname, port).await;
                }
            }
            Err(e) => tracing::error!("upgrade failed: {e}"),
        }
    });

    Ok(Response::new(AxumBody::empty()))
}

async fn handle_mitm_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    hostname: &str,
    port: u16,
    ca: &CertificateAuthority,
    leaf_cache: &LeafCertCache,
    master_key: Arc<MasterKey>,
    db_path: &str,
    traffic_tx: TrafficBroadcaster,
) {
    let io = hyper_util::rt::TokioIo::new(upgraded);
    let (reader, writer) = tokio::io::split(io);
    let stream = tokio::io::join(reader, writer);

    let lookup_path = db_path.to_string();
    let lookup_host = hostname.to_string();
    let rules = match tokio::task::spawn_blocking(move || -> Result<_> {
        let conn = rekey_vault::db::open_connection(&lookup_path)?;
        let rules = rekey_vault::rules::find_rules_for_host(&conn, &lookup_host)?;
        Ok(rules)
    })
    .await
    {
        Ok(Ok(rules)) => rules,
        Ok(Err(e)) => {
            tracing::error!("rules lookup failed: {e}");
            return;
        }
        Err(e) => {
            tracing::error!("rules lookup task failed: {e}");
            return;
        }
    };

    if let Err(e) = crate::mitm::mitm_intercept(
        stream, hostname, port, ca, leaf_cache, &rules, master_key, db_path, traffic_tx,
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
    web_router: Arc<Router>,
    traffic_tx: TrafficBroadcaster,
) -> Result<Response<AxumBody>, hyper::Error> {
    let path = req.uri().path().to_string();

    if path.starts_with("/proxy/") {
        let response =
            crate::gateway::handle_gateway_request(req, master_key, &db_path, traffic_tx).await?;
        let (parts, body) = response.into_parts();
        let bytes = match body.collect().await {
            Ok(body) => body.to_bytes(),
            Err(e) => {
                return Ok(Response::builder()
                    .status(502)
                    .body(AxumBody::from(Bytes::from(format!(
                        "response body error: {e}"
                    ))))
                    .unwrap_or_else(|_| {
                        Response::new(AxumBody::from(Bytes::from("response body error")))
                    }));
            }
        };
        return Ok(Response::from_parts(parts, AxumBody::from(bytes)));
    }

    if path.starts_with("/dashboard") || path.starts_with("/api/") {
        return Ok(serve_web_request(req, web_router).await);
    }

    Ok(Response::builder()
        .status(404)
        .body(AxumBody::from(Bytes::from("not found")))
        .unwrap_or_else(|_| Response::new(AxumBody::from(Bytes::from("not found")))))
}

async fn serve_web_request(req: Request<Incoming>, web_router: Arc<Router>) -> Response<AxumBody> {
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => {
            return Response::builder()
                .status(502)
                .body(AxumBody::from(Bytes::from(format!("body read error: {e}"))))
                .unwrap_or_else(|_| Response::new(AxumBody::from(Bytes::from("body read error"))));
        }
    };
    let axum_req = Request::from_parts(parts, AxumBody::from(body_bytes));

    let axum_resp = match web_router.as_ref().clone().oneshot(axum_req).await {
        Ok(resp) => resp,
        Err(e) => {
            return Response::builder()
                .status(500)
                .body(AxumBody::from(Bytes::from(format!("router error: {e}"))))
                .unwrap_or_else(|_| Response::new(AxumBody::from(Bytes::from("router error"))));
        }
    };
    axum_resp
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn parse_host_port(authority: &str) -> (String, u16) {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443)
    }
}
