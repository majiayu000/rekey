use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use rekey_vault::crypto::MasterKey;
use rekey_vault::rules::InjectionRule;
use rekey_web::sse::{TrafficBroadcaster, TrafficEvent, emit_traffic};
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::inject::{format_header_value, is_hop_by_hop_header, path_matches};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn build_upstream_url(hostname: &str, uri: &http::Uri) -> String {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    format!("https://{hostname}{path_and_query}")
}

pub async fn mitm_intercept<S>(
    stream: S,
    hostname: &str,
    port: u16,
    ca: &CertificateAuthority,
    leaf_cache: &LeafCertCache,
    rules: &[(InjectionRule, String)],
    master_key: Arc<MasterKey>,
    db_path: &str,
    traffic_tx: TrafficBroadcaster,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let leaf = leaf_cache.get_or_create(hostname, ca)?;
    let cert_chain = vec![rustls_pki_types::CertificateDer::from(
        leaf.cert_der.clone(),
    )];
    let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key_der.clone())
        .map_err(|e| anyhow::anyhow!("invalid leaf key: {e}"))?;

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("TLS config failed")?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let tls_stream = acceptor
        .accept(stream)
        .await
        .context("TLS handshake failed")?;

    let (reader, writer) = tokio::io::split(tls_stream);
    let io = hyper_util::rt::TokioIo::new(tokio::io::join(reader, writer));

    let rules_for_decrypt = rules.to_vec();
    let db_path_for_decrypt = db_path.to_string();
    let master_key_for_decrypt = master_key.clone();
    let decrypted_rules = tokio::task::spawn_blocking(move || -> Result<Vec<_>> {
        let conn = rekey_vault::db::open_connection(&db_path_for_decrypt)?;
        let mut decrypted_rules: Vec<(InjectionRule, String, String)> = Vec::new();
        for (rule, secret_name) in &rules_for_decrypt {
            match rekey_vault::secrets::get_secret_value_by_id(
                &conn,
                master_key_for_decrypt.as_ref(),
                &rule.secret_id,
            ) {
                Ok(value) => decrypted_rules.push((rule.clone(), secret_name.clone(), value)),
                Err(e) => {
                    tracing::error!(
                        "failed to decrypt secret {} for rule {}: {e}",
                        rule.secret_id,
                        rule.id
                    );
                }
            }
        }
        Ok(decrypted_rules)
    })
    .await
    .context("decrypt task failed")??;

    let hostname_owned = hostname.to_string();
    let port_owned = port;
    let db_path_owned = db_path.to_string();
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let hostname = hostname_owned.clone();
        let rules = decrypted_rules.clone();
        let db_path = db_path_owned.clone();
        let traffic_tx = traffic_tx.clone();

        async move {
            handle_mitm_request(req, &hostname, port_owned, &rules, &db_path, traffic_tx).await
        }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await
        .context("HTTP/1.1 serve failed")?;

    Ok(())
}

async fn handle_mitm_request(
    req: hyper::Request<hyper::body::Incoming>,
    hostname: &str,
    _port: u16,
    rules: &[(InjectionRule, String, String)],
    db_path: &str,
    traffic_tx: TrafficBroadcaster,
) -> Result<hyper::Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let path_for_match = req.uri().path().to_string();
    let path_for_audit = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let method_str = req.method().to_string();
    let url = build_upstream_url(hostname, req.uri());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    let method = match *req.method() {
        hyper::Method::GET => reqwest::Method::GET,
        hyper::Method::POST => reqwest::Method::POST,
        hyper::Method::PUT => reqwest::Method::PUT,
        hyper::Method::DELETE => reqwest::Method::DELETE,
        hyper::Method::PATCH => reqwest::Method::PATCH,
        hyper::Method::HEAD => reqwest::Method::HEAD,
        hyper::Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let original_headers: Vec<(String, Vec<u8>)> = req
        .headers()
        .iter()
        .filter(|(n, _)| !is_hop_by_hop_header(n.as_str()))
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return Ok(error_response(502, &format!("body read error: {e}"))),
    };

    let mut forward = client.request(method, &url);
    for (name, value) in &original_headers {
        forward = forward.header(name, value.as_slice());
    }
    forward = forward.header("host", hostname);

    let mut injected_secrets: Vec<String> = Vec::new();
    for (rule, secret_name, secret_value) in rules {
        if !path_matches(&rule.path_pattern, &path_for_match) {
            continue;
        }
        if rule.method != "*" && rule.method != method_str {
            continue;
        }
        let formatted = format_header_value(&rule.value_format, secret_value);
        forward = forward.header(&rule.header_name, &formatted);
        injected_secrets.push(secret_name.clone());
    }
    forward = forward.body(body_bytes.to_vec());

    let resp = match forward.send().await {
        Ok(r) => r,
        Err(e) => return Ok(error_response(502, &format!("upstream error: {e}"))),
    };

    let status = resp.status().as_u16();
    let latency = start.elapsed().as_millis() as i64;

    if !injected_secrets.is_empty() {
        let db_path_for_audit = db_path.to_string();
        let host_for_audit = hostname.to_string();
        let path_for_audit_db = path_for_audit.clone();
        let injected_for_audit = injected_secrets.clone();
        match tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = rekey_vault::db::open_connection(&db_path_for_audit)?;
            for secret_name in injected_for_audit {
                rekey_vault::audit::log_access(
                    &conn,
                    &secret_name,
                    &host_for_audit,
                    &path_for_audit_db,
                    Some(status as i32),
                    Some(latency),
                    "proxy",
                )?;
            }
            Ok(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("audit log failed: {e}"),
            Err(e) => tracing::error!("audit task failed: {e}"),
        }

        for secret_name in &injected_secrets {
            emit_traffic(
                &traffic_tx,
                TrafficEvent {
                    timestamp: now_unix(),
                    secret_name: secret_name.clone(),
                    target_host: hostname.to_string(),
                    target_path: path_for_audit.clone(),
                    status_code: Some(status as i32),
                    latency_ms: Some(latency),
                    source: "proxy".to_string(),
                },
            );
        }
    }

    let resp_status = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    let resp_bytes = resp.bytes().await.unwrap_or_default();

    Ok(hyper::Response::builder()
        .status(resp_status)
        .body(Full::new(resp_bytes))
        .unwrap_or_else(|_| {
            hyper::Response::new(Full::new(Bytes::from("internal error building response")))
        }))
}

fn error_response(status: u16, msg: &str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap_or_else(|_| hyper::Response::new(Full::new(Bytes::from("internal error"))))
}

#[cfg(test)]
mod tests {
    use super::build_upstream_url;

    #[test]
    fn upstream_url_keeps_query_string() {
        let uri: http::Uri = "/v1/messages?stream=true&limit=10".parse().unwrap();
        assert_eq!(
            build_upstream_url("api.anthropic.com", &uri),
            "https://api.anthropic.com/v1/messages?stream=true&limit=10"
        );
    }
}
