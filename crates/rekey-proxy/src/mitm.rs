use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use rekey_vault::crypto::MasterKey;
use rekey_vault::rules::InjectionRule;
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::inject::{format_header_value, path_matches};

pub async fn mitm_intercept<S>(
    stream: S,
    hostname: &str,
    port: u16,
    ca: &CertificateAuthority,
    leaf_cache: &LeafCertCache,
    rules: &[(InjectionRule, String)],
    master_key: &MasterKey,
    db_path: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let start = Instant::now();

    // Generate leaf cert for this hostname
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

    // TLS handshake with client
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let tls_stream = acceptor
        .accept(stream)
        .await
        .context("TLS handshake failed")?;

    let (reader, writer) = tokio::io::split(tls_stream);
    let io = hyper_util::rt::TokioIo::new(tokio::io::join(reader, writer));

    // Pre-decrypt secret values so the service closure doesn't need MasterKey (not Clone)
    let conn = rusqlite::Connection::open(db_path).context("DB open failed for MITM")?;
    let mut decrypted_rules: Vec<(InjectionRule, String, String)> = Vec::new();
    for (rule, secret_name) in rules {
        match rekey_vault::secrets::get_secret_value_by_id(&conn, master_key, &rule.secret_id) {
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
    drop(conn);

    let hostname_owned = hostname.to_string();
    let port_owned = port;
    let db_path_owned = db_path.to_string();

    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let hostname = hostname_owned.clone();
        let rules = decrypted_rules.clone();
        let db_path = db_path_owned.clone();

        async move { handle_mitm_request(req, &hostname, port_owned, &rules, &db_path, start).await }
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
    start: Instant,
) -> Result<hyper::Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
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

    // Extract headers before consuming the body
    let original_headers: Vec<(String, Vec<u8>)> = req
        .headers()
        .iter()
        .filter(|(n, _)| {
            !matches!(
                n.as_str(),
                "host" | "connection" | "proxy-authorization" | "transfer-encoding"
            )
        })
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return Ok(error_response(502, &format!("body read error: {e}"))),
    };

    let mut forward = client.request(method, &url);

    // Copy original headers, skip hop-by-hop
    for (name, value) in &original_headers {
        forward = forward.header(name, value.as_slice());
    }
    forward = forward.header("host", hostname);

    // Inject headers per matching rules
    let mut injected_secrets: Vec<String> = Vec::new();
    for (rule, secret_name, secret_value) in rules {
        if !path_matches(&rule.path_pattern, &path) {
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

    // Audit log
    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        for secret_name in &injected_secrets {
            if let Err(e) = rekey_vault::audit::log_access(
                &conn,
                secret_name,
                hostname,
                &path,
                Some(status as i32),
                Some(latency),
                "proxy",
            ) {
                tracing::error!("audit log failed for {secret_name}: {e}");
            }
        }
    } else {
        tracing::error!("failed to open DB for audit logging: {db_path}");
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

fn build_upstream_url(hostname: &str, uri: &http::Uri) -> String {
    let path_and_query = uri.path_and_query().map_or("/", |value| value.as_str());
    format!("https://{hostname}{path_and_query}")
}

#[cfg(test)]
mod tests {
    use super::build_upstream_url;

    #[test]
    fn upstream_url_keeps_v1_models_query_string() {
        let uri = match "/v1/models?limit=10".parse::<http::Uri>() {
            Ok(uri) => uri,
            Err(error) => panic!("test URI should parse: {error}"),
        };

        assert_eq!(
            build_upstream_url("api.openai.com", &uri),
            "https://api.openai.com/v1/models?limit=10"
        );
    }
}
