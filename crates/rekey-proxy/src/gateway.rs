use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use rekey_vault::crypto::MasterKey;
use std::time::Instant;

use crate::inject::format_header_value;

pub async fn handle_gateway_request(
    req: Request<Incoming>,
    master_key: &MasterKey,
    db_path: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let start = Instant::now();

    // Parse /proxy/{provider}/{api_path...}
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 4 {
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("usage: /proxy/{provider}/{path}")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("bad request")))));
    }

    let provider_name = parts[2];
    let api_path = format!("/{}", parts[3]);

    let provider = match rekey_vault::providers::get_provider(provider_name) {
        Some(p) => p,
        None => {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from(format!(
                    "unknown provider: {provider_name}"
                ))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("not found")))));
        }
    };

    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("gateway DB open failed: {e}");
            return Ok(Response::builder()
                .status(500)
                .body(Full::new(Bytes::from(format!("db error: {e}"))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("db error")))));
        }
    };

    let secret_value =
        match rekey_vault::secrets::get_secret_value(&conn, master_key, provider_name) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("secret lookup failed for {provider_name}: {e}");
                return Ok(Response::builder()
                    .status(404)
                    .body(Full::new(Bytes::from(format!("secret not found: {e}"))))
                    .unwrap_or_else(|_| {
                        Response::new(Full::new(Bytes::from("secret not found")))
                    }));
            }
        };

    let url = format!("https://{}{api_path}", provider.host_pattern);
    let formatted_value = format_header_value(provider.value_format, &secret_value);

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
        .filter(|(n, _)| !matches!(n.as_str(), "host" | "connection" | "transfer-encoding"))
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("body read error: {e}"))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("body error")))));
        }
    };

    let mut forward = client.request(method, &url);

    for (name, value) in &original_headers {
        forward = forward.header(name, value.as_slice());
    }

    // Inject auth header and host
    forward = forward.header(provider.header_name, &formatted_value);
    forward = forward.header("host", provider.host_pattern);
    forward = forward.body(body_bytes.to_vec());

    let resp = match forward.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("gateway upstream error for {provider_name}: {e}");
            return Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("upstream error: {e}"))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("upstream error")))));
        }
    };

    let status = resp.status().as_u16();
    let latency = start.elapsed().as_millis() as i64;

    // Audit log
    if let Err(e) = rekey_vault::audit::log_access(
        &conn,
        provider_name,
        provider.host_pattern,
        &api_path,
        Some(status as i32),
        Some(latency),
        "gateway",
    ) {
        tracing::error!("gateway audit log failed: {e}");
    }

    let resp_status = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    let resp_bytes = resp.bytes().await.unwrap_or_default();

    Ok(Response::builder()
        .status(resp_status)
        .body(Full::new(resp_bytes))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal error")))))
}
