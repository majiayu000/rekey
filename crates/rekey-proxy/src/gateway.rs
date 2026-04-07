use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use rekey_vault::crypto::MasterKey;
use rekey_web::sse::{TrafficBroadcaster, TrafficEvent, emit_traffic};
use std::sync::Arc;
use std::time::Instant;

use crate::inject::{format_header_value, is_hop_by_hop_header};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn build_gateway_url(host_pattern: &str, api_path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("https://{host_pattern}{api_path}?{q}"),
        None => format!("https://{host_pattern}{api_path}"),
    }
}

pub async fn handle_gateway_request(
    req: Request<Incoming>,
    master_key: Arc<MasterKey>,
    db_path: &str,
    traffic_tx: TrafficBroadcaster,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 4 {
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("usage: /proxy/{provider}/{path}")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("bad request")))));
    }

    let provider_name = parts[2].to_string();
    let api_path = format!("/{}", parts[3]);
    let api_path_with_query = match query.as_deref() {
        Some(q) => format!("{api_path}?{q}"),
        None => api_path.clone(),
    };

    let provider = match rekey_vault::providers::get_provider(&provider_name) {
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

    let db_path_for_lookup = db_path.to_string();
    let provider_for_lookup = provider_name.clone();
    let key_for_lookup = master_key.clone();
    let secret_value = match tokio::task::spawn_blocking(move || {
        let conn = rekey_vault::db::open_connection(&db_path_for_lookup)?;
        rekey_vault::secrets::get_secret_value(&conn, key_for_lookup.as_ref(), &provider_for_lookup)
    })
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(e)) => {
            tracing::error!("secret lookup failed for {provider_name}: {e}");
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from(format!("secret not found: {e}"))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("secret not found")))));
        }
        Err(e) => {
            tracing::error!("secret lookup task failed for {provider_name}: {e}");
            return Ok(Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("db task error")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("db task error")))));
        }
    };

    let url = build_gateway_url(provider.host_pattern, &api_path, query.as_deref());
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

    let original_headers: Vec<(String, Vec<u8>)> = req
        .headers()
        .iter()
        .filter(|(n, _)| !is_hop_by_hop_header(n.as_str()))
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
    let audit_path = api_path_with_query.clone();
    let db_path_for_audit = db_path.to_string();
    let provider_for_audit = provider_name.clone();
    let host_for_audit = provider.host_pattern.to_string();
    match tokio::task::spawn_blocking(move || {
        let conn = rekey_vault::db::open_connection(&db_path_for_audit)?;
        rekey_vault::audit::log_access(
            &conn,
            &provider_for_audit,
            &host_for_audit,
            &audit_path,
            Some(status as i32),
            Some(latency),
            "gateway",
        )
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("gateway audit log failed: {e}"),
        Err(e) => tracing::error!("gateway audit task failed: {e}"),
    }

    emit_traffic(
        &traffic_tx,
        TrafficEvent {
            timestamp: now_unix(),
            secret_name: provider_name,
            target_host: provider.host_pattern.to_string(),
            target_path: api_path_with_query,
            status_code: Some(status as i32),
            latency_ms: Some(latency),
            source: "gateway".to_string(),
        },
    );

    let resp_status = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    let resp_bytes = resp.bytes().await.unwrap_or_default();

    Ok(Response::builder()
        .status(resp_status)
        .body(Full::new(resp_bytes))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("internal error")))))
}

#[cfg(test)]
mod tests {
    use super::build_gateway_url;

    #[test]
    fn gateway_url_keeps_query() {
        assert_eq!(
            build_gateway_url("api.openai.com", "/v1/models", Some("limit=20")),
            "https://api.openai.com/v1/models?limit=20"
        );
        assert_eq!(
            build_gateway_url("api.openai.com", "/v1/models", None),
            "https://api.openai.com/v1/models"
        );
    }
}
