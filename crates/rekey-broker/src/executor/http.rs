use std::time::Duration;

use rekey_domain::action::FixedHttpAction;
use rekey_domain::ipc::{ExecuteResponseMeta, METADATA_MAX_BYTES};
use zeroize::Zeroizing;

use super::ExecuteRequest;
use crate::upstream::{UpstreamError, UpstreamRequest};

const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &[
    "authentication-info",
    "authorization",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "www-authenticate",
];

fn header_value_is_safe(value: &str) -> bool {
    value.len() <= 8 * 1024 && !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

pub(super) fn response_metadata_fits(
    status: u16,
    headers: &[(String, String)],
    body_len: usize,
) -> bool {
    let Ok(body_len) = u32::try_from(body_len) else {
        return false;
    };
    serde_json::to_vec(&ExecuteResponseMeta {
        upstream_status: status,
        headers: headers.to_vec(),
        body_len,
    })
    .is_ok_and(|metadata| metadata.len() <= METADATA_MAX_BYTES as usize)
}

pub(super) fn reason_static(reason: &str) -> &'static str {
    match reason {
        "private-address" => "private-address",
        "redirect" => "redirect",
        "upstream-timeout" => "upstream-timeout",
        _ => "upstream-transport",
    }
}

pub(super) fn upstream_failure_is_indeterminate(err: &UpstreamError) -> bool {
    matches!(
        err,
        UpstreamError::Timeout
            | UpstreamError::Transport
            | UpstreamError::ResponseTooLarge
            | UpstreamError::Blocked("redirect")
    )
}

pub(super) fn validate_request(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
) -> Result<(), &'static str> {
    if request.body.len() > action.request_policy.max_body_bytes as usize {
        return Err("request-too-large");
    }
    if let Some(ct) = &request.content_type
        && (!header_value_is_safe(ct) || ct.is_empty())
    {
        return Err("invalid-content-type");
    }
    for (name, value) in &request.extra_headers {
        let Ok(name) = rekey_domain::action::HeaderName::new(name) else {
            return Err("invalid-extra-header");
        };
        if name.is_forbidden()
            || name == action.auth.header_name
            || name.as_str() == "authorization"
            || name.as_str() == "content-type"
            || !action.request_policy.allowed_extra_headers.contains(&name)
        {
            return Err("extra-header-not-allowed");
        }
        if !header_value_is_safe(value) {
            return Err("invalid-extra-header");
        }
    }
    Ok(())
}

pub(super) fn build_upstream(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    auth_value: Zeroizing<Vec<u8>>,
) -> UpstreamRequest {
    let mut headers = Vec::with_capacity(request.extra_headers.len() + 1);
    if let Some(ct) = &request.content_type {
        headers.push(("content-type".to_owned(), ct.clone()));
    }
    for (name, value) in &request.extra_headers {
        headers.push((name.to_ascii_lowercase(), value.clone()));
    }
    UpstreamRequest {
        host: action.origin.host().to_owned(),
        port: action.origin.port(),
        method: action.method,
        path: action.exact_path.as_str().to_owned(),
        headers,
        auth_header: (action.auth.header_name.as_str().to_owned(), auth_value),
        body: request.body.clone(),
        timeout: Duration::from_millis(action.timeout_ms as u64),
        response_max_bytes: action.response_policy.max_body_bytes,
    }
}

pub(super) fn filter_response_headers(
    action: &FixedHttpAction,
    headers: &[(String, String)],
) -> Vec<(String, String)> {
    let auth_slot = action.auth.header_name.as_str();
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            if FORBIDDEN_RESPONSE_HEADERS.contains(&lower.as_str()) || lower == auth_slot {
                return false;
            }
            rekey_domain::action::HeaderName::new(&lower)
                .map(|name| action.response_policy.allowed_headers.contains(&name))
                .unwrap_or(false)
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}
