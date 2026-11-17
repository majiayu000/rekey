use std::time::Duration;

use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::ipc::{ExecuteResponseMeta, METADATA_MAX_BYTES};
use rekey_domain::template::RenderedTarget;
use zeroize::Zeroizing;

use super::ExecuteRequest;
use super::sealing::{contains_secret, headers_contain_secret};
use crate::upstream::{ResponseHeaders, UpstreamError, UpstreamRequest};

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
    value.len() <= 8 * 1024
        && value
            .bytes()
            .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
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

pub(crate) fn upstream_failure_is_indeterminate(err: &UpstreamError) -> bool {
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
    if action.text_stream.is_some() {
        super::text_stream::validate(request)?;
    }
    if request.body.len() > action.request_policy.max_body_bytes as usize {
        return Err("request-too-large");
    }
    if let Some(ct) = &request.content_type
        && (!header_value_is_safe(ct) || ct.is_empty())
    {
        return Err("invalid-content-type");
    }
    for (raw_name, value) in &request.extra_headers {
        let Ok(name) = rekey_domain::action::HeaderName::new(raw_name) else {
            return Err("invalid-extra-header");
        };
        if raw_name != name.as_str()
            || name.is_forbidden()
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

#[cfg(any(feature = "lab", test))]
pub(super) fn build_upstream(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    auth_value: Zeroizing<Vec<u8>>,
) -> Result<UpstreamRequest, &'static str> {
    let path = action
        .target
        .fixed_path()
        .ok_or("template-target-unavailable")?;
    Ok(upstream_request(
        action,
        request,
        path.as_str().to_owned(),
        auth_value,
    ))
}

pub(super) fn build_rendered_upstream(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    target: &RenderedTarget,
    auth_value: Zeroizing<Vec<u8>>,
) -> UpstreamRequest {
    upstream_request(action, request, target.request_target(), auth_value)
}

fn upstream_request(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    path: String,
    auth_value: Zeroizing<Vec<u8>>,
) -> UpstreamRequest {
    let mut headers = Vec::with_capacity(request.extra_headers.len() + 1);
    if let Some(ct) = &request.content_type {
        headers.push(("content-type".to_owned(), ct.clone()));
    }
    for (name, value) in &request.extra_headers {
        headers.push((name.to_ascii_lowercase(), value.clone()));
    }
    if let ActionTarget::Template { fixed_headers, .. } = &action.target {
        headers.extend(
            fixed_headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.clone())),
        );
    }
    UpstreamRequest {
        host: action.origin.host().to_owned(),
        port: action.origin.port(),
        method: action.method,
        path,
        headers,
        auth_header: (action.auth.header_name.as_str().to_owned(), auth_value),
        body: Zeroizing::new(request.body.clone()),
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

/// Sealing reads upstream bytes exactly as received, and a compressed body
/// would hide a reflected credential from every needle. Every request asks
/// for identity; this admits no content coding and no transfer coding other
/// than HTTP/1.1 chunked framing. Non-UTF-8 coding values are refused too.
pub(super) fn response_is_identity(headers: &ResponseHeaders) -> bool {
    headers.name_value_bytes().all(|(name, value)| {
        let value = value.trim_ascii();
        if name.eq_ignore_ascii_case(b"content-encoding") {
            value.eq_ignore_ascii_case(b"identity")
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            value.eq_ignore_ascii_case(b"chunked")
        } else {
            true
        }
    })
}

/// Terminal audit reason for a buffered response that must not be released.
pub(super) fn buffered_refusal(
    headers: &ResponseHeaders,
    body: &[u8],
    needles: &[Zeroizing<Vec<u8>>],
) -> Option<&'static str> {
    if !response_is_identity(headers) {
        Some("response-encoding")
    } else if contains_secret(body, needles) || headers_contain_secret(headers, needles) {
        Some("reflected-secret")
    } else {
        None
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> ResponseHeaders {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>()
            .into()
    }

    #[test]
    fn only_identity_bodies_are_released() {
        for allowed in [
            vec![],
            vec![("content-type", "application/json")],
            vec![("Content-Encoding", " Identity ")],
            vec![("transfer-encoding", "chunked")],
        ] {
            assert!(response_is_identity(&headers(&allowed)), "{allowed:?}");
        }
        for coded in [
            vec![("content-encoding", "gzip")],
            vec![("Content-Encoding", "br")],
            vec![("content-encoding", "identity, gzip")],
            vec![
                ("content-encoding", "identity"),
                ("content-encoding", "zstd"),
            ],
            vec![("content-encoding", "")],
            vec![("transfer-encoding", "gzip, chunked")],
        ] {
            assert!(!response_is_identity(&headers(&coded)), "{coded:?}");
        }
        let mut map = reqwest::header::HeaderMap::new();
        map.append(
            "content-encoding",
            reqwest::header::HeaderValue::from_bytes(b"gzip\xff").unwrap(),
        );
        let unsupported = ResponseHeaders::from_header_map(&map);
        assert!(unsupported.is_empty(), "the value is not a visible string");
        assert!(!response_is_identity(&unsupported));
    }

    #[test]
    fn encoding_refusal_precedes_the_secret_scan() {
        let needles = super::super::sealing_needles(b"synthetic-secret-value", b"");
        let gzip = headers(&[("content-encoding", "gzip")]);
        let plain = headers(&[("content-type", "text/plain")]);
        // A coded body is refused even when its bytes look harmless.
        assert_eq!(
            buffered_refusal(&gzip, b"\x1f\x8b\x08\x00", &needles),
            Some("response-encoding")
        );
        assert_eq!(
            buffered_refusal(&plain, b"synthetic-secret-value", &needles),
            Some("reflected-secret")
        );
        assert_eq!(buffered_refusal(&plain, b"safe", &needles), None);
    }
}
