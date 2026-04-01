use http::HeaderMap;

/// Replace `{value}` placeholder in format string with the actual secret.
pub fn format_header_value(format: &str, secret: &str) -> String {
    format.replace("{value}", secret)
}

/// Insert or overwrite a header in the map.
pub fn inject_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        http::header::HeaderName::from_bytes(name.as_bytes()),
        http::header::HeaderValue::from_str(value),
    ) {
        headers.insert(n, v);
    }
}

/// Check if a request path matches a glob-like pattern.
/// Supports `*` (match everything) and prefix matching with `*` suffix.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    pattern == path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bearer() {
        assert_eq!(
            format_header_value("Bearer {value}", "sk-123"),
            "Bearer sk-123"
        );
    }

    #[test]
    fn format_plain() {
        assert_eq!(format_header_value("{value}", "sk-123"), "sk-123");
    }

    #[test]
    fn inject_replaces_existing_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "REKEY_PLACEHOLDER".parse().unwrap());
        inject_header(&mut headers, "x-api-key", "sk-real-key");
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-real-key");
    }

    #[test]
    fn inject_adds_missing_header() {
        let mut headers = HeaderMap::new();
        inject_header(&mut headers, "authorization", "Bearer sk-real");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-real");
    }

    #[test]
    fn path_wildcard_matches_all() {
        assert!(path_matches("*", "/v1/chat"));
        assert!(path_matches("*", "/anything"));
    }

    #[test]
    fn path_prefix_match() {
        assert!(path_matches("/v1/*", "/v1/chat/completions"));
        assert!(!path_matches("/v1/*", "/v2/models"));
        assert!(!path_matches("/v2/*", "/v1/chat"));
    }

    #[test]
    fn path_exact_match() {
        assert!(path_matches("/v1/chat", "/v1/chat"));
        assert!(!path_matches("/v1/chat", "/v1/other"));
    }
}
