use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{ActionId, CredentialId};

pub const REQUEST_BODY_HARD_MAX: u32 = 1024 * 1024;
pub const RESPONSE_BODY_HARD_MAX: u32 = 4 * 1024 * 1024;
pub const ACTION_TIMEOUT_HARD_MAX_MS: u32 = 120_000;
pub const HEADER_PREFIX_MAX_BYTES: usize = 32;
pub const EXACT_PATH_MAX_BYTES: usize = 2048;

/// Header names an admin can never select as a credential slot and an agent
/// can never supply. Hop-by-hop and framing headers are owned by the broker.
const FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Auth slots allowed without appearing on an explicit action allowlist.
const DEFAULT_AUTH_HEADERS: &[&str] = &["authorization", "x-api-key"];

fn invalid(msg: &str) -> DomainError {
    DomainError::InvalidActionDefinition(msg.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ActionName(String);

impl ActionName {
    pub fn new(raw: &str) -> Result<Self, DomainError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 128 {
            return Err(invalid("action name must be 1-128 characters"));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(invalid("action name must not contain control characters"));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ActionName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FixedMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl FixedMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            _ => Err(invalid("unsupported method")),
        }
    }
}

/// `https://host[:port]` with no userinfo, path, query, or fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HttpsOrigin(String);

impl HttpsOrigin {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let rest = raw
            .strip_prefix("https://")
            .ok_or_else(|| invalid("origin must start with https://"))?;
        if rest.is_empty() {
            return Err(invalid("origin host is empty"));
        }
        if rest.contains(['/', '?', '#', '@', '\\']) || rest.chars().any(char::is_whitespace) {
            return Err(invalid(
                "origin must not contain userinfo, path, query, or fragment",
            ));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| invalid("origin port must be 1-65535"))?;
                if port == 0 {
                    return Err(invalid("origin port must be 1-65535"));
                }
                (h, Some(port))
            }
            None => (rest, None),
        };
        if host.is_empty() || host.len() > 253 {
            return Err(invalid("origin host length is invalid"));
        }
        if host.contains('[') || host.contains(']') {
            return Err(invalid("ipv6 literal origins are not supported in P0"));
        }
        let host = host.to_ascii_lowercase();
        let valid_host = host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
        if !valid_host {
            return Err(invalid("origin host contains invalid characters"));
        }
        match port {
            Some(p) if p != 443 => Ok(Self(format!("https://{host}:{p}"))),
            _ => Ok(Self(format!("https://{host}"))),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn host(&self) -> &str {
        let rest = &self.0["https://".len()..];
        rest.rsplit_once(':').map_or(rest, |(h, _)| h)
    }

    pub fn port(&self) -> u16 {
        let rest = &self.0["https://".len()..];
        rest.rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(443)
    }
}

impl fmt::Display for HttpsOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HttpsOrigin {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Exact request path fixed by the admin. Never influenced by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExactPath(String);

impl ExactPath {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if !raw.starts_with('/') {
            return Err(invalid("path must start with /"));
        }
        if raw.len() > EXACT_PATH_MAX_BYTES {
            return Err(invalid("path is too long"));
        }
        if raw.contains(['?', '#', '\\']) || raw.chars().any(|c| c.is_control() || c == ' ') {
            return Err(invalid(
                "path must not contain query, fragment, spaces, or control characters",
            ));
        }
        if raw.split('/').any(|seg| seg == ".." || seg == ".") {
            return Err(invalid("path must not contain dot segments"));
        }
        let lower = raw.to_ascii_lowercase();
        if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%2e") {
            return Err(invalid("path must not contain encoded separators or dots"));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ExactPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Lowercase HTTP header field name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn new(raw: &str) -> Result<Self, DomainError> {
        let lower = raw.trim().to_ascii_lowercase();
        if lower.is_empty() || lower.len() > 64 {
            return Err(invalid("header name must be 1-64 bytes"));
        }
        if !lower
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(invalid("header name contains invalid characters"));
        }
        Ok(Self(lower))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_forbidden(&self) -> bool {
        FORBIDDEN_HEADERS.contains(&self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for HeaderName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Optional printable-ASCII prefix placed before the credential value, e.g.
/// `Bearer `. At most one trailing space; never CR, LF, or NUL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HeaderPrefix(String);

impl HeaderPrefix {
    pub fn new(raw: &str) -> Result<Self, DomainError> {
        if raw.is_empty() {
            return Ok(Self(String::new()));
        }
        if raw.len() > HEADER_PREFIX_MAX_BYTES {
            return Err(invalid("header prefix is longer than 32 bytes"));
        }
        let bytes = raw.as_bytes();
        let (interior, last) = bytes.split_at(bytes.len() - 1);
        let printable = |b: &u8| (0x21..=0x7e).contains(b);
        if !interior.iter().all(printable) {
            return Err(invalid("header prefix must be printable ascii"));
        }
        if !printable(&last[0]) && last[0] != b' ' {
            return Err(invalid("header prefix may end with at most one space"));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HeaderPrefix {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderCredentialUse {
    pub header_name: HeaderName,
    pub prefix: HeaderPrefix,
}

impl HeaderCredentialUse {
    pub fn new(header_name: HeaderName, prefix: HeaderPrefix) -> Result<Self, DomainError> {
        if header_name.is_forbidden() {
            return Err(invalid("credential header slot is forbidden"));
        }
        if !DEFAULT_AUTH_HEADERS.contains(&header_name.as_str())
            && !header_name.as_str().starts_with("x-")
        {
            return Err(invalid(
                "credential header must be authorization, x-api-key, or an explicit x- header",
            ));
        }
        Ok(Self {
            header_name,
            prefix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestPolicy {
    pub max_body_bytes: u32,
    /// Plain headers the agent may supply via `extra_headers`. Anything not
    /// listed here rejects the whole request; nothing is silently stripped.
    pub allowed_extra_headers: BTreeSet<HeaderName>,
}

impl RequestPolicy {
    pub fn validate(&self, auth_header: &HeaderName) -> Result<(), DomainError> {
        if self.max_body_bytes == 0 || self.max_body_bytes > REQUEST_BODY_HARD_MAX {
            return Err(invalid("request max_body_bytes must be 1..=1 MiB"));
        }
        for h in &self.allowed_extra_headers {
            if h.is_forbidden() || h == auth_header || h.as_str() == "authorization" {
                return Err(invalid(
                    "allowed extra header collides with a protected header",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub max_body_bytes: u32,
    /// Response headers returned to the agent. Everything else is removed.
    pub allowed_headers: BTreeSet<HeaderName>,
}

impl ResponsePolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.max_body_bytes == 0 || self.max_body_bytes > RESPONSE_BODY_HARD_MAX {
            return Err(invalid("response max_body_bytes must be 1..=4 MiB"));
        }
        for h in &self.allowed_headers {
            if h.is_forbidden()
                || h.as_str() == "www-authenticate"
                || h.as_str() == "authentication-info"
                || h.as_str() == "authorization"
                || h.as_str() == "proxy-authorization"
            {
                return Err(invalid(
                    "response header allowlist contains a forbidden header",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedHttpAction {
    pub id: ActionId,
    pub name: ActionName,
    pub version: u64,
    pub enabled: bool,
    pub credential_id: CredentialId,
    pub origin: HttpsOrigin,
    pub method: FixedMethod,
    pub exact_path: ExactPath,
    pub auth: HeaderCredentialUse,
    pub timeout_ms: u32,
    pub request_policy: RequestPolicy,
    pub response_policy: ResponsePolicy,
}

impl FixedHttpAction {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.version == 0 {
            return Err(invalid("action version must be >= 1"));
        }
        if self.timeout_ms == 0 || self.timeout_ms > ACTION_TIMEOUT_HARD_MAX_MS {
            return Err(invalid("timeout_ms must be 1..=120000"));
        }
        if self.auth.header_name.is_forbidden() {
            return Err(invalid("credential header slot is forbidden"));
        }
        self.request_policy.validate(&self.auth.header_name)?;
        self.response_policy.validate()?;
        if self
            .response_policy
            .allowed_headers
            .contains(&self.auth.header_name)
        {
            return Err(invalid(
                "response header allowlist contains the credential header",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn origin_rules() {
        assert_eq!(
            HttpsOrigin::parse("https://API.Example.com")
                .unwrap()
                .as_str(),
            "https://api.example.com"
        );
        assert_eq!(
            HttpsOrigin::parse("https://api.example.com:443")
                .unwrap()
                .as_str(),
            "https://api.example.com"
        );
        let o = HttpsOrigin::parse("https://api.example.com:8443").unwrap();
        assert_eq!(o.host(), "api.example.com");
        assert_eq!(o.port(), 8443);
        for bad in [
            "http://api.example.com",
            "https://user@api.example.com",
            "https://api.example.com/path",
            "https://api.example.com?q=1",
            "https://api.example.com#f",
            "https://",
            "https://api.example.com:0",
            "https://api.example.com:99999",
            "https://-bad.example.com",
            "https://exa mple.com",
        ] {
            assert!(HttpsOrigin::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn path_rules() {
        assert!(ExactPath::parse("/v1/messages").is_ok());
        for bad in [
            "v1/messages",
            "/a/../b",
            "/a/./b",
            "/a%2Fb",
            "/a%2fb",
            "/a%5Cb",
            "/a%2E%2E/b",
            "/a b",
            "/a?x=1",
            "/a#f",
            "/a\nb",
        ] {
            assert!(ExactPath::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn header_rules() {
        assert!(HeaderName::new("Authorization").unwrap().as_str() == "authorization");
        assert!(HeaderName::new("bad header").is_err());
        assert!(HeaderName::new("").is_err());

        assert!(
            HeaderCredentialUse::new(
                HeaderName::new("authorization").unwrap(),
                HeaderPrefix::new("Bearer ").unwrap()
            )
            .is_ok()
        );
        assert!(
            HeaderCredentialUse::new(
                HeaderName::new("x-api-key").unwrap(),
                HeaderPrefix::new("").unwrap()
            )
            .is_ok()
        );
        for forbidden in [
            "cookie",
            "host",
            "content-length",
            "transfer-encoding",
            "proxy-authorization",
        ] {
            assert!(
                HeaderCredentialUse::new(
                    HeaderName::new(forbidden).unwrap(),
                    HeaderPrefix::new("").unwrap()
                )
                .is_err(),
                "{forbidden} must be rejected as auth slot"
            );
        }
    }

    #[test]
    fn response_allowlist_rejects_credential_headers() {
        let mut policy = ResponsePolicy {
            max_body_bytes: 1024,
            allowed_headers: BTreeSet::from([HeaderName::new("content-type").unwrap()]),
        };
        assert!(policy.validate().is_ok());
        for forbidden in ["authorization", "proxy-authorization", "set-cookie"] {
            policy.allowed_headers = BTreeSet::from([HeaderName::new(forbidden).unwrap()]);
            assert!(
                policy.validate().is_err(),
                "{forbidden} must not be returnable"
            );
        }
    }

    #[test]
    fn prefix_rules() {
        assert!(HeaderPrefix::new("").is_ok());
        assert!(HeaderPrefix::new("Bearer ").is_ok());
        assert!(HeaderPrefix::new("token=").is_ok());
        assert!(HeaderPrefix::new(" leading").is_err());
        assert!(HeaderPrefix::new("two  ").is_err());
        assert!(HeaderPrefix::new("crlf\r\n").is_err());
        assert!(HeaderPrefix::new(&"p".repeat(33)).is_err());
    }
}
