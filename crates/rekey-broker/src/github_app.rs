//! Closed GitHub App Installation credential profile.
//!
//! This is deliberately not a connector registry or an Agent-facing token
//! API. It only supports the one fixed GitHub operation documented in the
//! foundation spec.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use rekey_domain::action::{FixedHttpAction, FixedMethod};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::executor::ExecuteRequest;
use crate::upstream::{UpstreamRequest, UpstreamResponse, UpstreamTransport};

const CREDENTIAL_TYPE: &str = "github-app-installation-v1";
const GITHUB_HOST: &str = "api.github.com";
const RESOURCE_PATH: &str = "/installation/repositories";
const API_VERSION: &str = "2022-11-28";
const RESPONSE_LIMIT: u32 = 256 * 1024;
const MIN_TOTAL_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_BUDGET: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitHubError {
    ProfileMismatch,
    InvalidCredential,
    JwtSigning,
    ExchangeTransport,
    ExchangeRejected,
    ExchangeScope,
    ResourceTransport,
    ResourceRejected,
    ResourceScope,
    RevokeTransport,
    RevokeRejected,
    Deadline,
}

impl GitHubError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::ProfileMismatch => "github-profile-mismatch",
            Self::InvalidCredential => "github-credential-invalid",
            Self::JwtSigning => "github-jwt-signing-failed",
            Self::ExchangeTransport => "github-token-exchange-transport",
            Self::ExchangeRejected => "github-token-exchange-rejected",
            Self::ExchangeScope => "github-token-scope-invalid",
            Self::ResourceTransport => "github-resource-transport",
            Self::ResourceRejected => "github-resource-rejected",
            Self::ResourceScope => "github-resource-scope-invalid",
            Self::RevokeTransport => "github-token-revoke-transport",
            Self::RevokeRejected => "github-token-revoke-rejected",
            Self::Deadline => "github-action-deadline",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential<'a> {
    #[serde(borrow)]
    credential_type: &'a str,
    #[serde(borrow)]
    client_id: &'a str,
    app_id: u64,
    installation_id: u64,
    repository_id: u64,
    #[serde(borrow)]
    private_key_pkcs1_der_base64: &'a str,
}

pub(crate) struct GitHubAppCredential {
    client_id: String,
    app_id: u64,
    installation_id: u64,
    repository_id: u64,
    private_key_pkcs1_der: Zeroizing<Vec<u8>>,
}

impl GitHubAppCredential {
    pub(crate) fn validate_profile(input: &[u8]) -> Result<(), GitHubError> {
        Self::parse(input).map(|_| ())
    }

    pub(crate) fn parse_profile(input: &[u8]) -> Result<Self, GitHubError> {
        Self::parse(input)
    }

    pub(crate) fn action_is_reserved(action: &FixedHttpAction) -> bool {
        action.origin.host() == GITHUB_HOST
            && action.origin.port() == 443
            && action.method == FixedMethod::Get
            && action.exact_path.as_str() == RESOURCE_PATH
            && action.auth.header_name.as_str() == "authorization"
            && action.auth.prefix.as_str() == "Bearer "
    }

    fn parse(input: &[u8]) -> Result<Self, GitHubError> {
        let raw: RawCredential<'_> =
            serde_json::from_slice(input).map_err(|_| GitHubError::InvalidCredential)?;
        if raw.credential_type != CREDENTIAL_TYPE
            || raw.client_id.is_empty()
            || raw.client_id.len() > 128
            || !raw
                .client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            || raw.app_id == 0
            || raw.installation_id == 0
            || raw.repository_id == 0
            || raw.private_key_pkcs1_der_base64.is_empty()
            || raw.private_key_pkcs1_der_base64.len() > 48 * 1024
        {
            return Err(GitHubError::InvalidCredential);
        }
        let encoded_key = raw.private_key_pkcs1_der_base64.as_bytes();
        let decoded_len = BASE64
            .decode_len(encoded_key.len())
            .map_err(|_| GitHubError::InvalidCredential)?;
        let mut der = Zeroizing::new(vec![0u8; decoded_len]);
        let written = BASE64
            .decode_mut(encoded_key, &mut der)
            .map_err(|_| GitHubError::InvalidCredential)?;
        der.truncate(written);
        // PKCS#8 and malformed material fail before any network effect.
        // aws-lc-rs owns private components through managed EVP/RSA pointers;
        // its pointer contract zeroizes allocations in every *_free path.
        RsaKeyPair::from_der(&der).map_err(|_| GitHubError::InvalidCredential)?;
        Ok(Self {
            client_id: raw.client_id.to_owned(),
            app_id: raw.app_id,
            installation_id: raw.installation_id,
            repository_id: raw.repository_id,
            private_key_pkcs1_der: der,
        })
    }

    pub(crate) fn validate_action(
        &self,
        action: &FixedHttpAction,
        request: &ExecuteRequest,
    ) -> Result<(), GitHubError> {
        if !Self::action_is_reserved(action)
            || request.content_type.is_some()
            || !request.extra_headers.is_empty()
            || !request.body.is_empty()
            || Duration::from_millis(action.timeout_ms as u64) < MIN_TOTAL_TIMEOUT
        {
            return Err(GitHubError::ProfileMismatch);
        }
        Ok(())
    }

    pub(crate) fn commitment(&self) -> String {
        let mut hasher = Sha256::new();
        let app_id = self.app_id.to_string();
        let installation_id = self.installation_id.to_string();
        let repository_id = self.repository_id.to_string();
        for field in [
            self.client_id.as_bytes(),
            app_id.as_bytes(),
            installation_id.as_bytes(),
            repository_id.as_bytes(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        format!("binding-sha256={:x}", hasher.finalize())
    }

    pub(crate) fn private_key_bytes(&self) -> &[u8] {
        &self.private_key_pkcs1_der
    }

    pub(crate) async fn exchange(
        &self,
        transport: &dyn UpstreamTransport,
        timeout: Duration,
    ) -> Result<InstallationToken, ExchangeFailure> {
        let jwt = self.sign_jwt()?;
        let body = serde_json::to_vec(&ExchangeRequest {
            repository_ids: [self.repository_id],
            permissions: ExchangePermissions { metadata: "read" },
        })
        .map_err(|_| ExchangeFailure::without_token(GitHubError::InvalidCredential))?;
        let response = tokio::time::timeout(
            timeout,
            transport.send(UpstreamRequest {
                host: GITHUB_HOST.to_owned(),
                port: 443,
                method: FixedMethod::Post,
                path: format!("/app/installations/{}/access_tokens", self.installation_id),
                headers: github_headers(Some("application/json")),
                auth_header: ("authorization".to_owned(), bearer(&jwt)),
                body,
                timeout,
                response_max_bytes: RESPONSE_LIMIT,
            }),
        )
        .await
        .map_err(|_| ExchangeFailure::without_token(GitHubError::Deadline))?
        .map_err(|_| ExchangeFailure::without_token(GitHubError::ExchangeTransport))?;
        let body = response.body;
        let mut probe = probe_tokens(&body);
        if response.status != 201 {
            return Err(ExchangeFailure::with_tokens(
                GitHubError::ExchangeRejected,
                probe.tokens,
                jwt,
            ));
        }
        let raw: ExchangeResponse<'_> = match serde_json::from_slice(&body) {
            Ok(raw) => raw,
            Err(_) => {
                return Err(ExchangeFailure::with_tokens(
                    GitHubError::ExchangeRejected,
                    probe.tokens,
                    jwt,
                ));
            }
        };
        if probe.truncated
            || probe.occurrences != 1
            || probe.tokens.len() != 1
            || probe
                .tokens
                .first()
                .is_none_or(|token| raw.token.as_bytes() != token.as_bytes())
        {
            return Err(ExchangeFailure::with_tokens(
                GitHubError::ExchangeRejected,
                probe.tokens,
                jwt,
            ));
        }
        let Some(probed_token) = probe.tokens.pop() else {
            return Err(ExchangeFailure::with_tokens(
                GitHubError::ExchangeRejected,
                Vec::new(),
                jwt,
            ));
        };
        let token = InstallationToken {
            token: probed_token,
            jwt,
        };
        if raw.permissions.len() != 1
            || raw.permissions.get("metadata").map(String::as_str) != Some("read")
            || raw.repository_selection != "selected"
        {
            let InstallationToken { token, jwt } = token;
            return Err(ExchangeFailure::with_tokens(
                GitHubError::ExchangeScope,
                vec![token],
                jwt,
            ));
        }
        Ok(token)
    }

    pub(crate) async fn resource(
        &self,
        transport: &dyn UpstreamTransport,
        token: &InstallationToken,
        timeout: Duration,
        response_max_bytes: u32,
    ) -> Result<UpstreamResponse, GitHubError> {
        let response = tokio::time::timeout(
            timeout,
            transport.send(UpstreamRequest {
                host: GITHUB_HOST.to_owned(),
                port: 443,
                method: FixedMethod::Get,
                path: RESOURCE_PATH.to_owned(),
                headers: github_headers(None),
                auth_header: ("authorization".to_owned(), bearer(&token.token)),
                body: Vec::new(),
                timeout,
                response_max_bytes,
            }),
        )
        .await
        .map_err(|_| GitHubError::Deadline)?
        .map_err(|_| GitHubError::ResourceTransport)?;
        if response.status != 200 {
            return Err(GitHubError::ResourceRejected);
        }
        let scope: RepositoryList =
            serde_json::from_slice(&response.body).map_err(|_| GitHubError::ResourceScope)?;
        if scope.total_count != 1
            || scope.repositories.len() != 1
            || scope.repositories[0].id != self.repository_id
        {
            return Err(GitHubError::ResourceScope);
        }
        let body = serde_json::to_vec(&scope).map_err(|_| GitHubError::ResourceScope)?;
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: Zeroizing::new(body),
        })
    }

    pub(crate) async fn revoke(
        &self,
        transport: &dyn UpstreamTransport,
        token: &str,
        timeout: Duration,
    ) -> Result<(), GitHubError> {
        let response = tokio::time::timeout(
            timeout,
            transport.send(UpstreamRequest {
                host: GITHUB_HOST.to_owned(),
                port: 443,
                method: FixedMethod::Delete,
                path: "/installation/token".to_owned(),
                headers: github_headers(None),
                auth_header: ("authorization".to_owned(), bearer(token)),
                body: Vec::new(),
                timeout,
                response_max_bytes: 1024,
            }),
        )
        .await
        .map_err(|_| GitHubError::Deadline)?
        .map_err(|_| GitHubError::RevokeTransport)?;
        if response.status != 204 || !response.body.is_empty() {
            return Err(GitHubError::RevokeRejected);
        }
        Ok(())
    }

    pub(crate) async fn execute_effect(
        &self,
        transport: &dyn UpstreamTransport,
        total_deadline: Instant,
        response_max_bytes: u32,
    ) -> GitHubEffect {
        let Some(business_deadline) = total_deadline.checked_sub(CLEANUP_BUDGET) else {
            return GitHubEffect::WithoutToken(GitHubError::Deadline);
        };
        let exchange_timeout = match remaining(business_deadline) {
            Ok(value) => value,
            Err(error) => return GitHubEffect::WithoutToken(error),
        };
        let (resource, tokens, jwt) = match self.exchange(transport, exchange_timeout).await {
            Ok(token) => (
                match remaining(business_deadline) {
                    Ok(resource_timeout) => {
                        self.resource(transport, &token, resource_timeout, response_max_bytes)
                            .await
                    }
                    Err(error) => Err(error),
                },
                vec![token.token],
                token.jwt,
            ),
            Err(failure) => {
                if failure.tokens.is_empty() {
                    return GitHubEffect::WithoutToken(failure.reason);
                }
                (Err(failure.reason), failure.tokens, failure.jwt)
            }
        };
        let sealing_sources = sealing_sources(&jwt, &tokens);
        let mut revoke = Ok(());
        for token in &tokens {
            let token_revoke = match remaining(total_deadline) {
                Ok(revoke_timeout) => self.revoke(transport, token, revoke_timeout).await,
                Err(error) => Err(error),
            };
            if revoke.is_ok() {
                revoke = token_revoke;
            }
        }
        GitHubEffect::WithToken {
            resource,
            revoke,
            sealing_sources,
        }
    }

    fn sign_jwt(&self) -> Result<Zeroizing<String>, GitHubError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GitHubError::JwtSigning)?
            .as_secs();
        let claims = JwtClaims {
            iat: now.saturating_sub(60),
            exp: now.saturating_add(9 * 60),
            iss: &self.client_id,
        };
        let header = BASE64URL_NOPAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = BASE64URL_NOPAD
            .encode(&serde_json::to_vec(&claims).map_err(|_| GitHubError::JwtSigning)?);
        let signing_input = Zeroizing::new(format!("{header}.{payload}"));
        let key = RsaKeyPair::from_der(&self.private_key_pkcs1_der)
            .map_err(|_| GitHubError::JwtSigning)?;
        let mut signature = Zeroizing::new(vec![0u8; key.public_modulus_len()]);
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|_| GitHubError::JwtSigning)?;
        let encoded_signature = Zeroizing::new(BASE64URL_NOPAD.encode(&signature));
        let mut jwt = Zeroizing::new(String::with_capacity(
            signing_input.len() + 1 + encoded_signature.len(),
        ));
        jwt.push_str(&signing_input);
        jwt.push('.');
        jwt.push_str(&encoded_signature);
        Ok(jwt)
    }
}

pub(crate) struct ExchangeFailure {
    pub(crate) reason: GitHubError,
    pub(crate) tokens: Vec<Zeroizing<String>>,
    pub(crate) jwt: Zeroizing<String>,
}

impl ExchangeFailure {
    fn without_token(reason: GitHubError) -> Self {
        Self {
            reason,
            tokens: Vec::new(),
            jwt: Zeroizing::new(String::new()),
        }
    }

    fn with_tokens(
        reason: GitHubError,
        tokens: Vec<Zeroizing<String>>,
        jwt: Zeroizing<String>,
    ) -> Self {
        Self {
            reason,
            tokens,
            jwt,
        }
    }
}

impl From<GitHubError> for ExchangeFailure {
    fn from(reason: GitHubError) -> Self {
        Self::without_token(reason)
    }
}

pub(crate) struct InstallationToken {
    token: Zeroizing<String>,
    jwt: Zeroizing<String>,
}

pub(crate) enum GitHubEffect {
    WithoutToken(GitHubError),
    WithToken {
        resource: Result<UpstreamResponse, GitHubError>,
        revoke: Result<(), GitHubError>,
        sealing_sources: Vec<Zeroizing<Vec<u8>>>,
    },
}

fn remaining(deadline: Instant) -> Result<Duration, GitHubError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(GitHubError::Deadline)
}

fn sealing_sources(
    jwt: &Zeroizing<String>,
    tokens: &[Zeroizing<String>],
) -> Vec<Zeroizing<Vec<u8>>> {
    let mut sources = Vec::with_capacity(tokens.len() + 1);
    sources.push(Zeroizing::new(jwt.as_bytes().to_vec()));
    sources.extend(
        tokens
            .iter()
            .map(|token| Zeroizing::new(token.as_bytes().to_vec())),
    );
    sources
}

const TOKEN_CAPTURE_LIMIT: usize = 4;

struct TokenProbe {
    tokens: Vec<Zeroizing<String>>,
    occurrences: usize,
    truncated: bool,
}

/// Best-effort probe used before status and schema validation. GitHub
/// installation tokens are unescaped printable ASCII. Escaped JSON strings
/// and more than four distinct malformed tokens are deliberately outside the
/// cleanup guarantee documented in the spec.
fn probe_tokens(body: &[u8]) -> TokenProbe {
    let mut result = TokenProbe {
        tokens: Vec::new(),
        occurrences: 0,
        truncated: false,
    };
    let key = br#""token""#;
    let mut offset = 0;
    while let Some(relative) = body[offset..].windows(key.len()).position(|w| w == key) {
        let mut cursor = offset + relative + key.len();
        while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if body.get(cursor) != Some(&b':') {
            offset += relative + key.len();
            continue;
        }
        cursor += 1;
        while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if body.get(cursor) != Some(&b'"') {
            offset += relative + key.len();
            continue;
        }
        cursor += 1;
        let value_start = cursor;
        while body
            .get(cursor)
            .is_some_and(|byte| *byte != b'"' && *byte != b'\\')
        {
            cursor += 1;
        }
        let Some(terminator) = body.get(cursor) else {
            break;
        };
        if *terminator == b'\\' {
            offset = cursor + 1;
            continue;
        }
        let value = &body[value_start..cursor];
        if value.is_empty() || !value.iter().all(|byte| byte.is_ascii_graphic()) {
            offset = cursor + 1;
            continue;
        }
        result.occurrences = result.occurrences.saturating_add(1);
        if !result.tokens.iter().any(|known| known.as_bytes() == value) {
            if result.tokens.len() == TOKEN_CAPTURE_LIMIT {
                result.truncated = true;
            } else if let Ok(token) = String::from_utf8(value.to_vec()) {
                result.tokens.push(Zeroizing::new(token));
            }
        }
        offset = cursor + 1;
    }
    result
}

fn bearer(value: &str) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(7 + value.len()));
    output.extend_from_slice(b"Bearer ");
    output.extend_from_slice(value.as_bytes());
    output
}

fn github_headers(content_type: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        ),
        ("x-github-api-version".to_owned(), API_VERSION.to_owned()),
        (
            "user-agent".to_owned(),
            format!("rekey/{}", env!("CARGO_PKG_VERSION")),
        ),
    ];
    if let Some(value) = content_type {
        headers.push(("content-type".to_owned(), value.to_owned()));
    }
    headers
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iat: u64,
    exp: u64,
    iss: &'a str,
}

#[derive(Serialize)]
struct ExchangeRequest {
    repository_ids: [u64; 1],
    permissions: ExchangePermissions,
}

#[derive(Serialize)]
struct ExchangePermissions {
    metadata: &'static str,
}

#[derive(Deserialize)]
struct ExchangeResponse<'a> {
    #[serde(borrow)]
    token: &'a str,
    #[serde(rename = "expires_at")]
    _expires_at: String,
    permissions: BTreeMap<String, String>,
    #[serde(borrow)]
    repository_selection: &'a str,
}

#[derive(Deserialize, Serialize)]
struct RepositoryList {
    total_count: u64,
    repositories: Vec<RepositoryRef>,
}

#[derive(Deserialize, Serialize)]
struct RepositoryRef {
    id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PanicTransport;

    impl UpstreamTransport for PanicTransport {
        fn send(&self, _request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
            Box::pin(async { panic!("expired effect deadline reached transport") })
        }
    }

    #[test]
    fn marked_invalid_profile_fails_closed() {
        assert!(matches!(
            GitHubAppCredential::validate_profile(
                br#"{"credential_type":"github-app-installation-v1","client_id":"x"}"#,
            ),
            Err(GitHubError::InvalidCredential)
        ));
    }

    #[tokio::test]
    async fn max_timeout_deadline_is_not_reset_at_effect_entry() {
        let profile = GitHubAppCredential {
            client_id: "test".to_owned(),
            app_id: 1,
            installation_id: 1,
            repository_id: 1,
            private_key_pkcs1_der: Zeroizing::new(Vec::new()),
        };
        let admission_started = Instant::now() - Duration::from_secs(121);
        let result = profile
            .execute_effect(
                &PanicTransport,
                admission_started + Duration::from_secs(120),
                RESPONSE_LIMIT,
            )
            .await;
        assert!(matches!(
            result,
            GitHubEffect::WithoutToken(GitHubError::Deadline)
        ));
    }
}
