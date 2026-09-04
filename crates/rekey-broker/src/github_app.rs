//! Closed GitHub App Installation credential profile.
//!
//! This is deliberately not a connector registry or an Agent-facing token
//! API. It only supports the one fixed GitHub operation documented in the
//! foundation spec.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::action::FixedMethod;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::github_profile::GitHubAction;
pub(crate) use crate::github_profile::GitHubAppProfile as GitHubAppCredential;
use crate::upstream::{UpstreamRequest, UpstreamResponse, UpstreamTransport};

const GITHUB_HOST: &str = "api.github.com";
const RESOURCE_PATH: &str = "/installation/repositories";
const API_VERSION: &str = "2022-11-28";
const RESPONSE_LIMIT: u32 = 256 * 1024;
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
    WebhookSignature,
    WebhookPayload,
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
            Self::WebhookSignature => "github-webhook-signature-invalid",
            Self::WebhookPayload => "github-webhook-payload-invalid",
            Self::Deadline => "github-action-deadline",
        }
    }
}

impl GitHubAppCredential {
    pub(crate) async fn exchange(
        &self,
        transport: &dyn UpstreamTransport,
        action: GitHubAction,
        timeout: Duration,
    ) -> Result<InstallationToken, ExchangeFailure> {
        let jwt = self.sign_jwt()?;
        let repository_ids = match action {
            GitHubAction::ListRepositories => self
                .repositories
                .iter()
                .map(|repository| repository.id)
                .collect(),
            GitHubAction::CreateIssue { repository_index } => {
                vec![self.repositories[repository_index].id]
            }
        };
        let body = serde_json::to_vec(&ExchangeRequest {
            repository_ids,
            permissions: ExchangePermissions {
                metadata: "read",
                issues: matches!(action, GitHubAction::CreateIssue { .. }).then_some("write"),
            },
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
                body: Zeroizing::new(body),
                timeout,
                response_max_bytes: RESPONSE_LIMIT,
            }),
        )
        .await
        .map_err(|_| ExchangeFailure::uncertain_without_token(GitHubError::Deadline))?
        .map_err(|_| ExchangeFailure::uncertain_without_token(GitHubError::ExchangeTransport))?;
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
        let expected_ids: Vec<u64> = match action {
            GitHubAction::ListRepositories => self
                .repositories
                .iter()
                .map(|repository| repository.id)
                .collect(),
            GitHubAction::CreateIssue { repository_index } => {
                vec![self.repositories[repository_index].id]
            }
        };
        let mut returned_ids: Vec<u64> = raw
            .repositories
            .iter()
            .map(|repository| repository.id)
            .collect();
        returned_ids.sort_unstable();
        let permissions_match = raw.permissions.metadata == "read"
            && raw.permissions.issues
                == matches!(action, GitHubAction::CreateIssue { .. }).then_some("write");
        if !permissions_match
            || raw.repository_selection != "selected"
            || returned_ids != expected_ids
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
        action: GitHubAction,
        request_body: Vec<u8>,
        timeout: Duration,
        response_max_bytes: u32,
    ) -> Result<UpstreamResponse, GitHubError> {
        let (method, path, content_type) = match action {
            GitHubAction::ListRepositories => (FixedMethod::Get, RESOURCE_PATH.to_owned(), None),
            GitHubAction::CreateIssue { repository_index } => {
                let repository = &self.repositories[repository_index];
                (
                    FixedMethod::Post,
                    format!("/repos/{}/{}/issues", repository.owner, repository.name),
                    Some("application/json"),
                )
            }
        };
        let resource_request =
            ResourceRequest(method, path, content_type, request_body, response_max_bytes);
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(GitHubError::Deadline)?;
        let mut response =
            send_resource(transport, token, &resource_request, remaining(deadline)?).await?;
        if matches!(action, GitHubAction::ListRepositories) && matches!(response.status, 403 | 429)
        {
            let delay = retry_after(&response).ok_or(GitHubError::ResourceRejected)?;
            if delay >= remaining(deadline)? {
                return Err(GitHubError::Deadline);
            }
            tokio::time::sleep(delay).await;
            response =
                send_resource(transport, token, &resource_request, remaining(deadline)?).await?;
        }
        match action {
            GitHubAction::ListRepositories => self.validate_repository_list(response),
            GitHubAction::CreateIssue { repository_index } => {
                self.validate_created_issue(response, repository_index)
            }
        }
    }

    fn validate_repository_list(
        &self,
        response: UpstreamResponse,
    ) -> Result<UpstreamResponse, GitHubError> {
        if response.status != 200 {
            return Err(GitHubError::ResourceRejected);
        }
        let mut scope: RepositoryList =
            serde_json::from_slice(&response.body).map_err(|_| GitHubError::ResourceScope)?;
        scope.repositories.sort_by_key(|repository| repository.id);
        if scope.total_count as usize != self.repositories.len()
            || scope.repositories.len() != self.repositories.len()
            || !scope
                .repositories
                .iter()
                .zip(&self.repositories)
                .all(|(returned, expected)| {
                    returned.id == expected.id
                        && returned
                            .full_name
                            .eq_ignore_ascii_case(&format!("{}/{}", expected.owner, expected.name))
                })
        {
            return Err(GitHubError::ResourceScope);
        }
        let body = serde_json::to_vec(&RepositoryListOutput {
            total_count: self.repositories.len(),
            repositories: &self.repositories,
        })
        .map_err(|_| GitHubError::ResourceScope)?;
        Ok(json_response(200, body))
    }

    fn validate_created_issue(
        &self,
        response: UpstreamResponse,
        repository_index: usize,
    ) -> Result<UpstreamResponse, GitHubError> {
        if response.status != 201 {
            return Err(GitHubError::ResourceRejected);
        }
        let issue: CreatedIssue =
            serde_json::from_slice(&response.body).map_err(|_| GitHubError::ResourceScope)?;
        let repository = &self.repositories[repository_index];
        let expected_repository = format!("{}/{}", repository.owner, repository.name);
        let repository_matches = issue
            .repository_url
            .strip_prefix("https://api.github.com/repos/")
            .is_some_and(|value| value.eq_ignore_ascii_case(&expected_repository));
        let issue_matches = issue
            .html_url
            .strip_prefix("https://github.com/")
            .and_then(|value| value.rsplit_once("/issues/"))
            .is_some_and(|(returned_repository, returned_number)| {
                returned_repository.eq_ignore_ascii_case(&expected_repository)
                    && returned_number == issue.number.to_string()
            });
        if issue.id == 0 || issue.number == 0 || !repository_matches || !issue_matches {
            return Err(GitHubError::ResourceScope);
        }
        let body = serde_json::to_vec(&CreatedIssueOutput {
            id: issue.id,
            number: issue.number,
            html_url: issue.html_url,
        })
        .map_err(|_| GitHubError::ResourceScope)?;
        Ok(json_response(201, body))
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
                body: Zeroizing::new(Vec::new()),
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
        action: GitHubAction,
        request_body: Vec<u8>,
        total_deadline: Instant,
        response_max_bytes: u32,
    ) -> GitHubEffect {
        let Some(business_deadline) = total_deadline.checked_sub(CLEANUP_BUDGET) else {
            return GitHubEffect::without_token(GitHubError::Deadline, false);
        };
        let exchange_timeout = match remaining(business_deadline) {
            Ok(value) => value,
            Err(error) => return GitHubEffect::without_token(error, false),
        };
        let (resource, tokens, jwt) = match self.exchange(transport, action, exchange_timeout).await
        {
            Ok(token) => (
                match remaining(business_deadline) {
                    Ok(resource_timeout) => {
                        self.resource(
                            transport,
                            &token,
                            action,
                            request_body,
                            resource_timeout,
                            response_max_bytes,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                },
                vec![token.token],
                token.jwt,
            ),
            Err(failure) => {
                if failure.tokens.is_empty() {
                    return GitHubEffect::without_token(
                        failure.reason,
                        failure.remote_effect_possible,
                    );
                }
                (Err(failure.reason), failure.tokens, failure.jwt)
            }
        };
        let sealing_sources = sealing_sources(&jwt, &tokens);
        let revoke = self
            .revoke_captured_tokens(transport, &tokens, total_deadline)
            .await;
        GitHubEffect::WithToken {
            resource,
            revoke,
            sealing_sources,
        }
    }

    async fn revoke_captured_tokens(
        &self,
        transport: &dyn UpstreamTransport,
        tokens: &[Zeroizing<String>],
        total_deadline: Instant,
    ) -> Result<(), GitHubError> {
        let mut revoke = Ok(());
        for (index, token) in tokens.iter().enumerate() {
            let token_revoke = match remaining(total_deadline) {
                Ok(cleanup_remaining) => {
                    let attempts_left = (tokens.len() - index) as u32;
                    self.revoke(transport, token, cleanup_remaining / attempts_left)
                        .await
                }
                Err(error) => Err(error),
            };
            if revoke.is_ok() {
                revoke = token_revoke;
            }
        }
        revoke
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
    remote_effect_possible: bool,
}

impl ExchangeFailure {
    fn without_token(reason: GitHubError) -> Self {
        Self {
            reason,
            tokens: Vec::new(),
            jwt: Zeroizing::new(String::new()),
            remote_effect_possible: false,
        }
    }

    fn uncertain_without_token(reason: GitHubError) -> Self {
        Self {
            reason,
            tokens: Vec::new(),
            jwt: Zeroizing::new(String::new()),
            remote_effect_possible: true,
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
            remote_effect_possible: true,
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
    WithoutToken {
        error: GitHubError,
        remote_effect_possible: bool,
    },
    WithToken {
        resource: Result<UpstreamResponse, GitHubError>,
        revoke: Result<(), GitHubError>,
        sealing_sources: Vec<Zeroizing<Vec<u8>>>,
    },
}

impl GitHubEffect {
    fn without_token(error: GitHubError, remote_effect_possible: bool) -> Self {
        Self::WithoutToken {
            error,
            remote_effect_possible,
        }
    }
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
    repository_ids: Vec<u64>,
    permissions: ExchangePermissions,
}

#[derive(Serialize)]
struct ExchangePermissions {
    metadata: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    issues: Option<&'static str>,
}

#[derive(Deserialize)]
struct ExchangeResponse<'a> {
    #[serde(borrow)]
    token: &'a str,
    #[serde(rename = "expires_at", borrow)]
    _expires_at: &'a str,
    #[serde(borrow)]
    permissions: ExchangeResponsePermissions<'a>,
    repositories: Vec<ExchangeRepositoryRef>,
    #[serde(borrow)]
    repository_selection: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeResponsePermissions<'a> {
    #[serde(borrow)]
    metadata: &'a str,
    #[serde(default, borrow)]
    issues: Option<&'a str>,
}

#[derive(Deserialize)]
struct ExchangeRepositoryRef {
    id: u64,
}

#[derive(Deserialize)]
struct RepositoryList<'a> {
    total_count: u64,
    #[serde(borrow)]
    repositories: Vec<RepositoryRef<'a>>,
}

#[derive(Deserialize)]
struct RepositoryRef<'a> {
    id: u64,
    #[serde(borrow)]
    full_name: &'a str,
}

#[derive(Serialize)]
struct RepositoryListOutput<'a> {
    total_count: usize,
    repositories: &'a [crate::github_profile::GitHubRepository],
}

#[derive(Deserialize)]
struct CreatedIssue<'a> {
    id: u64,
    number: u64,
    #[serde(borrow)]
    repository_url: &'a str,
    #[serde(borrow)]
    html_url: &'a str,
}

#[derive(Serialize)]
struct CreatedIssueOutput<'a> {
    id: u64,
    number: u64,
    html_url: &'a str,
}

struct ResourceRequest(FixedMethod, String, Option<&'static str>, Vec<u8>, u32);

async fn send_resource(
    transport: &dyn UpstreamTransport,
    token: &InstallationToken,
    request: &ResourceRequest,
    timeout: Duration,
) -> Result<UpstreamResponse, GitHubError> {
    tokio::time::timeout(
        timeout,
        transport.send(UpstreamRequest {
            host: GITHUB_HOST.to_owned(),
            port: 443,
            method: request.0,
            path: request.1.clone(),
            headers: github_headers(request.2),
            auth_header: ("authorization".to_owned(), bearer(&token.token)),
            body: Zeroizing::new(request.3.clone()),
            timeout,
            response_max_bytes: request.4,
        }),
    )
    .await
    .map_err(|_| GitHubError::Deadline)?
    .map_err(|_| GitHubError::ResourceTransport)
}

fn retry_after(response: &UpstreamResponse) -> Option<Duration> {
    let mut values = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .map(|(_, value)| value.as_str());
    let value = values.next()?;
    if values.next().is_some()
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let seconds: u64 = value.parse().ok()?;
    (1..=30)
        .contains(&seconds)
        .then(|| Duration::from_secs(seconds))
}

fn json_response(status: u16, body: Vec<u8>) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())].into(),
        body: Zeroizing::new(body),
    }
}

#[cfg(test)]
#[path = "github_app_tests.rs"]
mod tests;
