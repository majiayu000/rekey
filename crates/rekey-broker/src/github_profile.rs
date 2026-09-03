//! Secret-bearing GitHub App v2 profile and webhook mutation rules.

use aws_lc_rs::{hmac, signature::RsaKeyPair};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::executor::ExecuteRequest;
use crate::github_app::GitHubError;
use rekey_domain::action::{FixedHttpAction, FixedMethod};

const CREDENTIAL_TYPE: &str = "github-app-installation-v2";
const MAX_REPOSITORIES: usize = 16;
const MIN_TOTAL_TIMEOUT_MS: u32 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitHubRepository {
    pub(crate) id: u64,
    pub(crate) owner: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitHubPermissions {
    pub(crate) metadata: MetadataPermission,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issues: Option<IssuesPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MetadataPermission {
    Read,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IssuesPermission {
    Write,
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
    repositories: Vec<GitHubRepository>,
    permissions: GitHubPermissions,
    #[serde(borrow)]
    webhook_secret: &'a str,
    #[serde(borrow)]
    private_key_pkcs1_der_base64: &'a str,
}

pub(crate) struct GitHubAppProfile {
    pub(crate) client_id: String,
    pub(crate) app_id: u64,
    pub(crate) installation_id: u64,
    pub(crate) repositories: Vec<GitHubRepository>,
    pub(crate) permissions: GitHubPermissions,
    webhook_secret: Zeroizing<Vec<u8>>,
    pub(crate) private_key_pkcs1_der: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitHubAction {
    ListRepositories,
    CreateIssue { repository_index: usize },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateIssueBody {
    pub(crate) title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) body: Option<String>,
}

impl GitHubAppProfile {
    pub(crate) fn validate_profile(input: &[u8]) -> Result<(), GitHubError> {
        Self::parse(input).map(|_| ())
    }

    pub(crate) fn parse_profile(input: &[u8]) -> Result<Self, GitHubError> {
        Self::parse(input)
    }

    fn parse(input: &[u8]) -> Result<Self, GitHubError> {
        let mut raw: RawCredential<'_> =
            serde_json::from_slice(input).map_err(|_| GitHubError::InvalidCredential)?;
        if raw.credential_type != CREDENTIAL_TYPE
            || !safe_client_id(raw.client_id)
            || raw.app_id == 0
            || raw.installation_id == 0
            || raw.repositories.is_empty()
            || raw.repositories.len() > MAX_REPOSITORIES
            || raw.webhook_secret.len() < 32
            || raw.webhook_secret.len() > 256
            || raw.webhook_secret.chars().any(char::is_control)
            || raw.private_key_pkcs1_der_base64.is_empty()
            || raw.private_key_pkcs1_der_base64.len() > 48 * 1024
        {
            return Err(GitHubError::InvalidCredential);
        }
        raw.repositories.sort_by_key(|repository| repository.id);
        for (index, repository) in raw.repositories.iter().enumerate() {
            if repository.id == 0
                || !safe_path_segment(&repository.owner)
                || !safe_path_segment(&repository.name)
                || raw.repositories[..index].iter().any(|existing| {
                    existing.id == repository.id
                        || (existing.owner.eq_ignore_ascii_case(&repository.owner)
                            && existing.name.eq_ignore_ascii_case(&repository.name))
                })
            {
                return Err(GitHubError::InvalidCredential);
            }
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
        RsaKeyPair::from_der(&der).map_err(|_| GitHubError::InvalidCredential)?;
        Ok(Self {
            client_id: raw.client_id.to_owned(),
            app_id: raw.app_id,
            installation_id: raw.installation_id,
            repositories: raw.repositories,
            permissions: raw.permissions,
            webhook_secret: Zeroizing::new(raw.webhook_secret.as_bytes().to_vec()),
            private_key_pkcs1_der: der,
        })
    }

    pub(crate) fn action(
        &self,
        action: &FixedHttpAction,
        request: &ExecuteRequest,
    ) -> Result<GitHubAction, GitHubError> {
        if action.origin.host() != "api.github.com"
            || action.origin.port() != 443
            || action.auth.header_name.as_str() != "authorization"
            || action.auth.prefix.as_str() != "Bearer "
            || action.timeout_ms < MIN_TOTAL_TIMEOUT_MS
            || !request.extra_headers.is_empty()
        {
            return Err(GitHubError::ProfileMismatch);
        }
        if action.method == FixedMethod::Get
            && action.exact_path.as_str() == "/installation/repositories"
            && request.content_type.is_none()
            && request.body.is_empty()
        {
            return Ok(GitHubAction::ListRepositories);
        }
        if action.method != FixedMethod::Post
            || request.content_type.as_deref() != Some("application/json")
        {
            return Err(GitHubError::ProfileMismatch);
        }
        let path = action.exact_path.as_str();
        let tail = path
            .strip_prefix("/repos/")
            .and_then(|value| value.strip_suffix("/issues"))
            .ok_or(GitHubError::ProfileMismatch)?;
        let (owner, name) = tail.split_once('/').ok_or(GitHubError::ProfileMismatch)?;
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(GitHubError::ProfileMismatch);
        }
        let repository_index = self
            .repositories
            .iter()
            .position(|repository| {
                repository.owner.eq_ignore_ascii_case(owner)
                    && repository.name.eq_ignore_ascii_case(name)
            })
            .ok_or(GitHubError::ProfileMismatch)?;
        if self.permissions.issues != Some(IssuesPermission::Write) {
            return Err(GitHubError::ProfileMismatch);
        }
        let issue: CreateIssueBody =
            serde_json::from_slice(&request.body).map_err(|_| GitHubError::ProfileMismatch)?;
        if issue.title.is_empty()
            || issue.title.len() > 256
            || issue
                .body
                .as_ref()
                .is_some_and(|body| body.len() > 32 * 1024)
        {
            return Err(GitHubError::ProfileMismatch);
        }
        Ok(GitHubAction::CreateIssue { repository_index })
    }

    pub(crate) fn issue_body(request: &ExecuteRequest) -> Result<Vec<u8>, GitHubError> {
        let body: CreateIssueBody =
            serde_json::from_slice(&request.body).map_err(|_| GitHubError::ProfileMismatch)?;
        serde_json::to_vec(&body).map_err(|_| GitHubError::ProfileMismatch)
    }

    pub(crate) fn commitment(&self) -> String {
        let mut hasher = Sha256::new();
        bind(&mut hasher, self.client_id.as_bytes());
        bind(&mut hasher, self.app_id.to_string().as_bytes());
        bind(&mut hasher, self.installation_id.to_string().as_bytes());
        for repository in &self.repositories {
            bind(&mut hasher, repository.id.to_string().as_bytes());
            bind(&mut hasher, repository.owner.as_bytes());
            bind(&mut hasher, repository.name.as_bytes());
        }
        bind(&mut hasher, b"metadata=read");
        if self.permissions.issues.is_some() {
            bind(&mut hasher, b"issues=write");
        }
        bind(&mut hasher, &Sha256::digest(&self.webhook_secret));
        format!("binding-sha256={:x}", hasher.finalize())
    }

    pub(crate) fn private_key_bytes(&self) -> &[u8] {
        &self.private_key_pkcs1_der
    }

    pub(crate) fn verify_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), GitHubError> {
        let hex = signature
            .strip_prefix("sha256=")
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            .ok_or(GitHubError::WebhookSignature)?;
        let mut expected = [0u8; 32];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            expected[index] = (hex_nibble(pair[0]).ok_or(GitHubError::WebhookSignature)? << 4)
                | hex_nibble(pair[1]).ok_or(GitHubError::WebhookSignature)?;
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.webhook_secret);
        let actual = hmac::sign(&key, payload);
        if actual.as_ref().ct_eq(&expected).unwrap_u8() != 1 {
            return Err(GitHubError::WebhookSignature);
        }
        Ok(())
    }

    pub(crate) fn apply_repository_webhook(&mut self, payload: &[u8]) -> Result<(), GitHubError> {
        let delivery: InstallationRepositories =
            serde_json::from_slice(payload).map_err(|_| GitHubError::WebhookPayload)?;
        if delivery.installation.id != self.installation_id {
            return Err(GitHubError::WebhookPayload);
        }
        let (added, removed) = match delivery.action.as_str() {
            "added"
                if !delivery.repositories_added.is_empty()
                    && delivery.repositories_removed.is_empty() =>
            {
                (&delivery.repositories_added, false)
            }
            "removed"
                if delivery.repositories_added.is_empty()
                    && !delivery.repositories_removed.is_empty() =>
            {
                (&delivery.repositories_removed, true)
            }
            _ => return Err(GitHubError::WebhookPayload),
        };
        if added.len() > MAX_REPOSITORIES {
            return Err(GitHubError::WebhookPayload);
        }
        let mut seen = Vec::with_capacity(added.len());
        for repository in added {
            let (owner, name) = repository
                .full_name
                .split_once('/')
                .ok_or(GitHubError::WebhookPayload)?;
            if repository.id == 0
                || !safe_path_segment(owner)
                || !safe_path_segment(name)
                || name.contains('/')
                || seen.iter().any(|(id, full_name): &(u64, String)| {
                    *id == repository.id || full_name.eq_ignore_ascii_case(&repository.full_name)
                })
            {
                return Err(GitHubError::WebhookPayload);
            }
            seen.push((repository.id, repository.full_name.clone()));
            let position = self.repositories.iter().position(|current| {
                current.id == repository.id
                    && current.owner.eq_ignore_ascii_case(owner)
                    && current.name.eq_ignore_ascii_case(name)
            });
            if removed {
                let position = position.ok_or(GitHubError::WebhookPayload)?;
                self.repositories.remove(position);
            } else {
                if position.is_some()
                    || self.repositories.iter().any(|current| {
                        current.id == repository.id
                            || (current.owner.eq_ignore_ascii_case(owner)
                                && current.name.eq_ignore_ascii_case(name))
                    })
                {
                    return Err(GitHubError::WebhookPayload);
                }
                self.repositories.push(GitHubRepository {
                    id: repository.id,
                    owner: owner.to_owned(),
                    name: name.to_owned(),
                });
            }
        }
        if self.repositories.is_empty() || self.repositories.len() > MAX_REPOSITORIES {
            return Err(GitHubError::WebhookPayload);
        }
        self.repositories.sort_by_key(|repository| repository.id);
        Ok(())
    }

    pub(crate) fn to_secret_json(&self) -> Result<Zeroizing<Vec<u8>>, GitHubError> {
        let private_key = Zeroizing::new(BASE64.encode(&self.private_key_pkcs1_der));
        let webhook_secret = std::str::from_utf8(&self.webhook_secret)
            .map_err(|_| GitHubError::InvalidCredential)?;
        let raw = SerializableCredential {
            credential_type: CREDENTIAL_TYPE,
            client_id: &self.client_id,
            app_id: self.app_id,
            installation_id: self.installation_id,
            repositories: &self.repositories,
            permissions: self.permissions,
            webhook_secret,
            private_key_pkcs1_der_base64: &private_key,
        };
        serde_json::to_vec(&raw)
            .map(Zeroizing::new)
            .map_err(|_| GitHubError::InvalidCredential)
    }

    #[cfg(test)]
    pub(crate) fn test_profile() -> Self {
        Self {
            client_id: "test".to_owned(),
            app_id: 1,
            installation_id: 1,
            repositories: vec![GitHubRepository {
                id: 1,
                owner: "owner".to_owned(),
                name: "repo".to_owned(),
            }],
            permissions: GitHubPermissions {
                metadata: MetadataPermission::Read,
                issues: Some(IssuesPermission::Write),
            },
            webhook_secret: Zeroizing::new(vec![b's'; 32]),
            private_key_pkcs1_der: Zeroizing::new(Vec::new()),
        }
    }
}

#[derive(Serialize)]
struct SerializableCredential<'a> {
    credential_type: &'static str,
    client_id: &'a str,
    app_id: u64,
    installation_id: u64,
    repositories: &'a [GitHubRepository],
    permissions: GitHubPermissions,
    webhook_secret: &'a str,
    private_key_pkcs1_der_base64: &'a str,
}

#[derive(Deserialize)]
struct InstallationRepositories {
    action: String,
    installation: InstallationRef,
    repositories_added: Vec<WebhookRepository>,
    repositories_removed: Vec<WebhookRepository>,
}

#[derive(Deserialize)]
struct InstallationRef {
    id: u64,
}

#[derive(Deserialize)]
struct WebhookRepository {
    id: u64,
    full_name: String,
}

fn safe_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn safe_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn bind(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "github_profile_tests.rs"]
mod tests;
