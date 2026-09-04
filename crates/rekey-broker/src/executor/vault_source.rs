use std::fmt;

use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::*;

const PROFILE_MARKER: &str = "vault-kv-v2-source-v1";
const SOURCE_RESPONSE_MAX_BYTES: u32 = 64 * 1024;
const RESOLVED_VALUE_MAX_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultKvError {
    InvalidCredential,
    SourceTransport,
    SourceRejected,
    SourceResponse,
    SourceVersion,
    SourceUnavailable,
    Deadline,
}

impl VaultKvError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::InvalidCredential => "vault-source-invalid",
            Self::SourceTransport => "vault-source-transport",
            Self::SourceRejected => "vault-source-rejected",
            Self::SourceResponse => "vault-source-response",
            Self::SourceVersion => "vault-source-version",
            Self::SourceUnavailable => "vault-source-unavailable",
            Self::Deadline => "upstream-timeout",
        }
    }
}

pub(crate) struct VaultKvProfile {
    origin: HttpsOrigin,
    mount: String,
    path: String,
    key: String,
    version: u64,
    token: Zeroizing<Vec<u8>>,
}

pub(super) struct VaultPrepared {
    pub(super) profile: Result<VaultKvProfile, VaultKvError>,
    pub(super) needles: Vec<Zeroizing<Vec<u8>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile<'a> {
    credential_type: &'a str,
    origin: &'a str,
    mount: &'a str,
    path: &'a str,
    key: &'a str,
    version: u64,
    vault_token: &'a str,
}

#[derive(Deserialize)]
struct VaultEnvelope {
    data: VaultData,
}

#[derive(Deserialize)]
struct VaultData {
    data: SingleSecretField,
    metadata: VaultMetadata,
}

#[derive(Deserialize)]
struct VaultMetadata {
    version: u64,
    deletion_time: String,
    destroyed: bool,
}

struct SingleSecretField {
    key: String,
    value: Zeroizing<String>,
}

impl<'de> Deserialize<'de> for SingleSecretField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SingleFieldVisitor;

        impl<'de> Visitor<'de> for SingleFieldVisitor {
            type Value = SingleSecretField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly one string secret field")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (key, value) = map
                    .next_entry::<String, String>()?
                    .ok_or_else(|| serde::de::Error::custom("missing secret field"))?;
                let value = Zeroizing::new(value);
                if map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {
                    return Err(serde::de::Error::custom("multiple secret fields"));
                }
                Ok(SingleSecretField { key, value })
            }
        }

        deserializer.deserialize_map(SingleFieldVisitor)
    }
}

impl VaultKvProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, VaultKvError> {
        let raw: RawProfile<'_> =
            serde_json::from_slice(secret).map_err(|_| VaultKvError::InvalidCredential)?;
        if raw.credential_type != PROFILE_MARKER
            || !safe_segment(raw.mount)
            || !safe_path(raw.path)
            || raw.key.is_empty()
            || raw.key.len() > 128
            || !raw.key.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
            || raw.version == 0
            || raw.vault_token.is_empty()
            || raw.vault_token.len() > 4_096
            || !raw
                .vault_token
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(VaultKvError::InvalidCredential);
        }
        Ok(Self {
            origin: HttpsOrigin::parse(raw.origin).map_err(|_| VaultKvError::InvalidCredential)?,
            mount: raw.mount.to_owned(),
            path: raw.path.to_owned(),
            key: raw.key.to_owned(),
            version: raw.version,
            token: Zeroizing::new(raw.vault_token.as_bytes().to_vec()),
        })
    }

    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), VaultKvError> {
        Self::parse_profile(secret).map(|_| ())
    }

    pub(super) fn token(&self) -> &[u8] {
        &self.token
    }

    fn request(&self, timeout: Duration) -> UpstreamRequest {
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Get,
            path: format!(
                "/v1/{}/data/{}?version={}",
                self.mount, self.path, self.version
            ),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            auth_header: (
                "x-vault-token".to_owned(),
                Zeroizing::new(self.token.to_vec()),
            ),
            body: Zeroizing::new(Vec::new()),
            timeout,
            response_max_bytes: SOURCE_RESPONSE_MAX_BYTES,
        }
    }

    fn resolve(
        &self,
        response: &crate::upstream::UpstreamResponse,
    ) -> Result<Zeroizing<Vec<u8>>, VaultKvError> {
        if response.status != 200 {
            return Err(VaultKvError::SourceRejected);
        }
        let envelope: VaultEnvelope =
            serde_json::from_slice(&response.body).map_err(|_| VaultKvError::SourceResponse)?;
        if envelope.data.metadata.version != self.version {
            return Err(VaultKvError::SourceVersion);
        }
        if envelope.data.metadata.destroyed || !envelope.data.metadata.deletion_time.is_empty() {
            return Err(VaultKvError::SourceUnavailable);
        }
        if envelope.data.data.key != self.key {
            return Err(VaultKvError::SourceResponse);
        }
        let value = envelope.data.data.value;
        if value.is_empty()
            || value.len() > RESOLVED_VALUE_MAX_BYTES
            || !value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(VaultKvError::SourceResponse);
        }
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }
}

impl ActionExecutor {
    pub(super) async fn resolve_vault_source(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: VaultPrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<PreparedExecution, BrokerError> {
        let profile = match prepared.profile {
            Ok(profile) => profile,
            Err(error) => {
                started
                    .blocked_until(effect_deadline, error.reason())
                    .await?;
                return Err(BrokerError::Denied(error.reason()));
            }
        };
        let timeout = effect_deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            started.submit_blocked(VaultKvError::Deadline.reason());
            return Err(BrokerError::Upstream(VaultKvError::Deadline.reason()));
        }
        let upstream = profile.request(timeout);
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-vault-source-header")
                .await?;
            return Err(BrokerError::Denied("invalid-vault-source-header"));
        }
        try_begin_remote_effect(&self.lifecycle, started, effect_deadline).await?;
        effect_kind.store(EFFECT_READ_ONLY_HTTP, Ordering::SeqCst);
        let response = tokio::time::timeout_at(
            tokio::time::Instant::from_std(effect_deadline),
            self.transport.send(upstream),
        )
        .await;
        let response = match response {
            Err(_) => {
                let reason = VaultKvError::Deadline.reason();
                started.blocked_until(effect_deadline, reason).await?;
                return Err(BrokerError::Upstream(reason));
            }
            Ok(Err(crate::upstream::UpstreamError::ResponseTooLarge)) => {
                let reason = "vault-source-response-too-large";
                started.blocked_until(effect_deadline, reason).await?;
                return Err(BrokerError::Upstream(reason));
            }
            Ok(Err(error)) => {
                let reason = match error {
                    crate::upstream::UpstreamError::Timeout => "upstream-timeout",
                    crate::upstream::UpstreamError::Blocked(reason) => reason_static(reason),
                    crate::upstream::UpstreamError::Transport => {
                        VaultKvError::SourceTransport.reason()
                    }
                    crate::upstream::UpstreamError::ResponseTooLarge => unreachable!(),
                };
                started.blocked_until(effect_deadline, reason).await?;
                return Err(BrokerError::Upstream(reason));
            }
            Ok(Ok(response)) => response,
        };
        if contains_secret(&response.body, &prepared.needles)
            || headers_contain_secret(&response.headers, &prepared.needles)
        {
            started
                .blocked_until(effect_deadline, "vault-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let resolved = match profile.resolve(&response) {
            Ok(value) => value,
            Err(error) => {
                started
                    .blocked_until(effect_deadline, error.reason())
                    .await?;
                return Err(BrokerError::Upstream(error.reason()));
            }
        };
        let mut auth_value = Zeroizing::new(Vec::with_capacity(
            action.auth.prefix.as_str().len() + resolved.len(),
        ));
        auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
        auth_value.extend_from_slice(&resolved);
        let mut needles = prepared.needles;
        needles.extend(sealing_needles(&resolved, &auth_value));
        Ok(PreparedExecution::Opaque {
            upstream: build_upstream(action, request, auth_value),
            needles,
        })
    }
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_path(value: &str) -> bool {
    let mut count = 0;
    for segment in value.split('/') {
        if !safe_segment(segment) {
            return false;
        }
        count += 1;
        if count > 16 {
            return false;
        }
    }
    count > 0
}

#[cfg(test)]
#[path = "vault_source_tests.rs"]
mod tests;
