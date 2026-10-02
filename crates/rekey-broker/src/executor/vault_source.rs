use crate::upstream::{
    SourceEndpoint, optional_source_endpoint, send_source, source_hostname_valid,
};
use std::fmt;

use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::*;

const PROFILE_MARKER: &str = "vault-kv-v2-source-v1";
const APPROLE_MARKER: &str = "vault-approle-kv-v2-source-v1";
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretVersion {
    Exact(u64),
    Latest,
}

impl<'de> Deserialize<'de> for SecretVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct VersionVisitor;
        impl Visitor<'_> for VersionVisitor {
            type Value = SecretVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a positive integer or literal latest")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                if value == 0 {
                    return Err(E::custom("version must be positive"));
                }
                Ok(SecretVersion::Exact(value))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == "latest" {
                    Ok(SecretVersion::Latest)
                } else {
                    Err(E::custom("unsupported version selector"))
                }
            }
        }
        deserializer.deserialize_any(VersionVisitor)
    }
}

struct VaultResolved {
    value: Zeroizing<Vec<u8>>,
    actual_version: u64,
}

pub(crate) struct VaultKvProfile {
    origin: HttpsOrigin,
    source_endpoint: Option<SourceEndpoint>,
    mount: String,
    path: String,
    key: String,
    version: SecretVersion,
    token: Zeroizing<Vec<u8>>,
    approle: Option<AppRole>,
}

pub(super) struct VaultPrepared {
    pub(super) profile: Result<VaultKvProfile, VaultKvError>,
    pub(super) needles: Vec<Zeroizing<Vec<u8>>>,
    pub(super) credential_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile<'a> {
    #[serde(default, deserialize_with = "optional_source_endpoint")]
    source_endpoint: Option<SourceEndpoint>,
    credential_type: &'a str,
    origin: &'a str,
    mount: &'a str,
    path: &'a str,
    key: &'a str,
    version: SecretVersion,
    vault_token: &'a str,
}

struct AppRole {
    auth_mount: String,
    role_id: Zeroizing<String>,
    secret_id: Zeroizing<String>,
    secret_id_expires_at_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAppRoleProfile<'a> {
    #[serde(default, deserialize_with = "optional_source_endpoint")]
    source_endpoint: Option<SourceEndpoint>,
    credential_type: &'a str,
    origin: &'a str,
    auth_mount: &'a str,
    #[serde(deserialize_with = "secret_string")]
    role_id: Zeroizing<String>,
    #[serde(deserialize_with = "secret_string")]
    secret_id: Zeroizing<String>,
    secret_id_expires_at_ms: i64,
    mount: &'a str,
    path: &'a str,
    key: &'a str,
    version: SecretVersion,
}

fn secret_string<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    struct SecretVisitor;
    impl Visitor<'_> for SecretVisitor {
        type Value = Zeroizing<String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(value.to_owned()))
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(value))
        }
    }
    d.deserialize_string(SecretVisitor)
}

fn header_secret(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= 4_096 && value.iter().all(|b| matches!(b, 0x21..=0x7e))
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
        #[derive(Deserialize)]
        struct Marker<'a> {
            credential_type: &'a str,
        }
        let marker: Marker<'_> =
            serde_json::from_slice(secret).map_err(|_| VaultKvError::InvalidCredential)?;
        let (origin, endpoint, mount, path, key, version, token, approle) =
            match marker.credential_type {
                PROFILE_MARKER => {
                    let raw: RawProfile<'_> = serde_json::from_slice(secret)
                        .map_err(|_| VaultKvError::InvalidCredential)?;
                    if raw.credential_type != PROFILE_MARKER
                        || !header_secret(raw.vault_token.as_bytes())
                    {
                        return Err(VaultKvError::InvalidCredential);
                    }
                    (
                        raw.origin,
                        raw.source_endpoint,
                        raw.mount,
                        raw.path,
                        raw.key,
                        raw.version,
                        Zeroizing::new(raw.vault_token.as_bytes().to_vec()),
                        None,
                    )
                }
                APPROLE_MARKER => {
                    let raw: RawAppRoleProfile<'_> = serde_json::from_slice(secret)
                        .map_err(|_| VaultKvError::InvalidCredential)?;
                    if raw.credential_type != APPROLE_MARKER
                        || !safe_segment(raw.auth_mount)
                        || !header_secret(raw.role_id.as_bytes())
                        || !header_secret(raw.secret_id.as_bytes())
                        || raw.secret_id_expires_at_ms
                            <= crate::now_ts()
                                .map_err(|_| VaultKvError::InvalidCredential)?
                                .as_unix_ms()
                    {
                        return Err(VaultKvError::InvalidCredential);
                    }
                    (
                        raw.origin,
                        raw.source_endpoint,
                        raw.mount,
                        raw.path,
                        raw.key,
                        raw.version,
                        Zeroizing::new(Vec::new()),
                        Some(AppRole {
                            auth_mount: raw.auth_mount.to_owned(),
                            role_id: raw.role_id,
                            secret_id: raw.secret_id,
                            secret_id_expires_at_ms: raw.secret_id_expires_at_ms,
                        }),
                    )
                }
                _ => return Err(VaultKvError::InvalidCredential),
            };
        if !safe_segment(mount)
            || !safe_path(path)
            || key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
        {
            return Err(VaultKvError::InvalidCredential);
        }
        let origin = HttpsOrigin::parse(origin).map_err(|_| VaultKvError::InvalidCredential)?;
        if endpoint.is_some() && !source_hostname_valid(origin.host()) {
            return Err(VaultKvError::InvalidCredential);
        }
        Ok(Self {
            origin,
            source_endpoint: endpoint,
            mount: mount.to_owned(),
            path: path.to_owned(),
            key: key.to_owned(),
            version,
            token,
            approle,
        })
    }

    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), VaultKvError> {
        Self::parse_profile(secret).map(|_| ())
    }

    pub(super) fn token(&self) -> &[u8] {
        &self.token
    }

    pub(super) fn bootstrap_needles(&self, secret: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
        let mut needles = sealing_needles(secret, self.token());
        if let Some(role) = &self.approle {
            for value in [&role.role_id, &role.secret_id] {
                needles.extend(sealing_needles(value.as_bytes(), value.as_bytes()));
            }
        }
        needles
    }

    fn audit_reason(&self, actual_version: Option<u64>) -> String {
        let mut reference = Sha256::new();
        for field in [self.origin.as_str(), &self.mount, &self.path, &self.key] {
            reference.update(field.as_bytes());
            reference.update([0]);
        }
        let selector = match self.version {
            SecretVersion::Exact(version) => format!("exact:{version}"),
            SecretVersion::Latest => "latest".to_owned(),
        };
        let mut reason = format!("ref={:x};selector={selector}", reference.finalize());
        if let Some(version) = actual_version {
            reason.push_str(&format!(";actual={version}"));
        }
        reason
    }

    fn request(&self, timeout: Duration) -> UpstreamRequest {
        let mut path = format!("/v1/{}/data/{}", self.mount, self.path);
        if let SecretVersion::Exact(version) = self.version {
            path.push_str(&format!("?version={version}"));
        }
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Get,
            path,
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
    ) -> Result<VaultResolved, VaultKvError> {
        if response.status != 200 {
            return Err(VaultKvError::SourceRejected);
        }
        let envelope: VaultEnvelope =
            serde_json::from_slice(&response.body).map_err(|_| VaultKvError::SourceResponse)?;
        let actual_version = envelope.data.metadata.version;
        if actual_version == 0
            || matches!(self.version, SecretVersion::Exact(version) if actual_version != version)
        {
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
        Ok(VaultResolved {
            value: Zeroizing::new(value.as_bytes().to_vec()),
            actual_version,
        })
    }
}

impl ActionExecutor {
    async fn read_vault_source(
        &self,
        started: &mut StartedAuditGuard,
        profile: &VaultKvProfile,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
        credential_version: u64,
    ) -> Result<crate::upstream::UpstreamResponse, BrokerError> {
        // This async body runs on the source future's first poll, including
        // when an already-ready audit reply is observed after the deadline.
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
        let source_transport = super::vault_dynamic_run::AuditedSourceTransport::execution(
            self,
            started.context(),
            credential_version,
            None,
            false,
            None,
        );
        let response = tokio::time::timeout_at(
            tokio::time::Instant::from_std(effect_deadline),
            send_source(
                &source_transport,
                upstream,
                profile.source_endpoint.as_ref(),
                effect_deadline,
            ),
        )
        .await;
        if let Some(error) = source_transport.take_audit_error() {
            started.submit_blocked(
                if matches!(error, BrokerError::Upstream("upstream-timeout")) {
                    "upstream-timeout"
                } else {
                    "connector-audit-failed"
                },
            );
            return Err(error);
        }
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
        Ok(response)
    }

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
        if effect_deadline
            .saturating_duration_since(Instant::now())
            .is_zero()
        {
            started.submit_blocked(VaultKvError::Deadline.reason());
            return Err(BrokerError::Upstream(VaultKvError::Deadline.reason()));
        }
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::VAULT_SOURCE_READ_STARTED,
            "success",
            profile.audit_reason(None),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(effect_deadline, draft).await?;
        let response = self
            .read_vault_source(
                started,
                &profile,
                effect_deadline,
                effect_kind,
                prepared.credential_version,
            )
            .await?;
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
        if contains_secret(&resolved.value, &prepared.needles) {
            started
                .blocked_until(effect_deadline, "vault-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::VAULT_SOURCE_RESOLVED,
            "success",
            profile.audit_reason(Some(resolved.actual_version)),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(effect_deadline, draft).await?;
        let mut auth_value = Zeroizing::new(Vec::with_capacity(
            action.auth.prefix.as_str().len() + resolved.value.len(),
        ));
        auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
        auth_value.extend_from_slice(&resolved.value);
        let mut needles = prepared.needles;
        needles.extend(fixed_header_sealing_needles(
            &resolved.value,
            &auth_value,
            action.auth.prefix.as_str().as_bytes(),
        ));
        Ok(PreparedExecution::Opaque {
            upstream: build_upstream(action, request, auth_value).map_err(BrokerError::Denied)?,
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

// A structured decoder retains only exact auth.client_token strings. It also
// checks decoded JSON strings, so escaping cannot hide a reflected credential.
struct LoginProbe {
    tokens: Vec<Zeroizing<String>>,
    reflected: bool,
}
struct ProbeSeed<'a> {
    probe: &'a mut LoginProbe,
    needles: &'a [Zeroizing<Vec<u8>>],
    path: u8,
}
impl<'de> DeserializeSeed<'de> for ProbeSeed<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ProbeSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON response")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if self.path == 2
            && header_secret(value.as_bytes())
            && !contains_secret(value.as_bytes(), self.needles)
        {
            if !self.probe.tokens.iter().any(|t| **t == value) {
                self.probe.tokens.push(Zeroizing::new(value.to_owned()));
            }
        } else {
            self.probe.reflected |= contains_secret(value.as_bytes(), self.needles);
        }
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, mut value: String) -> Result<(), E> {
        let result = self.visit_str(&value);
        value.zeroize();
        result
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            self.probe.reflected |= contains_secret(key.as_bytes(), self.needles);
            let path = match (self.path, key.as_str()) {
                (0, "auth") => 1,
                (1, "client_token") => 2,
                _ => 3,
            };
            map.next_value_seed(ProbeSeed {
                probe: self.probe,
                needles: self.needles,
                path,
            })?;
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(ProbeSeed {
                probe: self.probe,
                needles: self.needles,
                path: 3,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
}
fn login_probe(body: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> LoginProbe {
    let mut probe = LoginProbe {
        tokens: vec![],
        reflected: false,
    };
    let mut d = serde_json::Deserializer::from_slice(body);
    let _ = ProbeSeed {
        probe: &mut probe,
        needles,
        path: 0,
    }
    .deserialize(&mut d);
    probe
}

fn decoded_reflection(body: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> bool {
    let mut probe = LoginProbe {
        tokens: vec![],
        reflected: false,
    };
    let mut d = serde_json::Deserializer::from_slice(body);
    let _ = ProbeSeed {
        probe: &mut probe,
        needles,
        path: 3,
    }
    .deserialize(&mut d);
    probe.reflected
}

#[derive(Deserialize)]
struct LoginEnvelope {
    auth: LoginAuth,
}
#[derive(Deserialize)]
struct LoginAuth {
    #[serde(deserialize_with = "secret_string")]
    client_token: Zeroizing<String>,
    token_type: String,
    lease_duration: u64,
}

fn login_expiry(
    response: &crate::upstream::UpstreamResponse,
    probe: &LoginProbe,
    login_start: Instant,
    deadline: Instant,
    needles: &[Zeroizing<Vec<u8>>],
) -> Result<Instant, BrokerError> {
    if response.status != 200 {
        return Err(BrokerError::Denied("vault-approle-login-rejected"));
    }
    if probe.reflected || headers_contain_secret(&response.headers, needles) {
        return Err(BrokerError::ResponseSecurityViolation);
    }
    let raw: LoginEnvelope = serde_json::from_slice(&response.body)
        .map_err(|_| BrokerError::Indeterminate("vault-approle-login-response"))?;
    if probe.tokens.len() != 1
        || !header_secret(raw.auth.client_token.as_bytes())
        || raw.auth.client_token.as_str() != probe.tokens[0].as_str()
        || raw.auth.token_type != "service"
        || raw.auth.lease_duration == 0
    {
        return Err(BrokerError::Indeterminate("vault-approle-login-response"));
    }
    let expiry = login_start
        .checked_add(Duration::from_secs(raw.auth.lease_duration))
        .ok_or(BrokerError::Indeterminate("vault-approle-login-ttl"))?;
    if expiry < deadline {
        return Err(BrokerError::Indeterminate("vault-approle-login-ttl"));
    }
    Ok(expiry)
}

impl VaultKvProfile {
    pub(super) fn is_approle(&self) -> bool {
        self.approle.is_some()
    }
    fn approle_request(
        &self,
        path: String,
        body: Zeroizing<Vec<u8>>,
        token: Option<&str>,
        timeout: Duration,
    ) -> UpstreamRequest {
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Post,
            path,
            headers: vec![("content-type".into(), "application/json".into())],
            auth_header: token
                .map(|t| {
                    (
                        "x-vault-token".into(),
                        Zeroizing::new(t.as_bytes().to_vec()),
                    )
                })
                .unwrap_or_else(|| {
                    (
                        "accept".into(),
                        Zeroizing::new(b"application/json".to_vec()),
                    )
                }),
            body,
            timeout,
            response_max_bytes: SOURCE_RESPONSE_MAX_BYTES,
        }
    }
}

// Login bypasses send_source's late-result conversion, solely to retain a
// complete bounded identity before converting the stage to a deadline error.
async fn approle_source_send<'a>(
    transport: &'a dyn UpstreamTransport,
    profile: &'a VaultKvProfile,
    request: UpstreamRequest,
    deadline: Instant,
) -> Result<crate::upstream::UpstreamResponse, crate::upstream::UpstreamError> {
    if Instant::now() >= deadline {
        return Err(crate::upstream::UpstreamError::Timeout);
    }
    tokio::time::timeout_at(deadline.into(), async {
        match profile.source_endpoint.as_ref() {
            Some(binding) => {
                transport
                    .send_vault_source(
                        request,
                        binding,
                        deadline,
                        Arc::new(std::sync::Mutex::new(
                            crate::upstream::SourceAttempt::default(),
                        )),
                    )
                    .await
            }
            None => transport.send(request).await,
        }
    })
    .await
    .unwrap_or(Err(crate::upstream::UpstreamError::Timeout))
}

fn fatal_authority_error(error: &BrokerError) -> bool {
    matches!(error, BrokerError::Authority(_)) && !error.retryable()
}

impl ActionExecutor {
    async fn approle_audit(
        &self,
        started: &StartedAuditGuard,
        version: u64,
        deadline: Instant,
        event: &'static str,
        outcome: &'static str,
        reason: String,
    ) -> Result<(), BrokerError> {
        let mut draft = connector_event(started.context(), event, outcome, reason);
        draft.credential_version = Some(version);
        self.terminals.commit_until(deadline, draft).await
    }
    async fn cleanup_approle(
        &self,
        started: &StartedAuditGuard,
        profile: &VaultKvProfile,
        tokens: &[Zeroizing<String>],
        needles: &[Zeroizing<Vec<u8>>],
        version: u64,
        deadline: Instant,
    ) -> Result<(), BrokerError> {
        // Audit failure cannot abandon known identities. Preserve the first
        // typed fault while still attempting every bounded exact revoke.
        let mut failure = self
            .approle_audit(
                started,
                version,
                deadline,
                "vault.approle.cleanup.started",
                "success",
                profile.audit_reason(None),
            )
            .await
            .err();
        let transport = super::vault_dynamic_run::AuditedSourceTransport::execution(
            self,
            started.context(),
            version,
            None,
            false,
            None,
        );
        for token in tokens {
            let request = profile.approle_request(
                "/v1/auth/token/revoke-self".into(),
                Zeroizing::new(vec![]),
                Some(token),
                deadline.saturating_duration_since(Instant::now()),
            );
            let response = approle_source_send(&transport, profile, request, deadline).await;
            let result = match response {
                Ok(response)
                    if Instant::now() < deadline
                        && matches!(response.status, 200 | 204)
                        && response.body.is_empty()
                        && !headers_contain_secret(&response.headers, needles) =>
                {
                    Ok(())
                }
                _ => Err(BrokerError::Indeterminate(
                    "vault-approle-cleanup-unconfirmed",
                )),
            };
            let result = transport.take_audit_error().map_or(result, Err);
            if failure.is_none()
                || (!failure.as_ref().is_some_and(fatal_authority_error)
                    && result.as_ref().is_err_and(fatal_authority_error))
            {
                failure = result.err();
            }
        }
        let confirmed = failure.is_none();
        let audit = self
            .approle_audit(
                started,
                version,
                deadline,
                if confirmed {
                    "vault.approle.cleanup.confirmed"
                } else {
                    "vault.approle.cleanup.unconfirmed"
                },
                if confirmed { "success" } else { "unknown" },
                profile.audit_reason(None),
            )
            .await;
        match (failure, audit) {
            (Some(error), _) if fatal_authority_error(&error) => Err(error),
            (_, Err(error)) if fatal_authority_error(&error) => Err(error),
            (Some(error), _) => Err(error),
            (None, result) => result,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_vault_approle(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: VaultPrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
        cleanup_owned: &AtomicBool,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let mut profile = prepared
            .profile
            .map_err(|e| BrokerError::Denied(e.reason()))?;
        let version = prepared.credential_version;
        let business_deadline = effect_deadline
            .checked_sub(super::vault_dynamic::CLEANUP_BUDGET)
            .ok_or(BrokerError::Upstream("upstream-timeout"))?;
        self.approle_audit(
            started,
            version,
            business_deadline,
            "vault.approle.login.started",
            "success",
            profile.audit_reason(None),
        )
        .await?;
        let role = profile.approle.as_ref().unwrap();
        // Own the pending login across cancellation before its first poll.
        cleanup_owned.store(true, Ordering::SeqCst);
        #[derive(serde::Serialize)]
        struct LoginBody<'a> {
            role_id: &'a str,
            secret_id: &'a str,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&LoginBody {
                role_id: &role.role_id,
                secret_id: &role.secret_id,
            })
            .map_err(|_| BrokerError::Denied("vault-source-invalid"))?,
        );
        let login = profile.approle_request(
            format!("/v1/auth/{}/login", role.auth_mount),
            body,
            None,
            business_deadline.saturating_duration_since(Instant::now()),
        );
        // This gate and login_start execute on the actual first send poll;
        // there is no audit await between expiry/admission and transport IO.
        let login_start = Instant::now();
        if login_start >= business_deadline {
            started
                .blocked_until(effect_deadline, "upstream-timeout")
                .await?;
            return Err(BrokerError::Upstream("upstream-timeout"));
        }
        if role.secret_id_expires_at_ms <= crate::now_ts()?.as_unix_ms() {
            started
                .blocked_until(effect_deadline, "vault-approle-secret-id-expired")
                .await?;
            return Err(BrokerError::Denied("vault-approle-secret-id-expired"));
        }
        if !self.lifecycle.try_begin_remote_effect() {
            started
                .blocked_until(effect_deadline, "remote-effect-admission-closed")
                .await?;
            return Err(BrokerError::Authority(AuthorityError::Draining));
        }
        started.mark_remote_effect_started();
        let transport = super::vault_dynamic_run::AuditedSourceTransport::execution(
            self,
            started.context(),
            version,
            None,
            true,
            Some(business_deadline),
        );
        let response = approle_source_send(&transport, &profile, login, business_deadline).await;
        let mut needles = prepared.needles;
        let probe = match &response {
            Ok(r) if r.body.len() <= SOURCE_RESPONSE_MAX_BYTES as usize => {
                login_probe(&r.body, &needles)
            }
            _ => LoginProbe {
                tokens: vec![],
                reflected: false,
            },
        };
        // Identity ownership precedes every result-audit await and late check.
        let expiry = match &response {
            Ok(r)
                if r.body.len() <= SOURCE_RESPONSE_MAX_BYTES as usize
                    && Instant::now() < business_deadline =>
            {
                login_expiry(r, &probe, login_start, effect_deadline, &needles)
            }
            Err(error) if !upstream_failure_is_indeterminate(error) => {
                Err(BrokerError::Upstream("vault-source-transport"))
            }
            _ => Err(BrokerError::Indeterminate("vault-approle-login-unknown")),
        };
        for token in &probe.tokens {
            needles.extend(sealing_needles(token.as_bytes(), token.as_bytes()));
        }
        transport.commit_acquisition(business_deadline).await;
        let expiry = transport.take_audit_error().map_or(expiry, Err);
        let result_audit = self
            .approle_audit(
                started,
                version,
                business_deadline,
                "vault.approle.login.result",
                if expiry.is_ok() { "success" } else { "unknown" },
                match &expiry {
                    Ok(expiry) => format!(
                        "{};ttl_seconds={};remaining_ms={}",
                        profile.audit_reason(None),
                        expiry.duration_since(login_start).as_secs(),
                        expiry.saturating_duration_since(Instant::now()).as_millis()
                    ),
                    Err(_) => profile.audit_reason(None),
                },
            )
            .await;
        let expiry = match (expiry, result_audit) {
            (Err(e), _) if fatal_authority_error(&e) => Err(e),
            (_, Err(e)) => Err(e),
            (Err(e), _) => Err(e),
            (Ok(e), Ok(())) => Ok(e),
        };
        let mut business_admitted = false;
        let mut business_definite_denial = false;
        let result=async {
            expiry?;
            if *self.lifecycle.subscribe_cancel().borrow() { return Err(BrokerError::Authority(AuthorityError::Draining)); }
            profile.token=Zeroizing::new(probe.tokens[0].as_bytes().to_vec());
            self.approle_audit(started,version,business_deadline,rekey_vault::model::event_type::VAULT_SOURCE_READ_STARTED,"success",profile.audit_reason(None)).await?;
            let read=profile.request(business_deadline.saturating_duration_since(Instant::now()));
            let read=async { if !self.lifecycle.try_begin_remote_effect() { return Err(crate::upstream::UpstreamError::Blocked("remote-effect-admission-closed")); } approle_source_send(&transport,&profile,read,business_deadline).await };
            let source=tokio::select! { biased; result=read=>result, _=wait_for_cancel(self.lifecycle.subscribe_cancel())=>return Err(BrokerError::Authority(AuthorityError::Draining)) };
            if let Some(error)=transport.take_audit_error() { return Err(error); }
            let source=source.map_err(|_|BrokerError::Indeterminate("vault-source-transport"))?;
            if decoded_reflection(&source.body,&needles) || contains_secret(&source.body,&needles) || headers_contain_secret(&source.headers,&needles) { return Err(BrokerError::ResponseSecurityViolation); }
            let resolved=profile.resolve(&source).map_err(|e|BrokerError::Indeterminate(e.reason()))?;
            if contains_secret(&resolved.value,&needles) { return Err(BrokerError::ResponseSecurityViolation); }
            self.approle_audit(started,version,business_deadline,rekey_vault::model::event_type::VAULT_SOURCE_RESOLVED,"success",profile.audit_reason(Some(resolved.actual_version))).await?;
            let mut auth=Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec()); auth.extend_from_slice(&resolved.value);
            needles.extend(fixed_header_sealing_needles(&resolved.value,&auth,action.auth.prefix.as_str().as_bytes()));
            let mut upstream=build_upstream(action,request,auth).map_err(BrokerError::Denied)?;
            upstream.timeout=business_deadline.saturating_duration_since(Instant::now());
            if upstream.timeout.is_zero() { return Err(BrokerError::Indeterminate("upstream-timeout")); }
            if !outbound_headers_are_valid(&upstream) { return Err(BrokerError::Denied("invalid-upstream-header")); }
            let send=async {
                if !self.lifecycle.try_begin_remote_effect() { return Err(BrokerError::Authority(AuthorityError::Draining)); }
                if Instant::now()>=business_deadline { return Err(BrokerError::Indeterminate("upstream-timeout")); }
                business_admitted=true;
                effect_kind.store(EFFECT_ORDINARY_HTTP,Ordering::SeqCst);
                let response = tokio::time::timeout_at(business_deadline.into(), self.transport.send(upstream))
                    .await.map_err(|_| BrokerError::Indeterminate("upstream-timeout"))?;
                match response {
                    Ok(response) => Ok(response),
                    Err(error) => {
                        let reason = match &error {
                            crate::upstream::UpstreamError::Blocked(reason) => reason_static(reason),
                            crate::upstream::UpstreamError::Timeout => "upstream-timeout",
                            crate::upstream::UpstreamError::ResponseTooLarge => "response-too-large",
                            crate::upstream::UpstreamError::Transport => "upstream-transport",
                        };
                        if !upstream_failure_is_indeterminate(&error) {
                            // Transport proved a refusal before sending business IO.
                            business_admitted = false;
                            business_definite_denial = true;
                            effect_kind.store(EFFECT_READ_ONLY_HTTP, Ordering::SeqCst);
                            Err(BrokerError::Upstream(reason))
                        } else if matches!(error, crate::upstream::UpstreamError::ResponseTooLarge) {
                            Err(BrokerError::Domain(DomainError::ResponseTooLarge))
                        } else { Err(BrokerError::Indeterminate(reason)) }
                    }
                }
            };
            let send_start=Instant::now();
            let response=tokio::select! { biased; result=send=>result?, _=wait_for_cancel(self.lifecycle.subscribe_cancel())=>return Err(BrokerError::Indeterminate("cancelled-after-remote-effect")) };
            if Instant::now()>=business_deadline { return Err(BrokerError::Indeterminate("upstream-timeout")); }
            if decoded_reflection(&response.body,&needles) || contains_secret(&response.body,&needles) || headers_contain_secret(&response.headers,&needles) { return Err(BrokerError::ResponseSecurityViolation); }
            Ok((response,send_start.elapsed().as_millis() as i64))
        }.await;
        if probe.tokens.is_empty() {
            if matches!(&response,Err(error) if !upstream_failure_is_indeterminate(error)) {
                let terminal = started
                    .blocked_until(effect_deadline, "vault-approle-login-not-sent")
                    .await;
                return match result {
                    Err(error) if fatal_authority_error(&error) => Err(error),
                    Err(error) => {
                        terminal?;
                        Err(error)
                    }
                    Ok(_) => unreachable!(),
                };
            }
            started.submit_indeterminate("vault-approle-login-unknown");
            return match result {
                Err(error)
                    if fatal_authority_error(&error)
                        || matches!(error, BrokerError::ResponseSecurityViolation) =>
                {
                    Err(error)
                }
                _ => Err(BrokerError::Indeterminate("vault-approle-login-unknown")),
            };
        }
        if let Err(error) = self
            .cleanup_approle(
                started,
                &profile,
                &probe.tokens,
                &needles,
                version,
                effect_deadline,
            )
            .await
        {
            started.submit_indeterminate("vault-approle-cleanup-unconfirmed");
            return match result {
                Err(original) if fatal_authority_error(&original) => Err(original),
                _ => Err(match error {
                    error if fatal_authority_error(&error) => error,
                    _ => BrokerError::Indeterminate("vault-approle-cleanup-unconfirmed"),
                }),
            };
        }
        match result {
            Ok((mut response, latency)) => {
                let headers = filter_response_headers(action, &response.headers);
                if !response_metadata_fits(response.status, &headers, response.body.len()) {
                    started
                        .indeterminate_until(effect_deadline, "response-metadata-too-large")
                        .await
                        .map_err(|error| {
                            if fatal_authority_error(&error) {
                                error
                            } else {
                                BrokerError::Indeterminate("vault-approle-terminal-unconfirmed")
                            }
                        })?;
                    return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
                }
                started
                    .finished_until(effect_deadline, version, response.status, latency)
                    .await
                    .map_err(|error| {
                        if fatal_authority_error(&error) {
                            error
                        } else {
                            BrokerError::Indeterminate("vault-approle-terminal-unconfirmed")
                        }
                    })?;
                Ok(ExecuteOutcome {
                    stream_status: None,
                    upstream_status: response.status,
                    headers,
                    body: std::mem::take(&mut *response.body),
                })
            }
            Err(error) => {
                let terminal = if business_admitted
                    || matches!(error, BrokerError::Indeterminate(_))
                    || (error.retryable() && !business_definite_denial)
                {
                    started
                        .indeterminate_until(effect_deadline, "vault-approle-execution-failed")
                        .await
                } else {
                    started
                        .blocked_until(effect_deadline, "vault-approle-execution-failed")
                        .await
                };
                if !fatal_authority_error(&error) {
                    terminal.map_err(|error| {
                        if fatal_authority_error(&error) {
                            error
                        } else {
                            BrokerError::Indeterminate("vault-approle-terminal-unconfirmed")
                        }
                    })?;
                }
                Err(if error.retryable() && !business_definite_denial {
                    BrokerError::Indeterminate("vault-approle-execution-unconfirmed")
                } else {
                    error
                })
            }
        }
    }
}
