//! One fixed commercial Key Vault Secret version, without discovery or refresh.
use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::{Deserialize, Deserializer};

use super::*;

const RESPONSE_LIMIT: u32 = 64 * 1024;
const VALUE_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AzureSourceError {
    InvalidCredential,
    Expired,
    Response,
    Version,
    Ineligible,
}
impl AzureSourceError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::InvalidCredential => "azure-source-invalid",
            Self::Expired => "azure-source-expired",
            Self::Response => "azure-source-response",
            Self::Version => "azure-source-version",
            Self::Ineligible => "azure-source-ineligible",
        }
    }
}

pub(crate) struct AzureSourceProfile {
    origin: HttpsOrigin,
    secret_name: String,
    secret_version: String,
    token: Zeroizing<String>,
    expires_at_ms: i64,
}
pub(super) struct AzurePrepared {
    pub(super) credential_version: u64,
    pub(super) profile: Result<AzureSourceProfile, AzureSourceError>,
    pub(super) needles: Vec<Zeroizing<Vec<u8>>>,
}
fn secret_string<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    credential_type: String,
    origin: String,
    secret_name: String,
    secret_version: String,
    #[serde(deserialize_with = "secret_string")]
    access_token: Zeroizing<String>,
    access_token_expires_at_ms: i64,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretAttributes {
    #[serde(default, deserialize_with = "present")]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    nbf: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    exp: Option<i64>,
    #[serde(default, rename = "created")]
    _created: Option<i64>,
    #[serde(default, rename = "updated")]
    _updated: Option<i64>,
    #[serde(default, rename = "recoveryLevel", deserialize_with = "present")]
    _recovery_level: Option<String>,
    #[serde(default, rename = "recoverableDays", deserialize_with = "present")]
    _recoverable_days: Option<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceResponse {
    #[serde(deserialize_with = "secret_string")]
    value: Zeroizing<String>,
    id: String,
    #[serde(default)]
    attributes: SecretAttributes,
    #[serde(default, rename = "contentType", deserialize_with = "present")]
    _content_type: Option<String>,
    #[serde(default, rename = "kid", deserialize_with = "present")]
    _kid: Option<String>,
    #[serde(default, rename = "managed", deserialize_with = "present")]
    _managed: Option<bool>,
    #[serde(default, rename = "previousVersion", deserialize_with = "present")]
    _previous_version: Option<String>,
    #[serde(default, rename = "tags", deserialize_with = "tags")]
    _tags: Option<std::collections::BTreeMap<String, String>>,
}
fn tags<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<std::collections::BTreeMap<String, String>>, D::Error> {
    struct Tags;
    impl<'de> serde::de::Visitor<'de> for Tags {
        type Value = std::collections::BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique string tags")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut tags = std::collections::BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if tags.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate tag"));
                }
            }
            Ok(tags)
        }
    }
    d.deserialize_map(Tags).map(Some)
}
struct ResolvedSecret {
    value: Zeroizing<Vec<u8>>,
    nbf_ms: Option<i64>,
    exp_ms: Option<i64>,
}
impl ResolvedSecret {
    fn eligible_at(&self, now_ms: i64) -> Result<(), AzureSourceError> {
        if self.nbf_ms.is_some_and(|n| n > now_ms) || self.exp_ms.is_some_and(|e| e <= now_ms) {
            return Err(AzureSourceError::Ineligible);
        }
        Ok(())
    }
    fn eligible_now(&self) -> Result<(), AzureSourceError> {
        self.eligible_at(
            crate::now_ts()
                .map_err(|_| AzureSourceError::Ineligible)?
                .as_unix_ms(),
        )
    }
}
impl AzureSourceProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, AzureSourceError> {
        Self::parse_at(
            secret,
            crate::now_ts()
                .map_err(|_| AzureSourceError::InvalidCredential)?
                .as_unix_ms(),
        )
    }
    fn parse_at(secret: &[u8], now_ms: i64) -> Result<Self, AzureSourceError> {
        let raw: RawProfile =
            serde_json::from_slice(secret).map_err(|_| AzureSourceError::InvalidCredential)?;
        let origin =
            HttpsOrigin::parse(&raw.origin).map_err(|_| AzureSourceError::InvalidCredential)?;
        let vault = raw
            .origin
            .strip_prefix("https://")
            .and_then(|s| s.strip_suffix(".vault.azure.net"))
            .ok_or(AzureSourceError::InvalidCredential)?;
        if raw.credential_type != "azure-key-vault-source-v1"
            || raw.origin != origin.as_str()
            || !(3..=24).contains(&vault.len())
            || vault.starts_with('-')
            || vault.ends_with('-')
            || vault.contains("--")
            || !vault
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !(1..=127).contains(&raw.secret_name.len())
            || !raw
                .secret_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || raw.secret_version.len() != 32
            || !raw
                .secret_version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
            || raw.access_token.is_empty()
            || raw.access_token.len() > 16 * 1024
            || reqwest::header::HeaderValue::from_bytes(raw.access_token.as_bytes()).is_err()
        {
            return Err(AzureSourceError::InvalidCredential);
        }
        let remaining = raw
            .access_token_expires_at_ms
            .checked_sub(now_ms)
            .ok_or(AzureSourceError::InvalidCredential)?;
        if !(1..=3_600_000).contains(&remaining) {
            return Err(AzureSourceError::InvalidCredential);
        }
        Ok(Self {
            origin,
            secret_name: raw.secret_name,
            secret_version: raw.secret_version,
            token: raw.access_token,
            expires_at_ms: raw.access_token_expires_at_ms,
        })
    }
    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), AzureSourceError> {
        Self::parse_profile(secret).map(|_| ())
    }
    pub(super) fn token(&self) -> &[u8] {
        self.token.as_bytes()
    }
    pub(super) fn bearer(&self) -> Zeroizing<Vec<u8>> {
        let mut value = Zeroizing::new(b"Bearer ".to_vec());
        value.extend_from_slice(self.token());
        value
    }
    fn reference(&self) -> String {
        format!(
            "{}/secrets/{}/{}",
            self.origin.as_str(),
            self.secret_name,
            self.secret_version
        )
    }
    pub(super) fn bootstrap_needles(&self, raw_profile: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
        let mut needles = sealing_needles(raw_profile, self.token());
        needles.extend(sealing_needles(self.token(), &self.bearer()));
        // HTTP edge OWS and Bearer scheme separation can expose this exact
        // standard representation; retain the imported outbound bytes.
        let token = self.token.trim_matches([' ', '\t']);
        if !token.is_empty() && token.as_bytes() != self.token() {
            let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
            bearer.extend_from_slice(token.as_bytes());
            needles.extend(sealing_needles(token.as_bytes(), &bearer));
        }
        needles
    }
    fn source_deadline(&self, action_deadline: Instant) -> Result<Instant, AzureSourceError> {
        let anchor = Instant::now();
        let now = crate::now_ts()
            .map_err(|_| AzureSourceError::Expired)?
            .as_unix_ms();
        let remaining = self
            .expires_at_ms
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or(AzureSourceError::Expired)?;
        Ok(action_deadline.min(anchor + Duration::from_millis(remaining as u64)))
    }
    fn expiry_valid(&self, deadline: Instant) -> bool {
        Instant::now() < deadline
            && crate::now_ts().is_ok_and(|now| now.as_unix_ms() < self.expires_at_ms)
    }
    fn request(&self, timeout: Duration) -> UpstreamRequest {
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Get,
            path: format!(
                "/secrets/{}/{}?api-version=2025-07-01",
                self.secret_name, self.secret_version
            ),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            auth_header: ("authorization".to_owned(), self.bearer()),
            body: Zeroizing::new(Vec::new()),
            timeout,
            response_max_bytes: RESPONSE_LIMIT,
        }
    }
    fn resolve_at(
        &self,
        response: &crate::upstream::UpstreamResponse,
        now_ms: i64,
    ) -> Result<ResolvedSecret, AzureSourceError> {
        if response.status != 200 || response.body.len() > RESPONSE_LIMIT as usize {
            return Err(AzureSourceError::Response);
        }
        let parsed: SourceResponse =
            serde_json::from_slice(&response.body).map_err(|_| AzureSourceError::Response)?;
        if !parsed.id.eq_ignore_ascii_case(&self.reference()) {
            return Err(AzureSourceError::Version);
        }
        if parsed.value.is_empty() || parsed.value.len() > VALUE_LIMIT {
            return Err(AzureSourceError::Response);
        }
        if parsed.attributes.enabled == Some(false) {
            return Err(AzureSourceError::Ineligible);
        }
        let millis = |seconds: i64| seconds.checked_mul(1000).ok_or(AzureSourceError::Response);
        let resolved = ResolvedSecret {
            value: Zeroizing::new(parsed.value.as_bytes().to_vec()),
            nbf_ms: parsed.attributes.nbf.map(millis).transpose()?,
            exp_ms: parsed.attributes.exp.map(millis).transpose()?,
        };
        resolved.eligible_at(now_ms)?;
        Ok(resolved)
    }
    fn resolve(
        &self,
        response: &crate::upstream::UpstreamResponse,
    ) -> Result<ResolvedSecret, AzureSourceError> {
        self.resolve_at(
            response,
            crate::now_ts()
                .map_err(|_| AzureSourceError::Ineligible)?
                .as_unix_ms(),
        )
    }
}

// Exact HTTP field edge OWS only; returned bytes borrow the wiped value/auth.
fn edge_ows(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

impl ActionExecutor {
    pub(super) async fn resolve_azure_source(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: AzurePrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<PreparedExecution, BrokerError> {
        let profile = match prepared.profile {
            Ok(p) => p,
            Err(e) => {
                started.blocked_until(effect_deadline, e.reason()).await?;
                return Err(BrokerError::Denied(e.reason()));
            }
        };
        let source_deadline = match profile.source_deadline(effect_deadline) {
            Ok(d) => d,
            Err(e) => {
                started.blocked_until(effect_deadline, e.reason()).await?;
                return Err(BrokerError::Upstream(e.reason()));
            }
        };
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::AZURE_SOURCE_READ_STARTED,
            "success",
            profile.reference(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        let upstream = profile.request(source_deadline.saturating_duration_since(Instant::now()));
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, AzureSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(AzureSourceError::Expired.reason()));
        }
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-azure-source-header")
                .await?;
            return Err(BrokerError::Denied("invalid-azure-source-header"));
        }
        try_begin_remote_effect(&self.lifecycle, started, source_deadline).await?;
        effect_kind.store(EFFECT_READ_ONLY_HTTP, Ordering::SeqCst);
        let response = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(source_deadline),
            self.transport.send(upstream),
        )
        .await
        {
            Ok(Ok(response)) => response,
            failure => {
                let reason = match failure {
                    Err(_) | Ok(Err(crate::upstream::UpstreamError::Timeout)) => "upstream-timeout",
                    Ok(Err(crate::upstream::UpstreamError::ResponseTooLarge)) => {
                        "azure-source-response-too-large"
                    }
                    Ok(Err(crate::upstream::UpstreamError::Blocked(r))) => reason_static(r),
                    _ => "azure-source-transport",
                };
                started.blocked_until(effect_deadline, reason).await?;
                return Err(BrokerError::Upstream(reason));
            }
        };
        // Inspect every body/header byte before status handling or JSON parsing.
        if contains_secret(&response.body, &prepared.needles)
            || headers_contain_secret(&response.headers, &prepared.needles)
        {
            started
                .blocked_until(effect_deadline, "azure-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let resolved = match profile.resolve(&response) {
            Ok(value) => value,
            Err(e) => {
                started.blocked_until(effect_deadline, e.reason()).await?;
                return Err(BrokerError::Upstream(e.reason()));
            }
        };
        // Parsing/container decoding can expose bytes absent from the raw response.
        if contains_secret(&resolved.value, &prepared.needles) {
            started
                .blocked_until(effect_deadline, "azure-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, AzureSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(AzureSourceError::Expired.reason()));
        }
        let mut auth = Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec());
        auth.extend_from_slice(&resolved.value);
        let mut needles = prepared.needles;
        needles.extend(sealing_needles(&resolved.value, &auth));
        let value = edge_ows(&resolved.value);
        if !value.is_empty()
            && (value != resolved.value.as_slice() || edge_ows(&auth) != auth.as_slice())
        {
            let mut normalized_auth =
                Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec());
            normalized_auth.extend_from_slice(value);
            needles.extend(sealing_needles(value, edge_ows(&normalized_auth)));
            needles.extend(sealing_needles(value, edge_ows(&auth)));
        }

        let upstream = build_upstream(action, request, auth).map_err(BrokerError::Denied)?;
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-upstream-header")
                .await?;
            return Err(BrokerError::Denied("invalid-upstream-header"));
        }
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::AZURE_SOURCE_RESOLVED,
            "success",
            profile.reference(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, AzureSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(AzureSourceError::Expired.reason()));
        }
        if let Err(e) = resolved.eligible_now() {
            started.blocked_until(effect_deadline, e.reason()).await?;
            return Err(BrokerError::Upstream(e.reason()));
        }
        // Imported source token lifetime does not shorten the fetched business
        // value lifetime. The caller retains the original Action deadline/gate.
        Ok(PreparedExecution::Opaque { upstream, needles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: &str = "https://fixture-vault.vault.azure.net";
    const VERSION: &str = "0123456789AbCdEfGhIjKlMnOpQrStUv";
    fn profile(expiry: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"credential_type":"azure-key-vault-source-v1","origin":ORIGIN,"secret_name":"fixture-key","secret_version":VERSION,"access_token":"fixture-source-bearer","access_token_expires_at_ms":expiry})).unwrap()
    }
    fn response(value: &str) -> crate::upstream::UpstreamResponse {
        crate::upstream::UpstreamResponse {status:200,headers:vec![].into(),body:Zeroizing::new(serde_json::to_vec(&serde_json::json!({"value":value,"id":format!("{ORIGIN}/secrets/fixture-key/{VERSION}")})).unwrap())}
    }
    fn json_response(value: serde_json::Value) -> crate::upstream::UpstreamResponse {
        crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(serde_json::to_vec(&value).unwrap()),
        }
    }
    #[test]
    fn fixed_profile_origin_name_opaque_version_and_expiry_boundaries() {
        for expiry in [1000, 999, 3_601_001, i64::MAX, i64::MIN] {
            assert!(AzureSourceProfile::parse_at(&profile(expiry), 1000).is_err());
        }
        for expiry in [1001, 3_601_000] {
            assert!(AzureSourceProfile::parse_at(&profile(expiry), 1000).is_ok());
        }
        let raw: serde_json::Value = serde_json::from_slice(&profile(2000)).unwrap();
        for origin in [
            "http://fixture-vault.vault.azure.net",
            "https://Fixture-vault.vault.azure.net",
            "https://fixture-vault.vault.azure.net:443",
            "https://user@fixture-vault.vault.azure.net",
            "https://fixture-vault.vault.azure.net/",
            "https://fixture-vault.vault.azure.net?x=y",
            "https://fixture-vault.vault.azure.net#x",
            "https://fixture-vault.vault.azure.net.evil.example",
            "https://fixture-vault.privatelink.vaultcore.azure.net",
            "https://fixture-vault.vault.usgovcloudapi.net",
            "https://-vault.vault.azure.net",
            "https://vault-.vault.azure.net",
            "https://va--ult.vault.azure.net",
            "https://ab.vault.azure.net",
            "https://abcdefghijklmnopqrstuvwxy.vault.azure.net",
        ] {
            let mut v = raw.clone();
            v["origin"] = origin.into();
            assert!(
                AzureSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err(),
                "{origin}"
            );
        }
        for (field, bad) in [
            ("secret_name", ""),
            ("secret_name", "x_y"),
            ("secret_name", "../x"),
            ("secret_name", "x%2fy"),
            ("secret_version", "latest"),
            ("secret_version", ""),
            ("secret_version", "0123456789AbCdEfGhIjKlMnOpQrStUvW/"),
            ("secret_version", "0123456789AbCdEfGhIjKlMnOpQrStUvW-"),
        ] {
            let mut v = raw.clone();
            v[field] = bad.into();
            assert!(AzureSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err());
        }
        for (field, len) in [
            ("secret_name", 128),
            ("secret_version", 33),
            ("access_token", 16385),
        ] {
            let mut v = raw.clone();
            v[field] = "x".repeat(len).into();
            assert!(AzureSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err());
        }
        for token in ["", "x\r\ny", "x\0y"] {
            let mut v = raw.clone();
            v["access_token"] = token.into();
            assert!(AzureSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err());
        }
        let mut max = raw;
        max["access_token"] = "x".repeat(16384).into();
        max["secret_name"] = "x".repeat(127).into();
        assert!(AzureSourceProfile::parse_at(&serde_json::to_vec(&max).unwrap(), 1000).is_ok());
        let p = AzureSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let request = p.request(Duration::from_secs(1));
        assert_eq!(
            request.path,
            format!("/secrets/fixture-key/{VERSION}?api-version=2025-07-01")
        );
        assert_eq!(request.port, 443);
        assert!(request.body.is_empty());
    }
    #[test]
    fn response_preserves_complete_value_and_compares_full_case_insensitive_id() {
        let p = AzureSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&response("  中文 full value  ").body).unwrap();
        raw["id"] = p.reference().to_ascii_uppercase().into();
        assert_eq!(
            &*p.resolve_at(&json_response(raw.clone()), 1000)
                .unwrap()
                .value,
            "  中文 full value  ".as_bytes()
        );
        for id in [
            p.reference() + "x",
            p.reference().replace("fixture-vault", "another-vault"),
            p.reference().replace("fixture-key", "another-key"),
            p.reference()
                .replace(VERSION, "0123456789AbCdEfGhIjKlMnOpQrStUw"),
            p.reference().replace("fixture-key", "fixture%2Dkey"),
        ] {
            raw["id"] = id.into();
            assert!(matches!(
                p.resolve_at(&json_response(raw.clone()), 1000),
                Err(AzureSourceError::Version)
            ));
        }
        for value in [String::new(), "x".repeat(8193)] {
            assert!(p.resolve_at(&response(&value), 1000).is_err());
        }
        assert_eq!(
            p.resolve_at(&response(&"x".repeat(8192)), 1000)
                .unwrap()
                .value
                .len(),
            8192
        );
        let mut too_large = response("value");
        too_large.body.resize(65537, b' ');
        assert!(p.resolve_at(&too_large, 1000).is_err());
        let mut exact = response("value");
        exact.body.resize(65536, b' ');
        assert!(p.resolve_at(&exact, 1000).is_ok());
    }
    #[test]
    fn known_metadata_defaults_signed_times_and_explicit_null_contract() {
        let p = AzureSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&response("value").body).unwrap();
        assert!(p.resolve_at(&json_response(raw.clone()), 1000).is_ok());
        for attrs in [
            serde_json::json!({}),
            serde_json::json!({"enabled":true,"nbf":-1,"exp":2,"created":null,"updated":null,"recoveryLevel":"Recoverable+Purgeable","recoverableDays":90}),
            serde_json::json!({"nbf":1}),
        ] {
            let mut v = raw.clone();
            v["attributes"] = attrs;
            assert!(p.resolve_at(&json_response(v), 1000).is_ok());
        }
        let mut full = raw.clone();
        full["attributes"] = serde_json::json!({"created":0,"updated":1,"recoveryLevel":"Recoverable","recoverableDays":0});
        full["contentType"] = "application/x-pkcs12".into();
        full["kid"] = "metadata-key-id".into();
        full["managed"] = true.into();
        full["previousVersion"] = "opaque previous version".into();
        full["tags"] = serde_json::json!({"label":"metadata"});
        assert!(p.resolve_at(&json_response(full), 1000).is_ok());
        for attrs in [
            serde_json::json!({"enabled":false}),
            serde_json::json!({"nbf":2}),
            serde_json::json!({"exp":1}),
            serde_json::json!({"exp":-1}),
        ] {
            let mut v = raw.clone();
            v["attributes"] = attrs;
            assert!(matches!(
                p.resolve_at(&json_response(v), 1000),
                Err(AzureSourceError::Ineligible)
            ));
        }
        for attrs in [
            serde_json::json!(null),
            serde_json::json!({"enabled":null}),
            serde_json::json!({"nbf":null}),
            serde_json::json!({"exp":null}),
            serde_json::json!({"nbf":1.0}),
            serde_json::json!({"exp":"2"}),
            serde_json::json!({"nbf":i64::MAX}),
            serde_json::json!({"exp":i64::MIN}),
            serde_json::json!({"created":"wrong"}),
            serde_json::json!({"updated":1.5}),
            serde_json::json!({"recoveryLevel":1}),
            serde_json::json!({"recoverableDays":2147483648i64}),
            serde_json::json!({"recoverableDays":1.5}),
            serde_json::json!({"extra":true}),
        ] {
            let mut v = raw.clone();
            v["attributes"] = attrs;
            assert!(matches!(
                p.resolve_at(&json_response(v), 1000),
                Err(AzureSourceError::Response)
            ));
        }
        for (field, value) in [
            ("contentType", serde_json::json!(false)),
            ("kid", serde_json::json!(42)),
            ("managed", serde_json::json!("true")),
            ("previousVersion", serde_json::json!(42)),
            ("tags", serde_json::json!({"x":false})),
            ("tags", serde_json::json!(null)),
        ] {
            let mut v = raw.clone();
            v[field] = value;
            assert!(p.resolve_at(&json_response(v), 1000).is_err());
        }
        for seconds in [i64::MAX / 1000, i64::MIN / 1000] {
            let mut v = raw.clone();
            v["attributes"] = serde_json::json!({"nbf":seconds});
            let result = p.resolve_at(&json_response(v), 1000);
            assert!(!matches!(result, Err(AzureSourceError::Response)));
        }
    }
    #[test]
    fn closed_profile_and_response_reject_duplicate_unknown_and_missing_fields() {
        let valid = profile(2000);
        for field in [",\"access_token\":\"second\"", ",\"unknown\":true"] {
            let mut v = valid[..valid.len() - 1].to_vec();
            v.extend_from_slice(field.as_bytes());
            v.push(b'}');
            assert!(AzureSourceProfile::parse_at(&v, 1000).is_err());
        }
        let p = AzureSourceProfile::parse_at(&valid, 1000).unwrap();
        let valid = response("value");
        for field in [
            ",\"value\":\"second\"",
            ",\"id\":\"second\"",
            ",\"unknown\":true",
            ",\"attributes\":{\"nbf\":1,\"nbf\":2}",
            ",\"attributes\":{\"created\":null,\"created\":1}",
            ",\"tags\":{\"x\":\"one\",\"x\":\"two\"}",
        ] {
            let mut v = valid.body[..valid.body.len() - 1].to_vec();
            v.extend_from_slice(field.as_bytes());
            v.push(b'}');
            let r = crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(v),
            };
            assert!(p.resolve_at(&r, 1000).is_err(), "{field}");
        }
        for body in [
            b"not-json".as_slice(),
            br#"{"value":"value"}"#,
            br#"{"id":"id"}"#,
            br#"{"value":null,"id":"id"}"#,
        ] {
            let r = crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(body.to_vec()),
            };
            assert!(p.resolve_at(&r, 1000).is_err());
        }
    }
    // Real Authority actor/SQLite/envelope tests do not need listeners. They
    // complement (not replace) the strict UDS/TLS integration contracts.
    struct ActorFixture {
        _dir: tempfile::TempDir,
        state: std::path::PathBuf,
        recovery: Zeroizing<String>,
        authority: AuthorityHandle,
        worker: std::thread::JoinHandle<()>,
        terminal_worker: tokio::task::JoinHandle<()>,
        executor: ActionExecutor,
        fake: Arc<crate::testing::FakeUpstreamTransport>,
        action: FixedHttpAction,
    }
    impl ActorFixture {
        async fn new(expires_in_ms: i64, timeout_ms: u32) -> Self {
            use rekey_domain::credential::{CredentialKind, CredentialLabel};
            use rekey_vault::secret::SecretInput;
            let dir = tempfile::tempdir().unwrap();
            let state = dir.path().join("state");
            let initialized = rekey_vault::bootstrap::init_vault(
                &state,
                &SecretInput::from_slice(b"actor-proof"),
                rekey_vault::crypto::kdf::Argon2Params {
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1,
                },
                rekey_domain::authorization::PolicyMode::Team,
            )
            .unwrap();
            rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
            let (authority, worker) = rekey_vault::authority::spawn_authority(
                rekey_vault::handle::AuthorityConfig::new(state.clone()),
            )
            .unwrap();
            authority.unlock(Self::proof()).await.unwrap();
            let now = crate::now_ts().unwrap().as_unix_ms();
            let credential = authority
                .credential_add(
                    CredentialLabel::new("azure-actor").unwrap(),
                    CredentialKind::AzureKeyVaultSource,
                    SecretInput::from_slice(&profile(now + expires_in_ms)),
                    Self::proof(),
                )
                .await
                .unwrap();
            let action: FixedHttpAction = serde_json::from_value(serde_json::json!({"id":rekey_domain::ids::ActionId::new_random(),"name":"actor-action","version":1,"enabled":true,"credential_id":credential.id,"origin":"https://api.example.com","method":"POST","target":{"kind":"fixed","path":"/business"},"auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":timeout_ms,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":1024,"allowed_headers":["content-type"]}})).unwrap();
            action.validate().unwrap();
            let (terminals, terminal_worker) =
                crate::audit::spawn_terminal_worker(authority.clone());
            let lifecycle = Arc::new(Lifecycle::new());
            lifecycle.enter_running().unwrap();
            let fake = Arc::new(crate::testing::FakeUpstreamTransport::new());
            let executor = ActionExecutor::new(
                authority.clone(),
                Arc::new(SessionRegistry::new()),
                fake.clone(),
                lifecycle,
                terminals,
                Arc::new(RwLock::new(None)),
            );
            Self {
                _dir: dir,
                state,
                recovery: initialized.recovery_key_display,
                authority,
                worker,
                terminal_worker,
                executor,
                fake,
                action,
            }
        }
        fn proof() -> rekey_vault::command::UnlockProof {
            rekey_vault::command::UnlockProof::Password(
                rekey_vault::secret::SecretInput::from_slice(b"actor-proof"),
            )
        }
        async fn run(&self) -> Result<ExecuteOutcome, BrokerError> {
            let ctx = ExecutionAuditContext {
                request_id: RequestId::new_random(),
                session_id: rekey_domain::ids::SessionId::new_random(),
                action: ActionVersionRef {
                    action_id: self.action.id,
                    version: 1,
                },
                credential_id: self.action.credential_id,
                authorization: None,
            };
            let request = ExecuteRequest {
                request_id: ctx.request_id,
                capability_token: "unused-admitted-test".into(),
                action: ctx.action,
                content_type: Some("application/json".into()),
                extra_headers: vec![],
                params: Default::default(),
                query: Default::default(),
                body: b"{}".to_vec(),
                approval_grants: vec![],
                local_approval_request_id: None,
            };
            let end = Instant::now() + Duration::from_millis(self.action.timeout_ms.into());
            let mut started = self
                .executor
                .terminals
                .commit_started(ctx, vec![], Some(end), None)
                .await?;
            self.executor
                .run_started(
                    &mut started,
                    &request,
                    &self.action,
                    end,
                    &AtomicU8::new(EFFECT_NOT_STARTED),
                    None,
                )
                .await
        }
        async fn finish(self) {
            self.executor
                .terminals
                .wait_idle(Duration::from_secs(2))
                .await
                .ok();
            let Self {
                _dir,
                authority,
                worker,
                terminal_worker,
                executor,
                ..
            } = self;
            drop(executor);
            authority.shutdown(Some(Self::proof())).await.unwrap();
            drop(authority);
            worker.join().unwrap();
            terminal_worker.await.unwrap();
            drop(_dir);
        }
        fn db(&self) -> rusqlite::Connection {
            rusqlite::Connection::open(self.state.join("vault.sqlite3")).unwrap()
        }
        fn resolved(value: &[u8]) -> crate::upstream::UpstreamResponse {
            response(std::str::from_utf8(value).unwrap())
        }
    }

    #[tokio::test]
    async fn actor_envelope_one_read_and_durable_audit_order_before_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean");
        let sent = f.fake.take_requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].host, "fixture-vault.vault.azure.net");
        assert_eq!(sent[0].method, "GET");
        assert_eq!(sent[0].port, 443);
        assert!(sent[0].body.is_empty());
        assert_eq!(sent[1].auth_value, b"Bearer 123456789");
        let db = f.db();
        let events:Vec<String>=db.prepare("SELECT event_type FROM audit_events WHERE request_id IS NOT NULL ORDER BY sequence").unwrap().query_map([],|r|r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(
            events,
            [
                "execution.started",
                "azure.source.read_started",
                "azure.source.resolved",
                "execution.finished"
            ]
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM vault_lease_journal", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        let payload: Vec<u8> = db
            .query_row(
                "SELECT encrypted_payload FROM credential_versions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !payload
                .windows(b"fixture-source-bearer".len())
                .any(|w| w == b"fixture-source-bearer")
        );
        drop(db);
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_read_and_resolved_audit_failures_fail_closed() {
        for (event, reads) in [
            ("execution.started", 0),
            ("azure.source.read_started", 0),
            ("azure.source.resolved", 1),
        ] {
            let f = ActorFixture::new(60_000, 30_000).await;
            f.db().execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
            f.fake
                .push_response(Ok(ActorFixture::resolved(b"123456789")));
            assert!(f.run().await.is_err());
            assert_eq!(f.fake.take_requests().len(), reads);
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn actor_invalid_resolved_header_and_bootstrap_reflection_never_reach_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        for value in [b"x\r\ny".as_slice(), b"x\0y"] {
            f.fake.push_response(Ok(ActorFixture::resolved(value)));
            let error = match f.run().await {
                Err(e) => e,
                Ok(_) => panic!("invalid header accepted"),
            };
            assert_eq!(error.code(), "REQUEST_DENIED");
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        for form in sealing_needles(b"fixture-source-bearer", b"Bearer fixture-source-bearer") {
            f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
                status: 403,
                headers: vec![(
                    "x-not-allowed".into(),
                    String::from_utf8(form.to_vec()).unwrap(),
                )]
                .into(),
                body: Zeroizing::new(b"provider error".to_vec()),
            }));
            let error = match f.run().await {
                Err(e) => e,
                Ok(_) => panic!("reflected bootstrap accepted"),
            };
            assert_eq!(error.code(), "RESPONSE_SECURITY_VIOLATION");
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_source_expiry_and_action_deadline_do_not_restart_at_response() {
        let f = ActorFixture::new(250, 30_000).await;
        f.fake.push_response_delayed(
            Ok(ActorFixture::resolved(b"123456789")),
            Duration::from_millis(400),
        );
        assert!(f.run().await.is_err());
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
        let f = ActorFixture::new(60_000, 50).await;
        f.fake.push_response_delayed(
            Ok(ActorFixture::resolved(b"123456789")),
            Duration::from_millis(100),
        );
        assert!(f.run().await.is_err());
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
        let f = ActorFixture::new(250, 30_000).await;
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        f.fake.push_response_delayed(
            Ok(crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean".to_vec()),
            }),
            Duration::from_millis(400),
        );
        assert_eq!(f.run().await.unwrap().body, b"clean");
        assert_eq!(f.fake.take_requests().len(), 2);
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_complete_utf8_value_is_not_trimmed_and_business_reflections_are_sealed() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let value = "  full 中文 key  ".as_bytes();
        f.fake.push_response(Ok(ActorFixture::resolved(value)));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean");
        let sent = f.fake.take_requests();
        assert_eq!(sent[1].auth_value, [b"Bearer ".as_slice(), value].concat());
        for source in [
            b"123456789".as_slice(),
            b"Bearer 123456789",
            b"fixture-source-bearer",
            b"Bearer fixture-source-bearer",
        ] {
            for encoded in sealing_needles(source, source) {
                for as_header in [true, false] {
                    f.fake
                        .push_response(Ok(ActorFixture::resolved(b"123456789")));
                    let mut reflected = crate::upstream::UpstreamResponse {
                        status: 500,
                        headers: vec![].into(),
                        body: Zeroizing::new(b"safe error".to_vec()),
                    };
                    if as_header {
                        reflected.headers = vec![(
                            "x-disallowed".into(),
                            String::from_utf8(encoded.to_vec()).unwrap(),
                        )]
                        .into();
                    } else {
                        reflected.body = encoded.clone();
                    }
                    f.fake.push_response(Ok(reflected));
                    let error = match f.run().await {
                        Err(e) => e,
                        Ok(_) => panic!("business reflection accepted"),
                    };
                    assert_eq!(error.code(), "RESPONSE_SECURITY_VIOLATION");
                    assert_eq!(f.fake.take_requests().len(), 2);
                }
            }
        }
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_resolved_audit_cannot_extend_source_expiry() {
        let mut f = ActorFixture::new(250, 30_000).await;
        let authority = f.authority.clone();
        let (tracker, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
            let authority = authority.clone();
            async move {
                if draft.event_type == rekey_vault::model::event_type::AZURE_SOURCE_RESOLVED {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                authority.append_audit(draft).await
            }
        });
        f.executor.terminals = tracker;
        let old = std::mem::replace(&mut f.terminal_worker, worker);
        old.await.unwrap();
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        assert!(f.run().await.is_err());
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_drain_during_source_read_stops_before_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let gate = f
            .fake
            .push_response_gated(Ok(ActorFixture::resolved(b"123456789")));
        {
            let run = f.run();
            tokio::pin!(run);
            tokio::select! {result=&mut run=>panic!("gated source completed early: {}",result.is_ok()),_=async{while f.fake.requests.lock().unwrap().is_empty(){tokio::time::sleep(Duration::from_millis(1)).await;}}=>{}}
            f.executor.lifecycle.enter_draining();
            gate.notify_one();
            let error = match run.await {
                Err(e) => e,
                Ok(_) => panic!("business ran during drain"),
            };
            assert_eq!(error.code(), "DRAINING");
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        f.finish().await;
    }
    fn real_header_values(values: &[(&str, &[u8])]) -> crate::upstream::ResponseHeaders {
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in values {
            headers.append(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                reqwest::header::HeaderValue::from_bytes(value).unwrap(),
            );
        }
        crate::upstream::ResponseHeaders::from_header_map(&headers)
    }
    async fn rotate_actor_bootstrap(f: &ActorFixture, token: &str) {
        let mut raw: serde_json::Value =
            serde_json::from_slice(&profile(crate::now_ts().unwrap().as_unix_ms() + 60_000))
                .unwrap();
        raw["access_token"] = token.into();
        f.authority
            .credential_rotate_typed_before(
                f.action.credential_id,
                rekey_domain::credential::CredentialKind::AzureKeyVaultSource,
                Some(1),
                rekey_vault::secret::SecretInput::from_slice(&serde_json::to_vec(&raw).unwrap()),
                ActorFixture::proof(),
                None,
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn actor_real_header_map_source_reflections_stop_before_business_for_utf8_and_nonutf8() {
        for token in ["fixture-source-bearer", "bootstrap-中文-fixture"] {
            let f = ActorFixture::new(60_000, 30_000).await;
            rotate_actor_bootstrap(&f, token).await;
            for secret in [token.as_bytes(), format!("Bearer {token}").as_bytes()] {
                for unsupported in [false, true] {
                    for status in [200, 403] {
                        let value = if unsupported {
                            [b"\xffprefix-".as_slice(), secret, b"-suffix\xfe"].concat()
                        } else {
                            secret.to_vec()
                        };
                        let mut response = ActorFixture::resolved(b"123456789");
                        response.status = status;
                        response.headers = real_header_values(&[("x-not-allowed", &value)]);
                        assert_eq!(response.headers.name_value_bytes().count(), 1);
                        assert_eq!(response.headers.is_empty(), unsupported);
                        f.fake.push_response(Ok(response));
                        let error = match f.run().await {
                            Err(e) => e,
                            Ok(_) => panic!("source reflection crossed into business"),
                        };
                        assert_eq!(error.code(), "RESPONSE_SECURITY_VIOLATION");
                        let requests = f.fake.take_requests();
                        assert_eq!(requests.len(), 1);
                        assert_eq!(requests[0].host, "fixture-vault.vault.azure.net");
                    }
                }
            }
            assert_eq!(
                f.db()
                    .query_row(
                        "SELECT count(*) FROM audit_events WHERE event_type='azure.source.resolved'",
                        [],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                0
            );
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn actor_real_header_map_business_reflections_are_sealed_before_allowlist_projection() {
        for token in ["fixture-source-bearer", "bootstrap-中文-fixture"] {
            let f = ActorFixture::new(60_000, 30_000).await;
            rotate_actor_bootstrap(&f, token).await;
            let value = "业务 UTF8 fixture value".as_bytes();
            for secret in [
                token.as_bytes(),
                format!("Bearer {token}").as_bytes(),
                value,
                [b"Bearer ".as_slice(), value].concat().as_slice(),
            ] {
                for unsupported in [false, true] {
                    for name in ["content-type", "x-not-allowed"] {
                        for status in [200, 500] {
                            let header = if unsupported {
                                [b"\xffprefix-".as_slice(), secret, b"-suffix\xfe"].concat()
                            } else {
                                secret.to_vec()
                            };
                            f.fake.push_response(Ok(ActorFixture::resolved(value)));
                            f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
                                status,
                                headers: real_header_values(&[(name, &header)]),
                                body: Zeroizing::new(b"clean body".to_vec()),
                            }));
                            let error = match f.run().await {
                                Err(e) => e,
                                Ok(_) => panic!("business header reflection escaped sealing"),
                            };
                            assert_eq!(error.code(), "RESPONSE_SECURITY_VIOLATION");
                            assert_eq!(f.fake.take_requests().len(), 2);
                        }
                    }
                }
            }
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn actor_clean_nonutf8_headers_are_sealed_then_filtered_without_transport_failure() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let unsupported = b"\xffclean nonsecret header\xfe";
        let mut source = ActorFixture::resolved(b"123456789");
        source.headers = real_header_values(&[("content-type", unsupported)]);
        f.fake.push_response(Ok(source));
        let visible = "text/plain; fixture=中文";
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: real_header_values(&[
                ("content-type", unsupported),
                ("content-type", visible.as_bytes()),
            ]),
            body: Zeroizing::new(b"clean body".to_vec()),
        }));
        let outcome = f.run().await.unwrap();
        assert_eq!(outcome.body, b"clean body");
        assert_eq!(
            outcome.headers,
            vec![("content-type".to_owned(), visible.to_owned())]
        );
        assert_eq!(f.fake.take_requests().len(), 2);
        f.finish().await;
    }
    struct WitnessTransport {
        fake: Arc<crate::testing::FakeUpstreamTransport>,
        db: std::path::PathBuf,
    }
    impl crate::upstream::UpstreamTransport for WitnessTransport {
        fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
            Box::pin(async move {
                let db = rusqlite::Connection::open(&self.db).unwrap();
                let event = if request.host == "fixture-vault.vault.azure.net" {
                    "azure.source.read_started"
                } else {
                    "azure.source.resolved"
                };
                assert_eq!(
                    db.query_row(
                        "SELECT count(*) FROM audit_events WHERE event_type=?1",
                        [event],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                    1
                );
                assert_eq!(
                    db.query_row(
                        "SELECT count(*) FROM audit_events WHERE event_type='execution.started'",
                        [],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                    1
                );
                drop(db);
                self.fake.send(request).await
            })
        }
    }
    #[tokio::test]
    async fn actor_durable_audits_are_visible_at_both_real_send_boundaries() {
        let mut f = ActorFixture::new(60_000, 30_000).await;
        f.executor.transport = Arc::new(WitnessTransport {
            fake: f.fake.clone(),
            db: f.state.join("vault.sqlite3"),
        });
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean");
        assert_eq!(f.fake.take_requests().len(), 2);
        f.finish().await;
    }
    struct AuthorizationReflection {
        fake: Arc<crate::testing::FakeUpstreamTransport>,
        status: u16,
        location: u8,
    }
    impl crate::upstream::UpstreamTransport for AuthorizationReflection {
        fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
            Box::pin(async move {
                assert_eq!(request.host, "fixture-vault.vault.azure.net");
                let encoded = sealing_needles(&request.auth_header.1, &request.auth_header.1);
                let index = usize::from(self.location / 3).min(encoded.len() - 1);
                let bytes = &encoded[index];
                let mut r = ActorFixture::resolved(b"123456789");
                r.status = self.status;
                match self.location % 3 {
                    0 => r.body = bytes.clone(),
                    1 => r.headers = real_header_values(&[("x-provider-request-id", bytes)]),
                    _ => {
                        r.headers = real_header_values(&[(
                            "x-provider-request-id",
                            &[b"\xff".as_slice(), bytes, b"\xfe"].concat(),
                        )])
                    }
                }
                self.fake.push_response(Ok(r));
                self.fake.send(request).await
            })
        }
    }
    #[tokio::test]
    async fn actor_complete_authorization_is_sealed_in_full_body_and_real_header_bytes() {
        let mut f = ActorFixture::new(60_000, 30_000).await;
        for status in [200, 403] {
            for location in 0..18 {
                f.executor.transport = Arc::new(AuthorizationReflection {
                    fake: f.fake.clone(),
                    status,
                    location,
                });
                assert!(matches!(
                    f.run().await,
                    Err(BrokerError::ResponseSecurityViolation)
                ));
                assert_eq!(f.fake.take_requests().len(), 1);
            }
        }
        f.finish().await;
    }

    #[tokio::test]
    async fn actor_exact_raw_profile_token_bearer_and_json_escaped_reflections_are_sealed() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let raw = profile(crate::now_ts().unwrap().as_unix_ms() + 60_000);
        f.authority
            .credential_rotate_typed_before(
                f.action.credential_id,
                rekey_domain::credential::CredentialKind::AzureKeyVaultSource,
                Some(1),
                rekey_vault::secret::SecretInput::from_slice(&raw),
                ActorFixture::proof(),
                None,
            )
            .await
            .unwrap();
        for secret in [
            raw.as_slice(),
            b"fixture-source-bearer",
            b"Bearer fixture-source-bearer",
        ] {
            for bytes in sealing_needles(secret, secret) {
                for business in [false, true] {
                    for location in 0..3 {
                        if business {
                            f.fake
                                .push_response(Ok(ActorFixture::resolved(b"123456789")));
                        }
                        let mut r = ActorFixture::resolved(b"123456789");
                        r.status = 403;
                        match location {
                            0 => r.body = bytes.clone(),
                            1 => {
                                r.headers = real_header_values(&[("x-provider-request-id", &bytes)])
                            }
                            _ => {
                                r.headers = real_header_values(&[(
                                    "x-provider-request-id",
                                    &[b"\xff".as_slice(), &bytes, b"\xfe"].concat(),
                                )])
                            }
                        }
                        f.fake.push_response(Ok(r));
                        assert!(matches!(
                            f.run().await,
                            Err(BrokerError::ResponseSecurityViolation)
                        ));
                        assert_eq!(f.fake.take_requests().len(), if business { 2 } else { 1 });
                    }
                }
            }
        }
        let reasons: String = f
            .db()
            .prepare("SELECT reason_code FROM audit_events")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!reasons.contains("fixture-source-bearer"));
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_single_source_errors_and_ineligible_or_malformed_values_have_no_business_or_raw_provider_audit()
     {
        let f = ActorFixture::new(60_000, 30_000).await;
        for status in [401, 403, 404, 429, 500] {
            let mut r = ActorFixture::resolved(b"123456789");
            r.status = status;
            r.body = Zeroizing::new(b"synthetic-provider-message-request-id".to_vec());
            r.headers = real_header_values(&[(
                "x-ms-request-id",
                b"synthetic-provider-message-request-id",
            )]);
            f.fake.push_response(Ok(r));
            assert!(f.run().await.is_err());
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        for attrs in [
            serde_json::json!({"enabled":false}),
            serde_json::json!({"nbf":i64::MAX/1000}),
            serde_json::json!({"exp":-1}),
            serde_json::json!({"enabled":null}),
        ] {
            let mut raw: serde_json::Value =
                serde_json::from_slice(&ActorFixture::resolved(b"123456789").body).unwrap();
            raw["attributes"] = attrs;
            f.fake.push_response(Ok(json_response(raw)));
            assert!(f.run().await.is_err());
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        for error in [
            crate::upstream::UpstreamError::Transport,
            crate::upstream::UpstreamError::Timeout,
            crate::upstream::UpstreamError::ResponseTooLarge,
            crate::upstream::UpstreamError::Blocked("redirect"),
            crate::upstream::UpstreamError::Blocked("private-address"),
        ] {
            f.fake.push_response(Err(error));
            assert!(f.run().await.is_err());
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        let reasons: String = f
            .db()
            .prepare("SELECT reason_code FROM audit_events")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!reasons.contains("synthetic-provider-message-request-id"));
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_secret_expiry_is_rechecked_after_resolved_audit_before_business() {
        let mut f = ActorFixture::new(60_000, 30_000).await;
        let authority = f.authority.clone();
        let (tracker, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
            let authority = authority.clone();
            async move {
                if draft.event_type == rekey_vault::model::event_type::AZURE_SOURCE_RESOLVED {
                    tokio::time::sleep(Duration::from_millis(2200)).await;
                }
                authority.append_audit(draft).await
            }
        });
        f.executor.terminals = tracker;
        f.terminal_worker.await.unwrap();
        f.terminal_worker = worker;
        let now = crate::now_ts().unwrap().as_unix_ms();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&ActorFixture::resolved(b"123456789").body).unwrap();
        raw["attributes"] = serde_json::json!({"exp":(now+2000)/1000});
        f.fake.push_response(Ok(json_response(raw)));
        assert!(matches!(
            f.run().await,
            Err(BrokerError::Upstream("azure-source-ineligible"))
        ));
        assert_eq!(f.fake.take_requests().len(), 1);
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='azure.source.resolved'",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            1
        );
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_read_started_audit_cannot_outlive_bootstrap_before_source_send() {
        let mut f = ActorFixture::new(250, 30_000).await;
        let authority = f.authority.clone();
        let (tracker, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
            let authority = authority.clone();
            async move {
                if draft.event_type == rekey_vault::model::event_type::AZURE_SOURCE_READ_STARTED {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                authority.append_audit(draft).await
            }
        });
        f.executor.terminals = tracker;
        f.terminal_worker.await.unwrap();
        f.terminal_worker = worker;
        assert!(f.run().await.is_err());
        assert_eq!(f.fake.take_requests().len(), 0);
        f.finish().await;
    }
    struct BudgetTransport(Arc<crate::testing::FakeUpstreamTransport>);
    impl crate::upstream::UpstreamTransport for BudgetTransport {
        fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
            Box::pin(async move {
                let timeout = request.timeout;
                if request.host == "api.example.com" {
                    assert!(timeout < Duration::from_millis(300));
                }
                tokio::time::timeout(timeout, self.0.send(request))
                    .await
                    .unwrap_or(Err(crate::upstream::UpstreamError::Timeout))
            })
        }
    }
    #[tokio::test]
    async fn actor_source_and_business_share_the_original_absolute_budget() {
        let mut f = ActorFixture::new(60_000, 400).await;
        f.executor.transport = Arc::new(BudgetTransport(f.fake.clone()));
        f.fake.push_response_delayed(
            Ok(ActorFixture::resolved(b"123456789")),
            Duration::from_millis(150),
        );
        f.fake.push_response_delayed(
            Ok(crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean".to_vec()),
            }),
            Duration::from_millis(300),
        );
        let start = Instant::now();
        assert!(f.run().await.is_err());
        assert!(start.elapsed() < Duration::from_millis(600));
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), 2);
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='execution.indeterminate'",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            1
        );
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_dek_vrk_and_backup_restore_preserve_actual_source_execution() {
        let f = ActorFixture::new(60_000, 30_000).await;
        assert_eq!(
            f.authority
                .rotate_dek_before(ActorFixture::proof(), None)
                .await
                .unwrap(),
            1
        );
        f.authority
            .lock_for_restart("azure-rotation-test")
            .await
            .unwrap();
        let rotated = f
            .authority
            .rotate_vrk_before(
                rekey_vault::secret::SecretInput::from_slice(b"actor-proof"),
                rekey_vault::secret::SecretInput::from_slice(f.recovery.as_bytes()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(rotated.rotated_versions, 1);
        f.authority.unlock(ActorFixture::proof()).await.unwrap();
        let backup = f.state.parent().unwrap().join("azure.rkbackup");
        let receipt = f
            .authority
            .backup(backup.clone(), ActorFixture::proof())
            .await
            .unwrap();
        assert_eq!(receipt.format_version, rekey_vault::model::FORMAT_VERSION);
        let bytes = std::fs::read(&backup).unwrap();
        assert!(
            !bytes
                .windows(b"fixture-source-bearer".len())
                .any(|w| w == b"fixture-source-bearer")
        );
        let restored_dir = tempfile::tempdir().unwrap();
        let restored = restored_dir.path().join("restored");
        rekey_vault::bootstrap::restore_vault(
            &backup,
            &restored,
            rekey_vault::bootstrap::RestoreProof::Password(
                rekey_vault::secret::SecretInput::from_slice(b"actor-proof"),
            ),
            &receipt.sha256_hex,
        )
        .unwrap();
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean");
        assert_eq!(f.fake.take_requests().len(), 2);
        let action = f.action.clone();
        f.finish().await;
        let (authority, worker) = rekey_vault::authority::spawn_authority(
            rekey_vault::handle::AuthorityConfig::new(restored.clone()),
        )
        .unwrap();
        authority.unlock(ActorFixture::proof()).await.unwrap();
        let (terminals, terminal_worker) = crate::audit::spawn_terminal_worker(authority.clone());
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let fake = Arc::new(crate::testing::FakeUpstreamTransport::new());
        let executor = ActionExecutor::new(
            authority.clone(),
            Arc::new(SessionRegistry::new()),
            fake.clone(),
            lifecycle,
            terminals,
            Arc::new(RwLock::new(None)),
        );
        let restored_fixture = ActorFixture {
            _dir: restored_dir,
            state: restored,
            recovery: Zeroizing::new(String::new()),
            authority,
            worker,
            terminal_worker,
            executor,
            fake,
            action,
        };
        restored_fixture
            .fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        restored_fixture
            .fake
            .push_response(Ok(crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean".to_vec()),
            }));
        assert_eq!(restored_fixture.run().await.unwrap().body, b"clean");
        assert_eq!(restored_fixture.fake.take_requests().len(), 2);
        restored_fixture.finish().await;
    }

    #[tokio::test]
    async fn actor_http_standard_token_representations_are_sealed_in_source_and_business() {
        let mut evidence = Vec::new();
        for location in ["source-body", "source-header", "business-header"] {
            let f = ActorFixture::new(60_000, 30_000).await;
            rotate_actor_bootstrap(&f, "  edge-source-token  ").await;
            let mut source = ActorFixture::resolved(if location == "source-body" {
                b"edge-source-token"
            } else {
                b"123456789"
            });
            if location == "source-header" {
                source.headers = real_header_values(&[("x-reflection", b"edge-source-token")]);
            }
            f.fake.push_response(Ok(source));
            f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
                status: 200,
                headers: if location == "business-header" {
                    real_header_values(&[("x-reflection", b"edge-source-token")])
                } else {
                    vec![].into()
                },
                body: Zeroizing::new(b"clean body".to_vec()),
            }));
            let result = f.run().await;
            let requests = f.fake.take_requests();
            let code = match result {
                Ok(_) => "SUCCESS",
                Err(ref e) => e.code(),
            };
            eprintln!(
                "AZURE OWS probe location={location} outcome={code} source_requests={} business_requests={}",
                requests
                    .iter()
                    .filter(|r| r.host == "fixture-vault.vault.azure.net")
                    .count(),
                requests
                    .iter()
                    .filter(|r| r.host == "api.example.com")
                    .count()
            );
            assert_eq!(requests[0].auth_value, b"Bearer   edge-source-token  ");
            evidence.push((location, code.to_owned(), requests.len()));
            f.finish().await;
        }
        assert!(
            evidence
                .iter()
                .all(|(_, code, _)| code == "RESPONSE_SECURITY_VIOLATION"),
            "unsealed standard representation: {evidence:?}"
        );
    }
    #[tokio::test]
    async fn actor_standard_token_headers_and_encodings_are_sealed_with_independent_clean_bodies() {
        for token in ["  edge-source-token  ", " \t edge-source-token \t "] {
            let f = ActorFixture::new(60_000, 30_000).await;
            rotate_actor_bootstrap(&f, token).await;
            for bytes in sealing_needles(b"edge-source-token", b"Bearer edge-source-token") {
                for business in [false, true] {
                    for unsupported in [false, true] {
                        if business {
                            f.fake
                                .push_response(Ok(ActorFixture::resolved(b"123456789")));
                        }
                        let header = if unsupported {
                            [b"\xff".as_slice(), &bytes, b"\xfe"].concat()
                        } else {
                            bytes.to_vec()
                        };
                        let mut reflected = if business {
                            crate::upstream::UpstreamResponse {
                                status: 200,
                                headers: vec![].into(),
                                body: Zeroizing::new(b"clean business body".to_vec()),
                            }
                        } else {
                            ActorFixture::resolved(b"123456789")
                        };
                        reflected.headers = real_header_values(&[("x-reflection", &header)]);
                        f.fake.push_response(Ok(reflected));
                        assert!(matches!(
                            f.run().await,
                            Err(BrokerError::ResponseSecurityViolation)
                        ));
                        let requests = f.fake.take_requests();
                        assert_eq!(requests.len(), if business { 2 } else { 1 });
                        assert_eq!(requests[0].auth_value, format!("Bearer {token}").as_bytes());
                    }
                }
            }
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn actor_legal_edge_ows_preserves_exact_imported_authorization_when_unreflected() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let token = " \t edge-source-token \t ";
        rotate_actor_bootstrap(&f, token).await;
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean business body".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean business body");
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].auth_value, format!("Bearer {token}").as_bytes());
        assert_eq!(requests[1].auth_value, b"Bearer 123456789");
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_complete_value_http_standard_representations_are_sealed_before_business_response_projection()
     {
        let mut evidence = Vec::new();
        for location in ["body", "utf8-header", "nonutf8-header"] {
            let f = ActorFixture::new(60_000, 30_000).await;
            f.fake
                .push_response(Ok(ActorFixture::resolved(b"  edge-business-value  ")));
            let mut reflected = crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean business body".to_vec()),
            };
            match location {
                "body" => reflected.body = Zeroizing::new(b"edge-business-value".to_vec()),
                "utf8-header" => {
                    reflected.headers =
                        real_header_values(&[("x-reflection", b"edge-business-value")])
                }
                _ => {
                    reflected.headers =
                        real_header_values(&[("x-reflection", b"\xffedge-business-value\xfe")])
                }
            }
            f.fake.push_response(Ok(reflected));
            let result = f.run().await;
            let code = match result {
                Ok(_) => "SUCCESS",
                Err(ref e) => e.code(),
            };
            let requests = f.fake.take_requests();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[1].auth_value, b"Bearer   edge-business-value  ");
            eprintln!(
                "RESOLVED VALUE OWS probe location={location} outcome={code} source_requests=1 business_requests=1 raw_authorization_exact=true"
            );
            evidence.push((location, code.to_owned()));
            f.finish().await;
        }
        assert!(
            evidence
                .iter()
                .all(|(_, code)| code == "RESPONSE_SECURITY_VIOLATION"),
            "unsealed resolved value: {evidence:?}"
        );
    }
    #[tokio::test]
    async fn actor_complete_value_standard_auth_encodings_are_sealed_and_unreflected_bytes_stay_exact()
     {
        let f = ActorFixture::new(60_000, 30_000).await;
        let value = b" \t edge-business-value \t ";
        let raw_auth = [b"Bearer ".as_slice(), value].concat();
        for bytes in sealing_needles(b"edge-business-value", b"Bearer edge-business-value")
            .into_iter()
            .chain(sealing_needles(b"edge-business-value", edge_ows(&raw_auth)))
        {
            for location in ["body", "utf8-header", "nonutf8-header"] {
                f.fake.push_response(Ok(ActorFixture::resolved(value)));
                let mut reflected = crate::upstream::UpstreamResponse {
                    status: 200,
                    headers: vec![].into(),
                    body: Zeroizing::new(b"clean business body".to_vec()),
                };
                match location {
                    "body" => reflected.body = bytes.clone(),
                    "utf8-header" => {
                        reflected.headers = real_header_values(&[("x-reflection", &bytes)])
                    }
                    _ => {
                        reflected.headers = real_header_values(&[(
                            "x-reflection",
                            &[b"\xff".as_slice(), &bytes, b"\xfe"].concat(),
                        )])
                    }
                }
                f.fake.push_response(Ok(reflected));
                assert!(matches!(
                    f.run().await,
                    Err(BrokerError::ResponseSecurityViolation)
                ));
                let requests = f.fake.take_requests();
                assert_eq!(requests.len(), 2);
                assert_eq!(requests[1].auth_value, raw_auth);
            }
        }
        f.fake.push_response(Ok(ActorFixture::resolved(value)));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean business body".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean business body");
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].auth_value, raw_auth);
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_decoded_selected_bootstrap_never_crosses_into_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let token = "bootstrap-quote\"-backslash\\-fixture";
        rotate_actor_bootstrap(&f, token).await;
        let source = ActorFixture::resolved(token.as_bytes());
        let parsed = AzureSourceProfile::parse_profile(
            &serde_json::to_vec(&{
                let mut raw: serde_json::Value = serde_json::from_slice(&profile(
                    crate::now_ts().unwrap().as_unix_ms() + 60_000,
                ))
                .unwrap();
                raw["access_token"] = token.into();
                raw
            })
            .unwrap(),
        )
        .unwrap();
        assert!(contains_secret(
            &source.body,
            &parsed.bootstrap_needles(b"fixture-profile")
        ));
        assert!(parsed.resolve(&source).is_ok());
        f.fake.push_response(Ok(source));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean business body".to_vec()),
        }));
        let outcome = f.run().await;
        let requests = f.fake.take_requests();
        assert!(
            matches!(outcome, Err(BrokerError::ResponseSecurityViolation)),
            "decoded bootstrap accepted: success={}, source/business requests={}",
            outcome.is_ok(),
            requests.len()
        );
        assert_eq!(requests.len(), 1);
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='azure.source.resolved'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='execution.blocked'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        f.finish().await;
    }

    #[tokio::test]
    async fn actor_decoded_selected_known_bootstrap_forms_are_sealed_and_clean_values_stay_exact() {
        let f = ActorFixture::new(60_000, 30_000).await;
        for form in sealing_needles(b"fixture-source-bearer", b"Bearer fixture-source-bearer") {
            let value = format!("prefix:{}:suffix", std::str::from_utf8(&form).unwrap());
            let mut source = ActorFixture::resolved(value.as_bytes());
            let container = value;
            let escaped = container
                .bytes()
                .map(|b| format!("\\u{:04x}", b))
                .collect::<String>();
            source.body = Zeroizing::new(
                String::from_utf8(source.body.to_vec())
                    .unwrap()
                    .replace(&container, &escaped)
                    .into_bytes(),
            );
            assert!(contains_secret(
                &source.body,
                &sealing_needles(b"fixture-source-bearer", b"Bearer fixture-source-bearer")
            ));
            f.fake.push_response(Ok(source));
            assert!(matches!(
                f.run().await,
                Err(BrokerError::ResponseSecurityViolation)
            ));
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"clean-selected-value")));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean business body".to_vec()),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean business body");
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].auth_value, b"Bearer clean-selected-value");
        f.finish().await;
    }
}
