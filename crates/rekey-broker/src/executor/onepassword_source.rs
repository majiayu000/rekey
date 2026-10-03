//! One fixed public Connect item and exact field, without discovery or refresh.
use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::{Deserialize, Deserializer};

use super::*;

const RESPONSE_LIMIT: u32 = 64 * 1024;
const VALUE_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnePasswordSourceError {
    InvalidCredential,
    Expired,
    Response,
    Version,
    Ineligible,
}
impl OnePasswordSourceError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::InvalidCredential => "onepassword-source-invalid",
            Self::Expired => "onepassword-source-expired",
            Self::Response => "onepassword-source-response",
            Self::Version => "onepassword-source-version",
            Self::Ineligible => "onepassword-source-ineligible",
        }
    }
}
pub(crate) struct OnePasswordSourceProfile {
    origin: HttpsOrigin,
    vault_id: String,
    item_id: String,
    field_id: String,
    expected_item_version: u32,
    token: Zeroizing<String>,
    expires_at_ms: i64,
}
pub(super) struct OnePasswordPrepared {
    pub(super) credential_version: u64,
    pub(super) profile: Result<OnePasswordSourceProfile, OnePasswordSourceError>,
    pub(super) needles: Vec<Zeroizing<Vec<u8>>>,
}
fn secret_string<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    credential_type: String,
    origin: String,
    vault_id: String,
    item_id: String,
    field_id: String,
    expected_item_version: u32,
    #[serde(deserialize_with = "secret_string")]
    access_token: Zeroizing<String>,
    local_use_expires_at_ms: i64,
}
// A nullable metadata value remains a present wrapper even for JSON null.
// Serde's struct visitor therefore rejects duplicate null properties as well.
struct Nullable<T>(Option<T>);
impl<T> Default for Nullable<T> {
    fn default() -> Self {
        Self(None)
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(d).map(Self)
    }
}
// Eligibility markers distinguish omission from an explicitly null value.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
struct SecretText(Zeroizing<String>);
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        secret_string(d).map(Self)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemVault {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    id: String,
    vault: ItemVault,
    version: u32,
    #[serde(rename = "category")]
    _category: String,
    fields: Vec<ItemField>,
    #[serde(default, deserialize_with = "present")]
    state: Option<Nullable<String>>,
    #[serde(default, deserialize_with = "present")]
    trashed: Option<Nullable<bool>>,
    #[serde(default, rename = "title")]
    _title: Nullable<SecretText>,
    #[serde(default, rename = "lastEditedBy")]
    _last_edited_by: Nullable<String>,
    #[serde(default, rename = "createdAt")]
    _created_at: Nullable<String>,
    #[serde(default, rename = "updatedAt")]
    _updated_at: Nullable<String>,
    #[serde(default, rename = "urls")]
    _urls: Nullable<Vec<ItemUrl>>,
    #[serde(default, rename = "favorite")]
    _favorite: Nullable<bool>,
    #[serde(default, rename = "tags")]
    _tags: Nullable<Vec<String>>,
    #[serde(default, rename = "sections")]
    _sections: Nullable<Vec<Section>>,
    #[serde(default, rename = "files")]
    _files: Nullable<Vec<ItemFile>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemField {
    id: String,
    #[serde(default, rename = "type")]
    kind: Nullable<String>,
    #[serde(default)]
    value: Nullable<SecretText>,
    #[serde(default, rename = "purpose")]
    _purpose: Nullable<String>,
    #[serde(default, rename = "label")]
    _label: Nullable<String>,
    #[serde(default, rename = "totp")]
    _totp: Nullable<SecretText>,
    #[serde(default, rename = "section")]
    _section: Nullable<Section>,
    #[serde(default, rename = "generate")]
    _generate: Nullable<bool>,
    #[serde(default, rename = "recipe")]
    _recipe: Nullable<Recipe>,
    #[serde(default, rename = "entropy")]
    _entropy: Nullable<f64>,
    #[serde(default, rename = "passwordDetails")]
    _password_details: Nullable<PasswordDetails>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    #[serde(default, rename = "id")]
    _field_0: Nullable<String>,
    #[serde(default, rename = "label")]
    _field_1: Nullable<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    #[serde(default, rename = "length")]
    _field_0: Nullable<i64>,
    #[serde(default, rename = "characterSets")]
    _field_1: Nullable<Vec<String>>,
    #[serde(default, rename = "excludeCharacters")]
    _field_2: Nullable<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordDetails {
    #[serde(default, rename = "entropy")]
    _field_0: Nullable<f64>,
    #[serde(default, rename = "generated")]
    _field_1: Nullable<bool>,
    #[serde(default, rename = "strength")]
    _field_2: Nullable<String>,
    #[serde(default, rename = "history")]
    _field_3: Nullable<Vec<SecretText>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemUrl {
    #[serde(default, rename = "primary")]
    _field_0: Nullable<bool>,
    #[serde(default, rename = "label")]
    _field_1: Nullable<String>,
    #[serde(default, rename = "href")]
    _field_2: Nullable<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemFile {
    #[serde(default, rename = "id")]
    _field_0: Nullable<String>,
    #[serde(default, rename = "name")]
    _field_1: Nullable<String>,
    #[serde(default, rename = "content_path")]
    _field_2: Nullable<String>,
    #[serde(default, rename = "content")]
    _field_3: Nullable<SecretText>,
    #[serde(default, rename = "size")]
    _field_4: Nullable<i64>,
    #[serde(default, rename = "section")]
    _field_5: Nullable<Section>,
}
impl OnePasswordSourceProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, OnePasswordSourceError> {
        Self::parse_at(
            secret,
            crate::now_ts()
                .map_err(|_| OnePasswordSourceError::InvalidCredential)?
                .as_unix_ms(),
        )
    }
    fn parse_at(secret: &[u8], now_ms: i64) -> Result<Self, OnePasswordSourceError> {
        let raw: RawProfile = serde_json::from_slice(secret)
            .map_err(|_| OnePasswordSourceError::InvalidCredential)?;
        let origin = HttpsOrigin::parse(&raw.origin)
            .map_err(|_| OnePasswordSourceError::InvalidCredential)?;
        let id_valid = |id: &str| {
            id.len() == 26
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        };
        if raw.credential_type != "onepassword-connect-source-v1"
            || raw.origin != origin.as_str()
            || origin.port() != 443
            || origin.host().parse::<std::net::IpAddr>().is_ok()
            || !id_valid(&raw.vault_id)
            || !id_valid(&raw.item_id)
            || !(1..=128).contains(&raw.field_id.len())
            || raw.field_id.chars().any(char::is_control)
            || raw.expected_item_version == 0
            || raw.access_token.is_empty()
            || raw.access_token.len() > 16 * 1024
            || reqwest::header::HeaderValue::from_bytes(raw.access_token.as_bytes()).is_err()
        {
            return Err(OnePasswordSourceError::InvalidCredential);
        }
        let remaining = raw
            .local_use_expires_at_ms
            .checked_sub(now_ms)
            .ok_or(OnePasswordSourceError::InvalidCredential)?;
        if !(1..=3_600_000).contains(&remaining) {
            return Err(OnePasswordSourceError::InvalidCredential);
        }
        Ok(Self {
            origin,
            vault_id: raw.vault_id,
            item_id: raw.item_id,
            field_id: raw.field_id,
            expected_item_version: raw.expected_item_version,
            token: raw.access_token,
            expires_at_ms: raw.local_use_expires_at_ms,
        })
    }
    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), OnePasswordSourceError> {
        Self::parse_profile(secret).map(|_| ())
    }
    fn token(&self) -> &[u8] {
        self.token.as_bytes()
    }
    fn bearer(&self) -> Zeroizing<Vec<u8>> {
        let mut value = Zeroizing::new(b"Bearer ".to_vec());
        value.extend_from_slice(self.token());
        value
    }
    fn reference(&self) -> String {
        format!(
            "{}/v1/vaults/{}/items/{} field={} version={}",
            self.origin.as_str(),
            self.vault_id,
            self.item_id,
            self.field_id,
            self.expected_item_version
        )
    }
    pub(super) fn bootstrap_needles(&self, raw_profile: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
        let mut needles = sealing_needles(raw_profile, self.token());
        needles.extend(sealing_needles(self.token(), &self.bearer()));
        let token = self.token.trim_matches([' ', '\t']);
        if !token.is_empty() && token.as_bytes() != self.token() {
            let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
            bearer.extend_from_slice(token.as_bytes());
            needles.extend(sealing_needles(token.as_bytes(), &bearer));
        }
        needles
    }
    fn source_deadline(&self, action_deadline: Instant) -> Result<Instant, OnePasswordSourceError> {
        let anchor = Instant::now();
        let now = crate::now_ts()
            .map_err(|_| OnePasswordSourceError::Expired)?
            .as_unix_ms();
        let remaining = self
            .expires_at_ms
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or(OnePasswordSourceError::Expired)?;
        Ok(action_deadline.min(anchor + Duration::from_millis(remaining as u64)))
    }
    fn expiry_valid(&self, deadline: Instant) -> bool {
        Instant::now() < deadline
            && crate::now_ts().is_ok_and(|now| now.as_unix_ms() < self.expires_at_ms)
    }
    fn request(&self, timeout: Duration) -> UpstreamRequest {
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: 443,
            method: FixedMethod::Get,
            path: format!("/v1/vaults/{}/items/{}", self.vault_id, self.item_id),
            headers: vec![
                ("accept".into(), "application/json".into()),
                ("content-type".into(), "application/json".into()),
            ],
            auth_header: ("authorization".into(), self.bearer()),
            body: Zeroizing::new(Vec::new()),
            timeout,
            response_max_bytes: RESPONSE_LIMIT,
        }
    }
    fn resolve(
        &self,
        response: &crate::upstream::UpstreamResponse,
    ) -> Result<Zeroizing<Vec<u8>>, OnePasswordSourceError> {
        if response.status != 200 || response.body.len() > RESPONSE_LIMIT as usize {
            return Err(OnePasswordSourceError::Response);
        }
        let parsed: Item =
            serde_json::from_slice(&response.body).map_err(|_| OnePasswordSourceError::Response)?;
        if parsed.id != self.item_id
            || parsed.vault.id != self.vault_id
            || parsed.version != self.expected_item_version
        {
            return Err(OnePasswordSourceError::Version);
        }
        if parsed
            .state
            .is_some_and(|s| s.0.as_deref() != Some("ACTIVE"))
            || parsed.trashed.is_some_and(|t| t.0 != Some(false))
        {
            return Err(OnePasswordSourceError::Ineligible);
        }
        let mut seen = std::collections::HashSet::new();
        let mut selected = None;
        for field in parsed.fields {
            if field.id.is_empty() || !seen.insert(field.id.clone()) {
                return Err(OnePasswordSourceError::Response);
            }
            if field.id == self.field_id {
                if !field
                    .kind
                    .0
                    .as_deref()
                    .is_some_and(|s| matches!(s, "STRING" | "CONCEALED"))
                {
                    return Err(OnePasswordSourceError::Ineligible);
                }
                let value = field.value.0.ok_or(OnePasswordSourceError::Response)?;
                if value.0.is_empty()
                    || value.0.len() > VALUE_LIMIT
                    || reqwest::header::HeaderValue::from_bytes(value.0.as_bytes()).is_err()
                {
                    return Err(OnePasswordSourceError::Response);
                }
                selected = Some(Zeroizing::new(value.0.as_bytes().to_vec()));
            }
        }
        selected.ok_or(OnePasswordSourceError::Response)
    }
}
impl ActionExecutor {
    pub(super) async fn resolve_onepassword_source(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: OnePasswordPrepared,
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
            rekey_vault::model::event_type::ONEPASSWORD_SOURCE_READ_STARTED,
            "success",
            profile.reference(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        let upstream = profile.request(source_deadline.saturating_duration_since(Instant::now()));
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, OnePasswordSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(
                OnePasswordSourceError::Expired.reason(),
            ));
        }
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-onepassword-source-header")
                .await?;
            return Err(BrokerError::Denied("invalid-onepassword-source-header"));
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
                        "onepassword-source-response-too-large"
                    }
                    Ok(Err(crate::upstream::UpstreamError::Blocked(r))) => reason_static(r),
                    _ => "onepassword-source-transport",
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
                .blocked_until(effect_deadline, "onepassword-source-reflected-secret")
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
        // JSON decoding may expose bootstrap bytes absent from the raw body
        // (for example escaped quote/backslash characters in a selected value).
        if contains_secret(&resolved, &prepared.needles) {
            started
                .blocked_until(effect_deadline, "onepassword-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, OnePasswordSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(
                OnePasswordSourceError::Expired.reason(),
            ));
        }
        let mut auth = Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec());
        auth.extend_from_slice(&resolved);
        let mut needles = prepared.needles;
        needles.extend(fixed_header_sealing_needles(
            &resolved,
            &auth,
            action.auth.prefix.as_str().as_bytes(),
        ));

        let upstream = build_upstream(action, request, auth).map_err(BrokerError::Denied)?;
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-upstream-header")
                .await?;
            return Err(BrokerError::Denied("invalid-upstream-header"));
        }
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::ONEPASSWORD_SOURCE_RESOLVED,
            "success",
            profile.reference(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, OnePasswordSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(
                OnePasswordSourceError::Expired.reason(),
            ));
        }
        // The declared import-use window gates source admission only. The
        // caller retains the original absolute Action deadline for business.
        Ok(PreparedExecution::Opaque { upstream, needles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: &str = "https://connect.example.com";
    const VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
    const ITEM: &str = "0123456789abcdefghijklmnop";
    fn profile(expiry: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"credential_type":"onepassword-connect-source-v1","origin":ORIGIN,"vault_id":VAULT,"item_id":ITEM,"field_id":"password","expected_item_version":7,"access_token":"fixture-source-bearer","local_use_expires_at_ms":expiry})).unwrap()
    }
    fn item(value: &str) -> serde_json::Value {
        serde_json::json!({"id":ITEM,"vault":{"id":VAULT},"category":"API_CREDENTIAL","version":7,"fields":[{"id":"password","type":"CONCEALED","value":value}]})
    }
    fn response(value: &str) -> crate::upstream::UpstreamResponse {
        json_response(item(value))
    }
    fn json_response(value: serde_json::Value) -> crate::upstream::UpstreamResponse {
        raw_response(&serde_json::to_vec(&value).unwrap())
    }
    fn raw_response(value: &[u8]) -> crate::upstream::UpstreamResponse {
        crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(value.to_vec()),
        }
    }
    #[test]
    fn profile_fixed_origin_ids_field_exactness_and_declared_local_use_boundaries() {
        for expiry in [1000, 999, 3_601_001, i64::MAX, i64::MIN] {
            assert!(OnePasswordSourceProfile::parse_at(&profile(expiry), 1000).is_err());
        }
        for expiry in [1001, 3_601_000] {
            assert!(OnePasswordSourceProfile::parse_at(&profile(expiry), 1000).is_ok());
        }
        let raw: serde_json::Value = serde_json::from_slice(&profile(2000)).unwrap();
        for origin in [
            "http://connect.example.com",
            "https://Connect.example.com",
            "https://connect.example.com:443",
            "https://connect.example.com:8443",
            "https://user@connect.example.com",
            "https://connect.example.com/",
            "https://connect.example.com?version=7",
            "https://connect.example.com#x",
            "https://127.0.0.1",
            "https://[::1]",
            "https://invalid_.example.com",
        ] {
            let mut v = raw.clone();
            v["origin"] = origin.into();
            assert!(
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err(),
                "{origin}"
            );
        }
        for key in ["vault_id", "item_id"] {
            for invalid in [
                "",
                "ABCDEFGHIJKLMNOPQRSTUVWXY1",
                "a23456789abcdefghijklmnop",
                "abcdefghijklmnopqrstuvwxyz1",
                "12345678-1234-1234-1234-123456789012",
                "../../item",
                "abcdefghijklmnopqrstuvwxyz?",
            ] {
                let mut v = raw.clone();
                v[key] = invalid.into();
                assert!(
                    OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000)
                        .is_err(),
                    "{key}: {invalid}"
                );
            }
        }
        for field in [
            "username",
            "password",
            "notesPlain",
            "custom-field/中文 ",
            &"x".repeat(128),
        ] {
            let mut v = raw.clone();
            v["field_id"] = field.into();
            let p =
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).unwrap();
            assert_eq!(p.field_id, field);
        }
        for field in ["", "x\n", "x\0", &"x".repeat(129), &"中".repeat(43)] {
            let mut v = raw.clone();
            v["field_id"] = field.into();
            assert!(
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err()
            );
        }
        for version in [
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(4294967296u64),
            serde_json::json!(7.5),
            serde_json::json!("7"),
            serde_json::Value::Null,
        ] {
            let mut v = raw.clone();
            v["expected_item_version"] = version;
            assert!(
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err()
            );
        }
        for token in ["", "x\n", "x\r", "x\0", &"x".repeat(16385)] {
            let mut v = raw.clone();
            v["access_token"] = token.into();
            assert!(
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err()
            );
        }
        for token in [" \t opaque-token \t ", "中文token", &"x".repeat(16384)] {
            let mut v = raw.clone();
            v["access_token"] = token.into();
            let p =
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).unwrap();
            assert_eq!(p.token(), token.as_bytes());
        }
        for key in raw.as_object().unwrap().keys() {
            let mut v = raw.clone();
            v.as_object_mut().unwrap().remove(key);
            assert!(
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err()
            );
            let mut v = raw.clone();
            v[key] = serde_json::Value::Null;
            assert!(
                OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err()
            );
        }
        let mut v = raw.clone();
        v["extra"] = true.into();
        assert!(
            OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&v).unwrap(), 1000).is_err()
        );
        let mut bytes = profile(2000);
        bytes.pop();
        bytes.extend_from_slice(b",\"field_id\":\"password\"}");
        assert!(OnePasswordSourceProfile::parse_at(&bytes, 1000).is_err());
    }
    #[test]
    fn exact_single_get_without_query_or_body_and_typed_json_headers() {
        let p = OnePasswordSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let req = p.request(Duration::from_millis(500));
        assert_eq!(req.host, "connect.example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.method, FixedMethod::Get);
        assert_eq!(req.path, format!("/v1/vaults/{VAULT}/items/{ITEM}"));
        assert!(req.body.is_empty());
        assert_eq!(
            req.headers,
            vec![
                ("accept".into(), "application/json".into()),
                ("content-type".into(), "application/json".into())
            ]
        );
        assert_eq!(
            req.auth_header.1.as_slice(),
            b"Bearer fixture-source-bearer"
        );
        assert_eq!(req.response_max_bytes, 65536);
    }
    #[test]
    fn closed_item_security_core_exact_selection_and_full_header_safe_value() {
        let p = OnePasswordSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        for value in ["value", "  中文完整 value  ", &"x".repeat(8192)] {
            assert_eq!(
                p.resolve(&response(value)).unwrap().as_slice(),
                value.as_bytes()
            );
        }
        for value in ["", "x\r", "x\n", "x\0", &"x".repeat(8193)] {
            assert!(p.resolve(&response(value)).is_err());
        }
        for key in ["id", "vault", "category", "version", "fields"] {
            let mut v = item("value");
            v.as_object_mut().unwrap().remove(key);
            assert!(p.resolve(&json_response(v)).is_err(), "missing {key}");
            let mut v = item("value");
            v[key] = serde_json::Value::Null;
            assert!(p.resolve(&json_response(v)).is_err(), "null {key}");
        }
        for key in ["id", "type", "value"] {
            let mut v = item("value");
            v["fields"][0].as_object_mut().unwrap().remove(key);
            assert!(p.resolve(&json_response(v)).is_err());
            let mut v = item("value");
            v["fields"][0][key] = serde_json::Value::Null;
            assert!(p.resolve(&json_response(v)).is_err());
        }
        for ty in ["REFERENCE", "OTP", "FILE", "SSHKEY", "UNKNOWN", ""] {
            let mut v = item("value");
            v["fields"][0]["type"] = ty.into();
            assert!(p.resolve(&json_response(v)).is_err());
        }
        for ty in ["STRING", "CONCEALED"] {
            let mut v = item("value");
            v["fields"][0]["type"] = ty.into();
            assert!(p.resolve(&json_response(v)).is_ok());
        }
        for change in [
            serde_json::json!({"id":VAULT}),
            serde_json::json!({"vault":{"id":ITEM}}),
            serde_json::json!({"vault":{}}),
            serde_json::json!({"vault":{"id":null}}),
            serde_json::json!({"version":8}),
            serde_json::json!({"fields":[]}),
            serde_json::json!({"fields":[{"id":"other","label":"password","purpose":"PASSWORD","type":"CONCEALED","value":"value"}]}),
            serde_json::json!({"fields":[{"id":"","value":null}]}),
            serde_json::json!({"fields":[{"id":"password","type":"STRING","value":"value"},{"id":"password"}]}),
            serde_json::json!({"fields":[{"id":"password","type":"STRING","value":"value"},{"id":"other"},{"id":"other"}]}),
        ] {
            let mut v = item("value");
            v.as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(p.resolve(&json_response(v)).is_err(), "{change}");
        }
        for key in ["state", "trashed"] {
            let mut v = item("value");
            v[key] = serde_json::Value::Null;
            assert!(
                p.resolve(&json_response(v)).is_err(),
                "null eligibility marker {key}"
            );
        }
        for state in ["ARCHIVED", "DELETED", "UNKNOWN", ""] {
            let mut v = item("value");
            v["state"] = state.into();
            assert!(p.resolve(&json_response(v)).is_err());
        }
        let mut v = item("value");
        v["state"] = "ACTIVE".into();
        assert!(p.resolve(&json_response(v.clone())).is_ok());
        v["trashed"] = true.into();
        assert!(p.resolve(&json_response(v)).is_err());
        let mut v = item("value");
        v["fields"].as_array_mut().unwrap().extend([
            serde_json::json!({"id":"reference","type":"REFERENCE","value":"op://no-follow"}),
            serde_json::json!({"id":"unknown","type":"FUTURE","value":null}),
            serde_json::json!({"id":"absent"}),
        ]);
        assert_eq!(p.resolve(&json_response(v)).unwrap().as_slice(), b"value");
        let mut prof: serde_json::Value = serde_json::from_slice(&profile(2000)).unwrap();
        prof["field_id"] = "custom-field/中文 ".into();
        let p =
            OnePasswordSourceProfile::parse_at(&serde_json::to_vec(&prof).unwrap(), 1000).unwrap();
        let mut v = item("value");
        v["fields"][0]["id"] = "custom-field/中文 ".into();
        assert!(p.resolve(&json_response(v.clone())).is_ok());
        v["fields"][0]["id"] = "custom-field/中文".into();
        assert!(p.resolve(&json_response(v)).is_err());
        for body in [
            b"bad-json".as_slice(),
            b"{\"status\":401,\"message\":\"provider detail\"}",
            b"\xff",
        ] {
            assert!(p.resolve(&raw_response(body)).is_err());
        }
        assert!(p.resolve(&raw_response(&vec![b' '; 65537])).is_err());
        for status in [201, 301, 401, 403, 404, 429, 500] {
            let mut v = response("value");
            v.status = status;
            assert!(p.resolve(&v).is_err());
        }
    }
    fn metadata_item() -> serde_json::Value {
        let mut v = item("value");
        v.as_object_mut().unwrap().extend(serde_json::json!({"title":"ignored-secret-title","lastEditedBy":"editor","createdAt":"informational no date parser","updatedAt":"date","urls":[{"primary":true,"label":"site","href":"https://never-fetch.example"}],"favorite":false,"tags":["tag"],"state":"ACTIVE","trashed":false,"sections":[{"id":"section-id","label":"section"}],"files":[{"id":"file-id","name":"file","size":2,"content_path":"/no-fetch","content":"ignored-no-decode","section":{"id":"s","label":"label"}}]}).as_object().unwrap().clone());
        v["fields"][0].as_object_mut().unwrap().extend(serde_json::json!({"purpose":"PASSWORD","label":"ignored","totp":"never-execute","section":{"id":"s","label":"label"},"generate":true,"recipe":{"length":32,"characterSets":["LETTERS"],"excludeCharacters":"x"},"entropy":42.5,"passwordDetails":{"entropy":42.5,"generated":true,"strength":"GOOD","history":["ignored-history-secret"]}}).as_object().unwrap().clone());
        v
    }
    #[test]
    fn metadata_known_union_is_closed_typed_nullable_and_duplicate_null_safe() {
        let p = OnePasswordSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let raw = metadata_item();
        assert_eq!(
            p.resolve(&json_response(raw.clone())).unwrap().as_slice(),
            b"value"
        );
        for path in [
            "",
            "/fields/0",
            "/fields/0/section",
            "/fields/0/recipe",
            "/fields/0/passwordDetails",
            "/urls/0",
            "/sections/0",
            "/files/0",
            "/files/0/section",
            "/vault",
        ] {
            let object = raw.pointer(path).unwrap().as_object().unwrap();
            let mut v = raw.clone();
            v.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), serde_json::Value::Null);
            assert!(p.resolve(&json_response(v)).is_err(), "unknown {path}");
            for (key, value) in object {
                let security = path == "/vault"
                    || (path.is_empty()
                        && [
                            "id", "vault", "version", "category", "fields", "state", "trashed",
                        ]
                        .contains(&key.as_str()))
                    || (path == "/fields/0" && ["id", "type", "value"].contains(&key.as_str()));
                if !security {
                    let mut v = raw.clone();
                    v.pointer_mut(path).unwrap()[key] = serde_json::Value::Null;
                    assert!(
                        p.resolve(&json_response(v)).is_ok(),
                        "nullable {path}/{key}"
                    );
                    let mut v = raw.clone();
                    v.pointer_mut(path)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(key);
                    assert!(
                        p.resolve(&json_response(v)).is_ok(),
                        "optional {path}/{key}"
                    );
                }
                let mut v = raw.clone();
                v.pointer_mut(path).unwrap()[key] = if value.is_string() {
                    serde_json::json!(true)
                } else {
                    serde_json::json!("wrong-type")
                };
                assert!(p.resolve(&json_response(v)).is_err(), "typed {path}/{key}");
                // Serialize the enclosing object as exact raw duplicate properties.
                let mut enclosing = object.clone();
                enclosing.insert(key.clone(), serde_json::Value::Null);
                let original =
                    serde_json::to_string(&serde_json::Value::Object(enclosing)).unwrap();
                let mut duplicate = original[..original.len() - 1].to_owned();
                duplicate.push_str(&format!(",{}:null}}", serde_json::to_string(key).unwrap()));
                let unique =
                    serde_json::to_string(&serde_json::Value::Object(object.clone())).unwrap();
                let body = serde_json::to_string(&raw)
                    .unwrap()
                    .replacen(&unique, &duplicate, 1);
                assert!(
                    p.resolve(&raw_response(body.as_bytes())).is_err(),
                    "duplicate-null {path}/{key}"
                );
            }
        }
        for bad in ["1e999", "-1e999"] {
            let body = serde_json::to_string(&raw).unwrap().replace("42.5", bad);
            assert!(p.resolve(&raw_response(body.as_bytes())).is_err());
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
                    CredentialLabel::new("onepassword-actor").unwrap(),
                    CredentialKind::OnePasswordConnectSource,
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
                request_context: None,
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
        assert_eq!(sent[0].host, "connect.example.com");
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
                "onepassword.source.read_started",
                "onepassword.source.resolved",
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
            ("onepassword.source.read_started", 0),
            ("onepassword.source.resolved", 1),
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
            assert_eq!(error.code(), "UPSTREAM_FAILED");
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
        // Allow durable preparation to finish before the deliberately delayed source expires.
        let f = ActorFixture::new(2_000, 30_000).await;
        f.fake.push_response_delayed(
            Ok(ActorFixture::resolved(b"123456789")),
            Duration::from_millis(3_000),
        );
        assert!(f.run().await.is_err());
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
        let f = ActorFixture::new(60_000, 2_000).await;
        f.fake.push_response_delayed(
            Ok(ActorFixture::resolved(b"123456789")),
            Duration::from_millis(3_000),
        );
        assert!(f.run().await.is_err());
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
        let f = ActorFixture::new(2_000, 30_000).await;
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"123456789")));
        f.fake.push_response_delayed(
            Ok(crate::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean".to_vec()),
            }),
            Duration::from_millis(3_000),
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
                if draft.event_type == rekey_vault::model::event_type::ONEPASSWORD_SOURCE_RESOLVED {
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
                rekey_domain::credential::CredentialKind::OnePasswordConnectSource,
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
                        assert_eq!(requests[0].host, "connect.example.com");
                    }
                }
            }
            assert_eq!(
                f.db()
                    .query_row(
                        "SELECT count(*) FROM audit_events WHERE event_type='onepassword.source.resolved'",
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
                let event = if request.host == "connect.example.com" {
                    "onepassword.source.read_started"
                } else {
                    "onepassword.source.resolved"
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
                assert_eq!(request.host, "connect.example.com");
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
    async fn actor_exact_raw_profile_token_and_bearer_direct_encodings_are_sealed() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let raw = profile(crate::now_ts().unwrap().as_unix_ms() + 60_000);
        f.authority
            .credential_rotate_typed_before(
                f.action.credential_id,
                rekey_domain::credential::CredentialKind::OnePasswordConnectSource,
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
        for change in [
            serde_json::json!({"state":"ARCHIVED"}),
            serde_json::json!({"trashed":true}),
            serde_json::json!({"version":8}),
            serde_json::json!({"fields":[{"id":"password","type":"REFERENCE","value":"op://never-follow"}]}),
        ] {
            let mut raw = item("123456789");
            raw.as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
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
    async fn actor_read_started_audit_cannot_outlive_bootstrap_before_source_send() {
        let mut f = ActorFixture::new(250, 30_000).await;
        let authority = f.authority.clone();
        let (tracker, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
            let authority = authority.clone();
            async move {
                if draft.event_type
                    == rekey_vault::model::event_type::ONEPASSWORD_SOURCE_READ_STARTED
                {
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
            .lock_for_restart("onepassword-rotation-test")
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
        let backup = f.state.parent().unwrap().join("onepassword.rkbackup");
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
            rekey_vault::bootstrap::inspect_restore(
                &backup,
                &restored,
                rekey_vault::bootstrap::RestoreProof::Password(
                    rekey_vault::secret::SecretInput::from_slice(b"actor-proof"),
                ),
                &receipt.sha256_hex,
            )
            .unwrap(),
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
                    .filter(|r| r.host == "connect.example.com")
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
            .chain(sealing_needles(
                b"edge-business-value",
                raw_auth.as_slice().trim_ascii_end(),
            ))
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
    async fn actor_json_escaped_selected_bootstrap_token_never_crosses_into_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let token = "bootstrap-quote\"-backslash\\-fixture";
        rotate_actor_bootstrap(&f, token).await;
        f.fake.push_response(Ok(response(token)));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean business body".to_vec()),
        }));
        assert!(matches!(
            f.run().await,
            Err(BrokerError::ResponseSecurityViolation)
        ));
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
    }
}
