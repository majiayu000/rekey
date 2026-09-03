use std::fmt;
use std::time::{Duration, Instant};

use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, Zeroizing};

use super::*;

const PROFILE_MARKER: &str = "vault-dynamic-source-v1";
const SOURCE_RESPONSE_MAX_BYTES: u32 = 64 * 1024;
const RESOLVED_VALUE_MAX_BYTES: usize = 8 * 1024;
const LEASE_ID_MAX_BYTES: usize = 1024;
const LEASE_CAPTURE_LIMIT: usize = 4;
const MIN_LEASE_SECONDS: u64 = 5;
const MAX_LEASE_SECONDS: u64 = 300;
pub(super) const CLEANUP_BUDGET: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultDynamicError {
    InvalidCredential,
    SourceTransport,
    SourceRejected,
    SourceResponse,
    SourceReflected,
    ResponseTooLarge,
    RevokeTransport,
    RevokeRejected,
    RevokeReflected,
    Deadline,
}

impl VaultDynamicError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::InvalidCredential => "vault-dynamic-source-invalid",
            Self::SourceTransport => "vault-dynamic-source-transport",
            Self::SourceRejected => "vault-dynamic-source-rejected",
            Self::SourceResponse => "vault-dynamic-source-response",
            Self::SourceReflected => "vault-dynamic-source-reflected-secret",
            Self::ResponseTooLarge => "vault-dynamic-source-response-too-large",
            Self::RevokeTransport => "vault-dynamic-revoke-transport",
            Self::RevokeRejected => "vault-dynamic-revoke-rejected",
            Self::RevokeReflected => "vault-dynamic-revoke-reflected-secret",
            Self::Deadline => "upstream-timeout",
        }
    }
}

pub(crate) struct VaultDynamicProfile {
    origin: HttpsOrigin,
    mount: String,
    role: String,
    key: String,
    token: Zeroizing<Vec<u8>>,
}

pub(super) struct VaultDynamicPrepared {
    pub(super) credential_version: u64,
    pub(super) profile: Result<VaultDynamicProfile, VaultDynamicError>,
    pub(super) needles: Vec<Zeroizing<Vec<u8>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDynamicProfile<'a> {
    credential_type: &'a str,
    origin: &'a str,
    mount: &'a str,
    role: &'a str,
    key: &'a str,
    vault_token: &'a str,
}

pub(super) struct AcquiredLease {
    pub(super) acquired_at: Instant,
    pub(super) lease_id: Zeroizing<String>,
    pub(super) lease_duration: Duration,
    pub(super) value: Zeroizing<Vec<u8>>,
}

pub(super) struct AcquisitionFailure {
    pub(super) error: VaultDynamicError,
    pub(super) lease_ids: Vec<Zeroizing<String>>,
    pub(super) indeterminate: bool,
}

impl VaultDynamicProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, VaultDynamicError> {
        let raw: RawDynamicProfile<'_> =
            serde_json::from_slice(secret).map_err(|_| VaultDynamicError::InvalidCredential)?;
        if raw.credential_type != PROFILE_MARKER
            || !safe_segment(raw.mount)
            || !safe_segment(raw.role)
            || raw.key.is_empty()
            || raw.key.len() > 128
            || !raw.key.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
            || raw.vault_token.is_empty()
            || raw.vault_token.len() > 4_096
            || !raw
                .vault_token
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(VaultDynamicError::InvalidCredential);
        }
        Ok(Self {
            origin: HttpsOrigin::parse(raw.origin)
                .map_err(|_| VaultDynamicError::InvalidCredential)?,
            mount: raw.mount.to_owned(),
            role: raw.role.to_owned(),
            key: raw.key.to_owned(),
            token: Zeroizing::new(raw.vault_token.as_bytes().to_vec()),
        })
    }

    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), VaultDynamicError> {
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
            path: format!("/v1/{}/creds/{}", self.mount, self.role),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            auth_header: (
                "x-vault-token".to_owned(),
                Zeroizing::new(self.token.to_vec()),
            ),
            body: Vec::new(),
            timeout,
            response_max_bytes: SOURCE_RESPONSE_MAX_BYTES,
        }
    }

    pub(super) async fn acquire(
        &self,
        transport: &dyn UpstreamTransport,
        timeout: Duration,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<AcquiredLease, AcquisitionFailure> {
        let acquired_at = Instant::now();
        let request = self.request(timeout);
        if !outbound_headers_are_valid(&request) {
            return Err(AcquisitionFailure::definite(
                VaultDynamicError::InvalidCredential,
            ));
        }
        let response = tokio::time::timeout(timeout, transport.send(request)).await;
        let response = match response {
            Err(_) => return Err(AcquisitionFailure::uncertain(VaultDynamicError::Deadline)),
            Ok(Err(crate::upstream::UpstreamError::ResponseTooLarge)) => {
                return Err(AcquisitionFailure::uncertain(
                    VaultDynamicError::ResponseTooLarge,
                ));
            }
            Ok(Err(crate::upstream::UpstreamError::Timeout)) => {
                return Err(AcquisitionFailure::uncertain(VaultDynamicError::Deadline));
            }
            Ok(Err(crate::upstream::UpstreamError::Blocked("redirect")))
            | Ok(Err(crate::upstream::UpstreamError::Transport)) => {
                return Err(AcquisitionFailure::uncertain(
                    VaultDynamicError::SourceTransport,
                ));
            }
            Ok(Err(crate::upstream::UpstreamError::Blocked(_))) => {
                return Err(AcquisitionFailure::definite(
                    VaultDynamicError::SourceTransport,
                ));
            }
            Ok(Ok(response)) => response,
        };
        let probe = probe_lease_ids(&response.body);
        if contains_secret(&response.body, needles)
            || headers_contain_secret(&response.headers, needles)
        {
            return Err(AcquisitionFailure::with_ids(
                VaultDynamicError::SourceReflected,
                probe.lease_ids,
                true,
            ));
        }
        if response.status != 200 {
            return Err(AcquisitionFailure::with_ids(
                VaultDynamicError::SourceRejected,
                probe.lease_ids,
                probe.occurrences != 0,
            ));
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&response.body);
        let parsed = match (IssuedSeed { key: &self.key }).deserialize(&mut deserializer) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Err(AcquisitionFailure::with_ids(
                    VaultDynamicError::SourceResponse,
                    probe.lease_ids,
                    true,
                ));
            }
        };
        if deserializer.end().is_err() {
            return Err(AcquisitionFailure::with_ids(
                VaultDynamicError::SourceResponse,
                probe.lease_ids,
                true,
            ));
        }
        if probe.truncated
            || probe.occurrences != 1
            || probe.lease_ids.len() != 1
            || probe.lease_ids[0].as_bytes() != parsed.lease_id.as_bytes()
        {
            return Err(AcquisitionFailure::with_ids(
                VaultDynamicError::SourceResponse,
                probe.lease_ids,
                true,
            ));
        }
        let mut lease_ids = probe.lease_ids;
        let lease_id = lease_ids
            .pop()
            .ok_or_else(|| AcquisitionFailure::uncertain(VaultDynamicError::SourceResponse))?;
        Ok(AcquiredLease {
            acquired_at,
            lease_id,
            lease_duration: Duration::from_secs(parsed.lease_duration),
            value: parsed.value,
        })
    }

    pub(super) async fn revoke_all(
        &self,
        transport: &dyn UpstreamTransport,
        lease_ids: &[Zeroizing<String>],
        deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), VaultDynamicError> {
        let mut first_error = None;
        for (index, lease_id) in lease_ids.iter().enumerate() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or(VaultDynamicError::Deadline)?;
            let attempts_left = (lease_ids.len() - index) as u32;
            if let Err(error) = self
                .revoke_one(transport, lease_id, remaining / attempts_left, needles)
                .await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn revoke_one(
        &self,
        transport: &dyn UpstreamTransport,
        lease_id: &str,
        timeout: Duration,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), VaultDynamicError> {
        let mut body = Zeroizing::new(Vec::with_capacity(lease_id.len() + 32));
        body.extend_from_slice(b"{\"lease_id\":\"");
        append_json_string(lease_id, &mut body)?;
        body.extend_from_slice(b"\",\"sync\":true}");
        let request = UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Post,
            path: "/v1/sys/leases/revoke".to_owned(),
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
            auth_header: (
                "x-vault-token".to_owned(),
                Zeroizing::new(self.token.to_vec()),
            ),
            body: std::mem::take(&mut *body),
            timeout,
            response_max_bytes: 1024,
        };
        if !outbound_headers_are_valid(&request) {
            return Err(VaultDynamicError::InvalidCredential);
        }
        let response = tokio::time::timeout(timeout, transport.send(request))
            .await
            .map_err(|_| VaultDynamicError::Deadline)?
            .map_err(|_| VaultDynamicError::RevokeTransport)?;
        if contains_secret(&response.body, needles)
            || headers_contain_secret(&response.headers, needles)
        {
            return Err(VaultDynamicError::RevokeReflected);
        }
        if response.status != 204 || !response.body.is_empty() {
            return Err(VaultDynamicError::RevokeRejected);
        }
        Ok(())
    }
}

impl AcquisitionFailure {
    fn definite(error: VaultDynamicError) -> Self {
        Self {
            error,
            lease_ids: Vec::new(),
            indeterminate: false,
        }
    }

    fn uncertain(error: VaultDynamicError) -> Self {
        Self {
            error,
            lease_ids: Vec::new(),
            indeterminate: true,
        }
    }

    fn with_ids(
        error: VaultDynamicError,
        lease_ids: Vec<Zeroizing<String>>,
        indeterminate: bool,
    ) -> Self {
        Self {
            error,
            lease_ids,
            indeterminate,
        }
    }
}

struct ParsedIssued {
    lease_id: Zeroizing<String>,
    lease_duration: u64,
    value: Zeroizing<Vec<u8>>,
}

struct IssuedSeed<'a> {
    key: &'a str,
}

impl<'de> DeserializeSeed<'de> for IssuedSeed<'_> {
    type Value = ParsedIssued;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(IssuedVisitor { key: self.key })
    }
}

struct IssuedVisitor<'a> {
    key: &'a str,
}

impl<'de> Visitor<'de> for IssuedVisitor<'_> {
    type Value = ParsedIssued;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Vault dynamic lease response")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut lease_id = None;
        let mut lease_duration = None;
        let mut renewable = None;
        let mut value = None;
        while let Some(field) = map.next_key::<&str>()? {
            match field {
                "lease_id" => set_once(&mut lease_id, map.next_value_seed(LeaseIdSeed)?)?,
                "lease_duration" => set_once(&mut lease_duration, map.next_value()?)?,
                "renewable" => set_once(&mut renewable, map.next_value::<bool>()?)?,
                "data" => set_once(&mut value, map.next_value_seed(DataSeed { key: self.key })?)?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let lease_id = lease_id.ok_or_else(|| serde::de::Error::missing_field("lease_id"))?;
        if lease_id.is_empty()
            || lease_id.len() > LEASE_ID_MAX_BYTES
            || !lease_id.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(serde::de::Error::custom("invalid lease_id"));
        }
        let lease_duration =
            lease_duration.ok_or_else(|| serde::de::Error::missing_field("lease_duration"))?;
        if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&lease_duration) {
            return Err(serde::de::Error::custom("invalid lease_duration"));
        }
        renewable.ok_or_else(|| serde::de::Error::missing_field("renewable"))?;
        let value = value.ok_or_else(|| serde::de::Error::missing_field("data"))?;
        Ok(ParsedIssued {
            lease_id,
            lease_duration,
            value,
        })
    }
}

fn set_once<T, E: serde::de::Error>(slot: &mut Option<T>, value: T) -> Result<(), E> {
    if slot.replace(value).is_some() {
        return Err(E::custom("duplicate required field"));
    }
    Ok(())
}

struct DataSeed<'a> {
    key: &'a str,
}

impl<'de> DeserializeSeed<'de> for DataSeed<'_> {
    type Value = Zeroizing<Vec<u8>>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(DataVisitor { key: self.key })
    }
}

struct DataVisitor<'a> {
    key: &'a str,
}

impl<'de> Visitor<'de> for DataVisitor<'_> {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Vault data object containing the configured key")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut selected = None;
        while let Some(field) = map.next_key::<&str>()? {
            if field == self.key {
                set_once(&mut selected, map.next_value_seed(SecretValueSeed)?)?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        let value = selected.ok_or_else(|| serde::de::Error::custom("missing selected value"))?;
        if value.is_empty()
            || value.len() > RESOLVED_VALUE_MAX_BYTES
            || !value.iter().all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(serde::de::Error::custom("invalid selected value"));
        }
        Ok(value)
    }
}

struct SecretValueSeed;

impl<'de> DeserializeSeed<'de> for SecretValueSeed {
    type Value = Zeroizing<Vec<u8>>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_string(SecretValueVisitor)
    }
}

struct SecretValueVisitor;

impl Visitor<'_> for SecretValueVisitor {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }

    fn visit_string<E: serde::de::Error>(self, mut value: String) -> Result<Self::Value, E> {
        let output = Zeroizing::new(value.as_bytes().to_vec());
        value.zeroize();
        Ok(output)
    }
}

struct LeaseIdSeed;

impl<'de> DeserializeSeed<'de> for LeaseIdSeed {
    type Value = Zeroizing<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_string(LeaseIdVisitor)
    }
}

struct LeaseIdVisitor;

impl Visitor<'_> for LeaseIdVisitor {
    type Value = Zeroizing<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a lease identifier string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, mut value: String) -> Result<Self::Value, E> {
        let output = Zeroizing::new(value.clone());
        value.zeroize();
        Ok(output)
    }
}

struct LeaseProbe {
    lease_ids: Vec<Zeroizing<String>>,
    occurrences: usize,
    truncated: bool,
}

fn probe_lease_ids(body: &[u8]) -> LeaseProbe {
    let mut result = LeaseProbe {
        lease_ids: Vec::new(),
        occurrences: 0,
        truncated: false,
    };
    let key = br#""lease_id""#;
    let mut offset = 0;
    while let Some(relative) = body[offset..]
        .windows(key.len())
        .position(|window| window == key)
    {
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
        let start = cursor;
        while body
            .get(cursor)
            .is_some_and(|byte| *byte != b'"' && *byte != b'\\')
        {
            cursor += 1;
        }
        if body.get(cursor) != Some(&b'"') {
            offset = cursor.saturating_add(1);
            continue;
        }
        let value = &body[start..cursor];
        if !value.is_empty()
            && value.len() <= LEASE_ID_MAX_BYTES
            && value.iter().all(|byte| byte.is_ascii_graphic())
        {
            result.occurrences = result.occurrences.saturating_add(1);
            if !result
                .lease_ids
                .iter()
                .any(|known| known.as_bytes() == value)
            {
                if result.lease_ids.len() == LEASE_CAPTURE_LIMIT {
                    result.truncated = true;
                } else if let Ok(id) = String::from_utf8(value.to_vec()) {
                    result.lease_ids.push(Zeroizing::new(id));
                }
            }
        }
        offset = cursor + 1;
    }
    result
}

fn append_json_string(value: &str, output: &mut Vec<u8>) -> Result<(), VaultDynamicError> {
    for byte in value.bytes() {
        match byte {
            b'"' => output.extend_from_slice(br#"\""#),
            b'\\' => output.extend_from_slice(br#"\\"#),
            0x21..=0x7e => output.push(byte),
            _ => return Err(VaultDynamicError::InvalidCredential),
        }
    }
    Ok(())
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
#[path = "vault_dynamic_tests.rs"]
mod tests;
