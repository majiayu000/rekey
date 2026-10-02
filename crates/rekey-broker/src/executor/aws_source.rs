//! One fixed Secrets Manager version read with imported temporary credentials.
use aws_lc_rs::hmac;
use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::*;

const RESPONSE_LIMIT: u32 = 64 * 1024;
const VALUE_LIMIT: usize = 8 * 1024;
const TARGET: &str = "secretsmanager.GetSecretValue";
const SIGNED_HEADERS: &str = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AwsSourceError {
    InvalidCredential,
    Expired,
    Response,
    Version,
}
impl AwsSourceError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::InvalidCredential => "aws-source-invalid",
            Self::Expired => "aws-source-expired",
            Self::Response => "aws-source-response",
            Self::Version => "aws-source-version",
        }
    }
}
pub(crate) struct AwsSourceProfile {
    origin: HttpsOrigin,
    region: String,
    secret_arn: String,
    version_id: String,
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
    expires_at_ms: i64,
}
pub(super) struct AwsPrepared {
    pub(super) credential_version: u64,
    pub(super) profile: Result<AwsSourceProfile, AwsSourceError>,
    pub(super) needles: Vec<Zeroizing<Vec<u8>>>,
}
fn secret_string<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    credential_type: String,
    origin: String,
    region: String,
    secret_arn: String,
    version_id: String,
    #[serde(deserialize_with = "secret_string")]
    access_key_id: Zeroizing<String>,
    #[serde(deserialize_with = "secret_string")]
    secret_access_key: Zeroizing<String>,
    #[serde(deserialize_with = "secret_string")]
    session_token: Zeroizing<String>,
    credentials_expires_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceResponse {
    #[serde(rename = "ARN")]
    arn: String,
    #[serde(rename = "VersionId")]
    version_id: String,
    #[serde(rename = "SecretString", deserialize_with = "secret_string")]
    value: Zeroizing<String>,
    #[serde(rename = "Name", default, deserialize_with = "optional")]
    _name: Option<String>,
    #[serde(rename = "CreatedDate", default, deserialize_with = "optional")]
    _created: Option<f64>,
    #[serde(rename = "VersionStages", default, deserialize_with = "optional")]
    _stages: Option<Vec<String>>,
}
#[derive(Serialize)]
struct SourceRequest<'a> {
    #[serde(rename = "SecretId")]
    secret_arn: &'a str,
    #[serde(rename = "VersionId")]
    version_id: &'a str,
}
impl AwsSourceProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, AwsSourceError> {
        Self::parse_at(
            secret,
            crate::now_ts()
                .map_err(|_| AwsSourceError::InvalidCredential)?
                .as_unix_ms(),
        )
    }
    fn parse_at(secret: &[u8], now_ms: i64) -> Result<Self, AwsSourceError> {
        if secret.len() > RESPONSE_LIMIT as usize {
            return Err(AwsSourceError::InvalidCredential);
        }
        let raw: RawProfile =
            serde_json::from_slice(secret).map_err(|_| AwsSourceError::InvalidCredential)?;
        let origin =
            HttpsOrigin::parse(&raw.origin).map_err(|_| AwsSourceError::InvalidCredential)?;
        let expected = format!("https://secretsmanager.{}.amazonaws.com", raw.region);
        if raw.credential_type != "aws-secrets-manager-source-v1"
            || !valid_region(&raw.region)
            || raw.origin != expected
            || origin.as_str() != expected
            || !valid_arn(&raw.secret_arn, &raw.region)
            || !(32..=64).contains(&raw.version_id.chars().count())
            || raw.version_id.chars().any(char::is_control)
            || !(1..=128).contains(&raw.access_key_id.len())
            || !raw.access_key_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || raw.secret_access_key.is_empty()
            || raw.secret_access_key.len() > 16 * 1024
            || raw.session_token.is_empty()
            || raw.session_token.len() > 16 * 1024
            || reqwest::header::HeaderValue::from_bytes(raw.session_token.as_bytes()).is_err()
            || !raw
                .credentials_expires_at_ms
                .checked_sub(now_ms)
                .is_some_and(|n| (1..=3_600_000).contains(&n))
        {
            return Err(AwsSourceError::InvalidCredential);
        }
        Ok(Self {
            origin,
            region: raw.region,
            secret_arn: raw.secret_arn,
            version_id: raw.version_id,
            access_key_id: raw.access_key_id,
            secret_access_key: raw.secret_access_key,
            session_token: raw.session_token,
            expires_at_ms: raw.credentials_expires_at_ms,
        })
    }
    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), AwsSourceError> {
        Self::parse_profile(secret).map(|_| ())
    }
    pub(super) fn bootstrap_needles(&self, raw: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
        let mut result = sealing_needles(raw, raw);
        for secret in [
            self.access_key_id.as_bytes(),
            self.secret_access_key.as_bytes(),
            self.session_token.as_bytes(),
        ] {
            result.extend(sealing_needles(secret, secret));
        }
        let normalized = canonical_session_token(&self.session_token);
        result.extend(sealing_needles(
            normalized.as_bytes(),
            normalized.as_bytes(),
        ));
        result
    }
    fn public_version(&self) -> String {
        format!("{}:{}", self.secret_arn, self.version_id)
    }
    fn source_deadline(&self, action_deadline: Instant) -> Result<Instant, AwsSourceError> {
        let anchor = Instant::now();
        let now = crate::now_ts()
            .map_err(|_| AwsSourceError::Expired)?
            .as_unix_ms();
        let remaining = self
            .expires_at_ms
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or(AwsSourceError::Expired)?;
        Ok(action_deadline.min(anchor + Duration::from_millis(remaining as u64)))
    }
    fn expiry_valid(&self, deadline: Instant) -> bool {
        Instant::now() < deadline
            && crate::now_ts().is_ok_and(|n| n.as_unix_ms() < self.expires_at_ms)
    }
    fn request(&self, timeout: Duration) -> Result<UpstreamRequest, AwsSourceError> {
        let now = crate::now_ts()
            .map_err(|_| AwsSourceError::Expired)?
            .as_unix_ms();
        self.request_at(timeout, now)
    }
    fn request_at(
        &self,
        timeout: Duration,
        now_ms: i64,
    ) -> Result<UpstreamRequest, AwsSourceError> {
        let (date, stamp) = utc_date(now_ms)?;
        let body = Zeroizing::new(
            serde_json::to_vec(&SourceRequest {
                secret_arn: &self.secret_arn,
                version_id: &self.version_id,
            })
            .map_err(|_| AwsSourceError::InvalidCredential)?,
        );
        let token = canonical_session_token(&self.session_token);
        let canonical = Zeroizing::new(format!(
            "POST\n/\n\ncontent-type:application/x-amz-json-1.1\nhost:{}\nx-amz-date:{stamp}\nx-amz-security-token:{}\nx-amz-target:{TARGET}\n\n{SIGNED_HEADERS}\n{}",
            self.origin.host(),
            token.as_str(),
            hex(&Sha256::digest(&body))
        ));
        let signature = sign(
            &self.secret_access_key,
            &date,
            &self.region,
            "secretsmanager",
            &stamp,
            &canonical,
        );
        let authorization=Zeroizing::new(format!("AWS4-HMAC-SHA256 Credential={}/{date}/{}/secretsmanager/aws4_request, SignedHeaders={SIGNED_HEADERS}, Signature={}",self.access_key_id.as_str(),self.region,signature.as_str()).into_bytes());
        Ok(UpstreamRequest {
            host: self.origin.host().into(),
            port: 443,
            method: FixedMethod::Post,
            path: "/".into(),
            headers: vec![
                ("content-type".into(), "application/x-amz-json-1.1".into()),
                ("host".into(), self.origin.host().into()),
                ("x-amz-date".into(), stamp),
                (
                    "x-amz-security-token".into(),
                    self.session_token.to_string(),
                ),
                ("x-amz-target".into(), TARGET.into()),
            ],
            auth_header: ("authorization".into(), authorization),
            body,
            timeout,
            response_max_bytes: RESPONSE_LIMIT,
        })
    }
    fn resolve(
        &self,
        response: &crate::upstream::UpstreamResponse,
    ) -> Result<Zeroizing<Vec<u8>>, AwsSourceError> {
        if response.status != 200 || response.body.len() > RESPONSE_LIMIT as usize {
            return Err(AwsSourceError::Response);
        }
        let parsed: SourceResponse =
            serde_json::from_slice(&response.body).map_err(|_| AwsSourceError::Response)?;
        if parsed.arn != self.secret_arn || parsed.version_id != self.version_id {
            return Err(AwsSourceError::Version);
        }
        if parsed.value.is_empty() || parsed.value.len() > VALUE_LIMIT {
            return Err(AwsSourceError::Response);
        }
        Ok(Zeroizing::new(parsed.value.as_bytes().to_vec()))
    }
}
fn canonical_session_token(token: &str) -> Zeroizing<String> {
    Zeroizing::new(token.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
}

fn valid_region(region: &str) -> bool {
    (3..=64).contains(&region.len())
        && !["cn-", "us-gov-", "us-iso"]
            .iter()
            .any(|p| region.starts_with(p))
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && region.split('-').count() >= 3
        && region.split('-').all(|p| !p.is_empty())
        && region.as_bytes()[0].is_ascii_lowercase()
        && region
            .rsplit('-')
            .next()
            .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
}
fn valid_arn(arn: &str, region: &str) -> bool {
    if arn.len() > 2048 {
        return false;
    }
    let parts: Vec<_> = arn.split(':').collect();
    if parts.len() != 7
        || parts[..3] != ["arn", "aws", "secretsmanager"]
        || parts[3] != region
        || parts[4].len() != 12
        || !parts[4].bytes().all(|b| b.is_ascii_digit())
        || parts[5] != "secret"
    {
        return false;
    }
    let name = parts[6];
    name.rsplit_once('-').is_some_and(|(name, suffix)| {
        !name.is_empty() && suffix.len() == 6 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    }) && name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/_+=.@-".contains(&b))
}
fn utc_date(now_ms: i64) -> Result<(String, String), AwsSourceError> {
    let now = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
        .map_err(|_| AwsSourceError::InvalidCredential)?;
    let date = format!(
        "{:04}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    Ok((
        date.clone(),
        format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        ),
    ))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn mac(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Zeroizing::new(hmac::sign(&key, data).as_ref().to_vec())
}
fn sign(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
    stamp: &str,
    canonical: &str,
) -> Zeroizing<String> {
    let initial = Zeroizing::new(format!("AWS4{secret}"));
    let date_key = mac(initial.as_bytes(), date.as_bytes());
    let region_key = mac(&date_key, region.as_bytes());
    let service_key = mac(&region_key, service.as_bytes());
    let key = mac(&service_key, b"aws4_request");
    let to_sign = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{date}/{region}/{service}/aws4_request\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    ));
    Zeroizing::new(hex(&mac(&key, to_sign.as_bytes())))
}

impl ActionExecutor {
    pub(super) async fn resolve_aws_source(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        mut prepared: AwsPrepared,
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
            rekey_vault::model::event_type::AWS_SOURCE_READ_STARTED,
            "success",
            profile.public_version(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        let upstream =
            match profile.request(source_deadline.saturating_duration_since(Instant::now())) {
                Ok(upstream) => upstream,
                Err(e) => {
                    started.blocked_until(effect_deadline, e.reason()).await?;
                    return Err(BrokerError::Upstream(e.reason()));
                }
            };
        prepared.needles.extend(sealing_needles(
            &upstream.auth_header.1,
            &upstream.auth_header.1,
        ));
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, AwsSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(AwsSourceError::Expired.reason()));
        }
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-aws-source-header")
                .await?;
            return Err(BrokerError::Denied("invalid-aws-source-header"));
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
                        "aws-source-response-too-large"
                    }
                    Ok(Err(crate::upstream::UpstreamError::Blocked(r))) => reason_static(r),
                    _ => "aws-source-transport",
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
                .blocked_until(effect_deadline, "aws-source-reflected-secret")
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
        if contains_secret(&resolved, &prepared.needles) {
            started
                .blocked_until(effect_deadline, "aws-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, AwsSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(AwsSourceError::Expired.reason()));
        }
        let mut auth = Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec());
        auth.extend_from_slice(&resolved);
        let mut needles = prepared.needles;
        needles.extend(fixed_header_sealing_needles(
            &resolved,
            &auth,
            action.auth.prefix.as_str().as_bytes(),
        ));
        let upstream = build_upstream(action, request, auth);
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-upstream-header")
                .await?;
            return Err(BrokerError::Denied("invalid-upstream-header"));
        }
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::AWS_SOURCE_RESOLVED,
            "success",
            profile.public_version(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, AwsSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(AwsSourceError::Expired.reason()));
        }
        // Imported source token lifetime does not shorten the fetched business
        // value lifetime. The caller retains the original Action deadline/gate.
        Ok(PreparedExecution::Opaque { upstream, needles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ARN: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture/name-Ab12Cd";
    const VERSION: &str = "fixture-version-nonhex-00000000001";
    fn profile(expiry: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"credential_type":"aws-secrets-manager-source-v1","origin":"https://secretsmanager.us-east-1.amazonaws.com","region":"us-east-1","secret_arn":ARN,"version_id":VERSION,"access_key_id":"ASIAFIXTUREONLYKEY","secret_access_key":"fixture-secret-access-key","session_token":"fixture-source-bearer","credentials_expires_at_ms":expiry})).unwrap()
    }
    fn response(value: &str) -> crate::upstream::UpstreamResponse {
        crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(
                serde_json::to_vec(
                    &serde_json::json!({"ARN":ARN,"VersionId":VERSION,"SecretString":value}),
                )
                .unwrap(),
            ),
        }
    }
    #[test]
    fn published_aws_sdk_sigv4_vector_uses_actual_derivation() {
        // AWS-maintained botocore aws4_testsuite/get-vanilla.{creq,sts,authz}.
        let canonical = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            hex(&Sha256::digest(canonical.as_bytes())),
            "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        assert_eq!(
            sign(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "20150830",
                "us-east-1",
                "service",
                "20150830T123600Z",
                canonical
            )
            .as_str(),
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
    #[test]
    fn fixed_request_exact_bytes_signature_and_utc_boundary() {
        let p = AwsSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let request = p
            .request_at(Duration::from_secs(1), 1_445_171_760_000)
            .unwrap();
        assert_eq!(request.path, "/");
        assert_eq!(request.method, FixedMethod::Post);
        assert_eq!(
            request.body.as_slice(),
            format!("{{\"SecretId\":\"{ARN}\",\"VersionId\":\"{VERSION}\"}}").as_bytes()
        );
        assert_eq!(
            request.headers[2],
            ("x-amz-date".into(), "20151018T123600Z".into())
        );
        assert_eq!(
            request.headers[3],
            (
                "x-amz-security-token".into(),
                "fixture-source-bearer".into()
            )
        );
        assert_eq!(
            std::str::from_utf8(&request.auth_header.1).unwrap(),
            "AWS4-HMAC-SHA256 Credential=ASIAFIXTUREONLYKEY/20151018/us-east-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=5fedc08eaab090d6cf78af4c597c272f3184ef2df8abf51f6a0f1df8ce5e89bc"
        );
        assert_eq!(
            utc_date(0).unwrap(),
            ("19700101".into(), "19700101T000000Z".into())
        );
        assert_eq!(
            utc_date(1_709_251_199_999).unwrap(),
            ("20240229".into(), "20240229T235959Z".into())
        );
    }
    #[test]
    fn profile_is_closed_fixed_and_requires_bounded_temporary_credentials() {
        let raw: serde_json::Value = serde_json::from_slice(&profile(2000)).unwrap();
        for expiry in [999, 1000, 3_601_001, i64::MAX] {
            assert!(AwsSourceProfile::parse_at(&profile(expiry), 1000).is_err());
        }
        for expiry in [1001, 3_601_000] {
            assert!(AwsSourceProfile::parse_at(&profile(expiry), 1000).is_ok());
        }
        for (field, values) in [
            (
                "origin",
                vec![
                    "https://evil.example",
                    "https://secretsmanager.us-east-1.amazonaws.com:443",
                    "http://secretsmanager.us-east-1.amazonaws.com",
                    "https://secretsmanager.us-east-1.amazonaws.com/",
                    "https://secretsmanager.us-west-2.amazonaws.com",
                ],
            ),
            (
                "region",
                vec![
                    "cn-north-1",
                    "us-gov-west-1",
                    "us-iso-east-1",
                    "US-east-1",
                    "us.east-1",
                    "us-east-one",
                    "us--1",
                ],
            ),
            (
                "secret_arn",
                vec![
                    "arn:aws:secretsmanager:us-west-2:123456789012:secret:x-Ab12Cd",
                    "arn:aws-cn:secretsmanager:us-east-1:123456789012:secret:x-Ab12Cd",
                    "arn:aws:secretsmanager:us-east-1:123:secret:x-Ab12Cd",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:x",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:x-Ab12C",
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:x%-Ab12Cd",
                ],
            ),
            (
                "version_id",
                vec!["latest", "short", "1234567890123456789012345678901\n0"],
            ),
            ("access_key_id", vec!["", "A/B", "KEY key", "key\n"]),
            ("secret_access_key", vec![""]),
            ("session_token", vec!["", "x\r\ny", "x\0y"]),
        ] {
            for bad in values {
                let mut r = raw.clone();
                r[field] = bad.into();
                assert!(
                    AwsSourceProfile::parse_at(&serde_json::to_vec(&r).unwrap(), 1000).is_err(),
                    "{field}"
                );
            }
        }
        for field in ["access_key_id", "secret_access_key", "session_token"] {
            let mut r = raw.clone();
            r[field] = "x"
                .repeat(if field == "access_key_id" { 129 } else { 16385 })
                .into();
            assert!(AwsSourceProfile::parse_at(&serde_json::to_vec(&r).unwrap(), 1000).is_err());
        }
        for field in raw.as_object().unwrap().keys() {
            let mut r = raw.clone();
            r.as_object_mut().unwrap().remove(field);
            assert!(AwsSourceProfile::parse_at(&serde_json::to_vec(&r).unwrap(), 1000).is_err());
        }
        for extra in [",\"session_token\":\"duplicate\"", ",\"unknown\":null"] {
            let r = profile(2000);
            let r = [&r[..r.len() - 1], extra.as_bytes(), b"}"].concat();
            assert!(AwsSourceProfile::parse_at(&r, 1000).is_err());
        }
        let mut r = raw;
        r["version_id"] = "非".repeat(32).into();
        assert!(AwsSourceProfile::parse_at(&serde_json::to_vec(&r).unwrap(), 1000).is_ok());
    }
    #[test]
    fn response_exact_version_closed_fields_real_metadata_types_binary_and_value_bounds() {
        let p = AwsSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let mut good = response("  完整 secret  ");
        let mut raw: serde_json::Value = serde_json::from_slice(&good.body).unwrap();
        raw["Name"] = "fixture/name".into();
        raw["CreatedDate"] = serde_json::json!(1_445_171_760.5);
        raw["VersionStages"] = serde_json::json!(["AWSCURRENT"]);
        good.body = Zeroizing::new(serde_json::to_vec(&raw).unwrap());
        assert_eq!(&*p.resolve(&good).unwrap(), "  完整 secret  ".as_bytes());
        for (field, bad) in [
            ("ARN", serde_json::json!("wrong")),
            ("VersionId", serde_json::json!("wrong")),
            ("SecretString", serde_json::json!("")),
            ("SecretString", serde_json::json!("x".repeat(8193))),
            ("Name", serde_json::json!(0)),
            ("CreatedDate", serde_json::json!("0")),
            ("VersionStages", serde_json::json!([1])),
            ("SecretBinary", serde_json::Value::Null),
            ("SecretBinary", serde_json::json!("YQ==")),
            ("unknown", serde_json::Value::Null),
        ] {
            let mut r = raw.clone();
            r[field] = bad;
            good.body = Zeroizing::new(serde_json::to_vec(&r).unwrap());
            assert!(p.resolve(&good).is_err(), "{field}");
        }
        for field in [
            "ARN",
            "VersionId",
            "SecretString",
            "Name",
            "CreatedDate",
            "VersionStages",
        ] {
            let mut r = raw.clone();
            r[field] = serde_json::Value::Null;
            good.body = Zeroizing::new(serde_json::to_vec(&r).unwrap());
            assert!(p.resolve(&good).is_err());
        }
        for field in raw.as_object().unwrap().keys() {
            let bytes = serde_json::to_vec(&raw).unwrap();
            let extra = format!(",\"{field}\":{}", raw[field]);
            good.body =
                Zeroizing::new([&bytes[..bytes.len() - 1], extra.as_bytes(), b"}"].concat());
            assert!(p.resolve(&good).is_err());
        }
        assert_eq!(p.resolve(&response(&"x".repeat(8192))).unwrap().len(), 8192);
        good.body = Zeroizing::new(vec![b'x'; 65537]);
        assert!(p.resolve(&good).is_err());
    }
    // Real Authority actor/SQLite/envelope tests do not need listeners. They
    // complement (not replace) the strict UDS/TLS integration contracts.
    struct ActorFixture {
        _dir: tempfile::TempDir,
        state: std::path::PathBuf,
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
            rekey_vault::bootstrap::init_vault(
                &state,
                &SecretInput::from_slice(b"actor-proof"),
                rekey_vault::crypto::kdf::Argon2Params {
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1,
                },
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
                    CredentialLabel::new("aws-actor").unwrap(),
                    CredentialKind::AwsSecretsManagerSource,
                    SecretInput::from_slice(&profile(now + expires_in_ms)),
                    Self::proof(),
                )
                .await
                .unwrap();
            let action: FixedHttpAction = serde_json::from_value(serde_json::json!({"id":rekey_domain::ids::ActionId::new_random(),"name":"actor-action","version":1,"enabled":true,"credential_id":credential.id,"origin":"https://api.example.com","method":"POST","exact_path":"/business","auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":timeout_ms,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":1024,"allowed_headers":["content-type"]}})).unwrap();
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
                body: b"{}".to_vec(),
                approval_grants: vec![],
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
        assert_eq!(sent[0].host, "secretsmanager.us-east-1.amazonaws.com");
        assert_eq!(sent[0].method, "POST");
        assert_eq!(sent[0].port, 443);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&sent[0].body).unwrap(),
            serde_json::json!({"SecretId":ARN,"VersionId":VERSION})
        );
        assert_eq!(sent[1].auth_value, b"Bearer 123456789");
        let db = f.db();
        let events:Vec<String>=db.prepare("SELECT event_type FROM audit_events WHERE request_id IS NOT NULL ORDER BY sequence").unwrap().query_map([],|r|r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(
            events,
            [
                "execution.started",
                "aws.source.read_started",
                "aws.source.resolved",
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
            ("aws.source.read_started", 0),
            ("aws.source.resolved", 1),
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
        for form in sealing_needles(b"fixture-source-bearer", b"fixture-source-bearer") {
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
                if draft.event_type == rekey_vault::model::event_type::AWS_SOURCE_RESOLVED {
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
        raw["session_token"] = token.into();
        f.authority
            .credential_rotate_typed_before(
                f.action.credential_id,
                rekey_domain::credential::CredentialKind::AwsSecretsManagerSource,
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
                        assert_eq!(requests[0].host, "secretsmanager.us-east-1.amazonaws.com");
                    }
                }
            }
            assert_eq!(
                f.db()
                    .query_row(
                        "SELECT count(*) FROM audit_events WHERE event_type='aws.source.resolved'",
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
                let event = if request.host == "secretsmanager.us-east-1.amazonaws.com" {
                    "aws.source.read_started"
                } else {
                    "aws.source.resolved"
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
                assert_eq!(request.host, "secretsmanager.us-east-1.amazonaws.com");
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
    async fn actor_all_imported_fields_and_exact_raw_profile_are_sealed_before_parse_or_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let raw = profile(crate::now_ts().unwrap().as_unix_ms() + 60_000);
        f.authority
            .credential_rotate_typed_before(
                f.action.credential_id,
                rekey_domain::credential::CredentialKind::AwsSecretsManagerSource,
                Some(1),
                rekey_vault::secret::SecretInput::from_slice(&raw),
                ActorFixture::proof(),
                None,
            )
            .await
            .unwrap();
        for secret in [
            b"ASIAFIXTUREONLYKEY".as_slice(),
            b"fixture-secret-access-key",
            b"fixture-source-bearer",
            raw.as_slice(),
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
        let db = f.db();
        let mut stmt = db.prepare("SELECT reason_code FROM audit_events").unwrap();
        let reasons: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(reasons.iter().all(|r| !r.contains("ASIAFIXTUREONLYKEY")
            && !r.contains("fixture-secret-access-key")
            && !r.contains("fixture-source-bearer")));
        drop(stmt);
        drop(db);
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_provider_failures_malformed_binary_and_version_mismatch_have_no_business_or_raw_error_audit()
     {
        let f = ActorFixture::new(60_000, 30_000).await;
        for status in [401, 403, 404, 500] {
            let mut r = ActorFixture::resolved(b"123456789");
            r.status = status;
            r.body = Zeroizing::new(b"synthetic-provider-error-id-opaque".to_vec());
            f.fake.push_response(Ok(r));
            assert!(f.run().await.is_err());
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        for field in ["ARN", "VersionId", "SecretBinary", "unknown"] {
            let mut r = ActorFixture::resolved(b"123456789");
            let mut raw: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            raw[field] = serde_json::Value::Null;
            r.body = Zeroizing::new(serde_json::to_vec(&raw).unwrap());
            f.fake.push_response(Ok(r));
            assert!(f.run().await.is_err());
            assert_eq!(f.fake.take_requests().len(), 1);
        }
        let db = f.db();
        let reasons: String = db
            .prepare("SELECT reason_code FROM audit_events")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!reasons.contains("synthetic-provider-error-id-opaque"));
        drop(db);
        f.finish().await;
    }
    #[tokio::test]
    async fn actor_normalized_sts_token_reflections_never_cross_source_or_business_boundaries() {
        for token in [
            "  edge-source-token  ",
            "\tedge-tab-token\t",
            "internal  source\ttoken",
        ] {
            let f = ActorFixture::new(60_000, 30_000).await;
            rotate_actor_bootstrap(&f, token).await;
            let normalized = token.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
            let mut raw: serde_json::Value =
                serde_json::from_slice(&profile(crate::now_ts().unwrap().as_unix_ms() + 60_000))
                    .unwrap();
            raw["session_token"] = token.into();
            let raw = serde_json::to_vec(&raw).unwrap();
            let bootstrap = AwsSourceProfile::parse_profile(&raw).unwrap();
            let bootstrap_needles = bootstrap.bootstrap_needles(&raw);
            for business in [false, true] {
                for location in 0..3 {
                    if business {
                        let source = ActorFixture::resolved(b"123456789");
                        assert!(!contains_secret(&source.body, &bootstrap_needles));
                        f.fake.push_response(Ok(source));
                    }
                    let mut r = if business {
                        crate::upstream::UpstreamResponse {
                            status: 200,
                            headers: vec![].into(),
                            body: Zeroizing::new(b"unrelated-output".to_vec()),
                        }
                    } else if location == 0 {
                        ActorFixture::resolved(normalized.as_bytes())
                    } else {
                        ActorFixture::resolved(b"clean-source-value")
                    };
                    match location {
                        0 => {
                            if business {
                                r.body = Zeroizing::new(normalized.as_bytes().to_vec())
                            }
                        }
                        1 => {
                            r.headers = real_header_values(&[(
                                "x-provider-request-id",
                                normalized.as_bytes(),
                            )])
                        }
                        _ => {
                            r.headers = real_header_values(&[(
                                "x-provider-request-id",
                                &[b"\xff".as_slice(), normalized.as_bytes(), b"\xfe"].concat(),
                            )])
                        }
                    }
                    if location != 0 {
                        // Header bytes are the sole reflection trigger: both
                        // source and business bodies have passed independent scans.
                        assert!(!contains_secret(&r.body, &bootstrap_needles));
                        if business {
                            assert!(!contains_secret(
                                &r.body,
                                &sealing_needles(b"123456789", b"Bearer 123456789")
                            ));
                        }
                        assert!(headers_contain_secret(&r.headers, &bootstrap_needles));
                    } else {
                        assert!(contains_secret(&r.body, &bootstrap_needles));
                        assert!(!headers_contain_secret(&r.headers, &bootstrap_needles));
                    }
                    f.fake.push_response(Ok(r));
                    assert!(
                        matches!(f.run().await, Err(BrokerError::ResponseSecurityViolation)),
                        "normalized token reached business: token={token:?} business={business} location={location}"
                    );
                    assert_eq!(f.fake.take_requests().len(), if business { 2 } else { 1 });
                }
            }
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn actor_legal_unreflected_sts_whitespace_keeps_raw_header_and_independent_normalized_signature()
     {
        // Expected signatures derived independently with Python stdlib hmac/hashlib.
        for (token, signature) in [
            (
                "  edge-source-token  ",
                "cbdcbb111c87a3bd19846c6460c1ae488a2135496db751d55383c8df522b7fe1",
            ),
            (
                "\tedge-tab-token\t",
                "ff2593a726741c342cf766c01e0e47304a5e6fc0881c93b0f13074907a796419",
            ),
            (
                "internal  source\ttoken",
                "6bb2e8d2fc04bfc112e3ad345133e8e6f0bbc5757bcf75f57b627919c9b3cd22",
            ),
        ] {
            let mut raw: serde_json::Value = serde_json::from_slice(&profile(2000)).unwrap();
            raw["session_token"] = token.into();
            let p = AwsSourceProfile::parse_at(&serde_json::to_vec(&raw).unwrap(), 1000).unwrap();
            let signed = p
                .request_at(Duration::from_secs(1), 1_445_171_760_000)
                .unwrap();
            assert_eq!(signed.headers[3].1, token);
            assert!(
                std::str::from_utf8(&signed.auth_header.1)
                    .unwrap()
                    .ends_with(&format!("Signature={signature}"))
            );
            let f = ActorFixture::new(60_000, 30_000).await;
            rotate_actor_bootstrap(&f, token).await;
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
            assert_eq!(sent[0].headers[3].1, token);
            assert_eq!(sent[1].auth_value, b"Bearer 123456789");
            f.finish().await;
        }
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
        let mut outcomes = Vec::new();
        let value = b" \t edge-business-value \t ";
        let raw_auth = [b"Bearer ".as_slice(), value].concat();
        for bytes in sealing_needles(b"edge-business-value", b"Bearer edge-business-value")
            .into_iter()
            .chain(sealing_needles(
                b"edge-business-value",
                b"Bearer  \t edge-business-value",
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
                let result = f.run().await;
                outcomes.push(matches!(
                    result,
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
        assert!(
            outcomes.iter().all(|sealed| *sealed),
            "unsealed encoded outcomes: {outcomes:?}"
        );
    }
    #[tokio::test]
    async fn actor_decoded_selected_bootstrap_never_crosses_into_business() {
        let f = ActorFixture::new(60_000, 30_000).await;
        let token = "bootstrap-quote\"-backslash\\-fixture";
        rotate_actor_bootstrap(&f, token).await;
        let source = ActorFixture::resolved(token.as_bytes());
        let parsed = AwsSourceProfile::parse_profile(
            &serde_json::to_vec(&{
                let mut raw: serde_json::Value = serde_json::from_slice(&profile(
                    crate::now_ts().unwrap().as_unix_ms() + 60_000,
                ))
                .unwrap();
                raw["session_token"] = token.into();
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
                    "SELECT count(*) FROM audit_events WHERE event_type='aws.source.resolved'",
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
        for form in sealing_needles(b"fixture-source-bearer", b"fixture-source-bearer") {
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
                &sealing_needles(b"fixture-source-bearer", b"fixture-source-bearer")
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
