//! One fixed SecretVersion access, without discovery, refresh or caching.
use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use rekey_domain::action::{FixedMethod, HttpsOrigin};
use serde::{Deserialize, Deserializer};

use super::*;

const ORIGIN: &str = "https://secretmanager.googleapis.com";
const RESPONSE_LIMIT: u32 = 64 * 1024;
const VALUE_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GcpSourceError {
    InvalidCredential,
    Expired,
    Response,
    Version,
    Checksum,
}
impl GcpSourceError {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::InvalidCredential => "gcp-source-invalid",
            Self::Expired => "gcp-source-expired",
            Self::Response => "gcp-source-response",
            Self::Version => "gcp-source-version",
            Self::Checksum => "gcp-source-checksum",
        }
    }
}

pub(crate) struct GcpSourceProfile {
    origin: HttpsOrigin,
    secret_version: String,
    token: Zeroizing<String>,
    expires_at_ms: i64,
}

pub(super) struct GcpPrepared {
    pub(super) credential_version: u64,
    pub(super) profile: Result<GcpSourceProfile, GcpSourceError>,
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
    secret_version: String,
    #[serde(deserialize_with = "secret_string")]
    access_token: Zeroizing<String>,
    access_token_expires_at_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceResponse {
    name: String,
    payload: SourcePayload,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePayload {
    #[serde(deserialize_with = "secret_string")]
    data: Zeroizing<String>,
    #[serde(rename = "dataCrc32c")]
    checksum: String,
}

impl GcpSourceProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, GcpSourceError> {
        let now = crate::now_ts().map_err(|_| GcpSourceError::InvalidCredential)?;
        Self::parse_at(secret, now.as_unix_ms())
    }

    fn parse_at(secret: &[u8], now_ms: i64) -> Result<Self, GcpSourceError> {
        let raw: RawProfile =
            serde_json::from_slice(secret).map_err(|_| GcpSourceError::InvalidCredential)?;
        let origin =
            HttpsOrigin::parse(&raw.origin).map_err(|_| GcpSourceError::InvalidCredential)?;
        if raw.credential_type != "gcp-secret-manager-source-v1"
            || origin.as_str() != ORIGIN
            || !valid_version(&raw.secret_version)
            || raw.access_token.is_empty()
            || raw.access_token.len() > 16 * 1024
            || reqwest::header::HeaderValue::from_bytes(raw.access_token.as_bytes()).is_err()
        {
            return Err(GcpSourceError::InvalidCredential);
        }
        let remaining = raw
            .access_token_expires_at_ms
            .checked_sub(now_ms)
            .ok_or(GcpSourceError::InvalidCredential)?;
        if !(1..=3_600_000).contains(&remaining) {
            return Err(GcpSourceError::InvalidCredential);
        }
        Ok(Self {
            origin,
            secret_version: raw.secret_version,
            token: raw.access_token,
            expires_at_ms: raw.access_token_expires_at_ms,
        })
    }

    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), GcpSourceError> {
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
    fn source_deadline(&self, action_deadline: Instant) -> Result<Instant, GcpSourceError> {
        // Anchor before sending, never grant a fresh TTL at response arrival.
        let anchor = Instant::now();
        let now = crate::now_ts()
            .map_err(|_| GcpSourceError::Expired)?
            .as_unix_ms();
        let remaining = self
            .expires_at_ms
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or(GcpSourceError::Expired)?;
        Ok(action_deadline.min(anchor + Duration::from_millis(remaining as u64)))
    }
    fn expiry_valid(&self, source_deadline: Instant) -> bool {
        Instant::now() < source_deadline
            && crate::now_ts().is_ok_and(|now| now.as_unix_ms() < self.expires_at_ms)
    }
    fn request(&self, timeout: Duration) -> UpstreamRequest {
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Get,
            path: format!("/v1/{}:access", self.secret_version),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            auth_header: ("authorization".to_owned(), self.bearer()),
            body: Zeroizing::new(Vec::new()),
            timeout,
            response_max_bytes: RESPONSE_LIMIT,
        }
    }
    fn resolve(
        &self,
        response: &crate::upstream::UpstreamResponse,
    ) -> Result<Zeroizing<Vec<u8>>, GcpSourceError> {
        if response.status != 200 || response.body.len() > RESPONSE_LIMIT as usize {
            return Err(GcpSourceError::Response);
        }
        let parsed: SourceResponse =
            serde_json::from_slice(&response.body).map_err(|_| GcpSourceError::Response)?;
        if parsed.name != self.secret_version {
            return Err(GcpSourceError::Version);
        }
        if parsed.payload.checksum.is_empty()
            || !parsed.payload.checksum.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(GcpSourceError::Checksum);
        }
        let checksum: u32 = parsed
            .payload
            .checksum
            .parse()
            .map_err(|_| GcpSourceError::Checksum)?;
        let value = decode_proto_bytes(parsed.payload.data.as_bytes())?;
        if value.is_empty() || value.len() > VALUE_LIMIT || std::str::from_utf8(&value).is_err() {
            return Err(GcpSourceError::Response);
        }
        if crc32c(&value) != checksum {
            return Err(GcpSourceError::Checksum);
        }
        Ok(value)
    }
}

fn valid_version(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != 6 || parts[0] != "projects" || parts[2] != "secrets" || parts[4] != "versions"
    {
        return false;
    }
    let project = parts[1];
    let project_ok = (!project.is_empty() && project.bytes().all(|b| b.is_ascii_digit()))
        || ((6..=30).contains(&project.len())
            && project.as_bytes()[0].is_ascii_lowercase()
            && project
                .as_bytes()
                .last()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && project
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
    let secret = parts[3];
    project_ok
        && (1..=255).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && parts[5]
            .parse::<u64>()
            .is_ok_and(|v| v != 0 && v.to_string() == parts[5])
}

fn decode_proto_bytes(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, GcpSourceError> {
    // Select alphabet and padding exactly once. data-encoding rejects nonzero
    // unused bits, misplaced padding and whitespace; never retry another codec.
    let standard = data.iter().any(|b| matches!(b, b'+' | b'/'));
    let url = data.iter().any(|b| matches!(b, b'-' | b'_'));
    if standard && url {
        return Err(GcpSourceError::Response);
    }
    let encoding = match (url, data.contains(&b'=')) {
        (false, true) => BASE64,
        (false, false) => BASE64_NOPAD,
        (true, true) => BASE64URL,
        (true, false) => BASE64URL_NOPAD,
    };
    let length = encoding
        .decode_len(data.len())
        .map_err(|_| GcpSourceError::Response)?;
    // Keep partial decoded plaintext wipe-on-drop on malformed-input errors.
    let mut value = Zeroizing::new(vec![0; length]);
    let decoded = encoding
        .decode_mut(data, &mut value)
        .map_err(|_| GcpSourceError::Response)?;
    value.truncate(decoded);
    Ok(value)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
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
    pub(super) async fn resolve_gcp_source(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: GcpPrepared,
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
            rekey_vault::model::event_type::GCP_SOURCE_READ_STARTED,
            "success",
            profile.secret_version.clone(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        let upstream = profile.request(source_deadline.saturating_duration_since(Instant::now()));
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, GcpSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(GcpSourceError::Expired.reason()));
        }
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-gcp-source-header")
                .await?;
            return Err(BrokerError::Denied("invalid-gcp-source-header"));
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
                        "gcp-source-response-too-large"
                    }
                    Ok(Err(crate::upstream::UpstreamError::Blocked(r))) => reason_static(r),
                    _ => "gcp-source-transport",
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
                .blocked_until(effect_deadline, "gcp-source-reflected-secret")
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
                .blocked_until(effect_deadline, "gcp-source-reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, GcpSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(GcpSourceError::Expired.reason()));
        }
        let mut auth = Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec());
        auth.extend_from_slice(&resolved);
        let mut needles = prepared.needles;
        needles.extend(sealing_needles(&resolved, &auth));
        let value = edge_ows(&resolved);
        if !value.is_empty() && (value != resolved.as_slice() || edge_ows(&auth) != auth.as_slice())
        {
            let mut normalized_auth =
                Zeroizing::new(action.auth.prefix.as_str().as_bytes().to_vec());
            normalized_auth.extend_from_slice(value);
            needles.extend(sealing_needles(value, edge_ows(&normalized_auth)));
            needles.extend(sealing_needles(value, edge_ows(&auth)));
        }

        let upstream = build_upstream(action, request, auth);
        if !outbound_headers_are_valid(&upstream) {
            started
                .blocked_until(effect_deadline, "invalid-upstream-header")
                .await?;
            return Err(BrokerError::Denied("invalid-upstream-header"));
        }
        let mut draft = connector_event(
            started.context(),
            rekey_vault::model::event_type::GCP_SOURCE_RESOLVED,
            "success",
            profile.secret_version.clone(),
        );
        draft.credential_version = Some(prepared.credential_version);
        self.terminals.commit_until(source_deadline, draft).await?;
        if !profile.expiry_valid(source_deadline) {
            started
                .blocked_until(effect_deadline, GcpSourceError::Expired.reason())
                .await?;
            return Err(BrokerError::Upstream(GcpSourceError::Expired.reason()));
        }
        // Imported source token lifetime does not shorten the fetched business
        // value lifetime. The caller retains the original Action deadline/gate.
        Ok(PreparedExecution::Opaque { upstream, needles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(expiry: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"credential_type":"gcp-secret-manager-source-v1","origin":ORIGIN,"secret_version":"projects/123456/secrets/fixture_key/versions/7","access_token":"fixture-source-bearer","access_token_expires_at_ms":expiry})).unwrap()
    }
    fn response(data: &str, checksum: &str) -> crate::upstream::UpstreamResponse {
        crate::upstream::UpstreamResponse { status:200, headers:vec![].into(), body:Zeroizing::new(serde_json::to_vec(&serde_json::json!({"name":"projects/123456/secrets/fixture_key/versions/7","payload":{"data":data,"dataCrc32c":checksum}})).unwrap()) }
    }
    #[test]
    fn crc32c_independent_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
        assert_eq!(crc32c(b""), 0);
    }
    #[test]
    fn four_protojson_encodings_preserve_full_utf8() {
        let value = "保持全文\u{ffff}".as_bytes();
        let p = GcpSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        for codec in [BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD] {
            assert_eq!(
                &*p.resolve(&response(&codec.encode(value), &crc32c(value).to_string()))
                    .unwrap(),
                value
            );
        }
    }
    #[test]
    fn strict_base64_rejects_mixed_padding_whitespace_and_unused_bits() {
        for bad in [
            "+_8=", "-_8/", "Zg=", "Zg===", "Z=g=", "Zg==x", "Zh==", "Zh", "Zg\n", "Zg ", "Z",
            "====",
        ] {
            assert!(decode_proto_bytes(bad.as_bytes()).is_err(), "{bad:?}");
        }
        for valid in ["Zg==", "Zg", "-_8=", "-_8", "+/8=", "+/8"] {
            assert!(decode_proto_bytes(valid.as_bytes()).is_ok(), "{valid}");
        }
    }
    #[test]
    fn expiry_resource_origin_and_header_boundaries() {
        for expiry in [1000, 999, 3_601_001, i64::MAX] {
            assert!(GcpSourceProfile::parse_at(&profile(expiry), 1000).is_err());
        }
        for expiry in [1001, 3_601_000] {
            assert!(GcpSourceProfile::parse_at(&profile(expiry), 1000).is_ok());
        }
        for bad in [
            "projects/p/secrets/s/versions/1",
            "projects/123/secrets/s/versions/latest",
            "projects/123/secrets/s/versions/01",
            "projects/123/secrets/s/versions/0",
            "projects/123/secrets/s/versions/18446744073709551616",
            "projects/123/secrets/../versions/1",
            "projects/123/secrets/x%2fy/versions/1",
            "projects/123/locations/us/secrets/s/versions/1",
            "projects/123/secrets/s/versions/1?x=y",
            "projects/123/secrets/s/versions/+1",
        ] {
            assert!(!valid_version(bad), "{bad}");
        }
        for good in [
            "projects/my-project/secrets/S_1/versions/1",
            "projects/123/secrets/s/versions/18446744073709551615",
        ] {
            assert!(valid_version(good));
        }
        let mut raw: serde_json::Value = serde_json::from_slice(&profile(2000)).unwrap();
        for origin in [
            "http://secretmanager.googleapis.com",
            "https://evil.example",
            "https://secretmanager.googleapis.com:444",
            "https://us-secretmanager.googleapis.com",
            "https://secretmanager.googleapis.com/path",
        ] {
            raw["origin"] = origin.into();
            assert!(GcpSourceProfile::parse_at(&serde_json::to_vec(&raw).unwrap(), 1000).is_err());
        }
        raw["origin"] = ORIGIN.into();
        for bad in [
            String::new(),
            "x\r\ny".into(),
            "x\0y".into(),
            "x".repeat(16385),
        ] {
            raw["access_token"] = bad.into();
            assert!(GcpSourceProfile::parse_at(&serde_json::to_vec(&raw).unwrap(), 1000).is_err());
        }
        raw["access_token"] = "x".repeat(16384).into();
        assert!(GcpSourceProfile::parse_at(&serde_json::to_vec(&raw).unwrap(), 1000).is_ok());
    }
    #[test]
    fn closed_profile_and_response_reject_duplicates_unknowns_wrong_name_checksum_and_bytes() {
        let p = GcpSourceProfile::parse_at(&profile(2000), 1000).unwrap();
        let valid = profile(2000);
        for field in [",\"access_token\":\"second\"", ",\"unknown\":true"] {
            let mut dup = valid[..valid.len() - 1].to_vec();
            dup.extend_from_slice(field.as_bytes());
            dup.push(b'}');
            assert!(GcpSourceProfile::parse_at(&dup, 1000).is_err());
        }
        for sum in ["", "-1", "+1", " 1", "1.0", "4294967296", "1"] {
            assert!(p.resolve(&response("MTIzNDU2Nzg5", sum)).is_err());
        }
        for bytes in [vec![], vec![0xff], vec![b'x'; 8193]] {
            assert!(
                p.resolve(&response(
                    &BASE64.encode(&bytes),
                    &crc32c(&bytes).to_string()
                ))
                .is_err()
            );
        }
        let full = vec![b'x'; 8192];
        assert_eq!(
            p.resolve(&response(&BASE64.encode(&full), &crc32c(&full).to_string()))
                .unwrap()
                .len(),
            8192
        );
        for json in [
            r#"{"name":"wrong","payload":{"data":"Zg==","dataCrc32c":"3531649220"}}"#,
            r#"{"name":"projects/123456/secrets/fixture_key/versions/7","name":"x","payload":{"data":"Zg==","dataCrc32c":"3531649220"}}"#,
            r#"{"name":"projects/123456/secrets/fixture_key/versions/7","payload":{"data":"Zg==","data":"Zg==","dataCrc32c":"3531649220"}}"#,
            r#"{"name":"projects/123456/secrets/fixture_key/versions/7","payload":{"data":"Zg=="}}"#,
            r#"{"name":"projects/123456/secrets/fixture_key/versions/7","payload":{"data":"Zg==","dataCrc32c":3531649220}}"#,
            r#"{"name":"projects/123456/secrets/fixture_key/versions/7","payload":{"data":"Zg==","dataCrc32c":"3531649220","extra":true}}"#,
        ] {
            assert!(
                p.resolve(&crate::upstream::UpstreamResponse {
                    status: 200,
                    headers: vec![].into(),
                    body: Zeroizing::new(json.as_bytes().to_vec())
                })
                .is_err()
            );
        }
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
                    CredentialLabel::new("gcp-actor").unwrap(),
                    CredentialKind::GcpSecretManagerSource,
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
            response(&BASE64.encode(value), &crc32c(value).to_string())
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
        assert_eq!(sent[0].host, "secretmanager.googleapis.com");
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
                "gcp.source.read_started",
                "gcp.source.resolved",
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
            ("gcp.source.read_started", 0),
            ("gcp.source.resolved", 1),
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
                if draft.event_type == rekey_vault::model::event_type::GCP_SOURCE_RESOLVED {
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
                rekey_domain::credential::CredentialKind::GcpSecretManagerSource,
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
                        assert_eq!(requests[0].host, "secretmanager.googleapis.com");
                    }
                }
            }
            assert_eq!(
                f.db()
                    .query_row(
                        "SELECT count(*) FROM audit_events WHERE event_type='gcp.source.resolved'",
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
    #[tokio::test]
    async fn actor_http_standard_source_token_value_reflection_is_sealed() {
        let f = ActorFixture::new(60_000, 30_000).await;
        rotate_actor_bootstrap(&f, "  edge-source-token  ").await;
        f.fake
            .push_response(Ok(ActorFixture::resolved(b"edge-source-token")));
        f.fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean body".to_vec()),
        }));
        let result = f.run().await;
        let requests = f.fake.take_requests();
        let code = match result {
            Ok(_) => "SUCCESS",
            Err(ref e) => e.code(),
        };
        eprintln!(
            "GCP OWS probe location=source-value outcome={code} source_requests={} business_requests={}",
            requests
                .iter()
                .filter(|r| r.host == "secretmanager.googleapis.com")
                .count(),
            requests
                .iter()
                .filter(|r| r.host == "api.example.com")
                .count()
        );
        assert_eq!(requests[0].auth_value, b"Bearer   edge-source-token  ");
        f.finish().await;
        assert_eq!(code, "RESPONSE_SECURITY_VIOLATION");
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
        let mut source = ActorFixture::resolved(token.as_bytes());
        let encoded = BASE64.encode(token.as_bytes());
        let escaped = encoded
            .bytes()
            .map(|b| format!("\\u{:04x}", b))
            .collect::<String>();
        source.body = Zeroizing::new(
            String::from_utf8(source.body.to_vec())
                .unwrap()
                .replace(&encoded, &escaped)
                .into_bytes(),
        );
        let parsed = GcpSourceProfile::parse_profile(
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
                    "SELECT count(*) FROM audit_events WHERE event_type='gcp.source.resolved'",
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
            let container = BASE64.encode(value.as_bytes());
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
            // GCP adds a base64 container around each reflected form. Some are
            // detected in raw JSON, others only after provider decoding.
            assert!(contains_secret(
                value.as_bytes(),
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
