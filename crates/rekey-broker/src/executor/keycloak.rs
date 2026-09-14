//! One fixed Keycloak Standard V2 exchange, GET and direct issued-token revoke.
use super::*;
use rekey_domain::action::{ExactPath, FixedMethod, HttpsOrigin};
use serde::Deserialize;

const CLEANUP: Duration = Duration::from_millis(500);
const RESPONSE_LIMIT: u32 = 64 * 1024;
const TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

pub(crate) struct KeycloakProfile {
    origin: HttpsOrigin,
    realm: String,
    client_id: String,
    client_secret: Zeroizing<String>,
    subject_token: Zeroizing<String>,
    audience: String,
    target_origin: HttpsOrigin,
    target_path: ExactPath,
}

pub(super) struct KeycloakPrepared {
    pub(super) profile: Result<KeycloakProfile, &'static str>,
    pub(super) credential_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile<'a> {
    credential_type: &'a str,
    origin: &'a str,
    realm: &'a str,
    client_id: &'a str,
    #[serde(deserialize_with = "secret_string")]
    client_secret: Zeroizing<String>,
    #[serde(deserialize_with = "secret_string")]
    subject_token: Zeroizing<String>,
    audience: &'a str,
    target_origin: &'a str,
    target_path: &'a str,
}

fn secret_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

fn identifier(value: &str, limit: usize, dot: bool) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_') || (dot && b == b'.'))
}
fn token_bytes(value: &[u8]) -> bool {
    (16..=16384).contains(&value.len()) && value.iter().all(u8::is_ascii_graphic)
}

impl KeycloakProfile {
    pub(crate) fn parse_profile(secret: &[u8]) -> Result<Self, &'static str> {
        let p: RawProfile<'_> =
            serde_json::from_slice(secret).map_err(|_| "oauth-profile-invalid")?;
        if p.credential_type != "keycloak-token-exchange-v1"
            || !identifier(p.realm, 100, false)
            || !identifier(p.client_id, 128, true)
            || !identifier(p.audience, 128, true)
            || !token_bytes(p.client_secret.as_bytes())
            || !token_bytes(p.subject_token.as_bytes())
        {
            return Err("oauth-profile-invalid");
        }
        Ok(Self {
            origin: HttpsOrigin::parse(p.origin).map_err(|_| "oauth-profile-invalid")?,
            realm: p.realm.to_owned(),
            client_id: p.client_id.to_owned(),
            client_secret: p.client_secret,
            subject_token: p.subject_token,
            audience: p.audience.to_owned(),
            target_origin: HttpsOrigin::parse(p.target_origin)
                .map_err(|_| "oauth-profile-invalid")?,
            target_path: ExactPath::parse(p.target_path).map_err(|_| "oauth-profile-invalid")?,
        })
    }
    pub(crate) fn validate_profile(secret: &[u8]) -> Result<(), &'static str> {
        Self::parse_profile(secret).map(|_| ())
    }
    fn accepts(&self, action: &FixedHttpAction, request: &ExecuteRequest) -> bool {
        action.origin == self.target_origin
            && action.exact_path == self.target_path
            && action.method == FixedMethod::Get
            && action.auth.header_name.as_str() == "authorization"
            && action.auth.prefix.as_str() == "Bearer "
            && action.timeout_ms >= 2000
            && request.body.is_empty()
            && request.content_type.is_none()
            && request.extra_headers.is_empty()
    }
    fn auth(&self) -> Zeroizing<Vec<u8>> {
        // RFC6749 client_password is percent-encoded before Basic encoding.
        let client =
            url::form_urlencoded::byte_serialize(self.client_id.as_bytes()).collect::<String>();
        let password = Zeroizing::new(
            url::form_urlencoded::byte_serialize(self.client_secret.as_bytes()).collect::<String>(),
        );
        let input = Zeroizing::new(format!("{client}:{}", password.as_str()));
        let encoded = Zeroizing::new(data_encoding::BASE64.encode(input.as_bytes()));
        Zeroizing::new(format!("Basic {}", encoded.as_str()).into_bytes())
    }
    fn needles(&self) -> Vec<Zeroizing<Vec<u8>>> {
        let mut result = sealing_needles(self.client_secret.as_bytes(), &self.auth());
        result.extend(sealing_needles(
            self.subject_token.as_bytes(),
            self.subject_token.as_bytes(),
        ));
        for secret in [self.client_secret.as_str(), self.subject_token.as_str()] {
            result.extend(json_string_needles(secret));
        }
        result
    }
    fn provider_request(
        &self,
        endpoint: &str,
        fields: &[(&str, &str)],
        timeout: Duration,
    ) -> UpstreamRequest {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.extend_pairs(fields.iter().copied());
        UpstreamRequest {
            host: self.origin.host().to_owned(),
            port: self.origin.port(),
            method: FixedMethod::Post,
            path: format!("/realms/{}/protocol/openid-connect/{endpoint}", self.realm),
            headers: vec![(
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            auth_header: ("authorization".to_owned(), self.auth()),
            body: Zeroizing::new(form.finish().into_bytes()),
            timeout,
            response_max_bytes: RESPONSE_LIMIT,
        }
    }
    async fn exchange(
        &self,
        transport: &dyn crate::upstream::UpstreamTransport,
        deadline: Instant,
    ) -> Exchange {
        let request = self.provider_request(
            "token",
            &[
                (
                    "grant_type",
                    rekey_connector::OAUTH_TOKEN_EXCHANGE_GRANT_TYPE,
                ),
                ("subject_token", self.subject_token.as_str()),
                ("subject_token_type", TOKEN_TYPE),
                ("requested_token_type", TOKEN_TYPE),
                ("audience", self.audience.as_str()),
            ],
            deadline.saturating_duration_since(Instant::now()),
        );
        let response = match send(transport, request, deadline).await {
            Ok(response) => response,
            Err(reason) => {
                return Exchange {
                    tokens: Vec::new(),
                    value: Err(reason),
                };
            }
        };
        let (tokens, occurrences) = captured_tokens(&response.body);
        #[derive(Deserialize)]
        struct TokenResponse<'a> {
            access_token: &'a str,
            token_type: &'a str,
            issued_token_type: &'a str,
            expires_in: u64,
            #[serde(default)]
            refresh_token: Option<serde::de::IgnoredAny>,
        }
        let value = (|| {
            if response.status != 200 || occurrences != 1 || tokens.len() != 1 {
                return Err("oauth-exchange-invalid");
            }
            let p: TokenResponse<'_> =
                serde_json::from_slice(&response.body).map_err(|_| "oauth-exchange-invalid")?;
            if p.token_type != "Bearer"
                || p.issued_token_type != TOKEN_TYPE
                || p.refresh_token.is_some()
                || !(1..=300).contains(&p.expires_in)
                || p.access_token.as_bytes() != tokens[0].as_bytes()
            {
                return Err("oauth-exchange-invalid");
            }
            if contains_secret(&response.body, &self.needles())
                || headers_contain_secret(&response.headers, &self.needles())
            {
                return Err("reflected-secret");
            }
            Ok(Duration::from_secs(p.expires_in))
        })();
        Exchange { tokens, value }
    }
    async fn revoke(
        &self,
        transport: &dyn crate::upstream::UpstreamTransport,
        tokens: &[Zeroizing<String>],
        deadline: Instant,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), &'static str> {
        let mut result = Ok(());
        for (i, token) in tokens.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let slice = remaining / (tokens.len() - i) as u32;
            let until = Instant::now()
                .checked_add(slice)
                .unwrap_or(deadline)
                .min(deadline);
            let request = self.provider_request(
                "revoke",
                &[
                    ("token", token.as_str()),
                    ("token_type_hint", "access_token"),
                ],
                slice,
            );
            match send(transport, request, until).await {
                Ok(r)
                    if r.status == 200
                        && r.body.is_empty()
                        && !headers_contain_secret(&r.headers, needles) => {}
                _ => result = Err("oauth-revoke-failed"),
            }
        }
        result
    }
}

// Match JSON string contents, also when surrounded by a prefix/suffix. Keep
// this closed provider extension local; it is not an arbitrary decoder.
fn json_string_needles(secret: &str) -> Vec<Zeroizing<Vec<u8>>> {
    let encoded =
        Zeroizing::new(serde_json::to_vec(secret).expect("string serialization is infallible"));
    let content = &encoded[1..encoded.len() - 1];
    let mut needles = sealing_needles(content, content);
    let mut slash_escaped = Zeroizing::new(Vec::with_capacity(content.len()));
    for byte in content {
        if *byte == b'/' {
            slash_escaped.push(b'\\');
        }
        slash_escaped.push(*byte);
    }
    needles.extend(sealing_needles(&slash_escaped, &slash_escaped));
    needles
}

struct Exchange {
    tokens: Vec<Zeroizing<String>>,
    value: Result<Duration, &'static str>,
}

async fn send(
    transport: &dyn crate::upstream::UpstreamTransport,
    request: UpstreamRequest,
    deadline: Instant,
) -> Result<crate::upstream::UpstreamResponse, &'static str> {
    if deadline <= Instant::now() {
        return Err("upstream-timeout");
    }
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        transport.send(request),
    )
    .await
    .map_err(|_| "upstream-timeout")?
    .map_err(|_| "oauth-upstream-failed")
}

// Capture before validation, including duplicate fields and truncated JSON.
// Keycloak emits unescaped ASCII JWTs. Limits are part of the explicit contract.
fn captured_tokens(body: &[u8]) -> (Vec<Zeroizing<String>>, usize) {
    let key = br#""access_token""#;
    let mut offset = 0;
    let mut tokens: Vec<Zeroizing<String>> = Vec::new();
    let mut occurrences = 0;
    while let Some(pos) = body[offset..].windows(key.len()).position(|v| v == key) {
        let start = offset + pos + key.len();
        offset = start;
        let tail = &body[start..];
        let skip = tail
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(tail.len());
        if tail.get(skip) != Some(&b':') {
            continue;
        }
        let tail = &tail[skip + 1..];
        let skip = tail
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(tail.len());
        if tail.get(skip) != Some(&b'"') {
            continue;
        }
        let tail = &tail[skip + 1..];
        if let Some(end) = tail.iter().position(|b| matches!(b, b'"' | b'\\')) {
            let value = &tail[..end];
            if tail[end] == b'"' && token_bytes(value) {
                occurrences += 1;
                if tokens.len() < 4 && !tokens.iter().any(|t| t.as_bytes() == value) {
                    // ASCII has already been checked; conversion cannot disclose bytes.
                    if let Ok(text) = String::from_utf8(value.to_vec()) {
                        tokens.push(Zeroizing::new(text));
                    }
                }
            }
        }
    }
    (tokens, occurrences)
}

impl ActionExecutor {
    pub(super) async fn run_keycloak(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: KeycloakPrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let profile = match prepared.profile {
            Ok(profile) if profile.accepts(action, request) => profile,
            _ => {
                started
                    .blocked_until(effect_deadline, "oauth-profile-invalid")
                    .await?;
                return Err(BrokerError::Denied("oauth-profile-invalid"));
            }
        };
        let business = effect_deadline
            .checked_sub(CLEANUP)
            .ok_or(BrokerError::Upstream("upstream-timeout"))?;
        try_begin_remote_effect(&self.lifecycle, started, effect_deadline).await?;
        started.mark_remote_effect_started();
        effect_kind.store(EFFECT_REVOCABLE_CONNECTOR, Ordering::SeqCst);
        let acquired_at = Instant::now();
        let exchange = profile.exchange(self.transport.as_ref(), business).await;
        let mut needles = profile.needles();
        for token in &exchange.tokens {
            needles.extend(sealing_needles(token.as_bytes(), token.as_bytes()));
        }
        let issued = if !exchange.tokens.is_empty() {
            self.terminals
                .commit_until(
                    business,
                    connector_event(
                        started.context(),
                        "oauth.token.issued",
                        if exchange.value.is_ok() {
                            "success"
                        } else {
                            "failure"
                        },
                        "keycloak-standard-v2".to_owned(),
                    ),
                )
                .await
        } else {
            Ok(())
        };
        let result: Result<crate::upstream::UpstreamResponse, &'static str> =
            match (&exchange.value, &issued) {
                (Ok(ttl), Ok(())) => {
                    let until = acquired_at
                        .checked_add(*ttl)
                        .unwrap_or(business)
                        .min(business);
                    let token = &exchange.tokens[0];
                    let auth = Zeroizing::new(format!("Bearer {}", token.as_str()).into_bytes());
                    needles.extend(sealing_needles(token.as_bytes(), &auth));
                    let mut upstream = build_upstream(action, request, auth);
                    upstream.timeout = until.saturating_duration_since(Instant::now());
                    send(self.transport.as_ref(), upstream, until).await
                }
                (Err(reason), _) => Err(reason),
                _ => Err("connector-audit-failed"),
            };
        let revoke = profile
            .revoke(
                self.transport.as_ref(),
                &exchange.tokens,
                effect_deadline,
                &needles,
            )
            .await;
        if !exchange.tokens.is_empty()
            && let Err(error) = self
                .terminals
                .commit_until(
                    effect_deadline,
                    connector_event(
                        started.context(),
                        "oauth.token.revoked",
                        if revoke.is_ok() { "success" } else { "failure" },
                        "keycloak-standard-v2".to_owned(),
                    ),
                )
                .await
        {
            started.submit_indeterminate("connector-audit-failed");
            return Err(error);
        }
        if let Err(error) = issued {
            started.submit_indeterminate("connector-audit-failed");
            return Err(error);
        }
        let response = match revoke.and(result) {
            Ok(response) => response,
            Err(reason) => {
                started.indeterminate_until(effect_deadline, reason).await?;
                return Err(BrokerError::Indeterminate(reason));
            }
        };
        if contains_secret(&response.body, &needles)
            || headers_contain_secret(&response.headers, &needles)
        {
            started
                .indeterminate_until(effect_deadline, "reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let headers = filter_response_headers(action, &response.headers);
        if !response_metadata_fits(response.status, &headers, response.body.len()) {
            started
                .indeterminate_until(effect_deadline, "response-metadata-too-large")
                .await?;
            return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
        }
        started
            .finished_until(
                effect_deadline,
                prepared.credential_version,
                response.status,
                acquired_at.elapsed().as_millis() as i64,
            )
            .await?;
        let mut response = response;
        Ok(ExecuteOutcome {
            upstream_status: response.status,
            headers,
            body: std::mem::take(&mut *response.body),
        })
    }
}

#[cfg(test)]
mod tests;
