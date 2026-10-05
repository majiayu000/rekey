//! Four fixed provider adapters. OAuth state and bearer material never enter Agent metadata.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::TryRngCore;
use rekey_domain::action::FixedMethod;
use rekey_domain::connection::{Connection, OAuthBinding, OAuthProvider};
use rekey_domain::ids::{CredentialId, RequestId};
use rekey_vault::command::OAuthGrantUpdateReason;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::secret::SecretInput;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::upstream::{UpstreamRequest, UpstreamTransport};

fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|v| v.map(Zeroizing::new))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    credential_type: String,
    provider: OAuthProvider,
    client_id: String,
    scopes: BTreeSet<String>,
    #[serde(default, deserialize_with = "secret")]
    client_secret: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    refresh_token: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    access_token: Option<Zeroizing<String>>,
    expires_at_ms: Option<i64>,
}
impl Grant {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, BrokerError> {
        let g: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if g.credential_type != "oauth-grant-v1"
            || g.client_id.is_empty()
            || g.client_id.len() > 512
            || g.client_id.chars().any(char::is_control)
            || matches!(g.provider, OAuthProvider::GitHub | OAuthProvider::Notion)
                && g.client_secret.as_ref().is_none_or(|s| s.is_empty())
            || g.provider == OAuthProvider::Slack && g.client_secret.is_some()
            || [&g.client_secret, &g.refresh_token, &g.access_token]
                .iter()
                .any(|v| {
                    v.as_ref().is_some_and(|s| {
                        s.is_empty() || s.len() > 16 * 1024 || s.chars().any(char::is_control)
                    })
                })
            || g.provider != OAuthProvider::Notion && g.access_token.is_some()
        {
            return Err(invalid());
        }
        Ok(g)
    }
    fn identity_matches(&self, b: &OAuthBinding) -> bool {
        self.provider == b.provider && self.client_id == b.client_id
    }
    fn matches(&self, b: &OAuthBinding) -> bool {
        self.provider == b.provider && self.client_id == b.client_id && self.scopes == b.scopes
    }
    fn persist(&self) -> Result<SecretInput, BrokerError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            credential_type: &'static str,
            provider: OAuthProvider,
            client_id: &'a str,
            scopes: &'a BTreeSet<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            client_secret: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            refresh_token: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            access_token: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            expires_at_ms: Option<i64>,
        }
        let bytes = serde_json::to_vec(&Payload {
            credential_type: "oauth-grant-v1",
            provider: self.provider,
            client_id: &self.client_id,
            scopes: &self.scopes,
            client_secret: self.client_secret.as_deref().map(|v| v.as_str()),
            refresh_token: self.refresh_token.as_deref().map(|v| v.as_str()),
            access_token: self.access_token.as_deref().map(|v| v.as_str()),
            expires_at_ms: self.expires_at_ms,
        })
        .map_err(|_| invalid())?;
        Ok(SecretInput::new(bytes))
    }
    fn needles(&self) -> Vec<Zeroizing<Vec<u8>>> {
        [&self.client_secret, &self.refresh_token, &self.access_token]
            .into_iter()
            .filter_map(|s| s.as_ref())
            .flat_map(|s| crate::executor::sealing_needles(s.as_bytes(), s.as_bytes()))
            .collect()
    }
}
fn invalid() -> BrokerError {
    BrokerError::LocalCall(
        "INVALID_INPUT",
        "invalid OAuth client or grant",
        "Review the provider client settings in Rekey App.",
    )
}
fn needs_reauth() -> BrokerError {
    BrokerError::LocalCall(
        "NEEDS_REAUTH",
        "OAuth authorization is required",
        "Open this connection in Rekey App and authorize it again.",
    )
}
fn random() -> Result<Zeroizing<String>, BrokerError> {
    let mut bytes = Zeroizing::new(vec![0; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| rekey_vault::AuthorityError::EntropyUnavailable)?;
    Ok(Zeroizing::new(
        data_encoding::BASE64URL_NOPAD.encode(&bytes),
    ))
}
fn endpoints(provider: OAuthProvider) -> (&'static str, &'static str, &'static str) {
    match provider {
        OAuthProvider::Google => (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "oauth2.googleapis.com",
            "/token",
        ),
        OAuthProvider::GitHub => (
            "https://github.com/login/oauth/authorize",
            "github.com",
            "/login/oauth/access_token",
        ),
        OAuthProvider::Slack => (
            "https://slack.com/oauth/v2/authorize",
            "slack.com",
            "/api/oauth.v2.access",
        ),
        OAuthProvider::Notion => (
            "https://api.notion.com/v1/oauth/authorize",
            "api.notion.com",
            "/v1/oauth/token",
        ),
    }
}
struct Access {
    token: Zeroizing<String>,
    expires_at_ms: Option<i64>,
}
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default, deserialize_with = "secret")]
    access_token: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    refresh_token: Option<Zeroizing<String>>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    error: Option<String>,
    ok: Option<bool>,
    authed_user: Option<Box<TokenResponse>>,
}
async fn exchange(
    g: &mut Grant,
    fields: &[(&str, &str)],
    transport: &dyn UpstreamTransport,
) -> Result<Access, BrokerError> {
    let (_, host, path) = endpoints(g.provider);
    let mut form = fields.to_vec();
    let mut auth = Zeroizing::new(Vec::new());
    let mut headers = vec![("accept".into(), "application/json".into())];
    let body = if g.provider == OAuthProvider::Notion {
        let secret = g.client_secret.as_ref().ok_or_else(invalid)?;
        let basic = Zeroizing::new(format!("{}:{}", g.client_id, secret.as_str()));
        auth.extend_from_slice(b"Basic ");
        let encoded = Zeroizing::new(data_encoding::BASE64.encode(basic.as_bytes()));
        auth.extend_from_slice(encoded.as_bytes());
        headers.push(("content-type".into(), "application/json".into()));
        let values: BTreeMap<&str, &str> = form.into_iter().collect();
        Zeroizing::new(serde_json::to_vec(&values).map_err(|_| invalid())?)
    } else {
        form.push(("client_id", &g.client_id));
        if matches!(g.provider, OAuthProvider::GitHub | OAuthProvider::Google)
            && let Some(secret) = &g.client_secret
        {
            form.push(("client_secret", secret.as_str()));
        }
        headers.push((
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(form)
                .finish()
                .into_bytes(),
        )
    };
    let response = transport
        .send(UpstreamRequest {
            host: host.into(),
            port: 443,
            method: FixedMethod::Post,
            path: path.into(),
            headers,
            auth_header: ("authorization".into(), auth),
            body,
            timeout: Duration::from_secs(20),
            response_max_bytes: 64 * 1024,
        })
        .await
        .map_err(|_| BrokerError::Upstream("oauth-exchange-transport"))?;
    let mut raw: TokenResponse = serde_json::from_slice(&response.body)
        .map_err(|_| BrokerError::Upstream("oauth-response"))?;
    if raw.error.as_deref().is_some_and(|e| {
        matches!(
            e,
            "invalid_grant"
                | "invalid_token"
                | "token_revoked"
                | "invalid_refresh_token"
                | "bad_refresh_token"
        )
    }) {
        return Err(needs_reauth());
    }
    if response.status >= 500 {
        return Err(BrokerError::Upstream("oauth-provider-unavailable"));
    }
    if !(200..300).contains(&response.status) || raw.error.is_some() || raw.ok == Some(false) {
        return Err(invalid());
    }
    let raw = if g.provider == OAuthProvider::Slack {
        raw.authed_user.take().map(|v| *v).unwrap_or(raw)
    } else {
        raw
    };
    if raw.token_type.as_deref().is_some_and(|t| {
        !(t.eq_ignore_ascii_case("bearer") || g.provider == OAuthProvider::Slack && t == "user")
    }) {
        return Err(BrokerError::Upstream("oauth-token-type"));
    }
    if g.provider != OAuthProvider::Notion {
        let actual: BTreeSet<String> = raw
            .scope
            .as_deref()
            .ok_or_else(|| BrokerError::Upstream("oauth-scope-missing"))?
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let actual: BTreeSet<String> = actual
            .into_iter()
            .filter(|s| s != "offline_access")
            .collect();
        if actual
            != g.scopes
                .iter()
                .filter(|s| s.as_str() != "offline_access")
                .cloned()
                .collect()
        {
            return Err(BrokerError::LocalCall(
                "DENIED",
                "provider granted scopes differ from the signed ceiling",
                "Review the granted scopes and sign a matching connection before retrying.",
            ));
        }
    }
    let token = raw
        .access_token
        .filter(|t| !t.is_empty() && t.len() <= 16 * 1024 && !t.chars().any(char::is_control))
        .ok_or_else(|| BrokerError::Upstream("oauth-access-missing"))?;
    let expires_at_ms = match raw.expires_in {
        Some(seconds) if seconds > 0 && seconds <= 31_536_000 => {
            Some(crate::now_ts()?.as_unix_ms() + seconds as i64 * 1000)
        }
        None if g.provider == OAuthProvider::Notion => None,
        _ => return Err(BrokerError::Upstream("oauth-expiry")),
    };
    if let Some(refresh) = raw.refresh_token {
        g.refresh_token = Some(refresh);
    }
    if g.provider != OAuthProvider::Notion && g.refresh_token.as_ref().is_none_or(|s| s.is_empty())
    {
        return Err(needs_reauth());
    }
    if g.provider == OAuthProvider::Notion {
        g.access_token = Some(token.clone());
        g.expires_at_ms = expires_at_ms;
    }
    Ok(Access {
        token,
        expires_at_ms,
    })
}
struct Cached {
    version: u64,
    binding: [u8; 32],
    access: Access,
}
pub(crate) struct Bearer {
    pub token: Zeroizing<Vec<u8>>,
    pub version: u64,
    pub needles: Vec<Zeroizing<Vec<u8>>>,
}
#[derive(Default)]
pub(crate) struct Manager {
    cache: Mutex<BTreeMap<CredentialId, Cached>>,
    refresh: tokio::sync::Mutex<()>,
    flows: Mutex<Vec<tokio::task::AbortHandle>>,
    epoch: AtomicU64,
    broker: Mutex<Option<std::sync::Weak<crate::runtime::BrokerCtx>>>,
}
impl Manager {
    pub(crate) fn attach(&self, broker: &Arc<crate::runtime::BrokerCtx>) {
        *self.broker.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(broker));
    }
    pub(crate) fn clear(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
        for task in self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn bearer(
        &self,
        c: &Connection,
        active: &ActivePolicy,
        authority: &AuthorityHandle,
        transport: &dyn UpstreamTransport,
        deadline: Instant,
        lifecycle: &Lifecycle,
        started: &mut crate::audit::StartedAuditGuard,
        effect_kind: &AtomicU8,
    ) -> Result<Bearer, BrokerError> {
        let _refresh = tokio::time::timeout_at(deadline.into(), self.refresh.lock())
            .await
            .map_err(|_| BrokerError::Upstream("oauth-refresh-timeout"))?;
        let epoch = self.epoch.load(Ordering::SeqCst);
        let prepared = authority.prepare_oauth_grant(c.credential_id).await?;
        let version = prepared.version();
        let mut grant = prepared.consume(Grant::parse)?;
        let binding = c.oauth.as_ref().ok_or_else(invalid)?;
        if !grant.matches(binding) {
            return Err(BrokerError::Denied("oauth-binding-mismatch"));
        }
        let digest: [u8; 32] =
            Sha256::digest(serde_jcs::to_vec(binding).map_err(|_| invalid())?).into();
        let now = crate::now_ts()?.as_unix_ms();
        let mut needles = grant.needles();
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&c.credential_id)
            .filter(|cached| {
                cached.version == version
                    && cached.binding == digest
                    && cached
                        .access
                        .expires_at_ms
                        .is_none_or(|expiry| expiry > now + 30_000)
            })
        {
            return Ok(Bearer {
                token: Zeroizing::new(cached.access.token.as_bytes().to_vec()),
                version,
                needles,
            });
        }
        if let Some(token) = grant.access_token.as_ref().filter(|_| {
            grant
                .expires_at_ms
                .is_none_or(|expiry| expiry > now + 30_000)
        }) {
            return Ok(Bearer {
                token: Zeroizing::new(token.as_bytes().to_vec()),
                version,
                needles,
            });
        }
        let refresh = grant
            .refresh_token
            .as_ref()
            .ok_or_else(needs_reauth)?
            .clone();
        crate::executor::try_begin_remote_effect(lifecycle, started, deadline).await?;
        // Refresh-token rotation can consume a provider credential even before
        // the requested API call starts. Cache hits above have no such effect.
        started.mark_remote_effect_started();
        effect_kind.store(crate::executor::EFFECT_ORDINARY_HTTP, Ordering::SeqCst);
        let result = tokio::time::timeout_at(
            deadline.into(),
            exchange(
                &mut grant,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh.as_str()),
                ],
                transport,
            ),
        )
        .await;
        let access = match result {
            Ok(Ok(access)) => access,
            other => {
                let mut audit = crate::runtime::oauth_audit("oauth.refresh_failed", c, active)?;
                audit.outcome = rekey_vault::model::outcome::DENIED;
                audit.reason_code = "oauth-refresh-failed".into();
                authority.append_audit(audit).await?;
                return Err(match other {
                    Ok(Err(error)) => error,
                    _ => BrokerError::Upstream("oauth-refresh-timeout"),
                });
            }
        };
        if self.epoch.load(Ordering::SeqCst) != epoch {
            return Err(rekey_vault::AuthorityError::Locked.into());
        }
        let updated = authority
            .rotate_oauth_grant(
                c.credential_id,
                version,
                grant.persist()?,
                OAuthGrantUpdateReason::Refreshed,
                deadline,
            )
            .await?;
        if self.epoch.load(Ordering::SeqCst) != epoch {
            return Err(rekey_vault::AuthorityError::Locked.into());
        }
        needles.extend(grant.needles());
        let token = Zeroizing::new(access.token.as_bytes().to_vec());
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if self.epoch.load(Ordering::SeqCst) != epoch {
            return Err(rekey_vault::AuthorityError::Locked.into());
        }
        cache.insert(
            c.credential_id,
            Cached {
                version: updated.current_version,
                binding: digest,
                access,
            },
        );
        Ok(Bearer {
            token,
            version: updated.current_version,
            needles,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct LoginResponse {
    authorization_url: String,
    request_id: RequestId,
    expires_at_ms: i64,
}
impl Manager {
    pub(crate) async fn begin(
        self: &Arc<Self>,
        c: Connection,
        redirect: Option<&str>,
        broker: &crate::runtime::BrokerCtx,
        mut failure_audit: rekey_vault::command::AuditDraft,
    ) -> Result<LoginResponse, BrokerError> {
        let authority = broker.authority.clone();
        let transport = Arc::clone(&broker.executor.transport);
        let policy = Arc::clone(&broker.policy);
        let lifecycle = Arc::clone(&broker.lifecycle);
        failure_audit.event_type = "oauth.refresh_failed";
        failure_audit.outcome = rekey_vault::model::outcome::DENIED;
        failure_audit.reason_code = "oauth-authorization-failed".into();

        self.flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|t| !t.is_finished());
        if self.flows.lock().unwrap_or_else(|e| e.into_inner()).len() >= 4 {
            return Err(BrokerError::LocalCall(
                "RATE_LIMITED",
                "too many OAuth logins",
                "Finish or wait for the existing browser authorizations.",
            ));
        }
        let binding = c.oauth.as_ref().ok_or_else(invalid)?.clone();
        let listener = match redirect {
            Some(uri) => {
                let url = url::Url::parse(uri).map_err(|_| invalid())?;
                if url.scheme() != "http"
                    || !matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
                    || url.port().is_none()
                    || url.path() != "/callback"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return Err(invalid());
                }
                TcpListener::bind(("127.0.0.1", url.port().unwrap()))
                    .await
                    .map_err(BrokerError::Io)?
            }
            None if matches!(
                binding.provider,
                OAuthProvider::Google | OAuthProvider::GitHub
            ) =>
            {
                TcpListener::bind(("127.0.0.1", 0))
                    .await
                    .map_err(BrokerError::Io)?
            }
            _ => {
                return Err(BrokerError::LocalCall(
                    "INVALID_INPUT",
                    "this provider requires its registered localhost callback",
                    "Enter the exact registered localhost callback in Rekey App.",
                ));
            }
        };
        let redirect_uri = redirect.map(str::to_owned).unwrap_or(format!(
            "http://127.0.0.1:{}/callback",
            listener.local_addr().map_err(BrokerError::Io)?.port()
        ));
        let prepared = authority.prepare_oauth_grant(c.credential_id).await?;
        let version = prepared.version();
        let mut grant = prepared.consume(Grant::parse)?;
        if !grant.identity_matches(&binding) {
            return Err(BrokerError::Denied("oauth-binding-mismatch"));
        }
        let state = random()?;
        let verifier = random()?;
        let challenge = data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));
        let mut url = url::Url::parse(endpoints(binding.provider).0).map_err(|_| invalid())?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &binding.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("state", &state);
            if binding.provider != OAuthProvider::Notion {
                query
                    .append_pair("code_challenge", &challenge)
                    .append_pair("code_challenge_method", "S256");
                let mut scopes = binding.scopes.clone();
                if binding.provider == OAuthProvider::GitHub {
                    scopes.insert("offline_access".into());
                }
                let key = if binding.provider == OAuthProvider::Slack {
                    "user_scope"
                } else {
                    "scope"
                };
                query.append_pair(
                    key,
                    &scopes.into_iter().collect::<Vec<_>>().join(
                        if binding.provider == OAuthProvider::Slack {
                            ","
                        } else {
                            " "
                        },
                    ),
                );
            }
            if binding.provider == OAuthProvider::Google {
                query
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent");
            }
            if binding.provider == OAuthProvider::Notion {
                query.append_pair("owner", "user");
            }
        }
        let request_id = failure_audit.request_id.ok_or_else(invalid)?;
        let expires_at_ms = crate::now_ts()?.as_unix_ms() + 300_000;
        let epoch = self.epoch.load(Ordering::SeqCst);
        let manager = Arc::clone(self);
        let task = tokio::spawn(async move {
            let result = async {
                let code = tokio::time::timeout(
                    Duration::from_secs(300),
                    callback_code(&listener, &redirect_uri, &state),
                )
                .await
                .map_err(|_| {
                    BrokerError::LocalCall(
                        "EXPIRED",
                        "OAuth browser authorization expired",
                        "Start OAuth authorization again in Rekey App.",
                    )
                })??;
                let mut fields = vec![
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", redirect_uri.as_str()),
                ];
                if binding.provider != OAuthProvider::Notion {
                    fields.push(("code_verifier", verifier.as_str()));
                }
                grant.scopes = binding.scopes.clone();
                let access = exchange(&mut grant, &fields, transport.as_ref()).await?;
                let deadline = Instant::now() + Duration::from_secs(10);
                let _owner = lifecycle.coordinate_until(deadline.into()).await?;
                if lifecycle.phase() != BrokerPhase::Running
                    || manager.epoch.load(Ordering::SeqCst) != epoch
                {
                    return Err(rekey_vault::AuthorityError::Locked.into());
                }
                let now = crate::now_ts()?;
                let active = policy.read().await;
                if !active.as_ref().is_some_and(|p| {
                    !p.is_expired(now)
                        && p.snapshot()
                            .connections()
                            .iter()
                            .any(|current| current == &c)
                }) {
                    return Err(BrokerError::Denied("oauth-policy-changed"));
                }
                let updated = authority
                    .rotate_oauth_grant(
                        c.credential_id,
                        version,
                        grant.persist()?,
                        OAuthGrantUpdateReason::Authorized,
                        deadline,
                    )
                    .await?;
                let mut cache = manager.cache.lock().unwrap_or_else(|e| e.into_inner());
                if manager.epoch.load(Ordering::SeqCst) != epoch {
                    return Err(rekey_vault::AuthorityError::Locked.into());
                }
                cache.insert(
                    c.credential_id,
                    Cached {
                        version: updated.current_version,
                        binding: Sha256::digest(
                            serde_jcs::to_vec(&binding).map_err(|_| invalid())?,
                        )
                        .into(),
                        access,
                    },
                );
                Ok::<(), BrokerError>(())
            }
            .await;
            if let Err(error) = result {
                // Codes only: provider bodies, auth codes, and verifier never reach logs.
                tracing::info!(event = "oauth.authorization_failed", code = error.code());
                let audit_result = async {
                    authority.append_audit(failure_audit).await?;
                    Ok::<(), BrokerError>(())
                }
                .await;
                if audit_result.is_err() {
                    manager.clear();
                    lifecycle.mark_stop_pending();
                    if let Some(broker) = manager
                        .broker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                        .and_then(std::sync::Weak::upgrade)
                    {
                        broker.request_fault();
                    }
                }
            }
        });
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        if self.epoch.load(Ordering::SeqCst) != epoch {
            task.abort();
            return Err(rekey_vault::AuthorityError::Locked.into());
        }
        flows.push(task.abort_handle());
        Ok(LoginResponse {
            authorization_url: url.into(),
            request_id,
            expires_at_ms,
        })
    }
}
async fn callback_code(
    listener: &TcpListener,
    redirect: &str,
    state: &str,
) -> Result<Zeroizing<String>, BrokerError> {
    let expected = url::Url::parse(redirect).map_err(|_| invalid())?;
    let host = format!(
        "{}:{}",
        expected.host_str().ok_or_else(invalid)?,
        expected.port().ok_or_else(invalid)?
    );
    loop {
        let (mut stream, _) = listener.accept().await.map_err(BrokerError::Io)?;
        let mut bytes = Zeroizing::new(vec![0; 8192]);
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut len = 0;
            loop {
                let n = stream
                    .read(&mut bytes[len..])
                    .await
                    .map_err(BrokerError::Io)?;
                if n == 0 {
                    return Err(invalid());
                }
                len += n;
                if bytes[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if len == bytes.len() {
                    return Err(invalid());
                }
            }
            let text = std::str::from_utf8(&bytes[..len]).map_err(|_| invalid())?;
            let mut lines = text.split("\r\n");
            let mut first = lines.next().ok_or_else(invalid)?.split_whitespace();
            if first.next() != Some("GET") {
                return Err(invalid());
            }
            let target = first.next().ok_or_else(invalid)?;
            if first.next() != Some("HTTP/1.1") || first.next().is_some() {
                return Err(invalid());
            }
            let mut actual_host = None;
            for line in lines.take_while(|line| !line.is_empty()) {
                let (name, value) = line.split_once(':').ok_or_else(invalid)?;
                if name.eq_ignore_ascii_case("host") && actual_host.replace(value.trim()).is_some()
                {
                    return Err(invalid());
                }
                if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "origin" | "content-length" | "transfer-encoding"
                ) {
                    return Err(invalid());
                }
            }
            if actual_host != Some(host.as_str()) {
                return Err(invalid());
            }
            let (path, query) = target.split_once('?').ok_or_else(invalid)?;
            if path != "/callback" {
                return Err(invalid());
            }
            let mut received_state = None;
            let mut code = None;
            let mut rejected = false;
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                let duplicate = match key.as_ref() {
                    "state" => received_state
                        .replace(Zeroizing::new(value.into_owned()))
                        .is_some(),
                    "code" => code.replace(Zeroizing::new(value.into_owned())).is_some(),
                    "error" => {
                        rejected = true;
                        false
                    }
                    _ => false,
                };
                if duplicate {
                    return Err(invalid());
                }
            }
            if received_state.as_deref().is_none_or(|v| {
                !bool::from(subtle::ConstantTimeEq::ct_eq(
                    v.as_bytes(),
                    state.as_bytes(),
                ))
            }) {
                return Err(invalid());
            }
            if rejected {
                return Ok(None);
            }
            Ok(Some(
                code.filter(|s| {
                    !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
                })
                .ok_or_else(invalid)?,
            ))
        })
        .await;
        match result {
            Ok(Ok(code)) => {
                let message = if code.is_some() {
                    "Authorization received. Return to Rekey App."
                } else {
                    "Authorization was cancelled. Return to Rekey App."
                };
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    message.len(),
                    message
                );
                stream
                    .write_all(reply.as_bytes())
                    .await
                    .map_err(BrokerError::Io)?;
                return code.ok_or_else(|| BrokerError::Denied("oauth-user-cancelled"));
            }
            _ => {
                let _=stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeUpstreamTransport;
    use crate::upstream::UpstreamResponse;
    use serde_json::json;
    fn response(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> UpstreamResponse {
        UpstreamResponse {
            status,
            headers: headers.into(),
            body: Zeroizing::new(body),
        }
    }
    fn grant(provider: OAuthProvider, scopes: &[&str]) -> Grant {
        Grant::parse(&serde_json::to_vec(&json!({"credential_type":"oauth-grant-v1","provider":provider,"client_id":"synthetic-client","client_secret":if matches!(provider,OAuthProvider::GitHub|OAuthProvider::Notion){Some("synthetic-client-secret")}else{None},"refresh_token":"synthetic-refresh-before","scopes":scopes,"expires_at_ms":null})).unwrap()).unwrap()
    }
    #[tokio::test]
    async fn refresh_rotation_uses_fixed_provider_request_and_persists_no_google_bearer() {
        let mut g = grant(
            OAuthProvider::Google,
            &["https://www.googleapis.com/auth/drive.readonly"],
        );
        let fake = FakeUpstreamTransport::new();
        fake.push_response(Ok(response(200,vec![],serde_json::to_vec(&json!({"access_token":"synthetic-access","refresh_token":"synthetic-refresh-after","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/drive.readonly"})).unwrap())));
        let access = exchange(
            &mut g,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", "synthetic-refresh-before"),
            ],
            &fake,
        )
        .await
        .unwrap();
        assert_eq!(access.token.as_str(), "synthetic-access");
        assert_eq!(g.refresh_token.unwrap().as_str(), "synthetic-refresh-after");
        assert!(g.access_token.is_none());
        let requests = fake.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].host, "oauth2.googleapis.com");
        assert_eq!(requests[0].path, "/token");
        assert!(
            requests[0]
                .body
                .windows(b"client_id=synthetic-client".len())
                .any(|w| w == b"client_id=synthetic-client")
        );
    }
    #[tokio::test]
    async fn revoked_github_refresh_prompts_reauth_and_scope_mismatch_denies() {
        let mut g = grant(OAuthProvider::GitHub, &["repo", "offline_access"]);
        let fake = FakeUpstreamTransport::new();
        fake.push_response(Ok(response(
            200,
            vec![],
            br#"{"error":"bad_refresh_token"}"#.to_vec(),
        )));
        assert_eq!(
            exchange(&mut g, &[], &fake).await.err().unwrap().code(),
            "NEEDS_REAUTH"
        );
        fake.push_response(Ok(response(200,vec![],br#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600,"scope":"repo,offline_access","token_type":"Bearer"}"#.to_vec())));
        assert!(exchange(&mut g, &[], &fake).await.is_ok());
        fake.push_response(Ok(response(200,vec![],br#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600,"scope":"repo,admin:org","token_type":"Bearer"}"#.to_vec())));
        assert_eq!(
            exchange(&mut g, &[], &fake).await.err().unwrap().code(),
            "DENIED"
        );
    }
    #[tokio::test]
    async fn slack_user_rotation_and_notion_persisted_non_expiring_token_follow_distinct_contracts()
    {
        let mut slack = grant(OAuthProvider::Slack, &["channels:read"]);
        let fake = FakeUpstreamTransport::new();
        fake.push_response(Ok(response(200,vec![],br#"{"ok":true,"authed_user":{"access_token":"synthetic-user-token","refresh_token":"synthetic-user-refresh","expires_in":43200,"token_type":"user","scope":"channels:read"}}"#.to_vec())));
        assert!(
            exchange(
                &mut slack,
                &[("code_verifier", "synthetic-verifier")],
                &fake
            )
            .await
            .is_ok()
        );
        assert!(slack.client_secret.is_none());
        assert!(slack.access_token.is_none());
        let request = fake.take_requests().pop().unwrap();
        assert_eq!(request.host, "slack.com");
        assert!(
            !request
                .body
                .windows(b"client_secret".len())
                .any(|w| w == b"client_secret")
        );
        let mut notion = grant(OAuthProvider::Notion, &["read_content"]);
        fake.push_response(Ok(response(
            200,
            vec![],
            br#"{"access_token":"synthetic-notion-token","token_type":"bearer"}"#.to_vec(),
        )));
        let access = exchange(&mut notion, &[("code", "synthetic-code")], &fake)
            .await
            .unwrap();
        assert!(access.expires_at_ms.is_none());
        assert_eq!(
            notion.access_token.as_ref().unwrap().as_str(),
            "synthetic-notion-token"
        );
        let request = fake.take_requests().pop().unwrap();
        assert_eq!(request.host, "api.notion.com");
        assert_eq!(request.path, "/v1/oauth/token");
        assert!(request.auth_value.starts_with(b"Basic "));
    }
    #[tokio::test]
    async fn real_loopback_callback_rejects_wrong_nonce_origin_and_duplicate_state() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect = format!("http://{address}/callback");
        let task =
            tokio::spawn(
                async move { callback_code(&listener, &redirect, "synthetic-state").await },
            );
        for extra in [
            "state=wrong&code=synthetic-code",
            "state=synthetic-state&state=synthetic-state&code=synthetic-code",
        ] {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(
                    format!("GET /callback?{extra} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 400"));
        }
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(format!("GET /callback?state=synthetic-state&code=synthetic-code HTTP/1.1\r\nHost: {address}\r\nOrigin: https://evil.example\r\n\r\n").as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 400"));
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(format!("GET /callback?state=synthetic-state&code=synthetic-code HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(!reply.contains("synthetic-code"));
        assert_eq!(task.await.unwrap().unwrap().as_str(), "synthetic-code");
    }
}
