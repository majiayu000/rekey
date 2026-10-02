//! Fixed public-client OIDC node login. All state and source tokens are memory-only.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use rand::TryRngCore;
use rekey_domain::ids::{PrincipalId, VaultId};
use rekey_domain::ipc::{OidcBeginResponse, OidcLogoutResponse, OidcSessionResponse};
use rekey_policy::oidc_admin::{OidcAdminContext, verify_id_token};
use rekey_vault::command::AuditDraft;
use rekey_vault::model::outcome;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::Instant;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::BrokerError;
use crate::runtime::BrokerCtx;

const FLOW_LIFETIME: Duration = Duration::from_secs(120);
const SESSION_LIFETIME_MS: i64 = 300_000;
const TERMINAL_AUDIT_TIMEOUT: Duration = Duration::from_secs(3);

fn denied() -> BrokerError {
    BrokerError::Denied("OIDC administrator identity unavailable")
}
fn invalid() -> BrokerError {
    BrokerError::Frame(rekey_domain::ipc::FrameError::InvalidField)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Administrator {
    subject: String,
    principal_id: PrincipalId,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    format_version: u32,
    issuer: String,
    client_id: String,
    authorization_url: String,
    token_url: String,
    jwks_url: String,
    redirect_uri: String,
    ca_certificate_file: PathBuf,
    directory_identity_url: String,
    directory_ca_certificate_file: PathBuf,
    directory_mapping_sha256: String,
    node_id: String,
    vault_id: VaultId,
    administrators: Vec<Administrator>,
}

struct Endpoint {
    url: Url,
    ca: reqwest::Certificate,
}

fn bounded_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control)
}
fn canonical_node(text: &str) -> bool {
    text.parse::<VaultId>()
        .is_ok_and(|id| id.to_string() == text)
}
fn hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn https(text: &str) -> Result<Url, BrokerError> {
    let url = Url::parse(text).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().is_empty()
    {
        return Err(invalid());
    }
    Ok(url)
}

/// Open once with nofollow and verify the actual opened file and private parent.
fn private_file(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let parent = path.parent().ok_or_else(invalid)?;
    let pm = std::fs::symlink_metadata(parent).map_err(BrokerError::Io)?;
    let uid = unsafe { libc::geteuid() };
    if !pm.is_dir() || pm.uid() != uid || pm.mode() & 0o777 != 0o700 {
        return Err(denied());
    }
    for ancestor in path.ancestors() {
        if std::fs::symlink_metadata(ancestor)
            .map_err(BrokerError::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(denied());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(BrokerError::Io)?;
    read_private(file, max, uid)
}
fn read_private(file: File, max: usize, uid: u32) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let meta = file.metadata().map_err(BrokerError::Io)?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o777 != 0o600 {
        return Err(denied());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(BrokerError::Io)?;
    if bytes.len() > max {
        return Err(invalid());
    }
    Ok(bytes)
}

impl Profile {
    fn validate(&self) -> Result<(), BrokerError> {
        let issuer = https(&self.issuer)?;
        if self.format_version != 1
            || !bounded_text(&self.client_id)
            || !canonical_node(&self.node_id)
            || !hex_digest(&self.directory_mapping_sha256)
            || self.administrators.is_empty()
            || self.administrators.len() > 32
        {
            return Err(invalid());
        }
        let mut subjects = BTreeSet::new();
        let mut principals = BTreeSet::new();
        for admin in &self.administrators {
            if !bounded_text(&admin.subject)
                || !subjects.insert(&admin.subject)
                || !principals.insert(admin.principal_id)
            {
                return Err(invalid());
            }
        }
        for endpoint in [&self.authorization_url, &self.token_url, &self.jwks_url] {
            if https(endpoint)?.origin() != issuer.origin() || https(endpoint)?.path() == "/" {
                return Err(invalid());
            }
        }
        if https(&self.directory_identity_url)?.path() != "/v1/directory/admin-identity" {
            return Err(invalid());
        }
        let redirect = Url::parse(&self.redirect_uri).map_err(|_| invalid())?;
        if redirect.scheme() != "http"
            || redirect.host_str() != Some("127.0.0.1")
            || redirect.port().is_none_or(|p| p == 0)
            || redirect.path() != "/oidc/callback"
            || redirect.query().is_some()
            || redirect.fragment().is_some()
            || !redirect.username().is_empty()
            || redirect.password().is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

struct Flow {
    nonce: Zeroizing<String>,
    verifier: Zeroizing<String>,
    cancelled: Arc<AtomicBool>,
    principal_generations: BTreeMap<PrincipalId, u64>,
    deadline: Instant,
    expires_at_ms: i64,
    epoch: u64,
    sender: Option<oneshot::Sender<Result<Zeroizing<String>, BrokerError>>>,
    receiver: Option<oneshot::Receiver<Result<Zeroizing<String>, BrokerError>>>,
}
struct Login {
    principal: PrincipalId,
    subject: String,
    access: Zeroizing<String>,
    expires_at_ms: i64,
    deadline: Instant,
}
struct Session {
    hash: [u8; 32],
    generation: u64,
    principal: PrincipalId,
    subject: String,
    access: Zeroizing<String>,
    deadline: Instant,
    expires_at_ms: i64,
}
#[derive(Clone)]
pub(crate) struct Admission {
    hash: [u8; 32],
    generation: u64,
    pub principal: PrincipalId,
    pub expires_at_ms: i64,
    pub deadline: Instant,
}
struct State {
    epoch: u64,
    next_generation: u64,
    principal_generations: BTreeMap<PrincipalId, u64>,
    flows: BTreeMap<String, Flow>,
    exchanging: BTreeMap<String, Arc<AtomicBool>>,
    sessions: Vec<Session>,
    listener: Option<tokio::task::AbortHandle>,
}

pub(crate) struct Manager {
    profile: Profile,
    token: Endpoint,
    jwks: Endpoint,
    directory: Endpoint,
    owner_uid: u32,
    state: Mutex<State>,
}
impl Manager {
    pub(crate) fn load(path: &Path) -> Result<Arc<Self>, BrokerError> {
        let bytes = private_file(path, 64 * 1024)?;
        let profile: Profile =
            serde_json::from_value(unique_json(&bytes)?).map_err(|_| invalid())?;
        profile.validate()?;
        let ca =
            reqwest::Certificate::from_pem(&private_file(&profile.ca_certificate_file, 64 * 1024)?)
                .map_err(|_| invalid())?;
        let directory_ca = reqwest::Certificate::from_pem(&private_file(
            &profile.directory_ca_certificate_file,
            64 * 1024,
        )?)
        .map_err(|_| invalid())?;
        Ok(Arc::new(Self {
            token: Endpoint {
                url: https(&profile.token_url)?,
                ca: ca.clone(),
            },
            jwks: Endpoint {
                url: https(&profile.jwks_url)?,
                ca,
            },
            directory: Endpoint {
                url: https(&profile.directory_identity_url)?,
                ca: directory_ca,
            },
            profile,
            owner_uid: unsafe { libc::geteuid() },
            state: Mutex::new(State {
                epoch: 0,
                next_generation: 0,
                principal_generations: BTreeMap::new(),
                flows: BTreeMap::new(),
                exchanging: BTreeMap::new(),
                sessions: Vec::new(),
                listener: None,
            }),
        }))
    }
    pub(crate) fn vault_id(&self) -> VaultId {
        self.profile.vault_id
    }
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn clear(&self) {
        let mut state = self.state();
        state.epoch = state.epoch.wrapping_add(1);
        state.flows.clear();
        for flag in state.exchanging.values() {
            flag.store(true, Ordering::SeqCst);
        }
        state.exchanging.clear();
        state.sessions.clear();
        if let Some(task) = state.listener.take() {
            task.abort();
        }
    }
    pub(crate) fn begin(self: &Arc<Self>) -> Result<OidcBeginResponse, BrokerError> {
        let now = crate::now_ts()?.as_unix_ms();
        let deadline = Instant::now() + FLOW_LIFETIME;
        let mut state = self.state();
        state.flows.retain(|_, f| f.deadline > Instant::now());
        if state.flows.len() + state.exchanging.len() >= 8 {
            return Err(denied());
        }
        if state.listener.is_none() {
            let redirect = Url::parse(&self.profile.redirect_uri).map_err(|_| invalid())?;
            let listener =
                std::net::TcpListener::bind(("127.0.0.1", redirect.port().ok_or_else(invalid)?))
                    .map_err(BrokerError::Io)?;
            listener.set_nonblocking(true).map_err(BrokerError::Io)?;
            let listener = TcpListener::from_std(listener).map_err(BrokerError::Io)?;
            let weak = Arc::downgrade(self);
            let task = tokio::spawn(async move {
                // One bounded callback at a time; malformed peers cannot allocate tasks.
                while let Ok((stream, _)) = listener.accept().await {
                    let Some(manager) = weak.upgrade() else { break };
                    let _ = tokio::time::timeout(Duration::from_secs(3), manager.callback(stream))
                        .await;
                }
            });
            state.listener = Some(task.abort_handle());
        }
        let flow_id = random_token()?;
        let nonce = random_token()?;
        let verifier = random_token()?;
        let challenge = BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));
        let mut url = Url::parse(&self.profile.authorization_url).map_err(|_| invalid())?;
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &self.profile.client_id),
            ("redirect_uri", &self.profile.redirect_uri),
            ("scope", "openid"),
            ("state", flow_id.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
        let (sender, receiver) = oneshot::channel();
        let epoch = state.epoch;
        let principal_generations = state.principal_generations.clone();
        state.flows.insert(
            flow_id.to_string(),
            Flow {
                nonce,
                verifier,
                principal_generations,
                cancelled: Arc::new(AtomicBool::new(false)),
                deadline,
                expires_at_ms: now + 120_000,
                epoch,
                sender: Some(sender),
                receiver: Some(receiver),
            },
        );
        Ok(OidcBeginResponse {
            flow_id: flow_id.to_string(),
            authorization_url: url.into(),
            expires_at_ms: now + 120_000,
        })
    }
    pub(crate) fn cancel(&self, id: &str) -> Result<(), BrokerError> {
        let mut state = self.state();
        if state.flows.remove(id).is_some() {
            return Ok(());
        }
        if let Some(cancelled) = state.exchanging.remove(id) {
            cancelled.store(true, Ordering::SeqCst);
            return Ok(());
        }
        Err(denied())
    }
    async fn callback(&self, mut stream: TcpStream) -> Result<(), BrokerError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunk = [0u8; 512];
        loop {
            let n = stream.read(&mut chunk).await.map_err(BrokerError::Io)?;
            if n == 0 || bytes.len() + n > 8192 {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk[..n]);
            chunk.zeroize();
            if bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                break;
            }
        }
        let parsed = self.parse_callback(&bytes);
        if let Ok((id, result)) = parsed {
            let mut state = self.state();
            if let Some(flow) = state.flows.get_mut(&id)
                && flow.deadline > Instant::now()
                && let Some(sender) = flow.sender.take()
            {
                let _ = sender.send(result);
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nReturn to the Rekey CLI.").await.map_err(BrokerError::Io)?;
        Ok(())
    }
    fn parse_callback(
        &self,
        bytes: &[u8],
    ) -> Result<(String, Result<Zeroizing<String>, BrokerError>), BrokerError> {
        let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
        let (head, rest) = text.split_once("\r\n\r\n").ok_or_else(invalid)?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        let mut lines = head.split("\r\n");
        let request = lines.next().ok_or_else(invalid)?;
        let words = request.split(' ').collect::<Vec<_>>();
        if words.len() != 3
            || words[0] != "GET"
            || words[2] != "HTTP/1.1"
            || !words[1].starts_with("/oidc/callback?")
        {
            return Err(invalid());
        }
        let redirect = Url::parse(&self.profile.redirect_uri).map_err(|_| invalid())?;
        let expected_host = format!("127.0.0.1:{}", redirect.port().ok_or_else(invalid)?);
        let mut hosts = 0;
        for line in lines {
            let (name, value) = line.split_once(':').ok_or_else(invalid)?;
            if name.eq_ignore_ascii_case("host") {
                hosts += 1;
                if value.trim() != expected_host {
                    return Err(invalid());
                }
            }
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                return Err(invalid());
            }
        }
        if hosts != 1 {
            return Err(invalid());
        }
        let url =
            Url::parse(&format!("http://{expected_host}{}", words[1])).map_err(|_| invalid())?;
        if url.path() != "/oidc/callback" || url.fragment().is_some() {
            return Err(invalid());
        }
        let mut fields = BTreeMap::new();
        for (key, value) in url.query_pairs() {
            if fields
                .insert(key.into_owned(), Zeroizing::new(value.into_owned()))
                .is_some()
            {
                return Err(invalid());
            }
        }
        let id = fields.remove("state").ok_or_else(invalid)?.to_string();
        rekey_domain::ipc::validate_management_token(id.as_bytes())?;
        if fields
            .get("iss")
            .is_some_and(|iss| iss.as_str() != self.profile.issuer)
        {
            return Err(invalid());
        }
        let error = fields.remove("error");
        let code = fields.remove("code");
        let result = match (error, code) {
            (Some(_), None) => Err(denied()),
            (None, Some(code)) if !code.is_empty() && !code.chars().any(char::is_control) => {
                Ok(code)
            }
            _ => return Err(invalid()),
        };
        Ok((id, result))
    }
    pub(crate) async fn finish(
        &self,
        id: &str,
        ctx: &BrokerCtx,
    ) -> Result<(OidcSessionResponse, Zeroizing<Vec<u8>>), BrokerError> {
        let (receiver, deadline) = {
            let mut state = self.state();
            let flow = state.flows.get_mut(id).ok_or_else(denied)?;
            (flow.receiver.take().ok_or_else(denied)?, flow.deadline)
        };
        let code = match tokio::time::timeout_at(deadline, receiver).await {
            Ok(Ok(code)) => code,
            _ => Err(denied()),
        };
        // Consume before any token exchange; cancellation and generation still gate publication.
        let flow = {
            let mut state = self.state();
            let flow = state.flows.remove(id);
            if let Some(flow) = &flow {
                state
                    .exchanging
                    .insert(id.to_owned(), flow.cancelled.clone());
            }
            flow
        };
        let result = match (flow, code) {
            (Some(flow), Ok(code)) => self.complete(code, flow, ctx).await,
            _ => Err(denied()),
        };
        self.state().exchanging.remove(id);
        // A previous audit failure already faulted the broker and keeps its typed error.
        // Ordinary terminal failure gets its own audit budget after flow consumption;
        // this never extends the original deadline for successful login admission.
        if result.is_err()
            && !matches!(
                &result,
                Err(BrokerError::Authority(
                    rekey_vault::AuthorityError::AuditCommitFailed
                        | rekey_vault::AuthorityError::AuthorityBusy
                        | rekey_vault::AuthorityError::Faulted
                ))
            )
        {
            self.audit(
                ctx,
                None,
                "login_failed",
                None,
                Instant::now() + TERMINAL_AUDIT_TIMEOUT,
            )
            .await?;
        }
        result
    }
    async fn complete(
        &self,
        code: Zeroizing<String>,
        flow: Flow,
        ctx: &BrokerCtx,
    ) -> Result<(OidcSessionResponse, Zeroizing<Vec<u8>>), BrokerError> {
        if flow.cancelled.load(Ordering::SeqCst) || self.state().epoch != flow.epoch {
            return Err(denied());
        }
        let mut form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("client_id", &self.profile.client_id),
                    ("redirect_uri", &self.profile.redirect_uri),
                    ("code_verifier", flow.verifier.as_str()),
                ])
                .finish(),
        );
        let exchange_instant = Instant::now();
        let exchange_start = crate::now_ts()?.as_unix_ms();
        let bytes = self
            .request(&self.token, Some(&form), None, 64 * 1024, flow.deadline)
            .await?;
        form.zeroize();
        let response = CodeResponse::parse(&bytes)?;
        let validation_instant = Instant::now();
        let now = crate::now_ts()?;
        let access_expiry = exchange_start
            .checked_add(response.expires_in.checked_mul(1000).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let access_deadline = exchange_instant
            .checked_add(Duration::from_millis(
                (access_expiry - exchange_start) as u64,
            ))
            .ok_or_else(invalid)?;
        let jwks = self
            .request(&self.jwks, None, None, 64 * 1024, flow.deadline)
            .await?;
        let identity = verify_id_token(
            response.id_token.as_bytes(),
            &jwks,
            &OidcAdminContext {
                issuer: &self.profile.issuer,
                client_id: &self.profile.client_id,
                expected_nonce: &flow.nonce,
                now,
                access_token: &response.access_token,
            },
        )?;
        let id_deadline = validation_instant
            .checked_add(Duration::from_millis(
                (identity.expires_at_ms - now.as_unix_ms()) as u64,
            ))
            .ok_or_else(invalid)?;
        let admin = self
            .profile
            .administrators
            .iter()
            .find(|a| a.subject == identity.subject)
            .ok_or_else(denied)?;
        if let Err(error) = self
            .proof(
                &response.access_token,
                admin.principal_id,
                &identity.subject,
                flow.deadline,
            )
            .await
        {
            ctx.lifecycle.reject_if_not_running()?;
            self.close_principal(
                ctx,
                admin.principal_id,
                "offboard_or_unknown",
                flow.deadline,
            )
            .await?;
            return Err(error);
        }
        let now = crate::now_ts()?.as_unix_ms();
        let expiry = identity
            .expires_at_ms
            .min(access_expiry)
            .min(now + SESSION_LIFETIME_MS);
        if expiry <= now
            || flow.cancelled.load(Ordering::SeqCst)
            || self.state().epoch != flow.epoch
            || Instant::now() >= flow.deadline
            || now >= flow.expires_at_ms
        {
            return Err(denied());
        }
        self.publish_login(
            ctx,
            &flow,
            Login {
                principal: admin.principal_id,
                subject: identity.subject,
                access: response.access_token,
                expires_at_ms: expiry,
                deadline: management_deadline(
                    access_deadline,
                    id_deadline,
                    Instant::now(),
                    expiry - now,
                )?,
            },
        )
        .await
    }
    async fn publish_login(
        &self,
        ctx: &BrokerCtx,
        flow: &Flow,
        login: Login,
    ) -> Result<(OidcSessionResponse, Zeroizing<Vec<u8>>), BrokerError> {
        let principal_generation = *flow
            .principal_generations
            .get(&login.principal)
            .unwrap_or(&0);
        {
            let state = self.state();
            if state.epoch != flow.epoch
                || flow.cancelled.load(Ordering::SeqCst)
                || state
                    .principal_generations
                    .get(&login.principal)
                    .copied()
                    .unwrap_or(0)
                    != principal_generation
                || Instant::now() >= flow.deadline
                || Instant::now() >= login.deadline
                || crate::now_ts()?.as_unix_ms() >= login.expires_at_ms
            {
                return Err(denied());
            }
        }
        ctx.lifecycle.reject_if_not_running()?;
        self.audit(
            ctx,
            Some(login.principal),
            "login_success",
            None,
            flow.deadline,
        )
        .await?;
        let token = random_token()?;
        let mut state = self.state();
        ctx.lifecycle.reject_if_not_running()?;
        if state
            .principal_generations
            .get(&login.principal)
            .copied()
            .unwrap_or(0)
            != principal_generation
            || state.epoch != flow.epoch
            || flow.cancelled.load(Ordering::SeqCst)
            || Instant::now() >= flow.deadline
            || Instant::now() >= login.deadline
            || crate::now_ts()?.as_unix_ms() >= login.expires_at_ms
            || state.sessions.len() >= 32
        {
            return Err(denied());
        }
        state.next_generation = state.next_generation.wrapping_add(1);
        let generation = state.next_generation;
        let response = OidcSessionResponse {
            principal_id: login.principal,
            expires_at_ms: login.expires_at_ms,
            mapping_sha256: self.profile.directory_mapping_sha256.clone(),
        };
        // Cancel and successful publication share this owner decision. After insertion,
        // the completed exchange is no longer cancellable as an in-flight login.
        state
            .exchanging
            .retain(|_, cancelled| !Arc::ptr_eq(cancelled, &flow.cancelled));
        state.sessions.push(Session {
            hash: Sha256::digest(token.as_bytes()).into(),
            generation,
            principal: login.principal,
            subject: login.subject,
            access: login.access,
            deadline: login.deadline,
            expires_at_ms: login.expires_at_ms,
        });
        Ok((response, Zeroizing::new(token.as_bytes().to_vec())))
    }
    async fn request(
        &self,
        endpoint: &Endpoint,
        form: Option<&str>,
        access: Option<&str>,
        max: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
        let future = async {
            let host = endpoint.url.host_str().ok_or_else(invalid)?;
            let port = endpoint.url.port_or_known_default().ok_or_else(invalid)?;
            let addresses = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| denied())?
                .collect::<Vec<_>>();
            if addresses.is_empty() || addresses.len() > 32 {
                return Err(denied());
            }
            let client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .tls_built_in_root_certs(false)
                .add_root_certificate(endpoint.ca.clone())
                .resolve_to_addrs(host, &addresses)
                .timeout(deadline.saturating_duration_since(Instant::now()))
                .build()
                .map_err(|_| denied())?;
            let mut request = if let Some(form) = form {
                client
                    .post(endpoint.url.clone())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(form.to_owned())
            } else {
                client.get(endpoint.url.clone())
            };
            if let Some(access) = access {
                request = request.bearer_auth(access);
            }
            let mut response = request.send().await.map_err(|_| denied())?;
            if response.status() != reqwest::StatusCode::OK
                || response.content_length().is_some_and(|n| n > max as u64)
            {
                return Err(denied());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            while let Some(chunk) = response.chunk().await.map_err(|_| denied())? {
                if bytes.len() + chunk.len() > max {
                    return Err(denied());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        };
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| denied())?
    }
    async fn proof(
        &self,
        access: &str,
        principal: PrincipalId,
        subject: &str,
        deadline: Instant,
    ) -> Result<(), BrokerError> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(3));
        let bytes = self
            .request(&self.directory, None, Some(access), 4096, deadline)
            .await?;
        let proof: DirectoryProof =
            serde_json::from_value(unique_json(&bytes)?).map_err(|_| invalid())?;
        proof.validate(&self.profile, principal, subject)
    }
    fn snapshot(
        &self,
        token: &[u8],
    ) -> Result<(Admission, String, Zeroizing<String>), BrokerError> {
        rekey_domain::ipc::validate_management_token(token)?;
        if unsafe { libc::geteuid() } != self.owner_uid {
            return Err(denied());
        }
        let hash: [u8; 32] = Sha256::digest(token).into();
        let state = self.state();
        let session = state
            .sessions
            .iter()
            .find(|s| s.hash == hash)
            .ok_or_else(denied)?;
        Ok((
            Admission {
                hash,
                generation: session.generation,
                principal: session.principal,
                expires_at_ms: session.expires_at_ms,
                deadline: session.deadline,
            },
            session.subject.clone(),
            session.access.clone(),
        ))
    }
    pub(crate) async fn admit(
        &self,
        token: &[u8],
        ctx: &BrokerCtx,
        deadline: Instant,
    ) -> Result<Admission, BrokerError> {
        let (admission, subject, access) = self.snapshot(token)?;
        if self
            .proof(&access, admission.principal, &subject, deadline)
            .await
            .is_err()
            || self.publish(&admission, ctx, || ()).is_err()
        {
            ctx.lifecycle.reject_if_not_running()?;
            self.close_principal(ctx, admission.principal, "offboard_or_expired", deadline)
                .await?;
            return Err(denied());
        }
        Ok(admission)
    }
    /// No await under this owner: logout/expiry cannot race final token publication.
    pub(crate) fn publish<T>(
        &self,
        admission: &Admission,
        ctx: &BrokerCtx,
        publish: impl FnOnce() -> T,
    ) -> Result<T, BrokerError> {
        let state = self.state();
        ctx.lifecycle.reject_if_not_running()?;
        let now = crate::now_ts()?.as_unix_ms();
        if !state.sessions.iter().any(|s| {
            s.hash == admission.hash
                && s.generation == admission.generation
                && s.deadline > Instant::now()
                && s.expires_at_ms > now
        }) {
            return Err(denied());
        }
        Ok(publish())
    }
    pub(crate) async fn human_admission(
        &self,
        principal: PrincipalId,
        ctx: &BrokerCtx,
        deadline: Instant,
    ) -> Result<Admission, BrokerError> {
        let (admission, subject, access) = {
            let state = self.state();
            let s = state
                .sessions
                .iter()
                .find(|s| s.principal == principal)
                .ok_or_else(denied)?;
            (
                Admission {
                    hash: s.hash,
                    generation: s.generation,
                    principal,
                    expires_at_ms: s.expires_at_ms,
                    deadline: s.deadline,
                },
                s.subject.clone(),
                s.access.clone(),
            )
        };
        if self
            .proof(&access, principal, &subject, deadline)
            .await
            .is_err()
            || self.publish(&admission, ctx, || ()).is_err()
        {
            ctx.lifecycle.reject_if_not_running()?;
            self.close_principal(ctx, principal, "offboard_or_expired", deadline)
                .await?;
            return Err(denied());
        }
        Ok(admission)
    }
    pub(crate) fn human_binding(
        &self,
        snapshot: &rekey_policy::ValidatedSnapshot,
        principal: PrincipalId,
    ) -> bool {
        self.profile.administrators.iter().any(|a| {
            a.principal_id == principal
                && snapshot.has_oidc_human_binding(&self.profile.issuer, &a.subject, principal)
        })
    }
    pub(crate) async fn logout(
        &self,
        token: &[u8],
        ctx: &BrokerCtx,
    ) -> Result<OidcLogoutResponse, BrokerError> {
        let (admission, _, _) = self.snapshot(token)?;
        self.close_principal(
            ctx,
            admission.principal,
            "logout",
            Instant::now() + Duration::from_secs(25),
        )
        .await
    }
    async fn close_principal(
        &self,
        ctx: &BrokerCtx,
        principal: PrincipalId,
        reason: &str,
        io_deadline: Instant,
    ) -> Result<OidcLogoutResponse, BrokerError> {
        let counts = {
            let mut state = self.state();
            let before = state.sessions.len();
            let generation = state.principal_generations.entry(principal).or_default();
            *generation = generation.wrapping_add(1);
            state.sessions.retain(|s| s.principal != principal);
            let (capabilities, pending_approvals) = ctx.sessions.revoke_principal(principal);
            OidcLogoutResponse {
                management_sessions: before - state.sessions.len(),
                capabilities,
                pending_approvals,
            }
        };
        let terminal_deadline = Instant::now() + TERMINAL_AUDIT_TIMEOUT;
        // Successful logout also stays inside its original operation budget.
        let audit_deadline = if reason == "logout" {
            terminal_deadline.min(io_deadline)
        } else {
            terminal_deadline
        };
        self.audit(ctx, Some(principal), reason, Some(&counts), audit_deadline)
            .await?;
        Ok(counts)
    }
    async fn audit(
        &self,
        ctx: &BrokerCtx,
        principal: Option<PrincipalId>,
        reason: &str,
        counts: Option<&OidcLogoutResponse>,
        deadline: Instant,
    ) -> Result<(), BrokerError> {
        let reason = format!(
            "oidc.{reason};node={};mapping={};principal={};management={};capabilities={};pending={}",
            self.profile.node_id,
            self.profile.directory_mapping_sha256,
            principal
                .map(|p| p.to_string())
                .unwrap_or_else(|| "none".into()),
            counts.map_or(0, |c| c.management_sessions),
            counts.map_or(0, |c| c.capabilities),
            counts.map_or(0, |c| c.pending_approvals)
        );
        let audit = AuditDraft {
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            event_type: "admin.oidc",
            outcome: if reason.starts_with("oidc.login_failed") {
                outcome::FAILURE
            } else {
                outcome::SUCCESS
            },
            reason_code: reason,
            upstream_status: None,
            latency_ms: None,
        };
        let result = match tokio::time::timeout_at(
            deadline,
            ctx.authority
                .commit_audit_before(audit, Some(deadline.into_std())),
        )
        .await
        {
            Ok(Ok(())) if Instant::now() < deadline => Ok(()),
            Ok(Err(error)) => Err(error),
            // The actor checks its deadline at dequeue, but SQLite can finish later.
            // A ready success observed after the boundary is also a terminal timeout.
            Ok(Ok(())) | Err(_) => Err(rekey_vault::AuthorityError::AuthorityBusy),
        };
        if let Err(error) = result {
            self.clear();
            ctx.sessions.close_and_revoke_all();
            ctx.request_fault();
            return Err(error.into());
        }
        Ok(())
    }
    async fn close_incomplete_batch(
        &self,
        ctx: &BrokerCtx,
        affected: BTreeSet<PrincipalId>,
        _io_deadline: Instant,
    ) -> Result<(), BrokerError> {
        // Close the entire incomplete original batch before the first audit await.
        let receipts = {
            let mut state = self.state();
            let mut receipts = Vec::new();
            for principal in affected {
                let before = state.sessions.len();
                state.sessions.retain(|s| s.principal != principal);
                let generation = state.principal_generations.entry(principal).or_default();
                *generation = generation.wrapping_add(1);
                let (capabilities, pending_approvals) = ctx.sessions.revoke_principal(principal);
                receipts.push((
                    principal,
                    OidcLogoutResponse {
                        management_sessions: before - state.sessions.len(),
                        capabilities,
                        pending_approvals,
                    },
                ));
            }
            receipts
        };
        let terminal_deadline = Instant::now() + TERMINAL_AUDIT_TIMEOUT;
        for (principal, counts) in receipts {
            self.audit(
                ctx,
                Some(principal),
                "poll_incomplete",
                Some(&counts),
                terminal_deadline,
            )
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn poll(self: &Arc<Self>, ctx: &Arc<BrokerCtx>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let principals = {
            let state = self.state();
            state
                .sessions
                .iter()
                .map(|s| s.principal)
                .collect::<BTreeSet<_>>()
        };
        let affected = principals.clone();
        let mut pending = principals.into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            while tasks.len() < 4 {
                let Some(principal) = pending.next() else {
                    break;
                };
                let manager = self.clone();
                let ctx = ctx.clone();
                tasks.spawn(async move {
                    let _ = manager.human_admission(principal, &ctx, deadline).await;
                });
            }
            if tasks.is_empty() {
                break;
            }
            if tokio::time::timeout_at(deadline, tasks.join_next())
                .await
                .is_err()
            {
                tasks.abort_all();
                let _ = self.close_incomplete_batch(ctx, affected, deadline).await;
                break;
            }
        }
    }
}

fn management_deadline(
    access_deadline: Instant,
    id_deadline: Instant,
    installed_at: Instant,
    remaining_wall_ms: i64,
) -> Result<Instant, BrokerError> {
    installed_at
        .checked_add(Duration::from_millis(
            u64::try_from(remaining_wall_ms).map_err(|_| invalid())?,
        ))
        .map(|wall_deadline| {
            wall_deadline
                .min(access_deadline)
                .min(id_deadline)
                .min(installed_at + Duration::from_millis(SESSION_LIFETIME_MS as u64))
        })
        .ok_or_else(invalid)
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.clear();
    }
}

fn random_token() -> Result<Zeroizing<String>, BrokerError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| rekey_vault::AuthorityError::EntropyUnavailable)?;
    Ok(Zeroizing::new(BASE64URL_NOPAD.encode(bytes.as_ref())))
}

struct CodeResponse {
    access_token: Zeroizing<String>,
    id_token: Zeroizing<String>,
    expires_in: i64,
}
impl CodeResponse {
    fn parse(bytes: &[u8]) -> Result<Self, BrokerError> {
        let mut value = unique_json(bytes)?;
        let result = (|| {
            let fields = value.as_object().ok_or_else(invalid)?;
            let take = |name| fields.get(name).ok_or_else(invalid);
            let access = take("access_token")?;
            let id = take("id_token")?;
            let kind = take("token_type")?;
            let expiry = take("expires_in")?;
            let access = Zeroizing::new(access.as_str().ok_or_else(invalid)?.to_owned());
            let id = Zeroizing::new(id.as_str().ok_or_else(invalid)?.to_owned());
            if access.is_empty()
                || access.len() > 8192
                || access.chars().any(char::is_control)
                || id.is_empty()
                || id.len() > 16384
                || kind.as_str() != Some("Bearer")
            {
                return Err(invalid());
            }
            let expires_in = expiry.as_i64().filter(|v| *v > 0).ok_or_else(invalid)?;
            Ok(Self {
                access_token: access,
                id_token: id,
                expires_in,
            })
        })();
        wipe_json(&mut value);
        result
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DirectoryProof {
    format_version: u32,
    issuer: String,
    subject: String,
    principal_id: PrincipalId,
    mapping_version: u64,
    mapping_sha256: String,
    nodes: Vec<Node>,
    observed_at_ms: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Node {
    node_id: String,
    vault_id: VaultId,
}
impl DirectoryProof {
    fn validate(
        &self,
        profile: &Profile,
        principal: PrincipalId,
        subject: &str,
    ) -> Result<(), BrokerError> {
        let now = crate::now_ts()?.as_unix_ms();
        if self.format_version != 1
            || self.mapping_version == 0
            || self.issuer != profile.issuer
            || self.subject != subject
            || self.principal_id != principal
            || self.mapping_sha256 != profile.directory_mapping_sha256
            || self.observed_at_ms < 0
            || self.observed_at_ms > now
            || self.nodes.len() != 2
            || !self.nodes.iter().all(|n| canonical_node(&n.node_id))
            || self.nodes[0].node_id == self.nodes[1].node_id
            || self.nodes[0].vault_id == self.nodes[1].vault_id
            || !self
                .nodes
                .iter()
                .any(|n| n.node_id == profile.node_id && n.vault_id == profile.vault_id)
        {
            return Err(denied());
        }
        Ok(())
    }
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => (),
    }
}
/// Recursive unique-key parser: unknown duplicate fields are rejected too.
fn unique_json(bytes: &[u8]) -> Result<Value, BrokerError> {
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Value;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("unique JSON")
                }
                fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
                    Ok(Value::Bool(v))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
                    Ok(v.into())
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
                    Ok(v.into())
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
                    serde_json::Number::from_f64(v)
                        .map(Value::Number)
                        .ok_or_else(|| E::custom("number"))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
                    Ok(Value::String(v.into()))
                }
                fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
                    Ok(Value::String(v))
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                    Ok(Value::Null)
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> Result<Value, A::Error> {
                    let mut values = Vec::new();
                    while let Some(v) = a.next_element::<Unique>()? {
                        values.push(v.0)
                    }
                    Ok(Value::Array(values))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> Result<Value, A::Error> {
                    let mut fields = serde_json::Map::new();
                    while let Some(key) = a.next_key::<String>()? {
                        if fields.contains_key(&key) {
                            return Err(serde::de::Error::custom("duplicate"));
                        }
                        fields.insert(key, a.next_value::<Unique>()?.0);
                    }
                    Ok(Value::Object(fields))
                }
            }
            d.deserialize_any(Visitor).map(Unique)
        }
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let result = Unique::deserialize(&mut de).map_err(|_| invalid())?.0;
    de.end().map_err(|_| invalid())?;
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rekey_domain::authorization::Principal;
    use rekey_domain::capability::{ActionVersionRef, SessionGrant};
    use rekey_domain::ids::{ActionId, SessionId, TenantId};
    use serde_json::json;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    fn profile(vault: VaultId) -> Profile {
        Profile {
            format_version: 1,
            issuer: "https://issuer.example".into(),
            client_id: "rekey-admin".into(),
            authorization_url: "https://issuer.example/authorize".into(),
            token_url: "https://issuer.example/token".into(),
            jwks_url: "https://issuer.example/jwks".into(),
            redirect_uri: "http://127.0.0.1:45781/oidc/callback".into(),
            ca_certificate_file: "unused".into(),
            directory_identity_url: "https://directory.example/v1/directory/admin-identity".into(),
            directory_ca_certificate_file: "unused".into(),
            directory_mapping_sha256: "a".repeat(64),
            node_id: "11111111-1111-4111-8111-111111111111".into(),
            vault_id: vault,
            administrators: vec![Administrator {
                subject: "stable-admin".into(),
                principal_id: PrincipalId::new_random(),
            }],
        }
    }
    fn manager(vault: VaultId) -> Arc<Manager> {
        let profile = profile(vault);
        let cert = rcgen::generate_simple_self_signed(vec!["issuer.example".into()]).unwrap();
        let ca = reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap();
        Arc::new(Manager {
            token: Endpoint {
                url: https(&profile.token_url).unwrap(),
                ca: ca.clone(),
            },
            jwks: Endpoint {
                url: https(&profile.jwks_url).unwrap(),
                ca: ca.clone(),
            },
            directory: Endpoint {
                url: https(&profile.directory_identity_url).unwrap(),
                ca,
            },
            profile,
            owner_uid: unsafe { libc::geteuid() },
            state: Mutex::new(State {
                epoch: 0,
                next_generation: 0,
                principal_generations: BTreeMap::new(),
                flows: BTreeMap::new(),
                exchanging: BTreeMap::new(),
                sessions: Vec::new(),
                listener: None,
            }),
        })
    }
    pub(crate) fn protected_profile_file(directory: &Path, vault: VaultId) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::fs::canonicalize(directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ca = directory.join("oidc-ca.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["issuer.example".into()]).unwrap();
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut p = profile(vault);
        p.ca_certificate_file = ca.clone();
        p.directory_ca_certificate_file = ca;
        let path = directory.join("oidc-profile.json");
        std::fs::write(&path, serde_json::to_vec(&p).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    #[tokio::test]
    async fn oidc_protected_profile_load_and_actual_vault_reject_before_sockets() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let state = root.join("state");
        let outcome = rekey_vault::bootstrap::init_vault(
            &state,
            &rekey_vault::secret::SecretInput::from_slice(b"fixture-proof"),
            rekey_vault::crypto::kdf::Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let path = protected_profile_file(&root, outcome.vault_id);
        let manager = Manager::load(&path).unwrap();
        assert_eq!(manager.vault_id(), outcome.vault_id);
        let symlink = root.join("alias.json");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(Manager::load(&symlink).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Manager::load(&path).is_err());
        let wrong = protected_profile_file(&root, VaultId::new_random());
        let mut config = crate::runtime::BrokerConfig::new(state.clone());
        config.oidc_admin_profile = Some(wrong);
        assert_eq!(
            crate::runtime::serve(config).await.err().unwrap().code(),
            "REQUEST_DENIED"
        );
        assert!(!state.join("runtime/admin.sock").exists());
    }

    /// State-only Begin fixture: no real listener, URL reachability or TLS claim.
    pub(crate) fn socketless_begin_fixture(vault: VaultId) -> Arc<Manager> {
        let manager = manager(vault);
        let pending = tokio::spawn(std::future::pending::<()>());
        manager.state().listener = Some(pending.abort_handle());
        manager
    }
    fn flow(manager: &Manager) -> Flow {
        let state = manager.state();
        let (sender, receiver) = oneshot::channel();
        Flow {
            nonce: Zeroizing::new("synthetic-nonce".into()),
            verifier: Zeroizing::new("synthetic-verifier".into()),
            cancelled: Arc::new(AtomicBool::new(false)),
            principal_generations: state.principal_generations.clone(),
            deadline: Instant::now() + FLOW_LIFETIME,
            expires_at_ms: crate::now_ts().unwrap().as_unix_ms() + 120_000,
            epoch: state.epoch,
            sender: Some(sender),
            receiver: Some(receiver),
        }
    }
    // Explicit synthetic state fixture only; publish_login tests are not C1/TLS login proof.
    fn login(manager: &Manager) -> Login {
        Login {
            principal: manager.profile.administrators[0].principal_id,
            subject: "stable-admin".into(),
            access: Zeroizing::new("synthetic-source-token".into()),
            expires_at_ms: crate::now_ts().unwrap().as_unix_ms() + 60_000,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }
    async fn cleanup(
        ctx: Arc<BrokerCtx>,
        join: std::thread::JoinHandle<()>,
        terminal: tokio::task::JoinHandle<()>,
    ) {
        if ctx.authority.status().await.unwrap().state != "faulted" {
            ctx.authority.lock("oidc-test-cleanup").await.unwrap();
        }
        ctx.authority.shutdown(None).await.unwrap();
        drop(ctx);
        terminal.await.unwrap();
        join.join().unwrap();
    }
    fn proof(profile: &Profile) -> DirectoryProof {
        DirectoryProof {
            format_version: 1,
            issuer: profile.issuer.clone(),
            subject: profile.administrators[0].subject.clone(),
            principal_id: profile.administrators[0].principal_id,
            mapping_version: 1,
            mapping_sha256: profile.directory_mapping_sha256.clone(),
            nodes: vec![
                Node {
                    node_id: profile.node_id.clone(),
                    vault_id: profile.vault_id,
                },
                Node {
                    node_id: "22222222-2222-4222-8222-222222222222".into(),
                    vault_id: VaultId::new_random(),
                },
            ],
            observed_at_ms: crate::now_ts().unwrap().as_unix_ms(),
        }
    }
    #[test]
    fn review_exchange_clock_rollback_keeps_original_access_deadline() {
        let start = Instant::now();
        let access = start + Duration::from_secs(60);
        let id = start + Duration::from_secs(600);
        // Ten seconds elapsed with wall clock thirty seconds behind: old arithmetic gives M+80.
        let computed =
            management_deadline(access, id, start + Duration::from_secs(10), 70_000).unwrap();
        assert_eq!(computed, access);
        let early_id = start + Duration::from_secs(45);
        assert_eq!(
            management_deadline(access, early_id, start + Duration::from_secs(10), 70_000).unwrap(),
            early_id
        );
        let installed = start + Duration::from_secs(10);
        assert_eq!(
            management_deadline(start + Duration::from_secs(1000), id, installed, 900_000).unwrap(),
            installed + Duration::from_secs(300)
        );
        assert_eq!(
            management_deadline(access, id, installed, 5_000).unwrap(),
            installed + Duration::from_secs(5)
        );
    }
    #[tokio::test]
    async fn review_expired_finish_consumes_flow_and_commits_failure_without_fault() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let id = "A".repeat(43);
        let mut f = flow(&manager);
        f.deadline = Instant::now() - Duration::from_millis(1);
        f.expires_at_ms = crate::now_ts().unwrap().as_unix_ms() - 1;
        manager.state().flows.insert(id.clone(), f);
        let error = manager.finish(&id, &ctx).await.err().unwrap();
        assert_eq!(error.code(), "REQUEST_DENIED");
        assert!(manager.state().flows.is_empty());
        assert!(manager.state().exchanging.is_empty());
        assert_eq!(ctx.authority.status().await.unwrap().state, "unlocked");
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        let count:i64=db.query_row("SELECT count(*) FROM audit_events WHERE event_type='admin.oidc' AND outcome='failure' AND reason_code LIKE 'oidc.login_failed%'",[],|r|r.get(0)).unwrap();
        assert_eq!(count, 1);
        cleanup(ctx, join, terminal).await;
    }
    #[tokio::test]
    async fn review_expired_poll_closes_identity_then_commits_real_audit_without_fault() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let principal = manager.profile.administrators[0].principal_id;
        let (_, token) = manager
            .publish_login(&ctx, &flow(&manager), login(&manager))
            .await
            .unwrap();
        manager
            .close_incomplete_batch(
                &ctx,
                BTreeSet::from([principal]),
                Instant::now() - Duration::from_millis(1),
            )
            .await
            .unwrap();
        assert!(manager.snapshot(&token).is_err());
        assert!(manager.state().sessions.is_empty());
        assert_eq!(ctx.authority.status().await.unwrap().state, "unlocked");
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        let count:i64=db.query_row("SELECT count(*) FROM audit_events WHERE event_type='admin.oidc' AND reason_code LIKE 'oidc.poll_incomplete%'",[],|r|r.get(0)).unwrap();
        assert_eq!(count, 1);
        cleanup(ctx, join, terminal).await;
    }
    #[tokio::test]
    async fn review_completed_publication_atomically_consumes_exchange_before_cancel() {
        let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let id = "A".repeat(43);
        let f = flow(&manager);
        manager
            .state()
            .exchanging
            .insert(id.clone(), f.cancelled.clone());
        let (_, token) = manager
            .publish_login(&ctx, &f, login(&manager))
            .await
            .unwrap();
        assert_eq!(manager.cancel(&id).err().unwrap().code(), "REQUEST_DENIED");
        assert!(!f.cancelled.load(Ordering::SeqCst));
        assert!(manager.snapshot(&token).is_ok());
        assert!(manager.state().exchanging.is_empty());
        cleanup(ctx, join, terminal).await;
    }

    #[tokio::test]
    async fn review_expired_terminal_audit_failure_preserves_fault_contract() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("CREATE TRIGGER oidc_terminal_fail BEFORE INSERT ON audit_events WHEN NEW.event_type='admin.oidc' BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
        let id = "A".repeat(43);
        let mut f = flow(&manager);
        f.deadline = Instant::now() - Duration::from_millis(1);
        manager.state().flows.insert(id.clone(), f);
        let error = manager.finish(&id, &ctx).await.err().unwrap();
        assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
        assert!(manager.state().flows.is_empty());
        assert!(manager.state().exchanging.is_empty());
        assert!(manager.state().sessions.is_empty());
        assert_eq!(ctx.authority.status().await.unwrap().state, "faulted");
        cleanup(ctx, join, terminal).await;
    }
    #[tokio::test]
    async fn review_cancel_during_real_audit_wins_before_publication() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let id = "A".repeat(43);
        let f = flow(&manager);
        manager
            .state()
            .exchanging
            .insert(id.clone(), f.cancelled.clone());
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut pending = Box::pin(manager.publish_login(&ctx, &f, login(&manager)));
        poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        manager.cancel(&id).unwrap();
        assert!(f.cancelled.load(Ordering::SeqCst));
        assert!(manager.state().exchanging.is_empty());
        db.execute_batch("COMMIT").unwrap();
        assert_eq!(pending.await.err().unwrap().code(), "REQUEST_DENIED");
        assert!(manager.state().sessions.is_empty());
        assert_eq!(ctx.authority.status().await.unwrap().state, "unlocked");
        cleanup(ctx, join, terminal).await;
    }

    #[tokio::test]
    async fn review2_terminal_audit_dequeued_then_sqlite_busy_times_out_and_late_commit_stays_closed()
     {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let (_, token) = manager
            .publish_login(&ctx, &flow(&manager), login(&manager))
            .await
            .unwrap();
        let late_flow = flow(&manager);
        let principal = manager.profile.administrators[0].principal_id;
        let session_id = SessionId::new_random();
        let action = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let grant = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::from_bytes(*manager.vault_id().as_bytes()).unwrap(),
                principal_id: principal,
                session_id,
            },
            vec![action],
            crate::now_ts().unwrap(),
            60_000,
            10,
        )
        .unwrap();
        ctx.sessions.admit(grant, vec![(action, 1000)]).unwrap();
        let path = rekey_vault::paths::vault_db(&dir.path().join("state"));
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(4));
            db.execute_batch("COMMIT").unwrap();
        });
        let result = manager
            .audit(
                &ctx,
                Some(principal),
                "login_failed_db_busy",
                None,
                started + TERMINAL_AUDIT_TIMEOUT,
            )
            .await;
        let elapsed = started.elapsed();
        let closed_before_release = manager.snapshot(&token).is_err()
            && ctx.sessions.active_count(crate::now_ts().unwrap()) == 0
            && ctx.metrics.fault_signals.load(Ordering::Relaxed) == 1;
        // Status is an actual actor FIFO barrier: the original audit can finish late,
        // but cannot restore Manager identity or reopen capability admission.
        ctx.authority.status().await.unwrap();
        release.join().unwrap();
        let db = rusqlite::Connection::open(path).unwrap();
        let late_commits: i64 = db.query_row("SELECT count(*) FROM audit_events WHERE reason_code LIKE 'oidc.login_failed_db_busy%'", [], |r|r.get(0)).unwrap();
        let late_publication = manager
            .publish_login(&ctx, &late_flow, login(&manager))
            .await;
        let stayed_closed =
            manager.snapshot(&token).is_err() && manager.state().sessions.is_empty();
        cleanup(ctx, join, terminal).await;
        assert_eq!(
            late_commits, 1,
            "real audit entered the actor before its deadline and committed after the four-second SQLite lock"
        );
        assert_eq!(result.err().map(|e| e.code()), Some("AUTHORITY_BUSY"));
        assert!(
            elapsed >= TERMINAL_AUDIT_TIMEOUT && elapsed < Duration::from_millis(3600),
            "Broker audit returned at {elapsed:?}"
        );
        assert!(closed_before_release);
        assert_eq!(
            late_publication.err().map(|e| e.code()),
            Some("REQUEST_DENIED")
        );
        assert!(stayed_closed);
    }
    #[tokio::test]
    async fn review2_terminal_audit_queued_behind_sqlite_busy_returns_at_original_deadline() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let path = rekey_vault::paths::vault_db(&dir.path().join("state"));
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let blocking = AuditDraft {
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            event_type: "admin.oidc",
            outcome: outcome::FAILURE,
            reason_code: "review2.actor_sqlite_blocker".into(),
            upstream_status: None,
            latency_ms: None,
        };
        let mut blocker = Box::pin(ctx.authority.append_audit(blocking));
        // This enqueues a genuine SQLite-bound worker command ahead of terminal audit.
        poll_fn(|cx| {
            assert!(blocker.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let started = Instant::now();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(4));
            db.execute_batch("COMMIT").unwrap();
        });
        let result = manager
            .audit(
                &ctx,
                None,
                "login_failed_queued",
                None,
                started + TERMINAL_AUDIT_TIMEOUT,
            )
            .await;
        let elapsed = started.elapsed();
        let fault_before_release = ctx.metrics.fault_signals.load(Ordering::Relaxed) == 1;
        blocker.await.unwrap();
        ctx.authority.status().await.unwrap();
        release.join().unwrap();
        let db = rusqlite::Connection::open(path).unwrap();
        let queued_commits: i64 = db.query_row("SELECT count(*) FROM audit_events WHERE reason_code LIKE 'oidc.login_failed_queued%'", [], |r|r.get(0)).unwrap();
        let blockers: i64 = db.query_row("SELECT count(*) FROM audit_events WHERE reason_code='review2.actor_sqlite_blocker'", [], |r|r.get(0)).unwrap();
        cleanup(ctx, join, terminal).await;
        assert_eq!(blockers, 1);
        assert_eq!(
            queued_commits, 0,
            "expired queued audit cannot commit on late dequeue"
        );
        assert_eq!(result.err().map(|e| e.code()), Some("AUTHORITY_BUSY"));
        assert!(
            elapsed >= TERMINAL_AUDIT_TIMEOUT && elapsed < Duration::from_millis(3600),
            "Broker audit returned at {elapsed:?}"
        );
        assert!(fault_before_release);
    }

    #[tokio::test]
    async fn review2_terminal_audit_ready_success_observed_after_deadline_is_rejected() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let path = rekey_vault::paths::vault_db(&dir.path().join("state"));
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let mut pending = Box::pin(manager.audit(
            &ctx,
            None,
            "login_failed_ready_late",
            None,
            started + TERMINAL_AUDIT_TIMEOUT,
        ));
        poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            db.execute_batch("COMMIT").unwrap();
        });
        // Deliberately stop polling this actual Broker future while the worker commits.
        // timeout_at may see its ready success first; the elapsed boundary must reject it.
        std::thread::sleep(Duration::from_secs(4));
        let result = pending.await;
        release.join().unwrap();
        ctx.authority.status().await.unwrap();
        let db = rusqlite::Connection::open(path).unwrap();
        let committed: i64 = db.query_row("SELECT count(*) FROM audit_events WHERE reason_code LIKE 'oidc.login_failed_ready_late%'", [], |r|r.get(0)).unwrap();
        let faulted = ctx.metrics.fault_signals.load(Ordering::Relaxed) == 1;
        cleanup(ctx, join, terminal).await;
        assert_eq!(
            committed, 1,
            "the real actor completed before the supplied deadline"
        );
        assert_eq!(result.err().map(|e| e.code()), Some("AUTHORITY_BUSY"));
        assert!(faulted);
    }

    #[test]
    fn oidc_profile_is_closed_fixed_origin_and_explicit_human_mapping() {
        let mut p = profile(VaultId::new_random());
        p.validate().unwrap();
        for endpoint in [
            "http://issuer.example/token",
            "https://evil.example/token",
            "https://issuer.example/token?scope=x",
            "https://issuer.example/",
        ] {
            p.token_url = endpoint.into();
            assert!(p.validate().is_err());
        }
        p = profile(VaultId::new_random());
        p.administrators.push(p.administrators[0].clone());
        assert!(p.validate().is_err());
        p = profile(VaultId::new_random());
        p.redirect_uri = "http://localhost:45781/oidc/callback".into();
        assert!(p.validate().is_err());
        p = profile(VaultId::new_random());
        p.directory_mapping_sha256 = "A".repeat(64);
        assert!(p.validate().is_err());
        assert!(unique_json(br#"{"unused":1,"unused":2}"#).is_err());
        assert!(unique_json(br#"{"nested":{"unknown":1,"unknown":2}}"#).is_err());
    }
    #[test]
    fn oidc_directory_proof_exact_bindings_closed_two_nodes_and_time() {
        let p = profile(VaultId::new_random());
        let actual = proof(&p);
        actual
            .validate(&p, p.administrators[0].principal_id, "stable-admin")
            .unwrap();
        let base = serde_json::to_value(&actual).unwrap();
        for (field, value) in [
            ("issuer", json!("https://wrong.example")),
            ("subject", json!("wrong")),
            ("mappingSha256", json!("b".repeat(64))),
            ("mappingVersion", json!(0)),
            ("formatVersion", json!(2)),
            ("observedAtMs", json!(i64::MAX)),
            ("nodes", json!([])),
            ("principalId", json!(PrincipalId::new_random())),
        ] {
            let mut value_json = base.clone();
            value_json[field] = value;
            let proof: DirectoryProof = serde_json::from_value(value_json).unwrap();
            assert!(
                proof
                    .validate(&p, p.administrators[0].principal_id, "stable-admin")
                    .is_err(),
                "{field}"
            );
        }
        let mut extra = base.clone();
        extra["other"] = json!(true);
        assert!(serde_json::from_value::<DirectoryProof>(extra).is_err());
        let mut duplicated = actual;
        duplicated.nodes[1].vault_id = duplicated.nodes[0].vault_id;
        assert!(
            duplicated
                .validate(&p, p.administrators[0].principal_id, "stable-admin")
                .is_err()
        );
    }
    #[test]
    fn oidc_code_response_rejects_duplicate_wrong_type_and_secret_bounds() {
        let valid=br#"{"access_token":"synthetic-access","id_token":"signed.token.placeholder","token_type":"Bearer","expires_in":60,"refresh_token":"discarded"}"#;
        let parsed = CodeResponse::parse(valid).unwrap();
        assert_eq!(parsed.expires_in, 60);
        for bytes in [br#"{"access_token":"x","id_token":"i","token_type":"Bearer","expires_in":0}"#.as_slice(),
            br#"{"access_token":"x","id_token":"i","token_type":"bearer","expires_in":60}"#,
            br#"{"access_token":"x","id_token":"i","token_type":"Bearer","expires_in":60,"unknown":1,"unknown":2}"#,
            br#"{"access_token":"x\n","id_token":"i","token_type":"Bearer","expires_in":60}"#] {assert!(CodeResponse::parse(bytes).is_err());}
        let oversized = json!({"access_token":"x".repeat(8193),"id_token":"i","token_type":"Bearer","expires_in":60});
        assert!(CodeResponse::parse(&serde_json::to_vec(&oversized).unwrap()).is_err());
    }
    #[test]
    fn oidc_callback_exact_host_path_method_unique_query_and_no_body() {
        let manager = manager(VaultId::new_random());
        let state = "A".repeat(43);
        let target = format!(
            "/oidc/callback?state={state}&code=synthetic-code&iss=https%3A%2F%2Fissuer.example&unused=allowed"
        );
        let valid = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:45781\r\n\r\n");
        let (id, code) = manager.parse_callback(valid.as_bytes()).unwrap();
        assert_eq!(id, state);
        assert_eq!(code.unwrap().as_str(), "synthetic-code");
        for bad in [
            valid.replace("GET ", "POST "),
            valid.replace("127.0.0.1:45781", "localhost:45781"),
            valid.replace("/oidc/callback?", "/oidc/callback/other?"),
            valid.replace("&unused=allowed", "&code=another"),
            valid.replace("&unused=allowed", "&unused=again&unused=twice"),
            valid.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
            valid.replace("issuer.example", "other.example"),
            valid.replace("\r\n\r\n", "\r\nHost: 127.0.0.1:45781\r\n\r\n"),
        ] {
            assert!(manager.parse_callback(bad.as_bytes()).is_err());
        }
        let failure = valid.replace("code=synthetic-code", "error=access_denied");
        assert!(
            manager
                .parse_callback(failure.as_bytes())
                .unwrap()
                .1
                .is_err()
        );
    }
    #[tokio::test]
    async fn oidc_eight_pending_flow_bound_rejects_before_binding() {
        let manager = manager(VaultId::new_random());
        for n in 0..8 {
            let flow = flow(&manager);
            manager.state().flows.insert(n.to_string(), flow);
        }
        assert!(manager.begin().is_err());
        assert!(manager.state().listener.is_none());
        manager.clear();
        assert!(manager.state().flows.is_empty());
    }

    #[tokio::test]
    async fn oidc_cancel_consumes_waiting_receiver_and_exchange_never_revives() {
        let manager = manager(VaultId::new_random());
        let id = "A".repeat(43);
        let mut f = flow(&manager);
        let receiver = f.receiver.take().unwrap();
        manager.state().flows.insert(id.clone(), f);
        manager.cancel(&id).unwrap();
        assert!(receiver.await.is_err());
        assert!(manager.cancel(&id).is_err());
        let f = flow(&manager);
        manager
            .state()
            .exchanging
            .insert(id.clone(), f.cancelled.clone());
        manager.cancel(&id).unwrap();
        assert!(f.cancelled.load(Ordering::SeqCst));
        let f = flow(&manager);
        manager.state().exchanging.insert(id, f.cancelled.clone());
        manager.clear();
        assert!(f.cancelled.load(Ordering::SeqCst));
        assert!(manager.state().exchanging.is_empty());
    }
    #[tokio::test]
    async fn oidc_real_authority_audit_before_hash_only_session_and_logout_counts() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let f = flow(&manager);
        let l = login(&manager);
        let principal = l.principal;
        let (response, token) = manager.publish_login(&ctx, &f, l).await.unwrap();
        assert_eq!(response.principal_id, principal);
        let admission = manager.snapshot(&token).unwrap().0;
        assert!(manager.publish(&admission, &ctx, || ()).is_ok());
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        let (count,bare):(i64,i64)=db.query_row("SELECT count(*),count(principal_id) FROM audit_events WHERE event_type='admin.oidc'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!((count, bare), (1, 0));
        let reason: String = db
            .query_row(
                "SELECT reason_code FROM audit_events WHERE event_type='admin.oidc'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(reason.contains(&principal.to_string()));
        assert!(!reason.contains("synthetic-source-token"));
        assert!(!reason.contains(std::str::from_utf8(&token).unwrap()));
        let session_id = SessionId::new_random();
        let action = ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        };
        let grant = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::from_bytes(*manager.vault_id().as_bytes()).unwrap(),
                principal_id: principal,
                session_id,
            },
            vec![action],
            crate::now_ts().unwrap(),
            60_000,
            10,
        )
        .unwrap();
        ctx.sessions.admit(grant, vec![(action, 1000)]).unwrap();
        let counts = manager.logout(&token, &ctx).await.unwrap();
        assert_eq!(
            (
                counts.management_sessions,
                counts.capabilities,
                counts.pending_approvals
            ),
            (1, 1, 0)
        );
        assert!(manager.publish(&admission, &ctx, || ()).is_err());
        assert!(manager.snapshot(&token).is_err());
        assert_eq!(ctx.sessions.active_count(crate::now_ts().unwrap()), 0);
        cleanup(ctx, join, terminal).await;
    }
    #[tokio::test]
    async fn oidc_logout_during_real_audit_cannot_publish_late_management_token() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let (_, old) = manager
            .publish_login(&ctx, &flow(&manager), login(&manager))
            .await
            .unwrap();
        let f = flow(&manager);
        let l = login(&manager);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut pending = Box::pin(manager.publish_login(&ctx, &f, l));
        poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let mut logout = Box::pin(manager.logout(&old, &ctx));
        poll_fn(|cx| {
            assert!(logout.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(manager.state().sessions.is_empty());
        db.execute_batch("COMMIT").unwrap();
        logout.await.unwrap();
        assert!(pending.await.is_err());
        assert!(manager.state().sessions.is_empty());
        cleanup(ctx, join, terminal).await;
    }
    #[tokio::test]
    async fn oidc_real_audit_failure_faults_and_never_installs_identity() {
        let (dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("CREATE TRIGGER oidc_audit_fail BEFORE INSERT ON audit_events WHEN NEW.event_type='admin.oidc' BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
        let error = manager
            .publish_login(&ctx, &flow(&manager), login(&manager))
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
        assert!(manager.state().sessions.is_empty());
        assert_eq!(ctx.authority.status().await.unwrap().state, "faulted");
        cleanup(ctx, join, terminal).await;
    }
    #[tokio::test]
    async fn oidc_wall_monotonic_capacity_and_clear_gate_actual_publication() {
        let (_dir, ctx, join, terminal) = crate::runtime::tests::oidc_test_ctx().await;
        let manager = manager(ctx.authority.status().await.unwrap().vault_id);
        let mut expired = login(&manager);
        expired.expires_at_ms = 0;
        assert!(
            manager
                .publish_login(&ctx, &flow(&manager), expired)
                .await
                .is_err()
        );
        let mut expired = login(&manager);
        expired.deadline = Instant::now();
        assert!(
            manager
                .publish_login(&ctx, &flow(&manager), expired)
                .await
                .is_err()
        );
        for _ in 0..32 {
            manager
                .publish_login(&ctx, &flow(&manager), login(&manager))
                .await
                .unwrap();
        }
        assert!(
            manager
                .publish_login(&ctx, &flow(&manager), login(&manager))
                .await
                .is_err()
        );
        let old = flow(&manager);
        manager.clear();
        assert!(
            manager
                .publish_login(&ctx, &old, login(&manager))
                .await
                .is_err()
        );
        assert!(manager.state().sessions.is_empty());
        cleanup(ctx, join, terminal).await;
    }
}
