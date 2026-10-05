//! Real UDS/Authority/personal-policy boundary with synthetic provider replies.
//! Software signing and a synthetic Presence envelope do not attest hardware UI.
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
#[cfg(not(feature = "lab"))]
use data_encoding::BASE64;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::{FakeUpstreamTransport, RecordedRequest};
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::audit::{AuditPage, AuditQuery, RequestAuditContext};
use rekey_domain::authorization::PolicyMode;
use rekey_domain::connection::{
    Connection, DerivedCredentialConnection, DerivedCredentialTarget, OAuthBinding, OAuthProvider,
    RuleEffect,
};
use rekey_domain::ids::{CredentialId, PolicySignerId, VaultId};
use rekey_domain::ipc::{self, Channel, admin_msg, agent_msg};
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use url::Url;

const POLICY_PREFIX: &[u8] = b"RKPOLICY\0\x01";
const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
const CLIENT_SECRET: &str = "SYNTHETIC-OAUTH-CLIENT-SECRET";
const AWS_ID: &str = "AKIASYNTHETICROOT1234";
const AWS_SECRET: &str = "SYNTHETIC-AWS-ROOT-SECRET";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn expiry(seconds: i64) -> (String, i64) {
    let seconds = now() / 1000 + seconds;
    (
        time::OffsetDateTime::from_unix_timestamp(seconds)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        seconds * 1000,
    )
}
fn response(status: u16, body: impl Into<Vec<u8>>) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: body.into().into(),
    }
}
fn oauth_payload(refresh: Option<&str>) -> Vec<u8> {
    let mut value = json!({"credential_type":"oauth-grant-v1","provider":"google",
        "client_id":"synthetic-client","client_secret":CLIENT_SECRET,
        "scopes":[DRIVE_SCOPE],"expires_at_ms":null});
    if let Some(refresh) = refresh {
        value["refresh_token"] = refresh.into();
    }
    serde_json::to_vec(&value).unwrap()
}
fn token_response(access: &str, refresh: &str) -> UpstreamResponse {
    response(
        200,
        serde_json::to_vec(&json!({"access_token":access,"refresh_token":refresh,
        "token_type":"Bearer","expires_in":3600,"scope":DRIVE_SCOPE}))
        .unwrap(),
    )
}
fn aws_payload() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"credential_type":"aws-static-v1", "access_key_id":AWS_ID,
        "secret_access_key":AWS_SECRET}),
    )
    .unwrap()
}
fn form(request: &RecordedRequest) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}
fn assert_private(response: &common::WireResponse, values: &[&str]) {
    let metadata = response.metadata.to_string();
    for value in values {
        assert!(!metadata.contains(value), "secret in public metadata");
        assert!(
            !response
                .body
                .windows(value.len())
                .any(|w| w == value.as_bytes()),
            "secret in public body"
        );
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: PathBuf,
    task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    signer: EcdsaKeyPair,
    signer_id: PolicySignerId,
    vault_id: VaultId,
    fake: Arc<FakeUpstreamTransport>,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let initialized = rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(common::PASSWORD),
            common::TEST_PARAMS,
            PolicyMode::Personal,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let fake = Arc::new(FakeUpstreamTransport::new());
        let mut config = BrokerConfig::new(state.clone());
        config.transport = Some(fake.clone());
        config.service_port = Some(0);
        config.unlock_backoff_base = Duration::from_millis(20);
        config.drain_timeout = Duration::from_millis(100);
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let fixture = Self {
            _dir: dir,
            state,
            task: tokio::spawn(serve(config)),
            signer: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref())
                .unwrap(),
            signer_id: PolicySignerId::new_random(),
            vault_id: initialized.vault_id,
            fake,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                !fixture.task.is_finished(),
                "broker exited during fixture startup"
            );
            if UnixStream::connect(fixture.socket(Channel::Admin))
                .await
                .is_ok()
                && UnixStream::connect(fixture.socket(Channel::Agent))
                    .await
                    .is_ok()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "broker startup timed out"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        fixture
            .admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
            .await
            .ok();
        fixture
            .admin(
                admin_msg::POLICY_TRUST_INSTALL,
                json!({"format_version":1,
            "signer_id":fixture.signer_id,"algorithm":"secure-enclave-p256",
            "public_key":HEXLOWER.encode(fixture.signer.public_key().as_ref())}),
                &common::proof_body(common::PASSWORD),
            )
            .await
            .ok();
        fixture
    }
    fn socket(&self, channel: Channel) -> PathBuf {
        self.state.join(if channel == Channel::Admin {
            "runtime/admin.sock"
        } else {
            "runtime/agent.sock"
        })
    }
    async fn wire(
        &self,
        channel: Channel,
        message: u16,
        metadata: Value,
        body: &[u8],
    ) -> common::WireResponse {
        common::call(
            &self.socket(channel),
            channel,
            message,
            &serde_json::to_vec(&metadata).unwrap(),
            body,
        )
        .await
    }
    async fn admin(&self, message: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        self.wire(Channel::Admin, message, metadata, body).await
    }
    async fn agent(&self, message: u16, metadata: Value) -> common::WireResponse {
        self.wire(Channel::Agent, message, metadata, &[]).await
    }
    async fn add(&self, kind: &str, payload: &[u8]) -> CredentialId {
        let result = self
            .admin(
                admin_msg::CREDENTIAL_ADD,
                json!({"label":format!("synthetic-{kind}"),"kind":kind}),
                &common::proof_and_secret_body(common::PASSWORD, payload),
            )
            .await;
        assert_private(&result, &[CLIENT_SECRET, AWS_SECRET]);
        serde_json::from_value(result.ok()["id"].clone()).unwrap()
    }
    async fn version(&self, id: CredentialId) -> u64 {
        let listed = self.admin(admin_msg::CREDENTIAL_LIST, json!({}), &[]).await;
        listed.ok()["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == serde_json::to_value(id).unwrap())
            .unwrap()["current_version"]
            .as_u64()
            .unwrap()
    }
    async fn await_version(&self, id: CredentialId, version: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.version(id).await != version {
            assert!(
                tokio::time::Instant::now() < deadline,
                "OAuth rotation did not finish"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn draft(
        &self,
        connections: Vec<Connection>,
        grants: Vec<DerivedCredentialConnection>,
    ) -> common::WireResponse {
        let list = self.admin(admin_msg::PROFILE_LIST, json!({}), &[]).await;
        let base: ipc::ConnectionListResponse = serde_json::from_slice(&list.body).unwrap();
        self.admin(
            admin_msg::PERSONAL_POLICY_DRAFT,
            serde_json::to_value(ipc::PersonalPolicyDraftMeta {
                connections,
                ssh_keys: None,
                derived_credentials: Some(grants),
                expected_policy_sha256: base.policy_sha256,
                expires_at_ms: now() + 600_000,
            })
            .unwrap(),
            &[],
        )
        .await
    }
    fn sign(&self, mut unsigned: Value) -> Value {
        let mut bytes = POLICY_PREFIX.to_vec();
        bytes.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
        unsigned["signature"] = BASE64URL_NOPAD
            .encode(
                self.signer
                    .sign(&SystemRandom::new(), &bytes)
                    .unwrap()
                    .as_ref(),
            )
            .into();
        unsigned
    }
    async fn activate_bundle(
        &self,
        draft: &common::WireResponse,
        bundle: Value,
    ) -> common::WireResponse {
        self.admin(
            admin_msg::POLICY_ACTIVATE,
            json!({"expected_vault_id":self.vault_id,
            "expected_trust_sha256":draft.ok()["trust_sha256"],"bundle_json":bundle}),
            &common::proof_body(common::PASSWORD),
        )
        .await
    }
    async fn activate(
        &self,
        connections: Vec<Connection>,
        grants: Vec<DerivedCredentialConnection>,
    ) {
        let draft = self.draft(connections, grants).await;
        let _: ipc::PersonalPolicyDraftResponse =
            serde_json::from_value(draft.ok().clone()).unwrap();
        assert!(draft.body.starts_with(POLICY_PREFIX));
        let unsigned = serde_json::from_slice(&draft.body[POLICY_PREFIX.len()..]).unwrap();
        self.activate_bundle(&draft, self.sign(unsigned)).await.ok();
    }
    async fn audit(&self) -> AuditPage {
        let query: AuditQuery = serde_json::from_value(json!({"limit":100})).unwrap();
        let response = self
            .admin(
                admin_msg::AUDIT_QUERY,
                serde_json::to_value(&query).unwrap(),
                &[],
            )
            .await;
        response.ok();
        assert_eq!(response.metadata, json!({}));
        let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
        page.validate_for(&query).unwrap();
        assert_private(
            &response,
            &[
                CLIENT_SECRET,
                AWS_SECRET,
                "SYNTHETIC-REFRESH-AUTHORIZED",
                "SYNTHETIC-REFRESH-MANUAL",
                "SYNTHETIC-ACCESS-AUTHORIZED",
                "SYNTHETIC-ACCESS-REFRESHED",
                "SYNTHETIC-REFRESH-STALE",
                "SYNTHETIC-ACCESS-STALE",
                "SYNTHETIC-REFRESH-CURRENT",
                "SYNTHETIC-ACCESS-CURRENT",
                "SYNTHETIC-TEMP-SECRET",
                "SYNTHETIC-TEMP-SESSION",
                "SYNTHETIC-INSTALLATION-TOKEN",
                "SYNTHETIC-OVERBROAD-TOKEN",
            ],
        );
        page
    }
    async fn finish(self) {
        self.admin(
            admin_msg::SHUTDOWN,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await
        .ok();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn oauth_connection(id: CredentialId) -> Connection {
    let mut connection = rekey_policy::presets::builtin_preset("google-drive")
        .unwrap()
        .connection("drive".into(), id);
    connection.oauth = Some(OAuthBinding {
        provider: OAuthProvider::Google,
        client_id: "synthetic-client".into(),
        scopes: [DRIVE_SCOPE.into()].into_iter().collect(),
    });
    connection
}
fn get_drive() -> Value {
    json!({"connection":"drive","method":"GET","path":"/drive/v3/files"})
}
async fn begin(f: &Fixture) -> (common::WireResponse, BTreeMap<String, String>) {
    let response = f
        .admin(
            admin_msg::OAUTH_LOGIN,
            json!({"connection":"drive"}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    let url = Url::parse(response.ok()["authorization_url"].as_str().unwrap()).unwrap();
    assert_eq!(url.host_str(), Some("accounts.google.com"));
    assert!(response.body.is_empty());
    assert_private(&response, &[CLIENT_SECRET]);
    (response, url.query_pairs().into_owned().collect())
}
async fn callback(fields: &BTreeMap<String, String>, state: &str, host: Option<&str>) -> String {
    let redirect = Url::parse(&fields["redirect_uri"]).unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", redirect.port().unwrap()))
        .await
        .unwrap();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", state)
        .append_pair("code", "SYNTHETIC-AUTHORIZATION-CODE")
        .finish();
    let host = host.map(str::to_owned).unwrap_or(format!(
        "{}:{}",
        redirect.host_str().unwrap(),
        redirect.port().unwrap()
    ));
    stream
        .write_all(
            format!("GET /callback?{query} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn oauth_pkce_callback_rotates_and_cached_bearers_never_reach_agent_results() {
    let f = Fixture::new().await;
    let id = f.add("oauth-grant", &oauth_payload(None)).await;
    f.activate(vec![oauth_connection(id)], vec![]).await;
    let needed = f.agent(agent_msg::CALL, get_drive()).await;
    assert_eq!(needed.err_code(), "NEEDS_REAUTH");
    assert!(needed.metadata["next"].as_str().unwrap().contains("App"));
    assert!(f.fake.take_requests().is_empty());
    let wrong = f
        .admin(
            admin_msg::OAUTH_LOGIN,
            json!({"connection":"drive"}),
            &common::proof_body(b"wrong-synthetic-proof"),
        )
        .await;
    assert_eq!(wrong.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    tokio::time::sleep(Duration::from_millis(30)).await;
    let (_, fields) = begin(&f).await;
    assert_eq!(fields["scope"], DRIVE_SCOPE);
    assert_eq!(fields["code_challenge_method"], "S256");
    assert_eq!(fields["access_type"], "offline");
    assert!(fields["redirect_uri"].starts_with("http://127.0.0.1:"));
    assert!(
        callback(&fields, "wrong-state", None)
            .await
            .starts_with("HTTP/1.1 400")
    );
    assert!(
        callback(&fields, &fields["state"], Some("attacker.example"))
            .await
            .starts_with("HTTP/1.1 400")
    );
    assert!(f.fake.take_requests().is_empty());
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-AUTHORIZED",
        "SYNTHETIC-REFRESH-AUTHORIZED",
    )));
    let received = callback(&fields, &fields["state"], None).await;
    assert!(received.starts_with("HTTP/1.1 200"));
    assert!(!received.contains("SYNTHETIC-AUTHORIZATION-CODE"));
    f.await_version(id, 2).await;
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    let exchange = &requests[0];
    assert_eq!(
        (&*exchange.host, &*exchange.path, &*exchange.method),
        ("oauth2.googleapis.com", "/token", "POST")
    );
    let parameters = form(exchange);
    assert_eq!(parameters["grant_type"], "authorization_code");
    assert_eq!(parameters["redirect_uri"], fields["redirect_uri"]);
    assert_eq!(parameters["client_secret"], CLIENT_SECRET);
    assert_eq!(
        BASE64URL_NOPAD.encode(&Sha256::digest(parameters["code_verifier"].as_bytes())),
        fields["code_challenge"]
    );
    f.fake
        .push_response(Ok(response(200, b"{\"files\":[]}".to_vec())));
    let result = f.agent(agent_msg::CALL, get_drive()).await;
    result.ok();
    assert_private(
        &result,
        &[
            CLIENT_SECRET,
            "SYNTHETIC-ACCESS-AUTHORIZED",
            "SYNTHETIC-REFRESH-AUTHORIZED",
        ],
    );
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].auth_value,
        b"Bearer SYNTHETIC-ACCESS-AUTHORIZED"
    );
    // Cached access, refresh material and client secrets all remain sealed if reflected.
    for secret in [
        "SYNTHETIC-ACCESS-AUTHORIZED",
        "SYNTHETIC-REFRESH-AUTHORIZED",
        CLIENT_SECRET,
    ] {
        f.fake
            .push_response(Ok(response(200, secret.as_bytes().to_vec())));
        let sealed = f.agent(agent_msg::CALL, get_drive()).await;
        assert_eq!(sealed.err_code(), "RESPONSE_BLOCKED");
        assert_private(&sealed, &[secret]);
    }
    assert_eq!(f.fake.take_requests().len(), 3);
    f.admin(admin_msg::LOCK, json!({}), &[]).await.ok();
    assert_eq!(
        f.agent(agent_msg::CALL, get_drive()).await.err_code(),
        "LOCKED"
    );
    assert!(f.fake.take_requests().is_empty());
    f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
        .await
        .ok();
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-REFRESHED",
        "SYNTHETIC-REFRESH-ROTATED",
    )));
    f.fake
        .push_response(Ok(response(200, b"{\"files\":[]}".to_vec())));
    f.agent(agent_msg::CALL, get_drive()).await.ok();
    assert_eq!(f.version(id).await, 3);
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        form(&requests[0])["refresh_token"],
        "SYNTHETIC-REFRESH-AUTHORIZED"
    );
    assert_eq!(requests[1].auth_value, b"Bearer SYNTHETIC-ACCESS-REFRESHED");
    f.admin(
        admin_msg::CREDENTIAL_ROTATE,
        json!({"credential_id":id}),
        &common::proof_and_secret_body(
            common::PASSWORD,
            &oauth_payload(Some("SYNTHETIC-REFRESH-MANUAL")),
        ),
    )
    .await
    .ok();
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-MANUAL",
        "SYNTHETIC-REFRESH-MANUAL-ROTATED",
    )));
    f.fake
        .push_response(Ok(response(200, b"{\"files\":[]}".to_vec())));
    f.agent(agent_msg::CALL, get_drive()).await.ok();
    assert_eq!(f.version(id).await, 5);
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        form(&requests[0])["refresh_token"],
        "SYNTHETIC-REFRESH-MANUAL"
    );
    f.admin(admin_msg::LOCK, json!({}), &[]).await.ok();
    f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
        .await
        .ok();
    f.fake
        .push_response(Ok(response(400, br#"{"error":"invalid_grant"}"#.to_vec())));
    assert_eq!(
        f.agent(agent_msg::CALL, get_drive()).await.err_code(),
        "NEEDS_REAUTH"
    );
    assert_eq!(f.fake.take_requests().len(), 1);
    f.admin(
        admin_msg::CREDENTIAL_REVOKE,
        json!({"credential_id":id}),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    assert_eq!(
        f.agent(agent_msg::CALL, get_drive()).await.err_code(),
        "CREDENTIAL_UNAVAILABLE"
    );
    assert!(f.fake.take_requests().is_empty());
    let page = f.audit().await;
    assert!(
        page.events
            .iter()
            .any(|event| event.event_type == "oauth.authorized"
                && event.credential_version == Some(2))
    );
    assert!(
        page.events
            .iter()
            .any(|event| event.event_type == "oauth.refreshed"
                && event.credential_version == Some(5))
    );
    f.finish().await;
}

#[tokio::test]
async fn locking_during_oauth_refresh_records_one_remote_terminal_and_cancels_queued_reads() {
    let f = Fixture::new().await;
    let refresh = "SYNTHETIC-REFRESH-LOCK-ROOT";
    let access = "SYNTHETIC-ACCESS-LOCK-REPLY";
    let rotated = "SYNTHETIC-REFRESH-LOCK-REPLY";
    let id = f.add("oauth-grant", &oauth_payload(Some(refresh))).await;
    f.activate(vec![oauth_connection(id)], vec![]).await;
    let before = f.audit().await;
    let release = f
        .fake
        .push_response_gated(Ok(token_response(access, rotated)));
    let socket = f.socket(Channel::Agent);
    let first = tokio::spawn(async move {
        common::call(
            &socket,
            Channel::Agent,
            agent_msg::CALL,
            &serde_json::to_vec(&get_drive()).unwrap(),
            &[],
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.fake.requests.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("OAuth refresh did not reach its gated IdP request");
    let admitted = f.audit().await;
    let first_id = admitted
        .events
        .iter()
        .find(|event| {
            event.event_type == "execution.started"
                && matches!(&event.request_context, Some(RequestAuditContext::Connection(context)) if context.connection == "drive")
                && !before.events.iter().any(|old| old.event_id == event.event_id)
        })
        .expect("refresh must commit admission before contacting the IdP")
        .request_id;
    let socket = f.socket(Channel::Agent);
    let queued = tokio::spawn(async move {
        common::call(
            &socket,
            Channel::Agent,
            agent_msg::CALL,
            &serde_json::to_vec(&get_drive()).unwrap(),
            &[],
        )
        .await
    });
    let queued_id = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let page = f.audit().await;
            if let Some(event) = page.events.iter().find(|event| {
                event.event_type == "execution.started"
                    && event.request_id != first_id
                    && matches!(&event.request_context, Some(RequestAuditContext::Connection(context)) if context.connection == "drive")
                    && !before.events.iter().any(|old| old.event_id == event.event_id)
            }) {
                break event.request_id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second read was not admitted behind the held refresh");
    assert_eq!(f.fake.requests.lock().unwrap().len(), 1);
    // Keep the IdP blocked through drain. Cancellation must drop both the
    // remote refresh and the read queued behind its mutex, without an API call.
    tokio::time::timeout(
        Duration::from_secs(2),
        f.admin(admin_msg::LOCK, json!({}), &[]),
    )
    .await
    .expect("LOCK waited for the gated OAuth refresh")
    .ok();
    for pending in [first, queued] {
        let cancelled = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .expect("OAuth read did not finish after LOCK")
            .unwrap();
        assert!(!cancelled.err_code().is_empty());
        assert!(
            cancelled.metadata["next"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert_private(&cancelled, &[CLIENT_SECRET, refresh, access, rotated]);
        assert!(cancelled.body.is_empty());
    }
    release.notify_one();
    let requests = f.fake.take_requests();
    assert_eq!(
        requests.len(),
        1,
        "LOCK allowed an API read or second IdP send"
    );
    assert_eq!(
        (&*requests[0].host, &*requests[0].path),
        ("oauth2.googleapis.com", "/token")
    );
    assert_eq!(requests[0].method, "POST");
    assert_eq!(form(&requests[0])["refresh_token"], refresh);
    let page = f.audit().await;
    let audit_json = serde_json::to_string(&page).unwrap();
    for secret in [CLIENT_SECRET, refresh, access, rotated] {
        assert!(!audit_json.contains(secret), "OAuth secret in public audit");
    }
    for (request_id, expected) in [
        (first_id, "execution.indeterminate"),
        (queued_id, "execution.blocked"),
    ] {
        let terminals: Vec<_> = page
            .events
            .iter()
            .filter(|event| {
                event.request_id == request_id
                    && matches!(
                        event.event_type.as_str(),
                        "execution.finished" | "execution.blocked" | "execution.indeterminate"
                    )
            })
            .collect();
        assert_eq!(
            terminals.len(),
            1,
            "each OAuth read needs exactly one terminal"
        );
        assert_eq!(terminals[0].event_type, expected);
    }
    assert!(
        !page
            .events
            .iter()
            .any(|event| event.event_type == "oauth.refreshed")
    );
    assert_eq!(
        f.agent(agent_msg::CALL, get_drive()).await.err_code(),
        "LOCKED"
    );
    assert!(f.fake.take_requests().is_empty());
    // A completed IdP failure also happened after a remote effect. It must
    // retain the same terminal semantics as cancellation, without an API read.
    let before_failure = f.audit().await;
    f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
        .await
        .ok();
    f.fake
        .push_response(Ok(response(400, br#"{"error":"invalid_grant"}"#.to_vec())));
    let failed = f.agent(agent_msg::CALL, get_drive()).await;
    assert_eq!(failed.err_code(), "NEEDS_REAUTH");
    assert!(
        failed.metadata["next"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert_private(&failed, &[CLIENT_SECRET, refresh, access, rotated]);
    let requests = f.fake.take_requests();
    assert_eq!(
        requests.len(),
        1,
        "failed refresh unexpectedly sent an API read"
    );
    assert_eq!(
        (&*requests[0].host, &*requests[0].path),
        ("oauth2.googleapis.com", "/token")
    );
    assert_eq!(form(&requests[0])["refresh_token"], refresh);
    let page = f.audit().await;
    let started = page.events.iter().find(|event| {
        event.event_type == "execution.started"
            && matches!(&event.request_context, Some(RequestAuditContext::Connection(context)) if context.connection == "drive")
            && !before_failure.events.iter().any(|old| old.event_id == event.event_id)
    }).expect("failed refresh was not admitted");
    let terminals: Vec<_> = page
        .events
        .iter()
        .filter(|event| {
            event.request_id == started.request_id
                && matches!(
                    event.event_type.as_str(),
                    "execution.finished" | "execution.blocked" | "execution.indeterminate"
                )
        })
        .collect();
    assert_eq!(
        terminals.len(),
        1,
        "failed refresh needs exactly one terminal"
    );
    assert_eq!(terminals[0].event_type, "execution.indeterminate");
    assert_eq!(
        f.version(id).await,
        1,
        "cancelled or failed refresh rotated root material"
    );
    let audit_json = serde_json::to_string(&page).unwrap();
    for secret in [CLIENT_SECRET, refresh, access, rotated] {
        assert!(!audit_json.contains(secret), "OAuth secret in public audit");
    }
    f.finish().await;
}

#[tokio::test]
async fn oauth_refresh_effect_survives_target_preflight_rejection_but_cache_hit_stays_blocked() {
    let f = Fixture::new().await;
    let access = "SYNTHETIC-ACCESS-PREFLIGHT";
    let refresh = "SYNTHETIC-REFRESH-PREFLIGHT";
    let rotated = "SYNTHETIC-REFRESH-PREFLIGHT-ROTATED";
    let id = f.add("oauth-grant", &oauth_payload(Some(refresh))).await;
    f.activate(vec![oauth_connection(id)], vec![]).await;
    f.fake.push_response(Ok(token_response(access, rotated)));
    for (expected, request_count) in [("execution.indeterminate", 2), ("execution.blocked", 1)] {
        let before = f.audit().await;
        f.fake
            .push_response(Err(rekey_broker::upstream::UpstreamError::Blocked(
                "private-address",
            )));
        let result = f.agent(agent_msg::CALL, get_drive()).await;
        assert_eq!(result.err_code(), "UPSTREAM_ERROR");
        assert_private(&result, &[CLIENT_SECRET, access, refresh, rotated]);
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), request_count);
        assert_eq!(
            requests.last().unwrap().auth_value,
            format!("Bearer {access}").as_bytes()
        );
        assert_eq!(f.version(id).await, 2, "cached read must not refresh again");
        let page = f.audit().await;
        let started = page.events.iter().find(|event| {
            event.event_type == "execution.started"
                && matches!(&event.request_context, Some(RequestAuditContext::Connection(context)) if context.connection == "drive")
                && !before.events.iter().any(|old| old.event_id == event.event_id)
        }).expect("preflight-denied read was not admitted");
        let terminals: Vec<_> = page
            .events
            .iter()
            .filter(|event| {
                event.request_id == started.request_id
                    && matches!(
                        event.event_type.as_str(),
                        "execution.finished" | "execution.blocked" | "execution.indeterminate"
                    )
            })
            .collect();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].event_type, expected);
        let audit_json = serde_json::to_string(&page).unwrap();
        for secret in [CLIENT_SECRET, access, refresh, rotated] {
            assert!(!audit_json.contains(secret), "OAuth secret in public audit");
        }
    }
    f.finish().await;
}

#[tokio::test]
async fn oauth_callback_cannot_overwrite_a_root_rotated_after_login_began() {
    let f = Fixture::new().await;
    let id = f.add("oauth-grant", &oauth_payload(None)).await;
    f.activate(vec![oauth_connection(id)], vec![]).await;
    let (_, fields) = begin(&f).await;
    f.admin(
        admin_msg::CREDENTIAL_ROTATE,
        json!({"credential_id":id}),
        &common::proof_and_secret_body(
            common::PASSWORD,
            &oauth_payload(Some("SYNTHETIC-REFRESH-MANUAL")),
        ),
    )
    .await
    .ok();
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-STALE",
        "SYNTHETIC-REFRESH-STALE",
    )));
    assert!(
        callback(&fields, &fields["state"], None)
            .await
            .starts_with("HTTP/1.1 200")
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let page = f.audit().await;
        if page
            .events
            .iter()
            .any(|event| event.reason_code == "oauth-authorization-failed")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "stale callback failure did not reach audit"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(f.version(id).await, 2);
    assert_eq!(f.fake.take_requests().len(), 1);
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-CURRENT",
        "SYNTHETIC-REFRESH-CURRENT",
    )));
    f.fake
        .push_response(Ok(response(200, b"{\"files\":[]}".to_vec())));
    f.agent(agent_msg::CALL, get_drive()).await.ok();
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        form(&requests[0])["refresh_token"],
        "SYNTHETIC-REFRESH-MANUAL"
    );
    assert_eq!(requests[1].auth_value, b"Bearer SYNTHETIC-ACCESS-CURRENT");
    f.finish().await;
}

fn aws_grant(id: CredentialId, name: &str, effect: RuleEffect) -> DerivedCredentialConnection {
    DerivedCredentialConnection {
        name: name.into(),
        credential_id: id,
        effect,
        max_ttl_seconds: 900,
        target: DerivedCredentialTarget::AwsAssumeRole {
            role_arn: "arn:aws:iam::123456789012:role/synthetic".into(),
            region: "us-east-1".into(),
            session_policy: json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::synthetic/*"}]}),
        },
    }
}

#[tokio::test]
async fn aws_signed_target_and_presence_gate_issuance_and_actual_expiry_audit() {
    let f = Fixture::new().await;
    let id = f.add("aws-static", &aws_payload()).await;
    let approved = aws_grant(id, "aws-approved", RuleEffect::Approve);
    let denied = aws_grant(id, "aws-denied", RuleEffect::Deny);
    f.activate(vec![], vec![approved.clone(), denied]).await;
    let inventory = f.agent(agent_msg::LIST_CAPABILITIES, json!({})).await;
    inventory.ok();
    let listed: ipc::ListCapabilitiesResponse = serde_json::from_slice(&inventory.body).unwrap();
    assert_eq!(listed.derived_credentials.len(), 2);
    assert!(
        listed
            .derived_credentials
            .iter()
            .all(|row| row.grade == rekey_domain::connection::CredentialGrade::T1)
    );
    let public = String::from_utf8(inventory.body.clone()).unwrap();
    assert!(!public.contains(&id.to_string()) && !public.contains("credential_id"));
    assert_private(&inventory, &[AWS_ID, AWS_SECRET]);
    assert_eq!(
        f.agent(
            agent_msg::DERIVE_CREDENTIAL,
            json!({"connection":"aws-denied"})
        )
        .await
        .err_code(),
        "DENIED"
    );
    let pending = f
        .agent(
            agent_msg::DERIVE_CREDENTIAL,
            json!({"connection":"aws-approved"}),
        )
        .await;
    assert_eq!(pending.err_code(), "APPROVAL_REQUIRED");
    assert!(f.fake.take_requests().is_empty());
    let request = pending.metadata["approval"]["challenge_id"].clone();
    let review = f
        .admin(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":request}),
            &[],
        )
        .await;
    review.ok();
    let parsed: Value = serde_json::from_slice(&review.body).unwrap();
    assert_eq!(
        parsed["canonical_request"]["target"],
        serde_json::to_value(&approved.target).unwrap()
    );
    assert_eq!(
        parsed["canonical_request"]["agent_receives_temporary_credential"],
        true
    );
    let decision = json!({"approval_request_id":request,"expected_review_sha256":review.metadata["review_sha256"]});
    assert_eq!(
        f.admin(
            admin_msg::APPROVAL_LOCAL_APPROVE,
            decision.clone(),
            &common::proof_body(common::PASSWORD)
        )
        .await
        .err_code(),
        "INVALID_FRAME"
    );
    assert_eq!(f.agent(agent_msg::DERIVE_CREDENTIAL, json!({"connection":"aws-approved","role_arn":"arn:aws:iam::000000000000:role/attacker"})).await.err_code(), "INVALID_FRAME");
    assert!(f.fake.take_requests().is_empty());
    let remembered = f
        .admin(
            admin_msg::DESKTOP_REMEMBER,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    remembered.ok();
    let mut invalid_presence = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &[0; 32], &mut invalid_presence);
    assert_eq!(
        f.admin(
            admin_msg::APPROVAL_LOCAL_APPROVE,
            decision.clone(),
            &invalid_presence,
        )
        .await
        .err_code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    assert!(f.fake.take_requests().is_empty());
    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut presence = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut presence);
    f.admin(admin_msg::APPROVAL_LOCAL_APPROVE, decision, &presence)
        .await
        .ok();
    assert!(f.fake.take_requests().is_empty());
    let (expires, expires_at_ms) = expiry(600);
    let xml = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIASYNTHETICTEMP1234</AccessKeyId><SecretAccessKey>SYNTHETIC-TEMP-SECRET</SecretAccessKey><SessionToken>SYNTHETIC-TEMP-SESSION</SessionToken><Expiration>{expires}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    f.fake.push_response(Ok(response(200, xml.into_bytes())));
    let replay = json!({"connection":"aws-approved","approval_request_id":request});
    let issued = f.agent(agent_msg::DERIVE_CREDENTIAL, replay.clone()).await;
    assert_eq!(issued.ok()["kind"], "aws-assume-role");
    assert_eq!(issued.metadata["expires_at_ms"], expires_at_ms);
    assert_private(&issued, &[AWS_ID, AWS_SECRET]);
    let credentials: Value = serde_json::from_slice(&issued.body).unwrap();
    assert_eq!(credentials["Version"], 1);
    assert_eq!(credentials["Expiration"], expires);
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    let sts = &requests[0];
    assert_eq!(
        (&*sts.host, &*sts.path, &*sts.method),
        ("sts.us-east-1.amazonaws.com", "/", "POST")
    );
    let parameters = form(sts);
    assert_eq!(parameters["DurationSeconds"], "900");
    assert_eq!(parameters["RoleSessionName"], "rekey");
    let DerivedCredentialTarget::AwsAssumeRole {
        role_arn,
        session_policy,
        ..
    } = &approved.target
    else {
        unreachable!()
    };
    assert_eq!(&parameters["RoleArn"], role_arn);
    assert_eq!(
        serde_json::from_str::<Value>(&parameters["Policy"]).unwrap(),
        *session_policy
    );
    assert!(
        sts.auth_value
            .starts_with(b"AWS4-HMAC-SHA256 Credential=AKIASYNTHETICROOT1234/")
    );
    assert_eq!(
        f.agent(agent_msg::DERIVE_CREDENTIAL, replay)
            .await
            .err_code(),
        "DENIED"
    );
    assert!(f.fake.take_requests().is_empty());
    let page = f.audit().await;
    let event = page
        .events
        .iter()
        .find(|e| e.event_type == "credential.derived_issued")
        .unwrap();
    let Some(RequestAuditContext::Derived(context)) = &event.request_context else {
        panic!("missing derived context")
    };
    assert_eq!(context.target, approved.target);
    assert_eq!(context.expires_at_ms, Some(expires_at_ms));
    assert_eq!(event.credential_version, Some(1));
    f.finish().await;
}

fn eks_signature(url: &Url, cluster: &str) -> String {
    let values: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    let stamp = &values["X-Amz-Date"];
    let date = &stamp[..8];
    let query = url
        .query()
        .unwrap()
        .split('&')
        .filter(|p| !p.starts_with("X-Amz-Signature="))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = format!(
        "GET\n/\n{query}\nhost:{}\nx-k8s-aws-id:{cluster}\n\nhost;x-k8s-aws-id\n{}",
        url.host_str().unwrap(),
        HEXLOWER.encode(&Sha256::digest(b""))
    );
    let mut key = format!("AWS4{AWS_SECRET}").into_bytes();
    for part in [date, "us-west-2", "sts", "aws4_request"] {
        key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), part.as_bytes())
            .as_ref()
            .to_vec();
    }
    let signed = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{date}/us-west-2/sts/aws4_request\n{}",
        HEXLOWER.encode(&Sha256::digest(canonical.as_bytes()))
    );
    HEXLOWER
        .encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), signed.as_bytes()).as_ref())
}

#[tokio::test]
async fn eks_credential_binds_signed_cluster_and_returns_no_long_term_secret() {
    let f = Fixture::new().await;
    let id = f.add("aws-static", &aws_payload()).await;
    let target = DerivedCredentialTarget::KubernetesEks {
        cluster_id: "synthetic-cluster".into(),
        region: "us-west-2".into(),
    };
    f.activate(
        vec![],
        vec![DerivedCredentialConnection {
            name: "eks".into(),
            credential_id: id,
            effect: RuleEffect::Allow,
            max_ttl_seconds: 900,
            target: target.clone(),
        }],
    )
    .await;
    assert_eq!(
        f.agent(
            agent_msg::DERIVE_CREDENTIAL,
            json!({"connection":"eks","cluster_id":"attacker"})
        )
        .await
        .err_code(),
        "INVALID_FRAME"
    );
    let issued = f
        .agent(agent_msg::DERIVE_CREDENTIAL, json!({"connection":"eks"}))
        .await;
    assert_eq!(issued.ok()["kind"], "kubernetes-eks");
    assert_private(&issued, &[AWS_SECRET]);
    let credential: Value = serde_json::from_slice(&issued.body).unwrap();
    assert_eq!(credential["apiVersion"], "client.authentication.k8s.io/v1");
    assert_eq!(credential["kind"], "ExecCredential");
    let token = credential["status"]["token"]
        .as_str()
        .unwrap()
        .strip_prefix("k8s-aws-v1.")
        .unwrap();
    let signed_url = Url::parse(
        std::str::from_utf8(&BASE64URL_NOPAD.decode(token.as_bytes()).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(signed_url.host_str(), Some("sts.us-west-2.amazonaws.com"));
    assert!(!signed_url.as_str().contains(AWS_SECRET));
    let parameters: BTreeMap<String, String> = signed_url.query_pairs().into_owned().collect();
    assert_eq!(parameters["Action"], "GetCallerIdentity");
    assert_eq!(parameters["X-Amz-Expires"], "60");
    assert_eq!(parameters["X-Amz-SignedHeaders"], "host;x-k8s-aws-id");
    let stamp = &parameters["X-Amz-Date"];
    let signed_time = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &stamp[..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
        &stamp[13..15],
    );
    let signed_at_ms =
        time::OffsetDateTime::parse(&signed_time, &time::format_description::well_known::Rfc3339)
            .unwrap()
            .unix_timestamp()
            * 1000;
    assert_eq!(issued.metadata["expires_at_ms"], signed_at_ms + 900_000);
    assert_eq!(
        parameters["X-Amz-Signature"],
        eks_signature(&signed_url, "synthetic-cluster")
    );
    assert_ne!(
        parameters["X-Amz-Signature"],
        eks_signature(&signed_url, "attacker")
    );
    assert!(f.fake.take_requests().is_empty());
    let page = f.audit().await;
    let event = page
        .events
        .iter()
        .find(|e| e.event_type == "credential.derived_issued")
        .unwrap();
    let Some(RequestAuditContext::Derived(context)) = &event.request_context else {
        panic!("missing derived context")
    };
    assert_eq!(context.target, target);
    assert_eq!(
        context.expires_at_ms,
        issued.metadata["expires_at_ms"].as_i64()
    );
    f.finish().await;
}

#[tokio::test]
async fn locking_during_sts_issuance_cancels_without_publishing_temporary_credentials() {
    let f = Fixture::new().await;
    let id = f.add("aws-static", &aws_payload()).await;
    f.activate(vec![], vec![aws_grant(id, "aws-lock", RuleEffect::Allow)])
        .await;
    f.admin(admin_msg::LOCK, json!({}), &[]).await.ok();
    assert_eq!(
        f.agent(
            agent_msg::DERIVE_CREDENTIAL,
            json!({"connection":"aws-lock"})
        )
        .await
        .err_code(),
        "LOCKED"
    );
    assert!(f.fake.take_requests().is_empty());
    f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
        .await
        .ok();
    let before = f.audit().await;
    let (expires, _) = expiry(600);
    let xml = format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIASYNTHETICTEMP1234</AccessKeyId><SecretAccessKey>SYNTHETIC-TEMP-SECRET</SecretAccessKey><SessionToken>SYNTHETIC-TEMP-SESSION</SessionToken><Expiration>{expires}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"
    );
    let release = f
        .fake
        .push_response_gated(Ok(response(200, xml.into_bytes())));
    let agent_socket = f.socket(Channel::Agent);
    let derive = tokio::spawn(async move {
        common::call(
            &agent_socket,
            Channel::Agent,
            agent_msg::DERIVE_CREDENTIAL,
            br#"{"connection":"aws-lock"}"#,
            &[],
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.fake.requests.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("derive never reached the gated STS request");
    // Keep STS blocked throughout LOCK. Waiting for a remote response instead
    // of cancelling its admitted local permit would deadlock this drain.
    tokio::time::timeout(
        Duration::from_secs(2),
        f.admin(admin_msg::LOCK, json!({}), &[]),
    )
    .await
    .expect("LOCK waited for the gated STS request")
    .ok();
    let cancelled = tokio::time::timeout(Duration::from_secs(2), derive)
        .await
        .expect("derive did not finish after LOCK")
        .unwrap();
    assert!(!cancelled.err_code().is_empty());
    assert!(
        cancelled.metadata["next"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert_private(
        &cancelled,
        &[
            AWS_ID,
            AWS_SECRET,
            "SYNTHETIC-TEMP-SECRET",
            "SYNTHETIC-TEMP-SESSION",
        ],
    );
    assert!(cancelled.body.is_empty());
    release.notify_one();
    assert_eq!(f.fake.take_requests().len(), 1);
    let page = f.audit().await;
    let started = page.events.iter().find(|event| {
        event.event_type == "execution.started"
            && matches!(&event.request_context, Some(RequestAuditContext::Derived(context)) if context.connection == "aws-lock")
            && !before.events.iter().any(|old| old.event_id == event.event_id)
    }).expect("missing admitted derive audit");
    let terminals: Vec<_> = page
        .events
        .iter()
        .filter(|event| {
            event.request_id == started.request_id
                && matches!(
                    event.event_type.as_str(),
                    "execution.finished" | "execution.blocked" | "execution.indeterminate"
                )
        })
        .collect();
    assert_eq!(terminals.len(), 1, "derive must have exactly one terminal");
    assert_eq!(terminals[0].event_type, "execution.indeterminate");
    assert!(
        !page
            .events
            .iter()
            .any(|event| event.event_type == "credential.derived_issued")
    );
    assert_eq!(
        f.agent(
            agent_msg::DERIVE_CREDENTIAL,
            json!({"connection":"aws-lock"})
        )
        .await
        .err_code(),
        "LOCKED"
    );
    assert!(f.fake.take_requests().is_empty());
    f.finish().await;
}

#[tokio::test]
async fn oauth_and_aws_root_material_cannot_be_used_as_ordinary_http_credentials() {
    let f = Fixture::new().await;
    let pat = f.add("opaque-token", b"SYNTHETIC-PAT").await;
    let oauth = f
        .add(
            "oauth-grant",
            &oauth_payload(Some("SYNTHETIC-REFRESH-ROOT")),
        )
        .await;
    let aws = f.add("aws-static", &aws_payload()).await;
    let connection = rekey_policy::presets::builtin_preset("github-pat")
        .unwrap()
        .connection("http".into(), pat);
    for root in [oauth, aws] {
        let mut mismatched = connection.clone();
        mismatched.credential_id = root;
        assert_eq!(
            f.draft(vec![mismatched], vec![]).await.err_code(),
            "CREDENTIAL_UNAVAILABLE"
        );
        // A valid user signature is not permission to reinterpret source material.
        let draft = f.draft(vec![connection.clone()], vec![]).await;
        let mut unsigned: Value =
            serde_json::from_slice(&draft.body[POLICY_PREFIX.len()..]).unwrap();
        unsigned["snapshot"]["connections"][0]["credential_id"] =
            serde_json::to_value(root).unwrap();
        f.activate_bundle(&draft, f.sign(unsigned)).await.ok();
        assert_eq!(
            f.agent(
                agent_msg::CALL,
                json!({"connection":"http","method":"GET","path":"/repos/a/b"})
            )
            .await
            .err_code(),
            "CREDENTIAL_UNAVAILABLE"
        );
        assert!(f.fake.take_requests().is_empty());
    }
    f.audit().await;
    f.finish().await;
}

#[tokio::test]
#[cfg(not(feature = "lab"))]
async fn github_installation_token_uses_only_signed_repository_and_permission_ceiling() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let generated = Command::new("/usr/bin/openssl")
        .args(["genrsa", "2048"])
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(generated.status.success(), "synthetic RSA generation");
    let mut converter = Command::new("/usr/bin/openssl");
    converter.arg("rsa");
    #[cfg(target_os = "linux")]
    converter.arg("-traditional");
    let mut convert = converter
        .args(["-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    convert
        .stdin
        .take()
        .unwrap()
        .write_all(&generated.stdout)
        .unwrap();
    let private = convert.wait_with_output().unwrap();
    assert!(private.status.success(), "synthetic RSA conversion");
    let f = Fixture::new().await;
    let payload = serde_json::to_vec(
        &json!({"credential_type":"github-app-root-v1","client_id":"Iv1.synthetic",
        "installation_id":42,"private_key_pkcs1_der_base64":BASE64.encode(&private.stdout)}),
    )
    .unwrap();
    let id = f.add("github-app-installation", &payload).await;
    let target = DerivedCredentialTarget::GitHubApp {
        installation_id: 42,
        repository_ids: vec![7],
        permissions: [
            ("issues".into(), "write".into()),
            ("metadata".into(), "read".into()),
        ]
        .into_iter()
        .collect(),
    };
    f.activate(
        vec![],
        vec![DerivedCredentialConnection {
            name: "github".into(),
            credential_id: id,
            effect: RuleEffect::Allow,
            max_ttl_seconds: 3600,
            target: target.clone(),
        }],
    )
    .await;
    let (expires, expiry_ms) = expiry(1800);
    f.fake.push_response(Ok(response(
        201,
        serde_json::to_vec(
            &json!({"token":"SYNTHETIC-INSTALLATION-TOKEN", "expires_at":expires,
        "repositories":[{"id":7}],"permissions":{"issues":"write","metadata":"read"}}),
        )
        .unwrap(),
    )));
    let issued = f
        .agent(agent_msg::DERIVE_CREDENTIAL, json!({"connection":"github"}))
        .await;
    assert_eq!(issued.ok()["kind"], "github-app");
    assert_eq!(issued.metadata["expires_at_ms"], expiry_ms);
    assert_eq!(issued.body, b"SYNTHETIC-INSTALLATION-TOKEN");
    assert_private(&issued, &[&BASE64.encode(&private.stdout)]);
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        (&*requests[0].host, &*requests[0].path, &*requests[0].method),
        (
            "api.github.com",
            "/app/installations/42/access_tokens",
            "POST"
        )
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
        json!({"repository_ids":[7],"permissions":{"issues":"write","metadata":"read"}})
    );
    assert!(requests[0].auth_value.starts_with(b"Bearer ey"));
    f.fake.push_response(Ok(response(
        201,
        serde_json::to_vec(
            &json!({"token":"SYNTHETIC-OVERBROAD-TOKEN", "expires_at":expires,
        "repositories":[{"id":7},{"id":8}],"permissions":{"issues":"write","metadata":"read"}}),
        )
        .unwrap(),
    )));
    let overbroad = f
        .agent(agent_msg::DERIVE_CREDENTIAL, json!({"connection":"github"}))
        .await;
    assert_eq!(overbroad.err_code(), "RESPONSE_BLOCKED");
    assert_private(&overbroad, &["SYNTHETIC-OVERBROAD-TOKEN"]);
    f.audit().await;
    f.finish().await;
}
