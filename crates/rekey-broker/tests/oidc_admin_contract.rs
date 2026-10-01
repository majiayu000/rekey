//! Strict real TLS, RS256, callback and UDS chain. Bind failures are real failures.
mod common;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_domain::ids::{PrincipalId, VaultId};
use rekey_domain::ipc::{self, Channel, admin_msg};
use rekey_vault::bootstrap::{confirm_vault_init, init_vault};
use rekey_vault::secret::SecretInput;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn private_write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
struct Expected {
    nonce: String,
    challenge: String,
    code: String,
    used: bool,
    wrong_nonce: bool,
}
struct SourceState {
    expected: Option<Expected>,
    active: bool,
    token_calls: usize,
    proof_calls: usize,
}
struct Fixture {
    dir: tempfile::TempDir,
    state: PathBuf,
    socket: PathBuf,
    issuer: String,
    callback: String,
    principal: PrincipalId,
    vault: VaultId,
    source: Arc<Mutex<SourceState>>,
    server: tokio::task::JoinHandle<()>,
    broker: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
}
impl Fixture {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = dir.path().join("state");
        let outcome = init_vault(
            &state,
            &SecretInput::from_slice(common::PASSWORD),
            common::TEST_PARAMS,
        )
        .unwrap();
        confirm_vault_init(&state).unwrap();
        let vault = outcome.vault_id;
        let principal = PrincipalId::new_random();
        let other_vault = VaultId::new_random();
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let ca = dir.path().join("ca.pem");
        private_write(&ca, certified.cert.pem().as_bytes());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("strict OIDC TLS listener; never skipped");
        let issuer = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let reservation =
            std::net::TcpListener::bind("127.0.0.1:0").expect("strict callback port reservation");
        let callback = format!(
            "http://127.0.0.1:{}/oidc/callback",
            reservation.local_addr().unwrap().port()
        );
        drop(reservation);
        let source = Arc::new(Mutex::new(SourceState {
            expected: None,
            active: true,
            token_calls: 0,
            proof_calls: 0,
        }));
        let shared = source.clone();
        let expected_issuer = issuer.clone();
        let expected_redirect = callback.clone();
        let signing = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let jwks=serde_json::to_vec(&json!({"keys":[{"kty":"RSA","alg":"RS256","kid":"fixture-current","use":"sig","key_ops":["verify"],
            "n":BASE64URL_NOPAD.encode(signing.public_key().modulus().big_endian_without_leading_zero()),"e":BASE64URL_NOPAD.encode(signing.public_key().exponent().big_endian_without_leading_zero())}]})).unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(tcp).await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                let end = loop {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    assert!(bytes.len() <= 64 * 1024);
                    if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                        let header = std::str::from_utf8(&bytes[..end]).unwrap();
                        let len = header
                            .lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            break end;
                        }
                    }
                };
                let header = std::str::from_utf8(&bytes[..end]).unwrap();
                let line = header.lines().next().unwrap();
                let (status, body) = if line == "POST /token HTTP/1.1" {
                    let form = url::form_urlencoded::parse(&bytes[end + 4..])
                        .into_owned()
                        .collect::<BTreeMap<_, _>>();
                    assert_eq!(form.len(), 5);
                    assert_eq!(form["grant_type"], "authorization_code");
                    assert_eq!(form["client_id"], "rekey-admin");
                    assert_eq!(form["redirect_uri"], expected_redirect);
                    let mut state = shared.lock().unwrap();
                    state.token_calls += 1;
                    let expected = state
                        .expected
                        .as_mut()
                        .expect("authorization before exchange");
                    assert!(!expected.used, "code is consumed once");
                    expected.used = true;
                    assert_eq!(form["code"], expected.code);
                    assert_eq!(
                        BASE64URL_NOPAD.encode(&Sha256::digest(form["code_verifier"].as_bytes())),
                        expected.challenge
                    );
                    let now = now_ms() / 1000;
                    let nonce = if expected.wrong_nonce {
                        "wrong-nonce"
                    } else {
                        &expected.nonce
                    };
                    let input=format!("{}.{}",BASE64URL_NOPAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"fixture-current"}"#),
                        BASE64URL_NOPAD.encode(&serde_json::to_vec(&json!({"iss":expected_issuer,"sub":"stable-admin","aud":"rekey-admin","iat":now,"exp":now+180,"nonce":nonce,
                        "at_hash":BASE64URL_NOPAD.encode(&Sha256::digest(b"synthetic-access-token")[..16])})).unwrap()));
                    let mut signature = vec![0; signing.public_modulus_len()];
                    signing
                        .sign(
                            &RSA_PKCS1_SHA256,
                            &SystemRandom::new(),
                            input.as_bytes(),
                            &mut signature,
                        )
                        .unwrap();
                    let token = format!("{input}.{}", BASE64URL_NOPAD.encode(&signature));
                    (200,serde_json::to_vec(&json!({"access_token":"synthetic-access-token","id_token":token,"token_type":"Bearer","expires_in":180,"refresh_token":"never-retained"})).unwrap())
                } else if line == "GET /jwks HTTP/1.1" {
                    (200, jwks.clone())
                } else if line == "GET /v1/directory/admin-identity HTTP/1.1" {
                    assert!(header.lines().any(|line| {
                        line.split_once(':').is_some_and(|(k, v)| {
                            k.eq_ignore_ascii_case("authorization")
                                && v.trim() == "Bearer synthetic-access-token"
                        })
                    }));
                    let mut state = shared.lock().unwrap();
                    state.proof_calls += 1;
                    if state.active {
                        (200,serde_json::to_vec(&json!({"formatVersion":1,"issuer":expected_issuer,"subject":"stable-admin","principalId":principal,
                        "mappingVersion":1,"mappingSha256":"a".repeat(64),"nodes":[{"nodeId":"11111111-1111-4111-8111-111111111111","vaultId":vault},
                            {"nodeId":"22222222-2222-4222-8222-222222222222","vaultId":other_vault}],"observedAtMs":now_ms()})).unwrap())
                    } else {
                        (403, b"unavailable".to_vec())
                    }
                } else {
                    panic!("unexpected trusted endpoint request")
                };
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let profile = dir.path().join("oidc-profile.json");
        private_write(&profile,&serde_json::to_vec(&json!({"format_version":1,"issuer":issuer,"client_id":"rekey-admin",
            "authorization_url":format!("{issuer}/authorize"),"token_url":format!("{issuer}/token"),"jwks_url":format!("{issuer}/jwks"),"redirect_uri":callback,
            "ca_certificate_file":ca,"directory_identity_url":format!("{issuer}/v1/directory/admin-identity"),"directory_ca_certificate_file":ca,"directory_mapping_sha256":"a".repeat(64),
            "node_id":"11111111-1111-4111-8111-111111111111","vault_id":vault,"administrators":[{"subject":"stable-admin","principal_id":principal}]})).unwrap());
        let mut config = BrokerConfig::new(state.clone());
        config.oidc_admin_profile = Some(profile);
        config.drain_timeout = Duration::from_secs(1);
        let socket = state.join("runtime/admin.sock");
        let broker = tokio::spawn(serve(config));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if UnixStream::connect(&socket).await.is_ok() {
                    break;
                }
                assert!(!broker.is_finished(), "strict Broker startup failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("strict UDS readiness");
        common::call(
            &socket,
            Channel::Admin,
            admin_msg::UNLOCK_PASSWORD,
            b"{}",
            common::PASSWORD,
        )
        .await
        .ok();
        Self {
            dir,
            state,
            socket,
            issuer,
            callback,
            principal,
            vault,
            source,
            server,
            broker,
        }
    }
    async fn authenticate(&self, wrong_nonce: bool) -> common::WireResponse {
        let begun = common::call(
            &self.socket,
            Channel::Admin,
            admin_msg::OIDC_LOGIN_BEGIN,
            b"{}",
            b"",
        )
        .await;
        let url = url::Url::parse(begun.ok()["authorization_url"].as_str().unwrap()).unwrap();
        let fields = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        assert_eq!(fields["response_type"], "code");
        assert_eq!(fields["code_challenge_method"], "S256");
        assert_eq!(fields["redirect_uri"], self.callback);
        let code = "synthetic-code-single-use";
        self.source.lock().unwrap().expected = Some(Expected {
            nonce: fields["nonce"].clone(),
            challenge: fields["code_challenge"].clone(),
            code: code.into(),
            used: false,
            wrong_nonce,
        });
        let mut callback = url::Url::parse(&self.callback).unwrap();
        callback.query_pairs_mut().extend_pairs([
            ("state", fields["state"].as_str()),
            ("code", code),
            ("iss", self.issuer.as_str()),
        ]);
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(callback)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let result = common::call(
            &self.socket,
            Channel::Admin,
            admin_msg::OIDC_LOGIN_FINISH,
            &serde_json::to_vec(&json!({"flow_id":begun.ok()["flow_id"]})).unwrap(),
            b"",
        )
        .await;
        let repeated = common::call(
            &self.socket,
            Channel::Admin,
            admin_msg::OIDC_LOGIN_FINISH,
            &serde_json::to_vec(&json!({"flow_id":begun.ok()["flow_id"]})).unwrap(),
            b"",
        )
        .await;
        assert_ne!(repeated.message_type, ipc::resp_msg::OK);
        result
    }
    async fn managed(
        &self,
        id: u16,
        metadata: &[u8],
        body: &[u8],
        token: &[u8],
    ) -> common::WireResponse {
        common::call(
            &self.socket,
            Channel::Admin,
            id,
            metadata,
            &ipc::encode_management_body(token, body).unwrap(),
        )
        .await
    }
    async fn stop(self) {
        common::call(&self.socket, Channel::Admin, admin_msg::LOCK, b"{}", b"")
            .await
            .ok();
        common::call(
            &self.socket,
            Channel::Admin,
            admin_msg::SHUTDOWN,
            b"{}",
            b"",
        )
        .await
        .ok();
        self.broker.await.unwrap().unwrap();
        self.server.abort();
        let _ = self.server.await;
        drop(self.dir);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_oidc_rs256_pkce_directory_managed_ipc_stepup_mint_logout_and_offboard() {
    let fixture = Fixture::start().await;
    let invalid = fixture.authenticate(true).await;
    assert_eq!(invalid.err_code(), "POLICY_INVALID");
    assert!(invalid.body.is_empty());
    let login = fixture.authenticate(false).await;
    assert_eq!(login.ok()["principal_id"], fixture.principal.to_string());
    ipc::validate_management_token(&login.body).unwrap();
    let token = login.body;
    let without = common::call(
        &fixture.socket,
        Channel::Admin,
        admin_msg::METRICS,
        b"{}",
        b"",
    )
    .await;
    assert_eq!(without.err_code(), "INVALID_FRAME");
    let metrics = fixture
        .managed(admin_msg::METRICS, b"{}", b"", &token)
        .await;
    metrics.ok();
    let bad_step = fixture
        .managed(
            admin_msg::CREDENTIAL_ADD,
            br#"{"label":"fixture","kind":"opaque-token"}"#,
            &common::proof_and_secret_body(b"wrong-proof", b"fixture-business-credential"),
            &token,
        )
        .await;
    assert_eq!(bad_step.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let added = fixture
        .managed(
            admin_msg::CREDENTIAL_ADD,
            br#"{"label":"fixture","kind":"opaque-token"}"#,
            &common::proof_and_secret_body(common::PASSWORD, b"fixture-business-credential"),
            &token,
        )
        .await;
    let credential = added.ok()["id"].as_str().unwrap();
    let action_meta = common::action_meta(credential);
    let action = fixture
        .managed(
            admin_msg::ACTION_CREATE,
            &serde_json::to_vec(&action_meta).unwrap(),
            &common::proof_body(common::PASSWORD),
            &token,
        )
        .await;
    let create = json!({"actions":[{"action_id":action.ok()["id"],"version":action.ok()["version"]}],"ttl_ms":3_600_000,"max_uses":10});
    let session = fixture
        .managed(
            admin_msg::SESSION_CREATE,
            &serde_json::to_vec(&create).unwrap(),
            &common::proof_body(common::PASSWORD),
            &token,
        )
        .await;
    assert_eq!(session.ok()["principal_id"], fixture.principal.to_string());
    assert!(
        session.ok()["expires_at_ms"].as_i64().unwrap()
            <= login.metadata["expires_at_ms"].as_i64().unwrap()
    );
    let logout = common::call(
        &fixture.socket,
        Channel::Admin,
        admin_msg::OIDC_LOGOUT,
        b"{}",
        &token,
    )
    .await;
    assert_eq!(logout.ok()["capabilities"], 1);
    assert_eq!(
        fixture
            .managed(admin_msg::METRICS, b"{}", b"", &token)
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    let second = fixture.authenticate(false).await;
    second.ok();
    fixture.source.lock().unwrap().active = false;
    assert_eq!(
        fixture
            .managed(admin_msg::METRICS, b"{}", b"", &second.body)
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    let status = common::call(
        &fixture.socket,
        Channel::Admin,
        admin_msg::STATUS,
        b"{}",
        b"",
    )
    .await;
    assert_eq!(status.ok()["sessions_active"], 0);
    {
        let source = fixture.source.lock().unwrap();
        assert_eq!(source.token_calls, 3);
        assert!(source.proof_calls >= 7);
    }
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&fixture.state)).unwrap();
    let bare:i64=db.query_row("SELECT count(*) FROM audit_events WHERE event_type='admin.oidc' AND principal_id IS NOT NULL",[],|r|r.get(0)).unwrap();
    assert_eq!(bare, 0);
    assert_ne!(fixture.vault, VaultId::new_random());
    drop(db);
    fixture.stop().await;
}
