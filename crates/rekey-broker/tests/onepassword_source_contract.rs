//! Strict real Authority/UDS and screened TLS contracts; no network skips.
mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamTransport,
    select_public_endpoint, send_screened,
};
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use zeroize::Zeroizing;

const VAULT: &str = "abcdefghijklmnopqrstuvwxyz";
const ITEM: &str = "0123456789abcdefghijklmnop";
const RESOURCE: &str = "https://connect.example.com/v1/vaults/abcdefghijklmnopqrstuvwxyz/items/0123456789abcdefghijklmnop field=password version=7";
const BOOTSTRAP: &str = "onepassword-bootstrap-fixture-secret";
const VALUE: &[u8] = b"123456789";
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn profile(expiry: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"credential_type":"onepassword-connect-source-v1","origin":"https://connect.example.com","vault_id":VAULT,"item_id":ITEM,"field_id":"password","expected_item_version":7,"access_token":BOOTSTRAP,"local_use_expires_at_ms":expiry})).unwrap()
}
fn response(status: u16, body: Vec<u8>) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: Zeroizing::new(body),
    }
}
fn resolved() -> UpstreamResponse {
    response(
        200,
        serde_json::to_vec(&serde_json::json!({"id":ITEM,"vault":{"id":VAULT},"category":"API_CREDENTIAL","version":7,"fields":[{"id":"password","type":"CONCEALED","value":"123456789"}]})).unwrap(),
    )
}
async fn add(b: &common::TestBroker, p: &[u8]) -> String {
    common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        br#"{"label":"onepassword-fixture","kind":"onepassword-connect-source"}"#,
        &common::proof_and_secret_body(common::PASSWORD, p),
    )
    .await
    .ok()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn setup(expiry: i64, timeout_ms: u32) -> (common::TestBroker, String, String, u64, String) {
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let id = add(&b, &profile(expiry)).await;
    let mut meta = common::action_meta(&id);
    meta["timeout_ms"] = timeout_ms.into();
    let created = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action = created.ok()["id"].as_str().unwrap().to_owned();
    let version = created.ok()["version"].as_u64().unwrap();
    let cap = common::create_session(&b, &action, version).await;
    (b, id, action, version, cap)
}
async fn execute(
    b: &common::TestBroker,
    cap: &str,
    action: &str,
    version: u64,
) -> common::WireResponse {
    common::call(
        &b.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(cap, action, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_read_typed_rotation_and_durable_public_evidence() {
    let (b, id, action, version, cap) = setup(now_ms() + 3_500_000, 30000).await;
    for credential_version in [1, 2] {
        if credential_version == 2 {
            let p = profile(now_ms() + 3_500_000);
            common::call(
                &b.admin_sock(),
                Channel::Admin,
                admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT,
                serde_json::json!({"credential_id":id})
                    .to_string()
                    .as_bytes(),
                &common::proof_and_secret_body(common::PASSWORD, &p),
            )
            .await
            .ok();
        }
        b.fake.push_response(Ok(resolved()));
        b.fake.push_response(Ok(response(200, b"clean".to_vec())));
        let result = execute(&b, &cap, &action, version).await;
        result.ok();
        assert_eq!(result.body, b"clean");
        let sent = b.fake.take_requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].host, "connect.example.com");
        assert_eq!(sent[0].port, 443);
        assert_eq!(sent[0].method, "GET");
        assert_eq!(sent[0].path, format!("/v1/vaults/{VAULT}/items/{ITEM}"));
        assert!(sent[0].body.is_empty());
        assert_eq!(
            sent[0].headers,
            vec![
                ("accept".into(), "application/json".into()),
                ("content-type".into(), "application/json".into())
            ]
        );
        assert_eq!(sent[0].auth_value, format!("Bearer {BOOTSTRAP}").as_bytes());
        assert_eq!(sent[1].auth_value, b"Bearer 123456789");
        assert_eq!(sent[1].body, b"{}");
        let db = rusqlite::Connection::open(b.state_dir.join("vault.sqlite3")).unwrap();
        let rows:Vec<(String,u64,String)>=db.prepare("SELECT event_type,credential_version,reason_code FROM audit_events WHERE event_type IN ('onepassword.source.read_started','onepassword.source.resolved') ORDER BY sequence DESC LIMIT 2").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().map(Result::unwrap).collect();
        assert_eq!(
            rows,
            vec![
                (
                    "onepassword.source.resolved".into(),
                    credential_version,
                    RESOURCE.into()
                ),
                (
                    "onepassword.source.read_started".into(),
                    credential_version,
                    RESOURCE.into()
                )
            ]
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM vault_lease_journal", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn all_audit_failures_stop_before_the_next_effect() {
    for (event, reads) in [
        ("execution.started", 0),
        ("onepassword.source.read_started", 0),
        ("onepassword.source.resolved", 1),
    ] {
        let (b, _, action, version, cap) = setup(now_ms() + 3_500_000, 30000).await;
        let db = rusqlite::Connection::open(b.state_dir.join("vault.sqlite3")).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER fail_onepassword_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        b.fake.push_response(Ok(resolved()));
        let result = execute(&b, &cap, &action, version).await;
        assert_ne!(result.message_type, rekey_domain::ipc::resp_msg::OK);
        assert!(result.body.is_empty());
        assert_eq!(b.fake.take_requests().len(), reads);
        b.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bootstrap_and_value_reflection_is_sealed_in_body_and_header_names_and_values() {
    let (b, _, action, version, _) = setup(now_ms() + 3_500_000, 30000).await;
    let raw = profile(now_ms() + 3_500_000);
    // Rotate exactly this raw profile so its serialization is a sealing needle.
    let list = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    let id = list.ok()["credentials"][0]["id"].as_str().unwrap();
    common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT,
        serde_json::json!({"credential_id":id})
            .to_string()
            .as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, &raw),
    )
    .await
    .ok();
    for secret in [
        BOOTSTRAP.as_bytes(),
        format!("Bearer {BOOTSTRAP}").as_bytes(),
        raw.as_slice(),
        VALUE,
        b"Bearer 123456789",
    ] {
        let cap = common::create_session(&b, &action, version).await;
        let encodings = [
            secret.to_vec(),
            BASE64.encode(secret).into_bytes(),
            BASE64_NOPAD.encode(secret).into_bytes(),
            BASE64URL.encode(secret).into_bytes(),
            BASE64URL_NOPAD.encode(secret).into_bytes(),
            secret
                .iter()
                .map(|c| format!("%{c:02X}"))
                .collect::<String>()
                .into_bytes(),
        ];
        for encoded in encodings {
            for location in [0, 1, 2] {
                for business in [false, true] {
                    if !business && (secret == VALUE || secret == b"Bearer 123456789") {
                        continue;
                    }
                    if business {
                        b.fake.push_response(Ok(resolved()));
                    }
                    let mut reflected = response(403, b"safe provider error".to_vec());
                    match location {
                        0 => reflected.body = Zeroizing::new(encoded.clone()),
                        1 => {
                            reflected.headers =
                                vec![(String::from_utf8(encoded.clone()).unwrap(), "safe".into())]
                                    .into()
                        }
                        _ => {
                            reflected.headers = vec![(
                                "x-not-allowed".into(),
                                String::from_utf8(encoded.clone()).unwrap(),
                            )]
                            .into()
                        }
                    }
                    b.fake.push_response(Ok(reflected));
                    assert_eq!(
                        execute(&b, &cap, &action, version).await.err_code(),
                        "RESPONSE_SECURITY_VIOLATION"
                    );
                    assert_eq!(b.fake.take_requests().len(), if business { 2 } else { 1 });
                }
            }
        }
    }
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn source_errors_wrong_id_disabled_invalid_header_and_malformed_json_never_fall_back() {
    let (b, _, action, version, cap) = setup(now_ms() + 3_500_000, 30000).await;
    for error in [
        UpstreamError::Transport,
        UpstreamError::Timeout,
        UpstreamError::ResponseTooLarge,
        UpstreamError::Blocked("redirect"),
        UpstreamError::Blocked("private-address"),
    ] {
        b.fake.push_response(Err(error));
        assert_eq!(
            execute(&b, &cap, &action, version).await.err_code(),
            "UPSTREAM_FAILED"
        );
        assert_eq!(b.fake.take_requests().len(), 1);
    }
    for status in [401, 403, 404, 410, 429, 500] {
        b.fake.push_response(Ok(response(
            status,
            b"disabled or destroyed fixture".to_vec(),
        )));
        assert_eq!(
            execute(&b, &cap, &action, version).await.err_code(),
            "UPSTREAM_FAILED"
        );
        assert_eq!(b.fake.take_requests().len(), 1);
    }
    for invalid in [
        b"not-json".to_vec(),
        serde_json::to_vec(&serde_json::json!({"id":format!("{RESOURCE}x"),"value":"123456789"}))
            .unwrap(),
        serde_json::to_vec(
            &serde_json::json!({"id":ITEM,"vault":{"id":VAULT},"category":"API_CREDENTIAL","version":7,"state":"ARCHIVED","fields":[{"id":"password","type":"CONCEALED","value":"123456789"}]}),
        )
        .unwrap(),
    ] {
        b.fake.push_response(Ok(response(200, invalid)));
        assert_eq!(
            execute(&b, &cap, &action, version).await.err_code(),
            "UPSTREAM_FAILED"
        );
        assert_eq!(b.fake.take_requests().len(), 1);
    }
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_expiry_and_action_deadline_bound_source_but_expiry_does_not_bound_business() {
    let (b, _, action, version, cap) = setup(now_ms() + 1_000, 30000).await;
    b.fake
        .push_response_delayed(Ok(resolved()), Duration::from_millis(1500));
    assert_eq!(
        execute(&b, &cap, &action, version).await.err_code(),
        "UPSTREAM_FAILED"
    );
    assert_eq!(b.fake.take_requests().len(), 1);
    b.shutdown().await;
    let (b, _, action, version, cap) = setup(now_ms() + 3_500_000, 100).await;
    b.fake
        .push_response_delayed(Ok(resolved()), Duration::from_millis(300));
    assert_eq!(
        execute(&b, &cap, &action, version).await.err_code(),
        "UPSTREAM_FAILED"
    );
    assert_eq!(b.fake.take_requests().len(), 1);
    b.shutdown().await;
    let (b, _, action, version, cap) = setup(now_ms() + 1_500, 30000).await;
    b.fake.push_response(Ok(resolved()));
    b.fake.push_response_delayed(
        Ok(response(200, b"clean".to_vec())),
        Duration::from_millis(1700),
    );
    execute(&b, &cap, &action, version).await.ok();
    assert_eq!(b.fake.take_requests().len(), 2);
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_during_source_read_drains_without_business() {
    let (b, _, action, version, cap) = setup(now_ms() + 3_500_000, 30000).await;
    let gate = b.fake.push_response_gated(Ok(resolved()));
    let agent = b.agent_sock();
    let meta = common::execute_meta(&cap, &action, version).to_string();
    let task = tokio::spawn(async move {
        common::call(
            &agent,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            meta.as_bytes(),
            b"{}",
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while b.fake.requests.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let admin = b.admin_sock();
    let lock = tokio::spawn(async move {
        common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let probe = execute(&b, "invalid", &action, version).await;
            if probe.err_code() == "DRAINING" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    gate.notify_one();
    assert_eq!(task.await.unwrap().err_code(), "DRAINING");
    lock.await.unwrap().ok();
    assert_eq!(b.fake.take_requests().len(), 1);
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_add_rotate_step_up_and_generic_rotate_contracts() {
    let (b, id, _, _, _) = setup(now_ms() + 3_500_000, 30000).await;
    let metadata = serde_json::json!({"credential_id":id}).to_string();
    let invalid=b"{\"credential_type\":\"onepassword-connect-source-v1\",\"access_token\":\"invalid-profile-canary\"}";
    let wrong = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT,
        metadata.as_bytes(),
        &common::proof_and_secret_body(b"wrong", invalid),
    )
    .await;
    assert_eq!(wrong.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let valid_proof = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT,
        metadata.as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, invalid),
    )
    .await;
    assert_eq!(valid_proof.err_code(), "INVALID_INPUT");
    let generic = common::call(
        &b.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE,
        metadata.as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, b"raw-token"),
    )
    .await;
    assert_ne!(generic.message_type, rekey_domain::ipc::resp_msg::OK);
    b.shutdown().await;
}

struct WitnessTransport {
    fake: Arc<FakeUpstreamTransport>,
    db: Mutex<Option<std::path::PathBuf>>,
}
impl UpstreamTransport for WitnessTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            let db = rusqlite::Connection::open(self.db.lock().unwrap().as_ref().unwrap()).unwrap();
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
#[tokio::test(flavor = "multi_thread")]
async fn durable_audits_are_visible_at_source_and_business_send_boundaries() {
    let fake = Arc::new(FakeUpstreamTransport::new());
    let witness = Arc::new(WitnessTransport {
        fake: fake.clone(),
        db: Mutex::new(None),
    });
    let b = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        fake,
        witness.clone(),
    )
    .await;
    *witness.db.lock().unwrap() = Some(b.state_dir.join("vault.sqlite3"));
    common::unlock(&b).await;
    let id = add(&b, &profile(now_ms() + 3_500_000)).await;
    let (action, version) = common::create_action(&b, &id).await;
    let cap = common::create_session(&b, &action, version).await;
    b.fake.push_response(Ok(resolved()));
    b.fake.push_response(Ok(response(200, b"clean".to_vec())));
    execute(&b, &cap, &action, version).await.ok();
    b.shutdown().await;
}

struct TlsTransport {
    addr: std::net::SocketAddr,
    ca: Vec<u8>,
}
impl UpstreamTransport for TlsTransport {
    fn send(&self, mut request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            let mut screened =
                select_public_endpoint(&request.host, &["93.184.216.34:443".parse().unwrap()])?;
            screened.addr = self.addr;
            request.port = self.addr.port(); // test-only post-screen CA/address mapping
            send_screened(request, screened, Some(&self.ca)).await
        })
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn real_tls_source_and_business_use_production_transport() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec![
        "connect.example.com".into(),
        "api.example.com".into(),
    ])
    .unwrap();
    let ca = certified.cert.der().to_vec();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("strict real TLS listener");
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for source in [true, false] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let n = tls.read(&mut chunk).await.unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n")
                    && (source || bytes.len() >= end + 6)
                {
                    break;
                }
            }
            let text = String::from_utf8(bytes).unwrap();
            if source {
                assert!(text.starts_with(&format!("GET /v1/vaults/{VAULT}/items/{ITEM} HTTP/1.1")));
                assert!(text.contains(&format!("Bearer {BOOTSTRAP}")));
                assert!(!text.contains("Bearer 123456789"));
            } else {
                assert!(text.contains("Bearer 123456789"));
                assert!(!text.contains(BOOTSTRAP));
            }
            let body = if source {
                resolved().body.to_vec()
            } else {
                b"clean".to_vec()
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(header.as_bytes()).await.unwrap();
            tls.write_all(&body).await.unwrap();
            tls.shutdown().await.unwrap();
        }
    });
    let fake = Arc::new(FakeUpstreamTransport::new());
    let b = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        fake,
        Arc::new(TlsTransport { addr, ca }),
    )
    .await;
    common::unlock(&b).await;
    let id = add(&b, &profile(now_ms() + 3_500_000)).await;
    let (action, version) = common::create_action(&b, &id).await;
    let cap = common::create_session(&b, &action, version).await;
    let result = execute(&b, &cap, &action, version).await;
    result.ok();
    assert_eq!(result.body, b"clean");
    task.await.unwrap();
    b.shutdown().await;
}
