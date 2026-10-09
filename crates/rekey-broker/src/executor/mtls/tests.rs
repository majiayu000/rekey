use super::*;
use crate::execution_supervisor::{ExecutionSupervisorHandle, HttpExecution};
use crate::executor::LocalExecuteRequest;
use crate::session::SessionRegistry;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::action::{FixedMethod, HttpsOrigin};
use rekey_domain::connection::{
    ConnectionAuth, ConnectionRule, MethodSelector, MtlsAuthKind, RuleEffect,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{CredentialId, PolicyRuleId, PolicySignerId};
use rekey_vault::command::{PolicyBundleInput, PolicyTrustInput, UnlockProof};
use rekey_vault::secret::SecretInput;
use serde_json::json;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, RwLock, watch};
use tokio::task::JoinHandle;
const HOST: &str = "mtls.test";
const PASSWORD: &[u8] = b"synthetic-unified-mtls-proof";
fn proof() -> UnlockProof {
    UnlockProof::Password(SecretInput::from_slice(PASSWORD))
}
struct Server {
    fixture: TestFixture,
    identity: Zeroizing<String>,
    connections: Arc<AtomicUsize>,
    request: Arc<std::sync::Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}
async fn server(stage: Option<TestStage>, slow_body: bool, reflected: bool) -> Server {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let mut client_params = rcgen::CertificateParams::new(vec!["client.test".into()]).unwrap();
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();
    let identity = Zeroizing::new(format!(
        "{}{}{}",
        client_key.serialize_pem(),
        client_cert.pem(),
        ca.pem()
    ));
    let mut leaf_params = rcgen::CertificateParams::new(vec![HOST.into()]).unwrap();
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&connections);
    let request = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&request);
    let private_der = Zeroizing::new(client_key.serialize_der());
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut tls) = acceptor.accept(tcp).await {
            assert!(
                tls.get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|chain| !chain.is_empty())
            );
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match tls.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                }
                if bytes.windows(4).any(|w| w == b"\r\n\r\n") && bytes.ends_with(b"{}") {
                    break;
                }
            }
            *recorded.lock().unwrap() = bytes.clone();
            if !bytes.is_empty() {
                let response_body = if reflected {
                    data_encoding::BASE64.encode(&private_der).into_bytes()
                } else {
                    b"okay".to_vec()
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-visible: yes\r\nconnection: close\r\n\r\n",
                    response_body.len()
                );
                let _ = tls.write_all(headers.as_bytes()).await;
                if !slow_body {
                    let _ = tls.write_all(&response_body).await;
                }
                let _ = tls.flush().await;
                let _ = tls.read(&mut chunk).await; // client direct Both close, no TLS flush
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "private runner retried/reconnected"
        );
    });
    Server {
        fixture: TestFixture {
            endpoint: ScreenedEndpoint {
                host: HOST.into(),
                addr,
            },
            ca: ca.der().clone(),
            pause: stage.map(|stage| {
                Arc::new(TestPause {
                    stage,
                    reached: Notify::new(),
                    release: Notify::new(),
                })
            }),
            probe: Arc::new(TestProbe::default()),
        },
        identity,
        connections,
        request,
        task,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: std::path::PathBuf,
    executor: Arc<ActionExecutor>,
    credential: CredentialId,
    executions: ExecutionSupervisorHandle,
    shutdown: watch::Sender<bool>,
    supervisor: JoinHandle<Result<(), BrokerError>>,
    terminal: JoinHandle<()>,
    authority: std::thread::JoinHandle<()>,
}
impl Fixture {
    async fn new(server: &Server) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(PASSWORD),
            rekey_vault::crypto::kdf::Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let (authority, authority_thread) = rekey_vault::authority::spawn_authority(
            rekey_vault::handle::AuthorityConfig::new(state.clone()),
        )
        .unwrap();
        authority.unlock(proof()).await.unwrap();
        let credential = authority
            .credential_add(
                CredentialLabel::new("identity").unwrap(),
                CredentialKind::MtlsIdentity,
                SecretInput::from_slice(server.identity.as_bytes()),
                proof(),
            )
            .await
            .unwrap();
        let mut connection = rekey_policy::presets::generic_preset(
            HttpsOrigin::parse(&format!("https://{HOST}")).unwrap(),
            "authorization",
            "Bearer ",
        )
        .unwrap()
        .connection("fixture".into(), credential.id);
        connection.auth = ConnectionAuth::Mtls {
            kind: MtlsAuthKind::Mtls,
        };
        connection.rules = vec![ConnectionRule {
            id: PolicyRuleId::new_random(),
            methods: MethodSelector::Methods(vec![FixedMethod::Post]),
            path: "/fixed".into(),
            effect: RuleEffect::Allow,
        }];
        connection
            .allowed_response_headers
            .insert(rekey_domain::action::HeaderName::new("x-visible").unwrap());
        let signer = Ed25519KeyPair::from_seed_unchecked(&[44; 32]).unwrap();
        let signer_id = PolicySignerId::new_random();
        let trust = rekey_policy::parse_policy_trust(&serde_json::to_vec(&json!({"format_version":1,"signer_id":signer_id,"algorithm":"ed25519","public_key":HEXLOWER.encode(signer.public_key().as_ref())})).unwrap()).unwrap();
        authority
            .policy_trust_install_before(
                PolicyTrustInput {
                    signer_id,
                    key: trust.key().clone(),
                },
                proof(),
                None,
            )
            .await
            .unwrap();
        let mut bundle = json!({"format_version":1,"signer_id":signer_id,"snapshot":{"format_version":8,"version":1,"expires_at_ms":4_102_444_800_000_i64,"approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],"connections":[connection],"ssh_keys":[],"derived_credentials":[]}});
        let mut bytes = b"RKPOLICY\0\x01".to_vec();
        bytes.extend(serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = json!(BASE64URL_NOPAD.encode(signer.sign(&bytes).as_ref()));
        let now = crate::now_ts().unwrap();
        let bundle = rekey_policy::parse_and_verify_policy_bundle(
            &serde_json::to_vec(&bundle).unwrap(),
            &trust,
            now,
        )
        .unwrap();
        authority
            .policy_bundle_activate_before(
                PolicyBundleInput {
                    expected_vault_id: authority.status().await.unwrap().vault_id,
                    expected_trust_sha256: rekey_policy::policy_trust_sha256(
                        signer_id,
                        trust.key(),
                    )
                    .unwrap(),
                    signer_id,
                    version: 1,
                    expires_at_ms: bundle.snapshot().expires_at_ms(),
                    policy_digest: bundle.policy_digest(),
                    bundle_digest: bundle.bundle_digest(),
                    bundle_json: bundle.canonical_bytes().to_vec(),
                },
                proof(),
                None,
            )
            .await
            .unwrap();
        let policy = Arc::new(RwLock::new(Some(Arc::new(
            ActivePolicy::activate_bundle(bundle, now).unwrap(),
        ))));
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let (terminals, terminal) = crate::audit::spawn_terminal_worker(authority.clone());
        let executor = Arc::new(ActionExecutor::new(
            authority,
            Arc::new(SessionRegistry::new()),
            Arc::new(crate::testing::FakeUpstreamTransport::new()),
            lifecycle,
            terminals,
            policy,
        ));
        *executor.mtls_fixture.lock().unwrap() = Some(server.fixture.clone());
        let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
        let (shutdown, rx) = watch::channel(false);
        let supervisor = tokio::spawn(supervisor.run(rx));
        Self {
            _dir: dir,
            state,
            executor,
            credential: credential.id,
            executions,
            shutdown,
            supervisor,
            terminal,
            authority: authority_thread,
        }
    }
    async fn request(&self) -> tokio::sync::oneshot::Receiver<Result<HttpExecution, BrokerError>> {
        self.executions
            .submit_local(LocalExecuteRequest {
                request_id: rekey_domain::ids::RequestId::new_random(),
                meta: rekey_domain::ipc::CallMeta::http(
                    "fixture".into(),
                    FixedMethod::Post,
                    "/fixed".into(),
                ),
                body: Zeroizing::new(b"{}".to_vec()),
                caller: "mtls-test".into(),
            })
            .await
            .unwrap()
    }
    fn count(&self, event: &str) -> usize {
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.state))
            .unwrap()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type=?1",
                [event],
                |r| r.get(0),
            )
            .unwrap()
    }
    async fn stop(self) {
        self.shutdown.send_replace(true);
        self.supervisor.await.unwrap().unwrap();
        self.executor
            .terminals
            .wait_idle(Duration::from_secs(5))
            .await
            .unwrap();
        self.executor
            .authority
            .shutdown(Some(proof()))
            .await
            .unwrap();
        self.authority.join().unwrap();
        drop(self.executor);
        self.terminal.await.unwrap();
    }
}

#[tokio::test]
async fn signed_connection_performs_real_mtls_without_auth_header_or_retry() {
    let server = server(None, false, false).await;
    let f = Fixture::new(&server).await;
    let HttpExecution::Buffered(result) = f.request().await.await.unwrap().unwrap() else {
        panic!("buffered mTLS");
    };
    assert_eq!(result.body, b"okay");
    assert_eq!(result.upstream_status, 200);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.fixture.probe.signs.load(Ordering::SeqCst), 1);
    let request = String::from_utf8(server.request.lock().unwrap().clone()).unwrap();
    assert!(request.starts_with("POST /fixed HTTP/1.1\r\n"));
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    assert_eq!(f.count("execution.finished"), 1);
    assert!(matches!(
        f.executor.authority.prepare_credential(f.credential).await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    server.task.await.unwrap();
    f.stop().await;
}

#[tokio::test]
async fn private_der_reflection_is_sealed_after_real_client_authentication() {
    let server = server(None, false, true).await;
    let f = Fixture::new(&server).await;
    assert!(matches!(
        f.request().await.await.unwrap(),
        Err(BrokerError::ResponseSecurityViolation)
    ));
    f.executor
        .terminals
        .wait_idle(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(f.count("execution.indeterminate"), 1);
    server.task.await.unwrap();
    f.stop().await;
}

#[tokio::test]
async fn rotation_waits_for_native_key_and_tcp_owners_before_ack() {
    for stage in [
        TestStage::Prepared,
        TestStage::TlsConstructed,
        TestStage::Enqueue,
        TestStage::Body,
    ] {
        let server = server(Some(stage), true, false).await;
        let f = Fixture::new(&server).await;
        let response = f.request().await;
        let pause = server.fixture.pause.as_ref().unwrap();
        tokio::time::timeout(Duration::from_secs(5), pause.reached.notified())
            .await
            .unwrap();
        let executor = f.executor.clone();
        let credential = f.credential;
        let replacement = Zeroizing::new(server.identity.as_bytes().to_vec());
        let rotate = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let _coordinate = executor.lifecycle.coordinate_until(deadline).await.unwrap();
            executor
                .authority
                .credential_rotate_typed_before(
                    credential,
                    CredentialKind::MtlsIdentity,
                    Some(1),
                    SecretInput::from_slice(&replacement),
                    proof(),
                    Some(deadline.into_std()),
                )
                .await
                .unwrap();
            executor
                .lifecycle
                .cancel_private_credentials_until(Some(credential), deadline)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!rotate.is_finished());
        pause.release.notify_one();
        rotate.await.unwrap();
        assert!(response.await.unwrap().is_err());
        let events = server.fixture.probe.events.lock().unwrap().clone();
        let key = events.iter().position(|e| *e == "key-drop").unwrap();
        let tcp = events.iter().position(|e| *e == "tcp-close").unwrap();
        assert!(key < tcp, "{events:?}");
        if matches!(stage, TestStage::Prepared | TestStage::TlsConstructed) {
            assert_eq!(server.fixture.probe.signs.load(Ordering::SeqCst), 0);
        }
        server.task.await.unwrap();
        f.stop().await;
    }
}

#[tokio::test]
async fn changed_policy_before_tls_never_signs_or_sends_authentication() {
    let server = server(Some(TestStage::Prepared), false, false).await;
    let f = Fixture::new(&server).await;
    let response = f.request().await;
    let pause = server.fixture.pause.as_ref().unwrap();
    tokio::time::timeout(Duration::from_secs(5), pause.reached.notified())
        .await
        .unwrap();
    {
        let _owner = f.executor.lifecycle.coordinate().await;
        *f.executor.policy.write().await = None;
    }
    pause.release.notify_one();
    assert!(response.await.unwrap().is_err());
    assert_eq!(server.fixture.probe.signs.load(Ordering::SeqCst), 0);
    server.task.await.unwrap();
    f.stop().await;
}
