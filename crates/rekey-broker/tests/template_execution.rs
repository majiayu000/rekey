//! Real Authority/UDS authorization with synthetic template rows; installation is
//! a separate contract. The TLS case uses the existing screened transport seam.
mod common;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use data_encoding::BASE64URL_NOPAD;
use rekey_broker::{
    runtime::{BrokerConfig, serve},
    upstream::{
        UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamTransport,
        select_public_endpoint, send_screened,
    },
};
use rekey_domain::{
    action::{
        ActionName, FixedMethod, HeaderCredentialUse, HeaderName, HeaderPrefix, HttpsOrigin,
        RequestPolicy, ResponsePolicy,
    },
    authorization::ApprovalMode,
    credential::{CredentialKind, CredentialLabel},
    ids::{ApprovalId, ApproverId},
    ipc::{self, Channel, admin_msg, agent_msg},
};
use rekey_vault::{
    authority::spawn_authority,
    command::{ActionDefinition, UnlockProof},
    handle::AuthorityConfig,
    secret::SecretInput,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
};
use zeroize::Zeroizing;

const BODY: &[u8] = br#"{"title":"hello"}"#;
const SECRET: &[u8] = b"synthetic-template-execution-token";
fn proof() -> UnlockProof {
    UnlockProof::Password(SecretInput::from_slice(common::PASSWORD))
}

async fn fixture(transport: Option<Arc<dyn UpstreamTransport>>) -> (common::TestBroker, String) {
    let mut broker = common::start_broker().await;
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    tokio::time::timeout(Duration::from_secs(5), &mut broker.serve_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (authority, worker) =
        spawn_authority(AuthorityConfig::new(broker.state_dir.clone())).unwrap();
    authority.unlock(proof()).await.unwrap();
    let credential = authority
        .credential_add(
            CredentialLabel::new("template-fixture").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(SECRET),
            proof(),
        )
        .await
        .unwrap();
    let action=authority.action_upsert(None,ActionDefinition {
        native_plugin:None,text_stream:None,name:ActionName::new("template-fixture").unwrap(),credential_id:credential.id,
        origin:HttpsOrigin::parse("https://api.example.com").unwrap(),method:FixedMethod::Post,
        target:serde_json::from_value(json!({
            "kind":"template","target":{"path":"/repos/{repo}/issues/{number}","params":{"repo":"slug","number":"int:1..100"},"query":{"state":"enum:open,closed","page":"int:1..100"}},
            "fixed_headers":{"accept":"application/json","content-type":"application/json","x-template":"one"},
            "body_schema":{"type":"object","required":["title"],"properties":{"title":{"type":"string"}},"additionalProperties":false},
            "source":{"template":"team@1","capability":"issues","action_index":0,"digest":vec![7;32],"signer_id":null},"default_policy":{"rule":"allow"}
        })).unwrap(),
        auth:HeaderCredentialUse::new(HeaderName::new("authorization").unwrap(),HeaderPrefix::new("Bearer ").unwrap()).unwrap(),timeout_ms:5000,
        request_policy:RequestPolicy{max_body_bytes:4096,allowed_extra_headers:[HeaderName::new("x-note").unwrap()].into()},
        response_policy:ResponsePolicy{max_body_bytes:4096,allowed_headers:Default::default()},
    },proof()).await.unwrap();
    authority.shutdown(Some(proof())).await.unwrap();
    worker.join().unwrap();
    let mut config = BrokerConfig::new(broker.state_dir.clone());
    config.transport = Some(transport.unwrap_or_else(|| broker.fake.clone()));
    config.drain_timeout = Duration::from_secs(2);
    broker.serve_task = tokio::spawn(serve(config));
    let mut ready = false;
    for _ in 0..200 {
        if UnixStream::connect(broker.admin_sock()).await.is_ok()
            && UnixStream::connect(broker.agent_sock()).await.is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready);
    common::unlock(&broker).await;
    (broker, action.id.to_string())
}
fn metadata(token: &str, action: &str) -> Value {
    let mut value = common::execute_meta(token, action, 1);
    value["content_type"] = Value::Null;
    value["params"] = json!({"repo":"acme","number":"007"});
    value["query"] = json!({"state":"open","page":"02"});
    value
}
async fn execute(b: &common::TestBroker, meta: &Value, body: &[u8]) -> common::WireResponse {
    common::call(
        &b.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        &serde_json::to_vec(meta).unwrap(),
        body,
    )
    .await
}
fn success() -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        headers: vec![].into(),
        body: Zeroizing::new(b"clean".to_vec()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t7_attacks_and_schema_header_overrides_have_no_upstream_effect() {
    let (b, action) = fixture(None).await;
    let token = common::create_session(&b, &action, 1).await;
    let original = metadata(&token, &action);
    let mut attacks = Vec::new();
    for repo in [
        "..",
        ".",
        "%2f",
        "a/b",
        "a?b",
        "a#b",
        "аcme",
        &"a".repeat(101),
    ] {
        let mut m = original.clone();
        m["params"]["repo"] = repo.into();
        attacks.push(m);
    }
    for number in ["+1", " 1", "１", "101", "1/2"] {
        let mut m = original.clone();
        m["params"]["number"] = number.into();
        attacks.push(m);
    }
    let mut missing = original.clone();
    missing["params"].as_object_mut().unwrap().remove("repo");
    attacks.push(missing);
    let mut extra = original.clone();
    extra["params"]["unknown"] = "one".into();
    attacks.push(extra);
    let mut query = original.clone();
    query["query"]["unknown"] = "one".into();
    attacks.push(query);
    let mut ct = original.clone();
    ct["content_type"] = "application/json".into();
    attacks.push(ct);
    for header in ["accept", "x-template", "authorization", "content-type"] {
        let mut m = original.clone();
        m["extra_headers"] = json!([[header, "changed"]]);
        attacks.push(m);
    }
    for attack in attacks {
        assert_eq!(
            execute(&b, &attack, BODY).await.err_code(),
            "REQUEST_DENIED"
        );
    }
    for body in [
        br#"{}"#.as_slice(),
        br#"{"title":1}"#,
        br#"{"title":"one","title":"two"}"#,
        br#"{"title":"ok","other":1}"#,
    ] {
        assert_eq!(
            execute(&b, &original, body).await.err_code(),
            "REQUEST_DENIED"
        );
    }
    assert!(b.fake.take_requests().is_empty());
    // Rejected attempts did not disable a valid request or weaken fixed headers.
    b.fake.push_response(Ok(success()));
    execute(&b, &original, BODY).await.ok();
    let requests = b.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/repos/acme/issues/7?page=2&state=open");
    assert!(
        requests[0]
            .headers
            .contains(&("x-template".into(), "one".into()))
    );
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_template_allow_does_not_replace_active_policy() {
    let (b, action) = fixture(None).await;
    let session = common::policy::create_session_grant(&b, &action, 1, 5).await;
    assert_eq!(
        execute(&b, &metadata(&session.capability_token, &action), BODY)
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    assert!(b.fake.take_requests().is_empty());
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_requests_reject_params_and_query_but_keep_normal_execution() {
    let b = common::start_broker().await;
    common::unlock(&b).await;
    let cred = common::add_credential(&b, "fixed-test", SECRET).await;
    let (action, version) = common::create_action(&b, &cred).await;
    let token = common::create_session(&b, &action, version).await;
    let original = common::execute_meta(&token, &action, version);
    for field in ["params", "query"] {
        let mut changed = original.clone();
        changed[field] = json!({"unused":"value"});
        assert_eq!(
            execute(&b, &changed, b"{}").await.err_code(),
            "REQUEST_DENIED"
        );
    }
    assert!(b.fake.take_requests().is_empty());
    b.fake.push_response(Ok(success()));
    execute(&b, &original, b"{}").await.ok();
    assert_eq!(b.fake.take_requests()[0].path, "/v1/things");
    b.shutdown().await;
}

fn signed_grant(c: &ipc::ApprovalChallenge, approver: ApproverId, key: &Ed25519KeyPair) -> String {
    let mut grant = json!({"format_version":1,"approval_id":ApprovalId::new_random(),"approval_request_id":c.approval_request_id,"approver_id":approver,"tenant_id":c.tenant_id,"principal_id":c.principal_id,"session_id":c.session_id,"action_id":c.action_id,"action_version":c.action_version,"resource":c.resource,"schema_id":c.schema_id,"parameter_sha256":c.parameter_sha256,"policy_version":c.policy_version,"policy_sha256":c.policy_sha256,"policy_rule_id":c.policy_rule_id,"mode":c.mode,"not_before_ms":c.created_at_ms,"expires_at_ms":c.max_expires_at_ms.min(c.created_at_ms+60000),"max_uses":1});
    let mut message = b"RKAPPROVAL\0\x01".to_vec();
    message.extend(serde_jcs::to_vec(&grant).unwrap());
    grant["signature"] = BASE64URL_NOPAD.encode(key.sign(&message).as_ref()).into();
    grant.to_string()
}
#[tokio::test(flavor = "multi_thread")]
async fn approval_binds_params_and_query_and_accepts_equivalent_normalization() {
    let (b, action) = fixture(None).await;
    let session = common::policy::create_session_grant(&b, &action, 1, 10).await;
    let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let approver = ApproverId::new_random();
    common::policy::activate_approval_policy(
        &b,
        &action,
        1,
        common::policy::ApprovalPolicy {
            principal_id: &session.principal_id,
            approvers: &[(approver, key.public_key().as_ref().try_into().unwrap())],
            quorum: 1,
            mode: ApprovalMode::OneTime,
            max_uses: 1,
            max_window_ms: None,
        },
    )
    .await;
    let original = metadata(&session.capability_token, &action);
    let mut prepare = original.clone();
    prepare.as_object_mut().unwrap().remove("approval_grants");
    let response = common::call(
        &b.agent_sock(),
        Channel::Agent,
        agent_msg::PREPARE_APPROVAL,
        &serde_json::to_vec(&prepare).unwrap(),
        BODY,
    )
    .await;
    let envelope: ipc::SignedApprovalChallenge =
        serde_json::from_value(response.ok().clone()).unwrap();
    let c = &envelope.challenge;
    let grant = signed_grant(c, approver, &key);
    for (field, name, value) in [
        ("params", "number", "8"),
        ("params", "repo", "other"),
        ("query", "state", "closed"),
        ("query", "page", "3"),
    ] {
        let mut changed = original.clone();
        changed[field][name] = value.into();
        changed["approval_grants"] = json!([grant]);
        assert_eq!(
            execute(&b, &changed, BODY).await.err_code(),
            "REQUEST_DENIED"
        );
    }
    assert!(b.fake.take_requests().is_empty());
    let mut normalized = original;
    normalized["params"]["number"] = "7".into();
    normalized["query"] = json!({"page":"2","state":"open"});
    normalized["approval_grants"] = json!([grant]);
    b.fake.push_response(Ok(success()));
    execute(&b, &normalized, BODY).await.ok();
    assert_eq!(b.fake.take_requests().len(), 1);
    b.shutdown().await;
}

struct TlsTransport {
    addr: std::net::SocketAddr,
    ca: Vec<u8>,
}
impl UpstreamTransport for TlsTransport {
    fn send(&self, mut request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            let mut endpoint =
                select_public_endpoint(&request.host, &["93.184.216.34:443".parse().unwrap()])?;
            endpoint.addr = self.addr;
            request.port = self.addr.port();
            send_screened(request, endpoint, Some(&self.ca)).await
        })
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn real_tls_receives_the_authorized_path_sorted_query_and_fixed_headers() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["api.example.com".into()]).unwrap();
    let ca = cert.cert.der().to_vec();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = tls.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n")
                && bytes.len() >= end + 4 + BODY.len()
            {
                break;
            }
        }
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("POST /repos/acme/issues/7?page=2&state=open HTTP/1.1\r\n"));
        assert!(text.contains("\r\nx-template: one\r\n"));
        assert!(text.contains("\r\ncontent-type: application/json\r\n"));
        assert!(bytes.ends_with(BODY));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nclean")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
    });
    let (b, action) = fixture(Some(Arc::new(TlsTransport { addr, ca }))).await;
    let token = common::create_session(&b, &action, 1).await;
    let response = execute(&b, &metadata(&token, &action), BODY).await;
    response.ok();
    assert_eq!(response.body, b"clean");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    b.shutdown().await;
}
