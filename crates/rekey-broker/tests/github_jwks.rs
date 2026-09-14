//! Fixed online-key retrieval through the real Broker and signed policy boundary.
mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_broker::upstream::{
    UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamTransport,
};
use rekey_domain::ids::PrincipalId;
use rekey_domain::ipc::{Channel, agent_msg};
use rekey_policy::{GITHUB_ACTIONS_ISSUER, GITHUB_JWKS_MAX_BYTES};
use serde_json::{Value, json};
use tokio::sync::Notify;

fn identity() -> Value {
    json!({"principal_id":PrincipalId::new_random(),"issuer":GITHUB_ACTIONS_ISSUER,
        "audiences":["rekey://github-test"],"max_token_age_ms":900_000,
        "profile":{"kind":"ci-cloud","subject":"repo:owner/repo:ref:refs/heads/main"},
        "keys":[],"online_key_source":"github-actions-jwks"})
}

fn jwks(key: &RsaKeyPair) -> Vec<u8> {
    serde_json::to_vec(&json!({"keys":[{"kid":"rotating-key","kty":"RSA","alg":"RS256","use":"sig",
        "n":BASE64URL_NOPAD.encode(key.public_key().modulus().big_endian_without_leading_zero()),
        "e":BASE64URL_NOPAD.encode(key.public_key().exponent().big_endian_without_leading_zero())}]})).unwrap()
}

fn token(key: &RsaKeyPair, kid: &str, jti: &str, expired: bool) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let header = BASE64URL_NOPAD.encode(
        &serde_json::to_vec(
            &json!({"alg":"RS256","kid":kid,"x5t":BASE64URL_NOPAD.encode(&[7;20])}),
        )
        .unwrap(),
    );
    let claims = BASE64URL_NOPAD.encode(
        &serde_json::to_vec(&json!({"iss":GITHUB_ACTIONS_ISSUER,
        "sub":"repo:owner/repo:ref:refs/heads/main","aud":"rekey://github-test","jti":jti,
        "iat":now-60,"nbf":now-60,"exp":if expired {now-1} else {now+600}}))
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{input}.{}", BASE64URL_NOPAD.encode(&signature)).into_bytes()
}

fn response(body: Vec<u8>) -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: body.into(),
    }
}

async fn mint(broker: &common::TestBroker, action: &str, token: &[u8]) -> common::WireResponse {
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        &serde_json::to_vec(
            &json!({"actions":[{"action_id":action,"version":1}],"ttl_ms":60_000,"max_uses":1}),
        )
        .unwrap(),
        token,
    )
    .await
}

async fn setup(broker: &common::TestBroker) -> (String, Value) {
    common::unlock(broker).await;
    let credential =
        common::add_credential(broker, "github-workload", b"workload-action-secret").await;
    let (action, version) = common::create_action(broker, &credential).await;
    let identity = identity();
    common::policy::activate_workload_policy(broker, &action, version, identity.clone(), &[]).await;
    (action, identity)
}

#[tokio::test(flavor = "multi_thread")]
async fn each_mint_fetches_fresh_and_rotation_errors_expiry_replay_fail_closed() {
    let broker = common::start_broker().await;
    let (action, _) = setup(&broker).await;
    let old = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let new = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    broker.fake.push_response(Ok(response(jwks(&old))));
    mint(
        &broker,
        &action,
        &token(&old, "rotating-key", "old-first", false),
    )
    .await
    .ok();
    // Same kid has different material now: there must be no old-key cache fallback.
    broker.fake.push_response(Ok(response(jwks(&new))));
    assert_eq!(
        mint(
            &broker,
            &action,
            &token(&old, "rotating-key", "old-second", false)
        )
        .await
        .err_code(),
        "WORKLOAD_IDENTITY_INVALID"
    );
    broker.fake.push_response(Ok(response(jwks(&new))));
    assert_eq!(
        mint(
            &broker,
            &action,
            &token(&new, "rotating-key", "old-first", false)
        )
        .await
        .err_code(),
        "WORKLOAD_IDENTITY_INVALID"
    );
    let fresh = token(&new, "rotating-key", "new-first", false);
    broker.fake.push_response(Ok(response(jwks(&new))));
    mint(&broker, &action, &fresh).await.ok();
    broker.fake.push_response(Ok(response(jwks(&new))));
    assert_eq!(
        mint(&broker, &action, &fresh).await.err_code(),
        "WORKLOAD_IDENTITY_INVALID"
    );
    for bad in [
        token(&new, "missing-key", "unknown", false),
        token(&new, "rotating-key", "expired", true),
    ] {
        broker.fake.push_response(Ok(response(jwks(&new))));
        assert_eq!(
            mint(&broker, &action, &bad).await.err_code(),
            "WORKLOAD_IDENTITY_INVALID"
        );
    }
    for failure in [
        Err(UpstreamError::Transport),
        Ok(response(b"{bad".to_vec())),
        Ok(response(vec![b' '; GITHUB_JWKS_MAX_BYTES + 1])),
        Ok(UpstreamResponse {
            status: 302,
            ..response(jwks(&new))
        }),
    ] {
        broker.fake.push_response(failure);
        assert_eq!(
            mint(
                &broker,
                &action,
                &token(&new, "rotating-key", "network", false)
            )
            .await
            .err_code(),
            "WORKLOAD_IDENTITY_INVALID"
        );
    }
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 11);
    for request in requests {
        assert_eq!(request.host, "token.actions.githubusercontent.com");
        assert_eq!(request.port, 443);
        assert_eq!(request.path, "/.well-known/jwks");
        assert_eq!(request.method, "GET");
        assert_eq!(request.auth_name, "accept");
        assert_eq!(request.auth_value, b"application/json");
        assert!(request.body.is_empty());
    }
    broker.shutdown().await;
}

struct GatedJwks {
    entered: Notify,
    release: Notify,
    body: Vec<u8>,
}

impl UpstreamTransport for GatedJwks {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            assert_eq!(request.host, "token.actions.githubusercontent.com");
            assert_eq!(request.response_max_bytes, GITHUB_JWKS_MAX_BYTES as u32);
            assert!(request.timeout <= Duration::from_secs(25));
            self.entered.notify_one();
            self.release.notified().await;
            Ok(response(self.body.clone()))
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_can_change_during_network_wait_and_the_inflight_mint_is_rejected() {
    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let gate = Arc::new(GatedJwks {
        entered: Notify::new(),
        release: Notify::new(),
        body: jwks(&key),
    });
    let broker = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        Arc::new(FakeUpstreamTransport::new()),
        Arc::clone(&gate) as Arc<dyn UpstreamTransport>,
    )
    .await;
    let (action, identity) = setup(&broker).await;
    let token = token(&key, "rotating-key", "policy-race", false);
    let (minted, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(mint(&broker, &action, &token), async {
            gate.entered.notified().await;
            common::policy::activate_workload_policy(&broker, &action, 1, identity, &[]).await;
            gate.release.notify_one();
        })
    })
    .await
    .expect("network fetch must not hold mutation coordinator");
    assert_eq!(minted.err_code(), "POLICY_UNAVAILABLE");
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn online_jwks_fetches_are_bounded_below_agent_request_slots() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::watch;

    struct CountingGatedJwks {
        active: AtomicUsize,
        max_seen: AtomicUsize,
        release: watch::Sender<bool>,
        body: Vec<u8>,
    }

    impl UpstreamTransport for CountingGatedJwks {
        fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
            Box::pin(async move {
                assert_eq!(request.host, "token.actions.githubusercontent.com");
                let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_seen.fetch_max(current, Ordering::SeqCst);
                let mut released = self.release.subscribe();
                while !*released.borrow_and_update() {
                    if released.changed().await.is_err() {
                        break;
                    }
                }
                self.active.fetch_sub(1, Ordering::SeqCst);
                Ok(response(self.body.clone()))
            })
        }
    }

    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let (release, _) = watch::channel(false);
    let gate = Arc::new(CountingGatedJwks {
        active: AtomicUsize::new(0),
        max_seen: AtomicUsize::new(0),
        release,
        body: jwks(&key),
    });
    let broker = common::start_broker_with_transport(
        Duration::from_secs(300),
        Duration::from_secs(2),
        Arc::new(FakeUpstreamTransport::new()),
        Arc::clone(&gate) as Arc<dyn UpstreamTransport>,
    )
    .await;
    let (action, _) = setup(&broker).await;
    let agent = broker.agent_sock();

    let request_count = 8;
    let mut tasks = Vec::new();
    for i in 0..request_count {
        let agent = agent.clone();
        let action = action.clone();
        let tok = token(&key, "rotating-key", &format!("bound-{i}"), false);
        tasks.push(tokio::spawn(async move {
            common::call(
                &agent,
                Channel::Agent,
                agent_msg::WORKLOAD_SESSION_CREATE,
                &serde_json::to_vec(&json!({
                    "actions":[{"action_id":action,"version":1}],
                    "ttl_ms":60_000,
                    "max_uses":1
                }))
                .unwrap(),
                &tok,
            )
            .await
        }));
    }

    for _ in 0..50 {
        if gate.max_seen.load(Ordering::SeqCst) >= rekey_broker::runtime::MAX_ONLINE_JWKS_FETCHES {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        gate.max_seen.load(Ordering::SeqCst),
        rekey_broker::runtime::MAX_ONLINE_JWKS_FETCHES,
        "online JWKS must saturate at the dedicated fetch bound"
    );

    // Excess requests must fail without waiting on JWKS (non-waiting acquire).
    let excess = request_count - rekey_broker::runtime::MAX_ONLINE_JWKS_FETCHES;
    let mut rejected = 0usize;
    let mut pending = tasks;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while rejected < excess && tokio::time::Instant::now() < deadline {
        let mut still_pending = Vec::new();
        for task in pending {
            if task.is_finished() {
                let response = task.await.unwrap();
                assert_eq!(response.err_code(), "WORKLOAD_IDENTITY_INVALID");
                rejected += 1;
            } else {
                still_pending.push(task);
            }
        }
        pending = still_pending;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        rejected, excess,
        "excess online JWKS requests must fail fast without occupying Agent slots"
    );
    assert_eq!(
        gate.max_seen.load(Ordering::SeqCst),
        rekey_broker::runtime::MAX_ONLINE_JWKS_FETCHES
    );
    gate.release.send(true).unwrap();
    for task in pending {
        task.await.unwrap().ok();
    }
    assert_eq!(
        gate.max_seen.load(Ordering::SeqCst),
        rekey_broker::runtime::MAX_ONLINE_JWKS_FETCHES
    );
    broker.shutdown().await;
}
