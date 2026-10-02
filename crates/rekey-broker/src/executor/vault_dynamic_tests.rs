use serde::de::DeserializeSeed;

use super::*;

const PROFILE: &[u8] = br#"{
  "credential_type":"vault-dynamic-source-v2",
  "origin":"https://vault.example.com",
  "mount":"database",
  "role":"agent-api-token",
  "key":"token",
  "renew_increment_seconds":60,
  "vault_token":"hvs.bootstrap"
}"#;

fn parse_issued(body: &[u8]) -> Result<ParsedIssued, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let parsed = (IssuedSeed { key: "token" }).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(parsed)
}

#[test]
fn profile_accepts_only_the_closed_shape() {
    let profile = VaultDynamicProfile::parse_profile(PROFILE).unwrap();
    assert_eq!(profile.origin.host(), "vault.example.com");
    assert_eq!(profile.mount, "database");
    assert_eq!(profile.role, "agent-api-token");
    assert_eq!(profile.key, "token");
    assert_eq!(profile.token(), b"hvs.bootstrap");
    assert_eq!(profile.renew_increment_seconds, 60);

    for invalid in [
        br#"{}"#.as_slice(),
        br#"{"credential_type":"vault-dynamic-source-v2","credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"hvs.x","extra":true}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"http://vault.example.com","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com/path","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"bad/path","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"bad/path","key":"token","renew_increment_seconds":60,"vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"role","key":"","renew_increment_seconds":60,"vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":""}"#,
    ] {
        assert_eq!(
            VaultDynamicProfile::parse_profile(invalid).map(|_| ()),
            Err(VaultDynamicError::InvalidCredential)
        );
    }

    for (field, invalid_value) in [
        ("mount", "m".repeat(129)),
        ("role", "r".repeat(129)),
        ("key", "k".repeat(129)),
        ("vault_token", "t".repeat(4_097)),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
        value[field] = invalid_value.into();
        assert_eq!(
            VaultDynamicProfile::parse_profile(&serde_json::to_vec(&value).unwrap()).map(|_| ()),
            Err(VaultDynamicError::InvalidCredential)
        );
    }
}

#[test]
fn profile_requires_explicit_bounded_increment_and_v2_marker() {
    let valid: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
    for increment in [5, 300] {
        let mut value = valid.clone();
        value["renew_increment_seconds"] = increment.into();
        assert!(VaultDynamicProfile::parse_profile(&serde_json::to_vec(&value).unwrap()).is_ok());
    }
    for increment in [
        serde_json::json!(4),
        serde_json::json!(301),
        serde_json::json!(-1),
        serde_json::json!(5.5),
        serde_json::json!("60"),
        serde_json::Value::Null,
    ] {
        let mut value = valid.clone();
        value["renew_increment_seconds"] = increment;
        assert!(VaultDynamicProfile::parse_profile(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut missing = valid.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("renew_increment_seconds");
    assert!(VaultDynamicProfile::parse_profile(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut old = valid;
    old["credential_type"] = "vault-dynamic-source-v1".into();
    assert!(VaultDynamicProfile::parse_profile(&serde_json::to_vec(&old).unwrap()).is_err());
    let duplicate = String::from_utf8(PROFILE.to_vec()).unwrap().replace(
        "\"renew_increment_seconds\":60",
        "\"renew_increment_seconds\":60,\"renew_increment_seconds\":60",
    );
    assert!(VaultDynamicProfile::parse_profile(duplicate.as_bytes()).is_err());
}

fn parse_renewed(body: &[u8]) -> Result<ParsedRenewed, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let parsed = RenewedSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(parsed)
}

#[test]
fn renewal_accepts_metadata_only_and_checks_duplicates_types_and_ttl() {
    let parsed = parse_renewed(br#"{"lease_id":"id","lease_duration":5,"renewable":false,"data":null,"auth":null,"request_id":"ignored"}"#).unwrap();
    assert_eq!(parsed.lease_id.as_str(), "id");
    assert_eq!(parsed.lease_duration, 5);
    assert!(
        parse_renewed(br#"{"lease_id":"id","lease_duration":300,"renewable":true,"data":{}}"#)
            .is_ok()
    );
    for invalid in [
        br#"{"lease_id":"id","lease_duration":4,"renewable":true}"#.as_slice(),
        br#"{"lease_id":"id","lease_duration":301,"renewable":true}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":"true"}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":true,"renewable":true}"#,
        br#"{"lease_id":"id","lease_duration":5,"lease_duration":5,"renewable":true}"#,
        br#"{"lease_id":"id","lease_id":"id","lease_duration":5,"renewable":true}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":true,"data":null,"data":null}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":true,"data":{"password":"new-value"}}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":true,"auth":{"client_token":"new-token"}}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":true,"auth":null,"auth":null}"#,
        br#"{"lease_id":"id","lease_duration":5}"#,
        br#"{"lease_id":"id","lease_duration":5.5,"renewable":true}"#,
        br#"{"lease_id":"id","lease_duration":5,"renewable":true} trailing"#,
    ] { assert!(parse_renewed(invalid).is_err()); }
}

#[test]
fn renewal_deadline_uses_request_start_actual_ttl_and_original_action_cap() {
    let start = Instant::now();
    let action = start + Duration::from_secs(20);
    let renew_start = start + Duration::from_secs(2);
    // Actual 5s wins over a requested 60s; old expiry is never added.
    assert_eq!(
        lease_io_deadline(action, renew_start, Duration::from_secs(5)).unwrap(),
        start + Duration::from_millis(6_500)
    );
    // A large successful renewal cannot extend the absolute Action deadline.
    assert_eq!(
        lease_io_deadline(action, renew_start, Duration::from_secs(60)).unwrap(),
        action - CLEANUP_BUDGET
    );
    // Response/audit time consumes the window; it cannot move this deadline.
    let received = renew_start + Duration::from_secs(3);
    let remaining = lease_io_deadline(action, renew_start, Duration::from_secs(5))
        .unwrap()
        .duration_since(received);
    assert_eq!(remaining, Duration::from_millis(1_500));
}

#[test]
fn issued_response_extracts_one_bounded_selected_value() {
    let parsed = parse_issued(
        br#"{"lease_id":"database/creds/role/abc","lease_duration":60,"renewable":true,"data":{"username":"ignored","token":"dynamic-secret"},"request_id":"ignored"}"#,
    )
    .unwrap();
    assert_eq!(parsed.lease_id.as_str(), "database/creds/role/abc");
    assert_eq!(parsed.lease_duration, 60);
    assert!(parsed.renewable);
    assert_eq!(&*parsed.value, b"dynamic-secret");

    for duration in [5, 300] {
        let body = format!(
            r#"{{"lease_id":"id","lease_duration":{duration},"renewable":false,"data":{{"token":"x"}}}}"#
        );
        assert!(parse_issued(body.as_bytes()).is_ok());
    }

    for invalid in [
        br#"{"lease_id":"id","lease_duration":4,"renewable":true,"data":{"token":"x"}}"#.as_slice(),
        br#"{"lease_id":"id","lease_duration":301,"renewable":true,"data":{"token":"x"}}"#,
        br#"{"lease_id":"id","lease_id":"other","lease_duration":60,"renewable":true,"data":{"token":"x"}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":"x","token":"y"}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":null}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"other":"x"}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":"x"}} trailing"#,
    ] {
        assert!(parse_issued(invalid).is_err());
    }
}

#[test]
fn lease_probe_is_bounded_and_decodes_json_string_escapes() {
    let probe = probe_lease_ids(
        br#"{"lease_id":"one","nested":{"lease_id":"two"},"more":[{"lease_id":"three"},{"lease_id":"four"},{"lease_id":"five"}]}"#,
    );
    assert_eq!(probe.occurrences, 5);
    assert_eq!(probe.lease_ids.len(), LEASE_CAPTURE_LIMIT);
    assert!(probe.truncated);

    let slash = br#"{"lease_id":"database\/creds\/role\/abc"}"#;
    let slash_probe = probe_lease_ids(slash);
    assert_eq!(slash_probe.occurrences, 1);
    assert_eq!(slash_probe.lease_ids[0].as_str(), "database/creds/role/abc");

    let quoted = br#"{"lease_id":"foo\"bar"}"#;
    let quoted_probe = probe_lease_ids(quoted);
    assert_eq!(quoted_probe.occurrences, 1);
    assert_eq!(quoted_probe.lease_ids[0].as_str(), r#"foo"bar"#);

    let backslash = br#"{"lease_id":"foo\\bar"}"#;
    let backslash_probe = probe_lease_ids(backslash);
    assert_eq!(backslash_probe.occurrences, 1);
    assert_eq!(backslash_probe.lease_ids[0].as_str(), r"foo\bar");

    let unicode = br#"{"lease_id":"role\u002dname"}"#;
    let unicode_probe = probe_lease_ids(unicode);
    assert_eq!(unicode_probe.occurrences, 1);
    assert_eq!(unicode_probe.lease_ids[0].as_str(), "role-name");
    assert_eq!(
        parse_issued(
            br#"{"lease_id":"role\u002dname","lease_duration":60,"renewable":true,"data":{"token":"x"}}"#
        )
        .unwrap()
        .lease_id
        .as_str(),
        "role-name"
    );

    let unterminated = probe_lease_ids(br#"{"lease_id":"issued-id"#);
    assert_eq!(unterminated.occurrences, 0);
    assert!(unterminated.lease_ids.is_empty());
}

#[test]
fn edge_ows_is_closed_at_bootstrap_and_selected_value_intake() {
    for value in [" edge-vault-value ", "\tedge-vault-value\t", " \t "] {
        let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
        raw["vault_token"] = value.into();
        assert!(VaultDynamicProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).is_err());
        let issued = serde_json::to_vec(&serde_json::json!({"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":value}})).unwrap();
        assert!(parse_issued(&issued).is_err());
    }
}

use crate::upstream::UpstreamResponse;
struct PathBoundActorTransport {
    fake: Arc<crate::testing::FakeUpstreamTransport>,
}
impl UpstreamTransport for PathBoundActorTransport {
    fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        if request.path == "/v1/sys/leases/revoke" {
            self.fake.push_response(Ok(UpstreamResponse {
                status: 204,
                headers: vec![].into(),
                body: Zeroizing::new(vec![]),
            }));
        } else if request.path == "/business" {
            self.fake.push_response(Ok(UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(b"clean business body".to_vec()),
            }));
        }
        self.fake.send(request)
    }
}
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
    async fn new(key: &str) -> Self {
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
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let (authority, worker) = rekey_vault::authority::spawn_authority(
            rekey_vault::handle::AuthorityConfig::new(state.clone()),
        )
        .unwrap();
        authority.unlock(Self::proof()).await.unwrap();
        let credential = authority
            .credential_add(
                CredentialLabel::new("vault_dynamic-actor").unwrap(),
                CredentialKind::VaultDynamicSource,
                SecretInput::from_slice(&{
                    let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
                    raw["key"] = key.into();
                    serde_json::to_vec(&raw).unwrap()
                }),
                Self::proof(),
            )
            .await
            .unwrap();
        let action: FixedHttpAction = serde_json::from_value(serde_json::json!({"id":rekey_domain::ids::ActionId::new_random(),"name":"actor-action","version":1,"enabled":true,"credential_id":credential.id,"origin":"https://api.example.com","method":"POST","target":{"kind":"fixed","path":"/business"},"auth":{"header_name":"authorization","prefix":if key == "token" { "Bearer " } else { "Basic " }},"timeout_ms":30_000,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":1024,"allowed_headers":["content-type"]}})).unwrap();
        action.validate().unwrap();
        let (terminals, terminal_worker) = crate::audit::spawn_terminal_worker(authority.clone());
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let fake = Arc::new(crate::testing::FakeUpstreamTransport::new());
        let executor = ActionExecutor::new(
            authority.clone(),
            Arc::new(SessionRegistry::new()),
            Arc::new(PathBoundActorTransport { fake: fake.clone() }),
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
        rekey_vault::command::UnlockProof::Password(rekey_vault::secret::SecretInput::from_slice(
            b"actor-proof",
        ))
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
            params: Default::default(),
            query: Default::default(),
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
}

#[tokio::test]
async fn actor_decoded_selected_bootstrap_never_crosses_into_business() {
    let f = ActorFixture::new("token").await;
    let raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
    let token = raw["vault_token"].as_str().unwrap();
    let escaped = token
        .bytes()
        .map(|b| format!("\\u{:04x}", b))
        .collect::<String>();
    let mut source = UpstreamResponse {status:200,headers:vec![].into(),body:Zeroizing::new(serde_json::to_vec(&serde_json::json!({"lease_id":"database/creds/role/accepted-lease","lease_duration":60,"renewable":false,"data":{"token":token}})).unwrap())};
    source.body = Zeroizing::new(
        String::from_utf8(source.body.to_vec())
            .unwrap()
            .replace(token, &escaped)
            .into_bytes(),
    );
    assert!(contains_secret(
        &source.body,
        &sealing_needles(PROFILE, token.as_bytes())
    ));
    assert!(parse_issued(&source.body).is_ok());
    f.fake.push_response(Ok(source));
    let outcome = f.run().await;
    let requests = f.fake.take_requests();
    assert!(
        matches!(outcome, Err(BrokerError::ResponseSecurityViolation)),
        "decoded bootstrap accepted: success={}, source/business requests={}",
        outcome.is_ok(),
        requests.len()
    );
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
    assert_eq!(
        requests[1].body,
        br#"{"lease_id":"database/creds/role/accepted-lease","sync":true}"#
    );
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='vault.lease.issued'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_decoded_lease_identifier_bootstrap_is_compensated_before_public_audit() {
    let f = ActorFixture::new("token").await;
    let token = "hvs.bootstrap";
    let lease_id = format!("database/creds/role/{token}");
    let escaped = token
        .bytes()
        .map(|b| format!("\\u{:04x}", b))
        .collect::<String>();
    let body = serde_json::to_string(&serde_json::json!({"lease_id":lease_id,"lease_duration":60,"renewable":false,"data":{"token":"clean-dynamic-secret"}})).unwrap().replace(token, &escaped).into_bytes();
    assert!(parse_issued(&body).is_ok());
    assert!(contains_secret(
        &body,
        &sealing_needles(PROFILE, token.as_bytes())
    ));
    f.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![].into(),
        body: Zeroizing::new(body),
    }));
    let outcome = f.run().await;
    let requests = f.fake.take_requests();
    let public_reflections: i64 = f
        .db()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE reason_code LIKE '%hvs.bootstrap%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        matches!(outcome, Err(BrokerError::ResponseSecurityViolation)),
        "decoded lease bootstrap accepted: success={}, requests={}, public reflected audits={public_reflections}",
        outcome.is_ok(),
        requests.len()
    );
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[1].body).unwrap(),
        serde_json::json!({"lease_id":lease_id,"sync":true})
    );
    assert_eq!(public_reflections, 0);
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM vault_lease_journal WHERE phase='acquire_intent'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_decoded_selected_username_password_never_enter_basic_auth_and_clean_value_stays_exact()
 {
    for key in ["username", "password"] {
        for form in sealing_needles(b"hvs.bootstrap", b"hvs.bootstrap") {
            let f = ActorFixture::new(key).await;
            let value = format!("prefix:{}:suffix", std::str::from_utf8(&form).unwrap());
            let escaped = value
                .bytes()
                .map(|b| format!("\\u{:04x}", b))
                .collect::<String>();
            let body = serde_json::to_string(&serde_json::json!({"lease_id":"database/creds/role/accepted-lease","lease_duration":60,"renewable":false,"data":{key:value}})).unwrap().replace(&value, &escaped).into_bytes();
            let mut de = serde_json::Deserializer::from_slice(&body);
            assert!((IssuedSeed { key }).deserialize(&mut de).is_ok());
            assert!(contains_secret(
                &body,
                &sealing_needles(PROFILE, b"hvs.bootstrap")
            ));
            f.fake.push_response(Ok(UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: Zeroizing::new(body),
            }));
            assert!(matches!(
                f.run().await,
                Err(BrokerError::ResponseSecurityViolation)
            ));
            let requests = f.fake.take_requests();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
            f.finish().await;
        }
        let f = ActorFixture::new(key).await;
        let body = serde_json::to_vec(&serde_json::json!({"lease_id":"database/creds/role/clean-lease","lease_duration":60,"renewable":false,"data":{key:"clean-selected-value"}})).unwrap();
        f.fake.push_response(Ok(UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(body),
        }));
        assert_eq!(f.run().await.unwrap().body, b"clean business body");
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].auth_value, b"Basic clean-selected-value");
        assert_eq!(requests[2].path, "/v1/sys/leases/revoke");
        f.finish().await;
    }
}
