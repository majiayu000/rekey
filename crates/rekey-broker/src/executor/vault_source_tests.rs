use zeroize::Zeroizing;

use super::*;
use crate::upstream::UpstreamResponse;

const PROFILE: &[u8] = br#"{
  "credential_type":"vault-kv-v2-source-v1",
  "origin":"https://vault.example.com",
  "mount":"secret",
  "path":"agents/github",
  "key":"token",
  "version":7,
  "vault_token":"hvs.source-canary"
}"#;

fn response(value: serde_json::Value) -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: Zeroizing::new(serde_json::to_vec(&value).unwrap()),
    }
}

#[test]
fn profile_builds_one_exact_versioned_read() {
    let profile = VaultKvProfile::parse_profile(PROFILE).unwrap();
    let request = profile.request(Duration::from_secs(2));
    assert_eq!(request.host, "vault.example.com");
    assert_eq!(request.port, 443);
    assert_eq!(request.method, FixedMethod::Get);
    assert_eq!(request.path, "/v1/secret/data/agents/github?version=7");
    assert_eq!(
        request.headers,
        [("accept".to_owned(), "application/json".to_owned())]
    );
    assert_eq!(request.auth_header.0, "x-vault-token");
    assert_eq!(&*request.auth_header.1, b"hvs.source-canary");
    assert!(request.body.is_empty());
    assert_eq!(request.response_max_bytes, 64 * 1024);
}

#[test]
fn response_is_exactly_version_and_single_field_bound() {
    let profile = VaultKvProfile::parse_profile(PROFILE).unwrap();
    let valid = response(serde_json::json!({
        "data": {
            "data": {"token":"resolved-canary"},
            "metadata": {"version":7,"deletion_time":"","destroyed":false},
            "provider_extra":"ignored"
        },
        "request_id":"ignored"
    }));
    assert_eq!(&*profile.resolve(&valid).unwrap().value, b"resolved-canary");

    for invalid in [
        serde_json::json!({"data":{"data":{"other":"x"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x","other":"y"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x"},"metadata":{"version":8,"deletion_time":"","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x"},"metadata":{"version":7,"deletion_time":"2026-09-03T00:00:00Z","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x"},"metadata":{"version":7,"deletion_time":"","destroyed":true}}}),
        serde_json::json!({"data":{"data":{"token":{"nested":true}},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
    ] {
        assert!(profile.resolve(&response(invalid)).is_err());
    }

    let duplicate = br#"{"data":{"data":{"token":"first","token":"second"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}"#;
    let duplicate = UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: Zeroizing::new(duplicate.to_vec()),
    };
    assert_eq!(
        profile.resolve(&duplicate).map(|_| ()),
        Err(VaultKvError::SourceResponse)
    );

    let maximum = response(serde_json::json!({
        "data":{"data":{"token":"x".repeat(8 * 1024)},"metadata":{"version":7,"deletion_time":"","destroyed":false}}
    }));
    assert_eq!(profile.resolve(&maximum).unwrap().value.len(), 8 * 1024);
    for value in [
        String::new(),
        "contains space".to_owned(),
        "x".repeat(8 * 1024 + 1),
    ] {
        let invalid = response(serde_json::json!({
            "data":{"data":{"token":value},"metadata":{"version":7,"deletion_time":"","destroyed":false}}
        }));
        assert_eq!(
            profile.resolve(&invalid).map(|_| ()),
            Err(VaultKvError::SourceResponse)
        );
    }
}

#[test]
fn profile_rejects_open_or_unsafe_configuration() {
    for invalid in [
        br#"{"credential_type":"wrong","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"http://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"../secret","path":"a","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a/../b","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":0,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"bad token"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"hvs.x","extra":true}"#.as_slice(),
    ] {
        assert_eq!(
            VaultKvProfile::parse_profile(invalid).map(|_| ()),
            Err(VaultKvError::InvalidCredential)
        );
    }

    for (field, value) in [
        ("mount", "x".repeat(129)),
        (
            "path",
            std::iter::repeat_n("x", 17).collect::<Vec<_>>().join("/"),
        ),
        ("key", "x".repeat(129)),
        ("vault_token", "x".repeat(4_097)),
    ] {
        let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
        raw[field] = value.into();
        assert_eq!(
            VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).map(|_| ()),
            Err(VaultKvError::InvalidCredential)
        );
    }
}

#[test]
fn edge_ows_is_closed_at_bootstrap_and_resolved_intake() {
    for value in [" edge-vault-value ", "\tedge-vault-value\t", " \t "] {
        let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
        raw["vault_token"] = value.into();
        assert!(VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).is_err());
        let profile = VaultKvProfile::parse_profile(PROFILE).unwrap();
        assert!(profile.resolve(&response(serde_json::json!({"data":{"data":{"token":value},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}))).is_err());
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
    async fn new() -> Self {
        Self::with_profile(PROFILE).await
    }
    async fn with_profile(source_profile: &[u8]) -> Self {
        Self::with_kind(
            source_profile,
            rekey_domain::credential::CredentialKind::VaultKvV2Source,
        )
        .await
    }
    async fn with_kind(
        source_profile: &[u8],
        kind: rekey_domain::credential::CredentialKind,
    ) -> Self {
        use rekey_domain::credential::CredentialLabel;
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
                CredentialLabel::new("vault_source-actor").unwrap(),
                kind,
                SecretInput::from_slice(source_profile),
                Self::proof(),
            )
            .await
            .unwrap();
        let action: FixedHttpAction = serde_json::from_value(serde_json::json!({"id":rekey_domain::ids::ActionId::new_random(),"name":"actor-action","version":1,"enabled":true,"credential_id":credential.id,"origin":"https://api.example.com","method":"POST","target":{"kind":"fixed","path":"/business"},"auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":30_000,"request_policy":{"max_body_bytes":1024,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":1024,"allowed_headers":["content-type"]}})).unwrap();
        action.validate().unwrap();
        let (terminals, terminal_worker) = crate::audit::spawn_terminal_worker(authority.clone());
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let fake = Arc::new(crate::testing::FakeUpstreamTransport::new());
        let executor = ActionExecutor::new(
            authority.clone(),
            Arc::new(SessionRegistry::new()),
            fake.clone(),
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
    async fn begin(
        &self,
        end: Instant,
    ) -> Result<(StartedAuditGuard, ExecuteRequest), BrokerError> {
        let ctx = ExecutionAuditContext {
            request_context: None,
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
            local_approval_request_id: None,
        };
        let started = self
            .executor
            .terminals
            .commit_started(ctx, vec![], Some(end), None)
            .await?;
        Ok((started, request))
    }
    async fn run(&self) -> Result<ExecuteOutcome, BrokerError> {
        let end = Instant::now() + Duration::from_millis(self.action.timeout_ms.into());
        let (mut started, request) = self.begin(end).await?;
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
    let f = ActorFixture::new().await;
    let raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
    let token = raw["vault_token"].as_str().unwrap();
    let escaped = token
        .bytes()
        .map(|b| format!("\\u{:04x}", b))
        .collect::<String>();
    let mut source = response(
        serde_json::json!({"data":{"data":{"token":token},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
    );
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
    assert!(
        VaultKvProfile::parse_profile(PROFILE)
            .unwrap()
            .resolve(&source)
            .is_ok()
    );
    f.fake.push_response(Ok(source));
    f.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![].into(),
        body: Zeroizing::new(b"clean business body".to_vec()),
    }));

    let outcome = f.run().await;
    let requests = f.fake.take_requests();
    assert!(
        matches!(outcome, Err(BrokerError::ResponseSecurityViolation)),
        "decoded bootstrap accepted: success={}, source/business requests={}",
        outcome.is_ok(),
        requests.len()
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.blocked'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_decoded_selected_known_bootstrap_forms_are_sealed_and_clean_values_stay_exact() {
    let f = ActorFixture::new().await;
    for form in sealing_needles(b"hvs.source-canary", b"hvs.source-canary") {
        let value = format!("prefix:{}:suffix", std::str::from_utf8(&form).unwrap());
        let escaped = value
            .bytes()
            .map(|b| format!("\\u{:04x}", b))
            .collect::<String>();
        let mut source = response(
            serde_json::json!({"data":{"data":{"token":value},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
        );
        source.body = Zeroizing::new(
            String::from_utf8(source.body.to_vec())
                .unwrap()
                .replace(&value, &escaped)
                .into_bytes(),
        );
        assert!(contains_secret(
            &source.body,
            &sealing_needles(PROFILE, b"hvs.source-canary")
        ));
        assert!(
            VaultKvProfile::parse_profile(PROFILE)
                .unwrap()
                .resolve(&source)
                .is_ok()
        );
        f.fake.push_response(Ok(source));
        assert!(matches!(
            f.run().await,
            Err(BrokerError::ResponseSecurityViolation)
        ));
        assert_eq!(f.fake.take_requests().len(), 1);
    }
    f.fake.push_response(Ok(response(serde_json::json!({"data":{"data":{"token":"clean-selected-value"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}))));
    f.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![].into(),
        body: Zeroizing::new(b"clean business body".to_vec()),
    }));
    assert_eq!(f.run().await.unwrap().body, b"clean business body");
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].auth_value, b"Bearer clean-selected-value");
    f.finish().await;
}

#[test]
fn profile_accepts_literal_latest_without_a_query() {
    let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
    raw["version"] = "latest".into();
    let profile = VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).unwrap();
    let request = profile.request(Duration::from_secs(2));
    assert_eq!(request.method, FixedMethod::Get);
    assert_eq!(request.path, "/v1/secret/data/agents/github");
    assert!(request.body.is_empty());
}

#[test]
fn profile_version_has_no_alias_default_or_coercion() {
    let original: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
    for version in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("7"),
        serde_json::json!("LATEST"),
        serde_json::json!("current"),
        serde_json::json!(" latest"),
        serde_json::json!(null),
        serde_json::json!({"latest":true}),
        serde_json::json!([7]),
        serde_json::json!(true),
    ] {
        let mut raw = original.clone();
        raw["version"] = version;
        assert_eq!(
            VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).map(|_| ()),
            Err(VaultKvError::InvalidCredential)
        );
    }
    let mut raw = original;
    raw.as_object_mut().unwrap().remove("version");
    assert!(VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).is_err());
}

fn latest_profile() -> Vec<u8> {
    let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
    raw["version"] = "latest".into();
    serde_json::to_vec(&raw).unwrap()
}

fn resolved_response(version: u64, value: &str) -> UpstreamResponse {
    response(
        serde_json::json!({"data":{"data":{"token":value},"metadata":{"version":version,"deletion_time":"","destroyed":false}}}),
    )
}

#[test]
fn latest_freezes_the_positive_actual_version_and_zeroizing_value() {
    let profile = VaultKvProfile::parse_profile(&latest_profile()).unwrap();
    let first = profile
        .resolve(&resolved_response(17, "first-selected"))
        .unwrap();
    let second = profile
        .resolve(&resolved_response(18, "rotated-selected"))
        .unwrap();
    assert_eq!(first.actual_version, 17);
    assert_eq!(first.value.as_slice(), b"first-selected");
    assert_eq!(second.actual_version, 18);
    assert_eq!(second.value.as_slice(), b"rotated-selected");
    assert!(
        profile
            .audit_reason(Some(first.actual_version))
            .ends_with("selector=latest;actual=17")
    );
}

#[test]
fn latest_rejects_unresolved_or_unavailable_envelopes() {
    let profile = VaultKvProfile::parse_profile(&latest_profile()).unwrap();
    let valid: serde_json::Value =
        serde_json::from_slice(&resolved_response(17, "selected-value").body).unwrap();
    for version in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("17"),
        serde_json::json!(null),
    ] {
        let mut raw = valid.clone();
        raw["data"]["metadata"]["version"] = version;
        assert!(profile.resolve(&response(raw)).is_err());
    }
    let mut missing = valid.clone();
    missing["data"]["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("version");
    assert!(profile.resolve(&response(missing)).is_err());
    for (field, value, error) in [
        (
            "destroyed",
            serde_json::json!(true),
            VaultKvError::SourceUnavailable,
        ),
        (
            "deletion_time",
            serde_json::json!("deleted"),
            VaultKvError::SourceUnavailable,
        ),
        (
            "destroyed",
            serde_json::json!(null),
            VaultKvError::SourceResponse,
        ),
        (
            "deletion_time",
            serde_json::json!(null),
            VaultKvError::SourceResponse,
        ),
    ] {
        let mut raw = valid.clone();
        raw["data"]["metadata"][field] = value;
        assert_eq!(profile.resolve(&response(raw)).map(|_| ()), Err(error));
    }
    for data in [
        serde_json::json!({"other":"selected-value"}),
        serde_json::json!({"token":""}),
        serde_json::json!({"token":{"nested":true}}),
        serde_json::json!({"token":"one","other":"two"}),
    ] {
        let mut raw = valid.clone();
        raw["data"]["data"] = data;
        assert_eq!(
            profile.resolve(&response(raw)).map(|_| ()),
            Err(VaultKvError::SourceResponse)
        );
    }
}

#[test]
fn audit_reference_is_public_only_and_selector_and_actual_are_distinct() {
    let exact = VaultKvProfile::parse_profile(PROFILE).unwrap();
    let latest = VaultKvProfile::parse_profile(&latest_profile()).unwrap();
    let exact_reason = exact.audit_reason(Some(7));
    let latest_reason = latest.audit_reason(Some(17));
    assert_eq!(
        exact_reason.split(';').next(),
        latest_reason.split(';').next()
    );
    assert!(exact_reason.ends_with("selector=exact:7;actual=7"));
    assert!(latest_reason.ends_with("selector=latest;actual=17"));
    assert!(!latest.audit_reason(None).contains("actual="));
    assert!(latest_reason.len() < 160);
    let mut raw: serde_json::Value = serde_json::from_slice(&latest_profile()).unwrap();
    raw["vault_token"] = "different-bootstrap".into();
    let changed_token = VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(changed_token.audit_reason(Some(17)), latest_reason);
    for field in ["origin", "mount", "path", "key"] {
        let mut changed = raw.clone();
        changed[field] = match field {
            "origin" => "https://another.example.com",
            "mount" => "other",
            "path" => "agents/other",
            _ => "other-key",
        }
        .into();
        assert_ne!(
            VaultKvProfile::parse_profile(&serde_json::to_vec(&changed).unwrap())
                .unwrap()
                .audit_reason(Some(17)),
            latest_reason
        );
    }
    for secret in [
        "hvs.source-canary",
        "different-bootstrap",
        "selected-value",
        "vault.example.com",
        "agents/github",
    ] {
        assert!(!latest_reason.contains(secret));
    }
}

struct AuditWitness {
    fake: Arc<crate::testing::FakeUpstreamTransport>,
    db: std::path::PathBuf,
}
impl crate::upstream::UpstreamTransport for AuditWitness {
    fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        Box::pin(async move {
            let db = rusqlite::Connection::open(&self.db).unwrap();
            let event = if request.host == "vault.example.com" {
                "vault.source.read_started"
            } else {
                "vault.source.resolved"
            };
            let expected = self.fake.requests.lock().unwrap().len() / 2 + 1;
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type=?1",
                    [event],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
                expected
            );
            drop(db);
            self.fake.send(request).await
        })
    }
}

#[tokio::test]
async fn actor_latest_single_read_rotation_and_durable_version_association() {
    let mut f = ActorFixture::with_profile(&latest_profile()).await;
    f.authority
        .credential_rotate_typed_before(
            f.action.credential_id,
            rekey_domain::credential::CredentialKind::VaultKvV2Source,
            Some(1),
            rekey_vault::secret::SecretInput::from_slice(&latest_profile()),
            ActorFixture::proof(),
            None,
        )
        .await
        .unwrap();
    f.executor.transport = Arc::new(AuditWitness {
        fake: f.fake.clone(),
        db: f.state.join("vault.sqlite3"),
    });
    for (version, value) in [(17, "first-selected"), (18, "rotated-selected")] {
        f.fake.push_response(Ok(resolved_response(version, value)));
        f.fake.push_response(Ok(UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(b"clean business body".to_vec()),
        }));
    }
    assert_eq!(f.run().await.unwrap().body, b"clean business body");
    assert_eq!(f.run().await.unwrap().body, b"clean business body");
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 4);
    for (index, value) in [
        (0, b"Bearer first-selected".as_slice()),
        (2, b"Bearer rotated-selected".as_slice()),
    ] {
        assert_eq!(sent[index].path, "/v1/secret/data/agents/github");
        assert_eq!(sent[index].method, "GET");
        assert_eq!(sent[index + 1].auth_value, value);
    }
    let db = f.db();
    let mut query = db.prepare("SELECT event_type,request_id,credential_id,credential_version,reason_code FROM audit_events WHERE request_id IS NOT NULL ORDER BY sequence").unwrap();
    let rows: Vec<_> = query
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Option<u64>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows.len(), 8);
    for (execution, version) in rows.chunks_exact(4).zip([17, 18]) {
        assert_eq!(
            execution
                .iter()
                .map(|row| row.0.as_str())
                .collect::<Vec<_>>(),
            [
                "execution.started",
                "vault.source.read_started",
                "vault.source.resolved",
                "execution.finished"
            ]
        );
        for row in execution {
            assert_eq!(row.1, execution[0].1);
            assert_eq!(row.2, f.action.credential_id.as_bytes());
        }
        for row in &execution[1..] {
            assert_eq!(row.3, Some(2));
        }
        assert!(
            execution[2]
                .4
                .ends_with(&format!("selector=latest;actual={version}"))
        );
        assert!(!execution[1].4.contains("actual="));
    }
    drop(query);
    drop(db);
    f.finish().await;
}

#[tokio::test]
async fn actor_latest_real_sqlite_audit_failures_fault_before_source_or_target() {
    for (event, reads) in [
        ("execution.started", 0),
        ("vault.source.read_started", 0),
        ("vault.source.resolved", 1),
    ] {
        let f = ActorFixture::with_profile(&latest_profile()).await;
        f.db().execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        f.fake
            .push_response(Ok(resolved_response(17, "selected-value")));
        assert!(matches!(
            f.run().await,
            Err(BrokerError::Authority(AuthorityError::AuditCommitFailed))
        ));
        assert_eq!(f.fake.take_requests().len(), reads);
        assert_eq!(f.authority.status().await.unwrap().state, "faulted");
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='vault.source.resolved'",
                    [],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
            0
        );
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_latest_seals_source_headers_and_frozen_target_value() {
    let f = ActorFixture::with_profile(&latest_profile()).await;
    for bytes in [
        b"hvs.source-canary".as_slice(),
        b"\xffhvs.source-canary".as_slice(),
    ] {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-unlisted",
            reqwest::header::HeaderValue::from_bytes(bytes).unwrap(),
        );
        let mut source = resolved_response(17, "selected-value");
        source.headers = crate::upstream::ResponseHeaders::from_header_map(&headers);
        f.fake.push_response(Ok(source));
        assert!(matches!(
            f.run().await,
            Err(BrokerError::ResponseSecurityViolation)
        ));
        assert_eq!(f.fake.take_requests().len(), 1);
    }
    for reflected in [
        b"selected-value".as_slice(),
        b"c2VsZWN0ZWQtdmFsdWU=".as_slice(),
        b"Bearer selected-value".as_slice(),
        b"\xffselected-value".as_slice(),
    ] {
        f.fake
            .push_response(Ok(resolved_response(17, "selected-value")));
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-unlisted",
            reqwest::header::HeaderValue::from_bytes(reflected).unwrap(),
        );
        f.fake.push_response(Ok(UpstreamResponse {
            status: 200,
            headers: crate::upstream::ResponseHeaders::from_header_map(&headers),
            body: Zeroizing::new(b"clean".to_vec()),
        }));
        assert!(matches!(
            f.run().await,
            Err(BrokerError::ResponseSecurityViolation)
        ));
        let sent = f.fake.take_requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].auth_value, b"Bearer selected-value");
    }
    f.finish().await;
}

#[tokio::test]
async fn actor_latest_unresolved_versions_have_no_resolved_evidence_or_target() {
    let f = ActorFixture::with_profile(&latest_profile()).await;
    for source in [
        resolved_response(0, "selected-value"),
        response(
            serde_json::json!({"data":{"data":{"token":"selected-value"},"metadata":{"deletion_time":"","destroyed":false}}}),
        ),
        response(
            serde_json::json!({"data":{"data":{"token":"selected-value"},"metadata":{"version":"17","deletion_time":"","destroyed":false}}}),
        ),
        response(
            serde_json::json!({"data":{"data":{"token":"selected-value"},"metadata":{"version":17,"deletion_time":"deleted","destroyed":false}}}),
        ),
        response(
            serde_json::json!({"data":{"data":{"token":"selected-value"},"metadata":{"version":17,"deletion_time":"","destroyed":true}}}),
        ),
    ] {
        f.fake.push_response(Ok(source));
        assert!(matches!(f.run().await, Err(BrokerError::Upstream(_))));
        assert_eq!(f.fake.take_requests().len(), 1);
    }
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='vault.source.resolved'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.blocked'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
        5
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_latest_ready_read_audit_resumed_after_deadline_never_enters_source() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let f = ActorFixture::with_profile(&latest_profile()).await;
    let deadline = Instant::now() + Duration::from_millis(500);
    let (mut started, request) = f.begin(deadline).await.unwrap();
    let credential = f
        .authority
        .prepare_credential(f.action.credential_id)
        .await
        .unwrap();
    let version = credential.version();
    let prepared = credential.consume(|secret| {
        let profile = VaultKvProfile::parse_profile(secret);
        VaultPrepared {
            needles: profile
                .as_ref()
                .map(|p| sealing_needles(secret, p.token()))
                .unwrap_or_default(),
            profile,
            credential_version: version,
        }
    });
    f.fake
        .push_response(Ok(resolved_response(17, "selected-value")));
    let phase = AtomicU8::new(EFFECT_NOT_STARTED);
    let outcome = {
        let mut source = std::pin::pin!(f.executor.resolve_vault_source(
            &mut started,
            &request,
            &f.action,
            prepared,
            deadline,
            &phase
        ));
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(source.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        // The real Authority writes SQLite and the terminal worker delivers the
        // ready reply while this source future is deliberately not polled.
        f.executor
            .terminals
            .wait_idle(Duration::from_millis(250))
            .await
            .unwrap();
        assert_eq!(f.db().query_row("SELECT count(*) FROM audit_events WHERE event_type='vault.source.read_started'",[],|r|r.get::<_,usize>(0)).unwrap(),1);
        assert!(
            Instant::now() < deadline,
            "audit reply must be ready before expiry"
        );
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_millis(5),
        ))
        .await;
        source.await
    };
    let source_count = f.fake.take_requests().len();
    f.executor
        .terminals
        .wait_idle(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        source_count, 0,
        "source phase entered after the ready audit was resumed late"
    );
    assert_eq!(phase.load(Ordering::SeqCst), EFFECT_NOT_STARTED);
    assert!(matches!(
        outcome,
        Err(BrokerError::Upstream("upstream-timeout"))
    ));
    assert_eq!(f.db().query_row("SELECT count(*) FROM audit_events WHERE event_type='execution.blocked' AND reason_code='upstream-timeout'",[],|r|r.get::<_,usize>(0)).unwrap(),1);
    drop(started);
    f.finish().await;
}

#[tokio::test]
async fn actor_latest_source_future_constructed_before_deadline_first_polled_after_never_enters_source()
 {
    let f = ActorFixture::with_profile(&latest_profile()).await;
    let deadline = Instant::now() + Duration::from_millis(500);
    let (mut started, _) = f.begin(deadline).await.unwrap();
    let credential = f
        .authority
        .prepare_credential(f.action.credential_id)
        .await
        .unwrap();
    let version = credential.version();
    let profile = credential.consume(|secret| VaultKvProfile::parse_profile(secret).unwrap());
    let mut draft = connector_event(
        started.context(),
        rekey_vault::model::event_type::VAULT_SOURCE_READ_STARTED,
        "success",
        profile.audit_reason(None),
    );
    draft.credential_version = Some(version);
    f.executor
        .terminals
        .commit_until(deadline, draft)
        .await
        .unwrap();
    f.fake
        .push_response(Ok(resolved_response(17, "selected-value")));
    let phase = AtomicU8::new(EFFECT_NOT_STARTED);
    let outcome = {
        let source =
            f.executor
                .read_vault_source(&mut started, &profile, deadline, &phase, version);
        assert!(
            Instant::now() < deadline,
            "future must be constructed before expiry"
        );
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_millis(5),
        ))
        .await;
        source.await
    };
    let source_count = f.fake.take_requests().len();
    f.executor
        .terminals
        .wait_idle(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        source_count, 0,
        "source future entered transport on its late first poll"
    );
    assert_eq!(phase.load(Ordering::SeqCst), EFFECT_NOT_STARTED);
    assert!(matches!(
        outcome,
        Err(BrokerError::Upstream("upstream-timeout"))
    ));
    assert_eq!(f.db().query_row("SELECT count(*) FROM audit_events WHERE event_type='execution.blocked' AND reason_code='upstream-timeout'",[],|r|r.get::<_,usize>(0)).unwrap(),1);
    drop(started);
    f.finish().await;
}

fn private_profile(dynamic: bool, ip: &str) -> Vec<u8> {
    let cert = rcgen::generate_simple_self_signed(vec!["vault.example.com".into()])
        .unwrap()
        .cert;
    let endpoint = serde_json::json!({"allowed_ips":[ip],"ca_der_base64":[data_encoding::BASE64.encode(cert.der())]});
    let mut raw = if dynamic {
        serde_json::json!({"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"agent-token","key":"token","renew_increment_seconds":60,"vault_token":"hvs.source-canary"})
    } else {
        serde_json::from_slice(PROFILE).unwrap()
    };
    raw["source_endpoint"] = endpoint;
    serde_json::to_vec(&raw).unwrap()
}

#[test]
fn private_profiles_are_closed_and_binding_is_optional_but_never_null() {
    for dynamic in [false, true] {
        let original: serde_json::Value =
            serde_json::from_slice(&private_profile(dynamic, "10.1.2.3")).unwrap();
        let validate = |raw: &serde_json::Value| {
            let bytes = serde_json::to_vec(raw).unwrap();
            if dynamic {
                super::super::vault_dynamic::VaultDynamicProfile::validate_profile(&bytes).is_ok()
            } else {
                VaultKvProfile::validate_profile(&bytes).is_ok()
            }
        };
        assert!(validate(&original));
        for endpoint in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!({"allowed_ips":[],"ca_der_base64":original["source_endpoint"]["ca_der_base64"]}),
            serde_json::json!({"allowed_ips":["10.1.2.3"],"ca_der_base64":[]}),
            serde_json::json!({"allowed_ips":["10.1.2.3","10.1.2.3"],"ca_der_base64":original["source_endpoint"]["ca_der_base64"]}),
            serde_json::json!({"allowed_ips":["10.1.2.3"],"ca_der_base64":["AA=="]}),
            serde_json::json!({"allowed_ips":["10.1.2.3"],"ca_der_base64":[original["source_endpoint"]["ca_der_base64"][0],original["source_endpoint"]["ca_der_base64"][0]]}),
        ] {
            let mut raw = original.clone();
            raw["source_endpoint"] = endpoint;
            assert!(!validate(&raw));
        }
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "192.0.2.1",
            "224.0.0.1",
            "8.8.8.8",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.1.2.3",
            "64:ff9b::a01:203",
            "2002:a01:203::1",
            "10.1.2.0/24",
            "vault.local",
            "*",
        ] {
            let mut raw = original.clone();
            raw["source_endpoint"]["allowed_ips"] = serde_json::json!([ip]);
            assert!(!validate(&raw), "{ip}");
        }
        for origin in [
            "https://10.1.2.3",
            "https://[fd00::1]",
            "https://bad_host.example",
        ] {
            let mut raw = original.clone();
            raw["origin"] = origin.into();
            assert!(!validate(&raw));
        }
        let mut raw = original.clone();
        raw["source_endpoint"]["unknown"] = true.into();
        assert!(!validate(&raw));
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.2",
            "fd12:3456::1",
            "fc00::1",
        ] {
            let mut raw = original.clone();
            raw["source_endpoint"]["allowed_ips"] = serde_json::json!([ip]);
            assert!(validate(&raw));
        }
        let encoded = serde_json::to_string(&original).unwrap();
        for field in ["allowed_ips", "ca_der_base64", "source_endpoint"] {
            let duplicate = encoded.replacen(
                &format!("\"{field}\":"),
                &format!("\"{field}\":null,\"{field}\":"),
                1,
            );
            let bytes = duplicate.as_bytes();
            assert!(if dynamic {
                super::super::vault_dynamic::VaultDynamicProfile::validate_profile(bytes).is_err()
            } else {
                VaultKvProfile::validate_profile(bytes).is_err()
            });
        }
        raw.as_object_mut().unwrap().remove("source_endpoint");
        assert!(validate(&raw));
    }
}

struct PrivateActorTransport {
    fake: Arc<crate::testing::FakeUpstreamTransport>,
    ip: std::net::IpAddr,
    bound: Arc<std::sync::Mutex<Vec<String>>>,
    stall: Option<bool>,
}
impl crate::upstream::UpstreamTransport for PrivateActorTransport {
    fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        assert_eq!(
            request.host, "api.example.com",
            "source called ordinary transport"
        );
        self.fake.send(request)
    }
    fn send_vault_source<'a>(
        &'a self,
        request: UpstreamRequest,
        binding: &'a SourceEndpoint,
        deadline: Instant,
        trace: crate::upstream::SourceTrace,
    ) -> crate::upstream::UpstreamFuture<'a> {
        Box::pin(async move {
            assert!(Instant::now() < deadline);
            assert_eq!(request.host, "vault.example.com");
            if self.stall == Some(false) {
                return std::future::pending().await;
            }
            let selected = crate::upstream::select_source_endpoint(
                &request.host,
                request.port,
                &[std::net::SocketAddr::new(self.ip, request.port)],
                binding,
            )?;
            *trace.lock().unwrap() = crate::upstream::SourceAttempt {
                selected_ip: Some(selected.addr.ip()),
                phase: "response",
                outcome: "success",
            };
            self.bound.lock().unwrap().push(request.path.clone());
            if self.stall == Some(true) {
                {
                    let mut attempt = trace.lock().unwrap();
                    attempt.phase = "connect";
                    attempt.outcome = "unknown";
                }
                return std::future::pending().await;
            }
            self.fake.send(request).await
        })
    }
}
fn install_private_transport(f: &mut ActorFixture, ip: &str) -> Arc<std::sync::Mutex<Vec<String>>> {
    let bound = Arc::new(std::sync::Mutex::new(Vec::new()));
    f.executor.transport = Arc::new(PrivateActorTransport {
        fake: f.fake.clone(),
        ip: ip.parse().unwrap(),
        bound: bound.clone(),
        stall: None,
    });
    bound
}
fn private_issued() -> UpstreamResponse {
    response(
        serde_json::json!({"lease_id":"database/creds/agent-token/known-id","lease_duration":60,"renewable":true,"data":{"token":"private-selected"}}),
    )
}

#[tokio::test]
async fn actor_private_kv_routes_only_source_and_commits_actual_version_ip_phase() {
    let mut f = ActorFixture::with_profile(&private_profile(false, "10.1.2.3")).await;
    let bound = install_private_transport(&mut f, "10.1.2.3");
    f.fake
        .push_response(Ok(resolved_response(7, "private-selected")));
    f.fake
        .push_response(Ok(response(serde_json::json!({"ok":true}))));
    assert!(f.run().await.is_ok());
    assert_eq!(bound.lock().unwrap().len(), 1);
    assert_eq!(f.fake.take_requests().len(), 2);
    let row: (Vec<u8>, u64, String, String) = f.db().query_row("SELECT credential_id,credential_version,outcome,reason_code FROM audit_events WHERE event_type='vault.source.endpoint'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(row.0, f.action.credential_id.as_bytes());
    assert_eq!(row.1, 1);
    assert_eq!(row.2, "success");
    assert_eq!(row.3, "operation=read;phase=response;selected_ip=10.1.2.3");
    f.finish().await;
}

#[tokio::test]
async fn actor_private_kv_endpoint_audit_failure_denies_target_and_unsupported_never_falls_back() {
    for supported in [false, true] {
        let mut f = ActorFixture::with_profile(&private_profile(false, "10.1.2.3")).await;
        if supported {
            install_private_transport(&mut f, "10.1.2.3");
            f.db().execute_batch("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.source.endpoint' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        }
        f.fake
            .push_response(Ok(resolved_response(7, "private-selected")));
        let error = f.run().await.err().unwrap();
        if supported {
            assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
            assert!(!error.retryable());
            assert_eq!(f.authority.status().await.unwrap().state, "faulted");
        } else {
            assert_eq!(error.code(), "UPSTREAM_FAILED");
            assert!(error.retryable());
            assert_eq!(f.authority.status().await.unwrap().state, "unlocked");
        }
        assert_eq!(f.fake.take_requests().len(), usize::from(supported));
        if !supported {
            let reason: String = f
                .db()
                .query_row(
                    "SELECT reason_code FROM audit_events WHERE event_type='vault.source.endpoint'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(reason.contains("phase=unsupported"));
            assert!(!reason.contains("selected_ip="));
        }
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_private_dynamic_acquire_target_revoke_and_audit_failure_keep_unknown_cleanup() {
    for audit_failure in [false, true] {
        let mut f = ActorFixture::with_kind(
            &private_profile(true, "10.1.2.3"),
            rekey_domain::credential::CredentialKind::VaultDynamicSource,
        )
        .await;
        let bound = install_private_transport(&mut f, "10.1.2.3");
        if audit_failure {
            f.db().execute_batch("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.source.endpoint' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        }
        f.fake.push_response(Ok(private_issued()));
        if !audit_failure {
            f.fake
                .push_response(Ok(response(serde_json::json!({"ok":true}))));
        }
        f.fake.push_response(Ok(UpstreamResponse {
            status: 204,
            headers: vec![].into(),
            body: Zeroizing::new(vec![]),
        }));
        let result = f.run().await;
        assert_eq!(result.is_err(), audit_failure);
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), if audit_failure { 2 } else { 3 });
        assert!(
            requests
                .last()
                .unwrap()
                .body
                .windows(b"known-id".len())
                .any(|w| w == b"known-id")
        );
        assert_eq!(bound.lock().unwrap().len(), 2);
        if audit_failure {
            let counts = f.authority.lease_recovery_batch().await.unwrap().counts;
            assert_eq!(counts.unknown, 1);
        } else {
            let db = f.db();
            let mut query=db.prepare("SELECT credential_id,credential_version,reason_code FROM audit_events WHERE event_type='vault.source.endpoint' ORDER BY sequence").unwrap();
            let rows: Vec<(Vec<u8>, u64, String)> = query
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(rows.len(), 2);
            for row in &rows {
                assert_eq!(row.0, f.action.credential_id.as_bytes());
                assert_eq!(row.1, 1);
                assert!(row.2.contains("registration="));
                assert!(row.2.contains("selected_ip=10.1.2.3"));
            }
            assert!(rows[0].2.contains("operation=acquire"));
            assert!(rows[1].2.contains("operation=revoke"));
        }
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_private_dynamic_recovery_uses_historical_binding_and_receipt_version() {
    for old_binding_available in [true, false] {
        let mut f = ActorFixture::with_kind(
            &private_profile(true, "10.1.2.3"),
            rekey_domain::credential::CredentialKind::VaultDynamicSource,
        )
        .await;
        let profile = super::super::vault_dynamic::VaultDynamicProfile::parse_profile(
            &private_profile(true, "10.1.2.3"),
        )
        .unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        let (mut started, _) = f.begin(end).await.unwrap();
        let actual = started.context();
        let ctx = rekey_vault::model::LeaseExecutionContext {
            request_id: actual.request_id,
            session_id: actual.session_id,
            action_id: f.action.id,
            action_version: 1,
            credential_id: f.action.credential_id,
            credential_version: 1,
        };
        let receipt = f
            .authority
            .lease_acquire_begin(ctx, profile.source_ref(), None)
            .await
            .unwrap();
        f.authority
            .lease_record_issued(
                receipt.registration_id,
                rekey_vault::secret::SecretInput::from_slice(
                    b"database/creds/agent-token/known-id",
                ),
                crate::now_ts().unwrap().as_unix_ms(),
                60,
                true,
                None,
            )
            .await
            .unwrap();
        f.authority
            .credential_rotate_typed_before(
                f.action.credential_id,
                rekey_domain::credential::CredentialKind::VaultDynamicSource,
                Some(1),
                rekey_vault::secret::SecretInput::from_slice(&private_profile(true, "10.9.8.7")),
                ActorFixture::proof(),
                None,
            )
            .await
            .unwrap();
        install_private_transport(
            &mut f,
            if old_binding_available {
                "10.1.2.3"
            } else {
                "10.9.8.7"
            },
        );
        f.fake.push_response(Ok(UpstreamResponse {
            status: 204,
            headers: vec![].into(),
            body: Zeroizing::new(vec![]),
        }));
        let recovered = f.executor.recover_vault_leases(true).await.unwrap();
        assert_eq!(recovered.leases.len(), 1);
        assert_eq!(
            recovered.leases[0].outcome,
            if old_binding_available {
                rekey_domain::ipc::LeaseRecoveryOutcome::Complete
            } else {
                rekey_domain::ipc::LeaseRecoveryOutcome::Unconfirmed
            }
        );
        let row:(u64,String)=f.db().query_row("SELECT credential_version,reason_code FROM audit_events WHERE event_type='vault.source.endpoint'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(row.0, 1);
        assert!(
            row.1
                .contains(&format!("registration={}", receipt.registration_id))
        );
        assert_eq!(
            row.1.contains("selected_ip=10.1.2.3"),
            old_binding_available
        );
        assert!(!row.1.contains("selected_ip=10.9.8.7"));
        assert_eq!(
            f.fake.take_requests().len(),
            usize::from(old_binding_available)
        );
        if !old_binding_available {
            assert_eq!(
                f.authority
                    .lease_recovery_batch()
                    .await
                    .unwrap()
                    .counts
                    .pending,
                1
            );
        }
        started
            .blocked_until(end, "fixture-complete")
            .await
            .unwrap();
        drop(started);
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_private_dynamic_renew_revoke_result_audit_failures_hide_business_success() {
    for stage in ["none", "renew", "revoke"] {
        let mut f = ActorFixture::with_kind(
            &private_profile(true, "10.1.2.3"),
            rekey_domain::credential::CredentialKind::VaultDynamicSource,
        )
        .await;
        install_private_transport(&mut f, "10.1.2.3");
        if stage != "none" {
            f.db().execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.source.endpoint' AND NEW.reason_code LIKE '%operation={stage};%' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        }
        f.fake.push_response(Ok(response(serde_json::json!({"lease_id":"database/creds/agent-token/known-id","lease_duration":5,"renewable":true,"data":{"token":"private-selected"}}))));
        f.fake.push_response(Ok(response(serde_json::json!({"lease_id":"database/creds/agent-token/known-id","lease_duration":60,"renewable":true}))));
        if stage != "renew" {
            f.fake
                .push_response(Ok(response(serde_json::json!({"ok":true}))));
        }
        f.fake.push_response(Ok(UpstreamResponse {
            status: 204,
            headers: vec![].into(),
            body: Zeroizing::new(vec![]),
        }));
        assert_eq!(f.run().await.is_err(), stage != "none");
        let requests = f.fake.take_requests();
        assert_eq!(requests.len(), if stage == "renew" { 3 } else { 4 });
        assert_eq!(requests[1].path, "/v1/sys/leases/renew");
        assert_eq!(requests.last().unwrap().path, "/v1/sys/leases/revoke");
        if stage == "none" {
            let reason:String=f.db().query_row("SELECT reason_code FROM audit_events WHERE event_type='vault.source.endpoint' AND reason_code LIKE '%operation=renew;%'",[],|r|r.get(0)).unwrap();
            assert!(reason.contains("selected_ip=10.1.2.3"));
        } else {
            assert_eq!(f.authority.status().await.unwrap().state, "faulted");
        }
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_private_timeout_keeps_real_selected_phase_and_never_fabricates_success() {
    for selected in [false, true] {
        let mut f = ActorFixture::with_profile(&private_profile(false, "10.1.2.3")).await;
        f.action.timeout_ms = 50;
        f.executor.transport = Arc::new(PrivateActorTransport {
            fake: f.fake.clone(),
            ip: "10.1.2.3".parse().unwrap(),
            bound: Arc::new(std::sync::Mutex::new(vec![])),
            stall: Some(selected),
        });
        assert!(f.run().await.is_err());
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(1))
            .await
            .unwrap();
        let row:(String,String)=f.db().query_row("SELECT outcome,reason_code FROM audit_events WHERE event_type='vault.source.endpoint'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(row.0, "unknown");
        assert_eq!(row.1.contains("selected_ip=10.1.2.3"), selected);
        assert!(row.1.contains(if selected {
            "phase=connect"
        } else {
            "phase=resolve"
        }));
        assert!(f.fake.take_requests().is_empty());
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_private_acquire_result_audit_timeout_retains_exact_id_for_cleanup() {
    let mut f = ActorFixture::with_kind(
        &private_profile(true, "10.1.2.3"),
        rekey_domain::credential::CredentialKind::VaultDynamicSource,
    )
    .await;
    f.action.timeout_ms = 2_000;
    install_private_transport(&mut f, "10.1.2.3");
    let authority = f.authority.clone();
    let (terminals, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
        let authority = authority.clone();
        async move {
            if draft.event_type == "vault.source.endpoint"
                && draft.reason_code.contains("operation=acquire;")
            {
                tokio::time::sleep(Duration::from_millis(1_700)).await;
            }
            authority.commit_audit(draft).await
        }
    });
    f.executor.terminals = terminals;
    let old = std::mem::replace(&mut f.terminal_worker, worker);
    old.await.unwrap();
    f.fake.push_response(Ok(private_issued()));
    f.fake.push_response(Ok(UpstreamResponse {
        status: 204,
        headers: vec![].into(),
        body: Zeroizing::new(vec![]),
    }));
    let error = f.run().await.err().unwrap();
    assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
    assert!(!error.retryable());
    f.executor
        .terminals
        .wait_idle(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(f.authority.status().await.unwrap().state, "unlocked");
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].path, "/v1/sys/leases/revoke");
    assert!(
        requests[1]
            .body
            .windows(b"known-id".len())
            .any(|w| w == b"known-id")
    );
    assert_eq!(
        f.authority
            .lease_recovery_batch()
            .await
            .unwrap()
            .counts
            .unknown,
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_private_review_delayed_endpoint_ack_is_retryable_deadline_and_healthy() {
    let mut f = ActorFixture::with_profile(&private_profile(false, "10.1.2.3")).await;
    f.action.timeout_ms = 50;
    install_private_transport(&mut f, "10.1.2.3");
    let authority = f.authority.clone();
    let (terminals, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
        let authority = authority.clone();
        async move {
            if draft.event_type == "vault.source.endpoint" {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            authority.commit_audit(draft).await
        }
    });
    f.executor.terminals = terminals;
    let old = std::mem::replace(&mut f.terminal_worker, worker);
    old.await.unwrap();
    f.fake
        .push_response(Ok(resolved_response(7, "private-selected")));
    let error = f.run().await.err().unwrap();
    assert_eq!(error.code(), "UPSTREAM_FAILED");
    assert!(error.retryable());
    f.executor
        .terminals
        .wait_idle(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(f.authority.status().await.unwrap().state, "unlocked");
    assert_eq!(f.fake.take_requests().len(), 1);
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='vault.source.endpoint'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_private_review_ready_success_ack_polled_late_is_retryable_deadline_and_healthy() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let mut f = ActorFixture::with_profile(&private_profile(false, "10.1.2.3")).await;
    install_private_transport(&mut f, "10.1.2.3");
    let end = Instant::now() + Duration::from_millis(200);
    let (mut started, _) = f.begin(end).await.unwrap();
    let credential = f
        .authority
        .prepare_credential(f.action.credential_id)
        .await
        .unwrap();
    let version = credential.version();
    let profile = credential.consume(|secret| VaultKvProfile::parse_profile(secret).unwrap());
    f.fake
        .push_response(Ok(resolved_response(7, "private-selected")));
    let phase = AtomicU8::new(EFFECT_NOT_STARTED);
    let error = {
        let mut source = std::pin::pin!(f.executor.read_vault_source(
            &mut started,
            &profile,
            end,
            &phase,
            version
        ));
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(source.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        f.executor
            .terminals
            .wait_idle(Duration::from_millis(100))
            .await
            .unwrap();
        assert!(Instant::now() < end);
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='vault.source.endpoint'",
                    [],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
            1
        );
        tokio::time::sleep_until((end + Duration::from_millis(5)).into()).await;
        source.await.err().unwrap()
    };
    assert_eq!(error.code(), "UPSTREAM_FAILED");
    assert!(error.retryable());
    assert_eq!(f.authority.status().await.unwrap().state, "unlocked");
    assert_eq!(f.fake.take_requests().len(), 1);
    drop(started);
    f.finish().await;
}

fn approle_profile() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "credential_type":"vault-approle-kv-v2-source-v1",
        "origin":"https://vault.example.com", "auth_mount":"approle",
        "role_id":"role-fixture-canary", "secret_id":"secret-fixture-canary",
        "secret_id_expires_at_ms":crate::now_ts().unwrap().as_unix_ms()+60_000,
        "mount":"secret", "path":"agents/github", "key":"token", "version":7
    }))
    .unwrap()
}
fn login_response() -> UpstreamResponse {
    response(
        serde_json::json!({"auth":{"client_token":"hvs.login-fixture-canary","token_type":"service","lease_duration":60}}),
    )
}
fn revoke_response() -> UpstreamResponse {
    UpstreamResponse {
        status: 204,
        headers: vec![].into(),
        body: Zeroizing::new(vec![]),
    }
}

#[tokio::test]
async fn actor_approle_one_login_read_business_revoke_and_safe_audit() {
    let f = ActorFixture::with_profile(&approle_profile()).await;
    f.fake.push_response(Ok(login_response()));
    f.fake
        .push_response(Ok(resolved_response(7, "approle-selected")));
    f.fake
        .push_response(Ok(response(serde_json::json!({"ok":true}))));
    f.fake.push_response(Ok(revoke_response()));
    let outcome = f.run().await.unwrap();
    assert_eq!(outcome.body, br#"{"ok":true}"#);
    let sent = f.fake.take_requests();
    assert_eq!(
        sent.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        [
            "/v1/auth/approle/login",
            "/v1/secret/data/agents/github?version=7",
            "/business",
            "/v1/auth/token/revoke-self"
        ]
    );
    assert_eq!(sent[0].auth_name, "accept");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent[0].body).unwrap(),
        serde_json::json!({"role_id":"role-fixture-canary","secret_id":"secret-fixture-canary"})
    );
    assert_eq!(sent[1].auth_value, b"hvs.login-fixture-canary");
    assert_eq!(sent[2].auth_value, b"Bearer approle-selected");
    assert_eq!(sent[3].auth_value, b"hvs.login-fixture-canary");
    let db = f.db();
    let mut q = db
        .prepare("SELECT event_type,reason_code FROM audit_events ORDER BY sequence")
        .unwrap();
    let rows = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    let events = rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .position(|s| *s == "execution.started")
            .unwrap()
            < events
                .iter()
                .position(|s| *s == "vault.approle.login.started")
                .unwrap()
    );
    assert!(
        events
            .iter()
            .position(|s| *s == "vault.approle.cleanup.confirmed")
            .unwrap()
            < events
                .iter()
                .position(|s| *s == "execution.finished")
                .unwrap()
    );
    for (_, reason) in rows {
        for secret in [
            "role-fixture-canary",
            "secret-fixture-canary",
            "hvs.login-fixture-canary",
        ] {
            assert!(!reason.contains(secret));
        }
    }
    drop(q);
    f.finish().await;
}

#[test]
fn approle_profile_is_closed_expiry_bound_and_fixed_login() {
    let original: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
    let parsed = VaultKvProfile::parse_profile(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert!(parsed.is_approle());
    for (field, value) in [
        ("vault_token", serde_json::json!("mixed")),
        ("auth_mount", serde_json::json!("a/b")),
        ("role_id", serde_json::Value::Null),
        ("role_id", serde_json::json!("bad role")),
        ("secret_id", serde_json::json!("")),
        ("secret_id_expires_at_ms", serde_json::json!(0)),
        ("unknown", serde_json::json!(true)),
        ("version", serde_json::json!(0)),
        ("source_endpoint", serde_json::Value::Null),
    ] {
        let mut value_profile = original.clone();
        value_profile[field] = value;
        assert!(
            VaultKvProfile::parse_profile(&serde_json::to_vec(&value_profile).unwrap()).is_err(),
            "field {field}"
        );
    }
    for field in [
        "role_id",
        "secret_id",
        "auth_mount",
        "secret_id_expires_at_ms",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(VaultKvProfile::parse_profile(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let duplicate = String::from_utf8(approle_profile()).unwrap().replacen(
        "{",
        "{\"role_id\":\"duplicate\",",
        1,
    );
    assert!(VaultKvProfile::parse_profile(duplicate.as_bytes()).is_err());
}

#[test]
fn approle_complete_structured_candidates_precede_strict_schema_and_checked_ttl() {
    let needles = sealing_needles(b"secret-fixture-canary", b"secret-fixture-canary");
    let start = Instant::now();
    let end = start + Duration::from_secs(30);
    for (ttl, kind) in [
        (0, "service"),
        (1, "service"),
        (u64::MAX, "service"),
        (60, "batch"),
    ] {
        let value = response(
            serde_json::json!({"auth":{"client_token":"known-token","lease_duration":ttl,"token_type":kind}}),
        );
        let probe = login_probe(&value.body, &needles);
        assert_eq!(probe.tokens[0].as_str(), "known-token");
        assert!(login_expiry(&value, &probe, start, end, &needles).is_err());
    }
    for body in [
        br#"{"auth":{"client_token":"token-one","client_token":"token-two","lease_duration":60,"token_type":"service"}}"#.as_slice(),
        br#"{"auth":{"client_token":"token-one"},"auth":{"client_token":"token-two"}}"#.as_slice(),
        br#"{"auth":{"client_token":"token-one","broken":!}}"#.as_slice(),
    ] {
        let probe=login_probe(body,&needles);
        assert_eq!(probe.tokens[0].as_str(),"token-one");
        let value=UpstreamResponse { status:200,headers:vec![].into(),body:Zeroizing::new(body.to_vec()) };
        assert!(login_expiry(&value,&probe,start,end,&needles).is_err());
    }
    let escaped =
        br#"{"auth":{"client_token":"tok\u0065n-one","lease_duration":60,"token_type":"service"}}"#;
    assert_eq!(
        login_probe(escaped, &needles).tokens[0].as_str(),
        "token-one"
    );
    assert!(
        login_probe(br#"{"debug":{"client_token":"false-token"}}"#, &needles)
            .tokens
            .is_empty()
    );
    assert!(
        login_probe(br#"{"auth":{"client_token":"x\nbad"}}"#, &needles)
            .tokens
            .is_empty()
    );
    assert!(decoded_reflection(
        br#"{"debug":"secret-fixture-can\u0061ry"}"#,
        &needles
    ));
}

#[tokio::test]
async fn actor_approle_invalid_login_cleans_all_exact_candidates_and_never_reads() {
    for body in [
        br#"{"auth":{"client_token":"token-one","client_token":"token-two","lease_duration":60,"token_type":"service"}}"#.as_slice(),
        br#"{"auth":{"client_token":"token-one","broken":!}}"#.as_slice(),
        br#"{"auth":{"client_token":"token-one","lease_duration":0,"token_type":"service"}}"#.as_slice(),
        br#"{"auth":{"client_token":"token-one","lease_duration":60,"token_type":"batch"}}"#.as_slice(),
        br#"{"auth":{"client_token":"token-one","token_type":"service"}}"#.as_slice(),
    ] {
        let f=ActorFixture::with_profile(&approle_profile()).await;
        f.fake.push_response(Ok(UpstreamResponse { status:200,headers:vec![].into(),body:Zeroizing::new(body.to_vec()) }));
        f.fake.push_response(Ok(revoke_response()));f.fake.push_response(Ok(revoke_response()));
        let error=f.run().await.err().unwrap();assert!(!error.retryable());
        let sent=f.fake.take_requests();assert_eq!(sent[0].path,"/v1/auth/approle/login");
        assert_eq!(sent[1].path,"/v1/auth/token/revoke-self");assert_eq!(sent[1].auth_value,b"token-one");
        let duplicate=body.windows(b"token-two".len()).any(|w|w==b"token-two");
        assert_eq!(sent.len(),if duplicate {3}else{2});
        if duplicate {assert_eq!(sent[2].auth_value,b"token-two");}
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_login_unknown_never_retries_or_invents_expiry() {
    for failure in [
        crate::upstream::UpstreamError::Timeout,
        crate::upstream::UpstreamError::Transport,
        crate::upstream::UpstreamError::ResponseTooLarge,
    ] {
        let f = ActorFixture::with_profile(&approle_profile()).await;
        f.fake.push_response(Err(failure));
        let error = f.run().await.err().unwrap();
        assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
        assert!(!error.retryable());
        assert_eq!(f.fake.take_requests().len(), 1);
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(1))
            .await
            .unwrap();
        let reason:String=f.db().query_row("SELECT reason_code FROM audit_events WHERE event_type='vault.approle.login.result'",[],|r|r.get(0)).unwrap();
        assert!(!reason.contains("ttl_seconds="));
        assert!(!reason.contains("remaining_ms="));
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_reflections_at_login_source_business_and_cleanup_are_sealed() {
    for stage in ["login", "source", "business", "cleanup"] {
        let f = ActorFixture::with_profile(&approle_profile()).await;
        let mut login = login_response();
        if stage == "login" {
            login.body=Zeroizing::new(br#"{"auth":{"client_token":"hvs.login-fixture-canary","token_type":"service","lease_duration":60},"debug":"secret-fixture-can\u0061ry"}"#.to_vec());
        }
        f.fake.push_response(Ok(login));
        if stage != "login" {
            let mut source = resolved_response(7, "approle-selected");
            if stage == "source" {
                source.headers = vec![("x-debug".into(), "hvs.login-fixture-canary".into())].into();
            }
            f.fake.push_response(Ok(source));
            if stage != "source" {
                f.fake.push_response(Ok(if stage == "business" {
                    UpstreamResponse {
                        status: 200,
                        headers: vec![].into(),
                        body: Zeroizing::new(br#"{"debug":"role-fixture-can\u0061ry"}"#.to_vec()),
                    }
                } else {
                    response(serde_json::json!({"ok":true}))
                }));
            }
        }
        let mut revoke = revoke_response();
        if stage == "cleanup" {
            revoke.headers = vec![("x-debug".into(), "hvs.login-fixture-canary".into())].into();
        }
        f.fake.push_response(Ok(revoke));
        let error = f.run().await.err().unwrap();
        assert!(!error.retryable());
        assert_eq!(
            error.code(),
            if stage == "cleanup" {
                "UPSTREAM_INDETERMINATE"
            } else {
                "RESPONSE_SECURITY_VIOLATION"
            }
        );
        let sent = f.fake.take_requests();
        assert_eq!(sent.last().unwrap().path, "/v1/auth/token/revoke-self");
        assert_eq!(
            sent.len(),
            match stage {
                "login" => 2,
                "source" => 3,
                _ => 4,
            }
        );
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_cleanup_failure_never_releases_business_success() {
    for failure in [
        Err(crate::upstream::UpstreamError::Timeout),
        Err(crate::upstream::UpstreamError::Transport),
        Ok(UpstreamResponse {
            status: 403,
            headers: vec![].into(),
            body: Zeroizing::new(vec![]),
        }),
        Ok(response(serde_json::json!({}))),
        Ok(UpstreamResponse {
            status: 201,
            headers: vec![].into(),
            body: Zeroizing::new(vec![]),
        }),
    ] {
        let f = ActorFixture::with_profile(&approle_profile()).await;
        f.fake.push_response(Ok(login_response()));
        f.fake
            .push_response(Ok(resolved_response(7, "approle-selected")));
        f.fake
            .push_response(Ok(response(serde_json::json!({"ok":true}))));
        f.fake.push_response(failure);
        let error = f.run().await.err().unwrap();
        assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
        assert!(!error.retryable());
        assert_eq!(f.fake.take_requests().len(), 4);
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='execution.finished'",
                    [],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
            0
        );
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_audit_faults_preserve_typed_error_and_exact_cleanup() {
    for stage in [
        "vault.approle.login.started",
        "vault.approle.login.result",
        "vault.source.read_started",
        "vault.source.resolved",
        "vault.approle.cleanup.started",
        "vault.approle.cleanup.confirmed",
        "execution.finished",
    ] {
        let f = ActorFixture::with_profile(&approle_profile()).await;
        f.db().execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='{stage}' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        f.fake.push_response(Ok(login_response()));
        if !matches!(
            stage,
            "vault.approle.login.started"
                | "vault.approle.login.result"
                | "vault.source.read_started"
        ) {
            f.fake
                .push_response(Ok(resolved_response(7, "approle-selected")));
        }
        if matches!(
            stage,
            "vault.approle.cleanup.started"
                | "vault.approle.cleanup.confirmed"
                | "execution.finished"
        ) {
            f.fake
                .push_response(Ok(response(serde_json::json!({"ok":true}))));
        }
        f.fake.push_response(Ok(revoke_response()));
        let error = f.run().await.err().unwrap();
        assert_eq!(
            error.code(),
            if stage == "execution.finished" {
                "AUDIT_COMMIT_FAILED_AFTER_EXECUTION"
            } else {
                "AUDIT_COMMIT_FAILED"
            },
            "stage {stage}"
        );
        assert!(!error.retryable());
        assert_eq!(f.authority.status().await.unwrap().state, "faulted");
        let sent = f.fake.take_requests();
        if stage == "vault.approle.login.started" {
            assert!(sent.is_empty());
        } else {
            assert_eq!(sent.last().unwrap().path, "/v1/auth/token/revoke-self");
        }
        f.finish().await;
    }
}

struct AppRoleSignals {
    fake: Arc<crate::testing::FakeUpstreamTransport>,
    login: Arc<tokio::sync::Notify>,
    business: Arc<tokio::sync::Notify>,
    cleanup: Arc<tokio::sync::Notify>,
}
impl UpstreamTransport for AppRoleSignals {
    fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        Box::pin(async move {
            match request.path.as_str() {
                "/v1/auth/approle/login" => self.login.notify_one(),
                "/business" => self.business.notify_one(),
                "/v1/auth/token/revoke-self" => self.cleanup.notify_one(),
                _ => {}
            }
            self.fake.send(request).await
        })
    }
}
fn install_approle_signals(
    f: &mut ActorFixture,
) -> (
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
) {
    let login = Arc::new(tokio::sync::Notify::new());
    let business = Arc::new(tokio::sync::Notify::new());
    let cleanup = Arc::new(tokio::sync::Notify::new());
    f.executor.transport = Arc::new(AppRoleSignals {
        fake: f.fake.clone(),
        login: login.clone(),
        business: business.clone(),
        cleanup: cleanup.clone(),
    });
    (login, business, cleanup)
}

#[tokio::test]
async fn actor_approle_cancel_pending_login_retains_identity_and_cleans_before_return() {
    let mut f = ActorFixture::with_profile(&approle_profile()).await;
    let (login, _, cleanup) = install_approle_signals(&mut f);
    let release = f.fake.push_response_gated(Ok(login_response()));
    f.fake.push_response(Ok(revoke_response()));
    let lifecycle = f.executor.lifecycle.clone();
    let (result, ()) = tokio::join!(approle_admitted(&f).await.run(), async {
        login.notified().await;
        lifecycle.signal_cancel();
        release.notify_one();
        cleanup.notified().await;
    });
    let error = result.err().unwrap();
    assert_eq!(error.code(), "DRAINING", "{error:?}");
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].auth_value, b"hvs.login-fixture-canary");
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_cancel_business_keeps_ordinary_effect_and_cleanup_ownership() {
    for cleanup_ok in [true, false] {
        let mut f = ActorFixture::with_profile(&approle_profile()).await;
        let (_, business, _) = install_approle_signals(&mut f);
        f.fake.push_response(Ok(login_response()));
        f.fake
            .push_response(Ok(resolved_response(7, "approle-selected")));
        let _never_release = f
            .fake
            .push_response_gated(Ok(response(serde_json::json!({"ok":true}))));
        f.fake.push_response(if cleanup_ok {
            Ok(revoke_response())
        } else {
            Err(crate::upstream::UpstreamError::Transport)
        });
        let end = Instant::now() + Duration::from_secs(2);
        let (mut started, request) = f.begin(end).await.unwrap();
        let effect = AtomicU8::new(EFFECT_NOT_STARTED);
        let cleanup_owned = AtomicBool::new(false);
        let lifecycle = f.executor.lifecycle.clone();
        let target = RenderedTarget {
            path: f.action.target.fixed_path().unwrap().clone(),
            params: Default::default(),
            query: Default::default(),
        };
        let (result, ()) = tokio::join!(
            f.executor.run_started_owned(
                &mut started,
                &request,
                &f.action,
                &target,
                end,
                &effect,
                &cleanup_owned,
                None,
                None
            ),
            async {
                business.notified().await;
                assert_eq!(effect.load(Ordering::SeqCst), EFFECT_ORDINARY_HTTP);
                assert!(cleanup_owned.load(Ordering::SeqCst));
                lifecycle.signal_cancel();
            }
        );
        let error = result.err().unwrap();
        assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
        assert!(!error.retryable());
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            f.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='execution.indeterminate'",
                    [],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(f.fake.take_requests().len(), 4);
        drop(started);
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_response_is_held_through_cancel_during_cleanup() {
    let mut f = ActorFixture::with_profile(&approle_profile()).await;
    let (_, _, cleanup) = install_approle_signals(&mut f);
    f.fake.push_response(Ok(login_response()));
    f.fake
        .push_response(Ok(resolved_response(7, "approle-selected")));
    f.fake
        .push_response(Ok(response(serde_json::json!({"ok":true}))));
    let release = f.fake.push_response_gated(Ok(revoke_response()));
    let lifecycle = f.executor.lifecycle.clone();
    let (result, ()) = tokio::join!(approle_admitted(&f).await.run(), async {
        cleanup.notified().await;
        lifecycle.signal_cancel();
        release.notify_one();
    });
    // A complete business response plus confirmed cleanup remains observable.
    assert_eq!(result.unwrap().body, br#"{"ok":true}"#);
    assert_eq!(f.fake.take_requests().len(), 4);
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_private_result_audit_fault_or_healthy_timeout_retains_token() {
    for fault in [true, false] {
        let mut value: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
        value["source_endpoint"] =
            serde_json::from_slice::<serde_json::Value>(&private_profile(false, "10.1.2.3"))
                .unwrap()["source_endpoint"]
                .clone();
        let mut f = ActorFixture::with_profile(&serde_json::to_vec(&value).unwrap()).await;
        install_private_transport(&mut f, "10.1.2.3");
        f.action.timeout_ms = 800;
        if fault {
            f.db().execute_batch("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.source.endpoint' AND NEW.reason_code LIKE '%operation=login;%' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        } else {
            let authority = f.authority.clone();
            let (terminals, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
                let authority = authority.clone();
                async move {
                    if draft.event_type == "vault.source.endpoint"
                        && draft.reason_code.contains("operation=login;")
                    {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                    authority.commit_audit(draft).await
                }
            });
            f.executor.terminals = terminals;
            let old = std::mem::replace(&mut f.terminal_worker, worker);
            old.await.unwrap();
        }
        f.fake.push_response(Ok(login_response()));
        f.fake.push_response(Ok(revoke_response()));
        let error = f.run().await.err().unwrap();
        assert_eq!(
            error.code(),
            if fault {
                "AUDIT_COMMIT_FAILED"
            } else {
                "UPSTREAM_INDETERMINATE"
            }
        );
        assert!(!error.retryable());
        let sent = f.fake.take_requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].auth_value, b"hvs.login-fixture-canary");
        let idle = f.executor.terminals.wait_idle(Duration::from_secs(1)).await;
        if !fault {
            idle.unwrap();
        }
        assert_eq!(
            f.authority.status().await.unwrap().state,
            if fault { "faulted" } else { "unlocked" }
        );
        f.finish().await;
    }
}

async fn approle_admitted(f: &ActorFixture) -> AdmittedExecution {
    let end = Instant::now() + Duration::from_millis(f.action.timeout_ms.into());
    let (started, request) = f.begin(end).await.unwrap();
    let sessions = f.executor.sessions.clone();
    sessions.open_for_admission();
    let session_id = started.context().session_id;
    let grant = rekey_domain::capability::SessionGrant::new(
        session_id,
        rekey_domain::authorization::Principal {
            tenant_id: rekey_domain::ids::TenantId::new_random(),
            principal_id: rekey_domain::ids::PrincipalId::new_random(),
            session_id,
        },
        vec![request.action],
        crate::now_ts().unwrap(),
        60_000,
        10,
    )
    .unwrap();
    let token = sessions
        .admit(grant, vec![(request.action, f.action.timeout_ms)])
        .unwrap();
    let permit = sessions
        .acquire(&token, request.action, crate::now_ts().unwrap())
        .unwrap();
    let executor = Arc::new(ActionExecutor::new(
        f.authority.clone(),
        sessions,
        f.executor.transport.clone(),
        f.executor.lifecycle.clone(),
        f.executor.terminals.clone(),
        f.executor.policy.clone(),
    ));
    AdmittedExecution {
        llm: None,
        executor,
        request,
        action: f.action.clone(),
        target: RenderedTarget {
            path: f.action.target.fixed_path().unwrap().clone(),
            params: Default::default(),
            query: Default::default(),
        },
        effect_deadline: end,
        started,
        _permit: Some(permit),
    }
}

#[tokio::test]
async fn actor_approle_admitted_business_cancel_waits_for_cleanup_and_releases_permit() {
    let mut f = ActorFixture::with_profile(&approle_profile()).await;
    let (_, business, cleanup) = install_approle_signals(&mut f);
    f.fake.push_response(Ok(login_response()));
    f.fake
        .push_response(Ok(resolved_response(7, "approle-selected")));
    let _never_release = f
        .fake
        .push_response_gated(Ok(response(serde_json::json!({"ok":true}))));
    let release = f.fake.push_response_gated(Ok(revoke_response()));
    let admitted = approle_admitted(&f).await;
    let (result, ()) = tokio::join!(admitted.run(), async {
        business.notified().await;
        f.executor.lifecycle.signal_cancel();
        cleanup.notified().await;
        assert_eq!(f.executor.sessions.in_flight_total(), 1);
        release.notify_one();
    });
    assert_eq!(result.err().unwrap().code(), "UPSTREAM_INDETERMINATE");
    assert_eq!(f.executor.sessions.in_flight_total(), 0);
    assert_eq!(f.fake.take_requests().len(), 4);
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_bootstrap_echo_is_not_a_revocation_identity() {
    for bootstrap in [
        "role-fixture-canary",
        "secret-fixture-canary",
        "c2VjcmV0LWZpeHR1cmUtY2FuYXJ5",
    ] {
        let f = ActorFixture::with_profile(&approle_profile()).await;
        f.fake.push_response(Ok(response(serde_json::json!({"auth":{"client_token":bootstrap,"token_type":"service","lease_duration":60}}))));
        let error = f.run().await.err().unwrap();
        assert_eq!(error.code(), "RESPONSE_SECURITY_VIOLATION");
        assert_eq!(f.fake.take_requests().len(), 1);
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_current_typed_rotation_uses_latest_source_and_actual_authority_version() {
    let mut original: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
    original["version"] = serde_json::json!("latest");
    let f = ActorFixture::with_profile(&serde_json::to_vec(&original).unwrap()).await;
    original["auth_mount"] = serde_json::json!("current");
    original["role_id"] = serde_json::json!("current-role-canary");
    f.authority
        .credential_rotate_typed_before(
            f.action.credential_id,
            rekey_domain::credential::CredentialKind::VaultKvV2Source,
            Some(1),
            rekey_vault::secret::SecretInput::from_slice(&serde_json::to_vec(&original).unwrap()),
            ActorFixture::proof(),
            None,
        )
        .await
        .unwrap();
    f.fake.push_response(Ok(login_response()));
    f.fake
        .push_response(Ok(resolved_response(19, "approle-selected")));
    f.fake
        .push_response(Ok(response(serde_json::json!({"ok":true}))));
    f.fake.push_response(Ok(revoke_response()));
    f.run().await.unwrap();
    let sent = f.fake.take_requests();
    assert_eq!(sent[0].path, "/v1/auth/current/login");
    assert_eq!(sent[1].path, "/v1/secret/data/agents/github");
    let row:(u64,String)=f.db().query_row("SELECT credential_version,reason_code FROM audit_events WHERE event_type='vault.source.resolved'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(row.0, 2);
    assert!(row.1.contains("selector=latest;actual=19"));
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_expired_secret_id_is_rechecked_after_login_started_audit() {
    let mut f = ActorFixture::with_profile(&approle_profile()).await;
    let mut value: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
    // Start the original short expiry after vault setup; initialization must
    // not consume the interval intended for the login-started audit.
    let expires_at_ms = crate::now_ts().unwrap().as_unix_ms() + 500;
    value["secret_id_expires_at_ms"] = serde_json::json!(expires_at_ms);
    f.authority
        .credential_rotate_typed_before(
            f.action.credential_id,
            rekey_domain::credential::CredentialKind::VaultKvV2Source,
            Some(1),
            rekey_vault::secret::SecretInput::from_slice(&serde_json::to_vec(&value).unwrap()),
            ActorFixture::proof(),
            None,
        )
        .await
        .unwrap();
    let authority = f.authority.clone();
    let (terminals, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
        let authority = authority.clone();
        async move {
            if draft.event_type == "vault.approle.login.started" {
                let remaining = expires_at_ms + 1 - crate::now_ts().unwrap().as_unix_ms();
                tokio::time::sleep(Duration::from_millis(remaining.max(0) as u64)).await;
            }
            authority.commit_audit(draft).await
        }
    });
    f.executor.terminals = terminals;
    let old = std::mem::replace(&mut f.terminal_worker, worker);
    old.await.unwrap();
    assert!(crate::now_ts().unwrap().as_unix_ms() < expires_at_ms);
    let error = f.run().await.err().unwrap();
    assert_eq!(error.code(), "REQUEST_DENIED");
    assert!(f.fake.take_requests().is_empty());
    assert_eq!(
        f.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='vault.approle.login.started'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_private_complete_late_login_captures_before_deadline_conversion() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let mut value: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
    value["source_endpoint"] = serde_json::from_slice::<serde_json::Value>(&private_profile(
        false, "10.1.2.3",
    ))
    .unwrap()["source_endpoint"]
        .clone();
    let mut f = ActorFixture::with_profile(&serde_json::to_vec(&value).unwrap()).await;
    install_private_transport(&mut f, "10.1.2.3");
    let end = Instant::now() + Duration::from_millis(800);
    let business = end - super::super::vault_dynamic::CLEANUP_BUDGET;
    let (mut started, request) = f.begin(end).await.unwrap();
    let prepared = f
        .authority
        .prepare_credential(f.action.credential_id)
        .await
        .unwrap();
    let version = prepared.version();
    let prepared = prepared.consume(|secret| {
        let profile = VaultKvProfile::parse_profile(secret).unwrap();
        let needles = profile.bootstrap_needles(secret);
        VaultPrepared {
            profile: Ok(profile),
            needles,
            credential_version: version,
        }
    });
    let release = f.fake.push_response_gated(Ok(login_response()));
    f.fake.push_response(Ok(revoke_response()));
    let effect = AtomicU8::new(EFFECT_NOT_STARTED);
    let cleanup_owned = AtomicBool::new(false);
    let error = {
        let mut run = std::pin::pin!(f.executor.run_vault_approle(
            &mut started,
            &request,
            &f.action,
            prepared,
            end,
            &effect,
            &cleanup_owned
        ));
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        f.executor
            .terminals
            .wait_idle(Duration::from_millis(100))
            .await
            .unwrap();
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        assert_eq!(f.fake.requests.lock().unwrap().len(), 1);
        tokio::time::sleep_until((business + Duration::from_millis(5)).into()).await;
        release.notify_one();
        run.await.err().unwrap()
    };
    assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
    assert!(!error.retryable());
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].auth_value, b"hvs.login-fixture-canary");
    assert_eq!(f.authority.status().await.unwrap().state, "unlocked");
    drop(started);
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_private_source_binding_applies_to_login_read_revoke_only() {
    let mut value: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
    value["source_endpoint"] = serde_json::from_slice::<serde_json::Value>(&private_profile(
        false, "10.1.2.3",
    ))
    .unwrap()["source_endpoint"]
        .clone();
    let mut f = ActorFixture::with_profile(&serde_json::to_vec(&value).unwrap()).await;
    let binding = install_private_transport(&mut f, "10.1.2.3");
    f.fake.push_response(Ok(login_response()));
    f.fake
        .push_response(Ok(resolved_response(7, "approle-selected")));
    f.fake
        .push_response(Ok(response(serde_json::json!({"ok":true}))));
    f.fake.push_response(Ok(revoke_response()));
    f.run().await.unwrap();
    assert_eq!(
        *binding.lock().unwrap(),
        [
            "/v1/auth/approle/login",
            "/v1/secret/data/agents/github?version=7",
            "/v1/auth/token/revoke-self"
        ]
    );
    let db = f.db();
    let mut q=db.prepare("SELECT reason_code FROM audit_events WHERE event_type='vault.source.endpoint' ORDER BY sequence").unwrap();
    let rows = q
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 3);
    for (row, operation) in rows.iter().zip(["login", "read", "revoke-self"]) {
        assert!(row.contains(&format!("operation={operation};")));
        assert!(row.contains("selected_ip=10.1.2.3"));
    }
    drop(q);
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_definite_transport_denial_stays_safe_pre_login_error() {
    let f = ActorFixture::with_profile(&approle_profile()).await;
    f.fake
        .push_response(Err(crate::upstream::UpstreamError::Blocked(
            "private-address",
        )));
    let error = f.run().await.err().unwrap();
    assert_eq!(error.code(), "UPSTREAM_FAILED");
    assert!(error.retryable());
    assert_eq!(f.fake.take_requests().len(), 1);
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_business_definite_denial_and_response_loss_keep_error_contract() {
    for failure in [
        crate::upstream::UpstreamError::Blocked("private-address"),
        crate::upstream::UpstreamError::Blocked("redirect"),
        crate::upstream::UpstreamError::Transport,
        crate::upstream::UpstreamError::ResponseTooLarge,
    ] {
        let indeterminate = upstream_failure_is_indeterminate(&failure);
        let too_large = matches!(failure, crate::upstream::UpstreamError::ResponseTooLarge);
        let f = ActorFixture::with_profile(&approle_profile()).await;
        f.fake.push_response(Ok(login_response()));
        f.fake
            .push_response(Ok(resolved_response(7, "approle-selected")));
        f.fake.push_response(Err(failure));
        f.fake.push_response(Ok(revoke_response()));
        let error = f.run().await.err().unwrap();
        assert_eq!(
            error.code(),
            if too_large {
                "RESPONSE_TOO_LARGE"
            } else if indeterminate {
                "UPSTREAM_INDETERMINATE"
            } else {
                "UPSTREAM_FAILED"
            }
        );
        assert_eq!(error.retryable(), !indeterminate);
        assert_eq!(f.fake.take_requests().len(), 4);
        let event:String=f.db().query_row("SELECT event_type FROM audit_events WHERE event_type IN ('execution.blocked','execution.indeterminate')",[],|r|r.get(0)).unwrap();
        assert_eq!(
            event,
            if indeterminate {
                "execution.indeterminate"
            } else {
                "execution.blocked"
            }
        );
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_rejected_login_captures_identity_before_status_validation() {
    for known in [false, true] {
        let f = ActorFixture::with_profile(&approle_profile()).await;
        let mut login = if known {
            login_response()
        } else {
            response(serde_json::json!({"errors":["denied"]}))
        };
        login.status = 403;
        f.fake.push_response(Ok(login));
        if known {
            f.fake.push_response(Ok(revoke_response()));
        }
        let error = f.run().await.err().unwrap();
        assert!(!error.retryable());
        let sent = f.fake.take_requests();
        assert_eq!(sent.len(), if known { 2 } else { 1 });
        if known {
            assert_eq!(error.code(), "REQUEST_DENIED");
            assert_eq!(sent[1].auth_value, b"hvs.login-fixture-canary");
        } else {
            assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
        }
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_private_read_and_cleanup_endpoint_faults_remain_typed() {
    for stage in ["read", "revoke-self"] {
        let mut value: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
        value["source_endpoint"] =
            serde_json::from_slice::<serde_json::Value>(&private_profile(false, "10.1.2.3"))
                .unwrap()["source_endpoint"]
                .clone();
        let mut f = ActorFixture::with_profile(&serde_json::to_vec(&value).unwrap()).await;
        install_private_transport(&mut f, "10.1.2.3");
        f.db().execute_batch(&format!("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.source.endpoint' AND NEW.reason_code LIKE '%operation={stage};%' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        f.fake.push_response(Ok(login_response()));
        f.fake
            .push_response(Ok(resolved_response(7, "approle-selected")));
        if stage == "revoke-self" {
            f.fake
                .push_response(Ok(response(serde_json::json!({"ok":true}))));
        }
        f.fake.push_response(Ok(revoke_response()));
        let error = f.run().await.err().unwrap();
        assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
        assert!(!error.retryable());
        assert_eq!(f.authority.status().await.unwrap().state, "faulted");
        let sent = f.fake.take_requests();
        assert_eq!(sent.len(), if stage == "read" { 3 } else { 4 });
        assert_eq!(sent.last().unwrap().auth_value, b"hvs.login-fixture-canary");
        f.finish().await;
    }
}

#[tokio::test]
async fn actor_approle_cleanup_later_audit_fault_overrides_prior_transport_uncertainty() {
    let mut value: serde_json::Value = serde_json::from_slice(&approle_profile()).unwrap();
    value["source_endpoint"] = serde_json::from_slice::<serde_json::Value>(&private_profile(
        false, "10.1.2.3",
    ))
    .unwrap()["source_endpoint"]
        .clone();
    let mut f = ActorFixture::with_profile(&serde_json::to_vec(&value).unwrap()).await;
    install_private_transport(&mut f, "10.1.2.3");
    f.db().execute_batch("CREATE TRIGGER injected BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.source.endpoint' AND NEW.reason_code LIKE '%operation=revoke-self;%' AND (SELECT count(*) FROM audit_events WHERE event_type='vault.source.endpoint' AND reason_code LIKE '%operation=revoke-self;%')=1 BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    f.fake.push_response(Ok(UpstreamResponse {status:200,headers:vec![].into(),body:Zeroizing::new(br#"{"auth":{"client_token":"token-one","client_token":"token-two","lease_duration":60,"token_type":"service"}}"#.to_vec())}));
    f.fake
        .push_response(Err(crate::upstream::UpstreamError::Transport));
    f.fake.push_response(Ok(revoke_response()));
    let error = f.run().await.err().unwrap();
    assert_eq!(error.code(), "AUDIT_COMMIT_FAILED");
    assert!(!error.retryable());
    assert_eq!(f.authority.status().await.unwrap().state, "faulted");
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[1].auth_value, b"token-one");
    assert_eq!(sent[2].auth_value, b"token-two");
    f.finish().await;
}

#[tokio::test]
async fn actor_approle_post_login_busy_audit_never_invites_retry_or_releases_body() {
    for stage in [
        "vault.approle.login.result",
        "vault.approle.cleanup.started",
        "execution.finished",
    ] {
        let mut f = ActorFixture::with_profile(&approle_profile()).await;
        let authority = f.authority.clone();
        let (terminals, worker) = crate::audit::spawn_terminal_worker_with(move |draft| {
            let authority = authority.clone();
            async move {
                if draft.event_type == stage {
                    return Err(AuthorityError::AuthorityBusy);
                }
                authority.commit_audit(draft).await
            }
        });
        f.executor.terminals = terminals;
        let old = std::mem::replace(&mut f.terminal_worker, worker);
        old.await.unwrap();
        f.fake.push_response(Ok(login_response()));
        if stage != "vault.approle.login.result" {
            f.fake
                .push_response(Ok(resolved_response(7, "approle-selected")));
            f.fake
                .push_response(Ok(response(serde_json::json!({"ok":true}))));
        }
        f.fake.push_response(Ok(revoke_response()));
        let error = f.run().await.err().unwrap();
        assert_eq!(error.code(), "UPSTREAM_INDETERMINATE", "stage {stage}");
        assert!(!error.retryable());
        let sent = f.fake.take_requests();
        assert_eq!(
            sent.len(),
            if stage == "vault.approle.login.result" {
                2
            } else {
                4
            }
        );
        assert_eq!(sent.last().unwrap().auth_value, b"hvs.login-fixture-canary");
        assert_eq!(f.authority.status().await.unwrap().state, "unlocked");
        f.finish().await;
    }
}
