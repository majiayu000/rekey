//! Synthetic-only Actor/SQLite proof; never calls a Keychain item API.
use super::*;
use crate::bootstrap::{confirm_vault_init, init_vault};
use crate::crypto::kdf::Argon2Params;
use crate::secret::SecretInput;
use rekey_domain::action::*;
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::RequestId;
use std::collections::BTreeSet;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn proof() -> UnlockProof {
    UnlockProof::Password(SecretInput::from_slice(b"synthetic-keychain-proof"))
}
fn reference(expiry: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"credential_type":"macos-keychain-source-v1","keychain_path":"/synthetic/exact.keychain-db","service":"Exact.Service","account":"Exact.Account","reference_expires_at_ms":expiry})).unwrap()
}
struct Fixture {
    dir: tempfile::TempDir,
    handle: AuthorityHandle,
    join: std::thread::JoinHandle<()>,
    calls: Arc<AtomicUsize>,
    credential: rekey_domain::credential::CredentialMetadata,
    action: FixedHttpAction,
}
impl Fixture {
    async fn new(delay: Duration, ttl: i64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        init_vault(
            &state,
            &SecretInput::from_slice(b"synthetic-keychain-proof"),
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        confirm_vault_init(&state).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (handle, join) = spawn_authority_inner(
            AuthorityConfig::new(state),
            Some(Box::new(move |reference| {
                assert_eq!(reference.keychain_path, "/synthetic/exact.keychain-db");
                assert_eq!(reference.service, "Exact.Service");
                assert_eq!(reference.account, "Exact.Account");
                count.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(delay);
                Ok(Zeroizing::new(b"synthetic-native-value".to_vec()))
            })),
        )
        .unwrap();
        handle.unlock(proof()).await.unwrap();
        let credential = handle
            .credential_add(
                CredentialLabel::new("keychain fixture").unwrap(),
                CredentialKind::MacosKeychainSource,
                SecretInput::new(reference(now_ms().unwrap() + ttl)),
                proof(),
            )
            .await
            .unwrap();
        let action = handle
            .action_upsert(
                None,
                ActionDefinition {
                    native_plugin: None,
                    text_stream: None,
                    name: ActionName::new("fixture-action").unwrap(),
                    credential_id: credential.id,
                    origin: HttpsOrigin::parse("https://example.com").unwrap(),
                    method: FixedMethod::Post,
                    target: rekey_domain::action::ActionTarget::Fixed {
                        path: ExactPath::parse("/fixed").unwrap(),
                    },
                    auth: HeaderCredentialUse::new(
                        HeaderName::new("authorization").unwrap(),
                        HeaderPrefix::new("Bearer ").unwrap(),
                    )
                    .unwrap(),
                    timeout_ms: 30_000,
                    request_policy: RequestPolicy {
                        max_body_bytes: 1024,
                        allowed_extra_headers: BTreeSet::new(),
                    },
                    response_policy: ResponsePolicy {
                        max_body_bytes: 1024,
                        allowed_headers: BTreeSet::new(),
                    },
                },
                proof(),
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        Self {
            dir,
            handle,
            join,
            calls,
            credential,
            action,
        }
    }
    async fn audit(&self, request: RequestId, event: &'static str) {
        self.handle
            .append_audit(AuditDraft {
                request_id: Some(request),
                session_id: None,
                action_id: Some(self.action.id),
                action_version: Some(self.action.version),
                credential_id: Some(self.credential.id),
                credential_version: None,
                authorization: None,
                approval: None,
                request_context: None,
                usage: None,
                event_type: event,
                outcome: outcome::SUCCESS,
                reason_code: "synthetic-start".into(),
                upstream_status: None,
                latency_ms: None,
            })
            .await
            .unwrap();
    }
    async fn prepare(
        &self,
        request: RequestId,
        deadline: Instant,
    ) -> Result<crate::secret::PreparedCredential, AuthorityError> {
        self.handle
            .prepare_execution_credential(
                self.credential.id,
                request,
                self.action.id,
                self.action.version,
                deadline,
            )
            .await
    }
    async fn stop(self) {
        let status = self.handle.status().await.unwrap();
        self.handle
            .shutdown((status.state == "unlocked").then(proof))
            .await
            .unwrap();
        self.join.join().unwrap();
    }
}
#[test]
fn keychain_closed_reference_rejects_unknown_duplicate_null_reserved_and_bounds() {
    let bytes = reference(2000);
    assert!(keychain_source::Reference::import(&bytes, 1000).is_ok());
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for (field, replacement) in [
        ("keychain_path", serde_json::json!("relative")),
        ("service", serde_json::json!("")),
        ("account", serde_json::json!("a\nb")),
        (
            "service",
            serde_json::json!("com.starlight.rekey.remembered-unlock"),
        ),
        ("reference_expires_at_ms", serde_json::json!(1000)),
        ("account", serde_json::Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid[field] = replacement;
        assert!(
            keychain_source::Reference::import(&serde_json::to_vec(&invalid).unwrap(), 1000)
                .is_err()
        );
    }
    let mut unknown = value;
    unknown["ambient"] = serde_json::json!(true);
    assert!(
        keychain_source::Reference::import(&serde_json::to_vec(&unknown).unwrap(), 1000).is_err()
    );
    let duplicate =
        String::from_utf8(bytes)
            .unwrap()
            .replacen('{', "{\"account\":\"duplicate\",", 1);
    assert!(keychain_source::Reference::import(duplicate.as_bytes(), 1000).is_err());
    assert!(keychain_source::Reference::import(&reference(i64::MAX), -1).is_err());
}
#[test]
fn keychain_native_value_errors_are_safe_and_buffers_bounded() {
    for bytes in [
        vec![],
        vec![b'x'; 65537],
        vec![255],
        b"line\r\ninjection".to_vec(),
        vec![0],
    ] {
        let error = keychain_source::validate_value(Zeroizing::new(bytes)).unwrap_err();
        assert_eq!(error.code(), "CREDENTIAL_UNAVAILABLE");
        assert_eq!(error.to_string(), "credential source is unavailable");
    }
    assert!(keychain_source::validate_value(Zeroizing::new(b"safe-header-value".to_vec())).is_ok());
}
#[tokio::test]
async fn keychain_actor_unstarted_generic_terminal_mismatched_denied_without_lookup() {
    let f = Fixture::new(Duration::ZERO, 60000).await;
    let r = RequestId::new_random();
    assert!(f.handle.prepare_credential(f.credential.id).await.is_err());
    assert!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .is_err()
    );
    f.audit(r, event_type::EXECUTION_STARTED).await;
    assert!(
        f.handle
            .prepare_execution_credential(
                f.credential.id,
                r,
                f.action.id,
                2,
                Instant::now() + Duration::from_secs(5)
            )
            .await
            .is_err()
    );
    f.audit(r, event_type::EXECUTION_FINISHED).await;
    assert!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}
#[tokio::test]
async fn keychain_actor_valid_once_version_identity_and_no_plaintext_persisted() {
    let f = Fixture::new(Duration::ZERO, 60000).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    let prepared = f
        .prepare(r, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(prepared.kind(), CredentialKind::MacosKeychainSource);
    assert_eq!(prepared.version(), 1);
    assert_eq!(prepared.credential_id(), f.credential.id);
    prepared.consume(|bytes| assert_eq!(bytes, b"synthetic-native-value"));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    let db = rusqlite::Connection::open(f.dir.path().join("state/vault.sqlite3")).unwrap();
    let (id,version,count):(Vec<u8>,u64,u64)=db.query_row("SELECT credential_id,credential_version,count(*) FROM audit_events WHERE event_type='credential.source.finished'",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(id, f.credential.id.as_bytes());
    assert_eq!(version, 1);
    assert_eq!(count, 1);
    for entry in std::fs::read_dir(f.dir.path().join("state")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(!bytes.windows(22).any(|w| w == b"synthetic-native-value"));
        }
    }
    drop(db);
    f.stop().await;
}
#[tokio::test]
async fn keychain_actor_locked_revoked_expired_and_deadline_deny_without_lookup() {
    let f = Fixture::new(Duration::ZERO, 60000).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    assert!(f.prepare(r, Instant::now()).await.is_err());
    f.handle.lock("synthetic-lock").await.unwrap();
    assert!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .is_err()
    );
    f.handle.unlock(proof()).await.unwrap();
    f.handle
        .credential_revoke(f.credential.id, proof())
        .await
        .unwrap();
    assert!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
    let f = Fixture::new(Duration::ZERO, 40).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}
#[tokio::test]
async fn keychain_actor_late_result_never_releases_value() {
    let f = Fixture::new(Duration::from_millis(50), 60000).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    assert!(
        f.prepare(r, Instant::now() + Duration::from_millis(10))
            .await
            .is_err()
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.stop().await;
}
#[tokio::test]
async fn keychain_actor_source_audit_failure_faults_before_value_release() {
    let f = Fixture::new(Duration::ZERO, 60000).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    let db = rusqlite::Connection::open(f.dir.path().join("state/vault.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_keychain_result BEFORE INSERT ON audit_events WHEN NEW.event_type='credential.source.finished' BEGIN SELECT RAISE(ABORT,'synthetic-audit-fault'); END;").unwrap();
    let error = f
        .prepare(r, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::AuditCommitFailed));
    assert_eq!(f.handle.status().await.unwrap().state, "faulted");
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    drop(db);
    f.stop().await;
}

#[tokio::test]
async fn keychain_actor_expiry_during_native_lookup_closes_late_value() {
    let f = Fixture::new(Duration::from_millis(80), 50).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    assert!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.stop().await;
}
#[tokio::test]
async fn keychain_actor_start_audit_failure_never_calls_native() {
    let f = Fixture::new(Duration::ZERO, 60000).await;
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    let db = rusqlite::Connection::open(f.dir.path().join("state/vault.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_keychain_start BEFORE INSERT ON audit_events WHEN NEW.event_type='credential.source.started' BEGIN SELECT RAISE(ABORT,'synthetic-audit-fault'); END;").unwrap();
    assert!(matches!(
        f.prepare(r, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap_err(),
        AuthorityError::AuditCommitFailed
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.handle.status().await.unwrap().state, "faulted");
    drop(db);
    f.stop().await;
}
#[tokio::test]
async fn keychain_actor_reference_rotation_does_not_lookup_and_keeps_actual_version() {
    let f = Fixture::new(Duration::ZERO, 60000).await;
    let mut invalid: serde_json::Value =
        serde_json::from_slice(&reference(now_ms().unwrap() + 60000)).unwrap();
    invalid["unknown"] = serde_json::json!(true);
    assert!(
        f.handle
            .credential_rotate_typed_before(
                f.credential.id,
                CredentialKind::MacosKeychainSource,
                None,
                SecretInput::new(serde_json::to_vec(&invalid).unwrap()),
                proof(),
                None
            )
            .await
            .is_err()
    );
    let changed = f
        .handle
        .credential_rotate_typed_before(
            f.credential.id,
            CredentialKind::MacosKeychainSource,
            Some(1),
            SecretInput::new(reference(now_ms().unwrap() + 60000)),
            proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(changed.current_version, 2);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    let r = RequestId::new_random();
    f.audit(r, event_type::EXECUTION_STARTED).await;
    let prepared = f
        .prepare(r, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(prepared.version(), 2);
    prepared.consume(|bytes| assert_eq!(bytes, b"synthetic-native-value"));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.stop().await;
}
