//! Synthetic rollback generation and explicit confirmation contracts.
mod common;
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_vault::{error::AuthorityError, paths, secret::SecretInput};

fn generation(state: &std::path::Path) -> u64 {
    let db = rusqlite::Connection::open(paths::vault_db(state)).unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT generation FROM vault_header", [], |r| r.get(0))
        .unwrap();
    u64::from_be_bytes(bytes.try_into().unwrap())
}
#[tokio::test]
async fn successful_business_commit_increments_once_and_failure_does_not() {
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    assert_eq!(generation(&vault.state_dir), 1);
    let add = || {
        (
            CredentialLabel::new("generation-token").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic-generation-token"),
            common::password_proof(),
        )
    };
    let (label, kind, secret, proof) = add();
    h.credential_add(label, kind, secret, proof).await.unwrap();
    assert_eq!(generation(&vault.state_dir), 2);
    let (label, kind, secret, proof) = add();
    assert!(matches!(
        h.credential_add(label, kind, secret, proof).await,
        Err(AuthorityError::CredentialConflict)
    ));
    assert_eq!(generation(&vault.state_dir), 2);
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

fn anchors(state: &std::path::Path) -> rekey_vault::generation_anchor::GenerationAnchors {
    let header = rekey_vault::store::SqliteRecordStore::open(&paths::vault_db(state))
        .unwrap()
        .load_header()
        .unwrap();
    rekey_vault::generation_anchor::GenerationAnchors::open(state, header.vault_id).unwrap()
}
fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(20)
}
fn restore_proof() -> rekey_vault::bootstrap::RestoreProof {
    rekey_vault::bootstrap::RestoreProof::Password(common::password_input())
}

#[tokio::test]
async fn reserved_high_water_survives_restart_and_needs_explicit_fresh_confirmation() {
    let vault = common::init_test_vault();
    let a = anchors(&vault.state_dir);
    let mut reserved = false;
    a.reserve(a.read().unwrap(), 9, &mut reserved).unwrap();
    assert!(reserved); // actual durable reserve, with the old DB left uncommitted
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let status = h.status().await.unwrap();
    assert_eq!(status.state, "rollback-suspected");
    let context = status.rollback.unwrap();
    assert_eq!(context.source_generation, 1);
    assert_eq!(context.high_water, Some(9));
    assert!(!context.history_missing);
    assert!(matches!(
        h.credential_list().await,
        Err(AuthorityError::RollbackSuspected)
    ));
    h.lock("test").await.unwrap();
    assert_eq!(h.status().await.unwrap().rollback, Some(context.clone()));
    assert!(matches!(
        h.confirm_rollback(
            context.clone(),
            rekey_vault::bootstrap::RestoreProof::Password(SecretInput::from_slice(b"wrong")),
            deadline()
        )
        .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert_eq!(a.read().unwrap().file, Some(9));
    assert_eq!(generation(&vault.state_dir), 1);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
    let (h, j) = common::spawn(&vault.state_dir);
    assert_eq!(h.status().await.unwrap().state, "locked");
    assert!(matches!(
        h.confirm_rollback(context.clone(), restore_proof(), deadline())
            .await,
        Err(AuthorityError::RollbackSuspected)
    ));
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let mut stale = context.clone();
    stale.high_water = Some(8);
    assert!(matches!(
        h.confirm_rollback(stale, restore_proof(), deadline()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    h.confirm_rollback(context.clone(), restore_proof(), deadline())
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 10);
    assert_eq!(a.read().unwrap().file, Some(10));
    let status = h.status().await.unwrap();
    assert_eq!(status.state, "locked");
    assert!(status.rollback.is_none());
    assert!(matches!(
        h.confirm_rollback(context, restore_proof(), deadline())
            .await,
        Err(AuthorityError::RollbackSuspected)
    ));
    h.unlock(common::password_proof()).await.unwrap();
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn missing_history_is_not_permission_or_malformed_anchor_failure() {
    let vault = common::init_test_vault();
    std::fs::remove_file(vault.state_dir.join("generation")).unwrap();
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let context = h.status().await.unwrap().rollback.unwrap();
    assert!(context.history_missing);
    assert_eq!(context.high_water, None);
    h.confirm_rollback(context, restore_proof(), deadline())
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 2);
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
    std::fs::write(vault.state_dir.join("generation"), b"malformed").unwrap();
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn commit_failure_after_reservation_faults_and_preserves_ahead_anchor() {
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let a = anchors(&vault.state_dir);
    let sql = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE generation_commit_failure (id BLOB REFERENCES credentials(credential_id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER generation_commit_failure_trigger AFTER UPDATE OF generation ON vault_header BEGIN INSERT INTO generation_commit_failure VALUES(zeroblob(16)); END;").unwrap();
    let result = h
        .credential_add(
            CredentialLabel::new("commit-failed").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic"),
            common::password_proof(),
        )
        .await;
    assert!(
        matches!(result, Err(AuthorityError::AuditCommitFailed)),
        "{result:?}"
    );
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(a.read().unwrap().file, Some(2));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    let count: i64 = sql
        .query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let count: i64 = sql
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='credential.created'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    sql.execute_batch(
        "DROP TRIGGER generation_commit_failure_trigger; DROP TABLE generation_commit_failure;",
    )
    .unwrap();
    drop(sql);
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn audit_insert_failure_precedes_reservation_and_retention_noop_is_zero() {
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let prior = h.audit_retention_status().await.unwrap();
    let result = h
        .audit_retention_set_before(
            rekey_domain::audit::AuditRetentionSet { days: None },
            common::password_proof(),
            Some(deadline()),
        )
        .await
        .unwrap();
    assert_eq!(result, prior);
    assert_eq!(generation(&vault.state_dir), 1);
    let a = anchors(&vault.state_dir);
    let sql = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    sql.execute_batch("CREATE TRIGGER deny_generation_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='credential.created' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END;").unwrap();
    assert!(matches!(
        h.credential_add(
            CredentialLabel::new("audit-failed").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic"),
            common::password_proof()
        )
        .await,
        Err(AuthorityError::AuditCommitFailed)
    ));
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(a.read().unwrap().file, Some(1));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn offline_restore_preview_then_confirmation_rebases_without_modifying_source() {
    use rekey_vault::bootstrap::{inspect_restore, restore_vault};
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("snapshot.rkbackup");
    let receipt = h
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    assert_eq!(receipt.generation, 1);
    assert_eq!(generation(&vault.state_dir), 1);
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
    let source = std::fs::read(&backup).unwrap();
    let target = vault.dir.path().join("restored");
    let expected = inspect_restore(&backup, &target, restore_proof(), &receipt.sha256_hex).unwrap();
    assert!(!target.exists());
    assert_eq!(expected.source_generation, 1);
    assert!(expected.history_missing);
    let mut stale = expected.clone();
    stale.source_generation = 2;
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            restore_proof(),
            &receipt.sha256_hex,
            stale
        ),
        Err(AuthorityError::RollbackSuspected)
    ));
    assert!(!target.join("generation").exists());
    assert!(!paths::vault_db(&target).exists());
    let info = restore_vault(
        &backup,
        &target,
        restore_proof(),
        &receipt.sha256_hex,
        expected,
    )
    .unwrap();
    assert_eq!(info.generation, 2);
    assert_eq!(std::fs::read(&backup).unwrap(), source);
    let (h, j) = common::spawn(&target);
    h.unlock(common::password_proof()).await.unwrap();
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn business_families_increment_once_and_queries_or_idempotency_do_not() {
    use rekey_domain::{action::*, ids::PolicySignerId};
    use rekey_vault::command::{ActionDefinition, PolicyBundleInput, PolicyTrustInput};
    use sha2::{Digest, Sha256};
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let c = h
        .credential_add(
            CredentialLabel::new("all-families").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic-one"),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 2);
    h.credential_rotate(
        c.id,
        SecretInput::from_slice(b"synthetic-two"),
        common::password_proof(),
    )
    .await
    .unwrap();
    assert_eq!(generation(&vault.state_dir), 3);
    let definition = ActionDefinition {
        native_plugin: None,
        text_stream: None,
        name: ActionName::new("fixed-generation").unwrap(),
        credential_id: c.id,
        origin: HttpsOrigin::parse("https://example.com").unwrap(),
        method: FixedMethod::Get,
        target: ActionTarget::Fixed {
            path: ExactPath::parse("/generation").unwrap(),
        },
        auth: HeaderCredentialUse::new(
            HeaderName::new("authorization").unwrap(),
            HeaderPrefix::new("Bearer ").unwrap(),
        )
        .unwrap(),
        timeout_ms: 1000,
        request_policy: RequestPolicy {
            max_body_bytes: 1024,
            allowed_extra_headers: Default::default(),
        },
        response_policy: ResponsePolicy {
            max_body_bytes: 1024,
            allowed_headers: Default::default(),
        },
    };
    let action = h
        .action_upsert(None, definition.clone(), common::password_proof())
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 4);
    h.action_upsert(Some(action.id), definition, common::password_proof())
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 5);
    h.action_disable(action.id, common::password_proof())
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 6);
    assert!(
        h.action_disable(action.id, common::password_proof())
            .await
            .is_err()
    );
    assert_eq!(generation(&vault.state_dir), 6);
    let trust = PolicyTrustInput {
        signer_id: PolicySignerId::new_random(),
        key: common::policy_key(17),
    };
    h.policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 7);
    h.policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 7);
    // This trusted Worker DTO is already verified by Broker in production.
    let bytes = vec![7; 32];
    let bundle = PolicyBundleInput {
        expected_vault_id: vault.outcome.vault_id,
        expected_trust_sha256: rekey_policy::policy_trust_sha256(trust.signer_id, &trust.key)
            .unwrap(),
        signer_id: trust.signer_id,
        version: 1,
        expires_at_ms: 4_102_444_800_000,
        policy_digest: [7; 32],
        bundle_digest: Sha256::digest(&bytes).into(),
        bundle_json: bytes,
    };
    h.policy_bundle_activate_before(bundle.clone(), common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 8);
    h.policy_bundle_activate_before(bundle, common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 8);
    h.audit_retention_set_before(
        rekey_domain::audit::AuditRetentionSet { days: Some(30) },
        common::password_proof(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(generation(&vault.state_dir), 9);
    h.audit_retention_set_before(
        rekey_domain::audit::AuditRetentionSet { days: Some(30) },
        common::password_proof(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(generation(&vault.state_dir), 9);
    h.rotate_dek_before(common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 10);
    h.credential_revoke(c.id, common::password_proof())
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 11);
    assert!(matches!(
        h.credential_revoke(c.id, common::password_proof()).await,
        Err(AuthorityError::CredentialNotFound)
    ));
    assert_eq!(generation(&vault.state_dir), 11);
    h.action_list().await.unwrap();
    h.policy_material().await.unwrap();
    h.lock("generation-test").await.unwrap();
    h.unlock(common::password_proof()).await.unwrap();
    assert_eq!(generation(&vault.state_dir), 11);
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn template_batch_has_one_generation_for_all_actions() {
    use rekey_domain::{
        ids::RequestId,
        ipc::{TemplateInstallMeta, TemplateSource},
    };
    use std::collections::BTreeMap;
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let c = h
        .credential_add(
            CredentialLabel::new("batch-owner").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let request = TemplateInstallMeta {
        source: TemplateSource::GitHubPat {},
        credential_id: c.id,
        bindings: vec![BTreeMap::from([
            ("owner".into(), "acme".into()),
            ("repo".into(), "one".into()),
        ])],
        capabilities: vec!["read-repo".into(), "create-issue".into()],
        name_prefix: "batch".into(),
        timeout_ms: 1000,
        request_max_bytes: 1024,
        response_max_bytes: 1024,
        allowed_extra_headers: vec![],
        allowed_response_headers: vec![],
    };
    let reply = h
        .template_install_before(
            request,
            vec![],
            common::password_proof(),
            RequestId::new_random(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.actions.len(), 8);
    assert_eq!(generation(&vault.state_dir), 3);
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn password_recovery_and_new_vrk_advance_with_matching_new_header_mac() {
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let old_root = common::fixture_root(&vault.state_dir);
    // Rewrap with the same password still creates new wrapper material.
    h.password_change_before(common::password_proof(), common::password_input(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 2);
    let recovery = h
        .recovery_rotate_before(common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(generation(&vault.state_dir), 3);
    h.lock("vrk").await.unwrap();
    h.rotate_vrk_before(
        common::password_input(),
        SecretInput::from_slice(recovery.as_bytes()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(generation(&vault.state_dir), 4);
    assert_eq!(h.status().await.unwrap().state, "locked");
    assert_ne!(*common::fixture_root(&vault.state_dir), *old_root);
    h.unlock(common::password_proof()).await.unwrap(); // proves MAC under the new root
    h.lock("recovery").await.unwrap();
    h.unlock(rekey_vault::command::UnlockProof::Recovery(
        SecretInput::from_slice(recovery.as_bytes()),
    ))
    .await
    .unwrap();
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn sql_work_crossing_deadline_rolls_back_before_anchor_reservation() {
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let a = anchors(&vault.state_dir);
    let sql = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    sql.execute_batch("CREATE TRIGGER slow_generation_audit AFTER INSERT ON audit_events WHEN NEW.event_type='credential.created' BEGIN SELECT sum(value) FROM (WITH RECURSIVE counter(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM counter WHERE value<10000000) SELECT value FROM counter); END;").unwrap();
    let start = std::time::Instant::now();
    let result = h
        .credential_add_before(
            CredentialLabel::new("expired").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic"),
            common::password_proof(),
            Some(start + std::time::Duration::from_millis(100)),
        )
        .await;
    assert!(matches!(result, Err(AuthorityError::AuthorityBusy)));
    assert!(start.elapsed() >= std::time::Duration::from_millis(100));
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(a.read().unwrap().file, Some(1));
    assert_eq!(h.status().await.unwrap().state, "unlocked");
    let rows: i64 = sql
        .query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn maximum_high_water_never_wraps_and_wrong_confirm_has_no_database_writes() {
    let vault = common::init_test_vault();
    let a = anchors(&vault.state_dir);
    a.reserve(a.read().unwrap(), u64::MAX, &mut false).unwrap();
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let expected = h.status().await.unwrap().rollback.unwrap();
    let sql = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let before: i64 = sql
        .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
        .unwrap();
    assert!(matches!(
        h.confirm_rollback(
            expected.clone(),
            rekey_vault::bootstrap::RestoreProof::Password(SecretInput::from_slice(b"wrong")),
            deadline()
        )
        .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    let after: i64 = sql
        .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
    assert!(matches!(
        h.confirm_rollback(expected, restore_proof(), deadline())
            .await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(a.read().unwrap().file, Some(u64::MAX));
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[test]
#[ignore = "subprocess helper; the parent hard-kills this transaction"]
fn generation_crash_window_helper() {
    let state = std::path::PathBuf::from(
        std::env::var_os("REKEY_GENERATION_CRASH_FIXTURE").expect("synthetic fixture path"),
    );
    let database = if std::env::var_os("REKEY_GENERATION_RESTORE_WINDOW").is_some() {
        state.join(".incoming-vault.sqlite3")
    } else {
        paths::vault_db(&state)
    };
    let header = rekey_vault::store::SqliteRecordStore::open(&database)
        .unwrap()
        .load_header()
        .unwrap();
    let a =
        rekey_vault::generation_anchor::GenerationAnchors::open(&state, header.vault_id).unwrap();
    let mut sql = rusqlite::Connection::open(&database).unwrap();
    let tx = sql.transaction().unwrap();
    tx.execute(
        "UPDATE vault_header SET generation=?1",
        [2u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    a.reserve(a.read().unwrap(), 2, &mut false).unwrap();
    // No destructor or SQLite COMMIT runs. Only this synthetic child is killed.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    panic!("SIGKILL did not stop the fixture");
}

#[tokio::test]
async fn hard_kill_between_anchor_and_commit_recovers_old_db_without_unlocking() {
    use std::os::unix::process::ExitStatusExt;
    let vault = common::init_test_vault();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "generation_crash_window_helper",
            "--test-threads=1",
        ])
        .env("REKEY_GENERATION_CRASH_FIXTURE", &vault.state_dir)
        .env_remove("RUST_TEST_THREADS")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(anchors(&vault.state_dir).read().unwrap().file, Some(2));
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    assert_eq!(
        h.status().await.unwrap().rollback.unwrap().high_water,
        Some(2)
    );
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn failed_file_anchor_install_faults_without_replacing_original_storage_error() {
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "permission fixture requires non-root user"
    );
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    std::fs::set_permissions(&vault.state_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = h
        .credential_add(
            CredentialLabel::new("anchor-io").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic"),
            common::password_proof(),
        )
        .await;
    std::fs::set_permissions(&vault.state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(result, Err(AuthorityError::StorageUnavailable(_))),
        "{result:?}"
    );
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(anchors(&vault.state_dir).read().unwrap().file, Some(1));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn explicit_confirmation_checks_payloads_that_ordinary_unlock_defers_to_use() {
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    h.credential_add(
        CredentialLabel::new("payload-boundary").unwrap(),
        CredentialKind::OpaqueToken,
        SecretInput::from_slice(b"synthetic payload"),
        common::password_proof(),
    )
    .await
    .unwrap();
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
    let sql = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    sql.execute(
        "UPDATE credential_versions SET encrypted_payload=zeroblob(length(encrypted_payload))",
        [],
    )
    .unwrap();
    drop(sql);
    let a = anchors(&vault.state_dir);
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap(); // no new full-vault decryption scan
    h.lock("confirmation-boundary").await.unwrap();
    a.reserve(a.read().unwrap(), 3, &mut false).unwrap();
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let context = h.status().await.unwrap().rollback.unwrap();
    assert!(matches!(
        h.confirm_rollback(context, restore_proof(), deadline())
            .await,
        Err(AuthorityError::CryptoFailure)
    ));
    assert_eq!(generation(&vault.state_dir), 2);
    assert_eq!(a.read().unwrap().file, Some(3));
    assert_ne!(h.status().await.unwrap().state, "unlocked");
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn confirmation_rechecks_actual_high_water_and_rejects_expired_deadline_without_writes() {
    let vault = common::init_test_vault();
    let a = anchors(&vault.state_dir);
    a.reserve(a.read().unwrap(), 2, &mut false).unwrap();
    let (h, j) = common::spawn(&vault.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let expected = h.status().await.unwrap().rollback.unwrap();
    assert!(matches!(
        h.confirm_rollback(expected.clone(), restore_proof(), std::time::Instant::now())
            .await,
        Err(AuthorityError::AuthorityBusy)
    ));
    a.reserve(a.read().unwrap(), 3, &mut false).unwrap();
    assert!(matches!(
        h.confirm_rollback(expected, restore_proof(), deadline())
            .await,
        Err(AuthorityError::RollbackSuspected)
    ));
    assert_eq!(generation(&vault.state_dir), 1);
    assert_eq!(a.read().unwrap().file, Some(3));
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    let current = h.status().await.unwrap().rollback.unwrap();
    assert_eq!(current.high_water, Some(3));
    h.confirm_rollback(
        current,
        rekey_vault::bootstrap::RestoreProof::RecoveryKey(SecretInput::from_slice(
            vault.outcome.recovery_key_display.as_bytes(),
        )),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(generation(&vault.state_dir), 4);
    h.shutdown(None).await.unwrap();
    j.join().unwrap();
}

#[tokio::test]
async fn interrupted_restore_keeps_marker_and_requires_new_displayed_high_water() {
    use rekey_vault::bootstrap::{inspect_restore, restore_vault};
    use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
    let vault = common::init_test_vault();
    let (h, j) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("restore-window.rkbackup");
    let receipt = h
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
    let target = vault.dir.path().join("interrupted-target");
    let before = inspect_restore(&backup, &target, restore_proof(), &receipt.sha256_hex).unwrap();
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        paths::restore_incomplete(&target),
        b"rekey-restore-incomplete-v1\n",
    )
    .unwrap();
    std::fs::copy(&backup, target.join(".incoming-vault.sqlite3")).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "generation_crash_window_helper",
            "--test-threads=1",
        ])
        .env("REKEY_GENERATION_CRASH_FIXTURE", &target)
        .env("REKEY_GENERATION_RESTORE_WINDOW", "1")
        .env_remove("RUST_TEST_THREADS")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(matches!(
        rekey_vault::authority::spawn_authority(common::test_config(&target)),
        Err(AuthorityError::UnsupportedVaultLayout)
    ));
    let marker = std::fs::read(paths::restore_incomplete(&target)).unwrap();
    let anchor = std::fs::read(target.join("generation")).unwrap();
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            restore_proof(),
            &receipt.sha256_hex,
            before
        ),
        Err(AuthorityError::RollbackSuspected)
    ));
    assert_eq!(
        std::fs::read(paths::restore_incomplete(&target)).unwrap(),
        marker
    );
    assert_eq!(std::fs::read(target.join("generation")).unwrap(), anchor);
    assert!(target.join(".incoming-vault.sqlite3").exists());
    let fresh = inspect_restore(&backup, &target, restore_proof(), &receipt.sha256_hex).unwrap();
    assert_eq!(fresh.high_water, Some(2));
    let restored = restore_vault(
        &backup,
        &target,
        restore_proof(),
        &receipt.sha256_hex,
        fresh,
    )
    .unwrap();
    assert_eq!(restored.generation, 3);
    assert!(!paths::restore_incomplete(&target).exists());
    assert!(!target.join(".incoming-vault.sqlite3").exists());
    let (h, j) = common::spawn(&target);
    h.unlock(common::password_proof()).await.unwrap();
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}
