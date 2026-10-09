//! Synthetic storage/Authority contracts; no provider, gateway or real credentials.
mod common;
use rekey_domain::{
    audit::{UsageEvidence, UsageSource},
    ids::{ActionId, CredentialId, PolicyRuleId, PrincipalId, RequestId, SessionId},
};
use rekey_vault::{
    command::{AuditDraft, ProfileUsageStart},
    error::AuthorityError,
    handle::AuthorityHandle,
    model::{AuthorizationEvidence, UsageAdmission, UsageTotals, event_type, outcome},
    paths,
};
use rusqlite::Connection;
use std::time::{Duration, Instant};
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn draft(principal: PrincipalId) -> AuditDraft {
    AuditDraft {
        request_id: Some(RequestId::new_random()),
        session_id: Some(SessionId::new_random()),
        action_id: Some(ActionId::new_random()),
        action_version: Some(1),
        credential_id: Some(CredentialId::new_random()),
        credential_version: None,
        authorization: Some(Box::new(AuthorizationEvidence {
            principal_id: principal,
            policy_version: 1,
            policy_digest: [1; 32],
            policy_rule_id: Some(PolicyRuleId::new_random()),
            resource_type: "action".into(),
            resource_id: "synthetic-only".into(),
            parameter_hash: [2; 32],
        })),
        approval: None,
        request_context: None,
        usage: None,
        event_type: event_type::EXECUTION_STARTED,
        outcome: outcome::SUCCESS,
        reason_code: "started".into(),
        upstream_status: None,
        latency_ms: None,
    }
}
fn profile_draft(principal: PrincipalId) -> AuditDraft {
    let mut value = draft(principal);
    value.request_context = Some(
        rekey_domain::audit::ProfileRequestAuditContext {
            profile_name: "original-profile".into(),
            policy_sha256: "01".repeat(32),
            instance_slug: "sample-model".into(),
            capability: "messages".into(),
            model: Some("allowed".into()),
        }
        .into(),
    );
    value
}
fn audit_query(request: RequestId) -> rekey_domain::audit::AuditQuery {
    rekey_domain::audit::AuditQuery {
        request_id: Some(request),
        session_id: None,
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit: 100,
    }
}
fn limits(max: Option<u64>) -> ProfileUsageStart {
    ProfileUsageStart {
        instance_slug: "sample-model".into(),
        max_requests_per_day: 10,
        max_output_tokens_per_day: 100,
        generation_max_output: max,
    }
}
fn terminal(start: &AuditDraft) -> AuditDraft {
    let mut end = start.clone();
    end.event_type = event_type::EXECUTION_FINISHED;
    end.credential_version = Some(1);
    end.reason_code = "finished".into();
    end.upstream_status = Some(200);
    end.latency_ms = Some(7);
    end
}
async fn begin(
    h: &AuthorityHandle,
    usage: ProfileUsageStart,
    draft: AuditDraft,
) -> Result<UsageAdmission, AuthorityError> {
    h.begin_profile_execution(
        usage,
        vec![],
        draft,
        Instant::now() + Duration::from_secs(5),
        Some(now() + 5000),
    )
    .await
}
async fn sum(h: &AuthorityHandle, p: PrincipalId) -> UsageTotals {
    h.profile_usage(p, "sample-model".into(), now() / 86_400_000)
        .await
        .unwrap()
}

#[tokio::test]
async fn derived_audit_keeps_public_target_and_real_expiry_without_model_usage() {
    use rekey_domain::{audit::DerivedRequestAuditContext, connection::DerivedCredentialTarget};
    let vault = common::init_test_vault();
    let (h, join) = common::spawn(&vault.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let principal = PrincipalId::new_random();
    let mut started = draft(principal);
    started.authorization.as_mut().unwrap().resource_type = "connection".into();
    started.authorization.as_mut().unwrap().resource_id = "sample-model".into();
    let context = DerivedRequestAuditContext {
        connection: "sample-model".into(),
        caller: "codex".into(),
        target: DerivedCredentialTarget::KubernetesEks {
            cluster_id: "synthetic-cluster".into(),
            region: "us-east-1".into(),
        },
        expires_at_ms: None,
    };
    started.request_context = Some(context.clone().into());
    assert!(begin(&h, limits(Some(20)), started.clone()).await.is_err());
    assert_eq!(sum(&h, principal).await.requests, 0);
    h.append_audit(started.clone()).await.unwrap();
    let mut issued = started.clone();
    issued.event_type = "credential.derived_issued";
    let mut issued_context = context;
    issued_context.expires_at_ms = Some(now() + 900_000);
    issued.request_context = Some(issued_context.clone().into());
    for expiry in [None, Some(1)] {
        let mut bad = issued.clone();
        let mut bad_context = issued_context.clone();
        bad_context.expires_at_ms = expiry;
        bad.request_context = Some(bad_context.into());
        assert!(h.append_audit(bad).await.is_err());
    }
    let mut bad = issued.clone();
    bad.authorization.as_mut().unwrap().resource_id = "other-target".into();
    assert!(h.append_audit(bad).await.is_err());
    h.append_audit(issued).await.unwrap();
    let query = audit_query(started.request_id.unwrap());
    let page = h.audit_query(query.clone()).await.unwrap();
    page.validate_for(&query).unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(page.events.iter().all(|event| event.usage.is_none()));
    let issued = page
        .events
        .iter()
        .find(|event| event.event_type == "credential.derived_issued")
        .unwrap();
    assert_eq!(issued.request_context, Some(issued_context.into()));
    assert_eq!(h.status().await.unwrap().state, "unlocked");
    finish(h, join).await;
}
async fn finish(h: AuthorityHandle, j: std::thread::JoinHandle<()>) {
    h.shutdown(Some(common::password_proof())).await.unwrap();
    j.join().unwrap();
}
fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn revision(db: &Connection) -> i64 {
    db.query_row("SELECT revision FROM profile_usage_state", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn admission_and_measured_settlement_are_once_and_budget_denial_is_normal() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let s = draft(p);
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    assert_eq!(
        begin(&h, limits(Some(80)), s.clone()).await.unwrap(),
        UsageAdmission::Started
    );
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 1,
            output_tokens: 0
        }
    );
    assert!(matches!(
        begin(&h, limits(Some(80)), s.clone()).await,
        Err(AuthorityError::Domain(_))
    ));
    let end = terminal(&s);
    h.settle_profile_execution(s.request_id.unwrap(), Some(7), end.clone())
        .await
        .unwrap();
    let rev = revision(&db);
    h.settle_profile_execution(s.request_id.unwrap(), Some(7), end.clone())
        .await
        .unwrap();
    assert_eq!(revision(&db), rev);
    assert!(matches!(
        h.settle_profile_execution(s.request_id.unwrap(), Some(8), end)
            .await,
        Err(AuthorityError::Domain(_))
    ));
    let mut l = limits(Some(80));
    l.max_requests_per_day = 1;
    assert_eq!(
        begin(&h, l, draft(p)).await.unwrap(),
        UsageAdmission::BudgetDenied
    );
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 1,
            output_tokens: 7
        }
    );
    assert_eq!(h.status().await.unwrap().state, "unlocked");
    let mut l = limits(Some(80));
    l.max_output_tokens_per_day = 7;
    assert_eq!(
        begin(&h, l, draft(p)).await.unwrap(),
        UsageAdmission::BudgetDenied
    );
    assert_eq!(count(&db, "profile_usage"), 1);
    assert_eq!(revision(&db), rev);
    let usage: String = db
        .query_row(
            "SELECT metadata_json FROM audit_events WHERE event_type='execution.finished'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_value::<UsageEvidence>(
            serde_json::from_str::<serde_json::Value>(&usage).unwrap()["usage"].clone()
        )
        .unwrap(),
        UsageEvidence {
            instance_slug: "sample-model".into(),
            utc_day: now() / 86_400_000,
            output_tokens: 7,
            source: UsageSource::Measured
        }
    );
    finish(h, j).await;
}

#[tokio::test]
async fn buckets_share_across_sessions_but_not_principal_or_instance_and_non_generation_is_zero() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let a = draft(p);
    begin(&h, limits(Some(30)), a.clone()).await.unwrap();
    h.settle_profile_execution(a.request_id.unwrap(), None, terminal(&a))
        .await
        .unwrap();
    let b = draft(p);
    begin(&h, limits(None), b.clone()).await.unwrap();
    assert!(matches!(
        h.settle_profile_execution(b.request_id.unwrap(), Some(1), terminal(&b))
            .await,
        Err(AuthorityError::Domain(_))
    ));
    h.settle_profile_execution(b.request_id.unwrap(), None, terminal(&b))
        .await
        .unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 2,
            output_tokens: 30
        }
    );
    assert_eq!(
        sum(&h, PrincipalId::new_random()).await,
        UsageTotals::default()
    );
    let mut l = limits(None);
    l.instance_slug = "other".into();
    begin(&h, l, draft(p)).await.unwrap();
    assert_eq!(sum(&h, p).await.requests, 2);
    assert_eq!(
        h.profile_usage(p, "sample-model".into(), now() / 86_400_000 - 1)
            .await
            .unwrap(),
        UsageTotals::default()
    );
    finish(h, j).await;
}

#[tokio::test]
async fn forged_usage_invalid_context_and_locked_calls_do_not_write_or_fault() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    let p = PrincipalId::new_random();
    let s = draft(p);
    assert!(matches!(
        begin(&h, limits(Some(9)), s.clone()).await,
        Err(AuthorityError::Locked)
    ));
    assert!(matches!(
        h.profile_usage(p, "sample-model".into(), 0).await,
        Err(AuthorityError::Locked)
    ));
    h.unlock(common::password_proof()).await.unwrap();
    let mut forged = s.clone();
    forged.usage = Some(UsageEvidence {
        instance_slug: "sample-model".into(),
        utc_day: 0,
        output_tokens: 0,
        source: UsageSource::Measured,
    });
    assert!(matches!(
        h.append_audit(forged.clone()).await,
        Err(AuthorityError::Domain(_))
    ));
    assert!(matches!(
        h.commit_audits(vec![forged.clone()]).await,
        Err(AuthorityError::Domain(_))
    ));
    assert!(matches!(
        begin(&h, limits(Some(9)), forged).await,
        Err(AuthorityError::Domain(_))
    ));
    for max in [0, u64::MAX] {
        let mut l = limits(Some(9));
        l.max_requests_per_day = max;
        assert!(matches!(
            begin(&h, l, s.clone()).await,
            Err(AuthorityError::Domain(_))
        ));
    }
    begin(&h, limits(Some(9)), s.clone()).await.unwrap();
    let mut wrong = terminal(&s);
    wrong.authorization.as_mut().unwrap().parameter_hash = [9; 32];
    assert!(matches!(
        h.settle_profile_execution(s.request_id.unwrap(), Some(1), wrong)
            .await,
        Err(AuthorityError::Domain(_))
    ));
    assert_eq!(sum(&h, p).await.output_tokens, 0);
    assert_eq!(h.status().await.unwrap().state, "unlocked");
    finish(h, j).await;
}

#[tokio::test]
async fn valid_numeric_rewrite_row_deletion_missing_root_and_cross_vault_root_fail_closed() {
    for attack in [
        "UPDATE profile_usage SET generation_max_output=2",
        "UPDATE profile_usage SET started_at_ms=started_at_ms+1",
        "UPDATE profile_usage SET context_json=' '||context_json",
        "UPDATE profile_usage SET instance_slug='other'",
        "UPDATE profile_usage_state SET revision=revision+1",
        "DELETE FROM profile_usage",
        "DELETE FROM profile_usage_state",
    ] {
        let v = common::init_test_vault();
        let (h, j) = common::spawn(&v.state_dir);
        h.unlock(common::password_proof()).await.unwrap();
        let p = PrincipalId::new_random();
        begin(&h, limits(Some(30)), draft(p)).await.unwrap();
        let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
        db.execute_batch(attack).unwrap();
        assert!(
            matches!(
                h.profile_usage(p, "sample-model".into(), now() / 86_400_000)
                    .await,
                Err(AuthorityError::StorageIntegrityFailed)
            ),
            "{attack}"
        );
        assert_eq!(h.status().await.unwrap().state, "faulted");
        finish(h, j).await;
    }
    let first = common::init_test_vault();
    let second = common::init_test_vault();
    let db = Connection::open(paths::vault_db(&first.state_dir)).unwrap();
    let other = Connection::open(paths::vault_db(&second.state_dir)).unwrap();
    let (n, c): (Vec<u8>, Vec<u8>) = other
        .query_row(
            "SELECT seal_nonce,seal_ciphertext FROM profile_usage_state",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    db.execute(
        "UPDATE profile_usage_state SET seal_nonce=?1,seal_ciphertext=?2",
        rusqlite::params![n, c],
    )
    .unwrap();
    let (h, j) = common::spawn(&first.state_dir);
    assert!(matches!(
        h.unlock(common::password_proof()).await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    finish(h, j).await;
}

#[tokio::test]
async fn begin_checks_both_deadlines_after_blocked_sql_and_rolls_back_every_write() {
    for wall in [false, true] {
        let v = common::init_test_vault();
        let (h, j) = common::spawn(&v.state_dir);
        h.unlock(common::password_proof()).await.unwrap();
        let p = PrincipalId::new_random();
        let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
        let audits = count(&db, "audit_events");
        let rev = revision(&db);
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let copy = h.clone();
        let end = Instant::now() + Duration::from_millis(if wall { 5000 } else { 100 });
        let wallend = Some(now() + if wall { 100 } else { 5000 });
        let task = tokio::spawn(async move {
            copy.begin_profile_execution(limits(Some(9)), vec![], draft(p), end, wallend)
                .await
        });
        tokio::time::sleep(Duration::from_millis(250)).await;
        db.execute_batch("COMMIT").unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(AuthorityError::AuthorityBusy)
        ));
        assert_eq!(count(&db, "audit_events"), audits);
        assert_eq!(count(&db, "profile_usage"), 0);
        assert_eq!(revision(&db), rev);
        assert_eq!(h.status().await.unwrap().state, "unlocked");
        finish(h, j).await;
    }
}

#[tokio::test]
async fn terminal_audit_failure_rolls_back_settlement_and_faults_without_lost_usage() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let s = draft(p);
    begin(&h, limits(Some(25)), s.clone()).await.unwrap();
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    let rev = revision(&db);
    db.execute_batch("CREATE TRIGGER fail_usage_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.finished' BEGIN SELECT RAISE(ABORT,'synthetic'); END").unwrap();
    assert!(matches!(
        h.settle_profile_execution(s.request_id.unwrap(), Some(7), terminal(&s))
            .await,
        Err(AuthorityError::AuditCommitFailed)
    ));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    assert_eq!(revision(&db), rev);
    let n: Option<u64> = db
        .query_row("SELECT output_tokens FROM profile_usage", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, None);
    db.execute_batch("DROP TRIGGER fail_usage_terminal")
        .unwrap();
    finish(h, j).await;
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 1,
            output_tokens: 25
        }
    );
    finish(h, j).await;
}

#[tokio::test]
async fn backup_restore_rotation_and_presence_resume_keep_usage_and_recover_pending() {
    use rekey_vault::{
        bootstrap::{RestoreProof, restore_vault},
        secret::SecretInput,
    };
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let a = profile_draft(p);
    begin(&h, limits(Some(40)), a.clone()).await.unwrap();
    h.settle_profile_execution(a.request_id.unwrap(), Some(7), terminal(&a))
        .await
        .unwrap();
    let b = profile_draft(p);
    let pending_request = b.request_id.unwrap();
    let expected = b.request_context.clone();
    begin(&h, limits(Some(20)), b).await.unwrap();
    let archive = v.dir.path().join("usage.rkbackup");
    let receipt = h
        .backup(archive.clone(), common::password_proof())
        .await
        .unwrap();
    let restored = v.dir.path().join("restored");
    restore_vault(
        &archive,
        &restored,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
        rekey_vault::bootstrap::inspect_restore(
            &archive,
            &restored,
            RestoreProof::Password(common::password_input()),
            &receipt.sha256_hex,
        )
        .unwrap(),
    )
    .unwrap();
    let (r, rj) = common::spawn(&restored);
    r.unlock(common::password_proof()).await.unwrap();
    assert_eq!(
        sum(&r, p).await,
        UsageTotals {
            requests: 2,
            output_tokens: 27
        }
    );
    let page = r.audit_query(audit_query(pending_request)).await.unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(
        page.events
            .iter()
            .all(|row| row.request_context == expected)
    );
    finish(r, rj).await;
    let (key, _) = h
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    h.lock_for_restart("test").await.unwrap();
    h.desktop_resume(SecretInput::from_slice(&key), None)
        .await
        .unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 2,
            output_tokens: 27
        }
    );
    // Rotation verifies and preserves settled and pending rows; pending recovers at unlock.
    let rotation_pending = profile_draft(p);
    let rotation_request = rotation_pending.request_id.unwrap();
    begin(&h, limits(Some(5)), rotation_pending).await.unwrap();
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    let old: Vec<u8> = db
        .query_row("SELECT seal_ciphertext FROM profile_usage_state", [], |r| {
            r.get(0)
        })
        .unwrap();
    h.lock("usage-rotation").await.unwrap();
    h.rotate_vrk_before(
        common::password_input(),
        SecretInput::from_slice(v.outcome.recovery_key_display.as_bytes()),
        None,
    )
    .await
    .unwrap();
    let new: Vec<u8> = db
        .query_row("SELECT seal_ciphertext FROM profile_usage_state", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(old, new);
    h.unlock(common::password_proof()).await.unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 3,
            output_tokens: 32
        }
    );
    finish(h, j).await;
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 3,
            output_tokens: 32
        }
    );
    let terminals: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='execution.indeterminate'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(terminals, 2);
    let page = h.audit_query(audit_query(rotation_request)).await.unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(
        page.events
            .iter()
            .all(|row| row.request_context == expected)
    );
    finish(h, j).await;
}

#[tokio::test]
async fn corrupted_snapshot_and_live_backup_or_rotation_never_release_unverified_usage() {
    use rekey_vault::{
        bootstrap::{RestoreProof, restore_vault},
        secret::SecretInput,
    };
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    begin(&h, limits(Some(10)), draft(p)).await.unwrap();
    let archive = v.dir.path().join("valid.rkbackup");
    h.backup(archive.clone(), common::password_proof())
        .await
        .unwrap();
    let db = Connection::open(&archive).unwrap();
    db.execute("UPDATE profile_usage SET generation_max_output=1", [])
        .unwrap();
    drop(db);
    let hash = rekey_vault::durable::sha256_file(&archive).unwrap();
    let target = v.dir.path().join("bad-restore");
    assert!(matches!(
        restore_vault(
            &archive,
            &target,
            RestoreProof::Password(common::password_input()),
            &hash,
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert!(!paths::vault_db(&target).exists());
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    db.execute("UPDATE profile_usage SET generation_max_output=1", [])
        .unwrap();
    let out = v.dir.path().join("bad-backup");
    assert!(matches!(
        h.backup(out.clone(), common::password_proof()).await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert!(!out.exists());
    assert_eq!(h.status().await.unwrap().state, "faulted");
    finish(h, j).await;
    let fresh = common::init_test_vault();
    let (h, j) = common::spawn(&fresh.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    begin(&h, limits(Some(10)), draft(p)).await.unwrap();
    let db = Connection::open(paths::vault_db(&fresh.state_dir)).unwrap();
    db.execute("DELETE FROM profile_usage", []).unwrap();
    h.lock("usage-rotation").await.unwrap();
    assert!(matches!(
        h.rotate_vrk_before(
            common::password_input(),
            SecretInput::from_slice(fresh.outcome.recovery_key_display.as_bytes()),
            None
        )
        .await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    finish(h, j).await;
}

#[tokio::test]
async fn format_24_state_and_backup_are_rejected_without_migration() {
    use rekey_vault::{
        bootstrap::{RestoreProof, restore_vault},
        store::SqliteRecordStore,
    };
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let archive = v.dir.path().join("old.rkbackup");
    h.backup(archive.clone(), common::password_proof())
        .await
        .unwrap();
    finish(h, j).await;
    for file in [&archive, &paths::vault_db(&v.state_dir)] {
        let db = Connection::open(file).unwrap();
        db.execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = 27','format_version = 24') WHERE name='vault_header'; PRAGMA writable_schema=OFF;").unwrap();
        drop(db);
        let db = Connection::open(file).unwrap();
        db.execute("UPDATE vault_header SET format_version=24", [])
            .unwrap();
        drop(db);
        assert!(matches!(
            SqliteRecordStore::open(file),
            Err(AuthorityError::UnsupportedFormatVersion)
        ));
    }
    let hash = rekey_vault::durable::sha256_file(&archive).unwrap();
    let target = v.dir.path().join("old-restore");
    assert!(matches!(
        restore_vault(
            &archive,
            &target,
            RestoreProof::Password(common::password_input()),
            &hash,
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!paths::vault_db(&target).exists());
}

#[test]
fn hard_kill_child() {
    let Some(state) = std::env::var_os("REKEY_USAGE_SYNTHETIC_CHILD") else {
        return;
    };
    let state = std::path::PathBuf::from(state);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (h, _join) = common::spawn(&state);
        h.unlock(common::password_proof()).await.unwrap();
        let p = PrincipalId::new_random();
        begin(&h, limits(Some(37)), draft(p)).await.unwrap();
        std::fs::write(
            state.parent().unwrap().join("usage-ready"),
            serde_json::to_vec(&p).unwrap(),
        )
        .unwrap();
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[tokio::test]
async fn hard_kill_pending_is_recovered_once_before_unlock_admission() {
    let v = common::init_test_vault();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hard_kill_child", "--nocapture"])
        .env("REKEY_USAGE_SYNTHETIC_CHILD", &v.state_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let marker = v.dir.path().join("usage-ready");
    let end = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("synthetic child did not durably start");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let p: PrincipalId = serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    for _ in 0..2 {
        let (h, j) = common::spawn(&v.state_dir);
        let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
        h.unlock(common::password_proof()).await.unwrap();
        assert_eq!(
            sum(&h, p).await,
            UsageTotals {
                requests: 1,
                output_tokens: 37
            }
        );
        let n: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.indeterminate'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        finish(h, j).await;
    }
}

#[tokio::test]
async fn dropped_terminal_receiver_does_not_cancel_the_queued_settlement() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let s = draft(p);
    begin(&h, limits(Some(25)), s.clone()).await.unwrap();
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let copy = h.clone();
    let task = tokio::spawn(async move {
        copy.settle_profile_execution(s.request_id.unwrap(), Some(9), terminal(&s))
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    db.execute_batch("COMMIT").unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 1,
            output_tokens: 9
        }
    );
    let n: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='execution.finished'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    finish(h, j).await;
}

#[tokio::test]
async fn pruning_execution_audit_does_not_reset_the_authenticated_usage_ledger() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let s = draft(p);
    begin(&h, limits(Some(20)), s.clone()).await.unwrap();
    h.settle_profile_execution(s.request_id.unwrap(), Some(7), terminal(&s))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let receipt = h
        .audit_prune_before(
            rekey_domain::audit::AuditPruneRequest { before_ms: now() },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(receipt.deleted_groups, 1);
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 1,
            output_tokens: 7
        }
    );
    h.settle_profile_execution(s.request_id.unwrap(), Some(7), terminal(&s))
        .await
        .unwrap();
    assert_eq!(sum(&h, p).await.output_tokens, 7);
    finish(h, j).await;
}

#[tokio::test]
async fn reauthentication_while_unlocked_never_recovers_a_live_pending_request() {
    use rekey_vault::secret::SecretInput;
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let p = PrincipalId::new_random();
    let s = draft(p);
    begin(&h, limits(Some(20)), s.clone()).await.unwrap();
    let (key, _) = h
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    let rev = revision(&db);
    for _ in 0..2 {
        h.desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .unwrap();
        h.unlock(common::password_proof()).await.unwrap();
        assert_eq!(
            sum(&h, p).await,
            UsageTotals {
                requests: 1,
                output_tokens: 0
            }
        );
        assert_eq!(revision(&db), rev);
        let n: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.indeterminate'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }
    h.settle_profile_execution(s.request_id.unwrap(), Some(7), terminal(&s))
        .await
        .unwrap();
    assert_eq!(
        sum(&h, p).await,
        UsageTotals {
            requests: 1,
            output_tokens: 7
        }
    );
    finish(h, j).await;
}

#[tokio::test]
async fn profile_context_is_authenticated_and_terminal_cannot_rewrite_it() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let principal = PrincipalId::new_random();
    let started = profile_draft(principal);
    begin(&h, limits(Some(30)), started.clone()).await.unwrap();
    for field in 0..5 {
        let mut end = terminal(&started);
        let rekey_domain::audit::RequestAuditContext::Profile(context) =
            end.request_context.as_mut().unwrap()
        else {
            panic!("expected profile fixture")
        };
        match field {
            0 => context.profile_name = "renamed".into(),
            1 => context.policy_sha256 = "02".repeat(32),
            2 => context.instance_slug = "other".into(),
            3 => context.capability = "other".into(),
            4 => context.model = Some("other".into()),
            _ => unreachable!(),
        }
        assert!(matches!(
            h.settle_profile_execution(started.request_id.unwrap(), Some(7), end)
                .await,
            Err(AuthorityError::Domain(_))
        ));
    }
    let end = terminal(&started);
    for _ in 0..2 {
        h.settle_profile_execution(started.request_id.unwrap(), Some(7), end.clone())
            .await
            .unwrap();
    }
    let page = h
        .audit_query(audit_query(started.request_id.unwrap()))
        .await
        .unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(
        page.events
            .iter()
            .all(|row| row.request_context == started.request_context)
    );
    assert_eq!(
        page.events
            .iter()
            .filter_map(|row| row.usage.as_ref())
            .map(|usage| usage.output_tokens)
            .sum::<u64>(),
        7
    );
    assert_eq!(h.status().await.unwrap().state, "unlocked");
    let next = profile_draft(principal);
    begin(&h, limits(Some(3)), next).await.unwrap();
    let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
    db.execute_batch("UPDATE profile_usage SET context_json=replace(context_json, 'original-profile', 'forged-profile')").unwrap();
    assert!(matches!(
        h.profile_usage(principal, "sample-model".into(), now() / 86_400_000)
            .await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    finish(h, j).await;
}

#[tokio::test]
async fn connection_usage_is_bound_to_connection_and_settles_once() {
    let v = common::init_test_vault();
    let (h, j) = common::spawn(&v.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let principal = PrincipalId::new_random();
    let mut started = draft(principal);
    let auth = started.authorization.as_mut().unwrap();
    auth.resource_type = "connection".into();
    auth.resource_id = "sample-model".into();
    started.request_context = Some(
        rekey_domain::connection::ConnectionRequestAuditContext {
            connection: "sample-model".into(),
            caller: "synthetic".into(),
            method_class: rekey_domain::connection::MethodClass::Write,
            normalized_path: "/v1/messages".into(),
            rule_id: auth.policy_rule_id,
        }
        .into(),
    );
    let mut wrong = limits(Some(30));
    wrong.instance_slug = "other-connection".into();
    assert!(matches!(
        begin(&h, wrong, started.clone()).await,
        Err(AuthorityError::Domain(_))
    ));
    assert_eq!(
        begin(&h, limits(Some(30)), started.clone()).await.unwrap(),
        UsageAdmission::Started
    );
    let end = terminal(&started);
    for _ in 0..2 {
        h.settle_profile_execution(started.request_id.unwrap(), Some(7), end.clone())
            .await
            .unwrap();
    }
    assert_eq!(
        sum(&h, principal).await,
        UsageTotals {
            requests: 1,
            output_tokens: 7
        }
    );
    assert!(
        h.audit_query(audit_query(started.request_id.unwrap()))
            .await
            .unwrap()
            .events
            .iter()
            .all(|row| row.request_context == started.request_context)
    );
    finish(h, j).await;
}
