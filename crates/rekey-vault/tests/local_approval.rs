mod common;

use std::time::{Duration, Instant};

use rekey_domain::ids::{
    ActionId, ApprovalId, ApprovalRequestId, PolicyRuleId, PrincipalId, RequestId, SessionId,
};
use rekey_vault::command::AuditDraft;
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{ApprovalEvidence, AuthorizationEvidence, event_type, outcome};
use rekey_vault::secret::SecretInput;

fn draft(approved: bool) -> AuditDraft {
    AuditDraft {
        request_id: Some(RequestId::new_random()),
        session_id: Some(SessionId::new_random()),
        action_id: Some(ActionId::new_random()),
        action_version: Some(1),
        credential_id: None,
        credential_version: None,
        authorization: Some(Box::new(AuthorizationEvidence {
            principal_id: PrincipalId::new_random(),
            policy_version: 1,
            policy_digest: [1; 32],
            policy_rule_id: Some(PolicyRuleId::new_random()),
            resource_type: "test.resource".into(),
            resource_id: "synthetic-resource".into(),
            parameter_hash: [2; 32],
        })),
        approval: Some(ApprovalEvidence {
            approval_request_id: ApprovalRequestId::new_random(),
            approval_id: approved.then(ApprovalId::new_random),
            approver_id: None,
        }),
        request_context: Some(
            rekey_domain::audit::ProfileRequestAuditContext {
                profile_name: "local-writer".into(),
                policy_sha256: "01".repeat(32),
                instance_slug: "repo".into(),
                capability: "issues".into(),
                model: None,
            }
            .into(),
        ),
        usage: None,
        event_type: if approved {
            event_type::APPROVAL_APPROVED
        } else {
            event_type::APPROVAL_REJECTED
        },
        outcome: outcome::SUCCESS,
        reason_code: "local-presence".into(),
        upstream_status: None,
        latency_ms: None,
    }
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn deadlines() -> (Instant, i64) {
    (Instant::now() + Duration::from_secs(10), now_ms() + 10_000)
}
fn count(db: &rusqlite::Connection, kind: &str) -> i64 {
    db.query_row(
        "SELECT count(*) FROM audit_events WHERE event_type=?1",
        [kind],
        |row| row.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn current_presence_commits_only_fixed_decisions_and_public_evidence() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    for approved in [true, false] {
        let event = draft(approved);
        let challenge = event.approval.as_ref().unwrap().approval_request_id;
        let (deadline, wall) = deadlines();
        handle
            .authorize_local_approval(SecretInput::from_slice(&key), event.clone(), deadline, wall)
            .await
            .unwrap();
        type DecisionRow = (
            String,
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<i64>,
        );
        let row: DecisionRow = db.query_row(
            "SELECT outcome,reason_code,approval_id,approver_id,parameter_hash,credential_id,upstream_status FROM audit_events WHERE approval_request_id=?1",
            [challenge.as_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
        ).unwrap();
        assert_eq!(
            (row.0.as_str(), row.1.as_str()),
            ("success", "local-presence")
        );
        assert_eq!(row.2.is_some(), approved);
        assert!(row.3.is_none() && row.5.is_none() && row.6.is_none());
        assert_eq!(row.4, [2; 32]);
        assert!(!format!("{event:?}").contains(std::str::from_utf8(&key).unwrap()));
        if approved {
            let mut accepted = event.clone();
            accepted.event_type = event_type::APPROVAL_ACCEPTED;
            handle.append_audit(accepted).await.unwrap();
        }
        let page = handle
            .audit_query(rekey_domain::audit::AuditQuery {
                request_id: event.request_id,
                session_id: None,
                action_id: None,
                credential_id: None,
                outcome: None,
                since_ms: None,
                until_ms: None,
                snapshot_max_sequence: None,
                before_sequence: None,
                limit: 100,
            })
            .await
            .unwrap();
        assert_eq!(page.events.len(), if approved { 2 } else { 1 });
        assert!(
            page.events
                .iter()
                .all(|row| row.request_context == event.request_context)
        );
    }
    assert_eq!(count(&db, event_type::APPROVAL_APPROVED), 1);
    assert_eq!(count(&db, event_type::APPROVAL_REJECTED), 1);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn missing_wrong_a1_old_presence_and_locked_or_faulted_never_authorize() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let (deadline, wall) = deadlines();
    assert!(matches!(
        handle
            .authorize_local_approval(SecretInput::from_slice(b""), draft(true), deadline, wall)
            .await,
        Err(AuthorityError::Locked)
    ));
    handle.unlock(common::password_proof()).await.unwrap();
    let a1 = handle.desktop_issue().await.unwrap();
    let (old, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    for proof in [
        b"".as_slice(),
        b"wrong-K",
        common::PASSWORD,
        a1.as_slice(),
        old.as_slice(),
    ] {
        let (deadline, wall) = deadlines();
        let error = handle
            .authorize_local_approval(SecretInput::from_slice(proof), draft(true), deadline, wall)
            .await
            .unwrap_err();
        assert!(matches!(error, AuthorityError::InvalidUnlockCredential));
        assert!(!error.to_string().contains("wrong-K"));
        assert_eq!(handle.status().await.unwrap().state, "unlocked");
        // Test each rejected factor independently of the shared backoff contract.
        handle
            .verify_shutdown_proof(common::password_proof())
            .await
            .unwrap();
    }
    assert_eq!(count(&db, event_type::APPROVAL_APPROVED), 0);
    assert!(matches!(
        handle.fault_integrity().await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    let (deadline, wall) = deadlines();
    assert!(matches!(
        handle
            .authorize_local_approval(SecretInput::from_slice(&key), draft(true), deadline, wall)
            .await,
        Err(AuthorityError::Faulted)
    ));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn fixed_audit_boundary_rejects_unrelated_types_fields_and_missing_context() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    for change in 0..13 {
        let mut event = draft(true);
        match change {
            0 => event.event_type = event_type::EXECUTION_STARTED,
            1 => event.reason_code = "INJECTED-BODY-CANARY".into(),
            2 => event.outcome = outcome::FAILURE,
            3 => event.session_id = None,
            4 => event.action_id = None,
            5 => event.action_version = Some(0),
            6 => event.authorization = None,
            7 => event.approval = None,
            8 => event.approval.as_mut().unwrap().approval_id = None,
            9 => {
                event.approval.as_mut().unwrap().approver_id =
                    Some(rekey_domain::ids::ApproverId::new_random())
            }
            10 => event.credential_version = Some(1),
            11 => event.upstream_status = Some(200),
            12 => event.latency_ms = Some(1),
            _ => unreachable!(),
        }
        let (deadline, wall) = deadlines();
        let error = handle
            .authorize_local_approval(SecretInput::from_slice(&key), event, deadline, wall)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "INVALID_INPUT");
        assert!(!error.to_string().contains("INJECTED-BODY-CANARY"));
    }
    assert_eq!(count(&db, event_type::APPROVAL_APPROVED), 0);
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn both_clocks_expiring_after_sql_insert_roll_back_without_fault() {
    for wall_clock in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let (key, _) = handle
            .desktop_remember(common::password_proof(), None)
            .await
            .unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch("CREATE TRIGGER delay_local_decision AFTER INSERT ON audit_events WHEN NEW.event_type='approval.approved' BEGIN
            SELECT CASE WHEN EXISTS(SELECT 1 FROM audit_events WHERE event_id=NEW.event_id) THEN 1 ELSE RAISE(ABORT,'insert not reached') END;
            SELECT sum(value) FROM (WITH RECURSIVE counter(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM counter WHERE value<10000000) SELECT value FROM counter);
        END;").unwrap();
        let started = Instant::now();
        let (mut deadline, mut wall) = deadlines();
        if wall_clock {
            wall = now_ms() + 200;
        } else {
            deadline = started + Duration::from_millis(200);
        }
        let result = handle
            .authorize_local_approval(SecretInput::from_slice(&key), draft(true), deadline, wall)
            .await;
        assert!(matches!(result, Err(AuthorityError::AuthorityBusy)));
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "must enter delayed SQL work rather than fail early"
        );
        assert_eq!(count(&db, event_type::APPROVAL_APPROVED), 0);
        assert_eq!(count(&db, event_type::RUNTIME_FAULTED), 0);
        assert_eq!(handle.status().await.unwrap().state, "unlocked");
        db.execute_batch("DROP TRIGGER delay_local_decision")
            .unwrap();
        let (deadline, wall) = deadlines();
        handle
            .authorize_local_approval(SecretInput::from_slice(&key), draft(true), deadline, wall)
            .await
            .unwrap();
        assert_eq!(count(&db, event_type::APPROVAL_APPROVED), 1);
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn insert_and_deferred_commit_failure_fault_without_success_audit() {
    for commit_failure in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let (key, _) = handle
            .desktop_remember(common::password_proof(), None)
            .await
            .unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        if commit_failure {
            db.execute_batch("CREATE TABLE test_parent(id INTEGER PRIMARY KEY);CREATE TABLE test_child(id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED);
                CREATE TRIGGER deny_local_commit AFTER INSERT ON audit_events WHEN NEW.event_type='approval.approved' BEGIN INSERT INTO test_child VALUES(1);END;").unwrap();
        } else {
            db.execute_batch("CREATE TRIGGER deny_local_insert BEFORE INSERT ON audit_events WHEN NEW.event_type='approval.approved' BEGIN SELECT RAISE(ABORT,'synthetic audit failure');END;").unwrap();
        }
        let (deadline, wall) = deadlines();
        assert!(matches!(
            handle
                .authorize_local_approval(
                    SecretInput::from_slice(&key),
                    draft(true),
                    deadline,
                    wall
                )
                .await,
            Err(AuthorityError::AuditCommitFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert_eq!(count(&db, event_type::APPROVAL_APPROVED), 0);
        assert_eq!(count(&db, event_type::RUNTIME_FAULTED), 1);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}
