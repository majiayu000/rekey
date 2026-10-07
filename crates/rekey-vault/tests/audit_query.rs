mod common;

use rekey_domain::audit::{AUDIT_SCAN_MAX_ROWS, AUDIT_SCHEMA_V2, AuditQuery};
use rekey_domain::ids::{ActionId, CredentialId, PolicyRuleId, PrincipalId, RequestId, SessionId};
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{AuditEvent, AuthorizationEvidence};
use rekey_vault::paths;
use rekey_vault::store::SqliteRecordStore;

fn query(limit: u32) -> AuditQuery {
    AuditQuery {
        request_id: None,
        session_id: None,
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit,
    }
}

#[test]
fn filters_and_stable_snapshot_exclude_later_rows() {
    let vault = common::init_test_vault();
    let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let request_id = RequestId::new_random();
    let session_id = SessionId::new_random();
    let action_id = ActionId::new_random();
    let credential_id = CredentialId::new_random();
    for (byte, outcome, created_at_ms) in [
        (11, "success", 100),
        (12, "denied", 200),
        (13, "success", 300),
    ] {
        store
            .append_audit(&event(
                byte,
                request_id,
                session_id,
                action_id,
                credential_id,
                outcome,
                created_at_ms,
            ))
            .unwrap();
    }

    let mut filtered = query(1);
    filtered.request_id = Some(request_id);
    filtered.session_id = Some(session_id);
    filtered.action_id = Some(action_id);
    filtered.credential_id = Some(credential_id);
    filtered.outcome = Some("success".to_owned());
    filtered.since_ms = Some(100);
    filtered.until_ms = Some(300);
    let first = store.audit_query(&filtered).unwrap();
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].created_at_ms, 300);
    assert_eq!(first.next_before_sequence, Some(first.events[0].sequence));
    assert_eq!(first.events[0].record_type, AUDIT_SCHEMA_V2);

    store
        .append_audit(&event(
            14,
            request_id,
            session_id,
            action_id,
            credential_id,
            "success",
            250,
        ))
        .unwrap();
    filtered.snapshot_max_sequence = Some(first.snapshot_max_sequence);
    filtered.before_sequence = first.next_before_sequence;
    let second = store.audit_query(&filtered).unwrap();
    assert_eq!(second.snapshot_max_sequence, first.snapshot_max_sequence);
    assert_eq!(second.events.len(), 1);
    assert_eq!(second.events[0].created_at_ms, 100);
    assert_eq!(second.next_before_sequence, Some(second.events[0].sequence));
    filtered.before_sequence = second.next_before_sequence;
    let third = store.audit_query(&filtered).unwrap();
    assert!(third.events.is_empty());
    assert_eq!(third.next_before_sequence, None);

    let json = serde_json::to_string(&first).unwrap();
    assert!(!json.contains("private/repository-name"));
    assert!(!json.contains(&"ab".repeat(32)));

    for filtered in [
        AuditQuery {
            request_id: Some(request_id),
            ..query(10)
        },
        AuditQuery {
            session_id: Some(session_id),
            ..query(10)
        },
        AuditQuery {
            action_id: Some(action_id),
            ..query(10)
        },
        AuditQuery {
            credential_id: Some(credential_id),
            ..query(10)
        },
        AuditQuery {
            since_ms: Some(100),
            until_ms: Some(100),
            ..query(10)
        },
    ] {
        assert!(!store.audit_query(&filtered).unwrap().events.is_empty());
    }
    let empty = AuditQuery {
        request_id: Some(RequestId::new_random()),
        ..query(10)
    };
    assert!(store.audit_query(&empty).unwrap().events.is_empty());
}

#[test]
fn selective_queries_advance_after_a_bounded_scan_window() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let mut connection = rusqlite::Connection::open(&db).unwrap();
    let transaction = connection.transaction().unwrap();
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO audit_events
                 (event_id, event_type, outcome, reason_code, created_at_ms)
                 VALUES (?1, 'test.audit', 'success', 'test', ?2)",
            )
            .unwrap();
        for value in 0..=AUDIT_SCAN_MAX_ROWS {
            let mut event_id = [0x42; 16];
            event_id[12..].copy_from_slice(&value.to_be_bytes());
            insert
                .execute(rusqlite::params![event_id.as_slice(), i64::from(value)])
                .unwrap();
        }
    }
    transaction.commit().unwrap();
    drop(connection);

    let store = SqliteRecordStore::open(&db).unwrap();
    let mut filtered = query(100);
    filtered.outcome = Some("never-matches".to_owned());
    let first = store.audit_query(&filtered).unwrap();
    assert!(first.events.is_empty());
    let cursor = first
        .next_before_sequence
        .expect("a full scan window must return a continuation cursor");
    assert!(cursor < first.snapshot_max_sequence);

    filtered.snapshot_max_sequence = Some(first.snapshot_max_sequence);
    filtered.before_sequence = Some(cursor);
    let second = store.audit_query(&filtered).unwrap();
    assert!(second.events.is_empty());
    assert_eq!(second.next_before_sequence, None);
}

#[test]
fn malformed_stored_version_fails_instead_of_skipping_the_row() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let mut store = SqliteRecordStore::open(&db).unwrap();
    let request_id = RequestId::new_random();
    store
        .append_audit(&event(
            21,
            request_id,
            SessionId::new_random(),
            ActionId::new_random(),
            CredentialId::new_random(),
            "success",
            100,
        ))
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute(
            "UPDATE audit_events SET action_version = -1 WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    let store = SqliteRecordStore::open(&db).unwrap();
    let mut filtered = query(10);
    filtered.request_id = Some(request_id);
    assert!(matches!(
        store.audit_query(&filtered),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
}

#[test]
fn malformed_stored_identifier_fails_instead_of_returning_a_partial_page() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let store = SqliteRecordStore::open(&db).unwrap();
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE audit_events SET request_id = X'01' WHERE sequence = 1;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.audit_query(&query(10)),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
}

#[tokio::test]
async fn query_storage_failure_is_returned_without_partial_rows() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let (handle, join) = common::spawn(&vault.state_dir);
    let tamper = rusqlite::Connection::open(&db).unwrap();
    tamper
        .execute_batch("ALTER TABLE audit_events RENAME TO unavailable_audit_events;")
        .unwrap();
    drop(tamper);
    assert!(matches!(
        handle.audit_query(query(10)).await,
        Err(AuthorityError::StorageUnavailable(_))
    ));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn authority_allows_locked_queries_and_rejects_them_after_fault() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(
        !handle
            .audit_query(query(10))
            .await
            .unwrap()
            .events
            .is_empty()
    );

    handle.unlock(common::password_proof()).await.unwrap();
    let tamper = rusqlite::Connection::open(&db).unwrap();
    tamper.execute_batch("DROP TABLE audit_events;").unwrap();
    drop(tamper);
    assert!(matches!(
        handle.lock("test").await,
        Err(AuthorityError::AuditCommitFailed)
    ));
    assert!(matches!(
        handle.audit_query(query(10)).await,
        Err(AuthorityError::Faulted)
    ));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[allow(clippy::too_many_arguments)]
fn event(
    byte: u8,
    request_id: RequestId,
    session_id: SessionId,
    action_id: ActionId,
    credential_id: CredentialId,
    outcome: &'static str,
    created_at_ms: i64,
) -> AuditEvent {
    AuditEvent {
        event_id: [byte; 16],
        request_id: Some(request_id),
        session_id: Some(session_id),
        action_id: Some(action_id),
        action_version: Some(1),
        credential_id: Some(credential_id),
        credential_version: Some(1),
        authorization: Some(AuthorizationEvidence {
            principal_id: PrincipalId::new_random(),
            policy_version: 1,
            policy_digest: [0xcd; 32],
            policy_rule_id: Some(PolicyRuleId::new_random()),
            resource_type: "github.repository".to_owned(),
            resource_id: "private/repository-name".to_owned(),
            parameter_hash: [0xab; 32],
        }),
        approval: None,
        request_context: None,
        usage: None,
        event_type: "test.audit",
        outcome,
        reason_code: "test".to_owned(),
        upstream_status: Some(200),
        latency_ms: Some(1),
        created_at_ms,
    }
}

fn profile_context(model: Option<String>) -> rekey_domain::audit::ProfileRequestAuditContext {
    rekey_domain::audit::ProfileRequestAuditContext {
        profile_name: "writer".into(),
        policy_sha256: "cd".repeat(32),
        instance_slug: "provider".into(),
        capability: "messages".into(),
        model,
    }
}

#[test]
fn large_profile_metadata_pages_keep_whole_records_and_every_cursor() {
    let vault = common::init_test_vault();
    let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let session = SessionId::new_random();
    let model = "\"".repeat(30_000);
    let context = profile_context(Some(model));
    assert!(serde_json::to_vec(&context).unwrap().len() < 64 * 1024);
    let principal = PrincipalId::new_random();
    for byte in 1..=90 {
        let mut row = event(
            byte,
            RequestId::new_random(),
            session,
            ActionId::new_random(),
            CredentialId::new_random(),
            "success",
            1,
        );
        row.event_type = "execution.started";
        row.authorization.as_mut().unwrap().principal_id = principal;
        let mut historical = context.clone();
        if byte % 2 == 0 {
            historical.profile_name = "reader".into();
        }
        row.request_context = Some(historical.into());
        store.append_audit(&row).unwrap();
    }
    let mut query = AuditQuery {
        session_id: Some(session),
        ..query(100)
    };
    let mut ids = std::collections::BTreeSet::new();
    let mut pages = 0;
    let mut names = std::collections::BTreeSet::new();
    loop {
        let page = store.audit_query(&query).unwrap();
        page.validate_for(&query).unwrap();
        assert!(
            serde_json::to_vec(&page).unwrap().len()
                <= rekey_domain::ipc::RESPONSE_BODY_MAX_BYTES as usize
        );
        for row in &page.events {
            let historical = row.request_context.as_ref().unwrap().as_profile().unwrap();
            assert_eq!(row.principal_id, Some(principal));
            assert_eq!(historical.model, context.model);
            assert_eq!(historical.policy_sha256, context.policy_sha256);
            names.insert(historical.profile_name.clone());
            assert!(ids.insert(row.sequence));
        }
        pages += 1;
        if pages == 1 {
            assert!(page.events.len() < 90 && !page.events.is_empty());
            let mut later = event(
                91,
                RequestId::new_random(),
                session,
                ActionId::new_random(),
                CredentialId::new_random(),
                "success",
                1,
            );
            later.request_context = Some(profile_context(None).into());
            store.append_audit(&later).unwrap();
        }
        let Some(before) = page.next_before_sequence else {
            break;
        };
        query.snapshot_max_sequence = Some(page.snapshot_max_sequence);
        query.before_sequence = Some(before);
    }
    assert_eq!(ids.len(), 90);
    assert_eq!(pages, 2);
    assert_eq!(names, ["reader".to_owned(), "writer".to_owned()].into());
}

#[test]
fn malformed_profile_metadata_is_not_silently_skipped_by_filters() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let store = SqliteRecordStore::open(&db).unwrap();
    let connection = rusqlite::Connection::open(&db).unwrap();
    for value in [
        serde_json::json!({"request_context":profile_context(None),"usage":null,"unknown":true}),
        serde_json::json!({"request_context":{"profile_name":"../bad","policy_sha256":"cd".repeat(32),"instance_slug":"provider","capability":"messages","model":null},"usage":null}),
        serde_json::json!({"instance_slug":"provider","utc_day":0,"output_tokens":1,"source":"measured"}),
    ] {
        connection
            .execute(
                "UPDATE audit_events SET metadata_json=?1 WHERE sequence=1",
                [value.to_string()],
            )
            .unwrap();
        let query = AuditQuery {
            request_id: Some(RequestId::new_random()),
            ..query(100)
        };
        assert!(matches!(
            store.audit_query(&query),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }
}

#[tokio::test]
async fn locked_startup_preserves_non_llm_profile_context_in_abandoned_terminal() {
    let vault = common::init_test_vault();
    let request = RequestId::new_random();
    let context = profile_context(None);
    {
        let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
        let mut started = event(
            99,
            request,
            SessionId::new_random(),
            ActionId::new_random(),
            CredentialId::new_random(),
            "success",
            1,
        );
        started.event_type = "execution.started";
        started.request_context = Some(context.clone().into());
        store.append_audit(&started).unwrap();
    }
    let (handle, join) = common::spawn(&vault.state_dir);
    assert_eq!(handle.status().await.unwrap().state, "locked");
    let page = handle
        .audit_query(AuditQuery {
            request_id: Some(request),
            ..query(100)
        })
        .await
        .unwrap();
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].event_type, "execution.indeterminate");
    assert!(page.events.iter().all(|row| {
        row.request_context
            .as_ref()
            .and_then(|ctx| ctx.as_profile())
            == Some(&context)
    }));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}
