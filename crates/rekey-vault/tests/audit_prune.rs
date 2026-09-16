//! Explicit audit pruning preserves whole execution groups and invalidates old snapshots.
mod common;

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rekey_domain::audit::{AuditPruneRequest, AuditQuery};
use rekey_domain::ids::{ApprovalRequestId, PolicyRuleId, PrincipalId, RequestId};
use rekey_vault::command::UnlockProof;
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{AuditEvent, AuthorizationEvidence, event_type};
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use rusqlite::Connection;

fn query() -> AuditQuery {
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
        limit: 100,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn event(request: RequestId, kind: &'static str, time: i64) -> AuditEvent {
    AuditEvent {
        event_id: rekey_vault::crypto::random_array().unwrap(),
        request_id: Some(request),
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: kind,
        outcome: "success",
        reason_code: "test".into(),
        upstream_status: None,
        latency_ms: None,
        created_at_ms: time,
    }
}

fn append(store: &mut SqliteRecordStore, request: RequestId, events: &[(&'static str, i64)]) {
    for (kind, time) in events {
        store.append_audit(&event(request, kind, *time)).unwrap();
    }
}

fn count(db: &Connection, request: RequestId) -> i64 {
    db.query_row(
        "SELECT count(*) FROM audit_events WHERE request_id = ?1",
        [request.as_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

fn markers(db: &Connection) -> i64 {
    db.query_row(
        "SELECT count(*) FROM audit_events WHERE event_type = 'audit.pruned'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn sequences(db: &Connection) -> Vec<i64> {
    db.prepare(
        "SELECT sequence FROM audit_events WHERE event_type != 'runtime.faulted' ORDER BY sequence",
    )
    .unwrap()
    .query_map([], |row| row.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

#[tokio::test]
async fn prune_selects_all_three_terminals_and_keeps_approval_management_and_anomalous_groups() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let mut removed = Vec::new();
    for terminal in [
        event_type::EXECUTION_FINISHED,
        event_type::EXECUTION_BLOCKED,
        event_type::EXECUTION_INDETERMINATE,
    ] {
        let id = RequestId::new_random();
        append(
            &mut store,
            id,
            &[
                (event_type::EXECUTION_STARTED, 10),
                (event_type::GITHUB_CONNECTOR_AUTHORIZED, 11),
                (event_type::GITHUB_TOKEN_REVOKED, 12),
                (event_type::VAULT_LEASE_ISSUED, 13),
                (event_type::VAULT_LEASE_REVOKED, 14),
                (terminal, 20),
            ],
        );
        removed.push(id);
    }
    // The real schema rejects duplicate starts/terminals before pruning.
    assert!(matches!(
        store.append_audit(&event(removed[0], event_type::EXECUTION_STARTED, 15)),
        Err(AuthorityError::AuditCommitFailed)
    ));
    assert!(matches!(
        store.append_audit(&event(removed[0], event_type::EXECUTION_BLOCKED, 15)),
        Err(AuthorityError::AuditCommitFailed)
    ));
    let retained_cases: &[&[(&str, i64)]] = &[
        &[
            (event_type::EXECUTION_STARTED, 10),
            (event_type::EXECUTION_FINISHED, 100),
        ],
        &[
            (event_type::EXECUTION_STARTED, 10),
            (event_type::EXECUTION_FINISHED, 101),
        ],
        &[(event_type::EXECUTION_STARTED, 10)],
        &[(event_type::EXECUTION_BLOCKED, 20)],
        &[
            (event_type::EXECUTION_FINISHED, 10),
            (event_type::EXECUTION_STARTED, 20),
        ],
        &[
            (event_type::EXECUTION_STARTED, 10),
            (event_type::VAULT_LOCKED, 15),
            (event_type::EXECUTION_FINISHED, 20),
        ],
        &[
            (event_type::EXECUTION_STARTED, 10),
            ("unknown.future.event", 15),
            (event_type::EXECUTION_FINISHED, 20),
        ],
    ];
    let mut retained = Vec::new();
    for events in retained_cases {
        let id = RequestId::new_random();
        append(&mut store, id, events);
        retained.push((id, events.len() as i64));
    }
    // A valid approval rejection may carry no approval identifiers at all.
    let id = RequestId::new_random();
    append(&mut store, id, &[(event_type::EXECUTION_STARTED, 10)]);
    let mut approval = event(id, event_type::APPROVAL_REJECTED, 15);
    approval.authorization = Some(AuthorizationEvidence {
        principal_id: PrincipalId::new_random(),
        policy_version: 1,
        policy_digest: [1; 32],
        policy_rule_id: Some(PolicyRuleId::new_random()),
        resource_type: "test".into(),
        resource_id: "test".into(),
        parameter_hash: [2; 32],
    });
    store.append_audit(&approval).unwrap();
    append(&mut store, id, &[(event_type::EXECUTION_FINISHED, 20)]);
    retained.push((id, 3));
    // Even unexpected approval fields on a non-approval connector event retain
    // the whole group. They must not be hidden by pruning its execution rows.
    for column in ["approval_request_id", "approval_id", "approver_id"] {
        let id = RequestId::new_random();
        append(
            &mut store,
            id,
            &[
                (event_type::EXECUTION_STARTED, 10),
                (event_type::VAULT_LEASE_ISSUED, 15),
                (event_type::EXECUTION_FINISHED, 20),
            ],
        );
        db.execute(&format!("UPDATE audit_events SET {column} = ?1 WHERE request_id = ?2 AND event_type = 'vault.lease.issued'"),
            rusqlite::params![ApprovalRequestId::new_random().as_bytes().as_slice(), id.as_bytes().as_slice()]).unwrap();
        retained.push((id, 3));
    }
    drop(store);
    let receipt = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: 100 },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!((receipt.deleted_groups, receipt.deleted_rows), (3, 18));
    assert!(receipt.prune_sequence.is_some());
    for id in removed {
        assert_eq!(count(&db, id), 0);
    }
    for (id, expected) in retained {
        assert_eq!(count(&db, id), expected);
    }
    let second = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: 100 },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        (
            second.deleted_rows,
            second.deleted_groups,
            second.prune_sequence
        ),
        (0, 0, None)
    );
    assert_eq!(markers(&db), 1);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn prune_snapshot_invalidation_is_global_persistent_and_noop_does_not_invalidate() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let id = RequestId::new_random();
    append(
        &mut store,
        id,
        &[
            (event_type::EXECUTION_STARTED, 10),
            (event_type::EXECUTION_FINISHED, 20),
        ],
    );
    drop(store);
    let snapshot = handle
        .audit_query(query())
        .await
        .unwrap()
        .snapshot_max_sequence;
    let unchanged = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: 0 },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(unchanged.prune_sequence, None);
    let old = AuditQuery {
        snapshot_max_sequence: Some(snapshot),
        ..query()
    };
    assert!(handle.audit_query(old.clone()).await.is_ok());
    let receipt = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: 100 },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let marker = receipt.prune_sequence.unwrap();
    assert!(marker > snapshot);
    for filtered in [
        old.clone(),
        AuditQuery {
            request_id: Some(RequestId::new_random()),
            outcome: Some("never-matches".into()),
            until_ms: Some(0),
            ..old.clone()
        },
    ] {
        assert!(matches!(
            handle.audit_query(filtered).await,
            Err(AuthorityError::AuditSnapshotExpired)
        ));
    }
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    assert!(
        handle
            .audit_query(AuditQuery {
                snapshot_max_sequence: Some(marker),
                ..query()
            })
            .await
            .is_ok()
    );
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(matches!(
        handle.audit_query(old).await,
        Err(AuthorityError::AuditSnapshotExpired)
    ));
    assert_eq!(handle.status().await.unwrap().state, "locked");
    assert!(handle.audit_query(query()).await.is_ok());
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn prune_retains_unfinished_execution_and_two_restarts_do_not_duplicate_reconciliation() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let finished = RequestId::new_random();
    let orphan = RequestId::new_random();
    append(
        &mut store,
        finished,
        &[
            (event_type::EXECUTION_STARTED, 10),
            (event_type::EXECUTION_FINISHED, 20),
        ],
    );
    append(&mut store, orphan, &[(event_type::EXECUTION_STARTED, 10)]);
    drop(store);
    let receipt = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: 100 },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(receipt.deleted_groups, 1);
    assert_eq!(count(&db, orphan), 1);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    for restart in 0..2 {
        let (handle, join) = common::spawn(&vault.state_dir);
        assert_eq!(count(&db, finished), 0);
        assert_eq!(
            count(&db, orphan),
            2,
            "one recovery terminal across restarts"
        );
        handle.unlock(common::password_proof()).await.unwrap();
        if restart == 0 {
            // A fresh execution after pruning is an ordinary complete group.
            let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
            let new = RequestId::new_random();
            append(
                &mut store,
                new,
                &[
                    (event_type::EXECUTION_STARTED, 30),
                    (event_type::EXECUTION_BLOCKED, 40),
                ],
            );
            drop(store);
            let receipt = handle
                .audit_prune_before(
                    AuditPruneRequest { before_ms: 100 },
                    common::password_proof(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(receipt.deleted_groups, 1);
            assert_eq!(count(&db, new), 0);
        }
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    assert_eq!(markers(&db), 2);
}

#[tokio::test]
async fn prune_requires_unlock_proof_valid_cutoff_and_current_deadline() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let request = AuditPruneRequest { before_ms: 100 };
    assert!(matches!(
        handle
            .audit_prune_before(request.clone(), common::password_proof(), None)
            .await,
        Err(AuthorityError::Locked)
    ));
    handle.unlock(common::password_proof()).await.unwrap();
    assert!(matches!(
        handle
            .audit_prune_before(
                request.clone(),
                UnlockProof::Password(SecretInput::from_slice(b"wrong")),
                None
            )
            .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    for cutoff in [-1, i64::MAX] {
        assert!(matches!(
            handle
                .audit_prune_before(
                    AuditPruneRequest { before_ms: cutoff },
                    common::password_proof(),
                    None
                )
                .await,
            Err(AuthorityError::Domain(_))
        ));
    }
    assert!(matches!(
        handle
            .audit_prune_before(request, common::password_proof(), Some(Instant::now()))
            .await,
        Err(AuthorityError::AuthorityBusy)
    ));
    let receipt = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: now() },
            UnlockProof::Recovery(SecretInput::from_slice(
                vault.outcome.recovery_key_display.as_bytes(),
            )),
            None,
        )
        .await
        .unwrap();
    assert_eq!(receipt.deleted_rows, 0);
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(markers(&db), 0);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn prune_corruption_later_sql_audit_and_commit_failures_roll_back_every_group() {
    for mode in ["corrupt", "sql", "audit", "commit"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let mut store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
        for byte in [1, 2] {
            append(
                &mut store,
                RequestId::from_bytes([byte; 16]).unwrap(),
                &[
                    (event_type::EXECUTION_STARTED, 10),
                    (event_type::EXECUTION_FINISHED, 20),
                ],
            );
        }
        drop(store);
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        match mode {
            "corrupt" => { db.execute("UPDATE audit_events SET action_version = -1 WHERE request_id = ?1", [[2u8; 16].as_slice()]).unwrap(); }
            "sql" => db.execute_batch("CREATE TRIGGER fail_second_group BEFORE DELETE ON audit_events WHEN OLD.request_id = X'02020202020202020202020202020202' BEGIN SELECT RAISE(ABORT, 'injected later delete'); END;").unwrap(),
            "audit" => db.execute_batch("CREATE TRIGGER fail_prune_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = 'audit.pruned' BEGIN SELECT RAISE(ABORT, 'injected prune audit'); END;").unwrap(),
            "commit" => db.execute_batch("CREATE TABLE test_parent(id INTEGER PRIMARY KEY); CREATE TABLE test_child(id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_prune_commit AFTER INSERT ON audit_events WHEN NEW.event_type = 'audit.pruned' BEGIN INSERT INTO test_child VALUES(1); END;").unwrap(),
            _ => unreachable!(),
        }
        let before = sequences(&db);
        let error = handle
            .audit_prune_before(
                AuditPruneRequest { before_ms: 100 },
                common::password_proof(),
                None,
            )
            .await
            .unwrap_err();
        match mode {
            "corrupt" => assert!(matches!(error, AuthorityError::StorageIntegrityFailed)),
            "sql" => assert!(matches!(error, AuthorityError::StorageUnavailable(_))),
            _ => assert!(matches!(error, AuthorityError::AuditCommitFailed)),
        }
        assert_eq!(sequences(&db), before);
        assert_eq!(markers(&db), 0);
        assert_eq!(
            handle.status().await.unwrap().state,
            if mode == "sql" { "unlocked" } else { "faulted" }
        );
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn prune_many_groups_finishes_within_its_deadline_without_repeated_full_table_deletes() {
    const GROUPS: u64 = 10_000;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let mut db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let tx = db.transaction().unwrap();
    {
        let mut insert = tx.prepare("INSERT INTO audit_events(event_id, request_id, event_type, outcome, reason_code, created_at_ms) VALUES (?1, ?2, ?3, 'success', 'many-groups', 10)").unwrap();
        for group in 1..=GROUPS {
            let mut request = [0x41; 16];
            request[8..].copy_from_slice(&group.to_be_bytes());
            for (index, kind) in [
                event_type::EXECUTION_STARTED,
                event_type::EXECUTION_FINISHED,
            ]
            .into_iter()
            .enumerate()
            {
                let mut event_id = request;
                event_id[0] = index as u8;
                insert
                    .execute(rusqlite::params![
                        event_id.as_slice(),
                        request.as_slice(),
                        kind
                    ])
                    .unwrap();
            }
        }
    }
    tx.commit().unwrap();
    let receipt = handle
        .audit_prune_before(
            AuditPruneRequest { before_ms: 100 },
            common::password_proof(),
            Some(Instant::now() + std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();
    assert_eq!(receipt.deleted_groups, GROUPS);
    assert_eq!(receipt.deleted_rows, GROUPS * 2);
    assert_eq!(markers(&db), 1);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
