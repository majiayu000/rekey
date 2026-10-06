//! Opt-in measurement of the exact authenticated SQLite methods called by
//! Authority. Fixture seeding is outside timing; this is not an end-to-end
//! Broker, unlock, backup or production-latency claim.
use super::*;
use crate::model::AuthorizationEvidence;
use rekey_domain::ids::{ActionId, CredentialId, PolicyRuleId, SessionId};
use std::time::Duration;

fn context() -> UsageContext {
    UsageContext {
        request_context: None,
        session_id: SessionId::new_random(),
        action_id: ActionId::new_random(),
        action_version: 1,
        credential_id: CredentialId::new_random(),
        credential_version: None,
        authorization: AuthorizationEvidence {
            principal_id: PrincipalId::new_random(),
            policy_version: 1,
            policy_digest: [2; 32],
            policy_rule_id: Some(PolicyRuleId::new_random()),
            resource_type: "connection".into(),
            resource_id: "history-fixture".into(),
            parameter_hash: [3; 32],
        },
    }
}

fn row(context: &UsageContext) -> UsageRecord {
    UsageRecord {
        request_id: RequestId::new_random(),
        principal_id: context.authorization.principal_id,
        instance_slug: "history-fixture".into(),
        utc_day: 3,
        started_at_ms: 3 * 86_400_000 + 100,
        context_json: serde_json::to_string(context).unwrap(),
        generation_max_output: Some(32),
        output_tokens: None,
        source: None,
        terminal_json: None,
        settled_at_ms: None,
    }
}

fn event(context: &UsageContext, request: RequestId, terminal: bool) -> AuditEvent {
    AuditEvent {
        event_id: *RequestId::new_random().as_bytes(),
        request_id: Some(request),
        session_id: Some(context.session_id),
        action_id: Some(context.action_id),
        action_version: Some(context.action_version),
        credential_id: Some(context.credential_id),
        credential_version: None,
        authorization: Some(context.authorization.clone()),
        approval: None,
        request_context: None,
        usage: None,
        event_type: if terminal {
            event_type::EXECUTION_FINISHED
        } else {
            event_type::EXECUTION_STARTED
        },
        outcome: outcome::SUCCESS,
        reason_code: if terminal { "finished" } else { "started" }.into(),
        upstream_status: terminal.then_some(200),
        latency_ms: terminal.then_some(1),
        created_at_ms: now_ms().unwrap(),
    }
}

fn timings(mut values: Vec<u128>) -> serde_json::Value {
    values.sort_unstable();
    serde_json::json!({"samples":values.len(),"min_us":values[0],"median_us":values[values.len()/2],"max_us":values[values.len()-1]})
}

#[test]
#[ignore = "opt-in authenticated SQLite history benchmark; uses 1k/10k/100k synthetic rows"]
fn authenticated_usage_history_benchmark() {
    for size in [1_000, 10_000, 100_000] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteRecordStore::create(&dir.path().join("history.db")).unwrap();
        let vault = VaultId::new_random();
        let key = [17; 32];
        let context = context();
        let mut rows = Vec::with_capacity(size);
        for index in 0..size {
            let mut row = row(&context);
            row.instance_slug = format!("history-{}", index % 4);
            row.utc_day = 3 + (index % 30) as i64;
            row.started_at_ms = row.utc_day * 86_400_000 + 100;
            // Keep a small pending share, as in an interrupted historical run.
            if index % 4096 != 0 {
                let mut terminal = event(&context, row.request_id, true);
                terminal.created_at_ms = row.started_at_ms + 10;
                settle_row(&mut row, Some(7), &mut terminal).unwrap();
            }
            rows.push(row);
        }
        rows.sort_by_key(|row| row.request_id);
        let state = crypto::usage::seal(&key, vault, &rows, 1).unwrap();
        let tx = store.conn.transaction().unwrap();
        for row in &rows {
            write(&tx, row, true).unwrap();
        }
        initial_state(&tx, &state).unwrap();
        tx.commit().unwrap();
        drop(rows);
        assert_eq!(store.verified_usage(&key, vault).unwrap().0.len(), size);
        let usage = ProfileUsageStart {
            instance_slug: "history-fixture".into(),
            max_requests_per_day: 1_000_000,
            max_output_tokens_per_day: 1_000_000_000,
            generation_max_output: Some(32),
        };
        let mut verified = Vec::new();
        let mut started = Vec::new();
        let mut settled = Vec::new();
        for _ in 0..5 {
            let began = Instant::now();
            let _ = store.verified_usage(&key, vault).unwrap();
            verified.push(began.elapsed().as_micros());
            let row = row(&context);
            let request = row.request_id;
            let started_event = event(&context, request, false);
            let began = Instant::now();
            assert!(matches!(
                store
                    .begin_profile_execution(
                        &key,
                        vault,
                        row,
                        &usage,
                        &[started_event],
                        Instant::now() + Duration::from_secs(30),
                        None
                    )
                    .unwrap(),
                UsageAdmission::Started
            ));
            started.push(began.elapsed().as_micros());
            let terminal = event(&context, request, true);
            let began = Instant::now();
            store
                .settle_profile_execution(&key, vault, request, Some(7), terminal)
                .unwrap();
            settled.push(began.elapsed().as_micros());
        }
        assert_eq!(store.verified_usage(&key, vault).unwrap().0.len(), size + 5);
        let rss_kib = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find(|line| line.starts_with("VmRSS:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|value| value.parse::<u64>().ok())
            });
        println!(
            "{}",
            serde_json::json!({"history_rows":size,"pending_history_rows":size.div_ceil(4096),
            "authenticated_read":timings(verified),"started":timings(started),"settled":timings(settled),
            "process_rss_kib":rss_kib,"debug_assertions":cfg!(debug_assertions),
            "scope":"authenticated SQLite store methods; excludes Authority queue and network"})
        );
    }
}
