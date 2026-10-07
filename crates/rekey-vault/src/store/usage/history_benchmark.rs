//! Opt-in measurement of the exact authenticated SQLite methods called by
//! Authority, plus the actual Authority queue and lifecycle. Fixture seeding is
//! outside timing. Neither benchmark invokes Broker IPC or a real provider.
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

fn history(context: &UsageContext, size: usize) -> Vec<UsageRecord> {
    let mut rows = Vec::with_capacity(size);
    for index in 0..size {
        let mut row = row(context);
        row.instance_slug = format!("history-{}", index % 4);
        row.utc_day = 3 + (index % 30) as i64;
        row.started_at_ms = row.utc_day * 86_400_000 + 100;
        // A small pending share exercises conservative recovery on unlock.
        if index % 4096 != 0 {
            let mut terminal = event(context, row.request_id, true);
            terminal.created_at_ms = row.started_at_ms + 10;
            settle_row(&mut row, Some(7), &mut terminal).unwrap();
        }
        rows.push(row);
    }
    rows.sort_by_key(|row| row.request_id);
    rows
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
        let rows = history(&context, size);
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

fn proof() -> crate::command::UnlockProof {
    crate::command::UnlockProof::Password(crate::secret::SecretInput::from_slice(
        b"synthetic-history-benchmark-only",
    ))
}

fn draft(context: &UsageContext) -> crate::command::AuditDraft {
    crate::command::AuditDraft {
        request_id: Some(RequestId::new_random()),
        session_id: Some(context.session_id),
        action_id: Some(context.action_id),
        action_version: Some(context.action_version),
        credential_id: Some(context.credential_id),
        credential_version: None,
        authorization: Some(Box::new(context.authorization.clone())),
        approval: None,
        request_context: None,
        usage: None,
        event_type: event_type::EXECUTION_STARTED,
        outcome: outcome::SUCCESS,
        reason_code: "history-benchmark".into(),
        upstream_status: None,
        latency_ms: None,
    }
}

fn rss_field(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[tokio::test]
#[ignore = "opt-in real Authority history benchmark; uses 1k/10k/100k synthetic rows"]
async fn authority_usage_history_benchmark() {
    use crate::bootstrap::{confirm_vault_init, init_vault, kek_for_wrapper, unwrap_vrk};
    use crate::crypto::kdf::Argon2Params;
    use crate::handle::AuthorityConfig;
    use crate::model::WrapperKind;
    use crate::secret::SecretInput;

    for size in [1_000, 10_000, 100_000] {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let password = SecretInput::from_slice(b"synthetic-history-benchmark-only");
        init_vault(
            &state_dir,
            &password,
            Argon2Params::RFC9106_LOW_MEMORY,
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        confirm_vault_init(&state_dir).unwrap();
        let context = context();
        {
            // Seed an authenticated synthetic ledger while no Authority runs.
            // This avoids O(N^2) fixture setup; timed operations use the normal
            // handle, worker, SQLite transaction, audit and authentication path.
            let mut store = SqliteRecordStore::open(&crate::paths::vault_db(&state_dir)).unwrap();
            let header = store.load_header().unwrap();
            let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
            let kek = kek_for_wrapper(&wrapper, &password).unwrap();
            let key = unwrap_vrk(header.vault_id, &wrapper, &kek).unwrap();
            let rows = history(&context, size);
            let (_, previous) = store.verified_usage(key.bytes(), header.vault_id).unwrap();
            let sealed =
                crypto::usage::seal(key.bytes(), header.vault_id, &rows, previous.revision + 1)
                    .unwrap();
            let tx = store.conn.transaction().unwrap();
            for row in &rows {
                write(&tx, row, true).unwrap();
            }
            replace_state(&tx, &sealed).unwrap();
            tx.commit().unwrap();
            assert_eq!(
                store
                    .verified_usage(key.bytes(), header.vault_id)
                    .unwrap()
                    .0
                    .len(),
                size
            );
        }
        let (handle, worker) =
            crate::authority::spawn_authority(AuthorityConfig::new(state_dir.clone())).unwrap();
        let began = Instant::now();
        handle.unlock(proof()).await.unwrap();
        let recovery_unlock_us = began.elapsed().as_micros();
        let usage = ProfileUsageStart {
            instance_slug: "history-fixture".into(),
            max_requests_per_day: 1_000_000,
            max_output_tokens_per_day: 1_000_000_000,
            generation_max_output: Some(32),
        };
        let mut read = Vec::new();
        let mut started = Vec::new();
        let mut settled = Vec::new();
        let mut status = Vec::new();
        let mut status_during_start = Vec::new();
        let mut backup = Vec::new();
        let mut unlock = Vec::new();
        for sample in 0..5 {
            let began = Instant::now();
            assert_eq!(handle.status().await.unwrap().state, "unlocked");
            status.push(began.elapsed().as_micros());
            let began = Instant::now();
            let totals = handle
                .profile_usage(
                    context.authorization.principal_id,
                    "history-fixture".into(),
                    now_ms().unwrap() / 86_400_000,
                )
                .await
                .unwrap();
            read.push(began.elapsed().as_micros());
            assert_eq!(totals.requests, sample as u64);
            assert_eq!(totals.output_tokens, sample as u64 * 7);

            let start = draft(&context);
            let request = start.request_id.unwrap();
            let ((admitted, started_us), status_us) = tokio::join!(
                biased;
                async {
                    let began = Instant::now();
                    let result = handle.begin_profile_execution(
                        usage.clone(), vec![], start.clone(),
                        Instant::now() + Duration::from_secs(120), None,
                    ).await;
                    (result, began.elapsed().as_micros())
                },
                async {
                    let began = Instant::now();
                    assert_eq!(handle.status().await.unwrap().state, "unlocked");
                    began.elapsed().as_micros()
                },
            );
            assert!(matches!(admitted.unwrap(), UsageAdmission::Started));
            started.push(started_us);
            status_during_start.push(status_us);

            let mut terminal = start;
            terminal.event_type = event_type::EXECUTION_FINISHED;
            terminal.reason_code = "finished".into();
            terminal.upstream_status = Some(200);
            terminal.latency_ms = Some(1);
            let began = Instant::now();
            handle
                .settle_profile_execution(request, Some(7), terminal.clone())
                .await
                .unwrap();
            settled.push(began.elapsed().as_micros());
            // Replay uses the same worker path and must not add another charge.
            handle
                .settle_profile_execution(request, Some(7), terminal)
                .await
                .unwrap();

            let output = dir.path().join(format!("history-{sample}.backup"));
            let began = Instant::now();
            let saved = handle.backup(output.clone(), proof()).await.unwrap();
            backup.push(began.elapsed().as_micros());
            assert_eq!(saved.output_path, output);
            assert!(std::fs::metadata(&output).unwrap().len() > 0);
            std::fs::remove_file(output).unwrap();
            handle.lock("history-benchmark").await.unwrap();
            let began = Instant::now();
            handle.unlock(proof()).await.unwrap();
            unlock.push(began.elapsed().as_micros());
        }
        let totals = handle
            .profile_usage(
                context.authorization.principal_id,
                "history-fixture".into(),
                now_ms().unwrap() / 86_400_000,
            )
            .await
            .unwrap();
        assert_eq!(totals.requests, 5);
        assert_eq!(totals.output_tokens, 35);
        let rss = rss_field("VmRSS:");
        let high_water = rss_field("VmHWM:");
        handle.shutdown(Some(proof())).await.unwrap();
        worker.join().unwrap();
        {
            let store = SqliteRecordStore::open(&crate::paths::vault_db(&state_dir)).unwrap();
            let header = store.load_header().unwrap();
            let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
            let kek = kek_for_wrapper(&wrapper, &password).unwrap();
            let key = unwrap_vrk(header.vault_id, &wrapper, &kek).unwrap();
            let rows = store
                .verified_usage(key.bytes(), header.vault_id)
                .unwrap()
                .0;
            assert_eq!(rows.len(), size + 5);
            assert!(rows.iter().all(|row| row.output_tokens.is_some()));
            assert_eq!(
                rows.iter()
                    .filter(|row| row.output_tokens == Some(32))
                    .count(),
                size.div_ceil(4096)
            );
        }
        println!(
            "{}",
            serde_json::json!({
                "history_rows":size,"pending_history_rows":size.div_ceil(4096),
                "authority_usage_read":timings(read),"authority_started":timings(started),
                "authority_settled":timings(settled),"admin_status":timings(status),
                "admin_status_during_admission":timings(status_during_start),
                "recovery_unlock_us":recovery_unlock_us,"steady_unlock":timings(unlock),
                "backup":timings(backup),"process_rss_kib":rss,"process_peak_rss_kib":high_water,
                "debug_assertions":cfg!(debug_assertions),
                "kdf":Argon2Params::RFC9106_LOW_MEMORY,
                "scope":"real Authority queue, SQLite, audit, backup and password unlock; excludes Broker IPC and network",
            })
        );
    }
}
