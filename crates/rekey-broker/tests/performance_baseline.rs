//! Repeatable H-07 performance, capacity, and soak evidence.
//!
//! This test is ignored by the ordinary workspace suite. The dedicated
//! workflow supplies a bounded duration and report path.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rekey_broker::runtime::{MAX_ADMIN_CONNECTIONS, MAX_AGENT_CONNECTIONS};
use rekey_broker::session::SessionRegistry;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::Timestamp;
use rekey_domain::authorization::Principal;
use rekey_domain::capability::{ActionVersionRef, SESSION_MAX_CONCURRENT_EXECUTIONS, SessionGrant};
use rekey_domain::ids::{ActionId, PrincipalId, RequestId, SessionId, TenantId};
use rekey_domain::ipc::{self, Channel, FrameHeader, admin_msg, agent_msg};
use rekey_vault::bootstrap::{confirm_vault_init, init_vault};
use rekey_vault::command::{AuditDraft, UnlockProof};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::error::AuthorityError;
use rekey_vault::handle::{AuthorityConfig, DEFAULT_QUEUE_CAPACITY};
use rekey_vault::model::{event_type, outcome};
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

const LARGE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const SESSION_USES: u32 = 10_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run through the performance-baseline workflow"]
async fn performance_and_soak_baseline() {
    let soak_seconds = std::env::var("REKEY_SOAK_SECONDS")
        .expect("REKEY_SOAK_SECONDS is required")
        .parse::<u64>()
        .expect("REKEY_SOAK_SECONDS must be an integer");
    assert!((30..=3_600).contains(&soak_seconds));

    let queue = measure_authority_queue_and_audit().await;
    let broker =
        common::start_broker_with(Duration::from_secs(7_200), Duration::from_secs(10)).await;
    let ipc_capacity = measure_ipc_capacity(&broker).await;
    let session_capacity = measure_session_capacity();
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "performance", b"performance-secret").await;
    let (action_id, version) = create_large_action(&broker, &credential_id).await;
    let mut token = create_session(&broker, &action_id, version).await;

    let response_sealing = measure_response_sealing(&broker, &token, &action_id, version).await;
    let backup_interference =
        measure_backup_interference(&broker, &token, &action_id, version).await;

    let soak_started = Instant::now();
    let soak_deadline = soak_started + Duration::from_secs(soak_seconds);
    let lock_interval = if soak_seconds <= 120 { 15 } else { 60 };
    let backup_interval = if soak_seconds <= 120 { 20 } else { 120 };
    let sample_interval = if soak_seconds <= 120 { 5 } else { 10 };
    let mut next_lock = soak_started + Duration::from_secs(lock_interval);
    let mut next_backup = soak_started + Duration::from_secs(backup_interval);
    let mut next_sample = soak_started;
    let mut execution_latencies = Vec::new();
    let mut lock_latencies = Vec::new();
    let mut backup_latencies = Vec::new();
    let mut rss_samples = Vec::new();
    let mut unexpected_errors = 0u64;
    let mut session_uses = 0u32;
    let mut backup_index = 0u64;

    while Instant::now() < soak_deadline {
        if session_uses >= SESSION_USES - 100 {
            token = create_session(&broker, &action_id, version).await;
            session_uses = 0;
        }
        let (latency, response) = execute(&broker, &token, &action_id, version).await;
        execution_latencies.push(latency.as_micros());
        session_uses += 1;
        if response.message_type != ipc::resp_msg::OK {
            unexpected_errors += 1;
        }

        let now = Instant::now();
        if now >= next_lock {
            let started = Instant::now();
            common::call(
                &broker.admin_sock(),
                Channel::Admin,
                admin_msg::LOCK,
                b"{}",
                b"",
            )
            .await
            .ok();
            common::unlock(&broker).await;
            token = create_session(&broker, &action_id, version).await;
            session_uses = 0;
            lock_latencies.push(started.elapsed().as_micros());
            next_lock += Duration::from_secs(lock_interval);
        }
        if now >= next_backup {
            let output = broker
                .dir
                .path()
                .join(format!("soak-{backup_index}.rkbackup"));
            let started = Instant::now();
            backup(&broker, &output).await;
            backup_latencies.push(started.elapsed().as_micros());
            fs::remove_file(output).expect("remove completed soak backup");
            backup_index += 1;
            next_backup += Duration::from_secs(backup_interval);
        }
        if now >= next_sample {
            rss_samples.push(rss_kib());
            next_sample += Duration::from_secs(sample_interval);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    rss_samples.push(rss_kib());
    assert_eq!(
        unexpected_errors, 0,
        "soak request failures are not allowed"
    );
    assert!(!execution_latencies.is_empty());
    assert_memory_stable(&rss_samples);

    let (shutdown_drain, drained_executions) =
        measure_shutdown_drain(&broker, &token, &action_id, version).await;
    let state_dir = broker.state_dir.clone();
    let serve_task = broker.serve_task;
    tokio::time::timeout(Duration::from_secs(15), serve_task)
        .await
        .expect("broker shutdown timed out")
        .expect("serve task panicked")
        .expect("broker shutdown failed");

    let audit =
        rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir))
            .unwrap()
            .audit_execution_log()
            .unwrap();
    let started_count = audit
        .iter()
        .filter(|(_, kind)| kind == event_type::EXECUTION_STARTED)
        .count();
    let terminal_count = audit
        .iter()
        .filter(|(_, kind)| {
            matches!(
                kind.as_str(),
                event_type::EXECUTION_FINISHED
                    | event_type::EXECUTION_BLOCKED
                    | event_type::EXECUTION_INDETERMINATE
            )
        })
        .count();
    assert_eq!(
        started_count, terminal_count,
        "execution audit rows were lost"
    );

    let report = json!({
        "schema_version": 1,
        "commit": command_text("git", &["rev-parse", "HEAD"]),
        "environment": {
            "os": command_text("uname", &["-a"]),
            "arch": std::env::consts::ARCH,
            "rust": command_text("rustc", &["-Vv"]),
            "cpu": cpu_description(),
            "memory": memory_description(),
        },
        "data_scale": {
            "authority_queue_capacity": DEFAULT_QUEUE_CAPACITY,
            "agent_connection_capacity": MAX_AGENT_CONNECTIONS,
            "admin_connection_capacity": MAX_ADMIN_CONNECTIONS,
            "session_concurrency": 4,
            "large_response_bytes": LARGE_RESPONSE_BYTES,
            "soak_seconds": soak_seconds,
        },
        "authority_queue_and_audit": queue,
        "ipc_capacity": ipc_capacity,
        "session_capacity": session_capacity,
        "response_sealing": response_sealing,
        "backup_interference": backup_interference,
        "soak": {
            "executions": execution_latencies.len(),
            "unexpected_errors": unexpected_errors,
            "error_rate": unexpected_errors as f64 / execution_latencies.len() as f64,
            "execution_latency_us": summarize(&execution_latencies),
            "lock_unlock_count": lock_latencies.len(),
            "lock_unlock_latency_us": summarize(&lock_latencies),
            "backup_count": backup_latencies.len(),
            "backup_latency_us": summarize(&backup_latencies),
            "rss_kib": memory_summary(&rss_samples),
            "audit_started": started_count,
            "audit_terminal": terminal_count,
        },
        "shutdown_drain": {
            "latency_us": shutdown_drain.as_micros(),
            "drained_executions": drained_executions,
        }
    });
    write_report(&report);
    println!("REKEY_PERFORMANCE_REPORT={report}");
}

async fn measure_authority_queue_and_audit() -> Value {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    init_vault(
        &state_dir,
        &SecretInput::from_slice(common::PASSWORD),
        Argon2Params::RFC9106_LOW_MEMORY,
    )
    .unwrap();
    confirm_vault_init(&state_dir).unwrap();
    let config = AuthorityConfig::new(state_dir.clone());
    assert_eq!(config.queue_capacity, DEFAULT_QUEUE_CAPACITY);
    let (handle, join) = rekey_vault::authority::spawn_authority(config).unwrap();
    handle
        .unlock(UnlockProof::Password(SecretInput::from_slice(
            common::PASSWORD,
        )))
        .await
        .unwrap();

    let blocker_handle = handle.clone();
    let blocker = tokio::spawn(async move {
        blocker_handle
            .verify_proof(UnlockProof::Password(SecretInput::from_slice(
                common::PASSWORD,
            )))
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let attempts = DEFAULT_QUEUE_CAPACITY * 4;
    let barrier = Arc::new(Barrier::new(attempts + 1));
    let mut tasks = JoinSet::new();
    for _ in 0..attempts {
        let handle = handle.clone();
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            let started = Instant::now();
            let status = handle.status().await;
            (started.elapsed(), status)
        });
    }
    barrier.wait().await;
    let mut accepted_latencies = Vec::new();
    let mut busy = 0usize;
    let mut other_errors = 0usize;
    while let Some(result) = tasks.join_next().await {
        let (latency, status) = result.unwrap();
        match status {
            Ok(_) => accepted_latencies.push(latency.as_micros()),
            Err(AuthorityError::AuthorityBusy) => busy += 1,
            Err(_) => other_errors += 1,
        }
    }
    blocker.await.unwrap().unwrap();
    assert_eq!(accepted_latencies.len(), DEFAULT_QUEUE_CAPACITY);
    assert_eq!(busy, attempts - DEFAULT_QUEUE_CAPACITY);
    assert_eq!(other_errors, 0);

    let mut audit_latencies = Vec::new();
    for _ in 0..500 {
        let started = Instant::now();
        handle.append_audit(audit_draft()).await.unwrap();
        audit_latencies.push(started.elapsed().as_micros());
    }
    let audit_elapsed_us: u128 = audit_latencies.iter().sum();
    handle
        .shutdown(Some(UnlockProof::Password(SecretInput::from_slice(
            common::PASSWORD,
        ))))
        .await
        .unwrap();
    join.join().unwrap();
    let audit_count =
        rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir))
            .unwrap()
            .audit_event_types()
            .unwrap()
            .len();
    assert!(audit_count >= audit_latencies.len());

    json!({
        "attempts": attempts,
        "accepted": accepted_latencies.len(),
        "authority_busy": busy,
        "other_errors": other_errors,
        "accepted_latency_us": summarize(&accepted_latencies),
        "audit_commits": audit_latencies.len(),
        "audit_rows_after_reopen": audit_count,
        "audit_commits_per_second": audit_latencies.len() as f64 * 1_000_000.0 / audit_elapsed_us as f64,
        "audit_latency_us": summarize(&audit_latencies),
    })
}

async fn measure_ipc_capacity(broker: &common::TestBroker) -> Value {
    let started = Instant::now();
    let mut agent = hold_connections(&broker.agent_sock(), MAX_AGENT_CONNECTIONS).await;
    let mut admin = hold_connections(&broker.admin_sock(), MAX_ADMIN_CONNECTIONS).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let agent_reject_us = rejected_connection_latency(&broker.agent_sock()).await;
    let admin_reject_us = rejected_connection_latency(&broker.admin_sock()).await;
    agent.clear();
    admin.clear();
    tokio::time::sleep(Duration::from_millis(100)).await;
    json!({
        "held_agent": MAX_AGENT_CONNECTIONS,
        "held_admin": MAX_ADMIN_CONNECTIONS,
        "open_all_latency_us": started.elapsed().as_micros(),
        "extra_agent_rejected_us": agent_reject_us,
        "extra_admin_rejected_us": admin_reject_us,
    })
}

async fn hold_connections(path: &Path, count: usize) -> Vec<UnixStream> {
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(b"R").await.unwrap();
        streams.push(stream);
    }
    streams
}

async fn rejected_connection_latency(path: &Path) -> u128 {
    let started = Instant::now();
    let mut stream = UnixStream::connect(path).await.unwrap();
    if stream.write_all(b"R").await.is_ok() {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("over-capacity connection was not rejected: {other:?}"),
        }
    }
    started.elapsed().as_micros()
}

async fn create_large_action(broker: &common::TestBroker, credential_id: &str) -> (String, u64) {
    let mut meta = common::action_meta(credential_id);
    meta["response_max_bytes"] = json!(LARGE_RESPONSE_BYTES);
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let ok = response.ok();
    (
        ok["id"].as_str().unwrap().to_owned(),
        ok["version"].as_u64().unwrap(),
    )
}

async fn create_session(broker: &common::TestBroker, action_id: &str, version: u64) -> String {
    let meta = json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 3_600_000,
        "max_uses": SESSION_USES,
    });
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let ok = response.ok();
    let token = ok["capability_token"].as_str().unwrap().to_owned();
    common::activate_test_policy(
        broker,
        action_id,
        version,
        ok["principal_id"].as_str().unwrap(),
    )
    .await;
    token
}

async fn execute(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
) -> (Duration, common::WireResponse) {
    let meta = common::execute_meta(token, action_id, version);
    let started = Instant::now();
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    (started.elapsed(), response)
}

async fn measure_response_sealing(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
) -> Value {
    let mut latencies = Vec::new();
    for _ in 0..12 {
        broker
            .fake
            .push_response(Ok(clean_response(LARGE_RESPONSE_BYTES)));
        let (latency, response) = execute(broker, token, action_id, version).await;
        response.ok();
        assert_eq!(response.body.len(), LARGE_RESPONSE_BYTES);
        latencies.push(latency.as_micros());
    }
    json!({
        "samples": latencies.len(),
        "bytes_per_response": LARGE_RESPONSE_BYTES,
        "latency_us": summarize(&latencies),
        "rss_after_kib": rss_kib(),
    })
}

fn measure_session_capacity() -> Value {
    let registry = Arc::new(SessionRegistry::new());
    registry.open_for_admission();
    let session_id = SessionId::new_random();
    let action = ActionVersionRef {
        action_id: ActionId::new_random(),
        version: 1,
    };
    let now = Timestamp::from_unix_ms(1_000);
    let grant = SessionGrant::new(
        session_id,
        Principal {
            tenant_id: TenantId::new_random(),
            principal_id: PrincipalId::new_random(),
            session_id,
        },
        vec![action],
        now,
        60_000,
        100,
    )
    .unwrap();
    let token = registry.admit(grant, vec![(action, 30_000)]).unwrap();
    let held: Vec<_> = (0..SESSION_MAX_CONCURRENT_EXECUTIONS)
        .map(|_| registry.acquire(&token, action, now).unwrap())
        .collect();
    assert_eq!(
        registry.in_flight_total(),
        SESSION_MAX_CONCURRENT_EXECUTIONS
    );
    let rejected = match registry.acquire(&token, action, now) {
        Ok(_) => panic!("fifth concurrent execution was admitted"),
        Err(error) => error,
    };
    assert_eq!(rejected, rekey_domain::DomainError::InvalidCapability);
    drop(held);
    assert_eq!(registry.in_flight_total(), 0);
    let retry = registry.acquire(&token, action, now).unwrap();
    drop(retry);
    json!({
        "capacity": SESSION_MAX_CONCURRENT_EXECUTIONS,
        "fifth_attempt_error": "INVALID_CAPABILITY",
        "slot_reusable_after_release": true,
    })
}

async fn measure_backup_interference(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
) -> Value {
    broker.fake.take_requests();
    broker
        .fake
        .push_response_delayed(Ok(clean_response(32)), Duration::from_millis(100));
    let executions = concurrent_execute_task(broker, token, action_id, version, 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while broker.fake.requests.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("execution did not reach upstream before backup");
    let output = broker.dir.path().join("interference.rkbackup");
    let started = Instant::now();
    backup(broker, &output).await;
    let backup_latency = started.elapsed();
    let responses = executions.await.unwrap();
    assert!(
        responses
            .iter()
            .all(|response| response.message_type == ipc::resp_msg::OK)
    );
    fs::remove_file(output).unwrap();
    json!({
        "concurrent_executions": responses.len(),
        "execution_errors": 0,
        "backup_latency_us": backup_latency.as_micros(),
    })
}

fn concurrent_execute_task(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
    count: usize,
) -> tokio::task::JoinHandle<Vec<common::WireResponse>> {
    let socket = broker.agent_sock();
    let token = token.to_owned();
    let action_id = action_id.to_owned();
    tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        for _ in 0..count {
            let socket = socket.clone();
            let token = token.clone();
            let action_id = action_id.clone();
            tasks.spawn(async move {
                let meta = common::execute_meta(&token, &action_id, version);
                common::call(
                    &socket,
                    Channel::Agent,
                    agent_msg::EXECUTE_FIXED_HTTP_ACTION,
                    meta.to_string().as_bytes(),
                    b"{}",
                )
                .await
            });
        }
        let mut responses = Vec::new();
        while let Some(response) = tasks.join_next().await {
            responses.push(response.unwrap());
        }
        responses
    })
}

async fn backup(broker: &common::TestBroker, output: &Path) {
    let meta = json!({"output_path": output.display().to_string()});
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::BACKUP,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
}

async fn measure_shutdown_drain(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
) -> (Duration, usize) {
    broker.fake.take_requests();
    broker
        .fake
        .push_response_delayed(Ok(clean_response(32)), Duration::from_millis(250));
    let metadata = common::execute_meta(token, action_id, version)
        .to_string()
        .into_bytes();
    let header = FrameHeader {
        channel: Channel::Agent,
        flags: 0,
        message_type: agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        request_id: RequestId::new_random(),
        metadata_len: metadata.len() as u32,
        body_len: 2,
    };
    let mut execution = UnixStream::connect(broker.agent_sock()).await.unwrap();
    execution.write_all(&header.encode()).await.unwrap();
    execution.write_all(&metadata).await.unwrap();
    execution.write_all(b"{}").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while broker.fake.requests.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("execution did not reach upstream before shutdown");
    drop(execution);
    let started = Instant::now();
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    let latency = started.elapsed();
    (latency, 1)
}

fn clean_response(size: usize) -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())].into(),
        body: vec![b'x'; size].into(),
    }
}

fn audit_draft() -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        event_type: event_type::POLICY_ACTIVATED,
        outcome: outcome::SUCCESS,
        reason_code: "performance-baseline".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

fn summarize(values: &[u128]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    json!({
        "p50": percentile(&sorted, 50),
        "p95": percentile(&sorted, 95),
        "p99": percentile(&sorted, 99),
        "max": sorted[sorted.len() - 1],
    })
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index]
}

fn rss_kib() -> u64 {
    if let Ok(status) = fs::read_to_string("/proc/self/status")
        && let Some(value) = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
    {
        return value;
    }
    command_text("ps", &["-o", "rss=", "-p", &std::process::id().to_string()])
        .trim()
        .parse()
        .expect("read process RSS")
}

fn assert_memory_stable(samples: &[u64]) {
    assert!(samples.len() >= 2);
    let window = (samples.len() / 4).max(1);
    let first = average(&samples[..window]);
    let last = average(&samples[samples.len() - window..]);
    assert!(
        last <= first + 64 * 1024,
        "sustained RSS growth exceeded 64 MiB: first={first} KiB last={last} KiB"
    );
}

fn average(values: &[u64]) -> u64 {
    values.iter().sum::<u64>() / values.len() as u64
}

fn memory_summary(samples: &[u64]) -> Value {
    let window = (samples.len() / 4).max(1);
    json!({
        "samples": samples.len(),
        "first_window_average": average(&samples[..window]),
        "last_window_average": average(&samples[samples.len() - window..]),
        "max": samples.iter().copied().max().unwrap(),
    })
}

fn command_text(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(output.status.success(), "{program} failed");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn cpu_description() -> String {
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo")
        && let Some(model) = cpuinfo
            .lines()
            .find_map(|line| line.strip_prefix("model name\t: "))
    {
        return model.to_owned();
    }
    command_text("sysctl", &["-n", "machdep.cpu.brand_string"])
}

fn memory_description() -> String {
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo")
        && let Some(total) = meminfo.lines().find(|line| line.starts_with("MemTotal:"))
    {
        return total.to_owned();
    }
    command_text("sysctl", &["-n", "hw.memsize"])
}

fn write_report(report: &Value) {
    let path = std::env::var_os("REKEY_PERF_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/performance-report.json"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_vec_pretty(report).unwrap()).unwrap();
}
