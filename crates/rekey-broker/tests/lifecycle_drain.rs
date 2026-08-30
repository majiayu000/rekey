//! Broker-owned drain: idle/lock/shutdown revoke sessions, wait in-flight,
//! and pair every execution.started with a terminal event.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{Channel, FrameHeader, admin_msg, agent_msg};
use rekey_vault::store::SqliteRecordStore;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

fn assert_each_started_has_one_terminal(log: &[(Vec<u8>, String)]) {
    let mut started: HashMap<Vec<u8>, u32> = HashMap::new();
    let mut terminal: HashMap<Vec<u8>, u32> = HashMap::new();
    for (id, ty) in log {
        match ty.as_str() {
            "execution.started" => *started.entry(id.clone()).or_default() += 1,
            "execution.finished" | "execution.blocked" => {
                *terminal.entry(id.clone()).or_default() += 1;
            }
            _ => {}
        }
    }
    for (id, count) in &started {
        assert_eq!(*count, 1, "duplicate started for {id:?}");
        assert_eq!(
            terminal.get(id).copied().unwrap_or(0),
            1,
            "started without exactly one terminal for {id:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_lock_revokes_sessions_permanently() {
    let broker = common::start_broker_with(Duration::from_millis(80), Duration::from_secs(2)).await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "idle", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    tokio::time::sleep(Duration::from_millis(250)).await;
    let status = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(status.ok()["state"], "locked");

    common::unlock(&broker).await;
    let meta = common::execute_meta(&token, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_CAPABILITY");
    assert!(broker.fake.take_requests().is_empty());

    let token2 = common::create_session(&broker, &action_id, version).await;
    let meta = common::execute_meta(&token2, &action_id, version);
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.ok()["upstream_status"], 200);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_waits_for_in_flight_execute() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "slow", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"ok\":true}".to_vec().into(),
        }),
        Duration::from_millis(150),
    );

    let agent = broker.agent_sock();
    let admin = broker.admin_sock();
    let meta = common::execute_meta(&token, &action_id, version);
    let exec = tokio::spawn(async move {
        common::call(
            &agent,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            meta.to_string().as_bytes(),
            b"{}",
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    let lock = common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await;
    lock.ok();
    let exec = exec.await.unwrap();
    assert_eq!(exec.ok()["upstream_status"], 200);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_does_not_cancel_supervisor_owned_execution() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "detached", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;
    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"ok\":true}".to_vec().into(),
        }),
        Duration::from_millis(150),
    );

    let metadata = common::execute_meta(&token, &action_id, version)
        .to_string()
        .into_bytes();
    let body = b"{}";
    let header = FrameHeader {
        channel: Channel::Agent,
        flags: 0,
        message_type: agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        request_id: RequestId::new_random(),
        metadata_len: metadata.len() as u32,
        body_len: body.len() as u32,
    };
    let mut stream = UnixStream::connect(broker.agent_sock()).await.unwrap();
    stream.write_all(&header.encode()).await.unwrap();
    stream.write_all(&metadata).await.unwrap();
    stream.write_all(body).await.unwrap();
    for _ in 0..100 {
        if !broker.fake.requests.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!broker.fake.requests.lock().unwrap().is_empty());
    drop(stream);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let log = store.audit_execution_log().unwrap();
    assert_each_started_has_one_terminal(&log);
    assert_eq!(
        log.iter()
            .filter(|(_, event)| event == "execution.finished")
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_disconnected_admitted_execution() {
    let broker = common::start_broker_with(Duration::from_secs(300), Duration::from_secs(2)).await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "detached-stop", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;
    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"ok\":true}".to_vec().into(),
        }),
        Duration::from_millis(300),
    );

    let metadata = common::execute_meta(&token, &action_id, version)
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
    let mut stream = UnixStream::connect(broker.agent_sock()).await.unwrap();
    stream.write_all(&header.encode()).await.unwrap();
    stream.write_all(&metadata).await.unwrap();
    stream.write_all(b"{}").await.unwrap();
    for _ in 0..100 {
        if !broker.fake.requests.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!broker.fake.requests.lock().unwrap().is_empty());
    drop(stream);

    let shutdown = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    shutdown.ok();
    let state_dir = broker.state_dir.clone();
    let dir = broker.dir;
    assert!(broker.serve_task.await.unwrap().is_ok());
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let log = store.audit_execution_log().unwrap();
    assert_eq!(
        log.iter()
            .filter(|(_, event)| event == "execution.finished")
            .count(),
        1,
        "shutdown cancelled admitted execution: {log:?}"
    );
    drop(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn draining_rejects_new_execute_without_started() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "drain", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"ok\":true}".to_vec().into(),
        }),
        Duration::from_millis(200),
    );

    let agent = broker.agent_sock();
    let admin = broker.admin_sock();
    let meta = common::execute_meta(&token, &action_id, version);
    let exec = tokio::spawn({
        let agent = agent.clone();
        async move {
            common::call(
                &agent,
                Channel::Agent,
                agent_msg::EXECUTE_FIXED_HTTP_ACTION,
                meta.to_string().as_bytes(),
                b"{}",
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(40)).await;

    let lock = tokio::spawn(async move {
        common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let second = common::call(
        &agent,
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert!(
        ["INVALID_CAPABILITY", "DRAINING"].contains(&second.err_code().as_str()),
        "got {}",
        second.err_code()
    );

    exec.await.unwrap().ok();
    lock.await.unwrap().ok();

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let log = store.audit_execution_log().unwrap();
    let started = log.iter().filter(|(_, t)| t == "execution.started").count();
    assert_eq!(started, 1, "draining execute must not start: {log:?}");
    assert_each_started_has_one_terminal(&log);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_started_has_terminal_on_success_and_block() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "pair", b"secret-token-value").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    let meta = common::execute_meta(&token, &action_id, version);
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await
    .ok();

    broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        body: b"leaked secret-token-value".to_vec().into(),
    }));
    let blocked = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(blocked.err_code(), "RESPONSE_SECURITY_VIOLATION");

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let log = store.audit_execution_log().unwrap();
    assert_each_started_has_one_terminal(&log);
    assert!(log.iter().any(|(_, t)| t == "execution.finished"));
    assert!(log.iter().any(|(_, t)| t == "execution.blocked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn session_create_during_drain_is_rejected() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "race", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"ok\":true}".to_vec().into(),
        }),
        Duration::from_millis(200),
    );

    let agent = broker.agent_sock();
    let admin = broker.admin_sock();
    let meta = common::execute_meta(&token, &action_id, version);
    let exec = tokio::spawn(async move {
        common::call(
            &agent,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            meta.to_string().as_bytes(),
            b"{}",
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(40)).await;

    let lock_admin = admin.clone();
    let lock = tokio::spawn(async move {
        common::call(&lock_admin, Channel::Admin, admin_msg::LOCK, b"{}", &[]).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let create_meta = serde_json::json!({
        "actions": [{"action_id": action_id, "version": version}],
        "ttl_ms": 3_600_000,
        "max_uses": 100,
    });
    let created = common::call(
        &admin,
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        create_meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert!(
        ["DRAINING", "LOCKED"].contains(&created.err_code().as_str()),
        "SessionCreate during drain must fail, got {}",
        created.err_code()
    );

    exec.await.unwrap().ok();
    lock.await.unwrap().ok();

    common::unlock(&broker).await;
    let token2 = common::create_session(&broker, &action_id, version).await;
    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token2, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.ok()["upstream_status"], 200);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_timeout_commits_abandoned_terminal() {
    let broker =
        common::start_broker_with(Duration::from_secs(300), Duration::from_millis(60)).await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "cancel", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    broker.fake.push_response_delayed(
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: b"{\"ok\":true}".to_vec().into(),
        }),
        Duration::from_secs(2),
    );

    let agent = broker.agent_sock();
    let admin = broker.admin_sock();
    let meta = common::execute_meta(&token, &action_id, version);
    let exec = tokio::spawn(async move {
        common::call(
            &agent,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            meta.to_string().as_bytes(),
            b"{}",
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[])
        .await
        .ok();
    let exec = exec.await.unwrap();
    assert_eq!(exec.err_code(), "DRAINING");

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let log = store.audit_execution_log().unwrap();
    assert_each_started_has_one_terminal(&log);
    assert!(
        log.iter().any(|(_, t)| t == "execution.blocked"),
        "cancelled execute must leave a terminal blocked row: {log:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_terminal_commit_failure_reaches_tracker_and_fails_shutdown() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential_id = common::add_credential(&broker, "terminal-fault", b"v").await;
    let (action_id, version) = common::create_action(&broker, &credential_id).await;
    let token = common::create_session(&broker, &action_id, version).await;

    // Let execution.started commit, then reject the tracker-owned terminal.
    // The failure must remain visible so shutdown cannot report success.
    let db = rekey_vault::paths::vault_db(&broker.state_dir);
    let tamper = rusqlite::Connection::open(&db).unwrap();
    tamper
        .execute_batch(
            "CREATE TRIGGER fail_execution_terminal
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type IN ('execution.finished', 'execution.blocked')
             BEGIN
               SELECT RAISE(ABORT, 'terminal audit fault');
             END;",
        )
        .unwrap();
    drop(tamper);

    let response = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        common::execute_meta(&token, &action_id, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(response.err_code(), "AUDIT_COMMIT_FAILED_AFTER_EXECUTION");

    let shutdown = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(shutdown.err_code(), "AUDIT_COMMIT_FAILED");
    tokio::time::timeout(Duration::from_secs(5), broker.serve_task)
        .await
        .expect("broker stops after failed shutdown response")
        .expect("serve task joins")
        .expect_err("sticky terminal failure must make serve nonzero");
}
