//! Cross-boundary IPC contract: the agent data plane can never reach admin
//! capability, secret export does not exist on the wire, and the two sockets
//! stay separated.

use rekey_domain::audit::{AUDIT_SCHEMA_V2, AuditPage, AuditQuery};
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{Channel, FrameHeader, RESPONSE_BODY_MAX_BYTES, admin_msg, agent_msg};
use rekey_integration::harness as h;
use rekey_vault::model::AuditEvent;
use rekey_vault::{paths, store::SqliteRecordStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn connection_closes_without_reply(socket: &std::path::Path, request: &[u8]) -> bool {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte).await, Ok(0) | Err(_))
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_socket_has_no_admin_or_export_surface() {
    let broker = h::start_broker().await;
    h::unlock(&broker).await;
    let credential_id = h::add_credential(&broker, "ipc", b"secret-bytes").await;
    let (action_id, version) = h::create_action(&broker, &credential_id).await;
    let _token = h::create_session(&broker, &action_id, version).await;

    // Every admin message id (other than the two legitimate agent ids) is
    // rejected on the agent socket — including everything that could read or
    // export a secret.
    for message_type in 3u16..=64 {
        let response = h::call(
            &broker.agent_sock(),
            Channel::Agent,
            message_type,
            b"{}",
            &[],
        )
        .await;
        assert_eq!(
            response.err_code(),
            "INVALID_FRAME",
            "agent message type {message_type} must not exist"
        );
    }

    // The agent status subset leaks no identifiers.
    let response = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::AGENT_STATUS,
        b"{}",
        &[],
    )
    .await;
    assert!(response.ok().get("vault_id").is_none());

    // Admin frames on the agent socket are dropped by channel tag.
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(response.ok()["state"], "unlocked");

    broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_list_returns_metadata_only() {
    let broker = h::start_broker().await;
    h::unlock(&broker).await;
    let secret = b"list-canary-secret-value";
    h::add_credential(&broker, "listed", secret).await;
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    let serialized = response.ok().to_string();
    assert!(!serialized.contains(std::str::from_utf8(secret).unwrap()));
    broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_query_is_admin_only_bounded_and_available_while_locked() {
    let broker = h::start_broker().await;
    let query = AuditQuery {
        request_id: None,
        session_id: None,
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit: 10,
    };
    let metadata = serde_json::to_vec(&query).unwrap();
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &metadata,
        &[],
    )
    .await;
    assert_eq!(response.ok(), &serde_json::json!({}));
    let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
    page.validate_for(&query).unwrap();
    assert_eq!(page.schema, AUDIT_SCHEMA_V2);
    assert!(!page.events.is_empty());

    let body_header = FrameHeader {
        channel: Channel::Admin,
        flags: 0,
        message_type: admin_msg::AUDIT_QUERY,
        request_id: RequestId::new_random(),
        metadata_len: metadata.len() as u32,
        body_len: 1,
    };
    let mut body_request = body_header.encode().to_vec();
    body_request.extend_from_slice(&metadata);
    body_request.push(b'x');
    assert!(
        connection_closes_without_reply(&broker.admin_sock(), &body_request).await,
        "audit query bodies must close the admin connection"
    );

    let mut invalid = query.clone();
    invalid.snapshot_max_sequence = Some(10);
    invalid.before_sequence = Some(11);
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&invalid).unwrap(),
        &[],
    )
    .await;
    assert_eq!(response.err_code(), "INVALID_INPUT");
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&query).unwrap(),
        &[],
    )
    .await;
    assert_eq!(response.ok(), &serde_json::json!({}));
    broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_audit_page_fails_before_a_success_frame() {
    let broker = h::start_broker().await;
    let mut store = SqliteRecordStore::open(&paths::vault_db(&broker.state_dir)).unwrap();
    store
        .append_audit(&AuditEvent {
            event_id: [0xee; 16],
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            event_type: "test.oversized",
            outcome: "failure",
            reason_code: "x".repeat(RESPONSE_BODY_MAX_BYTES as usize),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: 1,
        })
        .unwrap();
    drop(store);
    let metadata = serde_json::to_vec(&AuditQuery {
        request_id: None,
        session_id: None,
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit: 1,
    })
    .unwrap();
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &metadata,
        &[],
    )
    .await;
    assert_eq!(response.err_code(), "RESPONSE_TOO_LARGE");
    broker.shutdown_keep_dir().await;
}

async fn metrics_snapshot(broker: &h::TestBroker) -> rekey_domain::ipc::MetricsResponse {
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::METRICS,
        b"{}",
        &[],
    )
    .await;
    serde_json::from_value(response.ok().clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_are_admin_only_passive_and_track_real_dispatch_results() {
    let broker = h::start_broker().await;
    let before = metrics_snapshot(&broker).await;
    let again = metrics_snapshot(&broker).await;
    assert_eq!(before.admin.dispatch.requests_total, 0);
    assert_eq!(again.admin.dispatch.requests_total, 0);
    assert_eq!(again.admin.dispatch.requests_in_flight, 0);
    assert_eq!(again.capabilities_active, 0);

    let denied = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        admin_msg::METRICS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(denied.err_code(), "INVALID_FRAME");
    let status = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::AGENT_STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(status.ok(), &serde_json::json!({"state": "locked"}));
    let backup = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::BACKUP,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(backup.err_code(), "LOCKED");
    let malformed = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::METRICS,
        br#"{"extra":1}"#,
        &[],
    )
    .await;
    assert_eq!(malformed.err_code(), "INVALID_FRAME");
    let after = metrics_snapshot(&broker).await;
    assert_eq!(after.agent.dispatch.requests_total, 2);
    assert_eq!(after.agent.dispatch.finished_total, 2);
    assert_eq!(after.agent.dispatch.errors_total, 1);
    assert_eq!(after.agent.dispatch.cancelled_total, 0);
    assert_eq!(after.agent.dispatch.requests_in_flight, 0);
    assert_eq!(after.admin.dispatch.requests_total, 1);
    assert_eq!(after.backup.requests_total, 1);
    assert_eq!(after.backup.errors_total, 1);

    h::unlock(&broker).await;
    let credential =
        h::add_credential(&broker, "METRICS-PRIVATE-LABEL", b"METRICS-PRIVATE-SECRET").await;
    let (action, version) = h::create_action(&broker, &credential).await;
    let token = h::create_session(&broker, &action, version).await;
    let active = metrics_snapshot(&broker).await;
    assert_eq!(active.capabilities_active, 1);
    assert_eq!(active.executions_in_flight, 0);
    let encoded = serde_json::to_string(&active).unwrap();
    for private in [
        &credential,
        &action,
        &token,
        "METRICS-PRIVATE-LABEL",
        "METRICS-PRIVATE-SECRET",
    ] {
        assert!(!encoded.contains(private));
    }
    h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    assert_eq!(metrics_snapshot(&broker).await.capabilities_active, 0);
    broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_count_frame_and_connection_capacity_rejections() {
    let broker = h::start_broker().await;
    let header = FrameHeader {
        channel: Channel::Admin,
        flags: 0,
        message_type: admin_msg::METRICS,
        request_id: RequestId::new_random(),
        metadata_len: 2,
        body_len: 1,
    };
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(b"{}x");
    assert!(connection_closes_without_reply(&broker.admin_sock(), &frame).await);
    assert_eq!(
        metrics_snapshot(&broker)
            .await
            .admin
            .frame_read_failures_total,
        1
    );

    // Keep every Agent request slot occupied; the Admin snapshot stays reachable.
    let mut connections = Vec::new();
    for _ in 0..rekey_broker::runtime::MAX_AGENT_REQUEST_CONNECTIONS {
        let stream = UnixStream::connect(broker.agent_sock()).await.unwrap();
        connections.push(stream);
    }
    // FIFO accept of the prior connections makes this request hit the bounded reply slot.
    let rejected = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::AGENT_STATUS,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(rejected.err_code(), "AUTHORITY_BUSY");
    let snapshot = metrics_snapshot(&broker).await;
    assert_eq!(snapshot.agent.capacity_rejections_total, 1);
    assert_eq!(snapshot.agent.dispatch.requests_total, 0);
    drop(connections);
    broker.shutdown_keep_dir().await;
}
