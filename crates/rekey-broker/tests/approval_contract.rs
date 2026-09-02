mod common;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::BASE64URL_NOPAD;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::audit::{AuditPage, AuditQuery};
use rekey_domain::authorization::ApprovalMode;
use rekey_domain::ids::{ApprovalId, ApproverId};
use rekey_domain::ipc::{self, ApprovalChallenge, Channel, admin_msg, agent_msg};

fn approver() -> (ApproverId, Ed25519KeyPair, [u8; 32]) {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let public_key = key.public_key().as_ref().try_into().unwrap();
    (ApproverId::new_random(), key, public_key)
}

async fn prepare(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
) -> ApprovalChallenge {
    let response = prepare_response(broker, token, action_id, version).await;
    serde_json::from_value(response.ok().clone()).unwrap()
}

async fn prepare_response(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
) -> common::WireResponse {
    let metadata = serde_json::to_vec(&ipc::PrepareApprovalMeta {
        capability_token: token.to_owned(),
        action_id: action_id.parse().unwrap(),
        action_version: version,
        content_type: Some("application/json".to_owned()),
        extra_headers: Vec::new(),
    })
    .unwrap();
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::PREPARE_APPROVAL,
        &metadata,
        b"{}",
    )
    .await
}

fn signed_grant(
    challenge: &ApprovalChallenge,
    approver_id: ApproverId,
    key: &Ed25519KeyPair,
    max_uses: u32,
) -> String {
    let unsigned = serde_json::json!({
        "format_version": 1,
        "approval_id": ApprovalId::new_random(),
        "approval_request_id": challenge.approval_request_id,
        "approver_id": approver_id,
        "tenant_id": challenge.tenant_id,
        "principal_id": challenge.principal_id,
        "session_id": challenge.session_id,
        "action_id": challenge.action_id,
        "action_version": challenge.action_version,
        "resource": challenge.resource,
        "schema_id": challenge.schema_id,
        "parameter_sha256": challenge.parameter_sha256,
        "policy_version": challenge.policy_version,
        "policy_sha256": challenge.policy_sha256,
        "policy_rule_id": challenge.policy_rule_id,
        "mode": challenge.mode,
        "not_before_ms": challenge.created_at_ms,
        "expires_at_ms": challenge.max_expires_at_ms.min(challenge.created_at_ms + 60_000),
        "max_uses": max_uses,
    });
    let mut message = b"RKAPPROVAL\0\x01".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
    let signature = BASE64URL_NOPAD.encode(key.sign(&message).as_ref());
    let mut grant = unsigned;
    grant
        .as_object_mut()
        .unwrap()
        .insert("signature".to_owned(), signature.into());
    String::from_utf8(serde_jcs::to_vec(&grant).unwrap()).unwrap()
}

async fn execute(
    broker: &common::TestBroker,
    token: &str,
    action_id: &str,
    version: u64,
    grants: Vec<String>,
) -> common::WireResponse {
    let mut metadata = common::execute_meta(token, action_id, version);
    metadata
        .as_object_mut()
        .unwrap()
        .insert("approval_grants".to_owned(), grants.into());
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        metadata.to_string().as_bytes(),
        b"{}",
    )
    .await
}

fn upstream_ok() -> Result<UpstreamResponse, rekey_broker::upstream::UpstreamError> {
    Ok(UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: b"{}".to_vec().into(),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn one_time_grant_admits_exactly_once_under_a_race() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "approval-race", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let session = common::policy::create_session_grant(&broker, &action, version, 8).await;
    let (approver_id, key, public_key) = approver();
    common::policy::activate_approval_policy(
        &broker,
        &action,
        version,
        common::policy::ApprovalPolicy {
            principal_id: &session.principal_id,
            approvers: &[(approver_id, public_key)],
            quorum: 1,
            mode: ApprovalMode::OneTime,
            max_uses: 1,
            max_window_ms: None,
        },
    )
    .await;
    let challenge = prepare(&broker, &session.capability_token, &action, version).await;
    assert_eq!(challenge.record_type, "rekey.approval.challenge.v1");
    let excessive = execute(
        &broker,
        &session.capability_token,
        &action,
        version,
        vec!["not-json".to_owned(); 3],
    )
    .await;
    assert_eq!(excessive.err_code(), "REQUEST_DENIED");
    assert_eq!(
        excessive.metadata["message"],
        "request denied: approval-insufficient-quorum"
    );
    let grant = signed_grant(&challenge, approver_id, &key, 1);
    broker.fake.push_response(upstream_ok());

    let left = execute(
        &broker,
        &session.capability_token,
        &action,
        version,
        vec![grant.clone()],
    );
    let right = execute(
        &broker,
        &session.capability_token,
        &action,
        version,
        vec![grant],
    );
    let (left, right) = tokio::join!(left, right);
    let responses = [left, right];
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.message_type == ipc::resp_msg::OK)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| {
                response.message_type == ipc::resp_msg::ERROR
                    && response.metadata["code"] == "REQUEST_DENIED"
            })
            .count(),
        1
    );
    assert_eq!(broker.fake.requests.lock().unwrap().len(), 1);

    let query = AuditQuery {
        request_id: None,
        session_id: Some(challenge.session_id),
        action_id: None,
        credential_id: None,
        outcome: None,
        since_ms: None,
        until_ms: None,
        snapshot_max_sequence: None,
        before_sequence: None,
        limit: 100,
    };
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&query).unwrap(),
        &[],
    )
    .await;
    response.ok();
    let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.event_type == "approval.requested")
            .count(),
        1
    );
    let accepted = page
        .events
        .iter()
        .find(|event| event.event_type == "approval.accepted")
        .unwrap();
    let started = page
        .events
        .iter()
        .find(|event| event.event_type == "execution.started")
        .unwrap();
    assert_eq!(started.sequence, accepted.sequence + 1);
    assert!(accepted.approval_id.is_some());
    assert!(accepted.approver_id.is_some());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_person_quorum_rejects_one_and_accepts_two_distinct_approvers() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "approval-quorum", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let session = common::policy::create_session_grant(&broker, &action, version, 8).await;
    let (first_id, first_key, first_public) = approver();
    let (second_id, second_key, second_public) = approver();
    common::policy::activate_approval_policy(
        &broker,
        &action,
        version,
        common::policy::ApprovalPolicy {
            principal_id: &session.principal_id,
            approvers: &[(first_id, first_public), (second_id, second_public)],
            quorum: 2,
            mode: ApprovalMode::OneTime,
            max_uses: 1,
            max_window_ms: None,
        },
    )
    .await;
    let challenge = prepare(&broker, &session.capability_token, &action, version).await;
    let first = signed_grant(&challenge, first_id, &first_key, 1);
    let second = signed_grant(&challenge, second_id, &second_key, 1);
    assert_eq!(
        execute(
            &broker,
            &session.capability_token,
            &action,
            version,
            vec![first.clone()],
        )
        .await
        .err_code(),
        "REQUEST_DENIED"
    );
    let duplicate_approver = signed_grant(&challenge, first_id, &first_key, 1);
    assert_eq!(
        execute(
            &broker,
            &session.capability_token,
            &action,
            version,
            vec![first.clone(), duplicate_approver],
        )
        .await
        .err_code(),
        "REQUEST_DENIED"
    );
    broker.fake.push_response(upstream_ok());
    execute(
        &broker,
        &session.capability_token,
        &action,
        version,
        vec![first, second],
    )
    .await
    .ok();
    assert_eq!(broker.fake.requests.lock().unwrap().len(), 1);

    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&AuditQuery {
            request_id: None,
            session_id: Some(challenge.session_id),
            action_id: None,
            credential_id: None,
            outcome: None,
            since_ms: None,
            until_ms: None,
            snapshot_max_sequence: None,
            before_sequence: None,
            limit: 100,
        })
        .unwrap(),
        &[],
    )
    .await;
    let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
    let rejected = page
        .events
        .iter()
        .find(|event| event.reason_code == "approval-approver-duplicate")
        .unwrap();
    assert!(rejected.approval_request_id.is_none());
    assert!(rejected.approval_id.is_none());
    assert!(rejected.approver_id.is_none());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn time_window_grant_obeys_its_signed_use_limit() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "approval-window", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let session = common::policy::create_session_grant(&broker, &action, version, 8).await;
    let (approver_id, key, public_key) = approver();
    common::policy::activate_approval_policy(
        &broker,
        &action,
        version,
        common::policy::ApprovalPolicy {
            principal_id: &session.principal_id,
            approvers: &[(approver_id, public_key)],
            quorum: 1,
            mode: ApprovalMode::TimeWindow,
            max_uses: 2,
            max_window_ms: Some(60_000),
        },
    )
    .await;
    let challenge = prepare(&broker, &session.capability_token, &action, version).await;
    let grant = signed_grant(&challenge, approver_id, &key, 2);
    let release_first = broker.fake.push_response_gated(upstream_ok());
    let release_second = broker.fake.push_response_gated(upstream_ok());
    let first = execute(
        &broker,
        &session.capability_token,
        &action,
        version,
        vec![grant.clone()],
    );
    let remaining = async {
        while broker.fake.requests.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        let second = execute(
            &broker,
            &session.capability_token,
            &action,
            version,
            vec![grant.clone()],
        );
        let third_after_second_admission = async {
            while broker.fake.requests.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
            let response = execute(
                &broker,
                &session.capability_token,
                &action,
                version,
                vec![grant],
            )
            .await;
            release_first.notify_one();
            release_second.notify_one();
            response
        };
        tokio::join!(second, third_after_second_admission)
    };
    let (first, (second, third)) = tokio::join!(first, remaining);
    let responses = (first, second, third);
    assert_eq!(
        [&responses.0, &responses.1, &responses.2]
            .iter()
            .filter(|response| response.message_type == ipc::resp_msg::OK)
            .count(),
        2,
        "responses: {}, {}, {}",
        responses.0.metadata,
        responses.1.metadata,
        responses.2.metadata
    );
    assert_eq!(
        [&responses.0, &responses.1, &responses.2]
            .iter()
            .filter(|response| response.message_type == ipc::resp_msg::ERROR)
            .count(),
        1
    );
    assert_eq!(broker.fake.requests.lock().unwrap().len(), 2);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_and_capability_exhaustion_invalidate_challenges_without_amplifying_audit() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "approval-lock", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let session = common::policy::create_session_grant(&broker, &action, version, 1).await;
    let (approver_id, key, public_key) = approver();
    common::policy::activate_approval_policy(
        &broker,
        &action,
        version,
        common::policy::ApprovalPolicy {
            principal_id: &session.principal_id,
            approvers: &[(approver_id, public_key)],
            quorum: 1,
            mode: ApprovalMode::OneTime,
            max_uses: 1,
            max_window_ms: None,
        },
    )
    .await;
    let challenge = prepare(&broker, &session.capability_token, &action, version).await;
    let grant = signed_grant(&challenge, approver_id, &key, 1);
    assert_eq!(
        prepare_response(&broker, &session.capability_token, &action, version)
            .await
            .err_code(),
        "INVALID_CAPABILITY"
    );
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    common::unlock(&broker).await;
    assert_eq!(
        execute(
            &broker,
            &session.capability_token,
            &action,
            version,
            vec![grant],
        )
        .await
        .err_code(),
        "INVALID_CAPABILITY"
    );
    let response = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&AuditQuery {
            request_id: None,
            session_id: Some(challenge.session_id),
            action_id: None,
            credential_id: None,
            outcome: None,
            since_ms: None,
            until_ms: None,
            snapshot_max_sequence: None,
            before_sequence: None,
            limit: 100,
        })
        .unwrap(),
        &[],
    )
    .await;
    let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.event_type == "approval.requested")
            .count(),
        1
    );
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_permit_refuses_approval_challenge_and_unexpected_grants() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "approval-not-required", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let token = common::create_session(&broker, &action, version).await;
    assert_eq!(
        prepare_response(&broker, &token, &action, version)
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    assert_eq!(
        execute(&broker, &token, &action, version, vec!["{}".to_owned()],)
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    assert!(broker.fake.requests.lock().unwrap().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_audit_transaction_failure_prevents_the_remote_effect() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = common::add_credential(&broker, "approval-audit-fault", b"secret").await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let session = common::policy::create_session_grant(&broker, &action, version, 8).await;
    let (approver_id, key, public_key) = approver();
    common::policy::activate_approval_policy(
        &broker,
        &action,
        version,
        common::policy::ApprovalPolicy {
            principal_id: &session.principal_id,
            approvers: &[(approver_id, public_key)],
            quorum: 1,
            mode: ApprovalMode::OneTime,
            max_uses: 1,
            max_window_ms: None,
        },
    )
    .await;
    let challenge = prepare(&broker, &session.capability_token, &action, version).await;
    let grant = signed_grant(&challenge, approver_id, &key, 1);
    let db = rekey_vault::paths::vault_db(&broker.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_approval_admission
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'execution.started'
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    drop(connection);

    let response = execute(
        &broker,
        &session.capability_token,
        &action,
        version,
        vec![grant],
    )
    .await;
    assert_eq!(response.message_type, ipc::resp_msg::ERROR);
    assert!(broker.fake.requests.lock().unwrap().is_empty());
    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let connection = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state_dir)).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_type IN ('approval.accepted', 'execution.started')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "the admission audit transaction must roll back");
}
