#![cfg(feature = "lab")]
mod common;

use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ids::{ApprovalRequestId, PolicyRuleId, PrincipalId};
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg, agent_msg};
use sha2::{Digest, Sha256};

struct Fixture {
    broker: common::TestBroker,
    action: String,
    version: u64,
    session: common::policy::TestSession,
    key: Vec<u8>,
}
impl Fixture {
    async fn new(max_uses: u32) -> Self {
        Self::new_with_stream(max_uses, false).await
    }
    async fn new_with_stream(max_uses: u32, stream: bool) -> Self {
        let broker = common::start_broker().await;
        common::unlock(&broker).await;
        let credential =
            common::add_credential(&broker, "local-approval", b"LOCAL-CREDENTIAL-CANARY").await;
        let (action, version) = if stream {
            let mut definition = common::action_meta(&credential);
            definition["origin"] = "https://api.anthropic.com".into();
            definition["exact_path"] = "/v1/messages".into();
            definition["auth_header"] = "x-api-key".into();
            definition["auth_prefix"] = "".into();
            definition["allowed_extra_headers"] = serde_json::json!([]);
            definition["allowed_response_headers"] = serde_json::json!([]);
            definition["text_stream"] =
                serde_json::json!({"model":"fixed-test-model","max_tokens":2048});
            let response = common::call(
                &broker.admin_sock(),
                Channel::Admin,
                admin_msg::ACTION_CREATE,
                definition.to_string().as_bytes(),
                &common::proof_body(common::PASSWORD),
            )
            .await;
            (
                response.ok()["id"].as_str().unwrap().to_owned(),
                response.ok()["version"].as_u64().unwrap(),
            )
        } else {
            common::create_action(&broker, &credential).await
        };
        let principal = PrincipalId::new_random().to_string();
        common::policy::activate_snapshot(
            &broker,
            serde_json::json!({
                "format_version": 7, "version": 1, "expires_at_ms": 4_102_444_800_000_i64,
                "approvers": [], "connections":[], "ssh_keys":[], "profiles": [], "workload_identities": [],
                "bindings": [{"action_id": action, "version": version,
                    "resource": {"type": "test-action", "id": action},
                    "parameter_schema_id": "test-any-json/v1", "parameter_schema": {}}],
                "rules": [{"id": PolicyRuleId::new_random(), "effect": "require-approval",
                    "principal_id": principal, "action_id": action, "version": version,
                    "resource": {"type": "test-action", "id": action},
                    "parameters": {"kind": "any_validated"}, "approver": {"kind": "local-presence"},
                    "approval": {"mode": "one-time", "max_uses": 1}}]
            }),
        )
        .await;
        let session = common::policy::create_session_for_principal(
            &broker,
            &action,
            version,
            max_uses,
            Some(&principal),
        )
        .await;
        let remembered = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::DESKTOP_REMEMBER,
            b"{}",
            &common::proof_body(common::PASSWORD),
        )
        .await;
        remembered.ok();
        let key = remembered.body;
        Self {
            broker,
            action,
            version,
            session,
            key,
        }
    }
    async fn execute(&self, id: Option<ApprovalRequestId>, body: &[u8]) -> common::WireResponse {
        self.execute_kind(agent_msg::EXECUTE_FIXED_HTTP_ACTION, id, body)
            .await
    }
    async fn execute_kind(
        &self,
        opcode: u16,
        id: Option<ApprovalRequestId>,
        body: &[u8],
    ) -> common::WireResponse {
        let mut meta =
            common::execute_meta(&self.session.capability_token, &self.action, self.version);
        meta["local_approval_request_id"] = serde_json::to_value(id).unwrap();
        common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            opcode,
            &serde_json::to_vec(&meta).unwrap(),
            body,
        )
        .await
    }
    async fn pending(&self, body: &[u8]) -> ApprovalRequestId {
        let response = self.execute(None, body).await;
        assert_eq!(response.err_code(), "APPROVAL_REQUIRED");
        serde_json::from_value::<ipc::ErrorEnvelope>(response.metadata.clone()).unwrap();
        assert_eq!(response.metadata["retryable"], false);
        serde_json::from_value(response.metadata["approval"]["challenge_id"].clone()).unwrap()
    }
    async fn review(&self, id: ApprovalRequestId) -> common::WireResponse {
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_LOCAL_REVIEW,
            &serde_json::to_vec(&ipc::ApprovalGetMeta {
                approval_request_id: id,
            })
            .unwrap(),
            &[],
        )
        .await
    }
    async fn decide(
        &self,
        opcode: u16,
        id: ApprovalRequestId,
        hash: &str,
        kind: ProofKind,
        proof: &[u8],
    ) -> common::WireResponse {
        let mut body = Vec::new();
        ipc::encode_proof_body(kind, proof, &mut body);
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            opcode,
            &serde_json::to_vec(&ipc::LocalApprovalDecisionMeta {
                approval_request_id: id,
                expected_review_sha256: hash.into(),
                window_seconds: None,
            })
            .unwrap(),
            &body,
        )
        .await
    }
    async fn owner(&self, opcode: u16, id: ApprovalRequestId, token: &str) -> common::WireResponse {
        common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            opcode,
            &serde_json::to_vec(&ipc::LocalApprovalRequestMeta {
                capability_token: token.into(),
                approval_request_id: id,
            })
            .unwrap(),
            &[],
        )
        .await
    }
    async fn approve(&self, id: ApprovalRequestId) {
        let review = self.review(id).await;
        let hash = review.ok()["review_sha256"].as_str().unwrap();
        assert_eq!(
            self.decide(
                admin_msg::APPROVAL_LOCAL_APPROVE,
                id,
                hash,
                ProofKind::Presence,
                &self.key
            )
            .await
            .ok()["state"],
            "approved"
        );
    }
}

fn ok_response() -> Result<UpstreamResponse, rekey_broker::upstream::UpstreamError> {
    Ok(UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: b"{}".to_vec().into(),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn single_use_wait_refunds_and_review_matches_exact_request_then_consumes_once() {
    let f = Fixture::new(1).await;
    let body = br#"{"amount":9007199254740992,"message":"review-canary"}"#;
    let prepared = common::call(
        &f.broker.agent_sock(),
        Channel::Agent,
        agent_msg::PREPARE_APPROVAL,
        &serde_json::to_vec(&ipc::PrepareApprovalMeta {
            capability_token: f.session.capability_token.clone(),
            action_id: f.action.parse().unwrap(),
            action_version: f.version,
            content_type: Some("application/json".into()),
            extra_headers: vec![],
            params: Default::default(),
            query: Default::default(),
        })
        .unwrap(),
        body,
    )
    .await;
    let envelope: ipc::SignedApprovalChallenge =
        serde_json::from_value(prepared.ok().clone()).unwrap();
    let id = f.pending(body).await;
    assert_eq!(envelope.challenge.approval_request_id, id);
    assert_eq!(f.pending(body).await, id);
    let review = f.review(id).await;
    assert_eq!(review.ok()["record_type"], "rekey.approval.local-review.v1");
    assert_eq!(review.metadata["body_len"], review.body.len());
    let parsed: ipc::LocalApprovalReview = serde_json::from_slice(&review.body).unwrap();
    assert_eq!(parsed.challenge.approval_request_id, id);
    assert!(parsed.canonical_request.get().contains("9007199254740992"));
    assert!(parsed.canonical_request.get().contains("review-canary"));
    assert_eq!(parsed.record_type, "rekey.approval.review.v1");
    let mut hash = Sha256::new();
    hash.update(ipc::LOCAL_APPROVAL_REVIEW_HASH_PREFIX);
    hash.update(&review.body);
    assert_eq!(
        review.metadata["review_sha256"],
        data_encoding::HEXLOWER.encode(&hash.finalize())
    );
    assert!(!String::from_utf8_lossy(&review.body).contains("LOCAL-CREDENTIAL-CANARY"));
    let wait = f.owner(agent_msg::AWAIT_APPROVAL, id, &f.session.capability_token);
    let approve = async {
        tokio::task::yield_now().await;
        f.approve(id).await;
    };
    let (state, ()) = tokio::join!(wait, approve);
    assert_eq!(state.ok()["state"], "approved");
    f.approve(id).await;
    f.broker.fake.push_response(ok_response());
    f.execute(Some(id), body).await.ok();
    let consumed = f
        .owner(agent_msg::AWAIT_APPROVAL, id, &f.session.capability_token)
        .await;
    assert_eq!(consumed.ok()["state"], "consumed");
    let after = f.review(id).await;
    assert_eq!(after.ok()["state"], "consumed");
    assert!(after.body.is_empty());
    assert_eq!(
        f.execute(Some(id), body).await.err_code(),
        "CAPABILITY_EXHAUSTED"
    );
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.broker.state_dir)).unwrap();
    for event in [
        "approval.requested",
        "approval.approved",
        "approval.accepted",
        "execution.started",
    ] {
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type=?1",
                [event],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "{event}");
    }
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn decision_requires_presence_matching_review_and_request_context() {
    let f = Fixture::new(20).await;
    let id = f.pending(b"{}").await;
    let review = f.review(id).await;
    let hash = review.ok()["review_sha256"].as_str().unwrap();
    for kind in [ProofKind::Password, ProofKind::Recovery] {
        assert_eq!(
            f.decide(
                admin_msg::APPROVAL_LOCAL_APPROVE,
                id,
                hash,
                kind,
                common::PASSWORD
            )
            .await
            .err_code(),
            "INVALID_FRAME"
        );
    }
    assert_eq!(
        f.decide(
            admin_msg::APPROVAL_LOCAL_APPROVE,
            id,
            hash,
            ProofKind::Presence,
            b"bad"
        )
        .await
        .err_code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    assert_eq!(
        f.decide(
            admin_msg::APPROVAL_LOCAL_APPROVE,
            id,
            &"00".repeat(32),
            ProofKind::Presence,
            &f.key
        )
        .await
        .err_code(),
        "REQUEST_DENIED"
    );
    assert_eq!(f.review(id).await.ok()["state"], "pending");
    f.approve(id).await;
    assert_eq!(
        f.execute(Some(id), br#"{"changed":true}"#).await.err_code(),
        "REQUEST_DENIED"
    );
    let mut altered = common::execute_meta(&f.session.capability_token, &f.action, f.version);
    altered["local_approval_request_id"] = serde_json::to_value(id).unwrap();
    altered["extra_headers"] = serde_json::json!([["x-request-id", "changed"]]);
    assert_eq!(
        common::call(
            &f.broker.agent_sock(),
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            &serde_json::to_vec(&altered).unwrap(),
            b"{}"
        )
        .await
        .err_code(),
        "REQUEST_DENIED"
    );
    altered["extra_headers"] = serde_json::json!([]);
    altered["approval_grants"] = serde_json::json!(["{}"]);
    assert_eq!(
        common::call(
            &f.broker.agent_sock(),
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            &serde_json::to_vec(&altered).unwrap(),
            b"{}"
        )
        .await
        .err_code(),
        "REQUEST_DENIED"
    );
    let another = common::policy::create_session_for_principal(
        &f.broker,
        &f.action,
        f.version,
        3,
        Some(&f.session.principal_id),
    )
    .await;
    assert_eq!(
        f.owner(agent_msg::CANCEL_APPROVAL, id, &another.capability_token)
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    f.broker.fake.push_response(ok_response());
    f.execute(Some(id), b"{}").await.ok();
    assert_eq!(
        f.execute(Some(id), b"{}").await.err_code(),
        "REQUEST_DENIED"
    );
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_notifies_waiter_and_reject_or_lock_never_revives_grant() {
    let f = Fixture::new(5).await;
    let id = f.pending(b"{}").await;
    let wait = f.owner(agent_msg::AWAIT_APPROVAL, id, &f.session.capability_token);
    let cancel = f.owner(agent_msg::CANCEL_APPROVAL, id, &f.session.capability_token);
    let (wait, cancel) = tokio::join!(wait, cancel);
    assert_eq!(wait.ok()["state"], "cancelled");
    assert_eq!(cancel.ok()["state"], "cancelled");
    assert_eq!(
        f.execute(Some(id), b"{}").await.err_code(),
        "REQUEST_DENIED"
    );
    let second = f.pending(b"{}").await;
    assert_ne!(second, id);
    let review = f.review(second).await;
    assert_eq!(
        f.decide(
            admin_msg::APPROVAL_LOCAL_REJECT,
            second,
            review.ok()["review_sha256"].as_str().unwrap(),
            ProofKind::Presence,
            &f.key
        )
        .await
        .ok()["state"],
        "cancelled"
    );
    let third = f.pending(b"{}").await;
    common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    assert_eq!(
        f.owner(
            agent_msg::AWAIT_APPROVAL,
            third,
            &f.session.capability_token
        )
        .await
        .err_code(),
        "LOCKED"
    );
    common::unlock(&f.broker).await;
    assert_eq!(f.review(third).await.err_code(), "REQUEST_DENIED");
    assert!(f.broker.fake.requests.lock().unwrap().is_empty());
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn last_use_concurrency_is_busy_and_same_grant_race_has_one_remote_effect() {
    let f = Fixture::new(1).await;
    let id = f.pending(b"{}").await;
    f.approve(id).await;
    let release = f.broker.fake.push_response_gated(ok_response());
    let first = f.execute(Some(id), b"{}");
    let race = async {
        while f.broker.fake.requests.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        let response = f.execute(Some(id), b"{}").await;
        assert_eq!(response.err_code(), "AUTHORITY_BUSY");
        assert_eq!(response.metadata["retryable"], true);
        release.notify_one();
    };
    let (response, ()) = tokio::join!(first, race);
    response.ok();
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_audit_failure_faults_without_publishing_or_sending() {
    let f = Fixture::new(3).await;
    let id = f.pending(b"{}").await;
    let review = f.review(id).await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.broker.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_local BEFORE INSERT ON audit_events WHEN NEW.event_type='approval.approved' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let response = f
        .decide(
            admin_msg::APPROVAL_LOCAL_APPROVE,
            id,
            review.ok()["review_sha256"].as_str().unwrap(),
            ProofKind::Presence,
            &f.key,
        )
        .await;
    assert_eq!(response.err_code(), "AUDIT_COMMIT_FAILED");
    assert!(f.broker.fake.requests.lock().unwrap().is_empty());
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='approval.approved'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), f.broker.serve_task)
        .await
        .expect("audit failure did not stop the daemon")
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        stopped,
        rekey_broker::error::BrokerError::Authority(rekey_vault::AuthorityError::Faulted)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_pre_admission_preserves_structured_approval_required() {
    // A wrong response opcode must not create an approval for a buffered Action.
    let buffered = Fixture::new(1).await;
    assert_eq!(
        buffered
            .execute_kind(agent_msg::EXECUTE_TEXT_STREAM, None, b"{}")
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&buffered.broker.state_dir))
        .unwrap();
    let pending: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='approval.requested'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0);
    assert!(buffered.broker.fake.requests.lock().unwrap().is_empty());
    drop(db);
    buffered.broker.shutdown().await;
    let f = Fixture::new_with_stream(1, true).await;
    let response = f
        .execute_kind(
            agent_msg::EXECUTE_TEXT_STREAM,
            None,
            br#"{"messages":[{"role":"user","content":"hello"}]}"#,
        )
        .await;
    assert_eq!(response.err_code(), "APPROVAL_REQUIRED");
    let id: ApprovalRequestId =
        serde_json::from_value(response.metadata["approval"]["challenge_id"].clone()).unwrap();
    assert_eq!(f.review(id).await.ok()["state"], "pending");
    assert!(response.body.is_empty());
    assert!(f.broker.fake.requests.lock().unwrap().is_empty());
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnected_waiter_does_not_cancel_and_lost_approval_reply_keeps_approved() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    async fn send_and_disconnect(
        socket: &std::path::Path,
        channel: Channel,
        opcode: u16,
        metadata: &[u8],
        body: &[u8],
    ) {
        let header = ipc::FrameHeader {
            channel,
            flags: 0,
            message_type: opcode,
            request_id: rekey_domain::ids::RequestId::new_random(),
            metadata_len: metadata.len() as u32,
            body_len: body.len() as u32,
        };
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(&header.encode()).await.unwrap();
        stream.write_all(metadata).await.unwrap();
        stream.write_all(body).await.unwrap();
    }
    let f = Fixture::new(1).await;
    let id = f.pending(b"{}").await;
    send_and_disconnect(
        &f.broker.agent_sock(),
        Channel::Agent,
        agent_msg::AWAIT_APPROVAL,
        &serde_json::to_vec(&ipc::LocalApprovalRequestMeta {
            capability_token: f.session.capability_token.clone(),
            approval_request_id: id,
        })
        .unwrap(),
        &[],
    )
    .await;
    let review = f.review(id).await;
    assert_eq!(review.ok()["state"], "pending");
    let hash = review.metadata["review_sha256"].as_str().unwrap();
    let mut body = Vec::new();
    ipc::encode_proof_body(ProofKind::Presence, &f.key, &mut body);
    send_and_disconnect(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_APPROVE,
        &serde_json::to_vec(&ipc::LocalApprovalDecisionMeta {
            approval_request_id: id,
            expected_review_sha256: hash.into(),
            window_seconds: None,
        })
        .unwrap(),
        &body,
    )
    .await;
    let state = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        f.owner(agent_msg::AWAIT_APPROVAL, id, &f.session.capability_token),
    )
    .await
    .unwrap();
    assert_eq!(state.ok()["state"], "approved");
    f.approve(id).await;
    f.broker.fake.push_response(ok_response());
    f.execute(Some(id), b"{}").await.ok();
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_and_final_consumption_have_one_coordinator_winner() {
    let f = Fixture::new(2).await;
    let id = f.pending(b"{}").await;
    f.approve(id).await;
    f.broker.fake.push_response(ok_response());
    let (execution, cancel) = tokio::join!(
        f.execute(Some(id), b"{}"),
        f.owner(agent_msg::CANCEL_APPROVAL, id, &f.session.capability_token)
    );
    let state = cancel.ok()["state"].as_str().unwrap();
    match state {
        "consumed" => {
            execution.ok();
            assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
        }
        "cancelled" => {
            assert_eq!(execution.err_code(), "REQUEST_DENIED");
            assert!(f.broker.fake.requests.lock().unwrap().is_empty());
        }
        other => panic!("unexpected final state: {other}"),
    }
    assert_eq!(f.review(id).await.ok()["state"], state);
    f.broker.shutdown().await;
}
