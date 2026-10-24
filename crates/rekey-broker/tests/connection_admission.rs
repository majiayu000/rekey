//! Real signed policy, Broker, Authority and SQLite; upstream and Presence are
//! synthetic. No external account, credential, provider or device is used.
mod common;

use std::sync::Arc;
use std::time::Duration;

use rekey_broker::runtime::MAX_AGENT_REQUEST_CONNECTIONS;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::connection::{Connection, MethodClass, MethodSelector, RuleEffect};
use rekey_domain::ids::{PolicyRuleId, RequestId};
use rekey_domain::ipc::{self, Channel, FrameHeader, admin_msg, agent_msg};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Notify;

const CHAT: &[u8] = br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#;

struct Fixture {
    broker: common::TestBroker,
}

impl Fixture {
    async fn new(connections: usize, hourly: u32, llm: bool) -> Self {
        let broker = common::start_broker().await;
        common::unlock(&broker).await;
        let credential =
            common::add_credential(&broker, "admission", b"synthetic-admission-key").await;
        let preset = if connections > 1 {
            rekey_policy::presets::generic_preset(
                rekey_domain::action::HttpsOrigin::parse("https://api.example.com").unwrap(),
                "authorization",
                "Bearer ",
            )
            .unwrap()
        } else {
            rekey_policy::presets::builtin_preset(if llm { "openai" } else { "github-pat" })
                .unwrap()
        };
        let connections: Vec<Connection> = (0..connections)
            .map(|index| {
                let mut connection =
                    preset.connection(format!("fixture-{index}"), credential.parse().unwrap());
                connection.limits.requests_per_hour = hourly;
                for rule in &mut connection.rules {
                    rule.id = PolicyRuleId::new_random();
                    if matches!(rule.methods, MethodSelector::Class(MethodClass::Read)) {
                        rule.effect = RuleEffect::Allow;
                    }
                    if matches!(rule.methods, MethodSelector::Class(MethodClass::Write))
                        || (llm && matches!(&rule.methods, MethodSelector::Methods(methods) if methods.contains(&rekey_domain::action::FixedMethod::Post)))
                    {
                        rule.effect = RuleEffect::Approve;
                    }
                }
                if llm {
                    connection.rules.push(rekey_domain::connection::ConnectionRule {
                        id: PolicyRuleId::new_random(),
                        methods: MethodSelector::Methods(vec![rekey_domain::action::FixedMethod::Post]),
                        path: "/v1/chat/completions".into(),
                        effect: RuleEffect::Approve,
                    });
                    connection.llm = Some(rekey_domain::connection::ConnectionLlmLimits {
                        models: ["synthetic-model".into()].into_iter().collect(),
                        max_tokens: 32,
                        max_requests_per_day: 1,
                        max_output_tokens_per_day: 1000,
                    });
                }
                connection
            })
            .collect();
        common::policy::activate_snapshot(
            &broker,
            json!({
                "format_version":8,"version":1,"expires_at_ms":4_102_444_800_000_i64,
                "approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],
                "connections":connections,"ssh_keys":[],"derived_credentials":[],
            }),
        )
        .await;
        Self { broker }
    }

    async fn call(&self, metadata: &Value, body: &[u8]) -> common::WireResponse {
        common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            agent_msg::CALL,
            &serde_json::to_vec(metadata).unwrap(),
            body,
        )
        .await
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.broker.state_dir)).unwrap()
    }

    fn count(&self, event: &str) -> usize {
        self.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type=?1",
                [event],
                |r| r.get(0),
            )
            .unwrap()
    }

    async fn wait_sent(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.broker.fake.requests.lock().unwrap().len() != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {expected} supervised upstream requests, observed {}",
                self.broker.fake.requests.lock().unwrap().len()
            )
        });
    }

    async fn wait_finished(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.count("execution.finished") != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {expected} durable terminal commits, observed {}",
                self.count("execution.finished")
            )
        });
    }

    // Disconnect only after the transport confirms a durable admitted effect.
    async fn disconnect_after_admission(&self, metadata: &Value, expected: usize) {
        let bytes = serde_json::to_vec(metadata).unwrap();
        let mut stream = UnixStream::connect(self.broker.agent_sock()).await.unwrap();
        let mut frame = FrameHeader {
            channel: Channel::Agent,
            flags: 0,
            message_type: agent_msg::CALL,
            request_id: RequestId::new_random(),
            metadata_len: bytes.len() as u32,
            body_len: 0,
        }
        .encode()
        .to_vec();
        frame.extend_from_slice(&bytes);
        stream.write_all(&frame).await.unwrap();
        self.wait_sent(expected).await;
        drop(stream);
    }

    fn gate(&self) -> Arc<Notify> {
        self.broker.fake.push_response_gated(Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())].into(),
            body: b"{}".to_vec().into(),
        }))
    }

    async fn approve(&self, metadata: &Value, body: &[u8]) -> Value {
        let required = self.call(metadata, body).await;
        assert_eq!(required.err_code(), "APPROVAL_REQUIRED");
        let id = required.metadata["approval"]["challenge_id"].clone();
        let review = common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_LOCAL_REVIEW,
            &serde_json::to_vec(&json!({"approval_request_id":id})).unwrap(),
            &[],
        )
        .await;
        // Contract: the CLI validates exactly what the daemon emits.
        let parsed_id: rekey_domain::ids::ApprovalRequestId = id.as_str().unwrap().parse().unwrap();
        let review_metadata = serde_json::to_vec(review.ok()).unwrap();
        ipc::validate_local_review_reply(parsed_id, &review_metadata, &review.body)
            .unwrap()
            .1
            .unwrap();
        let remembered = common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::DESKTOP_REMEMBER,
            br#"{"lifetime_ms":604800000}"#,
            &common::proof_body(common::PASSWORD),
        )
        .await;
        remembered.ok();
        let mut proof = Vec::new();
        ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut proof);
        common::call(&self.broker.admin_sock(), Channel::Admin, admin_msg::APPROVAL_LOCAL_APPROVE,
            &serde_json::to_vec(&json!({"approval_request_id":id,"expected_review_sha256":review.ok()["review_sha256"]})).unwrap(), &proof).await.ok();
        id
    }

    async fn approval_state(&self, id: &Value) -> String {
        let response = common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            agent_msg::AWAIT_APPROVAL,
            &serde_json::to_vec(&json!({"request_id":id,"timeout_s":0})).unwrap(),
            &[],
        )
        .await;
        response.ok();
        serde_json::from_slice::<Value>(&response.body).unwrap()["state"]
            .as_str()
            .unwrap()
            .into()
    }

    fn assert_paired_terminals(&self, expected: usize) {
        assert_eq!(self.count("execution.started"), expected);
        let unpaired: usize = self.db().query_row(
            "SELECT count(*) FROM (SELECT request_id FROM audit_events WHERE event_type IN ('execution.started','execution.finished','execution.blocked','execution.indeterminate') AND request_id IN (SELECT request_id FROM audit_events WHERE event_type='execution.started') GROUP BY request_id HAVING sum(event_type='execution.started') != 1 OR sum(event_type!='execution.started') != 1)",
            [], |r| r.get(0)).unwrap();
        assert_eq!(
            unpaired, 0,
            "each admitted request owns exactly one terminal"
        );
    }
}

fn read(index: usize) -> Value {
    json!({"connection":format!("fixture-{index}"),"method":"GET","path":"/repos/a/b"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_calls_keep_per_connection_capacity_and_approved_busy_retry_is_once() {
    let f = Fixture::new(1, 1000, false).await;
    let mut write = json!({"connection":"fixture-0","method":"POST","path":"/repos/a/b/issues"});
    let body = br#"{"title":"approved request"}"#;
    let id = f.approve(&write, body).await;
    write["approval_request_id"] = id.clone();
    let mut gates = Vec::new();
    for count in 1..=4 {
        gates.push(f.gate());
        f.disconnect_after_admission(&read(0), count).await;
    }
    assert_eq!(f.call(&write, body).await.err_code(), "AUTHORITY_BUSY");
    assert_eq!(f.approval_state(&id).await, "approved");
    assert_eq!(f.count("approval.accepted"), 0);
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 4);
    gates.pop().unwrap().notify_one();
    f.wait_finished(1).await;
    let (first, second) = tokio::join!(f.call(&write, body), f.call(&write, body));
    assert_eq!(
        usize::from(first.message_type == ipc::resp_msg::OK)
            + usize::from(second.message_type == ipc::resp_msg::OK),
        1
    );
    assert_eq!(f.approval_state(&id).await, "consumed");
    assert_eq!(f.count("approval.accepted"), 1);
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 5);
    for gate in gates {
        gate.notify_one();
    }
    f.wait_finished(5).await;
    f.assert_paired_terminals(5);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_calls_keep_agent_request_capacity_until_terminal() {
    // CALL handlers retain their IPC slots while admitted work is supervised,
    // even after the client disconnects. Agent IPC reserves one connection for
    // capacity replies; the independent global-120 executor regression lives in
    // executor::local::tests::disconnected_receivers_cannot_exceed_global_supervised_execution_limit.
    let capacity = MAX_AGENT_REQUEST_CONNECTIONS;
    let spare_connection = capacity.div_ceil(4);
    let f = Fixture::new(spare_connection + 1, 1000, false).await;
    let mut gates = Vec::new();
    for count in 0..capacity {
        gates.push(f.gate());
        f.disconnect_after_admission(&read(count / 4), count + 1)
            .await;
    }
    for _ in 0..5 {
        let busy = f.call(&read(spare_connection), &[]).await;
        assert_eq!(busy.err_code(), "AUTHORITY_BUSY");
        assert_eq!(busy.metadata["message"], "connection capacity exhausted");
        assert_eq!(busy.metadata["retryable"], true);
    }
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), capacity);
    assert_eq!(f.count("execution.started"), capacity);
    assert_eq!(f.count("execution.finished"), 0);
    gates.pop().unwrap().notify_one();
    f.wait_finished(1).await;
    // After the terminal commits, the disconnected handler can finish and
    // release its request slot. No rejected call reached execution admission.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let retry = f.call(&read(spare_connection), &[]).await;
            if retry.message_type == ipc::resp_msg::OK {
                break;
            }
            assert_eq!(retry.err_code(), "AUTHORITY_BUSY");
            assert_eq!(retry.metadata["message"], "connection capacity exhausted");
            assert_eq!(retry.metadata["retryable"], true);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for gate in gates {
        gate.notify_one();
    }
    f.wait_finished(capacity + 1).await;
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), capacity + 1);
    f.assert_paired_terminals(capacity + 1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_publishes_signed_models_rules_and_expiry_so_agents_need_not_guess() {
    let f = Fixture::new(1, 1000, true).await;
    let agent = |opcode, metadata: Value| {
        let sock = f.broker.agent_sock();
        async move {
            common::call(
                &sock,
                Channel::Agent,
                opcode,
                &serde_json::to_vec(&metadata).unwrap(),
                &[],
            )
            .await
        }
    };
    let listed = agent(agent_msg::LIST_CAPABILITIES, json!({})).await;
    listed.ok();
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    assert_eq!(list.policy_expires_at_ms, Some(4_102_444_800_000));
    let connection = &list.connections[0];
    let llm = connection.llm.as_ref().unwrap();
    assert_eq!(llm.models.iter().collect::<Vec<_>>(), ["synthetic-model"]);
    let chat = connection
        .operations
        .iter()
        .find(|operation| operation.name == "openai.chat")
        .unwrap();
    assert_eq!(
        chat.parameters["properties"]["model"]["enum"],
        json!(["synthetic-model"])
    );
    let described = agent(agent_msg::DESCRIBE, json!({"operation":"openai.chat"})).await;
    described.ok();
    let describe: ipc::DescribeResponse = serde_json::from_slice(&described.body).unwrap();
    assert_eq!(describe.connection, "fixture-0");
    assert_eq!(
        describe.operation.parameters["properties"]["model"]["enum"],
        json!(["synthetic-model"])
    );
    assert!(
        describe
            .rules
            .iter()
            .any(|rule| rule.path == "/v1/chat/completions")
    );
    assert!(describe.caller_rules.is_empty());
    assert_eq!(describe.limits.requests_per_hour, 1000);
    assert_eq!(describe.llm.unwrap().max_tokens, 32);
    assert_eq!(describe.policy_expires_at_ms, Some(4_102_444_800_000));
    // Discovery is public signed policy: no credential identifier is published.
    let raw = String::from_utf8(described.body.clone()).unwrap();
    assert!(!raw.contains("credential_id"));
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_mode_password_approves_but_unlock_only_remembered_key_cannot() {
    let f = Fixture::new(1, 1000, false).await;
    let mut write = json!({"connection":"fixture-0","method":"POST","path":"/repos/a/b/issues"});
    let body = br#"{"title":"basic mode approval"}"#;
    let required = f.call(&write, body).await;
    assert_eq!(required.err_code(), "APPROVAL_REQUIRED");
    let id = required.metadata["approval"]["challenge_id"].clone();
    let admin = |opcode, metadata: Value, proof: Vec<u8>| {
        let sock = f.broker.admin_sock();
        async move {
            common::call(
                &sock,
                Channel::Admin,
                opcode,
                &serde_json::to_vec(&metadata).unwrap(),
                &proof,
            )
            .await
        }
    };
    let review = admin(
        admin_msg::APPROVAL_LOCAL_REVIEW,
        json!({"approval_request_id":id}),
        Vec::new(),
    )
    .await;
    // Contract: the real Connection review body is accepted by the CLI validator.
    let parsed_id: rekey_domain::ids::ApprovalRequestId = id.as_str().unwrap().parse().unwrap();
    let (metadata, review_json) = ipc::validate_local_review_reply(
        parsed_id,
        &serde_json::to_vec(review.ok()).unwrap(),
        &review.body,
    )
    .unwrap();
    assert!(
        review_json
            .unwrap()
            .contains(ipc::LOCAL_APPROVAL_REVIEW_RECORD_TYPE)
    );
    let decision =
        json!({"approval_request_id":id,"expected_review_sha256":metadata.review_sha256});
    let proof = |kind, secret: &[u8]| {
        let mut body = Vec::new();
        ipc::encode_proof_body(kind, secret, &mut body);
        body
    };

    // `rekey unlock --remember` stores an unlock-only key in a same-user file.
    let remembered = admin(
        admin_msg::DESKTOP_REMEMBER,
        json!({"lifetime_ms":604_800_000,"unlock_only":true}),
        common::proof_body(common::PASSWORD),
    )
    .await;
    remembered.ok();
    let file_key = remembered.body.clone();
    let denied = admin(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        decision.clone(),
        proof(ipc::ProofKind::Presence, &file_key),
    )
    .await;
    assert_ne!(denied.err_code(), "");
    // Resuming with the file key unlocks but still grants no approval authority.
    admin(
        admin_msg::DESKTOP_RESUME,
        json!({}),
        proof(ipc::ProofKind::Presence, &file_key),
    )
    .await
    .ok();
    let denied = admin(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        decision.clone(),
        proof(ipc::ProofKind::Presence, &file_key),
    )
    .await;
    assert_ne!(denied.err_code(), "");
    let recovery = admin(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        decision.clone(),
        proof(ipc::ProofKind::Recovery, b"synthetic-recovery"),
    )
    .await;
    assert_ne!(recovery.err_code(), "");
    assert_eq!(f.approval_state(&id).await, "pending");
    assert_eq!(f.count("approval.approved"), 0);

    // The vault password is the basic-mode approval proof.
    let approved = admin(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        decision,
        proof(ipc::ProofKind::Password, common::PASSWORD),
    )
    .await;
    approved.ok();
    assert_eq!(f.approval_state(&id).await, "approved");
    let reasons: Vec<String> = {
        let db = f.db();
        let mut statement = db
            .prepare("SELECT reason_code FROM audit_events WHERE event_type='approval.approved'")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(reasons, ["local-password"]);
    f.broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: b"{}".to_vec().into(),
    }));
    write["approval_request_id"] = id;
    f.call(&write, body).await.ok();
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hourly_denial_preserves_approved_request_without_started_or_effect() {
    let f = Fixture::new(1, 1, false).await;
    f.call(&read(0), &[]).await.ok();
    let mut write = json!({"connection":"fixture-0","method":"POST","path":"/repos/a/b/issues"});
    let body = br#"{"title":"over hourly limit"}"#;
    let id = f.approve(&write, body).await;
    write["approval_request_id"] = id.clone();
    for _ in 0..2 {
        assert_eq!(f.call(&write, body).await.err_code(), "BUDGET_EXCEEDED");
        assert_eq!(f.approval_state(&id).await, "approved");
    }
    assert_eq!(f.count("approval.accepted"), 0);
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    f.assert_paired_terminals(1);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daily_denial_preserves_approval_without_started_or_effect() {
    let f = Fixture::new(1, 2, true).await;
    let meta = json!({"connection":"fixture-0","method":"POST","path":"/v1/chat/completions"});
    let first_body = br#"{"model":"synthetic-model","messages":[],"max_tokens":16}"#;
    let id = f.approve(&meta, first_body).await;
    let mut first = meta.clone();
    first["approval_request_id"] = id;
    f.broker.fake.push_response(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: CHAT.to_vec().into(),
    }));
    f.call(&first, first_body).await.ok();
    let second_body = br#"{"model":"synthetic-model","messages":[],"max_tokens":17}"#;
    let id = f.approve(&meta, second_body).await;
    let mut second = meta;
    second["approval_request_id"] = id.clone();
    assert_eq!(
        f.call(&second, second_body).await.err_code(),
        "BUDGET_EXCEEDED"
    );
    assert_eq!(f.approval_state(&id).await, "approved");
    assert_eq!(f.count("approval.accepted"), 1);
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.broker.fake.requests.lock().unwrap().len(), 1);
    let usage: usize = f
        .db()
        .query_row("SELECT count(*) FROM profile_usage", [], |r| r.get(0))
        .unwrap();
    assert_eq!(usage, 1);
    f.assert_paired_terminals(1);
    f.broker.shutdown().await;
}
