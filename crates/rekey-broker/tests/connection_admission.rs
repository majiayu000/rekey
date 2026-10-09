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
        let remembered = common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::DESKTOP_REMEMBER,
            b"{}",
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
