//! Agent discovery, Connection selectors and access requests over the real
//! agent/admin sockets and Authority. Upstream is synthetic; nothing here
//! reaches a provider or claims real provider behavior.
mod common;

use rekey_domain::audit::{AuditPage, AuditQuery};
use rekey_domain::connection::{Connection, ConnectionLlmLimits};
use rekey_domain::ids::CredentialId;
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use serde_json::{Value, json};

struct Fixture {
    broker: common::TestBroker,
    credential: CredentialId,
    version: u64,
}

impl Fixture {
    async fn new() -> Self {
        let broker = common::start_broker().await;
        common::unlock(&broker).await;
        let credential = common::add_credential(&broker, "discovery", b"discovery-synthetic")
            .await
            .parse()
            .unwrap();
        Self {
            broker,
            credential,
            version: 0,
        }
    }

    fn connection(&self, preset: &str, name: &str) -> Connection {
        let mut connection = rekey_policy::presets::builtin_preset(preset)
            .unwrap()
            .connection(name.into(), self.credential);
        if rekey_domain::connection::is_llm_preset(preset) {
            connection.llm = Some(ConnectionLlmLimits {
                models: ["synthetic-model".into()].into_iter().collect(),
                max_tokens: 32,
                max_requests_per_day: 100,
                max_output_tokens_per_day: 1000,
            });
        }
        if preset == "github-git" {
            connection.bindings = [
                ("owner".to_owned(), vec!["example".to_owned()]),
                ("repo".to_owned(), vec!["project.git".to_owned()]),
            ]
            .into_iter()
            .collect();
        }
        connection
    }

    async fn activate(&mut self, connections: Vec<Connection>) {
        self.version += 1;
        common::policy::activate_snapshot(
            &self.broker,
            json!({
                "format_version":8,"version":self.version,"expires_at_ms":4_102_444_800_000_i64,
                "approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],
                "connections":connections,"ssh_keys":[],"derived_credentials":[],
            }),
        )
        .await;
    }

    async fn agent(&self, opcode: u16, metadata: Value) -> common::WireResponse {
        common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            opcode,
            &serde_json::to_vec(&metadata).unwrap(),
            &[],
        )
        .await
    }

    async fn admin(&self, metadata: Value, proof: bool) -> common::WireResponse {
        let body = if proof {
            common::proof_body(common::PASSWORD)
        } else {
            Vec::new()
        };
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::ACCESS_RESOLVE,
            &serde_json::to_vec(&metadata).unwrap(),
            &body,
        )
        .await
    }

    async fn request(&self, request: Value) -> common::WireResponse {
        self.agent(agent_msg::REQUEST_ACCESS, request).await
    }

    async fn access_list(&self) -> Value {
        body(&self.admin(json!({"action":"list"}), false).await)
    }
}

fn body(response: &common::WireResponse) -> Value {
    response.ok();
    serde_json::from_slice(&response.body).unwrap()
}

fn next(response: &common::WireResponse) -> String {
    response.metadata["next"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn decision<'a>(list: &'a Value, connection: &str, operation: &str) -> &'a Value {
    list["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["connection"] == connection)
        .unwrap_or_else(|| panic!("connection {connection} listed"))["decisions"]
        .as_array()
        .unwrap_or_else(|| panic!("{connection} lists per-operation decisions"))
        .iter()
        .find(|d| d["operation"] == operation)
        .unwrap_or_else(|| panic!("{operation} has a decision"))
}

fn rule_id(connection: &Connection, path: &str, effect: &str) -> Value {
    let rule = connection
        .rules
        .iter()
        .find(|r| r.path == path && serde_json::to_value(r.effect).unwrap() == effect)
        .unwrap();
    serde_json::to_value(rule.id).unwrap()
}

#[tokio::test]
async fn shared_operation_names_require_a_connection_selector() {
    let mut f = Fixture::new().await;
    f.activate(vec![
        f.connection("qwen", "qwen"),
        f.connection("qwen-intl", "qwen-intl"),
    ])
    .await;
    let ambiguous = f
        .agent(agent_msg::DESCRIBE, json!({"operation":"qwen.chat"}))
        .await;
    assert_eq!(ambiguous.err_code(), "INVALID_INPUT");
    let guidance = next(&ambiguous);
    assert!(
        guidance.contains("connection") && guidance.contains("qwen, qwen-intl"),
        "{guidance}"
    );
    for (name, origin) in [
        ("qwen", "https://dashscope.aliyuncs.com"),
        ("qwen-intl", "https://dashscope-intl.aliyuncs.com"),
    ] {
        let described = f
            .agent(
                agent_msg::DESCRIBE,
                json!({"operation":"qwen.chat","connection":name}),
            )
            .await;
        assert_eq!(body(&described)["connection"], name);
        let dry = f
            .agent(
                agent_msg::CALL,
                json!({"connection":name,"operation":"qwen.chat","args":{"model":"synthetic-model"},"dry_run":true}),
            )
            .await;
        let dry = body(&dry);
        assert_eq!(dry["origin"], origin);
        assert_eq!(dry["path"], "/compatible-mode/v1/chat/completions");
    }
    let call = f
        .agent(
            agent_msg::CALL,
            json!({"connection":"","operation":"qwen.chat","args":{"model":"synthetic-model"},"dry_run":true}),
        )
        .await;
    assert_eq!(call.err_code(), "INVALID_INPUT");
    assert!(next(&call).contains("qwen, qwen-intl"), "{}", next(&call));
    let missing = f
        .agent(
            agent_msg::DESCRIBE,
            json!({"operation":"qwen.chat","connection":"qwen-us"}),
        )
        .await;
    assert_eq!(missing.err_code(), "NOT_CONFIGURED");
    assert!(f.broker.fake.take_requests().is_empty());
    f.broker.shutdown().await;
}

#[tokio::test]
async fn discovery_reports_each_operation_decision_example_and_matched_rule() {
    let mut f = Fixture::new().await;
    let github = f.connection("github-pat", "github");
    let stripe = f.connection("stripe", "stripe");
    let git = f.connection("github-git", "git");
    f.activate(vec![
        github.clone(),
        stripe.clone(),
        git.clone(),
        f.connection("openai", "openai"),
        f.connection("anthropic", "anthropic"),
    ])
    .await;
    let list = body(&f.agent(agent_msg::LIST_CAPABILITIES, json!({})).await);
    for (connection, operation, class, effect, rule) in [
        (
            "stripe",
            "stripe.list_customers",
            "read",
            "allow",
            Some(rule_id(&stripe, "/v1/customers", "allow")),
        ),
        (
            "git",
            "git.info_refs",
            "read",
            "allow",
            Some(rule_id(&git, "/{owner}/{repo}/info/refs", "allow")),
        ),
        (
            "git",
            "git.receive_pack",
            "write",
            "approve",
            Some(rule_id(&git, "/{owner}/{repo}/git-receive-pack", "approve")),
        ),
        ("openai", "openai.chat", "read", "allow", None),
        (
            "github",
            "github.create_issue",
            "write",
            "approve",
            Some(rule_id(&github, "/**", "approve")),
        ),
        (
            "github",
            "github.get_issue",
            "read",
            "allow",
            Some(rule_id(&github, "/**", "allow")),
        ),
    ] {
        let found = decision(&list, connection, operation);
        assert_eq!(found["method_class"], class, "{operation}");
        assert_eq!(found["effect"], effect, "{operation}");
        if let Some(rule) = rule {
            assert_eq!(found["rule_id"], rule, "{operation}");
        } else {
            assert!(found["rule_id"].is_string(), "{operation}");
        }
    }
    let described = body(
        &f.agent(
            agent_msg::DESCRIBE,
            json!({"operation":"github.create_issue"}),
        )
        .await,
    );
    assert_eq!(
        described["example_args"],
        json!({"owner":"OWNER","repo":"REPO","title":"TITLE"})
    );
    assert_eq!(described["decision"]["effect"], "approve");
    assert_eq!(described["matched_rule"]["path"], "/**");
    assert_eq!(described["matched_rule"]["effect"], "approve");
    let described = body(
        &f.agent(agent_msg::DESCRIBE, json!({"operation":"git.info_refs"}))
            .await,
    );
    assert_eq!(
        described["example_args"],
        json!({"owner":"example","repo":"project.git"})
    );
    assert_eq!(described["decision"]["effect"], "allow");
    let described = body(
        &f.agent(agent_msg::DESCRIBE, json!({"operation":"openai.chat"}))
            .await,
    );
    assert_eq!(
        described["example_args"],
        json!({"model":"synthetic-model"})
    );
    // The published example is callable as-is and gets the same decision.
    let dry = f
        .agent(
            agent_msg::CALL,
            json!({"connection":"","operation":"github.create_issue","args":{"owner":"OWNER","repo":"REPO","title":"TITLE"},"dry_run":true}),
        )
        .await;
    let dry = body(&dry);
    assert_eq!(dry["effect"], "approve");
    assert!(
        dry["headers"]
            .as_array()
            .unwrap()
            .contains(&json!(["authorization", "Bearer «rekey:github»"])),
        "{dry}"
    );
    let dry = f
        .agent(
            agent_msg::CALL,
            json!({"connection":"anthropic","method":"GET","path":"/v1/models","dry_run":true}),
        )
        .await;
    assert!(
        body(&dry)["headers"]
            .as_array()
            .unwrap()
            .contains(&json!(["x-api-key", "«rekey:anthropic»"]))
    );
    let text =
        String::from_utf8(f.agent(agent_msg::LIST_CAPABILITIES, json!({})).await.body).unwrap();
    assert!(!text.contains("discovery-synthetic"));
    assert!(f.broker.fake.take_requests().is_empty());
    f.broker.shutdown().await;
}

#[tokio::test]
async fn fourth_access_request_in_a_minute_is_rate_limited_with_its_reset_time() {
    let f = Fixture::new().await;
    for attempt in 0..3 {
        f.request(json!({"provider":"stripe","reason":format!("Need billing data {attempt}")}))
            .await
            .ok();
    }
    let limited = f
        .request(json!({"provider":"stripe","reason":"Need billing data again"}))
        .await;
    assert_eq!(limited.err_code(), "RATE_LIMITED");
    assert_eq!(limited.metadata["retryable"], false);
    assert!(next(&limited).contains("UTC"), "{}", next(&limited));
    assert_eq!(
        f.access_list().await["requests"].as_array().unwrap().len(),
        3
    );
    f.broker.shutdown().await;
}

#[tokio::test]
async fn provider_requests_resolve_real_presets_and_unknown_names_are_guided() {
    let mut f = Fixture::new().await;
    let unknown = f
        .request(json!({"provider":"githubb","reason":"Read issues"}))
        .await;
    assert_eq!(unknown.err_code(), "INVALID_INPUT");
    for preset in ["github-pat", "github-oauth", "generic-bearer"] {
        assert!(next(&unknown).contains(preset), "{}", next(&unknown));
    }
    let undeclared = f
        .request(json!({"provider":"stripe","operation":"stripe.create_charge","reason":"Charge"}))
        .await;
    assert_eq!(undeclared.err_code(), "INVALID_INPUT");
    assert!(next(&undeclared).contains("stripe.list_customers"));
    let requested = body(
        &f.request(
            json!({"provider":"github","operation":"github.list_issues","reason":"Read issues"}),
        )
        .await,
    );
    let list = f.access_list().await;
    assert_eq!(list["requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        list["requests"][0]["presets"],
        json!(["github-oauth", "github-pat"])
    );
    let resolve = json!({"action":"resolve","request_id":requested["request_id"],"granted":true});
    // Approval cannot bypass signing: no signed policy, then only an
    // unrelated Connection, cannot complete the request.
    assert_eq!(
        f.admin(resolve.clone(), true).await.err_code(),
        "POLICY_INVALID"
    );
    f.activate(vec![f.connection("stripe", "github")]).await;
    assert_eq!(
        f.admin(resolve.clone(), true).await.err_code(),
        "REQUEST_DENIED"
    );
    f.activate(vec![f.connection("github-pat", "github")]).await;
    assert_eq!(body(&f.admin(resolve, true).await)["status"], "GRANTED");
    let waited = f
        .agent(
            agent_msg::AWAIT_ACCESS,
            json!({"request_id":requested["request_id"],"timeout_s":1}),
        )
        .await;
    assert_eq!(body(&waited)["status"], "GRANTED");
    f.broker.shutdown().await;
}

#[tokio::test]
async fn rejected_blocked_and_overlong_requests_follow_the_inbox_contract() {
    let f = Fixture::new().await;
    let overlong = f
        .request(json!({"provider":"stripe","reason":"x".repeat(501)}))
        .await;
    assert_eq!(overlong.err_code(), "INVALID_INPUT");
    assert!(next(&overlong).contains("500"), "{}", next(&overlong));
    let first = body(
        &f.request(json!({"provider":"stripe","reason":"y".repeat(500)}))
            .await,
    );
    let rejected = f
        .admin(
            json!({"action":"resolve","request_id":first["request_id"],"granted":false}),
            true,
        )
        .await;
    assert_eq!(body(&rejected)["status"], "REJECTED");
    let waited = f
        .agent(
            agent_msg::AWAIT_ACCESS,
            json!({"request_id":first["request_id"],"timeout_s":1}),
        )
        .await;
    assert_eq!(body(&waited)["status"], "REJECTED");
    let second = body(
        &f.request(json!({"connection":"billing","reason":"Bill"}))
            .await,
    );
    f.admin(
        json!({"action":"resolve","request_id":second["request_id"],"granted":false,"block_caller":true}),
        true,
    )
    .await
    .ok();
    let blocked = f
        .request(json!({"connection":"billing","reason":"Bill"}))
        .await;
    assert_eq!(blocked.err_code(), "DENIED");
    let list = f.access_list().await;
    let caller = list["requests"][0]["caller"].clone();
    assert_eq!(list["blocked_callers"], json!([caller]));
    let unblocked = f
        .admin(
            json!({"action":"block","caller":caller,"blocked":false}),
            true,
        )
        .await;
    assert_eq!(body(&unblocked), json!({"blocked":false}));
    f.request(json!({"connection":"billing","reason":"Bill"}))
        .await
        .ok();
    assert_eq!(f.access_list().await["blocked_callers"], json!([]));
    // An explicit block also applies at once, ahead of the rate window.
    f.admin(
        json!({"action":"block","caller":caller,"blocked":true}),
        true,
    )
    .await
    .ok();
    assert_eq!(
        f.request(json!({"connection":"billing","reason":"Bill"}))
            .await
            .err_code(),
        "DENIED"
    );
    f.broker.shutdown().await;
}

#[tokio::test]
async fn access_audit_rows_keep_caller_target_and_operation_context() {
    let mut f = Fixture::new().await;
    f.activate(vec![f.connection("github-pat", "github")]).await;
    let first = body(
        &f.request(
            json!({"connection":"github","operation":"github.create_issue","reason":"File a bug"}),
        )
        .await,
    );
    let second = body(
        &f.request(json!({"provider":"stripe","reason":"Billing"}))
            .await,
    );
    f.admin(
        json!({"action":"resolve","request_id":first["request_id"],"granted":true}),
        true,
    )
    .await
    .ok();
    f.admin(
        json!({"action":"resolve","request_id":second["request_id"],"granted":false,"block_caller":true}),
        true,
    )
    .await
    .ok();
    let caller = f.access_list().await["requests"][0]["caller"].clone();
    f.admin(
        json!({"action":"block","caller":caller,"blocked":false}),
        true,
    )
    .await
    .ok();
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
        limit: 100,
    };
    let response = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::AUDIT_QUERY,
        &serde_json::to_vec(&query).unwrap(),
        &[],
    )
    .await;
    response.ok();
    let page: AuditPage = serde_json::from_slice(&response.body).unwrap();
    page.validate_for(&query).unwrap();
    let rows: Vec<Value> = page
        .events
        .iter()
        .filter(|e| e.event_type.starts_with("access_request."))
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let row = |event: &str, reason: &str| {
        rows.iter()
            .find(|r| r["event_type"] == event && r["reason_code"] == reason)
            .unwrap_or_else(|| panic!("{event}/{reason} in {rows:?}"))
            .clone()
    };
    let created = row("access_request.created", "connection-request");
    assert_eq!(created["request_id"], first["request_id"]);
    assert_eq!(created["request_context"]["caller"], caller);
    assert_eq!(created["request_context"]["connection"], "github");
    assert_eq!(created["request_context"]["method_class"], "write");
    assert_eq!(
        created["request_context"]["normalized_path"],
        "/repos/{owner}/{repo}/issues"
    );
    let provider = row("access_request.created", "provider-request");
    assert_eq!(provider["request_context"]["connection"], "stripe");
    assert_eq!(provider["request_context"]["normalized_path"], "/");
    for (reason, connection) in [("granted", "github"), ("rejected", "stripe")] {
        let resolved = row("access_request.resolved", reason);
        assert_eq!(resolved["request_context"]["caller"], caller);
        assert_eq!(resolved["request_context"]["connection"], connection);
    }
    for (reason, connection) in [("blocked", "stripe"), ("unblocked", "access-requests")] {
        let changed = row("access_request.block_changed", reason);
        assert_eq!(changed["request_context"]["caller"], caller);
        assert_eq!(changed["request_context"]["connection"], connection);
    }
    // Rejecting with a block links both rows to the access request.
    assert_eq!(
        row("access_request.block_changed", "blocked")["request_id"],
        second["request_id"]
    );
    assert!(
        !serde_json::to_string(&rows).unwrap().contains("File a bug"),
        "untrusted reasons stay out of audit rows"
    );
    f.broker.shutdown().await;
}
