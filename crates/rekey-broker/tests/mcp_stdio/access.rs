//! MCP access-request limits and Connection selectors over the real daemon.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fourth_mcp_access_request_in_a_minute_is_rate_limited_with_reset_time() {
    let f = Fixture::new("github-pat").await;
    let mut mcp = f.mcp("2025-11-25");
    let request = json!({"provider":"github","operation":"github.get_issue","reason":"Read the requested issue"});
    for _ in 0..3 {
        successful(&mcp.call("request_access", request.clone()));
    }
    let limited = mcp.call("request_access", request);
    assert_eq!(result_code(&limited), "RATE_LIMITED");
    let error = &limited["result"]["structuredContent"];
    assert_eq!(error["retryable"], false);
    assert!(error["next"].as_str().unwrap().contains("UTC"), "{error}");
    assert!(f.broker.fake.take_requests().is_empty());
    drop(mcp);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_describe_and_call_select_one_of_two_connections_sharing_an_operation() {
    let f = Fixture::new("openai").await;
    let regional = |preset: &str| {
        let mut connection = rekey_policy::presets::builtin_preset(preset)
            .unwrap()
            .connection(preset.into(), f.connection.credential_id);
        connection.llm = f.connection.llm.clone();
        connection
    };
    common::policy::activate_snapshot(
        &f.broker,
        json!({
            "format_version":8,"version":2,"expires_at_ms":4_102_444_800_000_i64,
            "approvers":[],"workload_identities":[],"profiles":[],"bindings":[],"rules":[],
            "connections":[regional("qwen"),regional("qwen-intl")],"ssh_keys":[],"derived_credentials":[],
        }),
    )
    .await;
    let mut mcp = f.mcp("2025-11-25");
    // Shared names never become a named tool that picks a Connection by accident.
    generic_only(&mcp.list());
    let ambiguous = mcp.call("describe", json!({"operation":"qwen.chat"}));
    assert_eq!(result_code(&ambiguous), "INVALID_INPUT");
    let guidance = ambiguous["result"]["structuredContent"]["next"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(guidance.contains("qwen, qwen-intl"), "{guidance}");
    let described = mcp.call(
        "describe",
        json!({"operation":"qwen.chat","connection":"qwen-intl"}),
    );
    assert_eq!(successful(&described)["connection"], "qwen-intl");
    let args = json!({"model":"synthetic-model"});
    let refused = mcp.call(
        "call",
        json!({"operation":"qwen.chat","args":args,"dry_run":true}),
    );
    assert_eq!(result_code(&refused), "INVALID_INPUT");
    assert!(
        refused["result"]["structuredContent"]["next"]
            .as_str()
            .unwrap()
            .contains("connection")
    );
    let dry = mcp.call(
        "call",
        json!({"operation":"qwen.chat","connection":"qwen-intl","args":args,"dry_run":true}),
    );
    assert_eq!(
        successful(&dry)["origin"],
        "https://dashscope-intl.aliyuncs.com"
    );
    assert!(f.broker.fake.take_requests().is_empty());
    drop(mcp);
    f.broker.shutdown().await;
}
