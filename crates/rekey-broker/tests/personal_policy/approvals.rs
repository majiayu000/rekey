//! Default-build approval contracts for HTTP retries and time windows.
//! Upstream is synthetic; the vault password stands in for presence.
use super::*;
use rekey_domain::connection::{ConnectionRule, MethodClass, MethodSelector};
use rekey_domain::ids::PolicyRuleId;

const CHALLENGE_HEADER: &str = "x-rekey-approval-challenge";

async fn activate_connection(f: &Fixture, connection: Connection) -> String {
    let draft = f.draft(vec![connection]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    list.service_url.unwrap()
}

async fn approve(f: &Fixture, id: &Value, window_seconds: Option<u32>) {
    let review = f
        .call(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":id}),
            &[],
        )
        .await;
    let mut decision =
        json!({"approval_request_id":id,"expected_review_sha256":review.ok()["review_sha256"]});
    if let Some(seconds) = window_seconds {
        decision["window_seconds"] = seconds.into();
    }
    f.call(
        admin_msg::APPROVAL_LOCAL_APPROVE,
        decision,
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
}

#[tokio::test]
async fn http_approval_retry_with_the_challenge_header_executes_exactly_once() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let service = activate_connection(&f, f.seed().await).await;
    let url = format!("{service}/c/fixture/repos/a/b/issues");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let send = |body: &'static str, challenge: Option<String>| {
        let mut request = client
            .post(&url)
            .bearer_auth("rekey")
            .header("content-type", "application/json")
            .body(body);
        if let Some(challenge) = challenge {
            request = request.header(CHALLENGE_HEADER, challenge);
        }
        request.send()
    };
    let required = send(r#"{"title":"one"}"#, None).await.unwrap();
    assert_eq!(required.status(), 403);
    let required: Value = serde_json::from_slice(&required.bytes().await.unwrap()).unwrap();
    assert_eq!(required["code"], "APPROVAL_REQUIRED");
    let id = required["approval"]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let guidance = required["next"].as_str().unwrap();
    assert!(
        guidance.contains(&format!("{CHALLENGE_HEADER}: {id}")),
        "{guidance}"
    );
    assert!(!guidance.contains("await_approval"), "{guidance}");
    // Before the decision the header returns the same challenge, unexecuted.
    let early = send(r#"{"title":"one"}"#, Some(id.clone())).await.unwrap();
    assert_eq!(early.status(), 403);
    let early: Value = serde_json::from_slice(&early.bytes().await.unwrap()).unwrap();
    assert_eq!(early["code"], "APPROVAL_REQUIRED");
    assert_eq!(early["approval"]["challenge_id"], id.as_str());
    assert!(f.fake.take_requests().is_empty());
    approve(&f, &json!(id), None).await;
    // The approval stays bound to the reviewed request body.
    let changed = send(r#"{"title":"two"}"#, Some(id.clone())).await.unwrap();
    assert_eq!(changed.status(), 403);
    assert!(f.fake.take_requests().is_empty());
    let approved = send(r#"{"title":"one"}"#, Some(id.clone())).await.unwrap();
    let status = approved.status();
    assert_eq!(status, 200, "{}", approved.text().await.unwrap());
    let sent = f.fake.take_requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].body, br#"{"title":"one"}"#);
    let replay = send(r#"{"title":"one"}"#, Some(id)).await.unwrap();
    assert_eq!(replay.status(), 403);
    assert!(f.fake.take_requests().is_empty());
    f.finish().await;
}

#[tokio::test]
async fn time_window_covers_only_its_rule_and_a_new_policy_version_clears_it() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let mut connection = f.seed().await;
    // A second approve rule, more specific than `write /**`.
    connection.rules.push(ConnectionRule {
        id: PolicyRuleId::new_random(),
        methods: MethodSelector::Class(MethodClass::Write),
        path: "/repos/*/*/pulls".into(),
        effect: RuleEffect::Approve,
    });
    activate_connection(&f, connection.clone()).await;
    let issues = json!({"connection":"fixture","method":"POST","path":"/repos/a/b/issues"});
    let pulls = json!({"connection":"fixture","method":"POST","path":"/repos/a/b/pulls"});
    let pending = f
        .agent(ipc::agent_msg::CALL, issues.clone(), br#"{"title":"one"}"#)
        .await;
    assert_eq!(pending.err_code(), "APPROVAL_REQUIRED");
    let id = pending.metadata["approval"]["challenge_id"].clone();
    approve(&f, &id, Some(1800)).await;
    let mut replay = issues.clone();
    replay["approval_request_id"] = id;
    f.agent(ipc::agent_msg::CALL, replay, br#"{"title":"one"}"#)
        .await
        .ok();
    // The window admits another request under the same rule ...
    f.agent(ipc::agent_msg::CALL, issues.clone(), br#"{"title":"two"}"#)
        .await
        .ok();
    // ... but never one matched by a different approve rule.
    assert_eq!(
        f.agent(ipc::agent_msg::CALL, pulls, br#"{"title":"pr"}"#)
            .await
            .err_code(),
        "APPROVAL_REQUIRED"
    );
    assert_eq!(f.fake.take_requests().len(), 2);
    // Re-signing the same rules is still a rule change: the window ends.
    activate_connection(&f, connection).await;
    assert_eq!(
        f.agent(ipc::agent_msg::CALL, issues, br#"{"title":"three"}"#)
            .await
            .err_code(),
        "APPROVAL_REQUIRED"
    );
    assert!(f.fake.take_requests().is_empty());
    f.finish().await;
}
