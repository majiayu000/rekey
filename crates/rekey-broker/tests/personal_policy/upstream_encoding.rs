//! Upstream compression contracts for default Connection calls. The upstream
//! is synthetic; nothing here claims real provider behavior.
use super::gateway::{activate, post};
use super::*;
use rekey_broker::upstream::UpstreamResponse;

/// gzip(`{"echo":"synthetic-connection-token"}`), mtime 0: a compressed echo
/// of the fixture credential that no sealing needle can see.
const GZIP_REFLECTION: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x13\xab\x56\x4a\x4d\xce\xc8\x57\xb2\x52\x2a\xae\xcc\x2b\xc9\x48\x2d\xc9\x4c\xd6\x4d\xce\xcf\xcb\x4b\x4d\x2e\xc9\xcc\xcf\xd3\x2d\xc9\xcf\x4e\xcd\x53\xaa\x05\x00\x1e\x15\x25\xc0\x25\x00\x00\x00";
const SECRET: &[u8] = b"synthetic-connection-token";

fn reply(encoding: Option<&str>, body: &[u8]) -> UpstreamResponse {
    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    if let Some(encoding) = encoding {
        headers.push(("content-encoding".to_owned(), encoding.to_owned()));
    }
    UpstreamResponse {
        status: 200,
        headers: headers.into(),
        body: body.to_vec().into(),
    }
}

/// Every upstream request asks for exactly one, identity, representation.
fn assert_identity_only(sent: &[rekey_broker::testing::RecordedRequest]) {
    assert!(!sent.is_empty());
    for request in sent {
        let values: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(values, ["identity"], "{:?}", request.headers);
    }
}

fn terminal_reasons(f: &Fixture) -> Vec<(String, String)> {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state))
        .unwrap()
        .prepare(
            "SELECT event_type, reason_code FROM audit_events \
             WHERE event_type IN ('execution.finished','execution.indeterminate') ORDER BY sequence",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

async fn activate_pat(f: &Fixture) -> String {
    let draft = f.draft(vec![f.seed().await]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    format!("{}/c/fixture", list.service_url.unwrap())
}

#[tokio::test]
async fn ipc_call_refuses_a_compressed_body_that_hides_a_reflected_secret() {
    assert!(!GZIP_REFLECTION.windows(SECRET.len()).any(|w| w == SECRET));
    let f = Fixture::new(PolicyMode::Personal, true).await;
    activate_pat(&f).await;
    let call = json!({"connection":"fixture","method":"GET","path":"/repos/a/b"});
    for encoding in ["gzip", "br", "identity, gzip"] {
        f.fake
            .push_response(Ok(reply(Some(encoding), GZIP_REFLECTION)));
        let refused = f.agent(ipc::agent_msg::CALL, call.clone(), &[]).await;
        assert_eq!(refused.err_code(), "RESPONSE_BLOCKED", "{encoding}");
        assert_eq!(refused.metadata["retryable"], false);
        assert!(!refused.body.windows(2).any(|w| w == b"\x1f\x8b"));
    }
    // Explicit identity and an uncoded body are both released unchanged.
    f.fake
        .push_response(Ok(reply(Some("identity"), b"{\"ok\":1}")));
    f.fake.push_response(Ok(reply(None, b"{\"ok\":2}")));
    for body in [b"{\"ok\":1}", b"{\"ok\":2}"] {
        let response = f.agent(ipc::agent_msg::CALL, call.clone(), &[]).await;
        response.ok();
        assert_eq!(response.body, body);
    }
    assert_identity_only(&f.fake.take_requests());
    let reasons = terminal_reasons(&f);
    assert_eq!(reasons.len(), 5, "{reasons:?}");
    for (event, reason) in &reasons[..3] {
        assert_eq!(
            (event.as_str(), reason.as_str()),
            ("execution.indeterminate", "response-encoding")
        );
    }
    assert!(reasons[3..].iter().all(|(e, _)| e == "execution.finished"));
    f.finish().await;
}

#[tokio::test]
async fn local_http_caller_cannot_negotiate_or_receive_a_compressed_body() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = format!("{}/repos/a/b", activate_pat(&f).await);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    f.fake.push_response(Ok(reply(None, b"{\"ok\":true}")));
    let out = client
        .get(&url)
        .bearer_auth("rekey")
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 200);
    assert!(out.headers().get("content-encoding").is_none());
    assert_eq!(out.bytes().await.unwrap().as_ref(), b"{\"ok\":true}");
    f.fake
        .push_response(Ok(reply(Some("gzip"), GZIP_REFLECTION)));
    let out = client
        .get(&url)
        .bearer_auth("rekey")
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 502);
    assert!(out.headers().get("content-encoding").is_none());
    let error: Value = serde_json::from_slice(&out.bytes().await.unwrap()).unwrap();
    assert_eq!(
        (&error["code"], &error["retryable"]),
        (&json!("RESPONSE_BLOCKED"), &json!(false))
    );
    assert!(error["next"].as_str().unwrap().contains("content encoding"));
    assert_identity_only(&f.fake.take_requests());
    assert_eq!(
        terminal_reasons(&f).last().unwrap(),
        &("execution.indeterminate".into(), "response-encoding".into())
    );
    f.finish().await;
}

#[tokio::test]
async fn non_streaming_llm_call_refuses_a_compressed_completion() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let url = activate(&f, "openai").await;
    f.fake.push_response(Ok(reply(
        Some("gzip"),
        br#"{"choices":[],"usage":{"completion_tokens":7}}"#,
    )));
    let out = post(&format!("{url}/v1/chat/completions"), false)
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 502);
    let error: Value = serde_json::from_slice(&out.bytes().await.unwrap()).unwrap();
    assert_eq!(error["code"], "RESPONSE_BLOCKED");
    assert_identity_only(&f.fake.take_requests());
    assert_eq!(
        terminal_reasons(&f),
        [("execution.indeterminate".into(), "response-encoding".into())]
    );
    f.finish().await;
}
