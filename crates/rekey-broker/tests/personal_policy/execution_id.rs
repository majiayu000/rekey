//! Callers get the execution ID their audit rows use; the frame ID stays transport-only.
use super::*;
use rekey_broker::upstream::{UpstreamError, UpstreamResponse};
use rekey_domain::ids::RequestId;

/// Audit event types recorded for one execution, waiting for its terminal row.
async fn audit_events(f: &Fixture, id: RequestId) -> Vec<String> {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
    for _ in 0..100 {
        let mut query = db
            .prepare("SELECT event_type FROM audit_events WHERE request_id = ?1 ORDER BY sequence")
            .unwrap();
        let events: Vec<String> = query
            .query_map([id.as_bytes().as_slice()], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        if events.len() >= 2 {
            return events;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no terminal audit row for execution {id}");
}

fn id(value: &Value) -> RequestId {
    serde_json::from_value(value.clone()).unwrap()
}

fn response(status: u16, headers: Vec<(String, String)>) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: headers.into(),
        body: b"{}".to_vec().into(),
    }
}

#[tokio::test]
async fn call_results_name_the_execution_id_their_audit_rows_use() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let c = f.seed().await;
    let draft = f.draft(vec![c]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let call = json!({"connection":"fixture","method":"GET","path":"/repos/a/b"});

    // A non-2xx upstream status is still a completed execution.
    f.fake.push_response(Ok(response(401, Vec::new())));
    let unauthorized = f.agent(ipc::agent_msg::CALL, call.clone(), &[]).await;
    let execution = id(&unauthorized.ok()["execution_id"]);
    assert_eq!(
        audit_events(&f, execution).await,
        ["execution.started", "execution.finished"]
    );

    // An error after admission names the execution too, beside the frame ID.
    f.fake
        .push_response(Err(UpstreamError::Blocked("private-address")));
    let blocked = f.agent(ipc::agent_msg::CALL, call.clone(), &[]).await;
    assert_eq!(blocked.err_code(), "UPSTREAM_ADDRESS_BLOCKED");
    let execution = id(&blocked.metadata["execution_id"]);
    assert_ne!(json!(execution), blocked.metadata["request_id"]);
    assert_eq!(
        audit_events(&f, execution).await,
        ["execution.started", "execution.blocked"]
    );

    // Local HTTP names it in a header the upstream cannot forge.
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    let url = format!("{}/c/fixture/repos/a/b", list.service_url.unwrap());
    let forged = "00000000-0000-4000-8000-000000000000";
    f.fake.push_response(Ok(response(
        200,
        vec![("x-rekey-request-id".into(), forged.into())],
    )));
    let http = reqwest::Client::new()
        .get(&url)
        .bearer_auth("rekey")
        .send()
        .await
        .unwrap();
    assert_eq!(http.status(), 200);
    let headers = http.headers().get_all("x-rekey-request-id");
    let values: Vec<_> = headers.iter().map(|v| v.to_str().unwrap()).collect();
    assert_eq!(values.len(), 1);
    assert_ne!(values[0], forged);
    let execution = id(&json!(values[0]));
    assert_eq!(
        audit_events(&f, execution).await,
        ["execution.started", "execution.finished"]
    );
    f.finish().await;
}
