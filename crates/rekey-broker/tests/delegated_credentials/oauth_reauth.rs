//! A provider refusal is remembered per grant version (agent-call §7.4).
use super::*;

#[tokio::test]
async fn a_refused_oauth_grant_is_not_resent_until_login_or_rotation() {
    let f = Fixture::new().await;
    let id = f
        .add(
            "oauth-grant",
            &oauth_payload(Some("SYNTHETIC-REFRESH-DEAD")),
        )
        .await;
    let other = f
        .admin(
            admin_msg::CREDENTIAL_ADD,
            json!({"label":"synthetic-oauth-other","kind":"oauth-grant"}),
            &common::proof_and_secret_body(
                common::PASSWORD,
                &oauth_payload(Some("SYNTHETIC-REFRESH-OTHER")),
            ),
        )
        .await;
    let other: CredentialId = serde_json::from_value(other.ok()["id"].clone()).unwrap();
    let mut second = oauth_connection(other);
    second.name = "drive-other".into();
    for rule in &mut second.rules {
        rule.id = rekey_domain::ids::PolicyRuleId::new_random();
    }
    f.activate(vec![oauth_connection(id), second], vec![]).await;
    let refuse = || {
        f.fake
            .push_response(Ok(response(400, br#"{"error":"invalid_grant"}"#.to_vec())))
    };
    let reauth = || async { f.agent(agent_msg::CALL, get_drive()).await.err_code() };
    refuse();
    assert_eq!(reauth().await, "NEEDS_REAUTH");
    assert_eq!(f.fake.take_requests().len(), 1);
    // Neither a repeat nor lock/unlock sends the refused refresh token again.
    assert_eq!(reauth().await, "NEEDS_REAUTH");
    f.admin(admin_msg::LOCK, json!({}), &[]).await.ok();
    f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
        .await
        .ok();
    assert_eq!(reauth().await, "NEEDS_REAUTH");
    assert!(f.fake.take_requests().is_empty());
    // Another Connection still refreshes its own grant.
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-OTHER",
        "SYNTHETIC-REFRESH-OTHER",
    )));
    f.fake
        .push_response(Ok(response(200, b"{\"files\":[]}".to_vec())));
    f.agent(
        agent_msg::CALL,
        json!({"connection":"drive-other","method":"GET","path":"/drive/v3/files"}),
    )
    .await
    .ok();
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        form(&requests[0])["refresh_token"],
        "SYNTHETIC-REFRESH-OTHER"
    );
    // A rotation replaces the refused grant version.
    f.admin(
        admin_msg::CREDENTIAL_ROTATE,
        json!({"credential_id":id}),
        &common::proof_and_secret_body(
            common::PASSWORD,
            &oauth_payload(Some("SYNTHETIC-REFRESH-MANUAL")),
        ),
    )
    .await
    .ok();
    refuse();
    assert_eq!(reauth().await, "NEEDS_REAUTH");
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        form(&requests[0])["refresh_token"],
        "SYNTHETIC-REFRESH-MANUAL"
    );
    assert_eq!(reauth().await, "NEEDS_REAUTH");
    assert!(f.fake.take_requests().is_empty());
    // So does a browser login.
    let (_, fields) = begin(&f).await;
    f.fake.push_response(Ok(token_response(
        "SYNTHETIC-ACCESS-AUTHORIZED",
        "SYNTHETIC-REFRESH-AUTHORIZED",
    )));
    assert!(
        callback(&fields, &fields["state"], None)
            .await
            .starts_with("HTTP/1.1 200")
    );
    f.await_version(id, 3).await;
    assert_eq!(f.fake.take_requests().len(), 1);
    f.fake
        .push_response(Ok(response(200, b"{\"files\":[]}".to_vec())));
    f.agent(agent_msg::CALL, get_drive()).await.ok();
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].auth_value,
        b"Bearer SYNTHETIC-ACCESS-AUTHORIZED"
    );
    // Every refused call stays visible to the App's re-authorization list.
    let page = f.audit().await;
    let refused = page
        .events
        .iter()
        .filter(|event| event.reason_code == "oauth-needs-reauth")
        .count();
    assert_eq!(refused, 5);
    f.finish().await;
}
