//! The App shows 需重新授权 from the reason of `oauth.refresh_failed`
//! (agent-call §7.4). Only a provider refusal is recorded that way; a failed
//! transport keeps the grant and the ordinary refresh-failure reason.
use super::tests::Fixture;
use crate::upstream::{UpstreamError, UpstreamResponse};
use rekey_domain::action::FixedMethod;

fn refusal() -> Result<UpstreamResponse, UpstreamError> {
    Ok(UpstreamResponse {
        status: 400,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: br#"{"error":"invalid_grant"}"#.to_vec().into(),
    })
}

#[tokio::test]
async fn only_a_provider_refusal_is_audited_as_needing_reauthorization() {
    for (upstream, needs_reauth, reason) in [
        (refusal(), true, "oauth-needs-reauth"),
        (Err(UpstreamError::Transport), false, "oauth-refresh-failed"),
    ] {
        let f = Fixture::build(1000, false, 1, true).await;
        f.fake.push_response(upstream);
        let error = f
            .executor
            .admit_connection(Fixture::request(
                FixedMethod::Get,
                "/drive/v3/files",
                &[],
                None,
            ))
            .await
            .unwrap()
            .run()
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.code() == "NEEDS_REAUTH",
            needs_reauth,
            "{}",
            error.code()
        );
        let db = f.db();
        let mut rows = db
            .prepare("SELECT reason_code FROM audit_events WHERE event_type='oauth.refresh_failed'")
            .unwrap();
        let reasons: Vec<String> = rows
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(reasons, [reason]);
        drop(rows);
        drop(db);
        f.stop().await;
    }
}
