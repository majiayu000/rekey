//! The App shows 需重新授权 from the reason of `oauth.refresh_failed`
//! (agent-call §7.4). Only a provider refusal is recorded that way; a failed
//! transport keeps the grant and the ordinary refresh-failure reason. A
//! refused grant version is never sent to the provider again.
use super::tests::Fixture;
use crate::error::BrokerError;
use crate::upstream::{UpstreamError, UpstreamResponse};
use rekey_domain::action::FixedMethod;

fn refusal() -> Result<UpstreamResponse, UpstreamError> {
    Ok(UpstreamResponse {
        status: 400,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: br#"{"error":"invalid_grant"}"#.to_vec().into(),
    })
}

async fn call(f: &Fixture) -> BrokerError {
    f.executor
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
        .unwrap()
}

fn refresh_failures(f: &Fixture) -> Vec<String> {
    let db = f.db();
    let mut rows = db
        .prepare("SELECT reason_code FROM audit_events WHERE event_type='oauth.refresh_failed'")
        .unwrap();
    rows.query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[tokio::test]
async fn a_refused_grant_is_never_resent_but_a_failed_transport_is_retried() {
    for (upstream, needs_reauth, resent) in [
        (refusal(), true, 0),
        (Err(UpstreamError::Transport), false, 1),
    ] {
        let f = Fixture::build(1000, false, 1, true).await;
        f.fake.push_response(upstream);
        call(&f).await;
        assert_eq!(f.fake.take_requests().len(), 1);
        // Lock and policy changes clear bearer caches; the refusal stays.
        f.executor.oauth.clear();
        f.fake.push_response(Err(UpstreamError::Transport));
        let error = call(&f).await;
        assert_eq!(f.fake.take_requests().len(), resent);
        assert_eq!(error.code() == "NEEDS_REAUTH", needs_reauth);
        let reason = if needs_reauth {
            "oauth-needs-reauth"
        } else {
            "oauth-refresh-failed"
        };
        // The App keeps listing the Connection: every refused call is audited.
        assert_eq!(refresh_failures(&f), [reason, reason]);
        f.stop().await;
    }
}

#[tokio::test]
async fn only_a_provider_refusal_is_audited_as_needing_reauthorization() {
    for (upstream, needs_reauth, reason) in [
        (refusal(), true, "oauth-needs-reauth"),
        (Err(UpstreamError::Transport), false, "oauth-refresh-failed"),
    ] {
        let f = Fixture::build(1000, false, 1, true).await;
        f.fake.push_response(upstream);
        let error = call(&f).await;
        assert_eq!(
            error.code() == "NEEDS_REAUTH",
            needs_reauth,
            "{}",
            error.code()
        );
        assert_eq!(refresh_failures(&f), [reason]);
        f.stop().await;
    }
}
