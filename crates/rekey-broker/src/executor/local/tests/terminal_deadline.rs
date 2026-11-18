//! Terminal-deadline scenarios on the real Authority. An attempt counts only
//! when the gated upstream reply is processed before the effect deadline while
//! SQLite holds the terminal commit until the run has returned. A loaded host
//! can miss that window before the reply; the committed audit (never a timer)
//! identifies such an attempt, which reruns with a doubled window.
use std::future::Future;
use std::task::Poll;

use super::*;
use crate::upstream::UpstreamError;

/// Effect windows per attempt; product deadlines are untouched. The cap keeps
/// the held SQLite lock well inside the Authority's five-second busy timeout.
const WINDOWS_MS: [u64; 6] = [150, 300, 600, 1200, 2400, 2400];

struct Reached {
    f: Fixture,
    error: BrokerError,
    terminal_event: String,
    terminal_reason: String,
}

fn terminal(f: &Fixture) -> (String, String) {
    f.db()
        .query_row(
            "SELECT event_type, reason_code FROM audit_events WHERE event_type IN \
             ('execution.finished','execution.indeterminate','execution.blocked')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

async fn attempt(oauth: bool, target: UpstreamError, window: Duration) -> Result<Reached, String> {
    let f = Fixture::build(1000, false, 1, oauth).await;
    if oauth {
        f.fake.push_response(Ok(UpstreamResponse {
            status: 200, headers: vec![("content-type".into(), "application/json".into())].into(),
            body: br#"{"access_token":"synthetic-access","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/drive.readonly"}"#.to_vec().into(),
        }));
    }
    let release = f.fake.push_response_gated(Err(target));
    let path = if oauth {
        "/drive/v3/files"
    } else {
        "/repos/a/b"
    };
    let mut admitted = f
        .executor
        .admit_connection(Fixture::request(FixedMethod::Get, path, &[], None))
        .await
        .unwrap();
    admitted.effect_deadline = Instant::now() + window;
    let db = f.db();
    let sent = 1 + usize::from(oauth);
    let mut run = Box::pin(admitted.run());
    let early = std::future::poll_fn(|cx| match run.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(Some(result.err())),
        Poll::Pending if f.fake.requests.lock().unwrap().len() < sent => Poll::Pending,
        Poll::Pending => Poll::Ready(None),
    })
    .await;
    if let Some(error) = early {
        drop(run);
        f.stop().await;
        return Err(format!("ended before its upstream request: {error:?}"));
    }
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    release.notify_one();
    // The held commit cannot confirm, so the run returns only at its deadline.
    let error = run.await.err().expect("terminal commit cannot confirm");
    db.execute_batch("COMMIT").unwrap();
    f.executor
        .terminals
        .wait_idle(crate::testing::test_timeout(Duration::from_secs(30)))
        .await
        .unwrap();
    let (terminal_event, terminal_reason) = terminal(&f);
    if terminal_reason == "upstream-timeout" {
        // The deadline fired while the reply was still waiting to be polled.
        f.stop().await;
        return Err(format!("reply polled after the deadline: {error:?}"));
    }
    Ok(Reached {
        f,
        error,
        terminal_event,
        terminal_reason,
    })
}

async fn reach(oauth: bool, target: fn() -> UpstreamError) -> Reached {
    let mut missed = Vec::new();
    for window in WINDOWS_MS {
        match attempt(oauth, target(), Duration::from_millis(window)).await {
            Ok(reached) => {
                if !missed.is_empty() {
                    eprintln!("reached at {window} ms after missed windows: {missed:?}");
                }
                return reached;
            }
            Err(reason) => missed.push(format!("{window} ms {reason}")),
        }
    }
    panic!("no attempt reached the terminal-deadline window: {missed:?}");
}

#[tokio::test]
async fn lost_response_terminal_worker_deadline_is_unconfirmed() {
    let r = reach(false, || UpstreamError::Transport).await;
    // The lost reply was processed; only its terminal commit missed the deadline.
    assert_eq!(
        (r.terminal_event.as_str(), r.terminal_reason.as_str()),
        ("execution.indeterminate", "upstream-transport")
    );
    assert!(
        matches!(
            r.error,
            BrokerError::UpstreamUnconfirmed("upstream-timeout")
        ),
        "{:?}",
        r.error
    );
    assert!(
        !r.error.retryable(),
        "terminal audit timeout must never invite replay"
    );
    assert_eq!(r.error.code(), "UPSTREAM_FAILED");
    assert_eq!(r.f.fake.take_requests().len(), 1);
    assert_eq!(r.f.count("execution.started"), 1);
    assert_eq!(r.f.count("execution.indeterminate"), 1);
    assert_eq!(r.f.count("execution.blocked"), 0);
    r.f.stop().await;
}

#[tokio::test]
async fn proven_target_block_terminal_deadline_preserves_prior_oauth_effect() {
    for oauth in [false, true] {
        let r = reach(oauth, || UpstreamError::Blocked("private-address")).await;
        let event = if oauth {
            "execution.indeterminate"
        } else {
            "execution.blocked"
        };
        assert_eq!(
            (r.terminal_event.as_str(), r.terminal_reason.as_str()),
            (event, "private-address")
        );
        if oauth {
            assert!(
                matches!(
                    r.error,
                    BrokerError::UpstreamUnconfirmed("upstream-timeout")
                ),
                "{:?}",
                r.error
            );
        } else {
            assert!(
                matches!(r.error, BrokerError::Upstream("upstream-timeout")),
                "{:?}",
                r.error
            );
        }
        assert_eq!(r.f.fake.take_requests().len(), 1 + usize::from(oauth));
        assert_eq!(r.f.count("execution.started"), 1);
        assert_eq!(r.f.count("execution.indeterminate"), usize::from(oauth));
        assert_eq!(r.f.count("execution.blocked"), usize::from(!oauth));
        assert_eq!(r.error.code(), "UPSTREAM_FAILED");
        assert_eq!(
            r.error.retryable(),
            !oauth,
            "only a proven no-effect execution permits retry"
        );
        r.f.stop().await;
    }
}
