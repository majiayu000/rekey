use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct PanicTransport;

impl UpstreamTransport for PanicTransport {
    fn send(&self, _request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        Box::pin(async { panic!("expired effect deadline reached transport") })
    }
}

struct StallingFirstRevoke {
    calls: AtomicUsize,
}

#[derive(Debug, PartialEq, Eq)]
struct ObservedRequest {
    method: FixedMethod,
    path: String,
    body: Vec<u8>,
}

struct SequenceTransport {
    requests: Mutex<Vec<ObservedRequest>>,
    responses: Mutex<VecDeque<UpstreamResponse>>,
}

impl SequenceTransport {
    fn new(responses: Vec<UpstreamResponse>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        }
    }
}

impl UpstreamTransport for SequenceTransport {
    fn send(&self, request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        self.requests.lock().unwrap().push(ObservedRequest {
            method: request.method,
            path: request.path,
            body: request.body,
        });
        let response = self.responses.lock().unwrap().pop_front();
        Box::pin(async move { response.ok_or(crate::upstream::UpstreamError::Transport) })
    }
}

impl UpstreamTransport for StallingFirstRevoke {
    fn send(&self, _request: UpstreamRequest) -> crate::upstream::UpstreamFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call == 0 {
                std::future::pending().await
            } else {
                Ok(UpstreamResponse {
                    status: 204,
                    headers: Vec::new().into(),
                    body: Zeroizing::new(Vec::new()),
                })
            }
        })
    }
}

#[test]
fn marked_v1_profile_fails_closed() {
    assert!(matches!(
        GitHubAppCredential::validate_profile(
            br#"{"credential_type":"github-app-installation-v1","client_id":"x"}"#,
        ),
        Err(GitHubError::InvalidCredential)
    ));
}

#[tokio::test]
async fn max_timeout_deadline_is_not_reset_at_effect_entry() {
    let profile = GitHubAppCredential::test_profile();
    let admission_started = Instant::now() - Duration::from_secs(121);
    let result = profile
        .execute_effect(
            &PanicTransport,
            GitHubAction::ListRepositories,
            Vec::new(),
            admission_started + Duration::from_secs(120),
            RESPONSE_LIMIT,
        )
        .await;
    assert!(matches!(
        result,
        GitHubEffect::WithoutToken {
            error: GitHubError::Deadline,
            remote_effect_possible: false
        }
    ));
}

#[test]
fn exchange_transport_uncertainty_is_preserved_without_a_token() {
    let failure = ExchangeFailure::uncertain_without_token(GitHubError::ExchangeTransport);
    assert!(failure.remote_effect_possible);
    assert!(failure.tokens.is_empty());

    let preflight = ExchangeFailure::without_token(GitHubError::Deadline);
    assert!(!preflight.remote_effect_possible);
}

#[test]
fn duplicate_exchange_permission_keys_are_rejected() {
    let response = br#"{"token":"t","expires_at":"later","permissions":{"metadata":"write","metadata":"read"},"repositories":[{"id":1}],"repository_selection":"selected"}"#;
    assert!(serde_json::from_slice::<ExchangeResponse<'_>>(response).is_err());
}

#[tokio::test]
async fn stalled_revoke_preserves_an_attempt_for_each_later_token() {
    let profile = GitHubAppCredential::test_profile();
    let transport = StallingFirstRevoke {
        calls: AtomicUsize::new(0),
    };
    let tokens = vec![
        Zeroizing::new("first".to_owned()),
        Zeroizing::new("second".to_owned()),
    ];

    let result = profile
        .revoke_captured_tokens(
            &transport,
            &tokens,
            Instant::now() + Duration::from_millis(100),
        )
        .await;

    assert_eq!(result, Err(GitHubError::Deadline));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn list_repositories_accepts_exact_unordered_scope_and_sanitizes_output() {
    let mut profile = GitHubAppCredential::test_profile();
    profile
        .repositories
        .push(crate::github_profile::GitHubRepository {
            id: 2,
            owner: "owner".to_owned(),
            name: "two".to_owned(),
        });
    let transport = SequenceTransport::new(vec![json_upstream(
        200,
        serde_json::json!({
            "total_count": 2,
            "repositories": [
                {"id":2,"full_name":"owner/two","private":true},
                {"id":1,"full_name":"owner/repo","private":true}
            ],
            "provider_extra": "removed"
        }),
        Vec::new(),
    )]);
    let response = profile
        .resource(
            &transport,
            &test_token(),
            GitHubAction::ListRepositories,
            Vec::new(),
            Duration::from_secs(2),
            RESPONSE_LIMIT,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
        serde_json::json!({
            "total_count":2,
            "repositories":[
                {"id":1,"owner":"owner","name":"repo"},
                {"id":2,"owner":"owner","name":"two"}
            ]
        })
    );
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn create_issue_binds_path_body_response_and_never_retries() {
    let profile = GitHubAppCredential::test_profile();
    let body = br#"{"title":"bounded"}"#.to_vec();
    let transport = SequenceTransport::new(vec![json_upstream(
        201,
        serde_json::json!({
            "id":44,
            "number":7,
            "repository_url":"https://api.github.com/repos/owner/repo",
            "html_url":"https://github.com/owner/repo/issues/7",
            "body":"provider extra"
        }),
        Vec::new(),
    )]);
    let response = profile
        .resource(
            &transport,
            &test_token(),
            GitHubAction::CreateIssue {
                repository_index: 0,
            },
            body.clone(),
            Duration::from_secs(2),
            RESPONSE_LIMIT,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
        serde_json::json!({
            "id":44,
            "number":7,
            "html_url":"https://github.com/owner/repo/issues/7"
        })
    );
    assert_eq!(
        transport.requests.lock().unwrap().as_slice(),
        &[ObservedRequest {
            method: FixedMethod::Post,
            path: "/repos/owner/repo/issues".to_owned(),
            body,
        }]
    );
}

#[tokio::test]
async fn list_retries_once_only_for_one_canonical_retry_after() {
    let profile = GitHubAppCredential::test_profile();
    let success = serde_json::json!({
        "total_count":1,
        "repositories":[{"id":1,"full_name":"owner/repo"}]
    });
    let transport = SequenceTransport::new(vec![
        json_upstream(
            429,
            serde_json::json!({"error":"limited"}),
            vec![("retry-after".to_owned(), "1".to_owned())],
        ),
        json_upstream(200, success.clone(), Vec::new()),
    ]);
    profile
        .resource(
            &transport,
            &test_token(),
            GitHubAction::ListRepositories,
            Vec::new(),
            Duration::from_secs(2),
            RESPONSE_LIMIT,
        )
        .await
        .unwrap();
    assert_eq!(transport.requests.lock().unwrap().len(), 2);

    let malformed = SequenceTransport::new(vec![json_upstream(
        429,
        serde_json::json!({"error":"limited"}),
        vec![("retry-after".to_owned(), "0".to_owned())],
    )]);
    assert_eq!(
        profile
            .resource(
                &malformed,
                &test_token(),
                GitHubAction::ListRepositories,
                Vec::new(),
                Duration::from_secs(2),
                RESPONSE_LIMIT,
            )
            .await
            .map(|_| ()),
        Err(GitHubError::ResourceRejected)
    );
    assert_eq!(malformed.requests.lock().unwrap().len(), 1);
}

fn test_token() -> InstallationToken {
    InstallationToken {
        token: Zeroizing::new("token".to_owned()),
        jwt: Zeroizing::new("jwt".to_owned()),
    }
}

fn json_upstream(
    status: u16,
    body: serde_json::Value,
    headers: Vec<(String, String)>,
) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: headers.into(),
        body: Zeroizing::new(serde_json::to_vec(&body).unwrap()),
    }
}
