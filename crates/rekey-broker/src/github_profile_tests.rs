use std::collections::BTreeSet;

use aws_lc_rs::hmac;
use rekey_domain::action::{
    ActionName, ExactPath, FixedHttpAction, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ActionId, CredentialId, RequestId};

use super::*;

fn action(method: FixedMethod, path: &str) -> FixedHttpAction {
    FixedHttpAction {
        id: ActionId::new_random(),
        name: ActionName::new("github test").unwrap(),
        version: 1,
        enabled: true,
        credential_id: CredentialId::new_random(),
        origin: HttpsOrigin::parse("https://api.github.com").unwrap(),
        method,
        exact_path: ExactPath::parse(path).unwrap(),
        auth: HeaderCredentialUse::new(
            HeaderName::new("authorization").unwrap(),
            HeaderPrefix::new("Bearer ").unwrap(),
        )
        .unwrap(),
        timeout_ms: 2_000,
        request_policy: RequestPolicy {
            max_body_bytes: 64 * 1024,
            allowed_extra_headers: BTreeSet::new(),
        },
        response_policy: ResponsePolicy {
            max_body_bytes: 256 * 1024,
            allowed_headers: BTreeSet::new(),
        },
    }
}

fn request(action: &FixedHttpAction, body: serde_json::Value) -> ExecuteRequest {
    ExecuteRequest {
        request_id: RequestId::new_random(),
        capability_token: "capability".to_owned(),
        action: ActionVersionRef {
            action_id: action.id,
            version: action.version,
        },
        content_type: Some("application/json".to_owned()),
        extra_headers: Vec::new(),
        body: serde_json::to_vec(&body).unwrap(),
        approval_grants: Vec::new(),
    }
}

#[test]
fn create_issue_is_closed_to_the_configured_repository_and_body() {
    let mut profile = GitHubAppProfile::test_profile();
    let create = action(FixedMethod::Post, "/repos/owner/repo/issues");
    let valid = request(
        &create,
        serde_json::json!({"title":"bounded","body":"details"}),
    );
    assert_eq!(
        profile.action(&create, &valid),
        Ok(GitHubAction::CreateIssue {
            repository_index: 0
        })
    );

    let unknown = action(FixedMethod::Post, "/repos/owner/other/issues");
    assert_eq!(
        profile.action(
            &unknown,
            &request(&unknown, serde_json::json!({"title":"x"}))
        ),
        Err(GitHubError::ProfileMismatch)
    );
    profile.permissions.issues = None;
    assert_eq!(
        profile.action(&create, &valid),
        Err(GitHubError::ProfileMismatch)
    );
    profile.permissions.issues = Some(IssuesPermission::Write);
    assert_eq!(
        profile.action(
            &create,
            &request(&create, serde_json::json!({"title":"","labels":["wide"]}))
        ),
        Err(GitHubError::ProfileMismatch)
    );
}

#[test]
fn webhook_signature_delta_and_replay_are_bounded() {
    let mut profile = GitHubAppProfile::test_profile();
    let payload = br#"{"action":"added","installation":{"id":1,"extra":true},"repositories_added":[{"id":2,"full_name":"owner/two","private":true}],"repositories_removed":[],"sender":{"login":"ignored"}}"#;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[b's'; 32]);
    let signature = format!("sha256={}", hex(hmac::sign(&key, payload).as_ref()));
    profile.verify_webhook(payload, &signature).unwrap();
    assert_eq!(
        profile.verify_webhook(b"tampered", &signature),
        Err(GitHubError::WebhookSignature)
    );
    profile.apply_repository_webhook(payload).unwrap();
    assert_eq!(profile.repositories.len(), 2);
    assert_eq!(profile.repositories[1].name, "two");
    assert_eq!(
        profile.apply_repository_webhook(payload),
        Err(GitHubError::WebhookPayload)
    );

    let encoded = profile.to_secret_json().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(value["credential_type"], "github-app-installation-v2");
    assert_eq!(value["repositories"].as_array().unwrap().len(), 2);
}

#[test]
fn webhook_rejects_mixed_or_wrong_installation_delta() {
    let mut profile = GitHubAppProfile::test_profile();
    let mixed = br#"{"action":"added","installation":{"id":1},"repositories_added":[{"id":2,"full_name":"owner/two"}],"repositories_removed":[{"id":1,"full_name":"owner/repo"}]}"#;
    let wrong = br#"{"action":"removed","installation":{"id":2},"repositories_added":[],"repositories_removed":[{"id":1,"full_name":"owner/repo"}]}"#;
    assert_eq!(
        profile.apply_repository_webhook(mixed),
        Err(GitHubError::WebhookPayload)
    );
    assert_eq!(
        profile.apply_repository_webhook(wrong),
        Err(GitHubError::WebhookPayload)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
