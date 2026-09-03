use std::collections::BTreeSet;

use rekey_connector::{
    BuiltInConnector, ConnectorIsolation, ConnectorSelectionError, ConnectorSource,
    CredentialEffect, OAuthAudience, OAuthTarget, OAuthTokenExchangeDescriptor, OAuthTokenType,
    adapt_mcp_invocation, github_action_is_reserved, project_mcp_tool, registry, resolve_builtin,
    sort_mcp_tools,
};
use rekey_domain::action::{
    ActionName, ExactPath, FixedHttpAction, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::credential::CredentialKind;
use rekey_domain::ids::{ActionId, CredentialId};
use serde_json::json;

fn action(origin: &str, path: &str) -> FixedHttpAction {
    FixedHttpAction {
        id: ActionId::new_random(),
        name: ActionName::new("test action").unwrap(),
        version: 1,
        enabled: true,
        credential_id: CredentialId::new_random(),
        origin: HttpsOrigin::parse(origin).unwrap(),
        method: FixedMethod::Get,
        exact_path: ExactPath::parse(path).unwrap(),
        auth: HeaderCredentialUse::new(
            HeaderName::new("authorization").unwrap(),
            HeaderPrefix::new("Bearer ").unwrap(),
        )
        .unwrap(),
        timeout_ms: 2_000,
        request_policy: RequestPolicy {
            max_body_bytes: 1024,
            allowed_extra_headers: BTreeSet::new(),
        },
        response_policy: ResponsePolicy {
            max_body_bytes: 1024,
            allowed_headers: BTreeSet::new(),
        },
    }
}

#[test]
fn registry_is_versioned_ordered_and_lifecycle_complete() {
    rekey_connector::testkit::assert_registry(registry());
    assert_eq!(registry().len(), 4);
    assert!(registry().iter().all(|contract| {
        contract.source == ConnectorSource::BuiltInBinary
            && contract.isolation == ConnectorIsolation::BrokerProcess
    }));
    assert_eq!(registry()[0].effects, &[CredentialEffect::Inject]);
    assert_eq!(
        registry()[1].effects,
        &[
            CredentialEffect::Sign,
            CredentialEffect::Exchange,
            CredentialEffect::Lease,
            CredentialEffect::Revoke,
        ]
    );
    assert_eq!(
        registry()[2].effects,
        &[
            CredentialEffect::Resolve,
            CredentialEffect::Lease,
            CredentialEffect::Inject,
            CredentialEffect::Revoke,
        ]
    );
    assert!(registry()[2].revoke_before_success);
    assert_eq!(
        registry()[3].effects,
        &[CredentialEffect::Resolve, CredentialEffect::Inject]
    );
}

#[test]
#[should_panic(expected = "lease must be revoked later")]
fn testkit_rejects_a_lease_after_the_last_revoke() {
    const EFFECTS: &[CredentialEffect] = &[
        CredentialEffect::Lease,
        CredentialEffect::Revoke,
        CredentialEffect::Lease,
    ];
    let mut contract = *registry().first().unwrap();
    contract.effects = EFFECTS;
    rekey_connector::testkit::assert_contract(&contract);
}

#[test]
fn selection_preserves_the_reserved_github_no_fallback_boundary() {
    let ordinary = action("https://api.example.com", "/v1/run");
    let github = action("https://api.github.com", "/installation/repositories");
    let mut github_issue = action("https://api.github.com", "/repos/owner/repo/issues");
    github_issue.method = FixedMethod::Post;
    assert!(!github_action_is_reserved(&ordinary));
    assert!(github_action_is_reserved(&github));
    assert!(github_action_is_reserved(&github_issue));
    assert_eq!(
        resolve_builtin(CredentialKind::OpaqueToken, &ordinary),
        Ok(BuiltInConnector::FixedHttpHeaderV1)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::OpaqueToken, &github),
        Err(ConnectorSelectionError::SelectionRejected)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::OpaqueToken, &github_issue),
        Err(ConnectorSelectionError::SelectionRejected)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::GitHubAppInstallation, &ordinary),
        Ok(BuiltInConnector::GitHubAppInstallationV1)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::VaultKvV2Source, &ordinary),
        Ok(BuiltInConnector::VaultKvV2SourceV1)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::VaultKvV2Source, &github),
        Err(ConnectorSelectionError::SelectionRejected)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::VaultDynamicSource, &ordinary),
        Ok(BuiltInConnector::VaultDynamicSourceV1)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::VaultDynamicSource, &github),
        Err(ConnectorSelectionError::SelectionRejected)
    );
}

#[test]
fn mcp_projection_is_stable_object_only_and_contains_no_authentication_input() {
    let first = action("https://api.example.com", "/v1/run");
    let second = action("https://api.example.com", "/v1/other");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {"input": {"type": "integer"}},
        "required": ["input"]
    });
    let first_tool = project_mcp_tool(&first, &schema).unwrap();
    assert_eq!(first_tool.name, format!("rekey.{}.v1", first.id));
    let encoded = serde_json::to_string(&first_tool).unwrap();
    for forbidden in ["capability", "credential", "access_token", "secret"] {
        assert!(!encoded.to_ascii_lowercase().contains(forbidden));
    }
    assert!(project_mcp_tool(&first, &json!({"type": "string"})).is_err());
    assert!(project_mcp_tool(&first, &json!({"oneOf": []})).is_err());
    assert!(
        project_mcp_tool(
            &first,
            &json!({
                "type": "object",
                "properties": {
                    "input": {"type": "string", "x-mcp-header": "Forwarded"}
                }
            })
        )
        .is_err()
    );

    let mut tools = vec![project_mcp_tool(&second, &schema).unwrap(), first_tool];
    sort_mcp_tools(&mut tools);
    assert!(tools[0].name < tools[1].name);

    let reference = ActionVersionRef {
        action_id: first.id,
        version: first.version,
    };
    let invocation = adapt_mcp_invocation(reference, &json!({"input": 7})).unwrap();
    assert_eq!(invocation.action, reference);
    assert_eq!(invocation.content_type, "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invocation.body).unwrap(),
        json!({"input": 7})
    );
    assert!(adapt_mcp_invocation(reference, &json!([1, 2])).is_err());
}

#[test]
fn oauth_projection_contains_only_fixed_public_metadata() {
    assert!(OAuthAudience::new("").is_err());
    assert!(OAuthAudience::new("bad audience").is_err());
    let descriptor = OAuthTokenExchangeDescriptor::new(
        HttpsOrigin::parse("https://issuer.example").unwrap(),
        ExactPath::parse("/oauth/token").unwrap(),
        OAuthTarget::Resource {
            origin: HttpsOrigin::parse("https://api.example.com").unwrap(),
            path: ExactPath::parse("/v1").unwrap(),
        },
        OAuthTokenType::Jwt,
        Some(OAuthTokenType::AccessToken),
        true,
    );
    let encoded = serde_json::to_string(&descriptor.metadata()).unwrap();
    assert!(encoded.contains("urn:ietf:params:oauth:grant-type:token-exchange"));
    assert!(encoded.contains("https://issuer.example/oauth/token"));
    assert!(encoded.contains("https://api.example.com/v1"));
    for forbidden in [
        "subject_token\"",
        "actor_token\"",
        "client_secret",
        "authorization",
        "refresh_token\"",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}
