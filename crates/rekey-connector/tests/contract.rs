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
        native_plugin: None,
        text_stream: None,
        id: ActionId::new_random(),
        name: ActionName::new("test action").unwrap(),
        version: 1,
        enabled: true,
        credential_id: CredentialId::new_random(),
        origin: HttpsOrigin::parse(origin).unwrap(),
        method: FixedMethod::Get,
        target: rekey_domain::action::ActionTarget::Fixed {
            path: ExactPath::parse(path).unwrap(),
        },
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
    assert_eq!(registry().len(), if cfg!(feature = "lab") { 10 } else { 2 });
    assert!(registry().iter().all(|contract| {
        contract.source == ConnectorSource::BuiltInBinary
            && contract.isolation == ConnectorIsolation::BrokerProcess
    }));
    assert_eq!(
        BuiltInConnector::FixedHttpHeaderV1.contract().effects,
        &[CredentialEffect::Inject]
    );
    assert_eq!(
        BuiltInConnector::GitHubAppInstallationV1.contract().effects,
        &[
            CredentialEffect::Sign,
            CredentialEffect::Exchange,
            CredentialEffect::Lease,
            CredentialEffect::Revoke,
        ]
    );
    #[cfg(feature = "lab")]
    {
        assert_eq!(
            BuiltInConnector::VaultDynamicSourceV1.contract().effects,
            &[
                CredentialEffect::Resolve,
                CredentialEffect::Lease,
                CredentialEffect::Inject,
                CredentialEffect::Revoke,
            ]
        );
        assert!(
            BuiltInConnector::VaultDynamicSourceV1
                .contract()
                .revoke_before_success
        );
        assert_eq!(
            BuiltInConnector::VaultKvV2SourceV1.contract().effects,
            &[
                CredentialEffect::Exchange,
                CredentialEffect::Lease,
                CredentialEffect::Resolve,
                CredentialEffect::Inject,
                CredentialEffect::Revoke
            ]
        );
    }
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
    let mut github_comment = action(
        "https://api.github.com",
        "/repos/owner/repo/issues/7/comments",
    );
    github_comment.method = FixedMethod::Post;
    let mut github_comment_bad = action(
        "https://api.github.com",
        "/repos/owner/repo/issues/07/comments",
    );
    github_comment_bad.method = FixedMethod::Post;
    assert!(!github_action_is_reserved(&ordinary));
    assert!(github_action_is_reserved(&github));
    assert!(github_action_is_reserved(&github_issue));
    assert!(github_action_is_reserved(&github_comment));
    assert!(!github_action_is_reserved(&github_comment_bad));
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
        resolve_builtin(CredentialKind::OpaqueToken, &github_comment),
        Err(ConnectorSelectionError::SelectionRejected)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::GitHubAppInstallation, &ordinary),
        Ok(BuiltInConnector::GitHubAppInstallationV1)
    );
    #[cfg(feature = "lab")]
    assert_eq!(
        resolve_builtin(CredentialKind::VaultKvV2Source, &ordinary),
        Ok(BuiltInConnector::VaultKvV2SourceV1)
    );
    assert_eq!(
        resolve_builtin(CredentialKind::VaultKvV2Source, &github),
        Err(ConnectorSelectionError::SelectionRejected)
    );
    #[cfg(feature = "lab")]
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

#[test]
#[cfg(feature = "lab")]
fn keycloak_contract_requires_exchange_inject_revoke_and_preserves_reserved_paths() {
    let c = BuiltInConnector::KeycloakTokenExchangeV1.contract();
    assert_eq!(
        c.effects,
        &[
            CredentialEffect::Exchange,
            CredentialEffect::Inject,
            CredentialEffect::Revoke
        ]
    );
    assert!(c.revoke_before_success);
    assert_eq!(
        c.exchange_protocol,
        Some(rekey_connector::ExchangeProtocol::OAuthTokenExchange)
    );
    assert_eq!(
        resolve_builtin(
            CredentialKind::KeycloakTokenExchange,
            &action("https://api.example.com", "/fixed")
        ),
        Ok(BuiltInConnector::KeycloakTokenExchangeV1)
    );
    assert!(
        resolve_builtin(
            CredentialKind::KeycloakTokenExchange,
            &action("https://api.github.com", "/installation/repositories")
        )
        .is_err()
    );
}

#[test]
fn mcp_projection_refuses_a_valid_text_stream_action() {
    let mut action = action("https://api.anthropic.com", "/v1/messages");
    action.method = FixedMethod::Post;
    action.auth = HeaderCredentialUse::new(
        HeaderName::new("x-api-key").unwrap(),
        HeaderPrefix::new("").unwrap(),
    )
    .unwrap();
    action.text_stream = Some(rekey_domain::action::AnthropicTextStream {
        model: "fixed-model".into(),
        max_tokens: 1024,
    });
    action.validate().unwrap();
    assert!(matches!(
        project_mcp_tool(&action, &json!({"type":"object"})),
        Err(rekey_connector::McpProjectionError::UnsupportedStreaming)
    ));
}

#[test]
#[cfg(feature = "lab")]
fn gcp_source_contract_is_resolve_inject_only_and_refuses_reserved_github() {
    let contract = BuiltInConnector::GcpSecretManagerSourceV1.contract();
    assert_eq!(
        contract.credential_kind,
        CredentialKind::GcpSecretManagerSource
    );
    assert_eq!(
        contract.effects,
        &[CredentialEffect::Resolve, CredentialEffect::Inject]
    );
    assert!(!contract.revoke_before_success);
    assert_eq!(
        resolve_builtin(
            CredentialKind::GcpSecretManagerSource,
            &action("https://api.example.com", "/v1/run")
        ),
        Ok(BuiltInConnector::GcpSecretManagerSourceV1)
    );
    assert_eq!(
        resolve_builtin(
            CredentialKind::GcpSecretManagerSource,
            &action("https://api.github.com", "/installation/repositories")
        ),
        Err(ConnectorSelectionError::SelectionRejected)
    );
}
#[test]
#[cfg(feature = "lab")]
fn aws_source_contract_is_resolve_inject_only_and_refuses_reserved_github() {
    let contract = BuiltInConnector::AwsSecretsManagerSourceV1.contract();
    assert_eq!(
        contract.credential_kind,
        CredentialKind::AwsSecretsManagerSource
    );
    assert_eq!(
        contract.effects,
        &[CredentialEffect::Resolve, CredentialEffect::Inject]
    );
    assert!(!contract.revoke_before_success);
    assert_eq!(
        resolve_builtin(
            CredentialKind::AwsSecretsManagerSource,
            &action("https://api.example.com", "/v1/run")
        ),
        Ok(BuiltInConnector::AwsSecretsManagerSourceV1)
    );
    assert_eq!(
        resolve_builtin(
            CredentialKind::AwsSecretsManagerSource,
            &action("https://api.github.com", "/installation/repositories")
        ),
        Err(ConnectorSelectionError::SelectionRejected)
    );
}

#[test]
#[cfg(feature = "lab")]
fn azure_source_contract_is_resolve_inject_only_and_refuses_reserved_github() {
    let contract = BuiltInConnector::AzureKeyVaultSourceV1.contract();
    assert_eq!(
        contract.credential_kind,
        CredentialKind::AzureKeyVaultSource
    );
    assert_eq!(
        contract.effects,
        &[CredentialEffect::Resolve, CredentialEffect::Inject]
    );
    assert!(!contract.revoke_before_success);
    assert_eq!(
        resolve_builtin(
            CredentialKind::AzureKeyVaultSource,
            &action("https://api.example.com", "/v1/run")
        ),
        Ok(BuiltInConnector::AzureKeyVaultSourceV1)
    );
    assert_eq!(
        resolve_builtin(
            CredentialKind::AzureKeyVaultSource,
            &action("https://api.github.com", "/installation/repositories")
        ),
        Err(ConnectorSelectionError::SelectionRejected)
    );
}

#[test]
#[cfg(feature = "lab")]
fn onepassword_source_contract_is_resolve_inject_only_and_refuses_reserved_github() {
    let contract = BuiltInConnector::OnePasswordConnectSourceV1.contract();
    assert_eq!(
        contract.credential_kind,
        CredentialKind::OnePasswordConnectSource
    );
    assert_eq!(
        contract.effects,
        &[CredentialEffect::Resolve, CredentialEffect::Inject]
    );
    assert!(!contract.revoke_before_success);
    assert_eq!(
        resolve_builtin(
            CredentialKind::OnePasswordConnectSource,
            &action("https://api.example.com", "/v1/run")
        ),
        Ok(BuiltInConnector::OnePasswordConnectSourceV1)
    );
    assert_eq!(
        resolve_builtin(
            CredentialKind::OnePasswordConnectSource,
            &action("https://api.github.com", "/installation/repositories")
        ),
        Err(ConnectorSelectionError::SelectionRejected)
    );
}

#[test]
#[cfg(feature = "lab")]
fn vault_kv_contract_covers_approle_without_expanding_other_sources() {
    let contract = BuiltInConnector::VaultKvV2SourceV1.contract();
    assert_eq!(
        contract.effects,
        &[
            CredentialEffect::Exchange,
            CredentialEffect::Lease,
            CredentialEffect::Resolve,
            CredentialEffect::Inject,
            CredentialEffect::Revoke,
        ]
    );
    assert_eq!(
        contract.exchange_protocol,
        Some(rekey_connector::ExchangeProtocol::ProviderDefined)
    );
    assert!(contract.revoke_before_success);
    rekey_connector::testkit::assert_contract(contract);
    for connector in [
        BuiltInConnector::AwsSecretsManagerSourceV1,
        BuiltInConnector::AzureKeyVaultSourceV1,
        BuiltInConnector::GcpSecretManagerSourceV1,
        BuiltInConnector::OnePasswordConnectSourceV1,
    ] {
        assert_eq!(
            connector.contract().effects,
            &[CredentialEffect::Resolve, CredentialEffect::Inject]
        );
        assert!(!connector.contract().revoke_before_success);
        assert_eq!(connector.contract().exchange_protocol, None);
    }
}

#[cfg(not(feature = "lab"))]
#[test]
fn default_registry_cannot_select_enterprise_sources_or_plugins() {
    let mut ordinary = action("https://api.example.com", "/v1/run");
    for kind in [
        CredentialKind::VaultKvV2Source,
        CredentialKind::VaultDynamicSource,
        CredentialKind::KeycloakTokenExchange,
        CredentialKind::GcpSecretManagerSource,
        CredentialKind::AwsSecretsManagerSource,
        CredentialKind::AzureKeyVaultSource,
        CredentialKind::OnePasswordConnectSource,
        CredentialKind::MacosKeychainSource,
    ] {
        assert_eq!(
            resolve_builtin(kind, &ordinary),
            Err(ConnectorSelectionError::SelectionRejected)
        );
    }
    ordinary.native_plugin = Some(rekey_domain::action::NativePlugin {
        path: "/tmp/lab-plugin".into(),
        sha256: "a".repeat(64),
        protocol: rekey_domain::action::GITHUB_ISSUES_PROTOCOL.into(),
    });
    assert_eq!(
        resolve_builtin(CredentialKind::OpaqueToken, &ordinary),
        Err(ConnectorSelectionError::SelectionRejected)
    );
}

#[test]
fn current_connector_profiles_reject_template_targets() {
    let mut action = action("https://api.github.com", "/installation/repositories");
    action.target=serde_json::from_value(json!({
        "kind":"template","target":{"path":"/installation/repositories","params":{},"query":{}},
        "fixed_headers":{},"body_schema":null,
        "source":{"template":"team@1","capability":"read","action_index":0,"digest":vec![1;32],"signer_id":null},
        "default_policy":{"rule":"allow"}
    })).unwrap();
    assert!(!github_action_is_reserved(&action));
    for kind in [
        CredentialKind::OpaqueToken,
        CredentialKind::GitHubAppInstallation,
        CredentialKind::KeycloakTokenExchange,
    ] {
        assert!(resolve_builtin(kind, &action).is_err());
    }
}
