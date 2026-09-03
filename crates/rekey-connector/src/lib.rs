//! Pure, versioned contracts for Rekey-owned connectors.
//!
//! This crate performs no IO and never handles credential material. The Broker
//! remains the only execution owner; these types describe and select its
//! compile-time built-in paths.

use rekey_domain::action::{ExactPath, FixedHttpAction, HttpsOrigin};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::credential::CredentialKind;
use serde::Serialize;
use serde_json::Value;

pub const CONNECTOR_CONTRACT_FORMAT_VERSION: u16 = 1;
pub const OAUTH_TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

const FIXED_HTTP_EFFECTS: &[CredentialEffect] = &[CredentialEffect::Inject];
const GITHUB_APP_EFFECTS: &[CredentialEffect] = &[
    CredentialEffect::Sign,
    CredentialEffect::Exchange,
    CredentialEffect::Lease,
    CredentialEffect::Revoke,
];

const CONTRACTS: &[ConnectorContract] = &[
    ConnectorContract {
        format_version: CONNECTOR_CONTRACT_FORMAT_VERSION,
        id: "fixed-http-header",
        version: 1,
        credential_kind: CredentialKind::OpaqueToken,
        effects: FIXED_HTTP_EFFECTS,
        exchange_protocol: None,
        source: ConnectorSource::BuiltInBinary,
        isolation: ConnectorIsolation::BrokerProcess,
        remote_effect: true,
        revoke_before_success: false,
    },
    ConnectorContract {
        format_version: CONNECTOR_CONTRACT_FORMAT_VERSION,
        id: "github-app-installation",
        version: 1,
        credential_kind: CredentialKind::GitHubAppInstallation,
        effects: GITHUB_APP_EFFECTS,
        exchange_protocol: Some(ExchangeProtocol::ProviderDefined),
        source: ConnectorSource::BuiltInBinary,
        isolation: ConnectorIsolation::BrokerProcess,
        remote_effect: true,
        revoke_before_success: true,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuiltInConnector {
    FixedHttpHeaderV1,
    GitHubAppInstallationV1,
}

impl BuiltInConnector {
    pub fn contract(self) -> &'static ConnectorContract {
        match self {
            Self::FixedHttpHeaderV1 => &CONTRACTS[0],
            Self::GitHubAppInstallationV1 => &CONTRACTS[1],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialEffect {
    Inject,
    Sign,
    Exchange,
    Lease,
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExchangeProtocol {
    OAuthTokenExchange,
    ProviderDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorSource {
    BuiltInBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorIsolation {
    BrokerProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConnectorContract {
    pub format_version: u16,
    pub id: &'static str,
    pub version: u16,
    pub credential_kind: CredentialKind,
    pub effects: &'static [CredentialEffect],
    pub exchange_protocol: Option<ExchangeProtocol>,
    pub source: ConnectorSource,
    pub isolation: ConnectorIsolation,
    pub remote_effect: bool,
    pub revoke_before_success: bool,
}

pub fn registry() -> &'static [ConnectorContract] {
    CONTRACTS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorSelectionError {
    #[error("credential and action do not match a built-in connector")]
    ProfileMismatch,
}

/// The public portion of the existing closed GitHub App action profile.
/// Request-body, header, and deadline constraints remain Broker-owned.
pub fn github_action_is_reserved(action: &FixedHttpAction) -> bool {
    action.origin.host() == "api.github.com"
        && action.origin.port() == 443
        && action.method == rekey_domain::action::FixedMethod::Get
        && action.exact_path.as_str() == "/installation/repositories"
        && action.auth.header_name.as_str() == "authorization"
        && action.auth.prefix.as_str() == "Bearer "
}

pub fn resolve_builtin(
    credential_kind: CredentialKind,
    action: &FixedHttpAction,
) -> Result<BuiltInConnector, ConnectorSelectionError> {
    match credential_kind {
        CredentialKind::OpaqueToken if !github_action_is_reserved(action) => {
            Ok(BuiltInConnector::FixedHttpHeaderV1)
        }
        CredentialKind::OpaqueToken => Err(ConnectorSelectionError::ProfileMismatch),
        CredentialKind::GitHubAppInstallation => Ok(BuiltInConnector::GitHubAppInstallationV1),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDescriptor {
    pub name: String,
    pub title: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpProjectionError {
    #[error("action definition is invalid")]
    InvalidAction,
    #[error("MCP projection requires an explicit object input schema")]
    UnsupportedInputSchema,
    #[error("MCP invocation arguments must be an object")]
    InvalidArguments,
    #[error("MCP invocation could not be serialized")]
    Serialization,
}

pub fn project_mcp_tool(
    action: &FixedHttpAction,
    input_schema: &Value,
) -> Result<McpToolDescriptor, McpProjectionError> {
    action
        .validate()
        .map_err(|_| McpProjectionError::InvalidAction)?;
    if input_schema.get("type").and_then(Value::as_str) != Some("object")
        || contains_key(input_schema, "x-mcp-header")
    {
        return Err(McpProjectionError::UnsupportedInputSchema);
    }
    Ok(McpToolDescriptor {
        name: format!("rekey.{}.v{}", action.id, action.version),
        title: action.name.as_str().to_owned(),
        description: "Execute an administrator-registered fixed Rekey action".to_owned(),
        input_schema: input_schema.clone(),
    })
}

fn contains_key(value: &Value, wanted: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(wanted) || object.values().any(|value| contains_key(value, wanted))
        }
        Value::Array(values) => values.iter().any(|value| contains_key(value, wanted)),
        _ => false,
    }
}

pub fn sort_mcp_tools(tools: &mut [McpToolDescriptor]) {
    tools.sort_by(|left, right| left.name.cmp(&right.name));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpInvocation {
    pub action: ActionVersionRef,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

pub fn adapt_mcp_invocation(
    action: ActionVersionRef,
    arguments: &Value,
) -> Result<McpInvocation, McpProjectionError> {
    if !arguments.is_object() {
        return Err(McpProjectionError::InvalidArguments);
    }
    let body = serde_json::to_vec(arguments).map_err(|_| McpProjectionError::Serialization)?;
    Ok(McpInvocation {
        action,
        content_type: "application/json",
        body,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAudience(String);

impl OAuthAudience {
    pub fn new(raw: &str) -> Result<Self, OAuthDescriptorError> {
        if raw.is_empty()
            || raw.len() > 1024
            || raw
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(OAuthDescriptorError::InvalidAudience);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthTokenType {
    AccessToken,
    RefreshToken,
    IdToken,
    Jwt,
}

impl OAuthTokenType {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::AccessToken => "urn:ietf:params:oauth:token-type:access_token",
            Self::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            Self::Jwt => "urn:ietf:params:oauth:token-type:jwt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthTarget {
    Resource {
        origin: HttpsOrigin,
        path: ExactPath,
    },
    Audience(OAuthAudience),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthTokenExchangeDescriptor {
    token_origin: HttpsOrigin,
    token_path: ExactPath,
    target: OAuthTarget,
    subject_token_type: OAuthTokenType,
    requested_token_type: Option<OAuthTokenType>,
    revoke_before_success: bool,
}

impl OAuthTokenExchangeDescriptor {
    pub fn new(
        token_origin: HttpsOrigin,
        token_path: ExactPath,
        target: OAuthTarget,
        subject_token_type: OAuthTokenType,
        requested_token_type: Option<OAuthTokenType>,
        revoke_before_success: bool,
    ) -> Self {
        Self {
            token_origin,
            token_path,
            target,
            subject_token_type,
            requested_token_type,
            revoke_before_success,
        }
    }

    pub fn metadata(&self) -> OAuthTokenExchangeMetadata {
        let target = match &self.target {
            OAuthTarget::Resource { origin, path } => OAuthTargetMetadata::Resource {
                uri: format!("{}{}", origin.as_str(), path.as_str()),
            },
            OAuthTarget::Audience(audience) => OAuthTargetMetadata::Audience {
                value: audience.as_str().to_owned(),
            },
        };
        OAuthTokenExchangeMetadata {
            grant_type: OAUTH_TOKEN_EXCHANGE_GRANT_TYPE,
            token_endpoint: format!("{}{}", self.token_origin.as_str(), self.token_path.as_str()),
            target,
            subject_token_type: self.subject_token_type.as_uri(),
            requested_token_type: self.requested_token_type.map(OAuthTokenType::as_uri),
            revoke_before_success: self.revoke_before_success,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OAuthTokenExchangeMetadata {
    pub grant_type: &'static str,
    pub token_endpoint: String,
    pub target: OAuthTargetMetadata,
    pub subject_token_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<&'static str>,
    pub revoke_before_success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OAuthTargetMetadata {
    Resource { uri: String },
    Audience { value: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OAuthDescriptorError {
    #[error("OAuth audience is invalid")]
    InvalidAudience,
}

pub mod testkit {
    use super::{CONNECTOR_CONTRACT_FORMAT_VERSION, ConnectorContract, CredentialEffect};

    pub fn assert_contract(contract: &ConnectorContract) {
        assert_eq!(
            contract.format_version, CONNECTOR_CONTRACT_FORMAT_VERSION,
            "unsupported connector contract format"
        );
        assert!(contract.version > 0, "connector version must be non-zero");
        assert!(
            !contract.effects.is_empty(),
            "connector effects must not be empty"
        );
        assert!(
            !contract.id.is_empty()
                && contract.id.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }),
            "connector id must be lowercase ASCII with optional digits and hyphens"
        );
        let lease = contract
            .effects
            .iter()
            .position(|effect| *effect == CredentialEffect::Lease);
        let revoke = contract
            .effects
            .iter()
            .position(|effect| *effect == CredentialEffect::Revoke);
        if let Some(lease) = lease {
            assert!(
                revoke.is_some_and(|revoke| revoke > lease),
                "lease must be revoked later"
            );
        }
        if contract.revoke_before_success {
            assert_eq!(contract.effects.last(), Some(&CredentialEffect::Revoke));
        }
        assert_eq!(
            contract.exchange_protocol.is_some(),
            contract.effects.contains(&CredentialEffect::Exchange),
            "exchange protocol must exactly accompany an exchange effect"
        );
    }

    pub fn assert_registry(contracts: &[ConnectorContract]) {
        for contract in contracts {
            assert_contract(contract);
        }
        for pair in contracts.windows(2) {
            assert!(
                (pair[0].id, pair[0].version) < (pair[1].id, pair[1].version),
                "connector registry must be unique and sorted"
            );
        }
    }
}
