use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::CredentialId;
use crate::time::Timestamp;

pub const CREDENTIAL_LABEL_MAX_CHARS: usize = 128;

/// Administrator-facing display label. Never used for agent authorization.
/// Stored as plaintext metadata; confidentiality of labels is out of P0 scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CredentialLabel(String);

impl CredentialLabel {
    pub fn new(raw: &str) -> Result<Self, DomainError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::InvalidCredentialLabel);
        }
        if trimmed.chars().count() > CREDENTIAL_LABEL_MAX_CHARS {
            return Err(DomainError::InvalidCredentialLabel);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(DomainError::InvalidCredentialLabel);
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CredentialLabel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(|_| serde::de::Error::custom("invalid credential label"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    OpaqueToken,
    #[serde(rename = "github-app-installation")]
    GitHubAppInstallation,
    VaultKvV2Source,
    VaultDynamicSource,
    KeycloakTokenExchange,
    GcpSecretManagerSource,
    AwsSecretsManagerSource,
    AzureKeyVaultSource,
    #[serde(rename = "onepassword-connect-source")]
    OnePasswordConnectSource,
    MacosKeychainSource,
    SshEd25519,
    SshP256,
    SshSecureEnclaveP256,
    #[serde(rename = "oauth-grant")]
    OAuthGrant,
    AwsStatic,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpaqueToken => "opaque-token",
            Self::GitHubAppInstallation => "github-app-installation",
            Self::VaultKvV2Source => "vault-kv-v2-source",
            Self::VaultDynamicSource => "vault-dynamic-source",
            Self::KeycloakTokenExchange => "keycloak-token-exchange",
            Self::GcpSecretManagerSource => "gcp-secret-manager-source",
            Self::AwsSecretsManagerSource => "aws-secrets-manager-source",
            Self::AzureKeyVaultSource => "azure-key-vault-source",
            Self::OnePasswordConnectSource => "onepassword-connect-source",
            Self::MacosKeychainSource => "macos-keychain-source",
            Self::SshEd25519 => "ssh-ed25519",
            Self::SshP256 => "ssh-p256",
            Self::SshSecureEnclaveP256 => "ssh-secure-enclave-p256",
            Self::OAuthGrant => "oauth-grant",
            Self::AwsStatic => "aws-static",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "opaque-token" => Ok(Self::OpaqueToken),
            "github-app-installation" => Ok(Self::GitHubAppInstallation),
            "vault-kv-v2-source" => Ok(Self::VaultKvV2Source),
            "vault-dynamic-source" => Ok(Self::VaultDynamicSource),
            "keycloak-token-exchange" => Ok(Self::KeycloakTokenExchange),
            "gcp-secret-manager-source" => Ok(Self::GcpSecretManagerSource),
            "aws-secrets-manager-source" => Ok(Self::AwsSecretsManagerSource),
            "azure-key-vault-source" => Ok(Self::AzureKeyVaultSource),
            "onepassword-connect-source" => Ok(Self::OnePasswordConnectSource),
            "macos-keychain-source" => Ok(Self::MacosKeychainSource),
            "ssh-ed25519" => Ok(Self::SshEd25519),
            "ssh-p256" => Ok(Self::SshP256),
            "ssh-secure-enclave-p256" => Ok(Self::SshSecureEnclaveP256),
            "oauth-grant" => Ok(Self::OAuthGrant),
            "aws-static" => Ok(Self::AwsStatic),
            _ => Err(DomainError::InvalidId),
        }
    }

    /// Stable numeric code used inside AAD encodings.
    pub fn aad_code(&self) -> u16 {
        match self {
            Self::OpaqueToken => 1,
            Self::GitHubAppInstallation => 2,
            Self::VaultKvV2Source => 3,
            Self::VaultDynamicSource => 4,
            Self::KeycloakTokenExchange => 5,
            Self::GcpSecretManagerSource => 6,
            Self::AwsSecretsManagerSource => 7,
            Self::AzureKeyVaultSource => 8,
            Self::OnePasswordConnectSource => 9,
            Self::MacosKeychainSource => 10,
            Self::SshEd25519 => 11,
            Self::SshP256 => 12,
            Self::SshSecureEnclaveP256 => 13,
            Self::OAuthGrant => 14,
            Self::AwsStatic => 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialState {
    Active,
    Revoked,
}

impl CredentialState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(DomainError::InvalidId),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionState {
    Active,
    Retired,
    Revoked,
}

impl VersionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(DomainError::InvalidId),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    pub id: CredentialId,
    pub label: CredentialLabel,
    pub kind: CredentialKind,
    pub state: CredentialState,
    pub current_version: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVersionMetadata {
    pub credential_id: CredentialId,
    pub version: u64,
    pub state: VersionState,
    pub created_at: Timestamp,
    pub aad_version: u16,
    pub crypto_suite: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn oauth_and_aws_source_kinds_bind_distinct_aad_codes() {
        for (kind, wire, code) in [
            (CredentialKind::OAuthGrant, "oauth-grant", 14),
            (CredentialKind::AwsStatic, "aws-static", 15),
        ] {
            assert_eq!(kind.aad_code(), code);
            assert_eq!(CredentialKind::parse(wire).unwrap(), kind);
            assert_eq!(serde_json::to_value(kind).unwrap(), wire);
        }
    }
    use super::*;

    #[test]
    fn label_rules() {
        assert!(CredentialLabel::new("github deploy token").is_ok());
        assert_eq!(
            CredentialLabel::new("  padded  ").unwrap().as_str(),
            "padded"
        );
        assert!(CredentialLabel::new("").is_err());
        assert!(CredentialLabel::new("   ").is_err());
        assert!(CredentialLabel::new("a\nb").is_err());
        assert!(CredentialLabel::new("a\0b").is_err());
        assert!(CredentialLabel::new(&"x".repeat(129)).is_err());
        assert!(CredentialLabel::new(&"x".repeat(128)).is_ok());
    }

    #[test]
    fn typed_kind_wire_names_match_durable_names() {
        let encoded = serde_json::to_string(&CredentialKind::GitHubAppInstallation).unwrap();
        assert_eq!(encoded, r#""github-app-installation""#);
        assert_eq!(
            serde_json::from_str::<CredentialKind>(&encoded).unwrap(),
            CredentialKind::GitHubAppInstallation
        );
        let encoded = serde_json::to_string(&CredentialKind::VaultKvV2Source).unwrap();
        assert_eq!(encoded, r#""vault-kv-v2-source""#);
        assert_eq!(
            serde_json::from_str::<CredentialKind>(&encoded).unwrap(),
            CredentialKind::VaultKvV2Source
        );
        let encoded = serde_json::to_string(&CredentialKind::VaultDynamicSource).unwrap();
        assert_eq!(encoded, r#""vault-dynamic-source""#);
        assert_eq!(
            serde_json::from_str::<CredentialKind>(&encoded).unwrap(),
            CredentialKind::VaultDynamicSource
        );
    }
    #[test]
    fn gcp_kind_has_the_frozen_wire_and_aad_code() {
        let kind = CredentialKind::GcpSecretManagerSource;
        assert_eq!(kind.aad_code(), 6);
        assert_eq!(CredentialKind::parse(kind.as_str()).unwrap(), kind);
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            r#""gcp-secret-manager-source""#
        );
        assert_eq!(
            serde_json::from_str::<CredentialKind>(r#""gcp-secret-manager-source""#).unwrap(),
            kind
        );
        assert_eq!(
            crate::ipc::admin_msg::CREDENTIAL_ROTATE_GCP_SECRET_MANAGER,
            41
        );
    }
    #[test]
    fn aws_kind_has_the_frozen_wire_and_aad_code() {
        let kind = CredentialKind::AwsSecretsManagerSource;
        assert_eq!(kind.aad_code(), 7);
        assert_eq!(CredentialKind::parse(kind.as_str()).unwrap(), kind);
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            r#""aws-secrets-manager-source""#
        );
        assert_eq!(
            serde_json::from_str::<CredentialKind>(r#""aws-secrets-manager-source""#).unwrap(),
            kind
        );
        assert_eq!(
            crate::ipc::admin_msg::CREDENTIAL_ROTATE_AWS_SECRETS_MANAGER,
            42
        );
    }
    #[test]
    fn azure_kind_has_the_frozen_wire_and_aad_code() {
        let kind = CredentialKind::AzureKeyVaultSource;
        assert_eq!(kind.aad_code(), 8);
        assert_eq!(CredentialKind::parse(kind.as_str()).unwrap(), kind);
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            r#""azure-key-vault-source""#
        );
        assert_eq!(
            serde_json::from_str::<CredentialKind>(r#""azure-key-vault-source""#).unwrap(),
            kind
        );
        assert_eq!(crate::ipc::admin_msg::CREDENTIAL_ROTATE_AZURE_KEY_VAULT, 43);
    }
}

#[cfg(test)]
mod onepassword_source_contract {
    use super::*;
    #[test]
    fn onepassword_kind_wire_aad_and_rotate_are_stable() {
        let kind = CredentialKind::OnePasswordConnectSource;
        assert_eq!(kind.as_str(), "onepassword-connect-source");
        assert_eq!(CredentialKind::parse(kind.as_str()).unwrap(), kind);
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            "\"onepassword-connect-source\""
        );
        assert_eq!(kind.aad_code(), 9);
        assert_eq!(
            crate::ipc::admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT,
            44
        );
    }
}

#[cfg(test)]
mod keychain_source_contract {
    use super::*;
    #[test]
    fn keychain_kind_wire_aad_and_protected_rotate_are_frozen() {
        let kind = CredentialKind::MacosKeychainSource;
        assert_eq!(kind.as_str(), "macos-keychain-source");
        assert_eq!(CredentialKind::parse(kind.as_str()).unwrap(), kind);
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            "\"macos-keychain-source\""
        );
        assert_eq!(kind.aad_code(), 10);
        assert_eq!(crate::ipc::admin_msg::CREDENTIAL_ROTATE_MACOS_KEYCHAIN, 49);
        assert!(crate::ipc::managed_admin_operation(49).unwrap());
    }
}
