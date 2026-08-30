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
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpaqueToken => "opaque-token",
            Self::GitHubAppInstallation => "github-app-installation",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "opaque-token" => Ok(Self::OpaqueToken),
            "github-app-installation" => Ok(Self::GitHubAppInstallation),
            _ => Err(DomainError::InvalidId),
        }
    }

    /// Stable numeric code used inside AAD encodings.
    pub fn aad_code(&self) -> u16 {
        match self {
            Self::OpaqueToken => 1,
            Self::GitHubAppInstallation => 2,
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
    fn github_kind_wire_name_matches_durable_name() {
        let encoded = serde_json::to_string(&CredentialKind::GitHubAppInstallation).unwrap();
        assert_eq!(encoded, r#""github-app-installation""#);
        assert_eq!(
            serde_json::from_str::<CredentialKind>(&encoded).unwrap(),
            CredentialKind::GitHubAppInstallation
        );
    }
}
