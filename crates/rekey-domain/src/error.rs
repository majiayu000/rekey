use thiserror::Error;

/// Stable domain errors. Messages must never contain secret material.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    #[error("invalid identifier")]
    InvalidId,
    #[error("invalid credential label")]
    InvalidCredentialLabel,
    #[error("invalid action definition: {0}")]
    InvalidActionDefinition(String),
    #[error("invalid capability")]
    InvalidCapability,
    #[error("capability expired")]
    CapabilityExpired,
    #[error("capability exhausted")]
    CapabilityExhausted,
    #[error("action is not allowed for this session")]
    ActionNotAllowed,
    #[error("credential revoked")]
    CredentialRevoked,
    #[error("action disabled")]
    ActionDisabled,
    #[error("request too large")]
    RequestTooLarge,
    #[error("response too large")]
    ResponseTooLarge,
}
