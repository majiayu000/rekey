use rekey_domain::DomainError;
use rekey_domain::ipc::FrameError;
use rekey_policy::PolicyError;
use rekey_vault::AuthorityError;
use thiserror::Error;

/// Broker-level errors. `Display` and `code()` are safe for IPC envelopes:
/// no secrets, no paths, no raw upstream or SQL text.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerError {
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("invalid frame")]
    Frame(#[from] FrameError),
    #[error("request denied: {0}")]
    Denied(&'static str),
    #[error("upstream request failed")]
    Upstream(&'static str),
    #[error("response blocked by security policy")]
    ResponseSecurityViolation,
    #[error("ipc unavailable")]
    Io(#[source] std::io::Error),
}

impl BrokerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Authority(err) => err.code(),
            Self::Domain(DomainError::InvalidCapability) => "INVALID_CAPABILITY",
            Self::Domain(DomainError::CapabilityExpired) => "CAPABILITY_EXPIRED",
            Self::Domain(DomainError::CapabilityExhausted) => "CAPABILITY_EXHAUSTED",
            Self::Domain(DomainError::ActionNotAllowed) => "ACTION_DENIED",
            Self::Domain(DomainError::ActionDisabled) => "ACTION_DISABLED",
            Self::Domain(DomainError::CredentialRevoked) => "CREDENTIAL_UNAVAILABLE",
            Self::Domain(DomainError::RequestTooLarge) => "REQUEST_TOO_LARGE",
            Self::Domain(DomainError::ResponseTooLarge) => "RESPONSE_TOO_LARGE",
            Self::Domain(_) => "INVALID_INPUT",
            Self::Policy(_) => "POLICY_INVALID",
            Self::Frame(_) => "INVALID_FRAME",
            Self::Denied(_) => "REQUEST_DENIED",
            Self::Upstream(_) => "UPSTREAM_FAILED",
            Self::ResponseSecurityViolation => "RESPONSE_SECURITY_VIOLATION",
            Self::Io(_) => "IPC_UNAVAILABLE",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Authority(AuthorityError::AuthorityBusy) | Self::Upstream(_) | Self::Io(_)
        )
    }

    /// Message safe to hand to an untrusted agent: the stable description
    /// only, never source chains.
    pub fn agent_message(&self) -> String {
        match self {
            // Agents must not distinguish missing, revoked, or undecryptable
            // credentials.
            Self::Authority(
                AuthorityError::CredentialNotFound
                | AuthorityError::CredentialRevoked
                | AuthorityError::CryptoFailure,
            ) => "credential unavailable".to_owned(),
            other => other.to_string(),
        }
    }
}
