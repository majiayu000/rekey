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
    #[error("{1}")]
    LocalCall(&'static str, &'static str, &'static str),
    #[error("connection budget exceeded")]
    BudgetExceeded { reset_at_ms: i64 },
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// Broker admission rejected without an unresolved Authority command.
    /// Keep its wire error while avoiding settlement of work that was not queued.
    #[error(transparent)]
    Admission(AuthorityError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("invalid frame")]
    Frame(#[from] FrameError),
    #[error("local approval required")]
    ApprovalRequired(rekey_domain::ipc::ApprovalRequired),
    #[error("local approval outcome is unconfirmed; query its state; do not retry automatically")]
    ApprovalOutcomeUnconfirmed,
    #[error("request denied: {0}")]
    Denied(&'static str),
    #[error("upstream request failed")]
    Upstream(&'static str),
    /// A prior remote effect may have completed; replay is unsafe.
    #[error("upstream request failed")]
    UpstreamUnconfirmed(&'static str),
    #[error("upstream effect outcome is indeterminate")]
    Indeterminate(&'static str),
    #[error("response blocked by security policy")]
    ResponseSecurityViolation,
    #[error("ipc unavailable")]
    Io(#[source] std::io::Error),
    #[error("unsupported on this platform")]
    UnsupportedPlatform,
    #[error("launcher unavailable")]
    LauncherUnavailable,
}

impl BrokerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::LocalCall(code, _, _) => code,
            Self::BudgetExceeded { .. } => "BUDGET_EXCEEDED",
            Self::Authority(err) | Self::Admission(err) => err.code(),
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
            Self::ApprovalRequired(_) => "APPROVAL_REQUIRED",
            Self::ApprovalOutcomeUnconfirmed => "APPROVAL_OUTCOME_UNCONFIRMED",
            Self::Upstream(_) | Self::UpstreamUnconfirmed(_) => "UPSTREAM_FAILED",
            Self::Indeterminate(_) => "UPSTREAM_INDETERMINATE",
            Self::ResponseSecurityViolation => "RESPONSE_SECURITY_VIOLATION",
            Self::Io(_) => "IPC_UNAVAILABLE",
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::LauncherUnavailable => "LAUNCHER_UNAVAILABLE",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Authority(AuthorityError::AuthorityBusy)
                | Self::Admission(AuthorityError::AuthorityBusy)
                | Self::Upstream(_)
                | Self::Io(_)
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
                | AuthorityError::CryptoFailure
                | AuthorityError::StorageIntegrityFailed,
            ) => "credential unavailable".to_owned(),
            other => other.to_string(),
        }
    }

    pub(crate) fn agent_next(&self) -> String {
        match self {
            Self::BudgetExceeded { reset_at_ms } => {
                let reset = time::OffsetDateTime::from_unix_timestamp_nanos(
                    i128::from(*reset_at_ms) * 1_000_000,
                )
                .map(|time| time.to_string())
                .unwrap_or_else(|_| format!("Unix milliseconds {reset_at_ms}"));
                format!("Retry after {reset} UTC.")
            }
            Self::LocalCall(_, _, next) => (*next).to_owned(),
            Self::UpstreamUnconfirmed(_) => {
                "Check whether the upstream effect completed; do not retry automatically."
                    .to_owned()
            }
            other => {
                crate::ipc::frame::agent_next(crate::ipc::agent::local_agent_code(other)).to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BrokerError;

    #[test]
    fn indeterminate_upstream_effect_is_not_retryable() {
        let error = BrokerError::Indeterminate("resource-transport");
        assert_eq!(error.code(), "UPSTREAM_INDETERMINATE");
        assert!(!error.retryable());
    }

    #[test]
    fn unconfirmed_upstream_guidance_forbids_automatic_replay() {
        let error = BrokerError::UpstreamUnconfirmed("upstream-timeout");
        assert_eq!(error.code(), "UPSTREAM_FAILED");
        assert!(!error.retryable());
        assert_eq!(error.agent_message(), "upstream request failed");
        assert_eq!(
            error.agent_next(),
            "Check whether the upstream effect completed; do not retry automatically."
        );
    }

    #[test]
    fn lifecycle_rejections_preserve_authority_wire_errors() {
        use rekey_vault::AuthorityError;
        for (local, worker) in [
            (AuthorityError::AuthorityBusy, AuthorityError::AuthorityBusy),
            (AuthorityError::Draining, AuthorityError::Draining),
            (AuthorityError::Locked, AuthorityError::Locked),
        ] {
            let local = BrokerError::Admission(local);
            let worker = BrokerError::Authority(worker);
            assert_eq!(local.code(), worker.code());
            assert_eq!(local.to_string(), worker.to_string());
            assert_eq!(local.agent_message(), worker.agent_message());
            assert_eq!(local.retryable(), worker.retryable());
        }
    }

    #[test]
    fn launcher_error_codes_are_stable() {
        assert_eq!(
            BrokerError::UnsupportedPlatform.code(),
            "UNSUPPORTED_PLATFORM"
        );
        assert_eq!(
            BrokerError::LauncherUnavailable.code(),
            "LAUNCHER_UNAVAILABLE"
        );
        assert!(!BrokerError::UnsupportedPlatform.retryable());
        assert!(!BrokerError::LauncherUnavailable.retryable());
    }
}
