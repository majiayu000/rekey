use thiserror::Error;

/// Authority-level errors. `Display` output is safe for diagnostics: it never
/// contains secret material, key bytes, nonces, ciphertext, or raw SQL text.
/// Underlying causes stay in `source()` for local debugging only.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthorityError {
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("state directory is not empty")]
    StateDirectoryNotEmpty,
    #[error("vault is locked")]
    Locked,
    #[error("vault is draining")]
    Draining,
    #[error("vault runtime is faulted")]
    Faulted,
    #[error("invalid password or recovery key")]
    InvalidUnlockCredential,
    #[error("unlock attempts are rate limited")]
    UnlockRateLimited,
    #[error("operating system entropy source is unavailable")]
    EntropyUnavailable,
    #[error("cryptographic operation failed")]
    CryptoFailure,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("storage is unavailable")]
    StorageUnavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("storage integrity check failed")]
    StorageIntegrityFailed,
    #[error("state directory does not contain a supported vault layout")]
    UnsupportedVaultLayout,
    #[error("unsupported vault format version")]
    UnsupportedFormatVersion,
    #[error("state directory permissions are insecure")]
    InsecureStatePermissions,
    #[error("credential not found")]
    CredentialNotFound,
    #[error("credential label already exists")]
    CredentialConflict,
    #[error("credential revoked")]
    CredentialRevoked,
    #[error("action not found")]
    ActionNotFound,
    #[error("authority command queue is full")]
    AuthorityBusy,
    #[error("audit commit failed")]
    AuditCommitFailed,
    #[error("audit commit failed after upstream execution")]
    AuditCommitFailedAfterExecution,
    #[error("backup failed")]
    BackupFailed,
    #[error("restore failed")]
    RestoreFailed,
    #[error("invalid input: {0}")]
    Domain(#[from] rekey_domain::DomainError),
}

impl AuthorityError {
    pub fn storage(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::StorageUnavailable(Box::new(err))
    }

    /// Stable machine-readable code for IPC error envelopes.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotInitialized => "NOT_INITIALIZED",
            Self::AlreadyInitialized => "ALREADY_INITIALIZED",
            Self::StateDirectoryNotEmpty => "STATE_DIRECTORY_NOT_EMPTY",
            Self::Locked => "LOCKED",
            Self::Draining => "DRAINING",
            Self::Faulted => "FAULTED",
            Self::InvalidUnlockCredential => "INVALID_UNLOCK_CREDENTIAL",
            Self::UnlockRateLimited => "UNLOCK_RATE_LIMITED",
            Self::EntropyUnavailable => "ENTROPY_UNAVAILABLE",
            Self::CryptoFailure => "CRYPTO_FAILURE",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::StorageUnavailable(_) => "STORAGE_UNAVAILABLE",
            Self::StorageIntegrityFailed => "STORAGE_INTEGRITY_FAILED",
            Self::UnsupportedVaultLayout => "UNSUPPORTED_VAULT_LAYOUT",
            Self::UnsupportedFormatVersion => "UNSUPPORTED_FORMAT_VERSION",
            Self::InsecureStatePermissions => "INSECURE_STATE_PERMISSIONS",
            Self::CredentialNotFound => "CREDENTIAL_UNAVAILABLE",
            Self::CredentialConflict => "CREDENTIAL_CONFLICT",
            Self::CredentialRevoked => "CREDENTIAL_UNAVAILABLE",
            Self::ActionNotFound => "ACTION_NOT_FOUND",
            Self::AuthorityBusy => "AUTHORITY_BUSY",
            Self::AuditCommitFailed => "AUDIT_COMMIT_FAILED",
            Self::AuditCommitFailedAfterExecution => "AUDIT_COMMIT_FAILED_AFTER_EXECUTION",
            Self::BackupFailed => "BACKUP_FAILED",
            Self::RestoreFailed => "RESTORE_FAILED",
            Self::Domain(_) => "INVALID_INPUT",
        }
    }
}
