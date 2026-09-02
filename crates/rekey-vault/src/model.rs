use rekey_domain::credential::{CredentialKind, CredentialState, VersionState};
use rekey_domain::ids::{
    ActionId, CredentialId, PolicyRuleId, PrincipalId, RequestId, SessionId, VaultId, WrapperId,
};

pub const FORMAT_VERSION: u32 = 5;
pub const VAULT_INTEGRITY_CIPHERTEXT_LEN: usize = 40;

#[derive(Debug, Clone)]
pub struct VaultHeaderRecord {
    pub vault_id: VaultId,
    pub format_version: u32,
    pub crypto_suite: String,
    pub created_at_ms: i64,
    pub schema_digest: [u8; 32],
    pub integrity_nonce: [u8; 12],
    pub integrity_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperKind {
    Password,
    Recovery,
}

impl WrapperKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Recovery => "recovery",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "password" => Some(Self::Password),
            "recovery" => Some(Self::Recovery),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperState {
    Active,
    Disabled,
}

impl WrapperState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// One wrapped copy of the VRK. `wrapped_vrk` is AES-GCM ciphertext bound to
/// this wrapper row through AAD.
#[derive(Debug, Clone)]
pub struct KeyWrapperRecord {
    pub wrapper_id: WrapperId,
    pub kind: WrapperKind,
    pub state: WrapperState,
    pub kdf_algorithm: String,
    pub kdf_params_json: String,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub wrapped_vrk: Vec<u8>,
    pub created_at_ms: i64,
    pub disabled_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CredentialRecord {
    pub credential_id: CredentialId,
    pub label: String,
    pub kind: CredentialKind,
    pub state: CredentialState,
    pub current_version: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub state_nonce: [u8; 12],
    pub state_ciphertext: [u8; 16],
}

/// One immutable encrypted credential version.
#[derive(Debug, Clone)]
pub struct CredentialVersionRecord {
    pub credential_id: CredentialId,
    pub version: u64,
    pub state: VersionState,
    pub aad_version: u16,
    pub crypto_suite: String,
    pub dek_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub payload_nonce: [u8; 12],
    pub encrypted_payload: Vec<u8>,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionState {
    Active,
    Retired,
    Disabled,
}

impl ActionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "retired" => Some(Self::Retired),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub action_id: ActionId,
    pub version: u64,
    pub name: String,
    pub state: ActionState,
    pub credential_id: CredentialId,
    pub origin: String,
    pub method: String,
    pub exact_path: String,
    pub auth_header: String,
    pub auth_prefix: String,
    pub request_max_bytes: u32,
    pub allowed_extra_headers_json: String,
    pub response_max_bytes: u32,
    pub allowed_response_headers_json: String,
    pub timeout_ms: u32,
    pub created_at_ms: i64,
}

/// Audit event. Field discipline is enforced at construction: no secrets, no
/// bodies, no raw errors — only identifiers, codes, and counters.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_id: [u8; 16],
    pub request_id: Option<RequestId>,
    pub session_id: Option<SessionId>,
    pub action_id: Option<ActionId>,
    pub action_version: Option<u64>,
    pub credential_id: Option<CredentialId>,
    pub credential_version: Option<u64>,
    pub authorization: Option<AuthorizationEvidence>,
    pub event_type: &'static str,
    pub outcome: &'static str,
    pub reason_code: String,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct AuthorizationEvidence {
    pub principal_id: PrincipalId,
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub policy_rule_id: Option<PolicyRuleId>,
    pub resource_type: String,
    pub resource_id: String,
    pub parameter_hash: [u8; 32],
}

pub mod event_type {
    pub const VAULT_INITIALIZED: &str = "vault.initialized";
    pub const VAULT_UNLOCKED: &str = "vault.unlocked";
    pub const VAULT_UNLOCK_FAILED: &str = "vault.unlock_failed";
    pub const VAULT_LOCKED: &str = "vault.locked";
    pub const VAULT_PASSWORD_CHANGED: &str = "vault.password_changed";
    pub const VAULT_PASSWORD_CHANGE_FAILED: &str = "vault.password_change_failed";
    pub const VAULT_RECOVERY_ROTATED: &str = "vault.recovery_rotated";
    pub const VAULT_RECOVERY_ROTATION_FAILED: &str = "vault.recovery_rotation_failed";
    pub const CREDENTIAL_CREATED: &str = "credential.created";
    pub const CREDENTIAL_ROTATED: &str = "credential.rotated";
    pub const CREDENTIAL_REVOKED: &str = "credential.revoked";
    pub const ACTION_CREATED: &str = "action.created";
    pub const ACTION_UPDATED: &str = "action.updated";
    pub const ACTION_DISABLED: &str = "action.disabled";
    pub const SESSION_CREATED: &str = "session.created";
    pub const SESSION_REVOKED: &str = "session.revoked";
    pub const POLICY_ACTIVATED: &str = "policy.activated";
    pub const GITHUB_CONNECTOR_AUTHORIZED: &str = "connector.github.authorized";
    pub const GITHUB_TOKEN_REVOKED: &str = "connector.github.token_revoked";
    pub const EXECUTION_STARTED: &str = "execution.started";
    pub const EXECUTION_FINISHED: &str = "execution.finished";
    pub const EXECUTION_BLOCKED: &str = "execution.blocked";
    pub const EXECUTION_INDETERMINATE: &str = "execution.indeterminate";
    pub const BACKUP_RELEASE_AUTHORIZED: &str = "backup.release_authorized";
    pub const BACKUP_CREATED: &str = "backup.created";
    pub const RESTORE_COMPLETED: &str = "restore.completed";
    pub const RUNTIME_FAULTED: &str = "runtime.faulted";
}

pub mod outcome {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
    pub const DENIED: &str = "denied";
    pub const UNKNOWN: &str = "unknown";
}
