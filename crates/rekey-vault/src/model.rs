use rekey_domain::credential::{CredentialKind, CredentialState, VersionState};
use rekey_domain::ids::{
    ActionId, ApprovalId, ApprovalRequestId, ApproverId, CredentialId, PolicyRuleId,
    PolicySignerId, PrincipalId, RequestId, SessionId, VaultId, WrapperId,
};

pub const FORMAT_VERSION: u32 = 23;
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
    pub native_plugin_json: Option<String>,
    pub text_stream_json: Option<String>,
    pub action_id: ActionId,
    pub version: u64,
    pub name: String,
    pub state: ActionState,
    pub credential_id: CredentialId,
    pub origin: String,
    pub method: String,
    pub target_json: String,
    pub auth_header: String,
    pub auth_prefix: String,
    pub request_max_bytes: u32,
    pub allowed_extra_headers_json: String,
    pub response_max_bytes: u32,
    pub allowed_response_headers_json: String,
    pub timeout_ms: u32,
    pub created_at_ms: i64,
    pub seal_nonce: [u8; 12],
    pub seal_ciphertext: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct AuditRetentionRecord {
    pub days: Option<u64>,
    pub updated_at_ms: i64,
    pub seal_nonce: [u8; 12],
    pub seal_ciphertext: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct PolicyStateRecord {
    pub mode: rekey_domain::authorization::PolicyMode,
    pub trust_installed: bool,
    pub bundle_activated: bool,
    pub signer_id: Option<PolicySignerId>,
    pub highest_version: Option<u64>,
    pub policy_digest: Option<[u8; 32]>,
    pub bundle_digest: Option<[u8; 32]>,
    pub updated_at_ms: i64,
    pub seal_nonce: [u8; 12],
    pub seal_ciphertext: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct PolicyTrustRecord {
    pub signer_id: PolicySignerId,
    pub key: rekey_policy::PolicyVerificationKey,
    pub installed_at_ms: i64,
    pub seal_nonce: [u8; 12],
    pub seal_ciphertext: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct PolicyBundleRecord {
    pub signer_id: PolicySignerId,
    pub version: u64,
    pub expires_at_ms: i64,
    pub policy_digest: [u8; 32],
    pub bundle_digest: [u8; 32],
    pub bundle_json: Vec<u8>,
    pub activated_at_ms: i64,
    pub seal_nonce: [u8; 12],
    pub seal_ciphertext: [u8; 16],
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
    pub approval: Option<ApprovalEvidence>,
    pub event_type: &'static str,
    pub outcome: &'static str,
    pub reason_code: String,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ApprovalEvidence {
    pub approval_request_id: ApprovalRequestId,
    pub approval_id: Option<ApprovalId>,
    pub approver_id: Option<ApproverId>,
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
    pub const AUDIT_PRUNED: &str = "audit.pruned";
    pub const AUDIT_RETENTION_CHANGED: &str = "audit.retention_changed";
    pub const VAULT_VRK_ROTATED: &str = "vault.vrk_rotated";
    pub const VAULT_DEK_ROTATED: &str = "vault.dek_rotated";
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
    pub const POLICY_TRUST_INSTALLED: &str = "policy.trust_installed";
    pub const APPROVAL_REQUESTED: &str = "approval.requested";
    pub const APPROVAL_ACCEPTED: &str = "approval.accepted";
    pub const APPROVAL_REJECTED: &str = "approval.rejected";
    pub const GITHUB_CONNECTOR_AUTHORIZED: &str = "connector.github.authorized";
    pub const GITHUB_TOKEN_REVOKED: &str = "connector.github.token_revoked";
    pub const AWS_SOURCE_READ_STARTED: &str = "aws.source.read_started";
    pub const AWS_SOURCE_RESOLVED: &str = "aws.source.resolved";
    pub const GCP_SOURCE_READ_STARTED: &str = "gcp.source.read_started";
    pub const GCP_SOURCE_RESOLVED: &str = "gcp.source.resolved";
    pub const AZURE_SOURCE_READ_STARTED: &str = "azure.source.read_started";
    pub const AZURE_SOURCE_RESOLVED: &str = "azure.source.resolved";
    pub const ONEPASSWORD_SOURCE_READ_STARTED: &str = "onepassword.source.read_started";
    pub const ONEPASSWORD_SOURCE_RESOLVED: &str = "onepassword.source.resolved";
    pub const VAULT_SOURCE_READ_STARTED: &str = "vault.source.read_started";
    pub const VAULT_SOURCE_RESOLVED: &str = "vault.source.resolved";
    pub const VAULT_LEASE_ISSUED: &str = "vault.lease.issued";
    pub const VAULT_LEASE_RENEWAL_STARTED: &str = "vault.lease.renewal_started";
    pub const VAULT_LEASE_RENEWED: &str = "vault.lease.renewed";
    pub const VAULT_LEASE_REVOKED: &str = "vault.lease.revoked";
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

/// Only nonsecret source identity is exposed; lease IDs live inside ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSourceRef {
    pub origin: rekey_domain::action::HttpsOrigin,
    pub mount: String,
    pub role: String,
}
#[derive(Debug, Clone)]
pub struct LeaseExecutionContext {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub action_id: ActionId,
    pub action_version: u64,
    pub credential_id: CredentialId,
    pub credential_version: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeasePhase {
    AcquireIntent,
    Issued,
    Renewing,
    CleanupStarted,
    Complete,
}
impl LeasePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcquireIntent => "acquire_intent",
            Self::Issued => "issued",
            Self::Renewing => "renewing",
            Self::CleanupStarted => "cleanup_started",
            Self::Complete => "complete",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "acquire_intent" => Some(Self::AcquireIntent),
            "issued" => Some(Self::Issued),
            "renewing" => Some(Self::Renewing),
            "cleanup_started" => Some(Self::CleanupStarted),
            "complete" => Some(Self::Complete),
            _ => None,
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::AcquireIntent => 1,
            Self::Issued => 2,
            Self::Renewing => 3,
            Self::CleanupStarted => 4,
            Self::Complete => 5,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCleanupOutcome {
    None,
    Unconfirmed,
    Confirmed,
}
impl LeaseCleanupOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Unconfirmed => "unconfirmed",
            Self::Confirmed => "confirmed",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "unconfirmed" => Some(Self::Unconfirmed),
            "confirmed" => Some(Self::Confirmed),
            _ => None,
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Unconfirmed => 1,
            Self::Confirmed => 2,
        }
    }
}
#[derive(Debug, Clone)]
pub struct LeaseJournalRecord {
    pub registration_id: rekey_domain::ids::LeaseRegistrationId,
    pub context: LeaseExecutionContext,
    pub source_ref_hash: [u8; 32],
    pub revision: u64,
    pub phase: LeasePhase,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub issued_at_ms: Option<i64>,
    pub last_confirmed_expires_at_ms: Option<i64>,
    pub renewable: Option<bool>,
    pub cleanup_outcome: LeaseCleanupOutcome,
    pub completed_at_ms: Option<i64>,
    pub last_audit_event_id: [u8; 16],
    pub aad_version: u16,
    pub crypto_suite: String,
    pub dek_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub payload_nonce: [u8; 12],
    pub encrypted_payload: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct LeaseJournalState {
    pub last_audit_event_id: Option<[u8; 16]>,
    pub revision: u64,
    pub record_count: u64,
    pub records_digest: [u8; 32],
    pub seal_nonce: [u8; 12],
    pub seal_ciphertext: [u8; 16],
}
#[derive(Debug, Clone)]
pub struct LeaseReceipt {
    pub registration_id: rekey_domain::ids::LeaseRegistrationId,
    pub credential_id: CredentialId,
    pub credential_version: u64,
    pub phase: LeasePhase,
    pub updated_at_ms: i64,
    pub last_audit_event_id: [u8; 16],
}
impl LeaseJournalRecord {
    pub fn receipt(&self) -> LeaseReceipt {
        LeaseReceipt {
            registration_id: self.registration_id,
            credential_id: self.context.credential_id,
            credential_version: self.context.credential_version,
            phase: self.phase,
            updated_at_ms: self.updated_at_ms,
            last_audit_event_id: self.last_audit_event_id,
        }
    }
}
#[derive(Debug, Clone)]
pub struct LeaseJournalCounts {
    pub verified: bool,
    pub pending: u64,
    pub unknown: u64,
    pub complete: u64,
}
#[derive(Debug)]
pub struct LeaseRecoveryBatch {
    pub unavailable: Option<crate::error::AuthorityError>,
    pub counts: LeaseJournalCounts,
    pub known: Vec<LeaseReceipt>,
}
