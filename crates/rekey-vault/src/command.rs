use std::path::PathBuf;
use std::time::Instant;

use rekey_domain::action::{
    ExactPath, FixedMethod, HeaderCredentialUse, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::audit::{AuditPage, AuditQuery};
use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialMetadata};
use rekey_domain::ids::{ActionId, CredentialId, RequestId, SessionId, VaultId};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::error::AuthorityError;
use crate::model::{ActionState, AuthorizationEvidence};
use crate::secret::{PreparedCredential, SecretInput};

pub type Reply<T> = oneshot::Sender<Result<T, AuthorityError>>;

/// Human proof presented at unlock time and again for every sensitive
/// mutation (step-up).
pub enum UnlockProof {
    Password(SecretInput),
    Recovery(SecretInput),
}

/// Validated definition for creating or updating a fixed HTTP action.
#[derive(Debug, Clone)]
pub struct ActionDefinition {
    pub name: rekey_domain::action::ActionName,
    pub credential_id: CredentialId,
    pub origin: HttpsOrigin,
    pub method: FixedMethod,
    pub exact_path: ExactPath,
    pub auth: HeaderCredentialUse,
    pub timeout_ms: u32,
    pub request_policy: RequestPolicy,
    pub response_policy: ResponsePolicy,
}

/// Audit event draft; the worker assigns `event_id` and `created_at_ms`.
#[derive(Debug, Clone)]
pub struct AuditDraft {
    pub request_id: Option<RequestId>,
    pub session_id: Option<SessionId>,
    pub action_id: Option<ActionId>,
    pub action_version: Option<u64>,
    pub credential_id: Option<CredentialId>,
    pub credential_version: Option<u64>,
    pub authorization: Option<Box<AuthorizationEvidence>>,
    pub event_type: &'static str,
    pub outcome: &'static str,
    pub reason_code: String,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StatusInfo {
    pub state: &'static str,
    pub vault_id: VaultId,
    pub format_version: u32,
    /// Time since last successful mutation or credential prepare. Zero when locked.
    pub idle_for_ms: u64,
}

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub vault_id: VaultId,
    pub format_version: u32,
    pub created_at_ms: i64,
    pub sha256_hex: String,
    pub output_path: PathBuf,
}

/// A pinned, immutable action version plus its lifecycle state.
#[derive(Debug, Clone)]
pub struct PinnedAction {
    pub action: rekey_domain::action::FixedHttpAction,
    pub state: ActionState,
}

pub enum AuthorityCommand {
    Status {
        refresh_activity: bool,
        reply: Reply<StatusInfo>,
    },
    Unlock {
        proof: UnlockProof,
        reply: Reply<()>,
    },
    Lock {
        reason: &'static str,
        reply: Reply<()>,
    },
    CheckIdle,
    Shutdown {
        proof: Option<UnlockProof>,
        reply: Reply<()>,
    },
    VerifyProof {
        proof: UnlockProof,
        reply: Reply<()>,
    },
    PasswordChange {
        proof: UnlockProof,
        new_password: SecretInput,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    RecoveryRotate {
        password: SecretInput,
        not_after: Option<Instant>,
        reply: Reply<Zeroizing<String>>,
    },
    CredentialAdd {
        label: CredentialLabel,
        kind: CredentialKind,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    CredentialList(Reply<Vec<CredentialMetadata>>),
    CredentialRotate {
        credential_id: CredentialId,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    CredentialRevoke {
        credential_id: CredentialId,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    ActionUpsert {
        existing: Option<ActionId>,
        definition: Box<ActionDefinition>,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<rekey_domain::action::FixedHttpAction>,
    },
    ActionDisable {
        action_id: ActionId,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    ActionList(Reply<Vec<rekey_domain::action::FixedHttpAction>>),
    ActionGet {
        action_id: ActionId,
        version: u64,
        reply: Reply<PinnedAction>,
    },
    ActionIdsForCredential {
        credential_id: CredentialId,
        reply: Reply<Vec<ActionId>>,
    },
    PrepareCredential {
        credential_id: CredentialId,
        reply: Reply<PreparedCredential>,
    },
    AppendAudit {
        draft: AuditDraft,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    AuditQuery {
        query: AuditQuery,
        reply: Reply<AuditPage>,
    },
    Backup {
        output: PathBuf,
        proof: UnlockProof,
        reply: Reply<BackupInfo>,
    },
}
