use std::path::PathBuf;
use std::time::Instant;

use rekey_domain::action::{
    ActionTarget, FixedMethod, HeaderCredentialUse, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::audit::{
    AuditPage, AuditPruneReceipt, AuditPruneRequest, AuditQuery, AuditRetentionSet,
    AuditRetentionStatus,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialMetadata};
use rekey_domain::ids::{ActionId, CredentialId, PolicySignerId, RequestId, SessionId, VaultId};
use rekey_domain::ipc::BackupSnapshotCut;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::error::AuthorityError;
use crate::model::{ActionState, ApprovalEvidence, AuthorizationEvidence};
use crate::secret::{PreparedCredential, SecretInput};

/// Trusted executor input derived from a signed Profile and a validated request.
#[derive(Debug, Clone)]
pub struct ProfileUsageStart {
    pub instance_slug: String,
    pub max_requests_per_day: u64,
    pub max_output_tokens_per_day: u64,
    pub generation_max_output: Option<u64>,
}

pub type Reply<T> = oneshot::Sender<Result<T, AuthorityError>>;

/// Human proof presented at unlock time and again for every sensitive
/// mutation (step-up).
pub enum UnlockProof {
    Password(SecretInput),
    Recovery(SecretInput),
    Presence(SecretInput),
}

/// Validated definition for creating or updating a fixed HTTP action.
#[derive(Debug, Clone)]
pub struct ActionDefinition {
    pub native_plugin: Option<rekey_domain::action::NativePlugin>,
    pub text_stream: Option<rekey_domain::action::AnthropicTextStream>,
    pub name: rekey_domain::action::ActionName,
    pub credential_id: CredentialId,
    pub origin: HttpsOrigin,
    pub method: FixedMethod,
    pub target: ActionTarget,
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
    pub approval: Option<ApprovalEvidence>,
    pub usage: Option<rekey_domain::audit::UsageEvidence>,
    pub request_context: Option<rekey_domain::audit::RequestAuditContext>,
    pub event_type: &'static str,
    pub outcome: &'static str,
    pub reason_code: String,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StatusInfo {
    pub state: &'static str,
    pub rollback: Option<rekey_domain::ipc::RollbackContext>,
    pub vault_id: VaultId,
    pub format_version: u32,
    /// Time since last successful mutation or credential prepare. Zero when locked.
    pub idle_for_ms: u64,
    pub policy_trust_installed: bool,
    pub policy_bundle_persisted: bool,
}

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub generation: u64,
    pub vault_id: VaultId,
    pub format_version: u32,
    pub created_at_ms: i64,
    pub sha256_hex: String,
    pub output_path: PathBuf,
    pub snapshot_cut: BackupSnapshotCut,
}

#[derive(Debug, Clone)]
pub struct RestoreInfo {
    pub generation: u64,
    pub vault_id: VaultId,
    pub format_version: u32,
    pub input_sha256_hex: String,
    pub output_path: String,
    pub snapshot_cut: BackupSnapshotCut,
}

/// A pinned, immutable action version plus its lifecycle state.
#[derive(Debug, Clone)]
pub struct PinnedAction {
    pub action: rekey_domain::action::FixedHttpAction,
    pub state: ActionState,
}

#[derive(Debug, Clone)]
pub struct PolicyTrustInput {
    pub signer_id: PolicySignerId,
    pub key: rekey_policy::PolicyVerificationKey,
}

#[derive(Debug, Clone)]
pub struct PolicyBundleInput {
    pub expected_vault_id: VaultId,
    pub expected_trust_sha256: [u8; 32],
    pub signer_id: PolicySignerId,
    pub version: u64,
    pub expires_at_ms: i64,
    pub policy_digest: [u8; 32],
    pub bundle_digest: [u8; 32],
    pub bundle_json: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PolicyMaterial {
    pub state: crate::model::PolicyStateRecord,
    pub trust: Option<crate::model::PolicyTrustRecord>,
    pub bundle: Option<crate::model::PolicyBundleRecord>,
}

/// Explicit software selection never follows a Secure Enclave failure.
#[derive(Debug, Clone, Copy)]
pub enum SshKeyMode {
    Default,
    Ed25519Software,
    P256Software,
}

#[derive(Debug, Clone)]
pub struct SshIdentity {
    pub credential: CredentialMetadata,
    /// OpenSSH public-key wire blob; contains no private bytes.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum OAuthGrantUpdateReason {
    Authorized,
    Refreshed,
}
impl OAuthGrantUpdateReason {
    pub(crate) fn event_type(self) -> &'static str {
        match self {
            Self::Authorized => "oauth.authorized",
            Self::Refreshed => "oauth.refreshed",
        }
    }
}

pub enum AuthorityCommand {
    OAuthGrantCreate {
        label: CredentialLabel,
        payload: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    OAuthGrantUpdate {
        credential_id: CredentialId,
        expected_version: u64,
        payload: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    RotateOAuthGrant {
        credential_id: CredentialId,
        expected_version: u64,
        payload: SecretInput,
        reason: OAuthGrantUpdateReason,
        not_after: Instant,
        reply: Reply<CredentialMetadata>,
    },
    PrepareOAuthGrant {
        credential_id: CredentialId,
        reply: Reply<PreparedCredential>,
    },
    PrepareAwsStatic {
        credential_id: CredentialId,
        reply: Reply<PreparedCredential>,
    },
    SshGenerate {
        label: CredentialLabel,
        mode: SshKeyMode,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<SshIdentity>,
    },
    SshImport {
        label: CredentialLabel,
        private_key: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<SshIdentity>,
    },
    PrepareMtlsConnection {
        request_id: RequestId,
        connection: String,
        policy_digest: [u8; 32],
        not_after: Instant,
        reply: Reply<PreparedCredential>,
    },
    SshSign {
        credential_id: CredentialId,
        public_key: Vec<u8>,
        data: Vec<u8>,
        started: Box<AuditDraft>,
        approvals: Vec<AuditDraft>,
        not_after: Instant,
        reply: Reply<Vec<u8>>,
    },
    ScanCredentials {
        inputs: Vec<crate::hygiene::ScanInput>,
        credentials: Vec<crate::hygiene::ScanCredential>,
        reply: Reply<Vec<crate::hygiene::ScanFinding>>,
    },
    ImportEnv {
        request: crate::hygiene::EnvImportRequest,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<crate::hygiene::EnvImportReport>,
    },
    LeaseAcquireBegin {
        context: crate::model::LeaseExecutionContext,
        source: crate::model::LeaseSourceRef,
        not_after: Option<Instant>,
        reply: Reply<crate::model::LeaseReceipt>,
    },
    LeaseIssued {
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        lease_id: SecretInput,
        request_started_at_ms: i64,
        actual_ttl_seconds: u64,
        renewable: bool,
        not_after: Option<Instant>,
        reply: Reply<crate::model::LeaseReceipt>,
    },
    LeaseAcquireAbortDefinite {
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        not_after: Option<Instant>,
        reply: Reply<crate::model::LeaseReceipt>,
    },
    LeaseRenewBegin {
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        not_after: Option<Instant>,
        reply: Reply<crate::model::LeaseReceipt>,
    },
    LeaseRenewResult {
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        request_started_at_ms: i64,
        actual_ttl_seconds: Option<u64>,
        renewable: bool,
        not_after: Option<Instant>,
        reply: Reply<crate::model::LeaseReceipt>,
    },
    LeaseCleanupPrepare {
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        not_after: Option<Instant>,
        reply: Reply<crate::secret::PreparedLeaseCleanup>,
    },
    LeaseCleanupFinish {
        registration_id: rekey_domain::ids::LeaseRegistrationId,
        confirmed: bool,
        not_after: Option<Instant>,
        reply: Reply<crate::model::LeaseReceipt>,
    },
    LeaseRecoveryBatch {
        reply: Reply<crate::model::LeaseRecoveryBatch>,
    },
    DesktopRemember {
        proof: UnlockProof,
        lifetime_ms: i64,
        not_after: Option<std::time::Instant>,
        reply: Reply<(Zeroizing<Vec<u8>>, i64)>,
    },
    DesktopLock {
        token: SecretInput,
        forget_remembered: bool,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    DesktopResume {
        token: SecretInput,
        not_after: Option<std::time::Instant>,
        reply: Reply<i64>,
    },
    DesktopIssue {
        reply: Reply<Zeroizing<Vec<u8>>>,
    },
    DesktopAdd {
        token: SecretInput,
        label: CredentialLabel,
        secret: SecretInput,
        not_after: Option<std::time::Instant>,
        reply: Reply<CredentialMetadata>,
    },
    DesktopReveal {
        proof: UnlockProof,
        credential_id: CredentialId,
        not_after: Option<std::time::Instant>,
        reply: Reply<Zeroizing<Vec<u8>>>,
    },
    Status {
        refresh_activity: bool,
        reply: Reply<StatusInfo>,
    },
    ConfirmRollback {
        expected: rekey_domain::ipc::RollbackContext,
        proof: crate::bootstrap::RestoreProof,
        not_after: std::time::Instant,
        reply: Reply<()>,
    },
    Unlock {
        proof: UnlockProof,
        reply: Reply<()>,
    },
    Lock {
        reason: &'static str,
        preserve_desktop: bool,
        reply: Reply<()>,
    },
    CheckIdle,
    Shutdown {
        proof: Option<UnlockProof>,
        reply: Reply<()>,
    },
    VerifyShutdownProof {
        proof: UnlockProof,
        reply: Reply<()>,
    },
    VerifyProof {
        proof: UnlockProof,
        reply: Reply<()>,
    },
    AuthorizeLocalApproval {
        proof: SecretInput,
        draft: AuditDraft,
        not_after: Instant,
        wall_not_after_ms: i64,
        reply: Reply<()>,
    },
    RotateVrk {
        password: SecretInput,
        recovery: SecretInput,
        not_after: Option<Instant>,
        reply: Reply<rekey_domain::ipc::VrkRotatedResponse>,
    },
    RotateDek {
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<u64>,
    },
    PasswordChange {
        proof: UnlockProof,
        new_password: SecretInput,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    RecoveryRotate {
        proof: UnlockProof,
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
    CredentialRotateTyped {
        credential_id: CredentialId,
        expected_kind: CredentialKind,
        expected_version: Option<u64>,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    PkiGenerateCrl {
        input: rekey_domain::ipc::PkiGenerateCrlMeta,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Instant,
        reply: Reply<(rekey_domain::ipc::PkiCrlResponse, Vec<u8>)>,
    },
    PkiRevokeCertificate {
        input: rekey_domain::ipc::PkiRevokeCertificateMeta,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Instant,
        reply: Reply<rekey_domain::ipc::PkiRevocationResponse>,
    },
    PkiIssueClientCsr {
        input: rekey_domain::ipc::PkiIssueClientCsrMeta,
        csr: SecretInput,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Instant,
        reply: Reply<rekey_domain::ipc::PkiCertificateResponse>,
    },
    CredentialRevoke {
        credential_id: CredentialId,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<CredentialMetadata>,
    },
    TemplateCatalog {
        source: rekey_domain::ipc::TemplateSource,
        package: Vec<u8>,
        not_after: Option<Instant>,
        reply: Reply<rekey_domain::ipc::TemplateCatalogResponse>,
    },
    TemplateInstall {
        input: Box<rekey_domain::ipc::TemplateInstallMeta>,
        package: Vec<u8>,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Option<Instant>,
        reply: Reply<rekey_domain::ipc::TemplateInstallResponse>,
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
    PrepareExecutionCredential {
        credential_id: CredentialId,
        request_id: RequestId,
        action_id: ActionId,
        action_version: u64,
        deadline: Instant,
        reply: Reply<PreparedCredential>,
    },
    PrepareCredential {
        credential_id: CredentialId,
        reply: Reply<PreparedCredential>,
    },
    BeginProfileExecution {
        usage: ProfileUsageStart,
        preceding: Vec<AuditDraft>,
        started: AuditDraft,
        not_after: Instant,
        wall_not_after_ms: Option<i64>,
        reply: Reply<crate::model::UsageAdmission>,
    },
    SettleProfileExecution {
        request_id: RequestId,
        measured_output_tokens: Option<u64>,
        terminal: AuditDraft,
        reply: Reply<()>,
    },
    ProfileUsage {
        principal_id: rekey_domain::ids::PrincipalId,
        instance_slug: String,
        utc_day: i64,
        reply: Reply<crate::model::UsageTotals>,
    },
    AppendAudit {
        draft: AuditDraft,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    AppendAudits {
        drafts: Vec<AuditDraft>,
        not_after: Option<Instant>,
        wall_not_after_ms: Option<i64>,
        reply: Reply<()>,
    },
    ConsumeWorkloadToken {
        replay_digest: [u8; 32],
        expires_at_ms: i64,
        audit: AuditDraft,
        not_after: Option<Instant>,
        reply: Reply<()>,
    },
    AuditRetentionSet {
        request: AuditRetentionSet,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<AuditRetentionStatus>,
    },
    AuditRetentionStatus {
        reply: Reply<AuditRetentionStatus>,
    },
    AuditRetentionMaintenance {
        not_after: Instant,
        reply: Reply<Option<AuditPruneReceipt>>,
    },
    AuditPrune {
        request: AuditPruneRequest,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<AuditPruneReceipt>,
    },
    AuditQuery {
        query: AuditQuery,
        reply: Reply<AuditPage>,
    },
    PolicyMaterial {
        reply: Reply<PolicyMaterial>,
    },
    PolicyTrustInstall {
        input: PolicyTrustInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<PolicyMaterial>,
    },
    PolicyBundleActivate {
        input: PolicyBundleInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
        reply: Reply<PolicyMaterial>,
    },
    FaultIntegrity {
        reply: Reply<()>,
    },
    Backup {
        output: PathBuf,
        proof: UnlockProof,
        reply: Reply<BackupInfo>,
    },
    ApprovalOriginPublicKey {
        reply: Reply<[u8; 32]>,
    },
    SignApprovalOrigin {
        message: Vec<u8>,
        reply: Reply<[u8; 64]>,
    },
}
