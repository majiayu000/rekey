//! Frame v1 wire protocol and message metadata DTOs.
//!
//! Pure byte-level encode/decode with no IO so both the broker and the
//! IPC-only CLI can share one implementation. Secret bytes travel only in the
//! raw frame body, never inside JSON metadata.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::action::{ExactPath, FixedHttpAction, FixedMethod, HttpsOrigin};
use crate::authorization::{ApprovalMode, PolicyVersion, ResourceRef, SchemaId};
use crate::capability::ActionVersionRef;
use crate::credential::{CredentialLabel, CredentialMetadata};
use crate::ids::{
    ActionId, ApprovalRequestId, ApproverId, CredentialId, PolicyRuleId, PolicySignerId,
    PrincipalId, RequestId, SessionId, TenantId, VaultId,
};
use crate::template::{ProviderTemplate, TemplateValues};

pub const FRAME_MAGIC: [u8; 4] = *b"RKIP";
pub const FRAME_VERSION: u16 = 1;
pub const FRAME_HEADER_LEN: usize = 36;
pub const METADATA_MAX_BYTES: u32 = 64 * 1024;
pub const ADMIN_SECRET_FIELD_MAX_BYTES: u32 = 64 * 1024;
pub const ADMIN_PROOF_BODY_MAX_BYTES: u32 = ADMIN_SECRET_FIELD_MAX_BYTES + 5;
pub const ADMIN_SECRET_BODY_MAX_BYTES: u32 = 2 * ADMIN_SECRET_FIELD_MAX_BYTES + 9;
pub const ADMIN_MANAGEMENT_OVERHEAD: u32 = 50;
pub const AGENT_BODY_MAX_BYTES: u32 = 1024 * 1024;
pub const WORKLOAD_TOKEN_MAX_BYTES: u32 = 16 * 1024;
pub const RESPONSE_BODY_MAX_BYTES: u32 = 4 * 1024 * 1024;
pub const APPROVAL_PENDING_MAX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Admin,
    Agent,
}

impl Channel {
    pub fn code(&self) -> u8 {
        match self {
            Self::Admin => 1,
            Self::Agent => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, FrameError> {
        match code {
            1 => Ok(Self::Admin),
            2 => Ok(Self::Agent),
            _ => Err(FrameError::UnknownChannel),
        }
    }
}

/// Admin channel message types.
pub mod admin_msg {
    pub const STATUS: u16 = 1;
    pub const UNLOCK_PASSWORD: u16 = 2;
    pub const UNLOCK_RECOVERY: u16 = 3;
    pub const CREDENTIAL_ADD: u16 = 4;
    pub const CREDENTIAL_LIST: u16 = 5;
    pub const CREDENTIAL_ROTATE: u16 = 6;
    pub const CREDENTIAL_REVOKE: u16 = 7;
    pub const ACTION_CREATE: u16 = 8;
    pub const ACTION_UPDATE: u16 = 9;
    pub const ACTION_DISABLE: u16 = 10;
    pub const ACTION_LIST: u16 = 11;
    pub const SESSION_CREATE: u16 = 12;
    pub const SESSION_REVOKE: u16 = 13;
    pub const BACKUP: u16 = 14;
    pub const LOCK: u16 = 15;
    pub const SHUTDOWN: u16 = 16;
    pub const POLICY_ACTIVATE: u16 = 17;
    pub const POLICY_STATUS: u16 = 18;
    pub const PASSWORD_CHANGE: u16 = 19;
    pub const RECOVERY_ROTATE: u16 = 20;
    pub const AUDIT_QUERY: u16 = 21;
    pub const POLICY_TRUST_INSTALL: u16 = 22;
    pub const CREDENTIAL_ROTATE_GITHUB_APP: u16 = 23;
    pub const GITHUB_WEBHOOK_APPLY: u16 = 24;
    pub const CREDENTIAL_ROTATE_VAULT_KV: u16 = 25;
    pub const CREDENTIAL_ROTATE_VAULT_DYNAMIC: u16 = 26;
    pub const CREDENTIAL_ROTATE_KEYCLOAK: u16 = 27;
    pub const APPROVAL_ORIGIN: u16 = 28;
    pub const APPROVAL_PENDING: u16 = 29;
    pub const APPROVAL_GET: u16 = 30;
    pub const DESKTOP_LOGIN: u16 = 31;
    pub const DESKTOP_ADD: u16 = 32;
    pub const DESKTOP_REVEAL: u16 = 33;
    pub const PASSIVE_STATUS: u16 = 34;
    pub const DESKTOP_REMEMBER: u16 = 35;
    pub const DESKTOP_RESUME: u16 = 36;
    pub const METRICS: u16 = 37;
    pub const KEY_ROTATE_DEK: u16 = 38;
    pub const AUDIT_PRUNE: u16 = 39;
    pub const KEY_ROTATE_VRK: u16 = 40;
    pub const CREDENTIAL_ROTATE_GCP_SECRET_MANAGER: u16 = 41;
    pub const CREDENTIAL_ROTATE_AWS_SECRETS_MANAGER: u16 = 42;
    pub const CREDENTIAL_ROTATE_AZURE_KEY_VAULT: u16 = 43;
    pub const CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT: u16 = 44;
    pub const OIDC_LOGIN_BEGIN: u16 = 45;
    pub const OIDC_LOGIN_FINISH: u16 = 46;
    pub const OIDC_LOGIN_CANCEL: u16 = 47;
    pub const OIDC_LOGOUT: u16 = 48;
    pub const CREDENTIAL_ROTATE_MACOS_KEYCHAIN: u16 = 49;
    pub const AUDIT_RETENTION_SET: u16 = 50;
    pub const AUDIT_RETENTION_STATUS: u16 = 51;
    pub const TEMPLATE_CATALOG: u16 = 52;
    pub const TEMPLATE_INSTALL: u16 = 53;
    pub const PERSONAL_POLICY_DRAFT: u16 = 54;
}

/// Agent channel message types.
pub mod agent_msg {
    pub const EXECUTE_FIXED_HTTP_ACTION: u16 = 1;
    pub const AGENT_STATUS: u16 = 2;
    pub const PREPARE_APPROVAL: u16 = 3;
    pub const WORKLOAD_SESSION_CREATE: u16 = 4;
    pub const EXECUTE_TEXT_STREAM: u16 = 5;
}

/// Response message types shared by both channels.
pub mod resp_msg {
    pub const OK: u16 = 100;
    pub const ERROR: u16 = 101;
    pub const STREAM_CHUNK: u16 = 102;
    pub const STREAM_TERMINAL: u16 = 103;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    #[error("frame magic mismatch")]
    BadMagic,
    #[error("unsupported frame version")]
    UnsupportedVersion,
    #[error("unknown channel")]
    UnknownChannel,
    #[error("reserved bytes must be zero")]
    NonZeroReserved,
    #[error("frame section exceeds limit")]
    SectionTooLarge,
    #[error("truncated frame")]
    Truncated,
    #[error("invalid frame field")]
    InvalidField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub channel: Channel,
    pub flags: u8,
    pub message_type: u16,
    pub request_id: RequestId,
    pub metadata_len: u32,
    pub body_len: u32,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0..4].copy_from_slice(&FRAME_MAGIC);
        out[4..6].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        out[6] = self.channel.code();
        out[7] = self.flags;
        out[8..10].copy_from_slice(&self.message_type.to_be_bytes());
        // bytes 10..12 are the reserved u16, already zero
        out[12..28].copy_from_slice(self.request_id.as_bytes());
        out[28..32].copy_from_slice(&self.metadata_len.to_be_bytes());
        out[32..36].copy_from_slice(&self.body_len.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8; FRAME_HEADER_LEN]) -> Result<Self, FrameError> {
        if buf[0..4] != FRAME_MAGIC {
            return Err(FrameError::BadMagic);
        }
        if u16::from_be_bytes([buf[4], buf[5]]) != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        let channel = Channel::from_code(buf[6])?;
        let flags = buf[7];
        if flags != 0 {
            return Err(FrameError::InvalidField);
        }
        let message_type = u16::from_be_bytes([buf[8], buf[9]]);
        if buf[10] != 0 || buf[11] != 0 {
            return Err(FrameError::NonZeroReserved);
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&buf[12..28]);
        let request_id = RequestId::from_bytes(id).map_err(|_| FrameError::InvalidField)?;
        let metadata_len = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let body_len = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        if metadata_len > METADATA_MAX_BYTES {
            return Err(FrameError::SectionTooLarge);
        }
        Ok(Self {
            channel,
            flags,
            message_type,
            request_id,
            metadata_len,
            body_len,
        })
    }
}

/// Closed operation classification shared by managed Broker dispatch and CLI.
pub fn managed_admin_operation(message_type: u16) -> Result<bool, FrameError> {
    if !(1..=54).contains(&message_type) {
        return Err(FrameError::InvalidField);
    }
    Ok(!matches!(
        message_type,
        1 | 2 | 3 | 15 | 16 | 31 | 34 | 36 | 45..=48
    ))
}

/// Exact canonical 32-byte base64url token, including zero pad bits.
pub fn validate_management_token(token: &[u8]) -> Result<(), FrameError> {
    if token.len() != 43
        || !token
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        || !b"AEIMQUYcgkosw048".contains(&token[42])
    {
        return Err(FrameError::InvalidField);
    }
    Ok(())
}

pub fn encode_management_body(token: &[u8], body: &[u8]) -> Result<Vec<u8>, FrameError> {
    validate_management_token(token)?;
    let mut out = Vec::with_capacity(body.len() + 50);
    out.extend_from_slice(b"RKAU\x01\x00\x2b");
    out.extend_from_slice(token);
    out.extend_from_slice(body);
    Ok(out)
}

pub fn parse_management_body(body: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    if body.get(..7) != Some(b"RKAU\x01\x00\x2b") {
        return Err(FrameError::InvalidField);
    }
    let token = body.get(7..50).ok_or(FrameError::Truncated)?;
    validate_management_token(token)?;
    Ok((token, &body[50..]))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcFlowMeta {
    pub flow_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcBeginResponse {
    pub flow_id: String,
    pub authorization_url: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSessionResponse {
    pub principal_id: PrincipalId,
    pub expires_at_ms: i64,
    pub mapping_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcLogoutResponse {
    pub management_sessions: usize,
    pub capabilities: usize,
    pub pending_approvals: usize,
}

/// Step-up proof kinds carried in secret frame bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    Password,
    Recovery,
}

impl ProofKind {
    pub fn code(&self) -> u8 {
        match self {
            Self::Password => 1,
            Self::Recovery => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, FrameError> {
        match code {
            1 => Ok(Self::Password),
            2 => Ok(Self::Recovery),
            _ => Err(FrameError::InvalidField),
        }
    }
}

/// Body layout for proof-only messages: `kind:u8 | len:u32 | proof`.
pub fn encode_proof_body(kind: ProofKind, proof: &[u8], out: &mut Vec<u8>) {
    out.push(kind.code());
    out.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    out.extend_from_slice(proof);
}

/// Body layout for proof+secret messages:
/// `kind:u8 | plen:u32 | proof | slen:u32 | secret`.
pub fn encode_proof_and_secret_body(
    kind: ProofKind,
    proof: &[u8],
    secret: &[u8],
    out: &mut Vec<u8>,
) {
    encode_proof_body(kind, proof, out);
    out.extend_from_slice(&(secret.len() as u32).to_be_bytes());
    out.extend_from_slice(secret);
}

fn read_u32(body: &[u8], at: usize) -> Result<u32, FrameError> {
    let end = at.checked_add(4).ok_or(FrameError::Truncated)?;
    let bytes: [u8; 4] = body
        .get(at..end)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .map_err(|_| FrameError::Truncated)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Zero-copy parse; the caller owns zeroization of the backing buffer.
pub fn parse_proof_body(body: &[u8]) -> Result<(ProofKind, &[u8]), FrameError> {
    let kind = ProofKind::from_code(*body.first().ok_or(FrameError::Truncated)?)?;
    let plen = read_u32(body, 1)? as usize;
    if plen > ADMIN_SECRET_FIELD_MAX_BYTES as usize {
        return Err(FrameError::SectionTooLarge);
    }
    let proof = body.get(5..5 + plen).ok_or(FrameError::Truncated)?;
    if body.len() != 5 + plen {
        return Err(FrameError::InvalidField);
    }
    Ok((kind, proof))
}

/// Zero-copy parse; the caller owns zeroization of the backing buffer.
pub fn parse_proof_and_secret_body(body: &[u8]) -> Result<(ProofKind, &[u8], &[u8]), FrameError> {
    let kind = ProofKind::from_code(*body.first().ok_or(FrameError::Truncated)?)?;
    let plen = read_u32(body, 1)? as usize;
    if plen > ADMIN_SECRET_FIELD_MAX_BYTES as usize {
        return Err(FrameError::SectionTooLarge);
    }
    let proof = body.get(5..5 + plen).ok_or(FrameError::Truncated)?;
    let slen = read_u32(body, 5 + plen)? as usize;
    if slen > ADMIN_SECRET_FIELD_MAX_BYTES as usize {
        return Err(FrameError::SectionTooLarge);
    }
    let secret = body
        .get(9 + plen..9 + plen + slen)
        .ok_or(FrameError::Truncated)?;
    if body.len() != 9 + plen + slen {
        return Err(FrameError::InvalidField);
    }
    Ok((kind, proof, secret))
}

// ---- metadata DTOs (JSON, never secret) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub request_id: RequestId,
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub state: String,
    pub format_version: u32,
    pub runtime_version: String,
    pub lab_enabled: bool,
    pub sessions_active: u32,
    pub lease_journal: LeaseJournalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseJournalStatus {
    pub verified: bool,
    pub pending: u64,
    pub unknown: u64,
    pub complete: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRecoveryOutcome {
    Complete,
    Unconfirmed,
    Deferred,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecoveryEntry {
    pub registration_id: crate::ids::LeaseRegistrationId,
    pub credential_id: CredentialId,
    pub credential_version: u64,
    pub outcome: LeaseRecoveryOutcome,
    pub updated_at_ms: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecoverySummary {
    pub performed: bool,
    pub journal: LeaseJournalStatus,
    pub deferred: u64,
    pub leases: Vec<LeaseRecoveryEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockResponse {
    pub unlocked: bool,
    pub lease_recovery: LeaseRecoverySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DekRotatedResponse {
    pub rotated_versions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrkRotatedResponse {
    pub vault_id: crate::ids::VaultId,
    pub rotated_versions: u64,
    pub resealed_credentials: u64,
    pub approval_origin: ApprovalOriginResponse,
    pub locked: bool,
}

impl VrkRotatedResponse {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        self.approval_origin.validate()?;
        if !self.locked
            || self.rotated_versions < self.resealed_credentials
            || (self.resealed_credentials == 0 && self.rotated_versions != 0)
        {
            return Err(invalid_response());
        }
        Ok(())
    }
}

/// Process-local, approximate monitoring snapshot. No identifiers or secrets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsResponse {
    pub admin: ChannelMetrics,
    pub agent: ChannelMetrics,
    pub backup: DispatchMetrics,
    pub fault_signals_total: u64,
    pub capabilities_active: u32,
    pub executions_in_flight: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelMetrics {
    pub dispatch: DispatchMetrics,
    pub peer_rejections_total: u64,
    pub capacity_rejections_total: u64,
    pub frame_read_failures_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchMetrics {
    pub requests_total: u64,
    pub finished_total: u64,
    pub errors_total: u64,
    pub cancelled_total: u64,
    pub duration_micros_total: u64,
    pub requests_in_flight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAddMeta {
    pub label: CredentialLabel,
    pub kind: crate::credential::CredentialKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRefMeta {
    pub credential_id: CredentialId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubWebhookApplyMeta {
    pub credential_id: CredentialId,
    pub expected_version: u64,
    pub event: String,
    pub delivery: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCreateMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_plugin: Option<crate::action::NativePlugin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_stream: Option<crate::action::AnthropicTextStream>,
    pub name: String,
    pub credential_id: CredentialId,
    pub origin: String,
    pub method: String,
    pub exact_path: String,
    pub auth_header: String,
    pub auth_prefix: String,
    pub timeout_ms: u32,
    pub request_max_bytes: u32,
    pub allowed_extra_headers: Vec<String>,
    pub response_max_bytes: u32,
    pub allowed_response_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionUpdateMeta {
    pub action_id: ActionId,
    pub definition: ActionCreateMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRefMeta {
    pub action_id: ActionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionListResponse {
    pub actions: Vec<FixedHttpAction>,
}

/// Closed sources; signed package bytes travel only in the frame body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TemplateSource {
    Anthropic {},
    #[serde(rename = "openai")]
    OpenAi {},
    #[serde(rename = "github-pat")]
    GitHubPat {},
    GenericBearer {
        origin: HttpsOrigin,
        actions: Vec<TemplateFixedAction>,
    },
    SignedPackage {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFixedAction {
    pub method: FixedMethod,
    pub path: ExactPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCatalogMeta {
    pub source: TemplateSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCatalogResponse {
    pub template: ProviderTemplate,
    pub digest: [u8; 32],
    pub signer_id: Option<PolicySignerId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInstallMeta {
    pub source: TemplateSource,
    pub credential_id: CredentialId,
    pub bindings: Vec<TemplateValues>,
    pub capabilities: Vec<String>,
    pub name_prefix: String,
    pub timeout_ms: u32,
    pub request_max_bytes: u32,
    pub allowed_extra_headers: Vec<String>,
    pub response_max_bytes: u32,
    pub allowed_response_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInstalledAction {
    pub binding_index: usize,
    /// Capability and action index are part of this Action's authenticated source.
    pub action: FixedHttpAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInstallResponse {
    pub actions: Vec<TemplateInstalledAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateMeta {
    pub actions: Vec<ActionVersionRef>,
    pub ttl_ms: i64,
    pub max_uses: u32,
}

/// Admin-only issuance; workload identity always comes from its verified token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSessionCreateMeta {
    pub actions: Vec<ActionVersionRef>,
    pub ttl_ms: i64,
    pub max_uses: u32,
    pub principal_id: Option<PrincipalId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCreatedResponse {
    pub session_id: SessionId,
    pub principal_id: crate::ids::PrincipalId,
    /// Short-lived capability, shown exactly once. Not a stored secret.
    pub capability_token: String,
    pub expires_at_ms: i64,
    pub max_uses: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivateMeta {
    pub expected_vault_id: VaultId,
    pub expected_trust_sha256: String,
    pub bundle_json: Box<serde_json::value::RawValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalPolicyDraftMeta {
    pub principal_id: PrincipalId,
    pub actions: Vec<ActionVersionRef>,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalPolicyFieldChange {
    pub field: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}

/// The associated frame body contains the exact RKPOLICY-prefixed sign bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalPolicyDraftResponse {
    pub vault_id: VaultId,
    pub trust_sha256: String,
    pub public_key: String,
    pub base_version: Option<u64>,
    pub next_version: u64,
    pub policy_sha256: String,
    pub changes: Vec<PersonalPolicyFieldChange>,
    pub actions: Vec<FixedHttpAction>,
}

impl PersonalPolicyDraftResponse {
    /// Wire-shape validation only; the broker authenticates stored material.
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        if !is_lower_hex(&self.trust_sha256, 64)
            || !is_lower_hex(&self.policy_sha256, 64)
            || !is_lower_hex(&self.public_key, 130)
            || !self.public_key.starts_with("04")
            || self
                .base_version
                .is_some_and(|v| PolicyVersion::new(v).is_err())
            || self.base_version.unwrap_or(0).checked_add(1) != Some(self.next_version)
            || PolicyVersion::new(self.next_version).is_err()
            || self.actions.iter().any(|action| !action.enabled)
            || self
                .actions
                .windows(2)
                .any(|pair| (pair[0].id, pair[0].version) >= (pair[1].id, pair[1].version))
        {
            return Err(invalid_response());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStatusResponse {
    pub vault_id: VaultId,
    pub tenant_id: TenantId,
    /// Present only when the policy state has been authenticated while unlocked.
    pub mode: Option<crate::authorization::PolicyMode>,
    pub algorithm: Option<crate::authorization::PolicyTrustAlgorithm>,
    pub trust_sha256: Option<String>,
    pub activated_at_ms: Option<i64>,
    pub trust_installed: bool,
    pub bundle_persisted: bool,
    pub status: String,
    pub signer_id: Option<PolicySignerId>,
    pub version: Option<u64>,
    pub expires_at_ms: Option<i64>,
    pub policy_sha256: Option<String>,
    pub bundle_sha256: Option<String>,
}

impl PolicyStatusResponse {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        use crate::authorization::{PolicyMode, PolicyTrustAlgorithm};
        if self.tenant_id.as_bytes() != self.vault_id.as_bytes()
            || (self.mode.is_none() && (self.algorithm.is_some() || self.trust_sha256.is_some()))
            || (self.mode.is_some() && self.trust_installed != self.algorithm.is_some())
            || matches!(
                (self.mode, self.algorithm),
                (
                    Some(PolicyMode::Personal),
                    Some(PolicyTrustAlgorithm::Ed25519)
                ) | (
                    Some(PolicyMode::Team),
                    Some(PolicyTrustAlgorithm::SecureEnclaveP256)
                )
            )
            || self
                .trust_sha256
                .as_deref()
                .is_some_and(|value| !self.trust_installed || !is_lower_hex(value, 64))
            || (self.bundle_persisted && !self.trust_installed)
        {
            return Err(invalid_response());
        }
        let details_present = self.mode.is_some()
            && self.algorithm.is_some()
            && self.trust_sha256.is_some()
            && self.activated_at_ms.is_some_and(|value| value >= 0)
            && self.signer_id.is_some()
            && self.version.is_some()
            && self.expires_at_ms.is_some()
            && self.policy_sha256.is_some()
            && self.bundle_sha256.is_some();
        match self.status.as_str() {
            "unavailable"
                if self.activated_at_ms.is_none()
                    && self.signer_id.is_none()
                    && self.version.is_none()
                    && self.expires_at_ms.is_none()
                    && self.policy_sha256.is_none()
                    && self.bundle_sha256.is_none() => {}
            "active" | "expired"
                if self.trust_installed
                    && self.bundle_persisted
                    && details_present
                    && self
                        .version
                        .is_some_and(|value| PolicyVersion::new(value).is_ok())
                    && self.expires_at_ms.is_some_and(|value| value >= 0)
                    && self
                        .policy_sha256
                        .as_deref()
                        .is_some_and(|value| is_lower_hex(value, 64))
                    && self
                        .bundle_sha256
                        .as_deref()
                        .is_some_and(|value| is_lower_hex(value, 64)) => {}
            _ => return Err(invalid_response()),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeMeta {
    pub session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupMeta {
    pub output_path: String,
}

/// Public coordinates of the persisted state in a selected encrypted snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSnapshotCut {
    pub audit_sequence: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub policy: Option<BackupPolicyCut>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPolicyCut {
    pub version: u64,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    pub vault_id: String,
    pub format_version: u32,
    pub created_at_ms: i64,
    pub sha256_hex: String,
    pub output_path: String,
    pub snapshot_cut: BackupSnapshotCut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    pub vault_id: String,
    pub format_version: u32,
    pub input_sha256_hex: String,
    pub output_path: String,
    pub snapshot_cut: BackupSnapshotCut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteMeta {
    /// Short-lived capability token; deliberately a capability, not a secret.
    pub capability_token: String,
    pub action_id: ActionId,
    pub action_version: u64,
    pub content_type: Option<String>,
    /// Plain headers, only those on the action's request-policy allowlist.
    pub extra_headers: Vec<(String, String)>,
    #[serde(default)]
    pub params: TemplateValues,
    #[serde(default)]
    pub query: TemplateValues,
    #[serde(default)]
    pub approval_grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareApprovalMeta {
    pub capability_token: String,
    pub action_id: ActionId,
    pub action_version: u64,
    pub content_type: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    #[serde(default)]
    pub params: TemplateValues,
    #[serde(default)]
    pub query: TemplateValues,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallenge {
    pub record_type: String,
    pub approval_request_id: ApprovalRequestId,
    pub tenant_id: crate::ids::TenantId,
    pub principal_id: crate::ids::PrincipalId,
    pub session_id: SessionId,
    pub action_id: ActionId,
    pub action_version: u64,
    pub resource: ResourceRef,
    pub schema_id: SchemaId,
    pub parameter_sha256: String,
    pub policy_version: u64,
    pub policy_sha256: String,
    pub policy_rule_id: PolicyRuleId,
    pub mode: ApprovalMode,
    pub quorum: u8,
    pub approver_ids: Vec<ApproverId>,
    pub max_uses: u32,
    pub created_at_ms: i64,
    pub max_expires_at_ms: i64,
}

impl ApprovalChallenge {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        let approvers: BTreeSet<_> = self.approver_ids.iter().copied().collect();
        let valid_common = self.record_type == "rekey.approval.challenge.v1"
            && self.action_version > 0
            && PolicyVersion::new(self.policy_version).is_ok()
            && is_lower_hex(&self.parameter_sha256, 64)
            && is_lower_hex(&self.policy_sha256, 64)
            && !self.approver_ids.is_empty()
            && self.approver_ids.len() <= 32
            && approvers.len() == self.approver_ids.len()
            && self.approver_ids.windows(2).all(|pair| pair[0] < pair[1])
            && (1..=2).contains(&self.quorum)
            && usize::from(self.quorum) <= approvers.len()
            && self.created_at_ms >= 0
            && self.max_expires_at_ms > self.created_at_ms;
        let window_ms = self.max_expires_at_ms.saturating_sub(self.created_at_ms);
        let valid_mode = match self.mode {
            ApprovalMode::OneTime => self.max_uses == 1 && window_ms <= 10 * 60 * 1_000,
            ApprovalMode::TimeWindow => {
                (1..=10_000).contains(&self.max_uses) && window_ms <= 8 * 60 * 60 * 1_000
            }
        };
        if !valid_common || !valid_mode {
            return Err(invalid_response());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalChallenge {
    pub record_type: String,
    pub challenge: ApprovalChallenge,
    pub signature: String,
}

impl SignedApprovalChallenge {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        if self.record_type != "rekey.approval.challenge.envelope.v1"
            || !is_canonical_unpadded_base64url(self.signature.as_str(), 64)
        {
            return Err(invalid_response());
        }
        self.challenge.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalOriginResponse {
    pub algorithm: String,
    pub public_key: String,
}

impl ApprovalOriginResponse {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        if self.algorithm != "ed25519" || !is_lower_hex(&self.public_key, 64) {
            return Err(invalid_response());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGetMeta {
    pub approval_request_id: ApprovalRequestId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPendingItem {
    pub approval_request_id: ApprovalRequestId,
    pub session_id: SessionId,
    pub principal_id: PrincipalId,
    pub action_id: ActionId,
    pub action_version: u64,
    pub created_at_ms: i64,
    pub max_expires_at_ms: i64,
    pub mode: ApprovalMode,
    pub quorum: u8,
    pub max_uses: u32,
    pub parameter_sha256: String,
}

impl ApprovalPendingItem {
    pub fn from_challenge(challenge: &ApprovalChallenge) -> Self {
        Self {
            approval_request_id: challenge.approval_request_id,
            session_id: challenge.session_id,
            principal_id: challenge.principal_id,
            action_id: challenge.action_id,
            action_version: challenge.action_version,
            created_at_ms: challenge.created_at_ms,
            max_expires_at_ms: challenge.max_expires_at_ms,
            mode: challenge.mode,
            quorum: challenge.quorum,
            max_uses: challenge.max_uses,
            parameter_sha256: challenge.parameter_sha256.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), crate::DomainError> {
        let valid_common = self.action_version > 0
            && is_lower_hex(&self.parameter_sha256, 64)
            && (1..=2).contains(&self.quorum)
            && self.created_at_ms >= 0
            && self.max_expires_at_ms > self.created_at_ms;
        let valid_mode = match self.mode {
            ApprovalMode::OneTime => self.max_uses == 1,
            ApprovalMode::TimeWindow => (1..=10_000).contains(&self.max_uses),
        };
        if !valid_common || !valid_mode {
            return Err(invalid_response());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPendingResponse {
    pub record_type: String,
    pub challenges: Vec<ApprovalPendingItem>,
}

impl ApprovalPendingResponse {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        if self.record_type != "rekey.approval.pending.v1"
            || self.challenges.len() > APPROVAL_PENDING_MAX
        {
            return Err(invalid_response());
        }
        let mut seen = BTreeSet::new();
        for window in self.challenges.windows(2) {
            let left = (window[0].created_at_ms, window[0].approval_request_id);
            let right = (window[1].created_at_ms, window[1].approval_request_id);
            if left > right {
                return Err(invalid_response());
            }
        }
        for item in &self.challenges {
            if !seen.insert(item.approval_request_id) {
                return Err(invalid_response());
            }
            item.validate()?;
        }
        Ok(())
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_unpadded_base64url(value: &str, decoded_len: usize) -> bool {
    let encoded_len = decoded_len
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(5))
        .map(|bits| bits / 6)
        .unwrap_or(0);
    value.len() == encoded_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn invalid_response() -> crate::DomainError {
    crate::DomainError::InvalidAuthorization("invalid broker response".to_owned())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteResponseMeta {
    pub upstream_status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: u32,
}

pub fn origin_display(origin: &HttpsOrigin) -> String {
    origin.as_str().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_and_restore_receipts_have_required_cut_and_fixed_json_shape() {
        let cut = BackupSnapshotCut {
            audit_sequence: 41,
            policy: Some(BackupPolicyCut {
                version: 2,
                bundle_sha256: "a1".repeat(32),
            }),
        };
        let backup = BackupReceipt {
            vault_id: "actual-vault".to_owned(),
            format_version: 20,
            created_at_ms: 1,
            sha256_hex: "b2".repeat(32),
            output_path: "/archive/selected.rkbackup".to_owned(),
            snapshot_cut: cut.clone(),
        };
        let restore = RestoreReceipt {
            vault_id: backup.vault_id.clone(),
            format_version: backup.format_version,
            input_sha256_hex: backup.sha256_hex.clone(),
            output_path: "/state/restored".to_owned(),
            snapshot_cut: cut,
        };
        let value = serde_json::to_value(&restore).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "vault_id": "actual-vault", "format_version": 20,
                "input_sha256_hex": "b2".repeat(32), "output_path": "/state/restored",
                "snapshot_cut": {"audit_sequence": 41, "policy": {"version": 2, "bundle_sha256": "a1".repeat(32)}}
            })
        );
        assert_eq!(
            serde_json::from_value::<RestoreReceipt>(value.clone())
                .unwrap()
                .snapshot_cut,
            restore.snapshot_cut
        );
        let mut unexpected = value;
        unexpected["latest"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RestoreReceipt>(unexpected).is_err());
        let mut old = serde_json::to_value(&backup).unwrap();
        old.as_object_mut().unwrap().remove("snapshot_cut");
        assert!(serde_json::from_value::<BackupReceipt>(old).is_err());
        let none = BackupSnapshotCut {
            audit_sequence: 0,
            policy: None,
        };
        assert_eq!(
            serde_json::to_value(&none).unwrap(),
            serde_json::json!({"audit_sequence": 0, "policy": null})
        );
        assert!(
            serde_json::from_value::<BackupSnapshotCut>(serde_json::json!({"audit_sequence": 0}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<BackupSnapshotCut>(
                serde_json::json!({"audit_sequence": -1, "policy": null})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<BackupSnapshotCut>(serde_json::json!({"audit_sequence": 1, "policy": {"version": 2, "bundle_sha256": "a1".repeat(32), "latest": true}})).is_err());
    }

    fn header() -> FrameHeader {
        FrameHeader {
            channel: Channel::Admin,
            flags: 0,
            message_type: admin_msg::STATUS,
            request_id: RequestId::new_random(),
            metadata_len: 10,
            body_len: 0,
        }
    }

    #[test]
    fn management_body_preserves_typed_proof_and_rejects_noncanonical_tokens() {
        let token = [b'A'; 43];
        let mut proof = Vec::new();
        encode_proof_body(ProofKind::Password, b"proof", &mut proof);
        let body = encode_management_body(&token, &proof).unwrap();
        let (actual, original) = parse_management_body(&body).unwrap();
        assert_eq!(actual, token);
        assert_eq!(parse_proof_body(original).unwrap().1, b"proof");
        for index in [0, 4, 5, 6, 49] {
            let mut bad = body.clone();
            bad[index] = b'B';
            assert!(parse_management_body(&bad).is_err());
        }
        assert!(parse_management_body(&body[..49]).is_err());
        for id in 1..=54 {
            assert_eq!(
                managed_admin_operation(id).unwrap(),
                !matches!(id, 1 | 2 | 3 | 15 | 16 | 31 | 34 | 36 | 45..=48)
            );
        }
        assert!(managed_admin_operation(55).is_err());
    }

    #[test]
    fn header_roundtrip() {
        let h = header();
        let enc = h.encode();
        assert_eq!(FrameHeader::decode(&enc).unwrap(), h);
    }

    #[test]
    fn template_sources_cannot_override_builtin_provenance() {
        for kind in ["anthropic", "openai", "github-pat", "signed-package"] {
            let source = serde_json::json!({"kind": kind});
            assert!(serde_json::from_value::<TemplateSource>(source.clone()).is_ok());
            let mut overridden = source;
            overridden["template"] = serde_json::json!({"origin": "https://example.com"});
            assert!(serde_json::from_value::<TemplateSource>(overridden).is_err());
        }
        assert!(
            serde_json::from_value::<TemplateSource>(serde_json::json!({
                "kind": "generic-bearer", "origin": "http://example.com",
                "actions": [{"method": "GET", "path": "/v1/items"}]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TemplateSource>(serde_json::json!({
                "kind": "custom", "template": {}
            }))
            .is_err()
        );
    }

    #[test]
    fn header_rejects_malformed() {
        let h = header();
        let mut bad_magic = h.encode();
        bad_magic[0] = b'X';
        assert_eq!(FrameHeader::decode(&bad_magic), Err(FrameError::BadMagic));

        let mut bad_version = h.encode();
        bad_version[5] = 9;
        assert_eq!(
            FrameHeader::decode(&bad_version),
            Err(FrameError::UnsupportedVersion)
        );

        let mut bad_channel = h.encode();
        bad_channel[6] = 7;
        assert_eq!(
            FrameHeader::decode(&bad_channel),
            Err(FrameError::UnknownChannel)
        );

        let mut bad_reserved = h.encode();
        bad_reserved[10] = 1;
        assert_eq!(
            FrameHeader::decode(&bad_reserved),
            Err(FrameError::NonZeroReserved)
        );

        let mut bad_flags = h.encode();
        bad_flags[7] = 1;
        assert_eq!(
            FrameHeader::decode(&bad_flags),
            Err(FrameError::InvalidField)
        );

        let mut oversized_meta = h.encode();
        oversized_meta[28..32].copy_from_slice(&(METADATA_MAX_BYTES + 1).to_be_bytes());
        assert_eq!(
            FrameHeader::decode(&oversized_meta),
            Err(FrameError::SectionTooLarge)
        );
    }

    #[test]
    fn policy_activation_outer_contract_is_closed_and_nested_json_is_verbatim() {
        let vault = "00112233-4455-4677-8899-aabbccddeeff";
        let digest = "a".repeat(64);
        let raw = format!(
            r#"{{"expected_vault_id":"{vault}","expected_trust_sha256":"{digest}","bundle_json":{{"snapshot":{{"version":1,"version":2}}}}}}"#
        );
        let metadata: PolicyActivateMeta = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            metadata.bundle_json.get(),
            r#"{"snapshot":{"version":1,"version":2}}"#
        );
        assert!(
            serde_json::to_string(&metadata)
                .unwrap()
                .contains(r#""bundle_json":{"snapshot":{"version":1,"version":2}}"#)
        );
        for invalid in [
            raw.replace(
                r#""expected_vault_id":""#,
                &format!(r#""expected_vault_id":"{vault}","expected_vault_id":""#),
            ),
            raw.replace(r#""bundle_json":"#, r#""unknown":1,"bundle_json":"#),
            raw.replace(&format!(r#""expected_trust_sha256":"{digest}","#), ""),
            r#"{"format_version":1,"snapshot":{}}"#.to_owned(),
        ] {
            assert!(serde_json::from_str::<PolicyActivateMeta>(&invalid).is_err());
        }
    }

    #[test]
    fn policy_status_requires_actual_identity_and_complete_persisted_details() {
        let vault_id = VaultId::new_random();
        let mut status = PolicyStatusResponse {
            vault_id,
            tenant_id: TenantId::from_bytes(*vault_id.as_bytes()).unwrap(),
            mode: Some(crate::authorization::PolicyMode::Team),
            algorithm: Some(crate::authorization::PolicyTrustAlgorithm::Ed25519),
            trust_installed: true,
            bundle_persisted: false,
            status: "unavailable".into(),
            trust_sha256: Some("a".repeat(64)),
            activated_at_ms: None,
            signer_id: None,
            version: None,
            expires_at_ms: None,
            policy_sha256: None,
            bundle_sha256: None,
        };
        status.validate().unwrap();
        status.trust_installed = false;
        assert!(status.validate().is_err());
        status.trust_installed = true;
        status.status = "active".into();
        status.bundle_persisted = true;
        status.signer_id = Some(PolicySignerId::new_random());
        status.version = Some(1);
        status.expires_at_ms = Some(10);
        status.policy_sha256 = Some("b".repeat(64));
        status.bundle_sha256 = Some("c".repeat(64));
        assert!(status.validate().is_err());
        status.activated_at_ms = Some(1);
        status.validate().unwrap();
        status.trust_sha256 = Some("A".repeat(64));
        assert!(status.validate().is_err());
        status.trust_sha256 = Some("a".repeat(64));
        status.mode = None;
        assert!(status.validate().is_err());
        status.mode = Some(crate::authorization::PolicyMode::Personal);
        assert!(status.validate().is_err());
        status.algorithm = Some(crate::authorization::PolicyTrustAlgorithm::SecureEnclaveP256);
        status.validate().unwrap();
        status.tenant_id = TenantId::from_random_bytes([0x55; 16]);
        assert_ne!(status.tenant_id.as_bytes(), status.vault_id.as_bytes());
        assert!(status.validate().is_err());
    }

    #[test]
    fn proof_body_roundtrip() {
        let proof = b"pw";
        let secret = b"token-value";
        let expected_len = 1 + 4 + proof.len() + 4 + secret.len();
        let mut buf = Vec::with_capacity(expected_len);
        let original_capacity = buf.capacity();
        let original_pointer = buf.as_ptr();
        encode_proof_and_secret_body(ProofKind::Password, proof, secret, &mut buf);
        assert_eq!(buf.len(), expected_len);
        assert_eq!(buf.capacity(), original_capacity);
        assert_eq!(buf.as_ptr(), original_pointer);
        let (kind, proof, secret) = parse_proof_and_secret_body(&buf).unwrap();
        assert_eq!(kind, ProofKind::Password);
        assert_eq!(proof, b"pw");
        assert_eq!(secret, b"token-value");

        // trailing garbage must be rejected, not ignored
        buf.push(0);
        assert!(parse_proof_and_secret_body(&buf).is_err());

        let mut only = Vec::new();
        encode_proof_body(ProofKind::Recovery, b"rk", &mut only);
        let (kind, proof) = parse_proof_body(&only).unwrap();
        assert_eq!(kind, ProofKind::Recovery);
        assert_eq!(proof, b"rk");
        assert!(parse_proof_body(&only[..3]).is_err());
    }

    #[test]
    fn maximum_admin_proof_and_secret_fit_the_body_limit() {
        let proof = vec![b'p'; ADMIN_SECRET_FIELD_MAX_BYTES as usize];
        let secret = vec![b's'; ADMIN_SECRET_FIELD_MAX_BYTES as usize];
        let mut body = Vec::with_capacity(ADMIN_SECRET_BODY_MAX_BYTES as usize);
        encode_proof_and_secret_body(ProofKind::Password, &proof, &secret, &mut body);
        assert_eq!(body.len(), ADMIN_SECRET_BODY_MAX_BYTES as usize);
        assert!(parse_proof_and_secret_body(&body).is_ok());

        let oversized = vec![b'x'; ADMIN_SECRET_FIELD_MAX_BYTES as usize + 1];
        let mut proof_body = Vec::new();
        encode_proof_body(ProofKind::Password, &oversized, &mut proof_body);
        assert_eq!(
            parse_proof_body(&proof_body),
            Err(FrameError::SectionTooLarge)
        );
        let mut secret_body = Vec::new();
        encode_proof_and_secret_body(ProofKind::Password, b"p", &oversized, &mut secret_body);
        assert_eq!(
            parse_proof_and_secret_body(&secret_body),
            Err(FrameError::SectionTooLarge)
        );
    }
}

/// Final outcome for the independent text stream operation. Missing terminal is failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextStreamStatus {
    Completed,
    Incomplete,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamChunkMeta {
    pub sequence: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextStreamTerminalMeta {
    pub sequence: u32,
    pub status: TextStreamStatus,
}

pub const TEXT_STREAM_CHUNK_MAX_BYTES: usize = 16 * 1024;
