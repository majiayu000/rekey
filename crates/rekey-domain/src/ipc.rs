//! Frame v1 wire protocol and message metadata DTOs.
//!
//! Pure byte-level encode/decode with no IO so both the broker and the
//! IPC-only CLI can share one implementation. Secret bytes travel only in the
//! raw frame body, never inside JSON metadata.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::action::{FixedHttpAction, HttpsOrigin};
use crate::authorization::{ApprovalMode, PolicyVersion, ResourceRef, SchemaId};
use crate::capability::ActionVersionRef;
use crate::credential::{CredentialLabel, CredentialMetadata};
use crate::ids::{
    ActionId, ApprovalRequestId, ApproverId, CredentialId, PolicyRuleId, PolicySignerId, RequestId,
    SessionId,
};

pub const FRAME_MAGIC: [u8; 4] = *b"RKIP";
pub const FRAME_VERSION: u16 = 1;
pub const FRAME_HEADER_LEN: usize = 36;
pub const METADATA_MAX_BYTES: u32 = 64 * 1024;
pub const ADMIN_SECRET_FIELD_MAX_BYTES: u32 = 64 * 1024;
pub const ADMIN_PROOF_BODY_MAX_BYTES: u32 = ADMIN_SECRET_FIELD_MAX_BYTES + 5;
pub const ADMIN_SECRET_BODY_MAX_BYTES: u32 = 2 * ADMIN_SECRET_FIELD_MAX_BYTES + 9;
pub const AGENT_BODY_MAX_BYTES: u32 = 1024 * 1024;
pub const WORKLOAD_TOKEN_MAX_BYTES: u32 = 16 * 1024;
pub const RESPONSE_BODY_MAX_BYTES: u32 = 4 * 1024 * 1024;

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
}

/// Agent channel message types.
pub mod agent_msg {
    pub const EXECUTE_FIXED_HTTP_ACTION: u16 = 1;
    pub const AGENT_STATUS: u16 = 2;
    pub const PREPARE_APPROVAL: u16 = 3;
    pub const WORKLOAD_SESSION_CREATE: u16 = 4;
}

/// Response message types shared by both channels.
pub mod resp_msg {
    pub const OK: u16 = 100;
    pub const ERROR: u16 = 101;
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
    pub sessions_active: u32,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateMeta {
    pub actions: Vec<ActionVersionRef>,
    pub ttl_ms: i64,
    pub max_uses: u32,
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
pub struct PolicyStatusResponse {
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
        if self.bundle_persisted && !self.trust_installed {
            return Err(invalid_response());
        }
        let details_present = self.signer_id.is_some()
            && self.version.is_some()
            && self.expires_at_ms.is_some()
            && self.policy_sha256.is_some()
            && self.bundle_sha256.is_some();
        match self.status.as_str() {
            "unavailable"
                if self.signer_id.is_none()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    pub vault_id: String,
    pub format_version: u32,
    pub created_at_ms: i64,
    pub sha256_hex: String,
    pub output_path: String,
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

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    fn header_roundtrip() {
        let h = header();
        let enc = h.encode();
        assert_eq!(FrameHeader::decode(&enc).unwrap(), h);
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
