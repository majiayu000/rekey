use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::edwards::CompressedEdwardsY;
use data_encoding::HEXLOWER;
use jsonschema::{Draft, Validator};
use rekey_domain::Timestamp;
use rekey_domain::action::{ActionTarget, FixedHttpAction, HeaderName};
use rekey_domain::authorization::{
    ApprovalMode, ApprovalRequirement, ApproverSpec, AuthorizationRequest, CanonicalParameters,
    Decision, DenyReason, PolicyVersion, ResourceRef, SchemaId,
};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ActionId, ApproverId, PolicyRuleId, PrincipalId};
use rekey_domain::template::{RenderedTarget, TemplateValues};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SNAPSHOT_FORMAT_VERSION: u32 = 4;
pub const SNAPSHOT_MAX_BYTES: usize = 64 * 1024;
pub const TRUST_MAX_BYTES: usize = 4 * 1024;
pub const APPROVAL_GRANT_MAX_BYTES: usize = 4 * 1024;

mod json;
use json::parse_unique_json;
#[cfg(feature = "lab")]
pub mod oidc_admin;
pub mod personal;
mod signed;
pub use signed::*;
pub mod templates;
mod workload;
pub use workload::*;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy snapshot is malformed")]
    Malformed,
    #[error("policy snapshot is too large")]
    TooLarge,
    #[error("policy snapshot format is unsupported")]
    UnsupportedFormat,
    #[error("policy snapshot is expired")]
    Expired,
    #[error("policy snapshot is invalid")]
    Invalid,
    #[error("request parameters are invalid")]
    InvalidParameters,
    #[error("signature verification failed")]
    InvalidSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshot {
    pub format_version: u32,
    pub version: PolicyVersion,
    pub expires_at_ms: i64,
    pub approvers: Vec<Approver>,
    pub workload_identities: Vec<WorkloadIdentity>,
    pub bindings: Vec<ActionBinding>,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approver {
    pub approver_id: ApproverId,
    pub algorithm: SignatureAlgorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBinding {
    pub action_id: ActionId,
    pub version: u64,
    pub resource: ResourceRef,
    pub parameter_schema_id: SchemaId,
    pub parameter_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: PolicyRuleId,
    pub effect: RuleEffect,
    pub principal_id: PrincipalId,
    pub action_id: ActionId,
    pub version: u64,
    pub resource: ResourceRef,
    pub parameters: ParameterScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<ApproverSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalRequirement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleEffect {
    Permit,
    Forbid,
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParameterScope {
    AnyValidated {},
    ExactHash { sha256: String },
}

struct CompiledBinding {
    definition: ActionBinding,
    validator: Validator,
}

pub struct ValidatedSnapshot {
    version: PolicyVersion,
    expires_at_ms: i64,
    digest: [u8; 32],
    bindings: Vec<CompiledBinding>,
    rules: Vec<PolicyRule>,
    approvers: BTreeMap<ApproverId, [u8; 32]>,
    workload_catalog: WorkloadCatalog,
}

/// The untrusted, per-call values used by both the Broker and approval signer.
pub struct ActionRequest<'a> {
    pub params: &'a TemplateValues,
    pub query: &'a TemplateValues,
    pub content_type: Option<&'a str>,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

impl ValidatedSnapshot {
    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn approver_key(&self, approver_id: ApproverId) -> Option<&[u8; 32]> {
        self.approvers.get(&approver_id)
    }

    /// Resolve canonical public keys through this authenticated snapshot only.
    /// IDs are derived for grant verification; they are never a second wire source.
    pub fn ed25519_approver_ids(&self, keys: &[String]) -> Option<Vec<ApproverId>> {
        resolve_approver_ids(keys, &self.approvers)
    }

    pub fn binding(&self, action: ActionVersionRef) -> Option<&ActionBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.definition.action() == action)
            .map(|binding| &binding.definition)
    }

    pub fn action_refs(&self) -> impl Iterator<Item = ActionVersionRef> + '_ {
        self.bindings
            .iter()
            .map(|binding| binding.definition.action())
    }

    /// Only exact signed OIDC human registrations participate in the node login gate.
    pub fn has_oidc_human_binding(
        &self,
        issuer: &str,
        subject: &str,
        principal: PrincipalId,
    ) -> bool {
        self.workload_catalog
            .has_oidc_human_binding(issuer, subject, principal)
    }

    pub fn verify_workload_token(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> Result<VerifiedWorkloadIdentity, PolicyError> {
        self.workload_catalog.verify(token, now, self.digest, None)
    }

    /// Routes bounded, unverified claims to an explicit signed source; does not authenticate.
    pub fn workload_online_key_source(
        &self,
        token: &[u8],
    ) -> Result<Option<OnlineKeySource>, PolicyError> {
        self.workload_catalog.online_key_source(token)
    }

    /// The caller must fetch these keys from the fixed trusted GitHub endpoint.
    /// Keys are transient; the policy digest and replay scope remain unchanged.
    pub fn verify_workload_token_with_github_jwks(
        &self,
        token: &[u8],
        now: Timestamp,
        jwks: &GithubActionsJwks,
    ) -> Result<VerifiedWorkloadIdentity, PolicyError> {
        self.workload_catalog
            .verify(token, now, self.digest, Some(jwks))
    }

    pub fn workload_principal_may_request(
        &self,
        principal_id: PrincipalId,
        action: ActionVersionRef,
    ) -> bool {
        self.binding(action).is_some()
            && self.rules.iter().any(|rule| {
                rule.principal_id == principal_id
                    && rule.action() == action
                    && matches!(
                        rule.effect,
                        RuleEffect::Permit | RuleEffect::RequireApproval
                    )
            })
    }

    /// Render exactly once and bind the resulting path, normalized parameters,
    /// sorted query, effective headers and validated JSON body into approval JCS.
    /// The caller carries the returned target unchanged to its HTTP transport.
    pub fn canonicalize(
        &self,
        action: &FixedHttpAction,
        request: ActionRequest<'_>,
    ) -> Result<(ResourceRef, CanonicalParameters, RenderedTarget), PolicyError> {
        let action_ref = ActionVersionRef {
            action_id: action.id,
            version: action.version,
        };
        let binding = self
            .bindings
            .iter()
            .find(|binding| binding.definition.action() == action_ref)
            .ok_or(PolicyError::InvalidParameters)?;
        let (target, fixed_headers, body_schema) = match &action.target {
            ActionTarget::Fixed { path } => {
                if !request.params.is_empty() || !request.query.is_empty() {
                    return Err(PolicyError::InvalidParameters);
                }
                (
                    RenderedTarget {
                        path: path.clone(),
                        params: BTreeMap::new(),
                        query: BTreeMap::new(),
                    },
                    None,
                    None,
                )
            }
            ActionTarget::Template {
                target,
                fixed_headers,
                body_schema,
                ..
            } => (
                target
                    .render(request.params, request.query)
                    .map_err(|_| PolicyError::InvalidParameters)?,
                Some(fixed_headers),
                body_schema.as_ref(),
            ),
        };
        if request.body.len() > action.request_policy.max_body_bytes as usize {
            return Err(PolicyError::InvalidParameters);
        }
        let fixed_content_type = fixed_headers.and_then(|headers| {
            headers
                .iter()
                .find(|(name, _)| name.as_str() == "content-type")
                .map(|(_, value)| value.as_str())
        });
        if fixed_content_type.is_some() && request.content_type.is_some() {
            return Err(PolicyError::InvalidParameters);
        }
        let content_type = fixed_content_type.or(request.content_type);
        if content_type.is_some_and(|value| value.is_empty() || !header_value_is_safe(value)) {
            return Err(PolicyError::InvalidParameters);
        }
        let normalized_content_type = normalize_content_type(content_type, request.body)?;
        let value = if request.body.is_empty() {
            Value::Null
        } else {
            let value = parse_unique_json(request.body)?;
            ensure_json_number_fidelity(request.body)?;
            value
        };
        if !binding.validator.is_valid(&value) {
            return Err(PolicyError::InvalidParameters);
        }
        if let Some(schema) = body_schema {
            let validator = templates::compile_template_schema(schema.clone())
                .map_err(|_| PolicyError::InvalidParameters)?;
            if !validator.is_valid(&value) {
                return Err(PolicyError::InvalidParameters);
            }
        }
        let mut normalized_headers = Vec::new();
        let mut seen = BTreeSet::new();
        if let Some(headers) = fixed_headers {
            for (name, value) in headers {
                seen.insert(name.as_str().to_owned());
                if name.as_str() != "content-type" {
                    normalized_headers.push((name.as_str().to_owned(), value.clone()));
                }
            }
        }
        for (raw_name, value) in request.headers {
            let name = HeaderName::new(raw_name).map_err(|_| PolicyError::InvalidParameters)?;
            if raw_name != name.as_str()
                || name.is_forbidden()
                || name == action.auth.header_name
                || name.as_str() == "authorization"
                || name.as_str() == "content-type"
                || !action.request_policy.allowed_extra_headers.contains(&name)
                || !header_value_is_safe(value)
                || !seen.insert(name.as_str().to_owned())
            {
                return Err(PolicyError::InvalidParameters);
            }
            normalized_headers.push((name.as_str().to_owned(), value.clone()));
        }
        normalized_headers.sort();
        let envelope = serde_json::json!({
            "target": target,
            "body": value,
            "content_type": normalized_content_type,
            "headers": normalized_headers,
        });
        let canonical = serde_jcs::to_vec(&envelope).map_err(|_| PolicyError::InvalidParameters)?;
        let definition = &binding.definition;
        let hash = parameter_hash(
            definition.action(),
            &definition.parameter_schema_id,
            &definition.resource,
            &canonical,
        )?;
        Ok((
            definition.resource.clone(),
            CanonicalParameters {
                schema_id: definition.parameter_schema_id.clone(),
                canonical_hash: hash,
                canonical_json: canonical,
            },
            target,
        ))
    }
}

pub fn parse_and_validate_snapshot(
    bytes: &[u8],
    now: Timestamp,
) -> Result<ValidatedSnapshot, PolicyError> {
    parse_and_validate_snapshot_inner(bytes, Some(now))
}

/// Validates a persisted signed snapshot without treating wall-clock expiry as
/// malformed. The Broker publishes it as expired and keeps execution denied.
pub fn parse_and_validate_snapshot_for_load(
    bytes: &[u8],
) -> Result<ValidatedSnapshot, PolicyError> {
    parse_and_validate_snapshot_inner(bytes, None)
}

fn parse_and_validate_snapshot_inner(
    bytes: &[u8],
    now: Option<Timestamp>,
) -> Result<ValidatedSnapshot, PolicyError> {
    if bytes.len() > SNAPSHOT_MAX_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let value = parse_unique_json(bytes)?;
    let snapshot: PolicySnapshot =
        serde_json::from_value(value.clone()).map_err(|_| PolicyError::Malformed)?;
    if snapshot.format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(PolicyError::UnsupportedFormat);
    }
    if snapshot.expires_at_ms < 0
        || now.is_some_and(|now| snapshot.expires_at_ms <= now.as_unix_ms())
    {
        return Err(PolicyError::Expired);
    }

    if snapshot.approvers.len() > 32 {
        return Err(PolicyError::Invalid);
    }
    let mut approvers = BTreeMap::new();
    let mut public_keys = BTreeSet::new();
    for approver in &snapshot.approvers {
        let key = validate_ed25519_public_key(&approver.public_key)?;
        if approvers.insert(approver.approver_id, key).is_some() || !public_keys.insert(key) {
            return Err(PolicyError::Invalid);
        }
    }

    let mut seen_bindings = BTreeSet::new();
    let mut compiled = Vec::with_capacity(snapshot.bindings.len());
    for binding in &snapshot.bindings {
        if binding.version == 0 || !seen_bindings.insert(binding.action()) {
            return Err(PolicyError::Invalid);
        }
        reject_remote_refs(&binding.parameter_schema)?;
        let validator = jsonschema::options()
            .with_draft(Draft::Draft202012)
            .build(&binding.parameter_schema)
            .map_err(|_| PolicyError::Invalid)?;
        compiled.push(CompiledBinding {
            definition: binding.clone(),
            validator,
        });
    }

    let mut seen_rules = BTreeSet::new();
    for rule in &snapshot.rules {
        if rule.version == 0 || !seen_rules.insert(rule.id) {
            return Err(PolicyError::Invalid);
        }
        let Some(binding) = snapshot
            .bindings
            .iter()
            .find(|binding| binding.action() == rule.action())
        else {
            return Err(PolicyError::Invalid);
        };
        if binding.resource != rule.resource {
            return Err(PolicyError::Invalid);
        }
        if let ParameterScope::ExactHash { sha256 } = &rule.parameters {
            decode_lower_hex_32(sha256)?;
        }
        match (rule.effect, rule.approver.as_ref(), rule.approval.as_ref()) {
            (RuleEffect::Permit | RuleEffect::Forbid, None, None) => {}
            (RuleEffect::RequireApproval, Some(approver), Some(requirement)) => {
                validate_requirement(approver, requirement, &approvers)?;
            }
            _ => return Err(PolicyError::Invalid),
        }
    }

    for (index, left) in snapshot.rules.iter().enumerate() {
        if left.effect != RuleEffect::RequireApproval {
            continue;
        }
        for right in snapshot.rules.iter().skip(index + 1) {
            if right.effect == RuleEffect::RequireApproval
                && left.principal_id == right.principal_id
                && left.action() == right.action()
                && left.resource == right.resource
                && scopes_overlap(&left.parameters, &right.parameters)
                && !requirements_equivalent(
                    left.approver.as_ref().ok_or(PolicyError::Invalid)?,
                    left.approval.as_ref().ok_or(PolicyError::Invalid)?,
                    right.approver.as_ref().ok_or(PolicyError::Invalid)?,
                    right.approval.as_ref().ok_or(PolicyError::Invalid)?,
                )
            {
                return Err(PolicyError::Invalid);
            }
        }
    }

    let workload_catalog =
        WorkloadCatalog::compile(&snapshot.workload_identities, &snapshot.rules)?;

    let canonical = serde_jcs::to_vec(&value).map_err(|_| PolicyError::Malformed)?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(canonical));
    Ok(ValidatedSnapshot {
        version: snapshot.version,
        expires_at_ms: snapshot.expires_at_ms,
        digest,
        bindings: compiled,
        rules: snapshot.rules,
        approvers,
        workload_catalog,
    })
}

pub fn evaluate(
    snapshot: &ValidatedSnapshot,
    request: &AuthorizationRequest,
    now: Timestamp,
    irrevocably_expired: bool,
) -> Decision {
    if irrevocably_expired || snapshot.expires_at_ms <= now.as_unix_ms() {
        return deny(snapshot, DenyReason::SnapshotExpired, None);
    }
    let mut permit: Option<PolicyRuleId> = None;
    let mut forbid: Option<PolicyRuleId> = None;
    let mut approval: Option<(PolicyRuleId, &ApproverSpec, &ApprovalRequirement)> = None;
    for rule in &snapshot.rules {
        if rule.principal_id != request.principal.principal_id
            || rule.action() != request.action
            || rule.resource != request.resource
            || !scope_matches(&rule.parameters, request.parameters.canonical_hash)
        {
            continue;
        }
        match rule.effect {
            RuleEffect::Forbid => forbid = minimum(forbid, rule.id),
            RuleEffect::Permit => permit = minimum(permit, rule.id),
            RuleEffect::RequireApproval => {
                let (Some(approver), Some(requirement)) =
                    (rule.approver.as_ref(), rule.approval.as_ref())
                else {
                    return deny(snapshot, DenyReason::EvaluationFailed, Some(rule.id));
                };
                if approval.is_none_or(|current| rule.id < current.0) {
                    approval = Some((rule.id, approver, requirement));
                }
            }
        }
    }
    if let Some(rule) = forbid {
        deny(snapshot, DenyReason::ExplicitForbid, Some(rule))
    } else if let Some((rule, approver, requirement)) = approval {
        let mut approver = approver.clone();
        if let ApproverSpec::Ed25519 { keys, .. } = &mut approver {
            keys.sort();
        }
        Decision::RequireApproval {
            policy_version: snapshot.version,
            snapshot_digest: snapshot.digest,
            determining_rule: rule,
            approver,
            requirement: requirement.clone(),
        }
    } else if let Some(rule) = permit {
        Decision::Allow {
            policy_version: snapshot.version,
            snapshot_digest: snapshot.digest,
            determining_rule: rule,
        }
    } else {
        deny(snapshot, DenyReason::NoMatchingPermit, None)
    }
}

impl ActionBinding {
    fn action(&self) -> ActionVersionRef {
        ActionVersionRef {
            action_id: self.action_id,
            version: self.version,
        }
    }
}

impl PolicyRule {
    fn action(&self) -> ActionVersionRef {
        ActionVersionRef {
            action_id: self.action_id,
            version: self.version,
        }
    }
}

fn deny(
    snapshot: &ValidatedSnapshot,
    reason: DenyReason,
    determining_rule: Option<PolicyRuleId>,
) -> Decision {
    Decision::Deny {
        policy_version: Some(snapshot.version),
        snapshot_digest: Some(snapshot.digest),
        reason,
        determining_rule,
    }
}

fn minimum(current: Option<PolicyRuleId>, candidate: PolicyRuleId) -> Option<PolicyRuleId> {
    Some(current.map_or(candidate, |value| value.min(candidate)))
}

fn scope_matches(scope: &ParameterScope, hash: [u8; 32]) -> bool {
    match scope {
        ParameterScope::AnyValidated {} => true,
        ParameterScope::ExactHash { sha256 } => HEXLOWER.encode(&hash) == *sha256,
    }
}

fn scopes_overlap(left: &ParameterScope, right: &ParameterScope) -> bool {
    match (left, right) {
        (ParameterScope::AnyValidated {}, _) | (_, ParameterScope::AnyValidated {}) => true,
        (
            ParameterScope::ExactHash { sha256: left },
            ParameterScope::ExactHash { sha256: right },
        ) => left == right,
    }
}

fn resolve_approver_ids(
    keys: &[String],
    approvers: &BTreeMap<ApproverId, [u8; 32]>,
) -> Option<Vec<ApproverId>> {
    if keys.is_empty() || keys.len() > 32 {
        return None;
    }
    let mut ids = BTreeSet::new();
    for key in keys {
        let id = approvers
            .iter()
            .find_map(|(id, public_key)| (HEXLOWER.encode(public_key) == *key).then_some(*id))?;
        if !ids.insert(id) {
            return None;
        }
    }
    Some(ids.into_iter().collect())
}

fn validate_requirement(
    approver: &ApproverSpec,
    requirement: &ApprovalRequirement,
    approvers: &BTreeMap<ApproverId, [u8; 32]>,
) -> Result<(), PolicyError> {
    match approver {
        ApproverSpec::LocalPresence {} => {
            if requirement.mode != ApprovalMode::OneTime {
                return Err(PolicyError::Invalid);
            }
        }
        ApproverSpec::Ed25519 { keys, threshold } => {
            let ids = resolve_approver_ids(keys, approvers).ok_or(PolicyError::Invalid)?;
            if !(1..=2).contains(threshold) || usize::from(*threshold) > ids.len() {
                return Err(PolicyError::Invalid);
            }
        }
        #[cfg(feature = "lab")]
        ApproverSpec::Remote {} => return Err(PolicyError::Invalid),
    }
    match requirement.mode {
        ApprovalMode::OneTime
            if requirement.max_uses == 1 && requirement.max_window_ms.is_none() => {}
        ApprovalMode::TimeWindow
            if (1..=10_000).contains(&requirement.max_uses)
                && requirement
                    .max_window_ms
                    .is_some_and(|window| (1..=8 * 60 * 60 * 1_000).contains(&window)) => {}
        _ => return Err(PolicyError::Invalid),
    }
    Ok(())
}

fn requirements_equivalent(
    left_approver: &ApproverSpec,
    left: &ApprovalRequirement,
    right_approver: &ApproverSpec,
    right: &ApprovalRequirement,
) -> bool {
    let same_approver = match (left_approver, right_approver) {
        (ApproverSpec::LocalPresence {}, ApproverSpec::LocalPresence {}) => true,
        (
            ApproverSpec::Ed25519 {
                keys: left,
                threshold: left_threshold,
            },
            ApproverSpec::Ed25519 {
                keys: right,
                threshold: right_threshold,
            },
        ) => {
            left_threshold == right_threshold
                && left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
        }
        _ => false,
    };
    same_approver
        && left.mode == right.mode
        && left.max_uses == right.max_uses
        && left.max_window_ms == right.max_window_ms
}

pub fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], PolicyError> {
    let decoded = HEXLOWER
        .decode(value.as_bytes())
        .map_err(|_| PolicyError::Invalid)?;
    if decoded.len() != 32 || HEXLOWER.encode(&decoded) != value {
        return Err(PolicyError::Invalid);
    }
    decoded.try_into().map_err(|_| PolicyError::Invalid)
}

pub fn validate_ed25519_public_key(value: &str) -> Result<[u8; 32], PolicyError> {
    let public_key = decode_lower_hex_32(value)?;
    let compressed = CompressedEdwardsY(public_key);
    let point = compressed.decompress().ok_or(PolicyError::Invalid)?;
    if point.is_small_order() || point.compress().to_bytes() != public_key {
        return Err(PolicyError::Invalid);
    }
    Ok(public_key)
}

fn header_value_is_safe(value: &str) -> bool {
    value.len() <= 8 * 1024
        && value
            .bytes()
            .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
}

fn normalize_content_type(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Option<&'static str>, PolicyError> {
    match content_type.map(str::trim) {
        None if body.is_empty() => Ok(None),
        Some("") if body.is_empty() => Ok(None),
        Some(value)
            if value.eq_ignore_ascii_case("application/json")
                || value.eq_ignore_ascii_case("application/json; charset=utf-8") =>
        {
            Ok(Some("application/json"))
        }
        _ => Err(PolicyError::InvalidParameters),
    }
}

// The JSON syntax and duplicate-key checks have already succeeded. Inspect
// only number tokens outside strings: the upstream still receives these raw
// bytes, so even precision lost during the first parse must fail closed.
fn ensure_json_number_fidelity(body: &[u8]) -> Result<(), PolicyError> {
    let mut at = 0;
    while at < body.len() {
        match body[at] {
            b'"' => {
                at += 1;
                while at < body.len() {
                    match body[at] {
                        b'\\' => at += 2,
                        b'"' => {
                            at += 1;
                            break;
                        }
                        _ => at += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = at;
                while at < body.len()
                    && matches!(body[at], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    at += 1;
                }
                let original = &body[start..at];
                let number: serde_json::Number =
                    serde_json::from_slice(original).map_err(|_| PolicyError::InvalidParameters)?;
                let canonical =
                    serde_jcs::to_vec(&number).map_err(|_| PolicyError::InvalidParameters)?;
                let left = decimal_parts(original).ok_or(PolicyError::InvalidParameters)?;
                let right = decimal_parts(&canonical).ok_or(PolicyError::InvalidParameters)?;
                if left != right {
                    return Err(PolicyError::InvalidParameters);
                }
            }
            _ => at += 1,
        }
    }
    Ok(())
}

// Compare exact decimal values without converting the comparison to f64.
// Both inputs are valid JSON number tokens. Zero ignores sign and exponent;
// nonzero exponents use checked arithmetic, with no powers or big integers.
fn decimal_parts(number: &[u8]) -> Option<(bool, Vec<u8>, i64)> {
    let negative = number.first() == Some(&b'-');
    let unsigned = if negative { &number[1..] } else { number };
    let exponent_at = unsigned
        .iter()
        .position(|b| matches!(b, b'e' | b'E'))
        .unwrap_or(unsigned.len());
    let mantissa = &unsigned[..exponent_at];
    let digits: Vec<u8> = mantissa
        .iter()
        .copied()
        .filter(u8::is_ascii_digit)
        .collect();
    let Some(first) = digits.iter().position(|b| *b != b'0') else {
        return Some((false, Vec::new(), 0));
    };
    let end = digits.iter().rposition(|b| *b != b'0')? + 1;
    let fractional = mantissa
        .iter()
        .position(|b| *b == b'.')
        .map_or(0, |dot| mantissa.len() - dot - 1);
    let exponent = if exponent_at == unsigned.len() {
        0
    } else {
        std::str::from_utf8(&unsigned[exponent_at + 1..])
            .ok()?
            .parse::<i64>()
            .ok()?
    };
    let exponent = exponent
        .checked_sub(i64::try_from(fractional).ok()?)?
        .checked_add(i64::try_from(digits.len() - end).ok()?)?;
    Some((negative, digits[first..end].to_vec(), exponent))
}

fn parameter_hash(
    action: ActionVersionRef,
    schema_id: &SchemaId,
    resource: &ResourceRef,
    canonical: &[u8],
) -> Result<[u8; 32], PolicyError> {
    let schema_len: u16 = schema_id
        .as_str()
        .len()
        .try_into()
        .map_err(|_| PolicyError::InvalidParameters)?;
    let resource_type_len: u16 = resource
        .resource_type
        .len()
        .try_into()
        .map_err(|_| PolicyError::InvalidParameters)?;
    let resource_id_len: u32 = resource
        .id
        .len()
        .try_into()
        .map_err(|_| PolicyError::InvalidParameters)?;
    let canonical_len: u32 = canonical
        .len()
        .try_into()
        .map_err(|_| PolicyError::InvalidParameters)?;
    let mut hasher = Sha256::new();
    hasher.update(b"RKPARAM\0\x01");
    hasher.update(action.action_id.as_bytes());
    hasher.update(action.version.to_be_bytes());
    hasher.update(schema_len.to_be_bytes());
    hasher.update(schema_id.as_str().as_bytes());
    hasher.update(resource_type_len.to_be_bytes());
    hasher.update(resource.resource_type.as_bytes());
    hasher.update(resource_id_len.to_be_bytes());
    hasher.update(resource.id.as_bytes());
    hasher.update(canonical_len.to_be_bytes());
    hasher.update(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

fn reject_remote_refs(value: &Value) -> Result<(), PolicyError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" {
                    let Some(reference) = value.as_str() else {
                        return Err(PolicyError::Invalid);
                    };
                    if !reference.starts_with('#') {
                        return Err(PolicyError::Invalid);
                    }
                }
                reject_remote_refs(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_remote_refs(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::ids::{ActionId, PrincipalId};

    fn fixed_action(action: ActionVersionRef) -> FixedHttpAction {
        serde_json::from_value(serde_json::json!({
            "id": action.action_id, "name": "policy-test", "version": action.version,
            "enabled": true, "credential_id": rekey_domain::ids::CredentialId::new_random(),
            "origin": "https://example.com", "method": "POST", "target": {"kind":"fixed","path":"/test"},
            "auth": {"header_name":"authorization","prefix":"Bearer "}, "timeout_ms":5000,
            "request_policy":{"max_body_bytes":4096,"allowed_extra_headers":[]},
            "response_policy":{"max_body_bytes":4096,"allowed_headers":[]}
        })).unwrap()
    }

    fn json_request(body: &[u8]) -> ActionRequest<'_> {
        static EMPTY: std::sync::LazyLock<TemplateValues> =
            std::sync::LazyLock::new(TemplateValues::new);
        ActionRequest {
            params: &EMPTY,
            query: &EMPTY,
            content_type: Some("application/json"),
            headers: &[],
            body,
        }
    }

    fn ids() -> (ActionVersionRef, PrincipalId, PolicyRuleId) {
        (
            ActionVersionRef {
                action_id: ActionId::new_random(),
                version: 1,
            },
            PrincipalId::new_random(),
            PolicyRuleId::new_random(),
        )
    }

    fn snapshot_json(
        action: ActionVersionRef,
        principal: PrincipalId,
        rule: PolicyRuleId,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "format_version": 4,
            "version": 1,
            "expires_at_ms": 10_000,
            "approvers": [],
            "workload_identities": [],
            "bindings": [{
                "action_id": action.action_id,
                "version": action.version,
                "resource": {"type": "test.resource", "id": "one"},
                "parameter_schema_id": "test/v1",
                "parameter_schema": {"type": "object", "required": ["input"], "additionalProperties": false, "properties": {"input": {"type": "integer"}}}
            }],
            "rules": [{
                "id": rule,
                "effect": "permit",
                "principal_id": principal,
                "action_id": action.action_id,
                "version": action.version,
                "resource": {"type": "test.resource", "id": "one"},
                "parameters": {"kind": "any_validated"}
            }]
        })).unwrap()
    }

    #[test]
    fn validates_and_evaluates_permit() {
        let (action, principal_id, rule) = ids();
        let snapshot = parse_and_validate_snapshot(
            &snapshot_json(action, principal_id, rule),
            Timestamp::from_unix_ms(1),
        )
        .unwrap();
        let (resource, parameters, _) = snapshot
            .canonicalize(&fixed_action(action), json_request(br#"{"input":1}"#))
            .unwrap();
        let request = AuthorizationRequest {
            principal: rekey_domain::authorization::Principal {
                tenant_id: rekey_domain::ids::TenantId::new_random(),
                principal_id,
                session_id: rekey_domain::ids::SessionId::new_random(),
            },
            action,
            resource,
            parameters,
        };
        assert!(matches!(
            evaluate(&snapshot, &request, Timestamp::from_unix_ms(2), false),
            Decision::Allow { determining_rule, .. } if determining_rule == rule
        ));
    }

    #[test]
    fn canonical_json_is_the_exact_hash_source_and_debug_hides_it() {
        let (action, principal_id, rule) = ids();
        let snapshot = parse_and_validate_snapshot(
            &snapshot_json(action, principal_id, rule),
            Timestamp::from_unix_ms(1),
        )
        .unwrap();
        let (resource, parameters, target) = snapshot
            .canonicalize(
                &fixed_action(action),
                json_request(br#"{ "input" : 12345 }"#),
            )
            .unwrap();
        let expected = serde_jcs::to_vec(&serde_json::json!({
            "target":target,"body":{"input":12345},"content_type":"application/json","headers":[],
        }))
        .unwrap();
        assert_eq!(parameters.canonical_json, expected);
        assert_eq!(
            parameters.canonical_hash,
            parameter_hash(action, &parameters.schema_id, &resource, &expected).unwrap()
        );
        assert!(!format!("{parameters:?}").contains("12345"));
        let (_, same, _) = snapshot
            .canonicalize(&fixed_action(action), json_request(br#"{"input":12345}"#))
            .unwrap();
        assert_eq!(parameters, same);
        // RawValue embeds the already-canonical value without a second renderer.
        let raw =
            serde_json::value::RawValue::from_string(String::from_utf8(expected.clone()).unwrap())
                .unwrap();
        #[derive(serde::Serialize)]
        struct Embedded {
            canonical_request: Box<serde_json::value::RawValue>,
        }
        let embedded = serde_jcs::to_vec(&Embedded {
            canonical_request: raw,
        })
        .unwrap();
        assert!(
            embedded
                .windows(expected.len())
                .any(|bytes| bytes == expected)
        );
    }

    #[test]
    fn original_json_numbers_must_survive_parse_and_jcs_exactly() {
        let (action, principal_id, rule) = ids();
        let mut source: Value =
            serde_json::from_slice(&snapshot_json(action, principal_id, rule)).unwrap();
        source["bindings"][0]["parameter_schema"] = serde_json::json!({"type":"object"});
        let snapshot = parse_and_validate_snapshot(
            &serde_json::to_vec(&source).unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .unwrap();
        let fixed = fixed_action(action);
        for number in [
            "9007199254740993",
            "-9007199254740993",
            "18446744073709551615",
            "-9223372036854775808",
            "1.0000000000000001",
            "1.234567890123456789",
            "1e-999",
            "1e-324",
            "1e-9223372036854775809",
            "4e-324",
        ] {
            let body = format!("{{\"nested\":[{{\"number\":{number}}}]}}");
            assert!(
                matches!(
                    snapshot.canonicalize(&fixed, json_request(body.as_bytes())),
                    Err(PolicyError::InvalidParameters)
                ),
                "accepted changed number {number}"
            );
        }
        for number in [
            "9007199254740992",
            "-9007199254740992",
            "1",
            "1.0",
            "1e0",
            "1E+000",
            "0.1",
            "0.1000",
            "10e-2",
            "1e20",
            "1e+21",
            "5e-324",
            "-0.0",
            "0e-999",
        ] {
            let body = format!("{{\"nested\":[{{\"number\":{number}}}]}}");
            assert!(
                snapshot
                    .canonicalize(&fixed, json_request(body.as_bytes()))
                    .is_ok(),
                "rejected preserved number {number}"
            );
        }
        let canonical = |number: &str| {
            let body = format!("{{\"number\":{number}}}");
            snapshot
                .canonicalize(&fixed, json_request(body.as_bytes()))
                .unwrap()
                .1
        };
        assert_eq!(canonical("1"), canonical("1.0"));
        assert_eq!(canonical("1"), canonical("1e0"));
        assert_eq!(canonical("0.1"), canonical("10e-2"));
        assert_eq!(canonical("0"), canonical("-0.0"));
        // Escaped quotes, escaped backslashes and unicode escapes are strings,
        // including strings used as keys; none are numeric authorization data.
        let strings=br#"{"9007199254740993":"1.0000000000000001","nested":["\"1e-999\"","\\9007199254740993","\u0031e-999"],"real":0.1}"#;
        assert!(snapshot.canonicalize(&fixed, json_request(strings)).is_ok());
        let mut attacked: Value = serde_json::from_slice(strings).unwrap();
        attacked["real"] = serde_json::json!(9007199254740993_u64);
        assert!(
            snapshot
                .canonicalize(
                    &fixed,
                    json_request(&serde_json::to_vec(&attacked).unwrap())
                )
                .is_err()
        );
    }

    #[test]
    fn duplicate_json_keys_and_schema_fail_closed() {
        let (action, principal_id, rule) = ids();
        let snapshot = parse_and_validate_snapshot(
            &snapshot_json(action, principal_id, rule),
            Timestamp::from_unix_ms(1),
        )
        .unwrap();
        assert!(
            snapshot
                .canonicalize(
                    &fixed_action(action),
                    json_request(br#"{"input":1,"input":2}"#)
                )
                .is_err()
        );
        assert!(
            snapshot
                .canonicalize(&fixed_action(action), json_request(br#"{"other":1}"#))
                .is_err()
        );

        let mut unknown: Value =
            serde_json::from_slice(&snapshot_json(action, principal_id, rule)).unwrap();
        unknown["unexpected"] = Value::Bool(true);
        assert!(
            parse_and_validate_snapshot(
                &serde_json::to_vec(&unknown).unwrap(),
                Timestamp::from_unix_ms(1)
            )
            .is_err()
        );

        let mut nested_unknown: Value =
            serde_json::from_slice(&snapshot_json(action, principal_id, rule)).unwrap();
        nested_unknown["bindings"][0]["resource"]["tenant"] = Value::String("ignored".into());
        assert!(
            parse_and_validate_snapshot(
                &serde_json::to_vec(&nested_unknown).unwrap(),
                Timestamp::from_unix_ms(1)
            )
            .is_err()
        );

        let mut unknown_scope: Value =
            serde_json::from_slice(&snapshot_json(action, principal_id, rule)).unwrap();
        unknown_scope["rules"][0]["parameters"]["future_constraint"] = Value::Bool(true);
        assert!(
            parse_and_validate_snapshot(
                &serde_json::to_vec(&unknown_scope).unwrap(),
                Timestamp::from_unix_ms(1)
            )
            .is_err()
        );
    }

    #[test]
    fn default_deny_forbid_precedence_and_expiry() {
        let (action, principal_id, permit_rule) = ids();
        let mut value: Value =
            serde_json::from_slice(&snapshot_json(action, principal_id, permit_rule)).unwrap();
        let forbid_rule = PolicyRuleId::new_random();
        value["rules"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": forbid_rule,
                "effect": "forbid",
                "principal_id": principal_id,
                "action_id": action.action_id,
                "version": action.version,
                "resource": {"type": "test.resource", "id": "one"},
                "parameters": {"kind": "any_validated"}
            }));
        let snapshot = parse_and_validate_snapshot(
            &serde_json::to_vec(&value).unwrap(),
            Timestamp::from_unix_ms(1),
        )
        .unwrap();
        let (resource, parameters, _) = snapshot
            .canonicalize(&fixed_action(action), json_request(br#"{"input":1}"#))
            .unwrap();
        let mut request = AuthorizationRequest {
            principal: rekey_domain::authorization::Principal {
                tenant_id: rekey_domain::ids::TenantId::new_random(),
                principal_id,
                session_id: rekey_domain::ids::SessionId::new_random(),
            },
            action,
            resource,
            parameters,
        };
        assert!(matches!(
            evaluate(&snapshot, &request, Timestamp::from_unix_ms(2), false),
            Decision::Deny {
                reason: DenyReason::ExplicitForbid,
                determining_rule: Some(rule),
                ..
            } if rule == forbid_rule
        ));
        request.principal.principal_id = PrincipalId::new_random();
        assert!(matches!(
            evaluate(&snapshot, &request, Timestamp::from_unix_ms(2), false),
            Decision::Deny {
                reason: DenyReason::NoMatchingPermit,
                ..
            }
        ));
        assert!(matches!(
            evaluate(&snapshot, &request, Timestamp::from_unix_ms(10_000), false,),
            Decision::Deny {
                reason: DenyReason::SnapshotExpired,
                ..
            }
        ));
        assert!(matches!(
            evaluate(&snapshot, &request, Timestamp::from_unix_ms(2), true),
            Decision::Deny {
                reason: DenyReason::SnapshotExpired,
                ..
            }
        ));
    }
}
