//! Pure full-replacement drafts from Actions authenticated by the Authority.
//! This module neither authenticates stored Action rows nor performs signing.

use std::collections::BTreeMap;

use rekey_domain::Timestamp;
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::authorization::{
    ApprovalMode, ApprovalRequirement, ApproverSpec, PolicyTrustAlgorithm, PolicyVersion,
    ResourceRef, SchemaId,
};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::PolicyRuleId;
use rekey_domain::profile::{AgentProfile, ProfileRule};
use rekey_domain::template::DefaultRule;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ActionBinding, ParameterScope, PolicyError, PolicyRule, PolicySnapshot, RuleEffect,
    SNAPSHOT_FORMAT_VERSION, SNAPSHOT_MAX_BYTES, ValidatedPolicyBundle, ValidatedPolicyTrust,
    parse_and_validate_snapshot,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyFieldChange {
    pub field: &'static str,
    pub before: Value,
    pub after: Value,
}

pub struct PersonalPolicyDraft {
    canonical_snapshot: Vec<u8>,
    sign_bytes: Vec<u8>,
    diff: Vec<PolicyFieldChange>,
}

impl PersonalPolicyDraft {
    pub fn canonical_snapshot(&self) -> &[u8] {
        &self.canonical_snapshot
    }

    pub fn sign_bytes(&self) -> &[u8] {
        &self.sign_bytes
    }

    pub fn diff(&self) -> &[PolicyFieldChange] {
        &self.diff
    }
}

/// `previous` is the current verified bundle under the installed `trust`.
/// Empty selection deliberately removes all previous authorizations. Action
/// targets remain in their authenticated rows; only their schema is copied here.
pub fn generate_personal_draft(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    actions: &[FixedHttpAction],
    profiles: &[AgentProfile],
    expires_at_ms: i64,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    if trust.key().algorithm() != PolicyTrustAlgorithm::SecureEnclaveP256 {
        return Err(PolicyError::Invalid);
    }
    if previous.is_some_and(|bundle| bundle.signer_id() != trust.signer_id()) {
        return Err(PolicyError::InvalidSignature);
    }
    let next = previous
        .map_or(0, |bundle| bundle.snapshot().version().get())
        .checked_add(1)
        .ok_or(PolicyError::Invalid)?;
    let version = PolicyVersion::new(next).map_err(|_| PolicyError::Invalid)?;
    let mut grants = BTreeMap::<ActionVersionRef, BTreeMap<_, ProfileRule>>::new();
    for profile in profiles {
        profile.validate().map_err(|_| PolicyError::Invalid)?;
        for grant in &profile.grants {
            for capability in &grant.capabilities {
                for reference in &capability.actions {
                    if let Some(previous) = grants
                        .entry(*reference)
                        .or_default()
                        .insert(profile.principal_id, capability.rule)
                        && previous != capability.rule
                    {
                        return Err(PolicyError::Invalid);
                    }
                }
            }
        }
    }
    let mut selected: Vec<_> = actions.iter().collect();
    selected.sort_by_key(|action| (action.id, action.version));
    if selected.len() != grants.len()
        || selected
            .windows(2)
            .any(|pair| (pair[0].id, pair[0].version) == (pair[1].id, pair[1].version))
    {
        return Err(PolicyError::Invalid);
    }
    let mut bindings = Vec::with_capacity(selected.len());
    let mut rules = Vec::with_capacity(selected.len());
    for action in selected {
        let principals = grants
            .get(&ActionVersionRef {
                action_id: action.id,
                version: action.version,
            })
            .ok_or(PolicyError::Invalid)?;
        action.validate().map_err(|_| PolicyError::Invalid)?;
        if !action.enabled {
            return Err(PolicyError::Invalid);
        }
        let ActionTarget::Template {
            body_schema,
            default_policy,
            ..
        } = &action.target
        else {
            return Err(PolicyError::Invalid);
        };
        let resource = ResourceRef::new("action".to_owned(), action.id.to_string())
            .map_err(|_| PolicyError::Invalid)?;
        bindings.push(ActionBinding {
            action_id: action.id,
            version: action.version,
            resource: resource.clone(),
            parameter_schema_id: SchemaId::new(format!("action/{}/{}", action.id, action.version))
                .map_err(|_| PolicyError::Invalid)?,
            parameter_schema: body_schema.clone().unwrap_or(Value::Bool(true)),
        });
        for (principal_id, choice) in principals {
            let rule = match choice {
                ProfileRule::TemplateDefault => default_policy.rule,
                ProfileRule::Allow => DefaultRule::Allow,
                ProfileRule::RequireApproval => DefaultRule::RequireApproval,
            };
            let (effect, approver, approval) = match rule {
                DefaultRule::Allow => (RuleEffect::Permit, None, None),
                DefaultRule::RequireApproval => (
                    RuleEffect::RequireApproval,
                    Some(ApproverSpec::LocalPresence {}),
                    Some(ApprovalRequirement {
                        mode: ApprovalMode::OneTime,
                        max_uses: 1,
                        max_window_ms: None,
                    }),
                ),
            };
            let mut id = Sha256::new();
            id.update(b"RKPERSONALRULE\0\x01");
            id.update(principal_id.as_bytes());
            id.update(action.id.as_bytes());
            id.update(action.version.to_be_bytes());
            let mut id_bytes = [0; 16];
            id_bytes.copy_from_slice(&id.finalize()[..16]);
            rules.push(PolicyRule {
                id: PolicyRuleId::from_random_bytes(id_bytes),
                effect,
                principal_id: *principal_id,
                action_id: action.id,
                version: action.version,
                resource: resource.clone(),
                parameters: ParameterScope::AnyValidated {},
                approver: approver.clone(),
                approval: approval.clone(),
            });
        }
    }
    let snapshot = PolicySnapshot {
        format_version: SNAPSHOT_FORMAT_VERSION,
        connections: Vec::new(),
        ssh_keys: Vec::new(),
        derived_credentials: Vec::new(),
        version,
        expires_at_ms,
        approvers: Vec::new(),
        workload_identities: Vec::new(),
        profiles: profiles.to_vec(),
        bindings,
        rules,
    };
    finish_draft(trust, previous, snapshot, now)
}

/// Complete signed replacement of personal Connection rules. No Action rows
/// or Profiles are needed for local caller authorization.
pub fn generate_connection_draft(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    connections: &[rekey_domain::connection::Connection],
    expires_at_ms: i64,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    if trust.key().algorithm() != PolicyTrustAlgorithm::SecureEnclaveP256 {
        return Err(PolicyError::Invalid);
    }
    if previous.is_some_and(|bundle| bundle.signer_id() != trust.signer_id()) {
        return Err(PolicyError::InvalidSignature);
    }
    generate_connection_draft_with_ssh(trust, previous, connections, None, expires_at_ms, now)
}

pub fn generate_connection_draft_with_ssh(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    connections: &[rekey_domain::connection::Connection],
    ssh_keys: Option<&[rekey_domain::connection::SshKeyConnection]>,
    expires_at_ms: i64,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    generate_connection_draft_with_grants(
        trust,
        previous,
        connections,
        ssh_keys,
        None,
        expires_at_ms,
        now,
    )
}

/// Omitted optional editor sections retain the authenticated previous grants;
/// explicit empty arrays revoke that section in the new signed snapshot.
pub fn generate_connection_draft_with_grants(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    connections: &[rekey_domain::connection::Connection],
    ssh_keys: Option<&[rekey_domain::connection::SshKeyConnection]>,
    derived_credentials: Option<&[rekey_domain::connection::DerivedCredentialConnection]>,
    expires_at_ms: i64,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    if trust.key().algorithm() != PolicyTrustAlgorithm::SecureEnclaveP256 {
        return Err(PolicyError::Invalid);
    }
    if previous.is_some_and(|bundle| bundle.signer_id() != trust.signer_id()) {
        return Err(PolicyError::InvalidSignature);
    }
    let next = previous
        .map_or(0, |bundle| bundle.snapshot().version().get())
        .checked_add(1)
        .ok_or(PolicyError::Invalid)?;
    let mut connections = connections.to_vec();
    connections.sort_by(|a, b| a.name.cmp(&b.name));
    finish_draft(
        trust,
        previous,
        PolicySnapshot {
            format_version: SNAPSHOT_FORMAT_VERSION,
            version: PolicyVersion::new(next).map_err(|_| PolicyError::Invalid)?,
            expires_at_ms,
            ssh_keys: ssh_keys.map_or_else(
                || previous.map_or_else(Vec::new, |bundle| bundle.snapshot().ssh_keys().to_vec()),
                |keys| keys.to_vec(),
            ),
            derived_credentials: derived_credentials.map_or_else(
                || {
                    previous.map_or_else(Vec::new, |bundle| {
                        bundle.snapshot().derived_credentials().to_vec()
                    })
                },
                |connections| connections.to_vec(),
            ),
            connections,
            approvers: Vec::new(),
            workload_identities: Vec::new(),
            profiles: Vec::new(),
            bindings: Vec::new(),
            rules: Vec::new(),
        },
        now,
    )
}

fn finish_draft(
    trust: &ValidatedPolicyTrust,
    previous: Option<&ValidatedPolicyBundle>,
    snapshot: PolicySnapshot,
    now: Timestamp,
) -> Result<PersonalPolicyDraft, PolicyError> {
    let next = snapshot.version.get();
    let expires_at_ms = snapshot.expires_at_ms;
    let canonical_snapshot = serde_jcs::to_vec(&snapshot).map_err(|_| PolicyError::Malformed)?;
    parse_and_validate_snapshot(&canonical_snapshot, now)?;
    let after: Value =
        serde_json::from_slice(&canonical_snapshot).map_err(|_| PolicyError::Malformed)?;
    // JCS uses IEEE-754 number formatting. Never silently round an authority
    // version or expiry while producing the bytes the user will actually sign.
    if after["version"].as_u64() != Some(next)
        || after["expires_at_ms"].as_i64() != Some(expires_at_ms)
        || serde_json::from_value::<Vec<AgentProfile>>(after["profiles"].clone())
            .map_err(|_| PolicyError::Invalid)?
            != snapshot.profiles
        || serde_json::from_value::<Vec<rekey_domain::connection::DerivedCredentialConnection>>(
            after["derived_credentials"].clone(),
        )
        .map_err(|_| PolicyError::Invalid)?
            != snapshot.derived_credentials
        || after["bindings"]
            .as_array()
            .ok_or(PolicyError::Malformed)?
            .iter()
            .zip(&snapshot.bindings)
            .any(|(encoded, binding)| encoded["version"].as_u64() != Some(binding.version))
    {
        return Err(PolicyError::Invalid);
    }
    let unsigned = json!({"format_version": 1, "signer_id": trust.signer_id(), "snapshot": after});
    let canonical_envelope = serde_jcs::to_vec(&unsigned).map_err(|_| PolicyError::Malformed)?;
    // P-256 DER is at most 72 bytes, or 96 base64url characters. Reserve the
    // entire signature field so a valid signature cannot exceed the bundle cap.
    if canonical_envelope.len() > SNAPSHOT_MAX_BYTES - b",\"signature\":\"\"".len() - 96 {
        return Err(PolicyError::TooLarge);
    }
    let mut sign_bytes = b"RKPOLICY\0\x01".to_vec();
    sign_bytes.extend_from_slice(&canonical_envelope);
    let before = match previous {
        Some(bundle) => {
            let envelope: Value = serde_json::from_slice(bundle.canonical_bytes())
                .map_err(|_| PolicyError::Malformed)?;
            envelope
                .get("snapshot")
                .cloned()
                .ok_or(PolicyError::Malformed)?
        }
        None => Value::Null,
    };
    let mut diff = Vec::new();
    for field in [
        "version",
        "expires_at_ms",
        "approvers",
        "workload_identities",
        "profiles",
        "connections",
        "ssh_keys",
        "derived_credentials",
        "bindings",
        "rules",
    ] {
        let old = before.get(field).cloned().unwrap_or(Value::Null);
        let new = after.get(field).cloned().ok_or(PolicyError::Malformed)?;
        if old != new {
            diff.push(PolicyFieldChange {
                field,
                before: old,
                after: new,
            });
        }
    }
    if serde_json::to_vec(&diff)
        .map_err(|_| PolicyError::Malformed)?
        .len()
        > SNAPSHOT_MAX_BYTES
    {
        return Err(PolicyError::TooLarge);
    }
    Ok(PersonalPolicyDraft {
        canonical_snapshot,
        sign_bytes,
        diff,
    })
}
