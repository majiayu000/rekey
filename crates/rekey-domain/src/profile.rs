//! Signed, pure Profile declarations. Stored Action provenance is checked at activation.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::capability::{ActionVersionRef, SESSION_MAX_USES_MAX, SESSION_TTL_MAX_MS};
use crate::ids::{ActionId, PrincipalId};
use crate::{DomainError, template};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    pub name: String,
    pub principal_id: PrincipalId,
    pub grants: Vec<ProfileGrant>,
    pub session: ProfileSession,
    pub confirm_each_run: bool,
    pub isolation: ProfileIsolation,
    pub egress: ProfileEgress,
    pub llm_limits: Vec<ProfileLlmLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileGrant {
    pub instance: String,
    pub capabilities: Vec<ProfileCapabilityGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCapabilityGrant {
    pub capability: String,
    pub rule: ProfileRule,
    #[serde(deserialize_with = "action_refs")]
    pub actions: Vec<ActionVersionRef>,
}

/// Signed authoring choice for personal policy generation. Execution still uses
/// the snapshot's rules and their existing deny/approval precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileRule {
    TemplateDefault,
    Allow,
    RequireApproval,
}

// Keep the shared ActionVersionRef API while closing this new signed wire shape.
fn action_refs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ActionVersionRef>, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        action_id: ActionId,
        version: u64,
    }
    Ok(Vec::<Reference>::deserialize(deserializer)?
        .into_iter()
        .map(|r| ActionVersionRef {
            action_id: r.action_id,
            version: r.version,
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSession {
    pub ttl_ms: i64,
    pub max_uses: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileIsolation {
    None,
    Seatbelt,
    Netns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileEgress {
    Allow,
    DenyOther,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileLlmLimit {
    pub instance: String,
    pub models: Vec<String>,
    pub max_output_tokens_per_request: u32,
    pub max_requests_per_day: u64,
    pub max_output_tokens_per_day: u64,
}

fn routable_slug(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl AgentProfile {
    /// Local declaration invariants only. The policy parser checks bindings,
    /// rules and consistency with other Profiles at its trusted boundary.
    pub fn validate(&self) -> Result<(), DomainError> {
        let invalid = || DomainError::InvalidAuthorization("invalid agent profile".into());
        if !routable_slug(&self.name)
            || self.grants.is_empty()
            || self.session.ttl_ms <= 0
            || self.session.ttl_ms > SESSION_TTL_MAX_MS
            || self.session.max_uses == 0
            || self.session.max_uses > SESSION_MAX_USES_MAX
        {
            return Err(invalid());
        }
        let mut instances = BTreeSet::new();
        let mut actions = BTreeSet::new();
        for grant in &self.grants {
            if !routable_slug(&grant.instance)
                || !instances.insert(grant.instance.as_str())
                || grant.capabilities.is_empty()
            {
                return Err(invalid());
            }
            let mut capabilities = BTreeSet::new();
            for capability in &grant.capabilities {
                if !template::slug(&capability.capability, 64)
                    || !capabilities.insert(capability.capability.as_str())
                    || capability.actions.is_empty()
                    || capability
                        .actions
                        .iter()
                        .any(|r| r.version == 0 || !actions.insert(*r))
                {
                    return Err(invalid());
                }
            }
        }
        let mut limited = BTreeSet::new();
        for limit in &self.llm_limits {
            let models: BTreeSet<_> = limit.models.iter().collect();
            if !instances.contains(limit.instance.as_str())
                || !limited.insert(limit.instance.as_str())
                || models.is_empty()
                || models.len() != limit.models.len()
                || models.iter().any(|m| {
                    m.is_empty() || m.trim() != m.as_str() || m.chars().any(char::is_control)
                })
                || limit.max_output_tokens_per_request == 0
                || limit.max_requests_per_day == 0
                || limit.max_requests_per_day > i64::MAX as u64
                || limit.max_output_tokens_per_day == 0
                || limit.max_output_tokens_per_day > i64::MAX as u64
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub fn action_refs(&self) -> impl Iterator<Item = ActionVersionRef> + '_ {
        self.grants
            .iter()
            .flat_map(|g| &g.capabilities)
            .flat_map(|c| c.actions.iter().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> AgentProfile {
        AgentProfile {
            name: "claude-code".into(),
            principal_id: PrincipalId::new_random(),
            grants: vec![ProfileGrant {
                instance: "anthropic".into(),
                capabilities: vec![ProfileCapabilityGrant {
                    capability: "messages".into(),
                    rule: ProfileRule::TemplateDefault,
                    actions: vec![ActionVersionRef {
                        action_id: ActionId::new_random(),
                        version: 1,
                    }],
                }],
            }],
            session: ProfileSession {
                ttl_ms: SESSION_TTL_MAX_MS,
                max_uses: SESSION_MAX_USES_MAX,
            },
            confirm_each_run: false,
            isolation: ProfileIsolation::None,
            egress: ProfileEgress::Allow,
            llm_limits: vec![ProfileLlmLimit {
                instance: "anthropic".into(),
                models: vec!["model-1".into()],
                max_output_tokens_per_request: 4096,
                max_requests_per_day: 2000,
                max_output_tokens_per_day: 2_000_000,
            }],
        }
    }

    #[test]
    fn profile_roundtrip_and_closed_nested_shape() {
        let p = profile();
        p.validate().unwrap();
        let value = serde_json::to_value(&p).unwrap();
        assert_eq!(
            serde_json::from_value::<AgentProfile>(value.clone()).unwrap(),
            p
        );
        for pointer in [
            "",
            "/session",
            "/grants/0",
            "/grants/0/capabilities/0",
            "/grants/0/capabilities/0/actions/0",
            "/llm_limits/0",
        ] {
            let mut malformed = value.clone();
            malformed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), true.into());
            assert!(
                serde_json::from_value::<AgentProfile>(malformed).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn rule_is_required_closed_and_roundtrips_each_choice() {
        let mut p = profile();
        for (rule, wire) in [
            (ProfileRule::TemplateDefault, "template-default"),
            (ProfileRule::Allow, "allow"),
            (ProfileRule::RequireApproval, "require-approval"),
        ] {
            p.grants[0].capabilities[0].rule = rule;
            let value = serde_json::to_value(&p).unwrap();
            assert_eq!(value["grants"][0]["capabilities"][0]["rule"], wire);
            assert_eq!(serde_json::from_value::<AgentProfile>(value).unwrap(), p);
        }
        let value = serde_json::to_value(p).unwrap();
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!("permit"),
            serde_json::json!({"kind":"allow"}),
        ] {
            let mut malformed = value.clone();
            malformed["grants"][0]["capabilities"][0]["rule"] = invalid;
            assert!(serde_json::from_value::<AgentProfile>(malformed).is_err());
        }
        let mut missing = value;
        missing["grants"][0]["capabilities"][0]
            .as_object_mut()
            .unwrap()
            .remove("rule");
        assert!(serde_json::from_value::<AgentProfile>(missing).is_err());
    }

    #[test]
    fn session_bounds_and_routable_slugs() {
        for ttl in [0, -1, SESSION_TTL_MAX_MS + 1] {
            let mut p = profile();
            p.session.ttl_ms = ttl;
            assert!(p.validate().is_err());
        }
        for uses in [0, SESSION_MAX_USES_MAX + 1] {
            let mut p = profile();
            p.session.max_uses = uses;
            assert!(p.validate().is_err());
        }
        for slug in [
            "", "../x", "x/y", "x%2fy", "x?y", "x#y", ".", "..", "x y", "中文", "x.y", "x-", "x_",
            "-x", "_x",
        ] {
            let mut p = profile();
            p.name = slug.into();
            assert!(p.validate().is_err());
            let mut p = profile();
            p.grants[0].instance = slug.into();
            assert!(p.validate().is_err());
        }
        let mut p = profile();
        p.name = "x".repeat(65);
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_empty_duplicate_grants_and_unbounded_llm_limits() {
        let valid = profile();
        let mut cases = Vec::new();
        let mut p = valid.clone();
        p.grants.clear();
        cases.push(p);
        let mut p = valid.clone();
        p.grants.push(p.grants[0].clone());
        cases.push(p);
        let mut p = valid.clone();
        p.grants[0].capabilities.clear();
        cases.push(p);
        let mut p = valid.clone();
        let c = p.grants[0].capabilities[0].clone();
        p.grants[0].capabilities.push(c);
        cases.push(p);
        let mut p = valid.clone();
        p.grants[0].capabilities[0].actions.clear();
        cases.push(p);
        let mut p = valid.clone();
        let r = p.grants[0].capabilities[0].actions[0];
        p.grants[0].capabilities[0].actions.push(r);
        cases.push(p);
        let mut p = valid.clone();
        p.grants[0].capabilities[0].actions[0].version = 0;
        cases.push(p);
        let mut p = valid.clone();
        p.llm_limits[0].models.clear();
        cases.push(p);
        let mut p = valid.clone();
        p.llm_limits[0].models.push("model-1".into());
        cases.push(p);
        let mut p = valid.clone();
        p.llm_limits[0].instance = "absent".into();
        cases.push(p);
        let mut p = valid.clone();
        p.llm_limits.push(p.llm_limits[0].clone());
        cases.push(p);
        let mut p = valid.clone();
        p.llm_limits[0].max_output_tokens_per_request = 0;
        cases.push(p);
        for value in [0, i64::MAX as u64 + 1] {
            let mut p = valid.clone();
            p.llm_limits[0].max_requests_per_day = value;
            cases.push(p);
            let mut p = valid.clone();
            p.llm_limits[0].max_output_tokens_per_day = value;
            cases.push(p);
        }
        for p in cases {
            assert!(p.validate().is_err(), "{p:?}");
        }
        let mut non_llm = valid;
        non_llm.llm_limits.clear();
        non_llm.validate().unwrap();
    }
}
