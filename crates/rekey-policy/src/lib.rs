use std::collections::{BTreeMap, BTreeSet};

use data_encoding::HEXLOWER;
use jsonschema::{Draft, Validator};
use rekey_domain::Timestamp;
use rekey_domain::authorization::{
    AuthorizationRequest, CanonicalParameters, Decision, DenyReason, PolicyVersion, ResourceRef,
    SchemaId,
};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ActionId, PolicyRuleId, PrincipalId};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;
pub const SNAPSHOT_MAX_BYTES: usize = 64 * 1024;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshot {
    pub format_version: u32,
    pub version: PolicyVersion,
    pub expires_at_ms: i64,
    pub bindings: Vec<ActionBinding>,
    pub rules: Vec<PolicyRule>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleEffect {
    Permit,
    Forbid,
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

    pub fn binding(&self, action: ActionVersionRef) -> Option<&ActionBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.definition.action() == action)
            .map(|binding| &binding.definition)
    }

    pub fn canonicalize(
        &self,
        action: ActionVersionRef,
        content_type: Option<&str>,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(ResourceRef, CanonicalParameters), PolicyError> {
        let binding = self
            .bindings
            .iter()
            .find(|binding| binding.definition.action() == action)
            .ok_or(PolicyError::InvalidParameters)?;
        let normalized_content_type = normalize_content_type(content_type, body)?;
        let value = if body.is_empty() {
            Value::Null
        } else {
            parse_unique_json(body)?
        };
        if !binding.validator.is_valid(&value) {
            return Err(PolicyError::InvalidParameters);
        }
        let mut normalized_headers = Vec::with_capacity(headers.len());
        let mut seen = BTreeSet::new();
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if !seen.insert(lower.clone()) {
                return Err(PolicyError::InvalidParameters);
            }
            normalized_headers.push((lower, value.clone()));
        }
        normalized_headers.sort();
        let envelope = serde_json::json!({
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
            },
        ))
    }
}

pub fn parse_and_validate_snapshot(
    bytes: &[u8],
    now: Timestamp,
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
    if snapshot.expires_at_ms <= now.as_unix_ms() {
        return Err(PolicyError::Expired);
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
            let decoded = HEXLOWER
                .decode(sha256.as_bytes())
                .map_err(|_| PolicyError::Invalid)?;
            if decoded.len() != 32 || HEXLOWER.encode(&decoded) != *sha256 {
                return Err(PolicyError::Invalid);
            }
        }
    }

    let canonical = serde_jcs::to_vec(&value).map_err(|_| PolicyError::Malformed)?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(canonical));
    Ok(ValidatedSnapshot {
        version: snapshot.version,
        expires_at_ms: snapshot.expires_at_ms,
        digest,
        bindings: compiled,
        rules: snapshot.rules,
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
        }
    }
    if let Some(rule) = forbid {
        deny(snapshot, DenyReason::ExplicitForbid, Some(rule))
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

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(|number| UniqueValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = access.next_entry::<String, UniqueValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(UniqueValue(Value::Object(Map::from_iter(values))))
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, PolicyError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer).map_err(|_| PolicyError::Malformed)?;
    deserializer.end().map_err(|_| PolicyError::Malformed)?;
    Ok(value.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::ids::{ActionId, PrincipalId};

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
            "format_version": 1,
            "version": 1,
            "expires_at_ms": 10_000,
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
        let (resource, parameters) = snapshot
            .canonicalize(action, Some("application/json"), &[], br#"{"input":1}"#)
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
                    action,
                    Some("application/json"),
                    &[],
                    br#"{"input":1,"input":2}"#
                )
                .is_err()
        );
        assert!(
            snapshot
                .canonicalize(action, Some("application/json"), &[], br#"{"other":1}"#)
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
        let (resource, parameters) = snapshot
            .canonicalize(action, Some("application/json"), &[], br#"{"input":1}"#)
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
