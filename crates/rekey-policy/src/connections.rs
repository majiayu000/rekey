//! Local authorization from a signed Connection, with one request boundary.
use std::collections::{BTreeMap, BTreeSet};

use rekey_domain::Timestamp;
use rekey_domain::action::{
    ActionName, ActionTarget, ExactPath, FixedHttpAction, FixedMethod, HeaderName, RequestPolicy,
    ResponsePolicy,
};
use rekey_domain::authorization::{CanonicalParameters, ResourceRef, SchemaId};
use rekey_domain::connection::{
    Connection, ConnectionRule, MethodClass, MethodSelector, ReadSemantics, RuleEffect,
    query_key_valid, validate_request_path,
};
use rekey_domain::ids::{ActionId, PolicyRuleId};
use rekey_domain::ipc::CallMeta;
use rekey_domain::template::{RenderedTarget, slug};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{PolicyError, ValidatedSnapshot, json::parse_unique_json};

/// Fully normalized admission result. Contains no Secret; body/input values are
/// intentionally omitted from Debug and must not be copied into audit records.
pub struct ConnectionAuthorization {
    pub connection: Connection,
    pub action: FixedHttpAction,
    pub target: RenderedTarget,
    pub parameters: CanonicalParameters,
    pub resource: ResourceRef,
    pub effect: RuleEffect,
    pub rule_id: Option<PolicyRuleId>,
    pub method_class: MethodClass,
    pub normalized_path: String,
    pub request_body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub operation: Option<String>,
    pub model: Option<String>,
    pub generation_max_output: Option<u64>,
    pub streaming: bool,
}

/// Resolve one signed Connection and normalize both generic and named calls.
pub fn evaluate_connection(
    snapshot: &ValidatedSnapshot,
    request: &CallMeta,
    body: &[u8],
    caller: &str,
    now: Timestamp,
) -> Result<ConnectionAuthorization, PolicyError> {
    if snapshot.expires_at_ms() <= now.as_unix_ms() {
        return Err(PolicyError::Expired);
    }
    let mut matches = snapshot.connections().iter().filter(|c| {
        c.enabled
            && (request.connection.is_empty() || c.name == request.connection)
            && request
                .operation
                .as_ref()
                .is_none_or(|name| c.operations.iter().any(|o| &o.name == name))
    });
    let connection = matches.next().ok_or(PolicyError::NotConfigured)?;
    if matches.next().is_some() {
        return Err(PolicyError::InvalidParameters);
    }
    let (method, path, mut body, operation) = normalize_call(connection, request, body)?;
    validate_request_path(&path).map_err(|_| PolicyError::InvalidParameters)?;
    if let Some(oauth) = &connection.oauth {
        let declared = connection
            .operations
            .iter()
            .find(|op| op.method == method && operation_path_matches(&op.path, &path))
            .ok_or(PolicyError::NotConfigured)?;
        if !crate::presets::oauth_required_scopes(&connection.preset, &declared.name)?
            .is_subset(&oauth.scopes)
        {
            return Err(PolicyError::NotConfigured);
        }
    }
    if request.query.iter().any(|(k, v)| {
        !query_key_valid(k)
            || v.len() > 1024
            || connection
                .query_allowlist
                .as_ref()
                .is_some_and(|keys| !keys.contains(k))
    }) {
        return Err(PolicyError::InvalidParameters);
    }
    let mut names = BTreeSet::new();
    let mut headers = BTreeMap::new();
    for (name, value) in &request.headers {
        let name = HeaderName::new(name).map_err(|_| PolicyError::InvalidParameters)?;
        if !connection.allowed_headers.contains(&name)
            || !names.insert(name.clone())
            || value.len() > 8192
            || !value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        {
            return Err(PolicyError::InvalidParameters);
        }
        headers.insert(name, value.clone());
    }
    headers.extend(connection.fixed_headers.clone());
    let headers: Vec<_> = headers
        .into_iter()
        .map(|(k, v)| (k.as_str().to_string(), v))
        .collect();
    let matching_operation = connection.operations.iter().find(|o| {
        o.method == method
            && (o.path == path
                || connection.preset == "github-git" && operation_path_matches(&o.path, &path))
    });
    if connection.preset == "github-git" && matching_operation.is_none() {
        return Err(PolicyError::NotConfigured);
    }
    let semantics = operation
        .as_ref()
        .and_then(|name| connection.operations.iter().find(|o| &o.name == name))
        .or(matching_operation)
        .and_then(|o| o.read_semantics.as_ref());
    let class = match method {
        FixedMethod::Get | FixedMethod::Head => MethodClass::Read,
        FixedMethod::Post if matches!(semantics, Some(ReadSemantics::Fixed)) => MethodClass::Read,
        FixedMethod::Post
            if matches!(semantics, Some(ReadSemantics::GraphqlQuery)) && graphql_read(&body) =>
        {
            MethodClass::Read
        }
        _ => MethodClass::Write,
    };
    let (model, generation_max_output, streaming) =
        normalize_llm(connection, &path, method, &mut body)?;
    if body.len() > connection.limits.max_request_bytes as usize {
        return Err(PolicyError::InvalidParameters);
    }
    let (effect, rule_id, normalized_path) = decide(connection, method, class, &path, caller);
    let exact = ExactPath::parse(&path).map_err(|_| PolicyError::InvalidParameters)?;
    let target = RenderedTarget {
        path: exact.clone(),
        params: BTreeMap::new(),
        query: request.query.clone(),
    };
    let mut id = Sha256::new();
    id.update(b"RKCONNECTIONACTION\0\x01");
    id.update(snapshot.digest());
    id.update(connection.name.as_bytes());
    let digest = id.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    let action = FixedHttpAction {
        native_plugin: None,
        text_stream: None,
        id: ActionId::from_random_bytes(bytes),
        name: ActionName::new(&connection.name).map_err(|_| PolicyError::Invalid)?,
        version: snapshot.version().get(),
        enabled: true,
        credential_id: connection.credential_id,
        origin: connection.origin.clone(),
        method,
        target: ActionTarget::Fixed { path: exact },
        auth: connection.auth.clone(),
        timeout_ms: 120_000,
        request_policy: RequestPolicy {
            max_body_bytes: connection.limits.max_request_bytes,
            allowed_extra_headers: connection.allowed_headers.clone(),
        },
        response_policy: ResponsePolicy {
            max_body_bytes: connection.limits.max_response_bytes,
            allowed_headers: connection.allowed_response_headers.clone(),
        },
    };
    let (canonical_body, body_encoding) = match std::str::from_utf8(&body) {
        Ok(text) => (text.to_owned(), "text"),
        Err(_) => (data_encoding::BASE64.encode(&body), "base64"),
    };
    let canonical=serde_jcs::to_vec(&json!({"policy_sha256":data_encoding::HEXLOWER.encode(&snapshot.digest()),"connection":connection.name,"origin":connection.origin,"method":method,"path":path,"query":request.query,"headers":headers,"body":canonical_body,"body_encoding":body_encoding})).map_err(|_|PolicyError::InvalidParameters)?;
    let mut hash = Sha256::new();
    hash.update(b"RKLOCALCALL\0\x01");
    hash.update(&canonical);
    let canonical_hash = hash.finalize().into();
    Ok(ConnectionAuthorization {
        connection: connection.clone(),
        action,
        target,
        parameters: CanonicalParameters {
            schema_id: SchemaId::new("rekey.connection/v1".into())
                .map_err(|_| PolicyError::Invalid)?,
            canonical_hash,
            canonical_json: canonical,
        },
        resource: ResourceRef::new("connection".into(), connection.name.clone())
            .map_err(|_| PolicyError::Invalid)?,
        effect,
        rule_id,
        method_class: class,
        normalized_path,
        request_body: body,
        headers,
        operation,
        model,
        generation_max_output,
        streaming,
    })
}

fn operation_path_matches(pattern: &str, path: &str) -> bool {
    let declared: Vec<_> = pattern.split('/').collect();
    let actual: Vec<_> = path.split('/').collect();
    declared.len() == actual.len()
        && declared
            .iter()
            .zip(actual)
            .all(|(a, b)| *a == b || a.starts_with('{') && a.ends_with('}'))
}

fn normalize_call(
    connection: &Connection,
    request: &CallMeta,
    body: &[u8],
) -> Result<(FixedMethod, String, Vec<u8>, Option<String>), PolicyError> {
    let Some(name) = &request.operation else {
        if !request.args.is_empty() {
            return Err(PolicyError::InvalidParameters);
        }
        return Ok((
            request.method.ok_or(PolicyError::InvalidParameters)?,
            request.path.clone().ok_or(PolicyError::InvalidParameters)?,
            body.to_vec(),
            None,
        ));
    };
    if request.method.is_some() || request.path.is_some() {
        return Err(PolicyError::InvalidParameters);
    }
    let operation = connection
        .operations
        .iter()
        .find(|o| &o.name == name)
        .ok_or(PolicyError::NotConfigured)?;
    let mut args = serde_json::Map::new();
    for (key, value) in &request.args {
        let schema = operation
            .parameters
            .get("properties")
            .and_then(|p| p.get(key))
            .ok_or(PolicyError::InvalidParameters)?;
        let value = match schema.get("type").and_then(Value::as_str) {
            Some("integer" | "number" | "boolean" | "object" | "array") => {
                crate::ensure_json_number_fidelity(value.as_bytes())?;
                parse_unique_json(value.as_bytes()).map_err(|_| PolicyError::InvalidParameters)?
            }
            _ => Value::String(value.clone()),
        };
        args.insert(key.clone(), value);
    }
    let validator = jsonschema::options()
        .build(&operation.parameters)
        .map_err(|_| PolicyError::Invalid)?;
    if !validator.is_valid(&Value::Object(args.clone())) {
        return Err(PolicyError::InvalidParameters);
    }
    let mut parts = Vec::new();
    for part in operation.path[1..].split('/') {
        if let Some(key) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
            let value = args.remove(key).ok_or(PolicyError::InvalidParameters)?;
            let value = match value {
                Value::String(v) => v,
                Value::Number(v) => v.to_string(),
                _ => return Err(PolicyError::InvalidParameters),
            };
            if !slug(&value, 100) {
                return Err(PolicyError::InvalidParameters);
            }
            parts.push(value);
        } else {
            parts.push(part.to_owned());
        }
    }
    let path = if operation.path == "/" {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    };
    let mut output = body.to_vec();
    if !args.is_empty() {
        if matches!(operation.method, FixedMethod::Get | FixedMethod::Head) {
            return Err(PolicyError::InvalidParameters);
        }
        if !body.is_empty() {
            crate::ensure_json_number_fidelity(body)?;
            let Value::Object(existing) =
                parse_unique_json(body).map_err(|_| PolicyError::InvalidParameters)?
            else {
                return Err(PolicyError::InvalidParameters);
            };
            for (key, value) in existing {
                if args.insert(key, value).is_some() {
                    return Err(PolicyError::InvalidParameters);
                }
            }
        }
        output = serde_jcs::to_vec(&args).map_err(|_| PolicyError::InvalidParameters)?;
    }
    Ok((operation.method, path, output, Some(name.clone())))
}

fn normalize_llm(
    connection: &Connection,
    path: &str,
    method: FixedMethod,
    body: &mut Vec<u8>,
) -> Result<(Option<String>, Option<u64>, bool), PolicyError> {
    let Some(limits) = &connection.llm else {
        return Ok((None, None, false));
    };
    if method != FixedMethod::Post {
        return Ok((None, None, false));
    }
    let protocol = match path {
        "/v1/messages" | "/api/anthropic/v1/messages" => {
            crate::ProfileLlmProtocol::AnthropicMessages
        }
        "/v1/messages/count_tokens" => crate::ProfileLlmProtocol::CountTokens,
        "/v1/chat/completions" => crate::ProfileLlmProtocol::OpenAiChat,
        "/v1/responses" | "/api/v1/responses" => crate::ProfileLlmProtocol::OpenAiResponses,
        "/v1/embeddings" => crate::ProfileLlmProtocol::Embeddings,
        _ => return Ok((None, None, false)),
    };
    crate::ensure_json_number_fidelity(body)?;
    let mut value = parse_unique_json(body).map_err(|_| PolicyError::InvalidParameters)?;
    // Reuse the existing provider ceiling and usage semantics; this is a pure
    // adapter, not a Profile session or additional authorization decision.
    let adapter = rekey_domain::profile::ProfileLlmLimit {
        instance: connection.name.clone(),
        models: limits.models.iter().cloned().collect(),
        max_output_tokens_per_request: limits.max_tokens,
        max_requests_per_day: u64::from(limits.max_requests_per_day),
        max_output_tokens_per_day: limits.max_output_tokens_per_day,
    };
    let normalized = crate::normalize_profile_llm_body(protocol, &adapter, body, &mut value)?;
    *body = normalized.bytes;
    Ok((normalized.model, normalized.maximum, normalized.streaming))
}

/// Most-specific matching; deny is absolute, with approve winning exact ties.
/// Caller labels can only make the already selected default effect stricter.
pub fn decide(
    connection: &Connection,
    method: FixedMethod,
    class: MethodClass,
    path: &str,
    caller: &str,
) -> (RuleEffect, Option<PolicyRuleId>, String) {
    let base = choose(&connection.rules, connection, method, class, path);
    let selected = connection
        .caller_overrides
        .get(caller)
        .and_then(|rules| choose(rules, connection, method, class, path));
    let winner = match (base, selected) {
        (Some(base), Some(over)) if over.0 > base.0 => Some(over),
        (base, _) => base,
    };
    winner.map_or(
        (RuleEffect::Deny, None, audit_path(path)),
        |(effect, id, pattern)| (effect, Some(id), pattern.to_owned()),
    )
}
fn audit_path(path: &str) -> String {
    if path == "/" {
        "/".into()
    } else {
        format!(
            "/{}",
            path[1..]
                .split('/')
                .map(|_| "*")
                .collect::<Vec<_>>()
                .join("/")
        )
    }
}
fn choose<'a>(
    rules: &'a [ConnectionRule],
    connection: &Connection,
    method: FixedMethod,
    class: MethodClass,
    path: &str,
) -> Option<(RuleEffect, PolicyRuleId, &'a str)> {
    let mut matches: Vec<_> = rules
        .iter()
        .filter_map(|rule| {
            let method_matches = match &rule.methods {
                MethodSelector::Class(c) => *c == class,
                MethodSelector::Methods(methods) => methods.contains(&method),
            };
            (method_matches && pattern_matches(&rule.path, path, &connection.bindings))
                .then_some((rule, specificity(&rule.path)))
        })
        .collect();
    if let Some((rule, _)) = matches
        .iter()
        .filter(|(r, _)| r.effect == RuleEffect::Deny)
        .min_by_key(|(r, _)| r.id)
    {
        return Some((rule.effect, rule.id, &rule.path));
    }
    matches.sort_by(|(a, sa), (b, sb)| {
        sb.cmp(sa)
            .then_with(|| b.effect.cmp(&a.effect))
            .then_with(|| a.id.cmp(&b.id))
    });
    matches
        .first()
        .map(|(rule, _)| (rule.effect, rule.id, rule.path.as_str()))
}
fn specificity(pattern: &str) -> (usize, bool, usize, usize) {
    let parts: Vec<_> = pattern.split('/').skip(1).collect();
    (
        parts.iter().filter(|p| !p.contains(['{', '*'])).count(),
        !parts.contains(&"**"),
        parts.iter().filter(|p| p.starts_with('{')).count(),
        parts.len(),
    )
}
fn pattern_matches(pattern: &str, path: &str, bindings: &BTreeMap<String, Vec<String>>) -> bool {
    let parts: Vec<_> = if path == "/" {
        Vec::new()
    } else {
        path[1..].split('/').collect()
    };
    let patterns: Vec<_> = if pattern == "/" {
        Vec::new()
    } else {
        pattern[1..].split('/').collect()
    };
    for (i, part) in patterns.iter().enumerate() {
        if *part == "**" {
            return true;
        }
        let Some(value) = parts.get(i) else {
            return false;
        };
        if *part == "*" {
            continue;
        }
        if let Some(name) = part.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if !bindings
                .get(name)
                .is_some_and(|choices| choices.iter().any(|v| v == "*" || v == value))
            {
                return false;
            }
        } else if part != value {
            return false;
        }
    }
    parts.len() == patterns.len()
}

fn graphql_read(body: &[u8]) -> bool {
    let Ok(value) = parse_unique_json(body) else {
        return false;
    };
    let Some(query) = value.get("query").and_then(Value::as_str) else {
        return false;
    };
    let Ok(document) = graphql_parser::parse_query::<String>(query) else {
        return false;
    };
    let selected = value.get("operationName").and_then(Value::as_str);
    let mut queries = 0;
    let mut names = Vec::new();
    for definition in document.definitions {
        match definition {
            graphql_parser::query::Definition::Operation(
                graphql_parser::query::OperationDefinition::Query(q),
            ) => {
                queries += 1;
                names.push(q.name);
            }
            graphql_parser::query::Definition::Operation(
                graphql_parser::query::OperationDefinition::SelectionSet(_),
            ) => {
                queries += 1;
                names.push(None);
            }
            graphql_parser::query::Definition::Fragment(_) => {}
            _ => return false,
        }
    }
    queries > 0
        && selected.map_or(queries == 1, |name| {
            names.iter().filter(|n| n.as_deref() == Some(name)).count() == 1
        })
}

pub(crate) fn ssh_name_valid(name: &str) -> bool {
    rekey_domain::connection::validate_request_path(&format!("/{name}")).is_ok()
        && !name.contains('/')
}
