//! Discovery projections (§6.2, §6.4): per-operation decisions, example
//! arguments and the matched rule, judged by the same evaluator as calls.
use std::collections::BTreeMap;

use rekey_domain::Timestamp;
use rekey_domain::action::FixedMethod;
use rekey_domain::connection::{
    Connection, ConnectionRule, MethodClass, PresetOperation, ReadSemantics, RuleEffect,
};
use rekey_domain::ids::PolicyRuleId;
use rekey_domain::ipc::{CallMeta, OperationDecision};
use rekey_policy::connections::evaluate_connection;
use rekey_policy::{PolicyError, ValidatedSnapshot};
use serde_json::Value;

/// Required arguments that satisfy the schema and the signed bindings. The
/// values are placeholders for the caller to replace, never an authorization.
pub(super) fn example_args(
    connection: &Connection,
    operation: &PresetOperation,
) -> BTreeMap<String, Value> {
    let properties = operation
        .parameters
        .get("properties")
        .and_then(Value::as_object);
    let mut names: Vec<&str> = operation
        .parameters
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    // A signed model allow-list makes `model` necessary in practice.
    if connection.llm.is_some()
        && properties.is_some_and(|p| p.contains_key("model"))
        && !names.contains(&"model")
    {
        names.push("model");
    }
    names
        .into_iter()
        .filter_map(|name| {
            let schema = properties?.get(name)?;
            Some((
                name.to_owned(),
                example_value(connection, operation, name, schema),
            ))
        })
        .collect()
}

fn example_value(
    connection: &Connection,
    operation: &PresetOperation,
    name: &str,
    schema: &Value,
) -> Value {
    if name == "model"
        && let Some(model) = connection.llm.as_ref().and_then(|l| l.models.iter().next())
    {
        return model.as_str().into();
    }
    let segment = format!("{{{name}}}");
    if operation.path.split('/').any(|part| part == segment)
        && let Some(bound) = connection
            .bindings
            .get(name)
            .and_then(|values| values.iter().find(|value| *value != "*"))
    {
        return bound.as_str().into();
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return first.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("integer" | "number") => schema
            .get("minimum")
            .filter(|minimum| minimum.is_number())
            .cloned()
            .unwrap_or_else(|| 1.into()),
        Some("boolean") => false.into(),
        Some("array") => Value::Array(Vec::new()),
        Some("object") => Value::Object(Default::default()),
        _ => name.to_ascii_uppercase().into(),
    }
}

/// The decision for a call with `args`, judged exactly like that call.
/// `None` when the example cannot be judged, so it would not be representative.
pub(super) fn decide(
    snapshot: &ValidatedSnapshot,
    connection: &Connection,
    operation: &PresetOperation,
    args: &BTreeMap<String, Value>,
    caller: &str,
    now: Timestamp,
) -> Option<OperationDecision> {
    let args = args
        .iter()
        .map(|(name, value)| {
            let text = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            (name.clone(), text)
        })
        .collect();
    let mut request = CallMeta::operation(operation.name.clone(), args);
    request.connection = connection.name.clone();
    let (method_class, effect, rule_id) =
        match evaluate_connection(snapshot, &request, &[], caller, now) {
            Ok(authorized) => (
                authorized.method_class,
                authorized.effect,
                authorized.rule_id,
            ),
            // Declared but not callable, for example without its OAuth scopes.
            Err(PolicyError::NotConfigured) => (class(operation), RuleEffect::Deny, None),
            Err(_) => return None,
        };
    Some(OperationDecision {
        operation: operation.name.clone(),
        method_class,
        effect,
        rule_id,
    })
}

fn class(operation: &PresetOperation) -> MethodClass {
    match (operation.method, &operation.read_semantics) {
        (FixedMethod::Get | FixedMethod::Head, _) | (_, Some(ReadSemantics::Fixed)) => {
            MethodClass::Read
        }
        _ => MethodClass::Write,
    }
}

/// Every named operation of a listed Connection, judged with its example.
pub(super) fn decisions(
    snapshot: &ValidatedSnapshot,
    connection: &Connection,
    caller: &str,
    now: Timestamp,
) -> Vec<OperationDecision> {
    connection
        .operations
        .iter()
        .filter_map(|operation| {
            let args = example_args(connection, operation);
            decide(snapshot, connection, operation, &args, caller, now)
        })
        .collect()
}

/// The signed rule, default or this caller's override, that a decision matched.
pub(super) fn matched_rule(
    connection: &Connection,
    caller: &str,
    rule_id: Option<PolicyRuleId>,
) -> Option<ConnectionRule> {
    let id = rule_id?;
    connection
        .rules
        .iter()
        .chain(
            connection
                .caller_overrides
                .get(caller)
                .into_iter()
                .flatten(),
        )
        .find(|rule| rule.id == id)
        .cloned()
}

/// Dry-run headers show where the credential is injected, never its value.
pub(super) fn with_credential_placeholder(
    mut headers: Vec<(String, String)>,
    connection: &Connection,
) -> Vec<(String, String)> {
    if let Some(auth) = connection.auth.header() {
        headers.push((
            auth.header_name.as_str().to_owned(),
            format!("{}«rekey:{}»", auth.prefix.as_str(), connection.name),
        ));
        headers.sort();
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::connection::{BUILTIN_PRESETS, ConnectionLlmLimits};
    use rekey_domain::ids::CredentialId;

    fn connection(preset: &str) -> Option<Connection> {
        let mut connection = rekey_policy::presets::builtin_preset(preset)
            .ok()?
            .connection(preset.into(), CredentialId::new_random());
        if rekey_domain::connection::is_llm_preset(preset) {
            connection.llm = Some(ConnectionLlmLimits {
                models: ["synthetic-model".into()].into_iter().collect(),
                max_tokens: 32,
                max_requests_per_day: 10,
                max_output_tokens_per_day: 100,
            });
        }
        if preset == "github-git" {
            connection.bindings = [
                ("owner".to_owned(), vec!["example".to_owned()]),
                ("repo".to_owned(), vec!["project.git".to_owned()]),
            ]
            .into_iter()
            .collect();
        }
        Some(connection)
    }

    #[test]
    fn every_builtin_operation_example_is_judged_like_a_call() {
        let mut judged = 0;
        for preset in BUILTIN_PRESETS {
            let Some(connection) = connection(preset) else {
                continue;
            };
            let snapshot = rekey_policy::parse_and_validate_snapshot(
                &serde_json::to_vec(&serde_json::json!({"format_version":8,"version":1,"expires_at_ms":10000,"connections":[connection],"ssh_keys":[],"derived_credentials":[],"profiles":[],"bindings":[],"rules":[],"approvers":[],"workload_identities":[]})).unwrap(),
                Timestamp::from_unix_ms(1),
            );
            let Ok(snapshot) = snapshot else {
                // OAuth presets need a signed OAuth binding to validate.
                assert!(
                    rekey_policy::presets::oauth_provider(preset).is_some(),
                    "{preset}"
                );
                continue;
            };
            let listed = decisions(&snapshot, &connection, "codex", Timestamp::from_unix_ms(2));
            assert_eq!(listed.len(), connection.operations.len(), "{preset}");
            for decision in listed {
                assert!(
                    decision.effect != RuleEffect::Deny || decision.rule_id.is_some(),
                    "{preset}: {decision:?}"
                );
                judged += 1;
            }
        }
        assert!(judged > 30, "{judged}");
        let mut git = connection("github-git").unwrap();
        git.bindings
            .insert("owner".into(), vec!["*".into(), "example".into()]);
        let args = example_args(&git, &git.operations[0]);
        assert_eq!(
            args["owner"], "example",
            "a wildcard is never an example value"
        );
        assert_eq!(args["repo"], "project.git");
    }

    #[test]
    fn placeholders_follow_schema_types_and_signed_models() {
        let github = connection("github-pat").unwrap();
        let comment = github
            .operations
            .iter()
            .find(|o| o.name == "github.create_comment")
            .unwrap();
        assert_eq!(
            serde_json::to_value(example_args(&github, comment)).unwrap(),
            serde_json::json!({"owner":"OWNER","repo":"REPO","number":1,"body":"BODY"})
        );
        let openai = connection("openai").unwrap();
        assert_eq!(
            serde_json::to_value(example_args(&openai, &openai.operations[1])).unwrap(),
            serde_json::json!({"model":"synthetic-model"})
        );
        let headers = with_credential_placeholder(vec![("accept".into(), "x".into())], &github);
        assert_eq!(
            headers,
            [
                ("accept".to_owned(), "x".to_owned()),
                (
                    "authorization".to_owned(),
                    "Bearer «rekey:github-pat»".to_owned()
                )
            ]
        );
    }
}
