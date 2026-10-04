use rekey_domain::{Timestamp, action::FixedHttpAction, ids::ActionId, profile::ProfileLlmLimit};
use rekey_policy::{
    ActionRequest, ProfileLlmProtocol as Protocol, parse_and_validate_snapshot,
    profile_llm_output_tokens,
};
use serde_json::{Value, json};

fn action() -> FixedHttpAction {
    serde_json::from_value(json!({
        "id":ActionId::new_random(),"name":"llm","version":1,"enabled":true,
        "credential_id":ActionId::new_random(),"origin":"https://api.example.com","method":"POST",
        "target":{"kind":"fixed","path":"/generation"},
        "auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":1000,
        "request_policy":{"max_body_bytes":4096,"allowed_extra_headers":[]},
        "response_policy":{"max_body_bytes":4096,"allowed_headers":[]}
    }))
    .unwrap()
}
fn limits() -> ProfileLlmLimit {
    ProfileLlmLimit {
        instance: "llm".into(),
        models: vec!["allowed".into()],
        max_output_tokens_per_request: 20,
        max_requests_per_day: 10,
        max_output_tokens_per_day: 100,
    }
}
fn snapshot(action: &FixedHttpAction, schema: Value) -> rekey_policy::ValidatedSnapshot {
    parse_and_validate_snapshot(&serde_json::to_vec(&json!({
        "format_version":6,"profiles":[],"version":1,"expires_at_ms":10000,"approvers":[],"workload_identities":[],"rules":[],
        "bindings":[{"action_id":action.id,"version":1,"resource":{"type":"test","id":"llm"},"parameter_schema_id":"llm/v1","parameter_schema":schema}]
    })).unwrap(), Timestamp::from_unix_ms(1)).unwrap()
}
fn request(body: &[u8]) -> ActionRequest<'_> {
    static EMPTY: std::sync::LazyLock<rekey_domain::template::TemplateValues> =
        std::sync::LazyLock::new(Default::default);
    ActionRequest {
        params: &EMPTY,
        query: &EMPTY,
        content_type: if body.is_empty() {
            None
        } else {
            Some("application/json")
        },
        headers: &[],
        body,
    }
}
#[test]
fn default_ceiling_is_the_only_wire_change_and_is_bound_to_approval() {
    for (protocol, field) in [
        (Protocol::AnthropicMessages, "max_tokens"),
        (Protocol::OpenAiChat, "max_completion_tokens"),
        (Protocol::OpenAiResponses, "max_output_tokens"),
    ] {
        let action = action();
        let policy = snapshot(&action, json!({"type":"object","required":[field]}));
        let body=b" { \"model\" : \"allowed\", \"tools\":[{\"name\":\"tool\"}], \"thinking\": {\"type\":\"enabled\"} } \n";
        let normalized = policy
            .canonicalize_profile_llm(&action, request(body), protocol, &limits())
            .unwrap();
        let expected = format!(
            " {{ \"model\" : \"allowed\", \"tools\":[{{\"name\":\"tool\"}}], \"thinking\": {{\"type\":\"enabled\"}} ,\"{field}\":20}} \n"
        );
        assert_eq!(normalized.body, expected.as_bytes());
        assert_eq!(normalized.generation_max_output, Some(20));
        let (_, external, _) = policy
            .canonicalize(&action, request(&normalized.body))
            .unwrap();
        assert_eq!(
            external.canonical_hash,
            normalized.parameters.canonical_hash
        );
        let retry = policy
            .canonicalize_profile_llm(&action, request(body), protocol, &limits())
            .unwrap();
        assert_eq!(retry.parameters.canonical_hash, external.canonical_hash);
        let review: Value = serde_json::from_slice(&normalized.parameters.canonical_json).unwrap();
        assert_eq!(review["body"][field], 20);
    }
}
#[test]
fn explicit_smaller_bound_and_chat_native_fields_are_preserved() {
    for field in ["max_tokens", "max_completion_tokens"] {
        let a = action();
        let p = snapshot(&a, json!({}));
        let raw = format!("{{\"model\":\"allowed\",\"{field}\":3}}");
        let c = p
            .canonicalize_profile_llm(&a, request(raw.as_bytes()), Protocol::OpenAiChat, &limits())
            .unwrap();
        assert_eq!(c.body, raw.as_bytes());
        assert_eq!(c.generation_max_output, Some(3));
    }
}
#[test]
fn invalid_fields_never_reach_a_canonical_request() {
    let a = action();
    let p = snapshot(&a, json!({}));
    for (protocol, body) in [
        (Protocol::OpenAiChat, r#"{"model":"other"}"#),
        (Protocol::OpenAiChat, r#"{"model":"allowed","n":2}"#),
        (Protocol::OpenAiChat, r#"{"model":"allowed","n":1.0}"#),
        (Protocol::OpenAiChat, r#"{"model":"allowed","n":null}"#),
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","max_tokens":2,"max_completion_tokens":2}"#,
        ),
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","max_completion_tokens":null}"#,
        ),
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","max_completion_tokens":0}"#,
        ),
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","max_completion_tokens":21}"#,
        ),
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","max_completion_tokens":"2"}"#,
        ),
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","stream":"false"}"#,
        ),
        (
            Protocol::OpenAiResponses,
            r#"{"model":"allowed","background":true}"#,
        ),
        (
            Protocol::OpenAiResponses,
            r#"{"model":"allowed","background":null}"#,
        ),
        (
            Protocol::AnthropicMessages,
            r#"{"model":"allowed","max_tokens":-1}"#,
        ),
        (
            Protocol::AnthropicMessages,
            r#"{"model":"allowed","model":"allowed"}"#,
        ),
        (
            Protocol::AnthropicMessages,
            r#"{"model":"allowed","x":9007199254740993}"#,
        ),
        (
            Protocol::AnthropicMessages,
            r#"{"model":"allowed","x":1.0000000000000001}"#,
        ),
    ] {
        assert!(
            p.canonicalize_profile_llm(&a, request(body.as_bytes()), protocol, &limits())
                .is_err(),
            "{body}"
        );
    }
    for (protocol, body) in [
        (
            Protocol::OpenAiChat,
            r#"{"model":"allowed","n":1,"stream":false}"#,
        ),
        (
            Protocol::OpenAiResponses,
            r#"{"model":"allowed","background":false}"#,
        ),
    ] {
        assert!(
            p.canonicalize_profile_llm(&a, request(body.as_bytes()), protocol, &limits())
                .is_ok()
        );
    }
}
#[test]
fn injected_length_and_schema_are_enforced_and_plain_http_is_unchanged() {
    let mut a = action();
    let p = snapshot(&a, json!({}));
    let body = br#"{"model":"allowed"}"#;
    a.request_policy.max_body_bytes = body.len() as u32;
    assert!(
        p.canonicalize_profile_llm(&a, request(body), Protocol::OpenAiChat, &limits())
            .is_err()
    );
    let (_, plain, _) = p.canonicalize(&a, request(body)).unwrap();
    let v: Value = serde_json::from_slice(&plain.canonical_json).unwrap();
    assert!(v["body"].get("max_completion_tokens").is_none());
    a.request_policy.max_body_bytes = 4096;
    let closed = snapshot(
        &a,
        json!({"type":"object","properties":{"model":{"type":"string"}},"additionalProperties":false}),
    );
    assert!(
        closed
            .canonicalize_profile_llm(&a, request(body), Protocol::OpenAiChat, &limits())
            .is_err()
    );
}
#[test]
fn non_generation_endpoints_have_no_output_reservation() {
    let a = action();
    let p = snapshot(&a, json!({}));
    for protocol in [Protocol::Embeddings, Protocol::CountTokens] {
        let body = br#"{"model":"allowed","input":"hello"}"#;
        let c = p
            .canonicalize_profile_llm(&a, request(body), protocol, &limits())
            .unwrap();
        assert_eq!(c.body, body);
        assert_eq!(c.generation_max_output, None);
    }
    assert_eq!(
        p.canonicalize_profile_llm(&a, request(b""), Protocol::Models, &limits())
            .unwrap()
            .generation_max_output,
        None
    );
    assert!(
        p.canonicalize_profile_llm(&a, request(b"{}"), Protocol::Models, &limits())
            .is_err()
    );
}
#[test]
fn only_complete_valid_cumulative_output_is_measured_once() {
    for (protocol, raw) in [
        (
            Protocol::AnthropicMessages,
            r#"{"type":"message","stop_reason":"max_tokens","usage":{"output_tokens":7}}"#,
        ),
        (
            Protocol::OpenAiChat,
            r#"{"object":"chat.completion","choices":[{"finish_reason":"length"}],"usage":{"completion_tokens":7}}"#,
        ),
        (
            Protocol::OpenAiResponses,
            r#"{"status":"incomplete","usage":{"output_tokens":7}}"#,
        ),
    ] {
        assert_eq!(profile_llm_output_tokens(protocol, raw.as_bytes()), Some(7));
        assert_eq!(
            profile_llm_output_tokens(protocol, raw.replace(":7", ":0").as_bytes()),
            Some(0)
        );
        for bad in [
            raw.replace(":7", ":-1"),
            raw.replace(":7", ":7.5"),
            raw.replace(":7", ":9223372036854775808"),
            raw.replace(":7", ":\"7\""),
            raw.replace("\"usage\":", "\"usage\":{},\"usage\":"),
            raw[..raw.len() - 1].to_owned(),
        ] {
            assert_eq!(
                profile_llm_output_tokens(protocol, bad.as_bytes()),
                None,
                "{bad}"
            );
        }
    }
    assert_eq!(
        profile_llm_output_tokens(
            Protocol::OpenAiResponses,
            br#"{"status":"in_progress","usage":{"output_tokens":7}}"#
        ),
        None
    );
    assert_eq!(
        profile_llm_output_tokens(Protocol::Embeddings, br#"{"usage":{"output_tokens":999}}"#),
        None
    );
}

#[test]
fn raw_stream_flag_is_bound_to_effective_canonical_body() {
    let a = action();
    let p = snapshot(&a, json!({}));
    for protocol in [
        Protocol::AnthropicMessages,
        Protocol::OpenAiChat,
        Protocol::OpenAiResponses,
    ] {
        let body = br#"{"model":"allowed","stream":true,"tools":[{"name":"tool"}],"thinking":{"type":"enabled"}}"#;
        let raw = p
            .canonicalize_profile_llm(&a, request(body), protocol, &limits())
            .unwrap();
        assert!(raw.streaming);
        let repeated = p
            .canonicalize_profile_llm(&a, request(&raw.body), protocol, &limits())
            .unwrap();
        assert_eq!(
            raw.parameters.canonical_hash,
            repeated.parameters.canonical_hash
        );
        assert_eq!(raw.body, repeated.body);
        let canonical: Value = serde_json::from_slice(&raw.parameters.canonical_json).unwrap();
        assert_eq!(canonical["body"]["stream"], true);
        assert_eq!(canonical["body"]["tools"], json!([{"name":"tool"}]));
    }
    assert!(
        p.canonicalize_profile_llm(
            &a,
            request(br#"{"model":"allowed","stream":true}"#),
            Protocol::Embeddings,
            &limits()
        )
        .is_err()
    );
}

#[test]
fn anthropic_beta_query_remains_in_effective_target_and_approval_hash() {
    use rekey_domain::template::TemplateValues;
    use rekey_policy::templates::{BuiltinTemplate, builtin_template};
    let package = builtin_template(BuiltinTemplate::Anthropic).unwrap();
    for (capability, protocol) in [
        ("messages", Protocol::AnthropicMessages),
        ("count-tokens", Protocol::CountTokens),
    ] {
        let material = package
            .template()
            .bind(&TemplateValues::new())
            .unwrap()
            .materialize(capability, 0)
            .unwrap();
        let m = material.definition();
        let mut a = action();
        a.target = serde_json::from_value(json!({"kind":"template","target":m.target,"fixed_headers":m.fixed_headers,"body_schema":null,
            "source":{"template":m.template,"capability":m.capability,"action_index":0,"digest":package.digest(),"signer_id":null},"default_policy":{"rule":"allow"}})).unwrap();
        a.origin = m.origin.clone();
        a.auth = rekey_domain::action::HeaderCredentialUse::new(
            m.credential.inject.header.clone(),
            m.credential.inject.prefix.clone(),
        )
        .unwrap();
        let p = snapshot(&a, json!({}));
        let body = br#"{"model":"allowed","messages":[]}"#;
        let beta = TemplateValues::from([("beta".into(), "true".into())]);
        let plain = p
            .canonicalize_profile_llm(&a, request(body), protocol, &limits())
            .unwrap();
        let effective = p
            .canonicalize_profile_llm(
                &a,
                ActionRequest {
                    query: &beta,
                    ..request(body)
                },
                protocol,
                &limits(),
            )
            .unwrap();
        assert_eq!(effective.body, plain.body);
        assert_ne!(
            effective.parameters.canonical_hash,
            plain.parameters.canonical_hash
        );
        assert_eq!(
            effective.target.request_target(),
            format!("{}?beta=true", m.target.path_pattern())
        );
        let review: Value = serde_json::from_slice(&effective.parameters.canonical_json).unwrap();
        assert_eq!(review["target"]["query"], json!({"beta":"true"}));
        let (_, external, target) = p
            .canonicalize(
                &a,
                ActionRequest {
                    query: &beta,
                    ..request(&effective.body)
                },
            )
            .unwrap();
        assert_eq!(external.canonical_hash, effective.parameters.canonical_hash);
        assert_eq!(target.request_target(), effective.target.request_target());
        let invalid = TemplateValues::from([("beta".into(), "false".into())]);
        assert!(
            p.canonicalize_profile_llm(
                &a,
                ActionRequest {
                    query: &invalid,
                    ..request(body)
                },
                protocol,
                &limits()
            )
            .is_err()
        );
    }
}
