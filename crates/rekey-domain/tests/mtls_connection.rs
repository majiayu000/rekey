//! mTLS Connections are T0, fixed-path HTTPS only: no OAuth, LLM, T1 grade or
//! templated/wildcard rule paths. Header-auth controls show each refusal is
//! specific to mTLS. Synthetic identifiers only.
use rekey_domain::DomainError;
use rekey_domain::connection::Connection;
use serde_json::{Value, json};

const T0_FIXED: &str = "mTLS requires T0 fixed HTTP semantics";
const FIXED_PATHS: &str = "mTLS requires fixed paths";

fn rule(path: &str) -> Value {
    rule_with_id(path, "00112233-4455-4677-8899-aabbccddee01")
}

fn rule_with_id(path: &str, id: &str) -> Value {
    json!({"id":id,"methods":["POST"],"path":path,"effect":"allow"})
}

fn mtls() -> Value {
    json!({
        "name":"mtls-fixture","preset":"generic-bearer",
        "credential_id":"00112233-4455-4677-8899-aabbccddeeff",
        "origin":"https://mtls.example","auth":{"kind":"mtls"},"enabled":true,"grade":"T0",
        "rules":[rule("/v1/fixed")],"bindings":{},"caller_overrides":{},
        "limits":{"requests_per_hour":600,"max_request_bytes":1024,"max_response_bytes":4096},
        "allowed_headers":[],"fixed_headers":{},"allowed_response_headers":[],
        "query_allowlist":null,"operations":[],"llm":null,"oauth":null
    })
}

fn validate(value: Value) -> Result<(), DomainError> {
    serde_json::from_value::<Connection>(value)
        .unwrap()
        .validate()
}

fn rejected(value: Value, expected: &str, case: &str) {
    match validate(value) {
        Err(DomainError::InvalidActionDefinition(message)) => {
            assert_eq!(message, expected, "{case}")
        }
        other => panic!("{case}: expected {expected:?}, got {other:?}"),
    }
}

fn header_auth(mut value: Value) -> Value {
    value["auth"] = json!({"header_name":"authorization","prefix":"Bearer "});
    value
}

#[test]
fn fixed_t0_mtls_is_the_only_accepted_shape() {
    validate(mtls()).unwrap();
}

#[test]
fn mtls_rejects_t1_oauth_and_llm_semantics() {
    let mut t1 = mtls();
    t1["grade"] = json!("T1");
    rejected(t1, T0_FIXED, "T1 grade");

    let mut oauth = mtls();
    oauth["oauth"] = json!({"provider":"google","client_id":"synthetic-client",
        "scopes":["https://www.googleapis.com/auth/drive.readonly"]});
    // The same binding is a valid header-auth OAuth Connection.
    validate(header_auth(oauth.clone())).unwrap();
    rejected(oauth, T0_FIXED, "OAuth binding");

    let limits = json!({"models":["synthetic-model"],"max_tokens":16,
        "max_requests_per_day":1,"max_output_tokens_per_day":16});
    for preset in ["generic-bearer", "anthropic"] {
        let mut llm = mtls();
        llm["preset"] = json!(preset);
        llm["llm"] = limits.clone();
        validate(header_auth(llm.clone())).unwrap();
        rejected(llm, T0_FIXED, preset);
    }
}

#[test]
fn mtls_rejects_wildcard_and_templated_paths_in_rules_and_overrides() {
    for path in ["/*", "/v1/*/items", "/v1/**", "/repos/{owner}"] {
        let mut value = mtls();
        value["bindings"] = json!({"owner":["*"]});
        value["rules"] = json!([rule(path)]);
        validate(header_auth(value.clone())).unwrap();
        rejected(value, FIXED_PATHS, path);

        let mut value = mtls();
        value["bindings"] = json!({"owner":["*"]});
        let override_rule = rule_with_id(path, "00112233-4455-4677-8899-aabbccddee02");
        value["caller_overrides"] = json!({"codex":[override_rule]});
        validate(header_auth(value.clone())).unwrap();
        rejected(value, FIXED_PATHS, &format!("override {path}"));
    }
}
