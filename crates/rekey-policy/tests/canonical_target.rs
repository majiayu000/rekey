//! The same request is normalized for Broker execution and external approval.
use rekey_domain::{Timestamp, action::FixedHttpAction, ids::ActionId, template::TemplateValues};
use rekey_policy::{ActionRequest, ValidatedSnapshot, parse_and_validate_snapshot};
use serde_json::json;

fn action() -> FixedHttpAction {
    serde_json::from_value(json!({
        "id":ActionId::new_random(),"name":"canonical-template","version":1,"enabled":true,
        "credential_id":ActionId::new_random(),"origin":"https://api.example.com","method":"POST",
        "target":{"kind":"template","target":{"path":"/issues/{number}","params":{"number":"int:1..100"},"query":{"state":"enum:open,closed","page":"int:1..100"}},
            "fixed_headers":{"content-type":"application/json","x-fixed":"one"},
            "body_schema":{"type":"object","required":["title"],"properties":{"title":{"type":"string"}},"additionalProperties":false},
            "source":{"template":"team@1","capability":"issues","action_index":0,"digest":vec![7;32],"signer_id":null},"default_policy":{"rule":"allow"}},
        "auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":1000,
        "request_policy":{"max_body_bytes":1024,"allowed_extra_headers":["x-note"]},
        "response_policy":{"max_body_bytes":1024,"allowed_headers":[]}
    })).unwrap()
}
fn policy(action: &FixedHttpAction) -> ValidatedSnapshot {
    parse_and_validate_snapshot(&serde_json::to_vec(&json!({
        "format_version":4,"version":1,"expires_at_ms":10000,"approvers":[],"workload_identities":[],"rules":[],
        "bindings":[{"action_id":action.id,"version":1,"resource":{"type":"test","id":"one"},"parameter_schema_id":"test/v1","parameter_schema":{}}]
    })).unwrap(), Timestamp::from_unix_ms(1)).unwrap()
}
fn values(pairs: &[(&str, &str)]) -> TemplateValues {
    pairs
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}
fn canonical(
    action: &FixedHttpAction,
    params: &TemplateValues,
    query: &TemplateValues,
) -> ([u8; 32], String) {
    let (_, parameters, target) = policy(action)
        .canonicalize(
            action,
            ActionRequest {
                params,
                query,
                content_type: None,
                headers: &[],
                body: br#"{"title":"hello"}"#,
            },
        )
        .unwrap();
    (parameters.canonical_hash, target.request_target())
}
#[test]
fn normalized_path_and_sorted_query_are_bound_to_the_hash() {
    let action = action();
    let p = values(&[("number", "007")]);
    let q = values(&[("state", "open"), ("page", "02")]);
    let (hash, path) = canonical(&action, &p, &q);
    assert_eq!(path, "/issues/7?page=2&state=open");
    assert_eq!(
        hash,
        canonical(
            &action,
            &values(&[("number", "7")]),
            &values(&[("page", "2"), ("state", "open")])
        )
        .0
    );
    assert_ne!(hash, canonical(&action, &values(&[("number", "8")]), &q).0);
    assert_ne!(
        hash,
        canonical(&action, &p, &values(&[("state", "closed"), ("page", "02")])).0
    );
    let mut other = serde_json::to_value(&action).unwrap();
    other["target"]["target"]["path"] = "/other/{number}".into();
    assert_ne!(
        hash,
        canonical(&serde_json::from_value(other).unwrap(), &p, &q).0
    );
}
#[test]
fn actual_template_schema_unique_json_and_fixed_headers_are_enforced() {
    let action = action();
    let snapshot = policy(&action);
    let p = values(&[("number", "1")]);
    let q = values(&[]);
    for body in [
        br#"{}"#.as_slice(),
        br#"{"title":1}"#,
        br#"{"title":"one","title":"two"}"#,
        br#"{"title":"ok","unexpected":1}"#,
    ] {
        assert!(
            snapshot
                .canonicalize(
                    &action,
                    ActionRequest {
                        params: &p,
                        query: &q,
                        content_type: None,
                        headers: &[],
                        body
                    }
                )
                .is_err()
        );
    }
    for (ct, headers) in [
        (Some("application/json"), vec![]),
        (None, vec![("x-fixed".into(), "two".into())]),
        (
            None,
            vec![
                ("x-note".into(), "one".into()),
                ("x-note".into(), "two".into()),
            ],
        ),
    ] {
        assert!(
            snapshot
                .canonicalize(
                    &action,
                    ActionRequest {
                        params: &p,
                        query: &q,
                        content_type: ct,
                        headers: &headers,
                        body: br#"{"title":"ok"}"#
                    }
                )
                .is_err()
        );
    }
    for schema in [
        json!({"$ref":"https://example.com/schema"}),
        json!({"$dynamicRef":"file:///tmp/schema"}),
        json!({"type":5}),
    ] {
        let mut raw = serde_json::to_value(&action).unwrap();
        raw["target"]["body_schema"] = schema;
        let malformed: FixedHttpAction = serde_json::from_value(raw).unwrap();
        assert!(
            policy(&malformed)
                .canonicalize(
                    &malformed,
                    ActionRequest {
                        params: &p,
                        query: &q,
                        content_type: None,
                        headers: &[],
                        body: br#"{"title":"ok"}"#
                    }
                )
                .is_err()
        );
    }
}
#[test]
fn fixed_action_rejects_unconsumed_values_and_hashes_its_path() {
    let mut raw = serde_json::to_value(action()).unwrap();
    raw["target"] = json!({"kind":"fixed","path":"/fixed"});
    let fixed: FixedHttpAction = serde_json::from_value(raw.clone()).unwrap();
    let empty = values(&[]);
    let nonempty = values(&[("x", "one")]);
    let snapshot = policy(&fixed);
    for (params, query) in [(&nonempty, &empty), (&empty, &nonempty)] {
        assert!(
            snapshot
                .canonicalize(
                    &fixed,
                    ActionRequest {
                        params,
                        query,
                        content_type: Some("application/json"),
                        headers: &[],
                        body: b"{}"
                    }
                )
                .is_err()
        );
    }
    let hash = |action: &FixedHttpAction| {
        snapshot
            .canonicalize(
                action,
                ActionRequest {
                    params: &empty,
                    query: &empty,
                    content_type: Some("application/json"),
                    headers: &[],
                    body: b"{}",
                },
            )
            .unwrap()
            .1
            .canonical_hash
    };
    raw["target"]["path"] = "/different".into();
    assert_ne!(hash(&fixed), hash(&serde_json::from_value(raw).unwrap()));
}
