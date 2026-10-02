use rekey_domain::action::{ExactPath, FixedMethod, HttpsOrigin};
use rekey_domain::template::{
    self, DefaultRule, MaterializedAction, ProviderTemplate, TemplateApprover, TemplateTarget,
    TemplateValues, ValueRule,
};
use serde_json::{Value, json};

fn values(pairs: &[(&str, &str)]) -> TemplateValues {
    pairs
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}

fn github() -> rekey_domain::template::BoundTemplate {
    template::github_pat()
        .unwrap()
        .bind(&values(&[("owner", "rekey"), ("repo", "agent-tools")]))
        .unwrap()
}

fn declaration() -> Value {
    serde_json::to_value(template::github_pat().unwrap()).unwrap()
}

#[test]
fn builtin_endpoint_and_auth_contracts_are_fixed() {
    let cases = [
        (
            template::anthropic().unwrap(),
            "https://api.anthropic.com",
            "x-api-key",
            "",
            vec![
                ("POST", "/v1/messages"),
                ("POST", "/v1/messages/count_tokens"),
                ("GET", "/v1/models"),
            ],
        ),
        (
            template::openai().unwrap(),
            "https://api.openai.com",
            "authorization",
            "Bearer ",
            vec![
                ("POST", "/v1/chat/completions"),
                ("POST", "/v1/responses"),
                ("POST", "/v1/embeddings"),
                ("GET", "/v1/models"),
            ],
        ),
    ];
    for (template, origin, header, prefix, expected) in cases {
        let bound = template.bind(&values(&[])).unwrap();
        let mut actual = Vec::new();
        for capability in &template.definition().capabilities {
            for index in 0..capability.actions.len() {
                let request = bound
                    .render(&capability.id, index, &values(&[]), &values(&[]))
                    .unwrap();
                assert_eq!(request.origin.as_str(), origin);
                assert_eq!(request.credential.inject.header.as_str(), header);
                assert_eq!(request.credential.inject.prefix.as_str(), prefix);
                actual.push((request.method.as_str(), request.path.as_str().to_owned()));
            }
        }
        assert_eq!(
            actual,
            expected
                .iter()
                .map(|(m, p)| (*m, (*p).to_owned()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn github_bindings_are_fixed_per_installation() {
    let template = template::github_pat().unwrap();
    let one = template
        .bind(&values(&[("owner", "alice"), ("repo", "one")]))
        .unwrap();
    let two = template
        .bind(&values(&[("owner", "bob"), ("repo", "two")]))
        .unwrap();
    for (bound, expected) in [
        (one, "/repos/alice/one/pulls/42"),
        (two, "/repos/bob/two/pulls/42"),
    ] {
        let request = bound
            .render(
                "read-repo",
                2,
                &values(&[("number", "00042")]),
                &values(&[]),
            )
            .unwrap();
        assert_eq!(request.path.as_str(), expected);
        assert_eq!(request.params["number"], "42");
        assert_eq!(request.origin.as_str(), "https://api.github.com");
        assert!(
            bound
                .render(
                    "read-repo",
                    2,
                    &values(&[("number", "42"), ("owner", "evil")]),
                    &values(&[])
                )
                .is_err()
        );
    }
    assert!(template.bind(&values(&[("owner", "alice")])).is_err());
    assert!(
        template
            .bind(&values(&[
                ("owner", "alice"),
                ("repo", "one"),
                ("extra", "x")
            ]))
            .is_err()
    );
    assert!(
        template
            .bind(&values(&[("owner", "a"), ("other", "b")]))
            .is_err()
    );
}

#[test]
fn t7_path_attacks_never_produce_a_rendered_request() {
    let bound = github();
    let attacks = [
        ".",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "%2f",
        "%2F",
        "%252f",
        "%2e%2e",
        "a?next=x",
        "a#fragment",
        "a&x=y",
        "a=b",
        "*",
        "",
        " a",
        "a ",
        "a\n",
        "a\0b",
        "＿name",
        "ａｂｃ",
        "a／b",
        "а",
        "a\u{200d}b",
        "_first",
        "-first",
    ];
    for attack in attacks {
        assert!(
            bound
                .render("read-repo", 6, &values(&[("path", attack)]), &values(&[]))
                .is_err(),
            "accepted {attack:?}"
        );
    }
    let overlong = "a".repeat(101);
    assert!(
        bound
            .render(
                "read-repo",
                6,
                &values(&[("path", &overlong)]),
                &values(&[])
            )
            .is_err()
    );
    for valid in ["a", "README.md", "file-name_1", "a..b"] {
        let request = bound
            .render("read-repo", 6, &values(&[("path", valid)]), &values(&[]))
            .unwrap();
        assert_eq!(
            request.path.as_str(),
            format!("/repos/rekey/agent-tools/contents/{valid}")
        );
    }
}

#[test]
fn administrator_binding_values_obey_the_same_segment_contract() {
    let template = template::github_pat().unwrap();
    for bad in ["..", ".", "a/b", "%2f", "a?x", "a#x", "α", "a\\b"] {
        assert!(
            template
                .bind(&values(&[("owner", bad), ("repo", "ok")]))
                .is_err()
        );
    }
    assert!(
        template
            .bind(&values(&[
                ("owner", &"a".repeat(39)),
                ("repo", &"r".repeat(100))
            ]))
            .is_ok()
    );
    assert!(
        template
            .bind(&values(&[("owner", &"a".repeat(40)), ("repo", "ok")]))
            .is_err()
    );
    assert!(
        template
            .bind(&values(&[("owner", "ok"), ("repo", &"r".repeat(101))]))
            .is_err()
    );
}

#[test]
fn integer_parameters_require_bounded_ascii_decimal() {
    let bound = github();
    for bad in [
        "0",
        "-1",
        "2147483648",
        "+1",
        " 1",
        "1 ",
        "１",
        "١",
        "1.0",
        "1e1",
        "1_0",
        "1/2",
        "%31",
        "--1",
        "",
        "99999999999999999999999999999999",
    ] {
        assert!(
            bound
                .render("merge-pr", 0, &values(&[("number", bad)]), &values(&[]))
                .is_err(),
            "accepted {bad:?}"
        );
    }
    for valid in ["1", "2147483647"] {
        assert!(
            bound
                .render("merge-pr", 0, &values(&[("number", valid)]), &values(&[]))
                .is_ok()
        );
    }
    assert!(
        bound
            .render("merge-pr", 0, &values(&[]), &values(&[]))
            .is_err()
    );
    assert!(
        bound
            .render("merge-pr", 0, &values(&[("other", "1")]), &values(&[]))
            .is_err()
    );
    assert!(
        bound
            .render("unknown", 0, &values(&[]), &values(&[]))
            .is_err()
    );
    assert!(
        bound
            .render("read-repo", 99, &values(&[]), &values(&[]))
            .is_err()
    );
}

#[test]
fn query_is_closed_optional_normalized_and_bound_to_serialized_request() {
    let bound = github();
    assert!(
        bound
            .render("read-repo", 1, &values(&[]), &values(&[]))
            .unwrap()
            .query
            .is_empty()
    );
    let first = bound
        .render(
            "read-repo",
            1,
            &values(&[]),
            &values(&[("state", "open"), ("per_page", "010"), ("page", "002")]),
        )
        .unwrap();
    let second = bound
        .render(
            "read-repo",
            1,
            &values(&[]),
            &values(&[("page", "2"), ("per_page", "10"), ("state", "open")]),
        )
        .unwrap();
    assert_eq!(
        first.request_target(),
        "/repos/rekey/agent-tools/issues?page=2&per_page=10&state=open"
    );
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    let mut changed = values(&[("page", "2"), ("per_page", "10"), ("state", "closed")]);
    let changed_request = bound
        .render("read-repo", 1, &values(&[]), &changed)
        .unwrap();
    assert_ne!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(changed_request).unwrap()
    );
    for (key, bad) in [
        ("state", "all&admin=true"),
        ("state", "OPEN"),
        ("state", "%6fpen"),
        ("state", "оpen"),
        ("page", "0"),
        ("page", "1001"),
        ("per_page", "101"),
        ("page", "+1"),
        ("unknown", "1"),
    ] {
        assert!(
            bound
                .render("read-repo", 1, &values(&[]), &values(&[(key, bad)]))
                .is_err(),
            "accepted {key}={bad}"
        );
    }
    changed.insert("origin".into(), "https://evil.example".into());
    assert!(
        bound
            .render("read-repo", 1, &values(&[]), &changed)
            .is_err()
    );
    assert!(
        bound
            .render("read-repo", 0, &values(&[]), &values(&[("page", "1")]))
            .is_err()
    );
}

#[test]
fn risk_defaults_have_the_required_local_approver() {
    let bound = github();
    for (capability, params, rule) in [
        ("read-repo", values(&[]), DefaultRule::Allow),
        ("create-issue", values(&[]), DefaultRule::Allow),
        (
            "merge-pr",
            values(&[("number", "7")]),
            DefaultRule::RequireApproval,
        ),
    ] {
        let request = bound.render(capability, 0, &params, &values(&[])).unwrap();
        assert_eq!(request.default_policy.rule, rule);
        assert_eq!(
            request.default_policy.approver,
            (rule == DefaultRule::RequireApproval).then_some(TemplateApprover::LocalPresence)
        );
    }
    let mut raw = declaration();
    raw["capabilities"][2]
        .as_object_mut()
        .unwrap()
        .remove("default_rule");
    raw["capabilities"][0]["default_rule"] = json!("require-approval");
    let template: ProviderTemplate = serde_json::from_value(raw).unwrap();
    assert_eq!(
        template.definition().capabilities[2].default_policy().rule,
        DefaultRule::RequireApproval
    );
    assert_eq!(
        template.definition().capabilities[0]
            .default_policy()
            .approver,
        Some(TemplateApprover::LocalPresence)
    );
}

#[test]
fn malformed_rules_and_injectable_enum_literals_fail_at_declaration() {
    for rule in [
        "regex:.*",
        "int:2..1",
        "int:+1..2",
        "int:0..",
        "int:1.0..2",
        "enum:",
        "enum:a,a",
        "enum:..,ok",
        "enum:a/b,ok",
        "enum:a%2fb,ok",
        "enum:a?x,ok",
        "enum:a#x,ok",
        "enum:a&b,ok",
        "enum:α,ok",
    ] {
        assert!(ValueRule::parse(rule).is_err(), "accepted {rule}");
    }
    let mut raw = declaration();
    raw["capabilities"][0]["actions"][2]["params"]["number"] = json!("enum:one,two");
    let template: ProviderTemplate = serde_json::from_value(raw).unwrap();
    let bound = template
        .bind(&values(&[("owner", "a"), ("repo", "b")]))
        .unwrap();
    assert!(
        bound
            .render("read-repo", 2, &values(&[("number", "one")]), &values(&[]))
            .is_ok()
    );
    assert!(
        bound
            .render(
                "read-repo",
                2,
                &values(&[("number", "three")]),
                &values(&[])
            )
            .is_err()
    );
}

#[test]
fn declaration_reuses_origin_auth_and_header_boundaries() {
    for origin in [
        "http://api.github.com",
        "https://user:pass@api.github.com",
        "https://api.github.com/path",
        "https://api.github.com?x=1",
        "https://api.github.com#x",
        "https://api.github.com\\evil",
        "https://аpi.github.com",
    ] {
        let mut raw = declaration();
        raw["origin"] = json!(origin);
        assert!(
            serde_json::from_value::<ProviderTemplate>(raw).is_err(),
            "accepted {origin}"
        );
    }
    for header in ["host", "content-length", "authorization", "connection"] {
        let mut raw = declaration();
        raw["fixed_headers"][header] = json!("x");
        assert!(
            serde_json::from_value::<ProviderTemplate>(raw).is_err(),
            "accepted {header}"
        );
    }
    let mut raw = declaration();
    raw["fixed_headers"]["accept"] = json!("value\r\nInjected: x");
    assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
    let mut raw = declaration();
    raw["credential"]["inject"]["header"] = json!("cookie");
    assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
    let mut raw = declaration();
    raw["credential"]["kind"] = json!("github-app-installation");
    assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
}

#[test]
fn placeholders_are_whole_segments_and_cannot_shadow_bindings() {
    for path in [
        "/repos/{owner}/{repo}/{unknown}",
        "/repos/{owner}/{repo}/{number}.json",
        "/repos/{owner}/{repo}/prefix{number}",
        "/repos/{owner}/{repo}/*",
        "/a/%2f",
        "/a/../b",
        "/a/./b",
        "/a?x=1",
        "/a#fragment",
        "/ａ",
        "relative",
    ] {
        let mut raw = declaration();
        raw["capabilities"][0]["actions"][2]["path"] = json!(path);
        assert!(
            serde_json::from_value::<ProviderTemplate>(raw).is_err(),
            "accepted {path}"
        );
    }
    let mut raw = declaration();
    raw["capabilities"][0]["actions"][2]["params"]["owner"] = json!("slug");
    assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
    let mut raw = declaration();
    raw["capabilities"][0]["actions"][2]["unknown"] = json!(true);
    assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
    let mut raw = declaration();
    raw["bindings"]["owner"]["max"] = json!(101);
    assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
}

#[test]
fn final_expansion_retains_the_existing_path_length_limit() {
    let mut raw = declaration();
    raw["capabilities"][0]["actions"][6]["path"] =
        json!(format!("/{}", vec!["{path}"; 21].join("/")));
    let template: ProviderTemplate = serde_json::from_value(raw).unwrap();
    let bound = template
        .bind(&values(&[("owner", "a"), ("repo", "b")]))
        .unwrap();
    assert!(
        bound
            .render(
                "read-repo",
                6,
                &values(&[("path", &"a".repeat(100))]),
                &values(&[])
            )
            .is_err()
    );
}

#[test]
fn generic_bearer_allows_only_one_to_twenty_fixed_actions() {
    let origin = HttpsOrigin::parse("https://EXAMPLE.com:443").unwrap();
    let action = (FixedMethod::Post, ExactPath::parse("/fixed").unwrap());
    for count in [0, 21] {
        assert!(template::generic_bearer(origin.clone(), vec![action.clone(); count]).is_err());
    }
    for count in [1, 20] {
        let template =
            template::generic_bearer(origin.clone(), vec![action.clone(); count]).unwrap();
        let bound = template.bind(&values(&[])).unwrap();
        let request = bound
            .render("fixed-actions", count - 1, &values(&[]), &values(&[]))
            .unwrap();
        assert_eq!(request.origin.as_str(), "https://example.com");
        assert_eq!(request.request_target(), "/fixed");
        assert_eq!(request.method, FixedMethod::Post);
        let mut raw = serde_json::to_value(template).unwrap();
        raw["capabilities"][0]["actions"][0]["query"] = json!({"page":"int:1..2"});
        assert!(serde_json::from_value::<ProviderTemplate>(raw).is_err());
    }
}

#[test]
fn materialized_actions_keep_binding_groups_independent_without_the_template() {
    let actions: Vec<_> = [("alice", "one"), ("bob", "two")]
        .into_iter()
        .map(|(owner, repo)| {
            let bound = template::github_pat()
                .unwrap()
                .bind(&values(&[("owner", owner), ("repo", repo)]))
                .unwrap();
            let action = bound.materialize("read-repo", 2).unwrap();
            let saved = serde_json::to_value(action).unwrap();
            assert_eq!(
                saved["target"]["path"],
                format!("/repos/{owner}/{repo}/pulls/{{number}}")
            );
            assert_eq!(
                saved["target"]["params"],
                json!({"number":"int:1..2147483647"})
            );
            for unrelated in ["bindings", "capabilities", "display", "path", "exact_path"] {
                assert!(saved.get(unrelated).is_none());
            }
            serde_json::from_value::<MaterializedAction>(saved).unwrap()
        })
        .collect();
    for (action, expected) in actions
        .iter()
        .zip(["/repos/alice/one/pulls/42", "/repos/bob/two/pulls/42"])
    {
        assert_eq!(
            action
                .render(&values(&[("number", "00042")]), &values(&[]))
                .unwrap()
                .request_target(),
            expected
        );
        for supplied in [
            values(&[("number", "42"), ("owner", "evil")]),
            values(&[("number", "42"), ("repo", "evil")]),
            values(&[("owner", "evil")]),
        ] {
            assert!(action.render(&supplied, &values(&[])).is_err());
        }
        assert!(
            action
                .render(&values(&[("number", "42")]), &values(&[("owner", "evil")]))
                .is_err()
        );
    }
    assert!(github().materialize("missing", 0).is_err());
    assert!(github().materialize("read-repo", usize::MAX).is_err());
}

#[test]
fn materialized_roundtrip_keeps_authoritative_metadata_and_normalization() {
    let bound = github();
    let create = bound.materialize("create-issue", 0).unwrap();
    let saved = serde_json::to_value(&create).unwrap();
    assert_eq!(
        saved,
        json!({
            "template":"github-pat@1", "capability":"create-issue", "action_index":0,
            "origin":"https://api.github.com", "method":"POST",
            "target":{"path":"/repos/rekey/agent-tools/issues", "params":{}, "query":{}},
            "fixed_headers":{"accept":"application/vnd.github+json", "x-github-api-version":"2022-11-28"},
            "credential":{"kind":"opaque-token", "inject":{"header":"authorization", "prefix":"Bearer "}},
            "default_policy":{"rule":"allow"}, "body_schema":"schemas/github-create-issue.json"
        })
    );
    let loaded: MaterializedAction = serde_json::from_value(saved.clone()).unwrap();
    assert_eq!(serde_json::to_value(&loaded).unwrap(), saved);
    assert_eq!(
        loaded.definition().body_schema.as_deref(),
        Some("schemas/github-create-issue.json")
    );
    assert_eq!(
        loaded.render(&values(&[]), &values(&[])).unwrap().method,
        FixedMethod::Post
    );
    let merge = bound.materialize("merge-pr", 0).unwrap();
    assert_eq!(
        merge.definition().default_policy.rule,
        DefaultRule::RequireApproval
    );
    assert_eq!(
        merge.definition().default_policy.approver,
        Some(TemplateApprover::LocalPresence)
    );

    let query_action = bound.materialize("read-repo", 1).unwrap();
    let target: TemplateTarget =
        serde_json::from_value(serde_json::to_value(&query_action.definition().target).unwrap())
            .unwrap();
    assert!(target.params().is_empty());
    assert_eq!(target.query().len(), 3);
    assert_eq!(target.path_pattern(), "/repos/rekey/agent-tools/issues");
    let query = values(&[("state", "open"), ("page", "002"), ("per_page", "010")]);
    let rendered = target.render(&values(&[]), &query).unwrap();
    assert_eq!(
        rendered.query,
        values(&[("page", "2"), ("per_page", "10"), ("state", "open")])
    );
    assert_eq!(
        rendered.request_target(),
        "/repos/rekey/agent-tools/issues?page=2&per_page=10&state=open"
    );
    assert_eq!(
        query_action
            .render(&values(&[]), &query)
            .unwrap()
            .request_target(),
        rendered.request_target()
    );
}

#[test]
fn materialized_target_deserialization_rejects_open_or_malformed_grammar() {
    let target =
        serde_json::to_value(github().materialize("read-repo", 2).unwrap()).unwrap()["target"]
            .clone();
    for path in [
        "relative/{number}",
        "/{unknown}",
        "/{owner}/{number}",
        "/a/{number}.json",
        "/a/prefix{number}",
        "/a/*/{number}",
        "/a/%2f/{number}",
        "/a/../{number}",
        "/a/./{number}",
        "/a/{number}?x=1",
        "/a/{number}#fragment",
        "/α/{number}",
        "/a/\\/{number}",
        "/a/\n/{number}",
        "/a/fixed",
    ] {
        let mut bad = target.clone();
        bad["path"] = json!(path);
        assert!(
            serde_json::from_value::<TemplateTarget>(bad).is_err(),
            "accepted {path:?}"
        );
    }
    for rule in [
        "regex:.*",
        "int:2..1",
        "int:+1..2",
        "enum:a,a",
        "enum:../a,b",
        "enum:a%2fb,c",
    ] {
        for field in ["params", "query"] {
            let mut bad = target.clone();
            bad[field]["number"] = json!(rule);
            assert!(
                serde_json::from_value::<TemplateTarget>(bad).is_err(),
                "accepted {field} {rule}"
            );
        }
    }
    for (pointer, value) in [
        ("/params", json!({})),
        ("/params", json!({"number":"slug", "unused":"slug"})),
        ("/query", json!({"page&other":"slug"})),
    ] {
        let mut bad = target.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(serde_json::from_value::<TemplateTarget>(bad).is_err());
    }
    let mut bad = target;
    bad["bindings"] = json!({"owner":"evil"});
    assert!(serde_json::from_value::<TemplateTarget>(bad).is_err());
}

#[test]
fn materialized_deserialization_rejects_bad_headers_and_inconsistent_metadata() {
    let saved = serde_json::to_value(github().materialize("merge-pr", 0).unwrap()).unwrap();
    for header in [
        "host",
        "authorization",
        "content-length",
        "connection",
        "accept-encoding",
    ] {
        let mut bad = saved.clone();
        bad["fixed_headers"][header] = json!("x");
        assert!(
            serde_json::from_value::<MaterializedAction>(bad).is_err(),
            "accepted {header}"
        );
    }
    for (pointer, value) in [
        ("/template", json!("unversioned")),
        ("/capability", json!("../arbitrary")),
        ("/origin", json!("https://api.github.com/path")),
        ("/method", json!("CONNECT")),
        ("/fixed_headers/accept", json!("value\r\nInjected: x")),
        ("/credential/inject/header", json!("cookie")),
        ("/credential/kind", json!("github-app-installation")),
        ("/default_policy", json!({"rule":"require-approval"})),
        (
            "/default_policy",
            json!({"rule":"allow", "approver":{"kind":"local-presence"}}),
        ),
        (
            "/default_policy",
            json!({"rule":"require-approval", "approver":{"kind":"remote"}}),
        ),
        ("/default_policy", json!({"rule":"allow", "unknown":true})),
    ] {
        let mut bad = saved.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<MaterializedAction>(bad).is_err(),
            "accepted {pointer}"
        );
    }
    let mut bad = saved;
    bad["exact_path"] = json!("/shadow");
    assert!(serde_json::from_value::<MaterializedAction>(bad).is_err());

    let mut raw = serde_json::to_value(
        template::anthropic()
            .unwrap()
            .bind(&values(&[]))
            .unwrap()
            .materialize("messages", 0)
            .unwrap(),
    )
    .unwrap();
    raw["fixed_headers"]["x-api-key"] = json!("cannot override injection");
    assert!(serde_json::from_value::<MaterializedAction>(raw).is_err());
}

#[test]
fn loaded_materialized_actions_keep_per_call_inputs_closed() {
    let action: MaterializedAction = serde_json::from_value(
        serde_json::to_value(github().materialize("read-repo", 6).unwrap()).unwrap(),
    )
    .unwrap();
    for input in [
        ".",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "%2F",
        "%252f",
        "a?x",
        "a#x",
        "a&x=y",
        "",
        "α",
    ] {
        assert!(
            action
                .render(&values(&[("path", input)]), &values(&[]))
                .is_err()
        );
    }
    assert!(action.render(&values(&[]), &values(&[])).is_err());
    assert!(
        action
            .render(&values(&[("unknown", "README.md")]), &values(&[]))
            .is_err()
    );
    assert_eq!(
        action
            .render(&values(&[("path", "README.md")]), &values(&[]))
            .unwrap()
            .request_target(),
        "/repos/rekey/agent-tools/contents/README.md"
    );
    let query_action: MaterializedAction = serde_json::from_value(
        serde_json::to_value(github().materialize("read-repo", 1).unwrap()).unwrap(),
    )
    .unwrap();
    for (key, input) in [
        ("page", "0"),
        ("per_page", "101"),
        ("state", "OPEN"),
        ("state", "open&admin=1"),
        ("accept", "override"),
        ("unknown", "x"),
    ] {
        assert!(
            query_action
                .render(&values(&[]), &values(&[(key, input)]))
                .is_err()
        );
    }
    let fixed = template::openai()
        .unwrap()
        .bind(&values(&[]))
        .unwrap()
        .materialize("models", 0)
        .unwrap();
    assert!(
        fixed
            .render(&values(&[("path", "elsewhere")]), &values(&[]))
            .is_err()
    );
    assert!(
        fixed
            .render(&values(&[]), &values(&[("page", "1")]))
            .is_err()
    );
}

#[test]
fn materializing_checks_final_binding_expansion_length() {
    let mut raw = declaration();
    raw["capabilities"][0]["actions"][0]["path"] =
        json!(format!("/{}", vec!["{repo}"; 21].join("/")));
    let template: ProviderTemplate = serde_json::from_value(raw).unwrap();
    let bound = template
        .bind(&values(&[("owner", "a"), ("repo", &"r".repeat(100))]))
        .unwrap();
    assert!(bound.materialize("read-repo", 0).is_err());
}
