//! Dotenv import on a real daemon (agent-call 7.3, C8): preview, import with a
//! proof, signing and rewrite; then SDK-shaped calls built only from the
//! rewritten file reach a synthetic upstream through the local service.
//! Values and upstreams are synthetic; no real SDK or provider is used.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::connection::ConnectionLlmLimits;
use rekey_domain::ids::CredentialId;

const OPENAI_KEY: &str = "sk-synthetic-dotenv-openai";
const ANTHROPIC_KEY: &str = "sk-ant-synthetic-dotenv";
const AWS_SECRET: &str = "synthetic-aws-secret";

struct Project {
    _dir: tempfile::TempDir,
    env: PathBuf,
    backup: PathBuf,
}

/// The daemon opens each component without following symlinks, so the
/// project path is canonical (`/var` is a symlink on macOS).
fn project(contents: &str) -> Project {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join(".env"), contents).unwrap();
    Project {
        env: root.join(".env"),
        backup: root.join(".env.rekey-backup"),
        _dir: dir,
    }
}

/// `KEY=value` and `KEY="value"` lines, as a dotenv loader reads them.
fn dotenv(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.trim_matches('"').to_owned()))
        .collect()
}

async fn import(f: &Fixture, env: &Path, selections: Value) -> common::WireResponse {
    f.call(
        admin_msg::IMPORT_ENV,
        json!({"path": env, "selections": selections}),
        &common::proof_body(common::PASSWORD),
    )
    .await
}

async fn rewrite(f: &Fixture, env: &Path, replacements: Value) -> common::WireResponse {
    f.call(
        admin_msg::IMPORT_ENV,
        json!({"path": env, "action": "rewrite", "replacements": replacements}),
        &common::proof_body(common::PASSWORD),
    )
    .await
}

/// Imports each `(key, name, preset)` with a proof and returns its LLM
/// Connection, bound to the credential from the import report.
async fn import_connections(
    f: &Fixture,
    env: &Path,
    items: &[(&str, &str, &str)],
) -> Vec<Connection> {
    let selections = items
        .iter()
        .map(|(key, name, _)| json!({"key": key, "label": name}))
        .collect();
    let response = import(f, env, Value::Array(selections)).await;
    response.ok();
    let report: Value = serde_json::from_slice(&response.body).unwrap();
    items
        .iter()
        .map(|(key, name, preset)| {
            let entry = report["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["key"] == *key)
                .unwrap();
            let credential: CredentialId =
                serde_json::from_value(entry["credential"]["id"].clone()).unwrap();
            let mut connection = rekey_policy::presets::builtin_preset(preset)
                .unwrap()
                .connection((*name).into(), credential);
            connection.llm = Some(ConnectionLlmLimits {
                models: ["synthetic-model".into()].into_iter().collect(),
                max_tokens: 32,
                max_requests_per_day: 20,
                max_output_tokens_per_day: 1000,
            });
            connection
        })
        .collect()
}

/// Signs and activates the Connections; returns the local service URL.
async fn sign(f: &Fixture, connections: Vec<Connection>) -> String {
    let draft = f.draft(connections).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    list.service_url.unwrap()
}

fn audited(f: &Fixture, event: &str) -> i64 {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type=?1",
            [event],
            |r| r.get(0),
        )
        .unwrap()
}

fn upstream_ok(body: &[u8]) -> Result<UpstreamResponse, rekey_broker::upstream::UpstreamError> {
    Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())].into(),
        body: body.to_vec().into(),
    })
}

#[tokio::test]
async fn rewritten_dotenv_reaches_the_synthetic_upstream_through_the_local_service() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let original = format!(
        "# synthetic project\nOPENAI_API_KEY={OPENAI_KEY}\nANTHROPIC_API_KEY={ANTHROPIC_KEY}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\nAPP_MODE=dev\n"
    );
    let p = project(&original);

    // Preview: names and recognition only, without a proof or any value.
    let preview = f
        .call(
            admin_msg::IMPORT_ENV,
            json!({"path": p.env, "dry_run": true}),
            &[],
        )
        .await;
    preview.ok();
    let text = String::from_utf8(preview.body.clone()).unwrap();
    assert!(
        [OPENAI_KEY, ANTHROPIC_KEY, AWS_SECRET]
            .iter()
            .all(|value| !text.contains(value))
    );
    let preview: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        preview["entries"],
        json!([
            {"key":"OPENAI_API_KEY","preset_hint":"openai","unsupported_protocol":null},
            {"key":"ANTHROPIC_API_KEY","preset_hint":"anthropic","unsupported_protocol":null},
            {"key":"AWS_SECRET_ACCESS_KEY","preset_hint":null,"unsupported_protocol":"aws"},
            {"key":"APP_MODE","preset_hint":null,"unsupported_protocol":null},
        ])
    );

    // An entry the service cannot proxy is refused even with a valid proof.
    let refused = import(
        &f,
        &p.env,
        json!([{"key":"AWS_SECRET_ACCESS_KEY","label":"never-aws"}]),
    )
    .await;
    assert_eq!(refused.err_code(), "INVALID_INPUT");

    let mut connections = import_connections(
        &f,
        &p.env,
        &[
            ("OPENAI_API_KEY", "dotenv-openai", "openai"),
            ("ANTHROPIC_API_KEY", "dotenv-anthropic", "anthropic"),
        ],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(&p.env).unwrap(),
        original,
        "importing alone never touches the file"
    );
    let mut dormant = connections[0].clone();
    dormant.name = "dotenv-dormant".into();
    dormant.enabled = false;
    connections.push(dormant);
    let service = sign(&f, connections).await;

    // A disabled or unknown Connection is refused before the file changes.
    for connection in ["dotenv-dormant", "dotenv-missing"] {
        let response = rewrite(
            &f,
            &p.env,
            json!([{"key":"OPENAI_API_KEY","connection":connection,"base_url_variable":"OPENAI_BASE_URL"}]),
        )
        .await;
        assert_eq!(response.err_code(), "POLICY_INVALID", "{connection}");
    }
    assert_eq!(std::fs::read_to_string(&p.env).unwrap(), original);
    assert!(!p.backup.exists());

    let response = rewrite(
        &f,
        &p.env,
        json!([
            {"key":"OPENAI_API_KEY","connection":"dotenv-openai","base_url_variable":"OPENAI_BASE_URL"},
            {"key":"ANTHROPIC_API_KEY","connection":"dotenv-anthropic","base_url_variable":"ANTHROPIC_BASE_URL"},
        ]),
    )
    .await;
    response.ok();
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({ "backup": p.backup })
    );
    assert_eq!(std::fs::read_to_string(&p.backup).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&p.backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The address carries the port the service actually listens on (the
    // fixture binds port 0) and each preset's SDK path suffix.
    let port: u16 = service
        .strip_prefix("http://127.0.0.1:")
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(port, 0);
    assert_eq!(
        std::fs::read_to_string(&p.env).unwrap(),
        format!(
            "# synthetic project\nOPENAI_API_KEY=rekey\nANTHROPIC_API_KEY=rekey\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\nAPP_MODE=dev\nOPENAI_BASE_URL=\"{service}/c/dotenv-openai/v1\"\nANTHROPIC_BASE_URL=\"{service}/c/dotenv-anthropic\"\n"
        )
    );

    // Calls shaped like the SDKs, built only from the rewritten file: the
    // OpenAI SDK appends /chat/completions to OPENAI_BASE_URL and the
    // Anthropic SDK /v1/messages to ANTHROPIC_BASE_URL.
    let values = dotenv(&p.env);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let body = json!({"model":"synthetic-model","messages":[{"role":"user","content":"test"}],"max_tokens":16}).to_string();
    f.fake.push_response(upstream_ok(
        br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#,
    ));
    let openai = client
        .post(format!("{}/chat/completions", values["OPENAI_BASE_URL"]))
        .bearer_auth(&values["OPENAI_API_KEY"])
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(openai.status(), 200);
    f.fake.push_response(upstream_ok(
        br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#,
    ));
    let anthropic = client
        .post(format!("{}/v1/messages", values["ANTHROPIC_BASE_URL"]))
        .header("x-api-key", &values["ANTHROPIC_API_KEY"])
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(anthropic.status(), 200);
    let requests = f.fake.take_requests();
    let bearer = format!("Bearer {OPENAI_KEY}");
    let seen: Vec<_> = requests
        .iter()
        .map(|r| {
            (
                r.host.as_str(),
                r.path.as_str(),
                r.auth_name.as_str(),
                r.auth_value.as_slice(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (
                "api.openai.com",
                "/v1/chat/completions",
                "authorization",
                bearer.as_bytes()
            ),
            (
                "api.anthropic.com",
                "/v1/messages",
                "x-api-key",
                ANTHROPIC_KEY.as_bytes()
            ),
        ]
    );
    assert_eq!(
        ["env.imported", "env.rewrite_started", "env.rewritten"].map(|event| audited(&f, event)),
        [1, 1, 1]
    );
    f.finish().await;
}

#[tokio::test]
async fn rewrite_whose_audit_fails_reports_an_unconfirmed_outcome_and_faults() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let original = format!("OPENAI_API_KEY={OPENAI_KEY}\n");
    let p = project(&original);
    let connections =
        import_connections(&f, &p.env, &[("OPENAI_API_KEY", "dotenv-openai", "openai")]).await;
    let service = sign(&f, connections).await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_env_rewritten BEFORE INSERT ON audit_events WHEN NEW.event_type='env.rewritten' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let response = rewrite(
        &f,
        &p.env,
        json!([{"key":"OPENAI_API_KEY","connection":"dotenv-openai","base_url_variable":"OPENAI_BASE_URL"}]),
    )
    .await;
    assert_eq!(response.err_code(), "ENV_REWRITE_OUTCOME_UNCONFIRMED");
    assert_eq!(response.metadata["retryable"], false);
    // The rewrite happened; only its audit outcome is unknown, so the caller
    // must inspect the file and backup instead of retrying.
    assert_eq!(
        std::fs::read_to_string(&p.env).unwrap(),
        format!("OPENAI_API_KEY=rekey\nOPENAI_BASE_URL=\"{service}/c/dotenv-openai/v1\"\n")
    );
    assert_eq!(std::fs::read_to_string(&p.backup).unwrap(), original);
    db.execute_batch("DROP TRIGGER fail_env_rewritten;")
        .unwrap();
    // The audit failure faults the broker; it stops instead of serving on.
    let _ = tokio::time::timeout(Duration::from_secs(5), f.task)
        .await
        .unwrap()
        .unwrap();
}
