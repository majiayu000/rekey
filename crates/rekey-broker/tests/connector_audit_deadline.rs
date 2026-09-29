//! A committed upstream effect must never become retryable when its audit stalls.
mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use serde_json::{Value, json};

fn github_profile() -> Value {
    let key = Command::new("/usr/bin/openssl")
        .args(["genrsa", "2048"])
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(key.status.success());
    let mut converter = Command::new("/usr/bin/openssl");
    converter.arg("rsa");
    #[cfg(target_os = "linux")]
    converter.arg("-traditional");
    let mut child = converter
        .args(["-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&key.stdout).unwrap();
    let der = child.wait_with_output().unwrap();
    assert!(der.status.success());
    json!({
        "credential_type":"github-app-installation-v2", "client_id":"fixture-client",
        "app_id":1, "installation_id":42,
        "repositories":[{"id":7,"owner":"owner","name":"repo"}],
        "permissions":{"metadata":"read","issues":"write"},
        "webhook_secret":"s".repeat(32),
        "private_key_pkcs1_der_base64":data_encoding::BASE64.encode(&der.stdout)
    })
}

fn response(status: u16, body: Value) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: Vec::new().into(),
        body: if status == 204 {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        }
        .into(),
    }
}

async fn audit_timeout(kind: &str, issued: bool, malformed: bool) {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let (profile, issued_response, issued_event, revoked_event) = match kind {
        "github-app-installation" => (
            github_profile(),
            response(
                201,
                json!({
                    "token":"synthetic-installation-token", "expires_at":"2099-01-01T00:00:00Z",
                    "permissions":{"metadata":"read","issues":"write"},
                    "repositories":[{"id":7}], "repository_selection":"selected"
                }),
            ),
            "connector.github.authorized",
            "connector.github.token_revoked",
        ),
        "keycloak-token-exchange" => (
            json!({
                "credential_type":"keycloak-token-exchange-v1",
                "origin":"https://keycloak.example.com", "realm":"test",
                "client_id":"requester", "client_secret":"synthetic-client-secret",
                "subject_token":"synthetic-subject-token", "audience":"target",
                "target_origin":"https://api.example.com", "target_path":"/v1/things"
            }),
            response(
                200,
                json!({"access_token":"synthetic-issued-token", "expires_in":60,
                    "token_type":"Bearer", "issued_token_type":"urn:ietf:params:oauth:token-type:access_token"
                }),
            ),
            "oauth.token.issued",
            "oauth.token.revoked",
        ),
        "vault-dynamic-source" => (
            json!({
                "credential_type":"vault-dynamic-source-v2", "origin":"https://vault.example.com",
                "mount":"database", "role":"agent-api-token", "key":"token", "renew_increment_seconds":60, "vault_token":"synthetic-vault-token"
            }),
            response(
                200,
                json!({"lease_id":"database/creds/agent-api-token/lease-one",
                    "lease_duration":60, "renewable":true,
                    "data": if malformed { json!({}) } else { json!({"token":"synthetic-dynamic-value"}) }
                }),
            ),
            "vault.lease.issued",
            "vault.lease.revoked",
        ),
        _ => unreachable!(),
    };
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        json!({"label":"audit-stall", "kind":kind})
            .to_string()
            .as_bytes(),
        &common::proof_and_secret_body(common::PASSWORD, &serde_json::to_vec(&profile).unwrap()),
    )
    .await;
    let mut action = common::action_meta(added.ok()["id"].as_str().unwrap());
    action["timeout_ms"] = 2000.into();
    if kind == "github-app-installation" {
        action["origin"] = "https://api.github.com".into();
        action["exact_path"] = "/repos/owner/repo/issues".into();
        action["allowed_extra_headers"] = json!([]);
    } else if kind == "keycloak-token-exchange" {
        action["method"] = "GET".into();
    }
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        action.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let id = created.ok()["id"].as_str().unwrap();
    let cap = common::create_session(&broker, id, 1).await;
    let resource = response(
        201,
        json!({"id":44,"number":7,
        "repository_url":"https://api.github.com/repos/owner/repo",
        "html_url":"https://github.com/owner/repo/issues/7"}),
    );
    let revoked_response = UpstreamResponse {
        status: if kind == "keycloak-token-exchange" {
            200
        } else {
            204
        },
        headers: Vec::new().into(),
        body: Vec::new().into(),
    };
    let (gate, cleanup_gate) = if issued {
        let gate = broker.fake.push_response_gated(Ok(issued_response));
        let cleanup = broker.fake.push_response_gated(Ok(revoked_response));
        (gate, Some(cleanup))
    } else {
        broker.fake.push_response(Ok(issued_response));
        broker.fake.push_response(Ok(resource));
        (broker.fake.push_response_gated(Ok(revoked_response)), None)
    };
    let mut meta = common::execute_meta(&cap, id, 1);
    let body = if kind == "keycloak-token-exchange" {
        meta["content_type"] = Value::Null;
        b"".as_slice()
    } else {
        br#"{"title":"audit deadline"}"#.as_slice()
    };
    let socket = broker.agent_sock();
    let call = tokio::spawn(async move {
        common::call(
            &socket,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            meta.to_string().as_bytes(),
            body,
        )
        .await
    });
    let wait_requests = async |count| {
        tokio::time::timeout(Duration::from_secs(4), async {
            while broker.fake.requests.lock().unwrap().len() < count {
                assert!(
                    !call.is_finished(),
                    "execution ended before gated upstream call"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    };
    wait_requests(if issued { 1 } else { 3 }).await;
    // Stall the real SQLite writer exactly between the upstream effect and audit.
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    gate.notify_one();
    if let Some(cleanup) = cleanup_gate {
        // The issuance deadline has expired, but cleanup must still run.
        wait_requests(2).await;
        db.execute_batch("COMMIT").unwrap();
        cleanup.notify_one();
    }
    let result = tokio::time::timeout(Duration::from_secs(4), call)
        .await
        .unwrap()
        .unwrap();
    if !issued {
        db.execute_batch("COMMIT").unwrap();
    }
    assert_eq!(
        result.err_code(),
        "UPSTREAM_INDETERMINATE",
        "{kind} issued={issued}"
    );
    assert_eq!(result.metadata["retryable"], false);
    assert!(result.body.is_empty());
    assert_eq!(
        broker.fake.take_requests().len(),
        if issued { 2 } else { 3 }
    );
    let state = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
    let mut query = db.prepare("SELECT event_type FROM audit_events WHERE event_type IN (?1, ?2, 'execution.indeterminate') ORDER BY sequence").unwrap();
    let events: Vec<String> = query
        .query_map([issued_event, revoked_event], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        events,
        [issued_event, revoked_event, "execution.indeterminate"]
    );
    let outcome: String = db
        .query_row(
            "SELECT outcome FROM audit_events WHERE event_type = ?1",
            [revoked_event],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        outcome, "success",
        "cleanup must succeed despite the audit timeout"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn github_revoked_audit_deadline_is_not_retryable() {
    audit_timeout("github-app-installation", false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn keycloak_issued_audit_deadline_is_not_retryable() {
    audit_timeout("keycloak-token-exchange", true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn keycloak_revoked_audit_deadline_is_not_retryable() {
    audit_timeout("keycloak-token-exchange", false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_issued_audit_deadline_is_not_retryable() {
    audit_timeout("vault-dynamic-source", true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_revoked_audit_deadline_is_not_retryable() {
    audit_timeout("vault-dynamic-source", false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_vault_issued_audit_deadline_is_not_retryable() {
    audit_timeout("vault-dynamic-source", true, true).await;
}
