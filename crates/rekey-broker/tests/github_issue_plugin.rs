//! Real Broker/Authority/Agent IPC and native reference sidecar; no GitHub IO.
#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use data_encoding::BASE64;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use serde_json::{Value, json};

fn profile() -> Vec<u8> {
    let generated = Command::new("/usr/bin/openssl")
        .args(["genrsa", "2048"])
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(generated.status.success());
    let mut converter = Command::new("/usr/bin/openssl");
    converter.arg("rsa");
    #[cfg(target_os = "linux")]
    converter.arg("-traditional");
    let mut convert = converter
        .args(["-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    convert
        .stdin
        .take()
        .unwrap()
        .write_all(&generated.stdout)
        .unwrap();
    let der = convert.wait_with_output().unwrap();
    assert!(der.status.success());
    serde_json::to_vec(&json!({
        "credential_type":"github-app-installation-v2", "client_id":"fixture-client",
        "app_id":1,"installation_id":42,"repositories":[{"id":7,"owner":"owner","name":"repo"}],
        "permissions":{"metadata":"read","issues":"write"}, "webhook_secret":"s".repeat(32),
        "private_key_pkcs1_der_base64":BASE64.encode(&der.stdout)
    }))
    .unwrap()
}

fn response(status: u16, body: Value) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: Vec::new().into(),
        body: serde_json::to_vec(&body).unwrap().into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_public_request_reaches_broker_transport_and_revoke_precedes_success() {
    for comment in [false, true] {
        successful_operation(comment, false).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn same_registered_native_artifact_executes_both_operations() {
    for comment in [false, true] {
        successful_operation(comment, true).await;
    }
}

async fn successful_operation(comment: bool, registered: bool) {
    let path = if comment {
        "/repos/owner/repo/issues/7/comments"
    } else {
        "/repos/owner/repo/issues"
    };
    let input = if comment {
        br#"{ "body" : "public details" }"#.as_slice()
    } else {
        br#"{ "body" : "public details", "title" : "reference plugin" }"#
    };
    let expected_body = if comment {
        br#"{"body":"public details"}"#.as_slice()
    } else {
        br#"{"title":"reference plugin","body":"public details"}"#
    };
    // Cargo builds broker binaries for this integration target.
    assert!(std::path::Path::new(env!("CARGO_BIN_EXE_rekey-github-create-issue")).is_file());
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        br#"{"label":"github","kind":"github-app-installation"}"#,
        &common::proof_and_secret_body(common::PASSWORD, &profile()),
    )
    .await;
    let credential = added.ok()["id"].as_str().unwrap();
    let mut meta = common::action_meta(credential);
    meta["origin"] = json!("https://api.github.com");
    meta["exact_path"] = json!(path);
    meta["allowed_extra_headers"] = json!([]);
    if registered {
        meta["native_plugin"] = registration(std::path::Path::new(env!(
            "CARGO_BIN_EXE_rekey-github-create-issue"
        )));
    }
    let created = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        meta.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    let action = created.ok()["id"].as_str().unwrap();
    let capability = common::create_session(&broker, action, 1).await;
    broker.fake.push_response(Ok(response(
        201,
        json!({
            "token":"installation-token-fixture-canary", "expires_at":"2099-01-01T00:00:00Z",
            "permissions":{"metadata":"read","issues":"write"}, "repositories":[{"id":7}],
            "repository_selection":"selected"
        }),
    )));
    broker.fake.push_response(Ok(response(
        201,
        if comment { json!({"id":44,"issue_url":"https://api.github.com/repos/owner/repo/issues/7","html_url":"https://github.com/owner/repo/issues/7#issuecomment-44"}) } else { json!({
            "id":44,"number":7,"repository_url":"https://api.github.com/repos/owner/repo",
            "html_url":"https://github.com/owner/repo/issues/7"
        }) },
    )));
    let revoke = broker.fake.push_response_gated(Ok(UpstreamResponse {
        status: 204,
        headers: Vec::new().into(),
        body: Vec::new().into(),
    }));
    let socket = broker.agent_sock();
    let metadata = common::execute_meta(&capability, action, 1).to_string();
    let call_socket = socket.clone();
    let call_metadata = metadata.clone();
    let call = tokio::spawn(async move {
        common::call(
            &call_socket,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            call_metadata.as_bytes(),
            input,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while broker.fake.requests.lock().unwrap().len() < 3 {
            assert!(
                !call.is_finished(),
                "execution terminated before gated revoke"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("revoke request must reach deterministic transport");
    assert!(
        !call.is_finished(),
        "success must wait for revoke completion"
    );
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3, "exchange, public effect, revoke");
    assert_eq!(requests[0].path, "/app/installations/42/access_tokens");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
        json!({"repository_ids":[7],"permissions":{"metadata":"read","issues":"write"}})
    );
    assert_eq!(requests[1].path, path);
    assert_eq!(requests[1].host, "api.github.com");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].body, expected_body);
    assert_eq!(
        requests[1].auth_value,
        b"Bearer installation-token-fixture-canary"
    );
    assert_eq!(requests[2].path, "/installation/token");
    assert_eq!(requests[2].method, "DELETE");
    revoke.notify_one();
    let reply = call.await.unwrap();
    assert_eq!(reply.metadata["upstream_status"], 201, "{}", reply.metadata);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["id"],
        44
    );
    if !comment {
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.body).unwrap()["number"],
            7
        );
    }

    assert_eq!(count_event(&broker, "execution.finished"), 1);
    assert_eq!(count_event(&broker, "connector.github.token_revoked"), 1);

    // Unknown and altered-effect fields fail before exchange; no extra upstream.
    for body in [
        br#"{"title":"reference","url":"https://evil"}"#.as_slice(),
        br#"{"title":""}"#,
        br#"{"body":"b","operation":"create_issue"}"#,
        br#"{"body":"b","body":"changed"}"#,
    ] {
        let reply = common::call(
            &socket,
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            metadata.as_bytes(),
            body,
        )
        .await;
        assert_eq!(reply.err_code(), "REQUEST_DENIED");
        assert!(broker.fake.take_requests().is_empty());
    }
    let state = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
    let mut statement = db.prepare("SELECT event_type FROM audit_events WHERE event_type LIKE 'execution.%' OR event_type LIKE 'connector.github.%' ORDER BY sequence").unwrap();
    let events: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let authorized = events
        .iter()
        .position(|event| event == "connector.github.authorized")
        .unwrap();
    let revoked = events
        .iter()
        .position(|event| event == "connector.github.token_revoked")
        .unwrap();
    let finished = events
        .iter()
        .position(|event| event == "execution.finished")
        .unwrap();
    assert!(
        events[..authorized]
            .iter()
            .any(|event| event == "execution.started")
    );
    assert!(authorized < revoked && revoked < finished);
}

fn native_artifacts() -> &'static [std::path::PathBuf; 2] {
    use std::sync::OnceLock;
    static ARTIFACTS: OnceLock<(tempfile::TempDir, [std::path::PathBuf; 2])> = OnceLock::new();
    &ARTIFACTS
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("registered.c");
            // Two protocol fixtures accept distinct public requests. A packaged
            // fallback would wrongly accept their crossed-input negative controls.
            std::fs::write(
                &source,
                r#"
#include <stdio.h>
#include <string.h>
#ifndef VARIANT
#error missing variant
#endif
int main(void) {
 char input[1024];size_t used=fread(input,1,sizeof(input),stdin);
 const char *expected=VARIANT==1 ? "{\"operation\":\"create_issue\",\"body\":{\"title\":\"artifact-A\"}}" : "{\"operation\":\"create_issue\",\"body\":{\"title\":\"artifact-B\"}}";
 if(ferror(stdin)||used!=strlen(expected)||memcmp(input,expected,used))return 17;
 return fwrite(expected,1,used,stdout)==used?0:18;
}
"#,
            )
            .unwrap();
            let paths = [
                dir.path().join("registered-a"),
                dir.path().join("registered-b"),
            ];
            for (index, path) in paths.iter().enumerate() {
                let output = Command::new("/usr/bin/cc")
                    .args(["-O0", "-Wall", "-Werror"])
                    .arg(format!("-DVARIANT={}", index + 1))
                    .arg(&source)
                    .arg("-o")
                    .arg(path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert_ne!(
                std::fs::read(&paths[0]).unwrap(),
                std::fs::read(&paths[1]).unwrap()
            );
            (dir, paths)
        })
        .1
}

fn registration(path: &std::path::Path) -> Value {
    use sha2::{Digest, Sha256};
    json!({"path":path,"sha256":data_encoding::HEXLOWER.encode(&Sha256::digest(std::fs::read(path).unwrap())),"protocol":"github-issues-v1"})
}
async fn github_credential(broker: &common::TestBroker) -> String {
    let added = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ADD,
        br#"{"label":"registered-github","kind":"github-app-installation"}"#,
        &common::proof_and_secret_body(common::PASSWORD, &profile()),
    )
    .await;
    added.ok()["id"].as_str().unwrap().into()
}
fn plugin_definition(credential: &str, plugin: Value) -> Value {
    let mut meta = common::action_meta(credential);
    meta["origin"] = json!("https://api.github.com");
    meta["exact_path"] = json!("/repos/owner/repo/issues");
    meta["allowed_extra_headers"] = json!([]);
    meta["native_plugin"] = plugin;
    meta
}
async fn register(broker: &common::TestBroker, definition: &Value) -> Value {
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        definition.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok()
    .clone()
}
async fn invoke(
    broker: &common::TestBroker,
    token: &str,
    action: &Value,
    title: &str,
) -> common::WireResponse {
    let meta = common::execute_meta(
        token,
        action["id"].as_str().unwrap(),
        action["version"].as_u64().unwrap(),
    );
    common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        json!({"title":title}).to_string().as_bytes(),
    )
    .await
}
fn queue_success(broker: &common::TestBroker) {
    broker.fake.push_response(Ok(response(201,json!({"token":"registered-installation-token","expires_at":"2099-01-01T00:00:00Z","permissions":{"metadata":"read","issues":"write"},"repositories":[{"id":7}],"repository_selection":"selected"}))));
    broker.fake.push_response(Ok(response(201,json!({"id":44,"number":7,"repository_url":"https://api.github.com/repos/owner/repo","html_url":"https://github.com/owner/repo/issues/7"}))));
    broker.fake.push_response(Ok(UpstreamResponse {
        status: 204,
        headers: Vec::new().into(),
        body: Vec::new().into(),
    }));
}
fn assert_effects(broker: &common::TestBroker, title: &str) {
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 3, "exchange, effect, revoke");
    assert_eq!(requests[0].path, "/app/installations/42/access_tokens");
    assert_eq!(
        requests[1].body,
        json!({"title":title}).to_string().as_bytes()
    );
    assert_eq!(requests[2].path, "/installation/token");
    assert_eq!(requests[2].method, "DELETE");
}
fn count_event(broker: &common::TestBroker, event: &str) -> i64 {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type = ?1",
            [event],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_registered_native_artifacts_are_selected_without_packaged_fallback() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = github_credential(&broker).await;
    for (index, path) in native_artifacts().iter().enumerate() {
        let binding = registration(path);
        let action = register(&broker, &plugin_definition(&credential, binding.clone())).await;
        assert_eq!(action["native_plugin"], binding);
        let token = common::create_session(&broker, action["id"].as_str().unwrap(), 1).await;
        let title = if index == 0 {
            "artifact-A"
        } else {
            "artifact-B"
        };
        queue_success(&broker);
        let result = invoke(&broker, &token, &action, title).await;
        assert_eq!(result.ok()["upstream_status"], 201);
        assert_effects(&broker, title);
        // The selected artifact's unique input policy must actually execute.
        let crossed = if index == 0 {
            "artifact-B"
        } else {
            "artifact-A"
        };
        assert_eq!(
            invoke(&broker, &token, &action, crossed).await.err_code(),
            "REQUEST_DENIED"
        );
        assert!(broker.fake.take_requests().is_empty());
    }
    assert_eq!(count_event(&broker, "execution.finished"), 2);
    assert_eq!(count_event(&broker, "connector.github.token_revoked"), 2);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_digest_missing_symlink_and_replaced_artifacts_have_zero_remote_effects() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = github_credential(&broker).await;
    let artifacts = native_artifacts();
    for mode in ["digest", "missing", "symlink", "replaced"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        let mut binding = registration(&artifacts[0]);
        binding["path"] = json!(path);
        match mode {
            "missing" => {}
            "symlink" => std::os::unix::fs::symlink(&artifacts[0], &path).unwrap(),
            _ => {
                std::fs::copy(&artifacts[0], &path).unwrap();
            }
        }
        if mode == "digest" {
            binding["sha256"] = json!("0".repeat(64));
        }
        // Declaration registration intentionally does not probe or run a file.
        let action = register(&broker, &plugin_definition(&credential, binding)).await;
        if mode == "replaced" {
            std::fs::copy(&artifacts[1], &path).unwrap();
        }
        let token = common::create_session(&broker, action["id"].as_str().unwrap(), 1).await;
        let response = invoke(&broker, &token, &action, "artifact-A").await;
        assert_eq!(
            response.message_type,
            rekey_domain::ipc::resp_msg::ERROR,
            "{mode}"
        );
        assert!(response.body.is_empty());
        assert!(broker.fake.take_requests().is_empty(), "{mode}");
    }
    assert_eq!(count_event(&broker, "connector.github.authorized"), 0);
    assert_eq!(count_event(&broker, "execution.blocked"), 4);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_updates_preserve_pinned_version_and_disable_revokes_sessions() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = github_credential(&broker).await;
    let artifacts = native_artifacts();
    let pinned_dir = tempfile::tempdir().unwrap();
    let pinned_path = pinned_dir.path().join("pinned-v1");
    std::fs::copy(&artifacts[0], &pinned_path).unwrap();
    let action = register(
        &broker,
        &plugin_definition(&credential, registration(&pinned_path)),
    )
    .await;
    let id = action["id"].as_str().unwrap();
    let old = common::create_session(&broker, id, 1).await;
    let update = json!({"action_id":id,"definition":plugin_definition(&credential,registration(&artifacts[1]))});
    let v2 = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_UPDATE,
        update.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok()
    .clone();
    assert_eq!(v2["version"], 2);
    queue_success(&broker);
    assert_eq!(
        invoke(&broker, &old, &action, "artifact-A").await.ok()["upstream_status"],
        201
    );
    assert_effects(&broker, "artifact-A");
    assert_eq!(
        invoke(&broker, &old, &action, "artifact-B")
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    assert!(broker.fake.take_requests().is_empty());
    std::fs::copy(&artifacts[1], &pinned_path).unwrap();
    assert_eq!(
        invoke(&broker, &old, &action, "artifact-A")
            .await
            .err_code(),
        "REQUEST_DENIED"
    );
    assert!(
        broker.fake.take_requests().is_empty(),
        "old pin cannot follow replaced bytes"
    );
    let retired = json!({"actions":[{"action_id":id,"version":1}],"ttl_ms":3600000,"max_uses":1});
    let denied = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::SESSION_CREATE,
        retired.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(denied.message_type, rekey_domain::ipc::resp_msg::ERROR);
    let new = common::create_session(&broker, id, 2).await;
    queue_success(&broker);
    assert_eq!(
        invoke(&broker, &new, &v2, "artifact-B").await.ok()["upstream_status"],
        201
    );
    assert_effects(&broker, "artifact-B");
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_DISABLE,
        json!({"action_id":id}).to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    assert_eq!(
        invoke(&broker, &new, &v2, "artifact-B").await.err_code(),
        "INVALID_CAPABILITY"
    );
    assert_eq!(
        invoke(&broker, &old, &action, "artifact-A")
            .await
            .err_code(),
        "INVALID_CAPABILITY"
    );
    assert!(broker.fake.take_requests().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_registration_requires_step_up_and_github_app_credential() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = github_credential(&broker).await;
    let definition = plugin_definition(&credential, registration(&native_artifacts()[0]));
    let rejected = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        definition.to_string().as_bytes(),
        &common::proof_body(b"wrong-proof"),
    )
    .await;
    assert_eq!(rejected.err_code(), "INVALID_UNLOCK_CREDENTIAL");
    let listed = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_LIST,
        b"{}",
        &[],
    )
    .await;
    assert!(listed.ok()["actions"].as_array().unwrap().is_empty());
    assert_eq!(count_event(&broker, "action.created"), 0);
    let opaque = common::add_credential(&broker, "not-a-github-app", b"opaque-token").await;
    let rejected = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_CREATE,
        plugin_definition(&opaque, registration(&native_artifacts()[0]))
            .to_string()
            .as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(rejected.err_code(), "INVALID_INPUT");
    assert_eq!(count_event(&broker, "action.created"), 0);
    let created = register(&broker, &definition).await;
    assert_eq!(created["native_plugin"], definition["native_plugin"]);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_update_audit_failure_rolls_back_binding_and_version() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = github_credential(&broker).await;
    let binding = registration(&native_artifacts()[0]);
    let created = register(&broker, &plugin_definition(&credential, binding.clone())).await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&broker.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_plugin_update BEFORE INSERT ON audit_events WHEN NEW.event_type = 'action.updated' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let update = json!({"action_id":created["id"],"definition":plugin_definition(&credential,registration(&native_artifacts()[1]))});
    let rejected = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_UPDATE,
        update.to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(rejected.err_code(), "AUDIT_COMMIT_FAILED");
    let (count, version, state, stored): (i64, i64, String, String) = db
        .query_row(
            "SELECT count(*),version,state,native_plugin_json FROM actions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((count, version, state.as_str()), (1, 1, "active"));
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), binding);
    assert_eq!(count_event(&broker, "action.updated"), 0);
    assert!(broker.fake.take_requests().is_empty());
    drop(db);
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_binding_roundtrips_admin_list_restart_and_backup_restore() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    let credential = github_credential(&broker).await;
    let binding = registration(&native_artifacts()[0]);
    let created = register(&broker, &plugin_definition(&credential, binding.clone())).await;
    let list = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_LIST,
        b"{}",
        &[],
    )
    .await;
    assert_eq!(list.ok()["actions"][0], created);
    let backup = broker.dir.path().join("registered.rkbackup");
    let receipt = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::BACKUP,
        json!({"output_path":backup}).to_string().as_bytes(),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(receipt.ok()["format_version"], 14);
    let state = broker.state_dir.clone();
    let dir = broker.shutdown_keep_dir().await;
    let config = rekey_broker::runtime::BrokerConfig::new(state.clone());
    let serve = tokio::spawn(async move { rekey_broker::runtime::serve(config).await });
    let socket = state.join("runtime/admin.sock");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    common::call(
        &socket,
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        common::PASSWORD,
    )
    .await
    .ok();
    let list = common::call(&socket, Channel::Admin, admin_msg::ACTION_LIST, b"{}", &[]).await;
    assert_eq!(list.ok()["actions"][0], created);
    common::call(
        &socket,
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let restored = dir.path().join("restored");
    rekey_vault::bootstrap::restore_vault(
        &backup,
        &restored,
        rekey_vault::bootstrap::RestoreProof::Password(
            rekey_vault::secret::SecretInput::from_slice(common::PASSWORD),
        ),
        receipt.ok()["sha256_hex"].as_str().unwrap(),
    )
    .unwrap();
    let (authority, join) = rekey_vault::authority::spawn_authority(
        rekey_vault::handle::AuthorityConfig::new(restored),
    )
    .unwrap();
    authority
        .unlock(rekey_vault::command::UnlockProof::Password(
            rekey_vault::secret::SecretInput::from_slice(common::PASSWORD),
        ))
        .await
        .unwrap();
    let pinned = authority
        .action_get(created["id"].as_str().unwrap().parse().unwrap(), 1)
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(pinned.action).unwrap(), created);
    authority
        .shutdown(Some(rekey_vault::command::UnlockProof::Password(
            rekey_vault::secret::SecretInput::from_slice(common::PASSWORD),
        )))
        .await
        .unwrap();
    join.join().unwrap();
}

#[path = "github_issue_plugin/attacks.rs"]
mod attacks;
