//! Real CLI + Broker/Authority/SQLite over UDS, with the existing fake upstream.
//! Synthetic Team vault and Presence key only; no Keychain, SE or Internet.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId};
use rekey_domain::ipc::{Channel, LOCAL_APPROVAL_REVIEW_HASH_PREFIX, admin_msg};
use rekey_integration::harness::{PASSWORD, TestBroker, call, start_broker};
use serde_json::{Value, json};

const SECRET: &str = "LOCAL-APPROVAL-CLI-SYNTHETIC-CREDENTIAL";

fn cli_binary() -> PathBuf {
    // Integration tests live in <custom target>/<profile>/deps. Require the
    // CLI from the same build, never another checkout's hard-coded target.
    let executable = std::env::current_exe().unwrap();
    let binary = executable.parent().unwrap().parent().unwrap().join("rekey");
    assert!(
        binary.is_file(),
        "build rekey in this target before this test"
    );
    binary
}

async fn cli(state: &Path, args: &[&str], stdin: &str) -> Output {
    let state = state.to_owned();
    let args: Vec<_> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let stdin = stdin.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(cli_binary())
            .arg("--state-dir")
            .arg(state)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            for canary in [PASSWORD, SECRET.as_bytes()] {
                assert!(!bytes.windows(canary.len()).any(|part| part == canary));
            }
        }
        output
    })
    .await
    .unwrap()
}

fn success(output: Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn approval_required(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "APPROVAL_REQUIRED");
    assert_eq!(error["retryable"], false);
    assert!(error["approval"]["expires_at_ms"].as_i64().unwrap() > 0);
    error["approval"]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn upstream_count(broker: &TestBroker) -> usize {
    broker.fake.requests.lock().unwrap().len()
}

async fn session(broker: &TestBroker, action: &str, principal: &str, proof: &str) -> String {
    let result = success(
        cli(
            &broker.state_dir,
            &[
                "session",
                "create",
                "--action",
                action,
                "--principal",
                principal,
                "--ttl",
                "10m",
                "--max-uses",
                "1",
                "--password-stdin",
            ],
            proof,
        )
        .await,
    );
    assert_eq!(result["max_uses"], 1);
    result["capability_token"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_cli_local_approval_preserves_last_use_and_executes_only_once() {
    let broker = start_broker().await;
    let state = &broker.state_dir;
    let proof = format!("{}\n", std::str::from_utf8(PASSWORD).unwrap());
    success(cli(state, &["unlock", "--password-stdin"], &proof).await);
    let credential = success(
        cli(
            state,
            &["credential", "add", "local fixture", "--stdin-secrets"],
            &format!("{proof}{SECRET}\n"),
        )
        .await,
    );
    let action_file = broker.dir.path().join("action.json");
    std::fs::write(
        &action_file,
        json!({
            "name":"Local CLI fixture", "credential_id":credential["id"],
            "origin":"https://api.example.com", "method":"POST", "exact_path":"/v1/local",
            "auth_header":"authorization", "auth_prefix":"Bearer ", "timeout_ms":10000,
            "request_max_bytes":4096, "allowed_extra_headers":[], "response_max_bytes":4096,
            "allowed_response_headers":["content-type"]
        })
        .to_string(),
    )
    .unwrap();
    let action = success(
        cli(
            state,
            &[
                "action",
                "create",
                "--file",
                action_file.to_str().unwrap(),
                "--password-stdin",
            ],
            &proof,
        )
        .await,
    );
    let action_ref = format!("{}@{}", action["id"].as_str().unwrap(), action["version"]);
    let principal = PrincipalId::new_random().to_string();
    let signer_id = PolicySignerId::new_random();
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let trust = json!({"format_version":1,"signer_id":signer_id,"algorithm":"ed25519",
        "public_key":HEXLOWER.encode(signer.public_key().as_ref())});
    let status = success(
        cli(
            state,
            &[
                "policy",
                "trust",
                "install",
                "--stdin-request",
                "--step-up-stdin",
            ],
            &format!("{proof}{trust}\n"),
        )
        .await,
    );
    let resource = json!({"type":"fixed-http-action","id":action["id"]});
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 600_000;
    let mut bundle = json!({"format_version":1,"signer_id":signer_id,"snapshot":{
        "format_version":4,"version":1,"expires_at_ms":expires,"approvers":[],"workload_identities":[],
        "bindings":[{"action_id":action["id"],"version":action["version"],"resource":resource,
            "parameter_schema_id":"local-cli/v1","parameter_schema":{"type":"object",
                "required":["message"],"properties":{"message":{"type":"string"}},"additionalProperties":false}}],
        "rules":[{"id":PolicyRuleId::new_random(),"effect":"require-approval","principal_id":principal,
            "action_id":action["id"],"version":action["version"],"resource":resource,
            "parameters":{"kind":"any_validated"},"approver":{"kind":"local-presence"},
            "approval":{"mode":"one-time","max_uses":1}}]
    }});
    let mut sign_bytes = b"RKPOLICY\0\x01".to_vec();
    sign_bytes.extend(serde_jcs::to_vec(&bundle).unwrap());
    bundle["signature"] = BASE64URL_NOPAD
        .encode(signer.sign(&sign_bytes).as_ref())
        .into();
    success(
        cli(
            state,
            &[
                "policy",
                "activate",
                "--stdin-request",
                "--step-up-stdin",
                "--expected-vault-id",
                status["vault_id"].as_str().unwrap(),
                "--expected-trust-sha256",
                status["trust_sha256"].as_str().unwrap(),
            ],
            &format!("{proof}{bundle}\n"),
        )
        .await,
    );
    let owner = session(&broker, &action_ref, &principal, &proof).await;
    let other = session(&broker, &action_ref, &principal, &proof).await;
    let remembered = cli(state, &["desktop-remember"], &proof).await;
    assert!(remembered.status.success());
    let remembered = String::from_utf8(remembered.stdout).unwrap();
    let (_, presence) = remembered.split_once('\n').unwrap();
    assert_eq!(presence.len(), 64);
    let presence_input = format!("{presence}\n");
    let body_file = broker.dir.path().join("request.json");
    let request_body = b"{\"message\":\"review the complete request\"}";
    std::fs::write(&body_file, request_body).unwrap();
    let execute = [
        "execute",
        &action_ref,
        "--capability",
        "-",
        "--body-file",
        body_file.to_str().unwrap(),
        "--content-type",
        "application/json",
    ];
    let owner_input = format!("{owner}\n");
    let other_input = format!("{other}\n");
    let id = approval_required(cli(state, &execute, &owner_input).await);
    assert_eq!(upstream_count(&broker), 0);
    // Repeating the waiting request returns its challenge and refunds the
    // reservation again: max_uses=1 remains available for the actual execution.
    assert_eq!(
        approval_required(cli(state, &execute, &owner_input).await),
        id
    );
    let review = success(cli(state, &["approval", "review", &id], "").await);
    assert_eq!(
        review["metadata"]["record_type"],
        "rekey.approval.local-review.v1"
    );
    assert_eq!(review["metadata"]["state"], "pending");
    let raw = review["review_json"].as_str().unwrap().as_bytes();
    let direct = call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        json!({"approval_request_id":id}).to_string().as_bytes(),
        &[],
    )
    .await;
    direct.ok();
    assert_eq!(raw, direct.body);
    assert_eq!(
        review["metadata"]["body_len"].as_u64().unwrap() as usize,
        raw.len()
    );
    let mut hash_bytes = LOCAL_APPROVAL_REVIEW_HASH_PREFIX.to_vec();
    hash_bytes.extend(raw);
    let review_hash = HEXLOWER.encode(digest(&SHA256, &hash_bytes).as_ref());
    assert_eq!(review["metadata"]["review_sha256"], review_hash);
    let decoded: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(decoded["record_type"], "rekey.approval.review.v1");
    assert_eq!(decoded["challenge"]["approval_request_id"], id);
    assert_eq!(decoded["challenge"]["approver"]["kind"], "local-presence");
    assert_eq!(
        decoded["canonical_request"]["body"],
        serde_json::from_slice::<Value>(request_body).unwrap()
    );
    for canary in [SECRET, presence, &owner, &other] {
        assert!(!std::str::from_utf8(raw).unwrap().contains(canary));
    }
    let approve = [
        "approval",
        "approve",
        &id,
        "--review-sha256",
        &review_hash,
        "--presence",
        "--password-stdin",
    ];
    let wrong = cli(state, &approve, &format!("{}\n", "0".repeat(64))).await;
    assert_eq!(wrong.status.code(), Some(3));
    assert_eq!(
        success(cli(state, &["approval", "review", &id], "").await)["metadata"]["state"],
        "pending"
    );
    let foreign = cli(
        state,
        &["approval", "cancel", &id, "--capability", "-"],
        &other_input,
    )
    .await;
    assert_eq!(foreign.status.code(), Some(4));
    assert_eq!(
        success(cli(state, &approve, &presence_input).await)["state"],
        "approved"
    );
    assert_eq!(
        success(
            cli(
                state,
                &["approval", "await", &id, "--capability", "-"],
                &owner_input
            )
            .await
        )["state"],
        "approved"
    );
    assert_eq!(upstream_count(&broker), 0);
    let mut retry = execute.to_vec();
    retry.extend(["--challenge", &id]);
    let executed = cli(state, &retry, &owner_input).await;
    assert_eq!(
        executed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert!(
        String::from_utf8(executed.stdout)
            .unwrap()
            .contains("{\"ok\":true}")
    );
    assert_eq!(upstream_count(&broker), 1);
    {
        let requests = broker.fake.requests.lock().unwrap();
        assert_eq!(requests[0].path, "/v1/local");
        assert_eq!(requests[0].body, request_body);
        assert_eq!(
            requests[0].auth_value,
            format!("Bearer {SECRET}").as_bytes()
        );
    }
    let replay = cli(state, &retry, &owner_input).await;
    assert_eq!(replay.status.code(), Some(4));
    assert_eq!(upstream_count(&broker), 1);
    assert_eq!(
        success(cli(state, &["approval", "review", &id], "").await)["metadata"]["state"],
        "consumed"
    );

    // The other owner can cancel its own pending challenge, but cancellation
    // never causes an upstream request or an implicitly retried execution.
    let cancelled_id = approval_required(cli(state, &execute, &other_input).await);
    assert_eq!(
        success(
            cli(
                state,
                &["approval", "cancel", &cancelled_id, "--capability", "-"],
                &other_input
            )
            .await
        )["state"],
        "cancelled"
    );
    assert_eq!(
        success(
            cli(
                state,
                &["approval", "await", &cancelled_id, "--capability", "-"],
                &other_input
            )
            .await
        )["state"],
        "cancelled"
    );
    let cancelled_review = success(cli(state, &["approval", "review", &cancelled_id], "").await);
    assert_eq!(cancelled_review["metadata"]["state"], "cancelled");
    let mut cancelled_retry = execute.to_vec();
    cancelled_retry.extend(["--challenge", &cancelled_id]);
    assert_eq!(
        cli(state, &cancelled_retry, &other_input)
            .await
            .status
            .code(),
        Some(4)
    );
    assert_eq!(upstream_count(&broker), 1);
    success(cli(state, &["shutdown", "--password-stdin"], &proof).await);
    broker.serve_task.await.unwrap();
}
