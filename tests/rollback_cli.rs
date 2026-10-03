//! Actual CLI + Broker rollback confirmation and offline inspect/restore.
//! Synthetic vault only: no system Keychain, profile or real credentials.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};
use rekey_integration::harness::{PASSWORD, call, start_broker};
use rekey_vault::generation_anchor::GenerationAnchors;
use rekey_vault::store::SqliteRecordStore;
use serde_json::{Value, json};

fn binary() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rekey")
}
async fn cli(state: &Path, args: &[&str], proof: &[u8]) -> Output {
    let state = state.to_owned();
    let args: Vec<_> = args.iter().map(|s| (*s).to_owned()).collect();
    let proof = proof.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(binary())
            .arg("--state-dir")
            .arg(state)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut input) = child.stdin.take() {
            // Invalid arguments may terminate before the password is consumed.
            let _ = input.write_all(&proof);
            let _ = input.write_all(b"\n");
        }
        let output = child.wait_with_output().unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!bytes.windows(PASSWORD.len()).any(|s| s == PASSWORD));
        }
        output
    })
    .await
    .unwrap()
}
fn ok(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn error(output: Output, code: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with(&format!("error [{code}]: ")), "{stderr}");
}
fn database_bytes(state: &Path) -> Vec<Option<Vec<u8>>> {
    ["vault.sqlite3", "vault.sqlite3-wal"]
        .into_iter()
        .map(|p| std::fs::read(state.join(p)).ok())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_cli_requires_separate_confirmation_and_restores_at_a_new_generation() {
    let broker = start_broker().await;
    let state = &broker.state_dir;
    ok(cli(state, &["unlock", "--password-stdin"], PASSWORD).await);
    let header = SqliteRecordStore::open(&rekey_vault::paths::vault_db(state))
        .unwrap()
        .load_header()
        .unwrap();
    let anchors = GenerationAnchors::open(state, header.vault_id).unwrap();
    anchors
        .reserve(anchors.read().unwrap(), header.generation + 1, &mut false)
        .unwrap();
    error(
        cli(state, &["unlock", "--password-stdin"], PASSWORD).await,
        "ROLLBACK_SUSPECTED",
    );
    let status = ok(cli(state, &["status"], b"").await);
    assert_eq!(status["state"], "rollback-suspected");
    assert_eq!(status["sessions_active"], 0);
    let expected = status["rollback"].clone();
    assert_eq!(expected["source_generation"], header.generation);
    assert_eq!(expected["high_water"], header.generation + 1);
    assert_eq!(expected["history_missing"], false);
    ok(cli(state, &["lock"], b"").await);
    assert_eq!(ok(cli(state, &["status"], b"").await)["rollback"], expected);
    let database = database_bytes(state);
    let observed = anchors.read().unwrap();
    let metadata = json!({"expected": expected}).to_string();
    let mut presence = Vec::new();
    ipc::encode_proof_body(ProofKind::Presence, b"SYNTHETIC-PRESENCE", &mut presence);
    assert_eq!(
        call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::ROLLBACK_CONFIRM,
            metadata.as_bytes(),
            &presence
        )
        .await
        .err_code(),
        "INVALID_FRAME"
    );
    let encoded = expected.to_string();
    let args = [
        "rollback-confirm",
        "--expected-context",
        &encoded,
        "--password-stdin",
    ];
    error(
        cli(state, &args, b"wrong-proof").await,
        "INVALID_UNLOCK_CREDENTIAL",
    );
    assert_eq!(
        database_bytes(state),
        database,
        "wrong confirmation proof wrote database"
    );
    assert_eq!(anchors.read().unwrap(), observed);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut stale = expected.clone();
    stale["source_generation"] = (header.generation + 1).into();
    error(
        cli(
            state,
            &[
                "rollback-confirm",
                "--expected-context",
                &stale.to_string(),
                "--password-stdin",
            ],
            PASSWORD,
        )
        .await,
        "ROLLBACK_SUSPECTED",
    );
    assert_eq!(database_bytes(state), database);
    assert_eq!(
        ok(cli(state, &args, PASSWORD).await),
        json!({"locked":true})
    );
    let locked = ok(cli(state, &["status"], b"").await);
    assert_eq!(locked["state"], "locked");
    assert_eq!(locked["rollback"], Value::Null);
    error(cli(state, &args, PASSWORD).await, "ROLLBACK_SUSPECTED");
    ok(cli(state, &["unlock", "--password-stdin"], PASSWORD).await);
    let live_database = database_bytes(state);
    error(
        cli(state, &args, b"wrong-proof").await,
        "ROLLBACK_SUSPECTED",
    );
    assert_eq!(
        database_bytes(state),
        live_database,
        "stale confirmation changed an ordinary unlocked vault"
    );
    assert_eq!(ok(cli(state, &["status"], b"").await)["state"], "unlocked");
    let archive = broker.dir.path().join("snapshot.rkbackup");
    let receipt = ok(cli(
        state,
        &[
            "backup",
            "--output",
            archive.to_str().unwrap(),
            "--password-stdin",
        ],
        PASSWORD,
    )
    .await);
    assert_eq!(receipt["generation"], header.generation + 2);
    let target = broker.dir.path().join("restored");
    let digest = receipt["sha256_hex"].as_str().unwrap();
    let restore_args = [
        "restore",
        "--input",
        archive.to_str().unwrap(),
        "--sha256",
        digest,
        "--password-stdin",
    ];
    let rejected = cli(&target, &restore_args, PASSWORD).await;
    assert!(!rejected.status.success());
    assert!(!rekey_vault::paths::vault_db(&target).exists());
    let mut inspect_args = restore_args.to_vec();
    inspect_args.push("--inspect");
    let preview = ok(cli(&target, &inspect_args, PASSWORD).await);
    assert_eq!(preview["source_generation"], header.generation + 2);
    assert_eq!(preview["high_water"], Value::Null);
    assert_eq!(preview["history_missing"], true);
    assert!(!rekey_vault::paths::vault_db(&target).exists());
    assert_eq!(
        GenerationAnchors::open(&target, header.vault_id)
            .unwrap()
            .read()
            .unwrap()
            .file,
        None
    );
    let source_before = std::fs::read(&archive).unwrap();
    let context = preview.to_string();
    let mut restore_args = restore_args.to_vec();
    restore_args.extend(["--expected-context", &context]);
    let restored = ok(cli(&target, &restore_args, PASSWORD).await);
    assert_eq!(restored["generation"], header.generation + 3);
    assert_eq!(std::fs::read(&archive).unwrap(), source_before);
    assert_eq!(
        GenerationAnchors::open(&target, header.vault_id)
            .unwrap()
            .read()
            .unwrap()
            .file,
        Some(header.generation + 3)
    );
    let _ = broker.shutdown_keep_dir().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_mutation_rollback_revokes_existing_session_before_error_reply() {
    use rekey_integration::harness::{
        add_credential, create_action, create_session, execute_meta, proof_and_secret_body,
    };
    let broker = start_broker().await;
    let state = &broker.state_dir;
    ok(cli(state, &["unlock", "--password-stdin"], PASSWORD).await);
    let credential = add_credential(
        &broker,
        "rollback-mutation",
        b"SYNTHETIC-ROLLBACK-CREDENTIAL",
    )
    .await;
    let (action, version) = create_action(&broker, &credential).await;
    let token = create_session(&broker, &action, version).await;
    assert_eq!(ok(cli(state, &["status"], b"").await)["sessions_active"], 1);
    let header = SqliteRecordStore::open(&rekey_vault::paths::vault_db(state))
        .unwrap()
        .load_header()
        .unwrap();
    let anchors = GenerationAnchors::open(state, header.vault_id).unwrap();
    anchors
        .reserve(anchors.read().unwrap(), header.generation + 1, &mut false)
        .unwrap();
    let result = call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE,
        json!({"credential_id":credential}).to_string().as_bytes(),
        &proof_and_secret_body(PASSWORD, b"SYNTHETIC-ROTATED-ROLLBACK-CREDENTIAL"),
    )
    .await;
    assert_eq!(result.err_code(), "ROLLBACK_SUSPECTED");
    let status = ok(cli(state, &["status"], b"").await);
    assert_eq!(status["state"], "rollback-suspected");
    assert_eq!(status["sessions_active"], 0);
    let result = call(
        &broker.agent_sock(),
        Channel::Agent,
        ipc::agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        execute_meta(&token, &action, version)
            .to_string()
            .as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(result.message_type, ipc::resp_msg::ERROR);
    assert!(broker.fake.requests.lock().unwrap().is_empty());
    let context = status["rollback"].to_string();
    ok(cli(
        state,
        &[
            "rollback-confirm",
            "--expected-context",
            &context,
            "--password-stdin",
        ],
        PASSWORD,
    )
    .await);
    ok(cli(state, &["unlock", "--password-stdin"], PASSWORD).await);
    assert_eq!(ok(cli(state, &["status"], b"").await)["sessions_active"], 0);
    let _ = broker.shutdown_keep_dir().await;
}
