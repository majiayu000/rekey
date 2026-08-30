//! Secret canary: after a full lifecycle, the canary value must appear
//! nowhere on disk, in audit rows, or in agent-visible output — only inside
//! the upstream request the broker itself constructed.

use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
use rekey_integration::harness as h;

const CANARY: &[u8] = b"CANARY-9f8e7d6c5b4a-SECRET-VALUE";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn canary_never_escapes() {
    let broker = h::start_broker().await;
    h::unlock(&broker).await;
    let credential_id = h::add_credential(&broker, "canary", CANARY).await;
    let (action_id, version) = h::create_action(&broker, &credential_id).await;
    let token = h::create_session(&broker, &action_id, version).await;

    // One successful execution.
    let meta = h::execute_meta(&token, &action_id, version);
    let response = h::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        meta.to_string().as_bytes(),
        b"{}",
    )
    .await;
    response.ok();
    assert!(!contains(&response.body, CANARY));
    assert!(
        !response
            .metadata
            .to_string()
            .as_bytes()
            .windows(CANARY.len())
            .any(|w| w == CANARY)
    );

    // One rotation and one failed unlock so error paths are exercised too.
    let rotate_meta = serde_json::json!({ "credential_id": credential_id });
    h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_ROTATE,
        rotate_meta.to_string().as_bytes(),
        &h::proof_and_secret_body(h::PASSWORD, CANARY),
    )
    .await
    .ok();
    let response = h::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::UNLOCK_PASSWORD,
        b"{}",
        b"wrong",
    )
    .await;
    assert!(!response.metadata.to_string().contains("CANARY"));

    // The only place the canary may exist in plaintext: the upstream request
    // the broker constructed.
    let requests = broker.fake.take_requests();
    assert!(requests.iter().any(|r| contains(&r.auth_value, CANARY)));

    let state_dir = broker.state_dir.clone();
    let _dir = broker.shutdown_keep_dir().await;

    // Scan every file in the state directory: ciphertext only.
    let mut scanned = 0;
    for entry in walk(&state_dir) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        assert!(
            !contains(&bytes, CANARY),
            "plaintext canary found in {}",
            entry.display()
        );
        scanned += 1;
    }
    assert!(scanned >= 1, "expected at least the vault db to be scanned");

    // Audit rows: identifiers and codes only.
    let store =
        rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state_dir))
            .unwrap();
    for event_type in store.audit_event_types().unwrap() {
        assert!(!event_type.contains("CANARY"));
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk(&path));
            } else {
                files.push(path);
            }
        }
    }
    files
}
