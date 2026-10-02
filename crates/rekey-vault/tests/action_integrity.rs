//! Synthetic format-22 Action rows: authenticated lifecycle and copy boundaries.
mod common;

use std::collections::BTreeSet;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use rekey_domain::action::{
    ActionName, ActionTarget, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{ActionId, CredentialId, VaultId};
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::command::ActionDefinition;
use rekey_vault::crypto::{
    aad::{AadPurpose, AadV1},
    action_state, aead,
    kdf::Argon2Params,
};
use rekey_vault::error::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::{ActionRecord, ActionState, WrapperKind};
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use rusqlite::{Connection, params};
use serde_json::json;
use zeroize::Zeroizing;

fn definition(credential_id: CredentialId) -> ActionDefinition {
    ActionDefinition {
        native_plugin: None, text_stream: None,
        name: ActionName::new("sealed-template").unwrap(), credential_id,
        origin: HttpsOrigin::parse("https://api.example.com").unwrap(), method: FixedMethod::Post,
        target: serde_json::from_value(json!({
            "kind":"template", "target":{"path":"/repos/acme/issues/{number}","params":{"number":"int:1..100"},"query":{"state":"enum:open,closed"}},
            "fixed_headers":{"x-fixed":"one"}, "body_schema":{"type":"object","properties":{"title":{"type":"string"}}},
            "source":{"template":"team@1","capability":"issues","action_index":0,"digest":vec![7;32],"signer_id":null},
            "default_policy":{"rule":"allow"}
        })).unwrap(),
        auth: HeaderCredentialUse::new(HeaderName::new("authorization").unwrap(), HeaderPrefix::new("Bearer ").unwrap()).unwrap(),
        timeout_ms: 1000,
        request_policy: RequestPolicy { max_body_bytes: 1024, allowed_extra_headers: BTreeSet::new() },
        response_policy: ResponsePolicy { max_body_bytes: 1024, allowed_headers: BTreeSet::new() },
    }
}

async fn seed(handle: &AuthorityHandle) -> (CredentialId, rekey_domain::action::FixedHttpAction) {
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("synthetic-token").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic-action-integrity-token"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let action = handle
        .action_upsert(None, definition(credential.id), common::password_proof())
        .await
        .unwrap();
    (credential.id, action)
}

fn root_key(store: &SqliteRecordStore) -> (VaultId, Zeroizing<[u8; 32]>) {
    let header = store.load_header().unwrap();
    let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
    let params = Argon2Params::from_json(&wrapper.kdf_params_json).unwrap();
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(32),
        )
        .unwrap(),
    );
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(common::PASSWORD, &wrapper.salt, &mut *kek)
        .unwrap();
    let aad = AadV1 {
        purpose: AadPurpose::WrapVrk,
        vault_id: header.vault_id,
        object_id: *wrapper.wrapper_id.as_bytes(),
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0; 32],
    }
    .encode();
    let plain = aead::open(&kek, &aad, &wrapper.nonce, &wrapper.wrapped_vrk).unwrap();
    (
        header.vault_id,
        Zeroizing::new(plain.as_slice().try_into().unwrap()),
    )
}

fn verified_rows(path: &Path) -> Vec<ActionRecord> {
    let store = SqliteRecordStore::open(path).unwrap();
    let (vault_id, key) = root_key(&store);
    let rows = store.list_all_actions().unwrap();
    for row in &rows {
        action_state::verify(&key, vault_id, row).unwrap();
        rekey_vault::convert::record_to_action(row).unwrap();
    }
    rows
}

async fn finish(handle: AuthorityHandle, join: std::thread::JoinHandle<()>) {
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn raw_row_seal_covers_every_field_and_cross_row_identity() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let (_, action) = seed(&handle).await;
    let store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let (vault_id, key) = root_key(&store);
    let row = store.get_action(action.id, 1).unwrap();
    action_state::verify(&key, vault_id, &row).unwrap();
    let mutations: Vec<fn(&mut ActionRecord)> = vec![
        |r| r.action_id = ActionId::new_random(),
        |r| r.version += 1,
        |r| r.name.push('x'),
        |r| r.state = ActionState::Retired,
        |r| r.credential_id = CredentialId::new_random(),
        |r| r.origin = "https://other.example.com".into(),
        |r| r.method = "PUT".into(),
        |r| r.target_json.push(' '),
        |r| r.auth_header = "x-api-key".into(),
        |r| r.auth_prefix = "Token ".into(),
        |r| r.request_max_bytes += 1,
        |r| r.allowed_extra_headers_json = "[\"x-new\"]".into(),
        |r| r.response_max_bytes += 1,
        |r| r.allowed_response_headers_json = "[\"content-type\"]".into(),
        |r| r.timeout_ms += 1,
        |r| r.created_at_ms += 1,
        |r| r.native_plugin_json = Some("{}".into()),
        |r| r.text_stream_json = Some("{}".into()),
        |r| r.seal_nonce[0] ^= 1,
        |r| r.seal_ciphertext[0] ^= 1,
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut bad = row.clone();
        mutate(&mut bad);
        assert!(
            matches!(
                action_state::verify(&key, vault_id, &bad),
                Err(AuthorityError::StorageIntegrityFailed)
            ),
            "field {index}"
        );
    }
    assert!(action_state::verify(&key, VaultId::new_random(), &row).is_err());
    assert!(action_state::verify(&[0; 32], vault_id, &row).is_err());
    assert_eq!(AadPurpose::ActionState.code(), 13);
    finish(handle, join).await;
}

#[tokio::test]
async fn legal_template_row_rewrites_fail_before_read_and_fault_worker() {
    let changes = [
        ("/target/path", json!("/other/{number}")),
        ("/target/params/number", json!("int:1..101")),
        ("/target/query/state", json!("enum:open,closed,all")),
        ("/fixed_headers/x-fixed", json!("two")),
        ("/body_schema/properties/title/type", json!("integer")),
        ("/source/template", json!("team@2")),
        ("/source/capability", json!("other")),
        ("/source/action_index", json!(1)),
        ("/source/digest/0", json!(8)),
        (
            "/source/signer_id",
            json!(rekey_domain::ids::PolicySignerId::new_random()),
        ),
        (
            "/default_policy",
            json!({"rule":"require-approval","approver":{"kind":"local-presence"}}),
        ),
    ];
    for (pointer, value) in changes {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let (_, action) = seed(&handle).await;
        let mut target = serde_json::to_value(&action.target).unwrap();
        *target.pointer_mut(pointer).unwrap() = value;
        let mut valid = action.clone();
        valid.target = serde_json::from_value(target.clone()).unwrap();
        valid.validate().unwrap(); // This is valid syntax, not a parser-only rejection.
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        db.execute(
            "UPDATE actions SET target_json=?1",
            [serde_json::to_string(&target).unwrap()],
        )
        .unwrap();
        assert!(
            matches!(
                handle.action_get(action.id, 1).await,
                Err(AuthorityError::StorageIntegrityFailed)
            ),
            "{pointer}"
        );
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        finish(handle, join).await;
    }
}

#[tokio::test]
async fn retired_disabled_and_active_versions_survive_rotation_and_both_backup_generations() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let (credential, first) = seed(&handle).await;
    let mut fixed = definition(credential);
    fixed.target = ActionTarget::Fixed {
        path: ExactPath::parse("/fixed").unwrap(),
    };
    let second = handle
        .action_upsert(Some(first.id), fixed, common::password_proof())
        .await
        .unwrap();
    handle
        .action_disable(second.id, common::password_proof())
        .await
        .unwrap();
    let active = handle
        .action_upsert(None, definition(credential), common::password_proof())
        .await
        .unwrap();
    let before = verified_rows(&paths::vault_db(&vault.state_dir));
    assert_eq!(before.len(), 3);
    let old = handle.action_get(first.id, 1).await.unwrap();
    assert_eq!(old.state, ActionState::Retired);
    assert!(old.action.enabled);
    let old_backup = vault.dir.path().join("old.rkbackup");
    handle
        .backup(old_backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle.lock("action-test").await.unwrap();
    assert!(matches!(
        handle.action_get(first.id, 1).await,
        Err(AuthorityError::Locked)
    ));
    assert!(matches!(
        handle.action_ids_for_credential(credential).await,
        Err(AuthorityError::Locked)
    ));
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle
        .rotate_vrk_before(
            common::password_input(),
            SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
            None,
        )
        .await
        .unwrap();
    let after = verified_rows(&paths::vault_db(&vault.state_dir));
    let store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let (vault_id, key) = root_key(&store);
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(
            (old.action_id, old.version, old.state, &old.target_json),
            (new.action_id, new.version, new.state, &new.target_json)
        );
        assert_ne!(
            (old.seal_nonce, old.seal_ciphertext),
            (new.seal_nonce, new.seal_ciphertext)
        );
        assert!(action_state::verify(&key, vault_id, old).is_err());
    }
    handle.unlock(common::password_proof()).await.unwrap();
    let new_backup = vault.dir.path().join("new.rkbackup");
    handle
        .backup(new_backup.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;
    for (index, backup) in [old_backup, new_backup].iter().enumerate() {
        let target = vault.dir.path().join(format!("restore-{index}"));
        restore_vault(
            backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &rekey_vault::durable::sha256_file(backup).unwrap(),
        )
        .unwrap();
        assert_eq!(verified_rows(&paths::vault_db(&target)).len(), 3);
        let (restored, join) = common::spawn(&target);
        restored.unlock(common::password_proof()).await.unwrap();
        assert_eq!(
            restored.action_get(first.id, 1).await.unwrap().state,
            ActionState::Retired
        );
        assert!(
            !restored
                .action_get(second.id, 2)
                .await
                .unwrap()
                .action
                .enabled
        );
        assert!(
            restored
                .action_get(active.id, 1)
                .await
                .unwrap()
                .action
                .enabled
        );
        finish(restored, join).await;
    }
}

#[tokio::test]
async fn forged_retired_rows_block_mutations_lists_rotation_and_backup() {
    for operation in ["update", "disable", "list", "ids", "rotation", "backup"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let (credential, first) = seed(&handle).await;
        handle
            .action_upsert(
                Some(first.id),
                definition(credential),
                common::password_proof(),
            )
            .await
            .unwrap();
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        db.execute(
            "UPDATE actions SET name='valid-retired-rewrite' WHERE version=1",
            [],
        )
        .unwrap();
        let output = vault.dir.path().join("must-not-release.rkbackup");
        let result = match operation {
            "update" => handle
                .action_upsert(
                    Some(first.id),
                    definition(credential),
                    common::password_proof(),
                )
                .await
                .map(|_| ()),
            "disable" => {
                handle
                    .action_disable(first.id, common::password_proof())
                    .await
            }
            "list" => handle.action_list().await.map(|_| ()),
            "ids" => handle
                .action_ids_for_credential(credential)
                .await
                .map(|_| ()),
            "rotation" => {
                handle.lock("action-test").await.unwrap();
                handle
                    .rotate_vrk_before(
                        common::password_input(),
                        SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
                        None,
                    )
                    .await
                    .map(|_| ())
            }
            "backup" => handle
                .backup(output.clone(), common::password_proof())
                .await
                .map(|_| ()),
            _ => unreachable!(),
        };
        assert!(
            matches!(result, Err(AuthorityError::StorageIntegrityFailed)),
            "{operation}: {result:?}"
        );
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert!(!output.exists());
        assert!(!paths::backup_snapshot(&vault.state_dir).exists());
        finish(handle, join).await;
    }
}

#[tokio::test]
async fn restore_rejects_forged_actions_in_every_lifecycle_state() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let (credential, first) = seed(&handle).await;
    handle
        .action_upsert(
            Some(first.id),
            definition(credential),
            common::password_proof(),
        )
        .await
        .unwrap();
    handle
        .action_disable(first.id, common::password_proof())
        .await
        .unwrap();
    handle
        .action_upsert(None, definition(credential), common::password_proof())
        .await
        .unwrap();
    let backup = vault.dir.path().join("valid.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;
    for state in ["active", "retired", "disabled"] {
        let forged = vault.dir.path().join(format!("{state}.rkbackup"));
        std::fs::copy(&backup, &forged).unwrap();
        let db = Connection::open(&forged).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE actions SET origin='https://other.example.com' WHERE state=?1",
                [state]
            )
            .unwrap(),
            1
        );
        drop(db);
        let target = vault.dir.path().join(format!("restore-{state}"));
        assert!(
            matches!(
                restore_vault(
                    &forged,
                    &target,
                    RestoreProof::Password(common::password_input()),
                    &rekey_vault::durable::sha256_file(&forged).unwrap()
                ),
                Err(AuthorityError::StorageIntegrityFailed)
            ),
            "{state}"
        );
        assert!(!paths::vault_db(&target).exists());
    }
}

#[tokio::test]
async fn transplanted_seals_between_real_actions_and_versions_are_rejected() {
    for across_version in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let (credential, first) = seed(&handle).await;
        let second = handle
            .action_upsert(
                across_version.then_some(first.id),
                definition(credential),
                common::password_proof(),
            )
            .await
            .unwrap();
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        let (nonce, tag): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT seal_nonce,seal_ciphertext FROM actions WHERE action_id=?1 AND version=?2",
                params![second.id.as_bytes().as_slice(), second.version],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        db.execute(
            "UPDATE actions SET seal_nonce=?1,seal_ciphertext=?2 WHERE action_id=?3 AND version=1",
            params![nonce, tag, first.id.as_bytes().as_slice()],
        )
        .unwrap();
        assert!(matches!(
            handle.action_get(first.id, 1).await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        finish(handle, join).await;
    }
}

#[tokio::test]
async fn format_twenty_one_is_rejected_before_new_action_layout_is_read() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    seed(&handle).await;
    let backup = vault.dir.path().join("v21.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;
    let db = Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 21') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=21", [])
        .unwrap();
    drop(db);
    assert!(matches!(
        SqliteRecordStore::open(&backup),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    let target = vault.dir.path().join("restore-v21");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &rekey_vault::durable::sha256_file(&backup).unwrap()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!paths::vault_db(&target).exists());
}

#[tokio::test]
async fn ignored_action_writes_and_failed_audit_roll_back_seals_and_state() {
    for (trigger, disable) in [
        (
            "CREATE TRIGGER fail_action BEFORE INSERT ON actions BEGIN SELECT RAISE(IGNORE); END",
            false,
        ),
        (
            "CREATE TRIGGER fail_action BEFORE UPDATE ON actions BEGIN SELECT RAISE(IGNORE); END",
            false,
        ),
        (
            "CREATE TRIGGER fail_action BEFORE UPDATE ON actions BEGIN SELECT RAISE(IGNORE); END",
            true,
        ),
        (
            "CREATE TRIGGER fail_action BEFORE INSERT ON audit_events WHEN NEW.event_type='action.updated' BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            false,
        ),
        (
            "CREATE TRIGGER fail_action BEFORE INSERT ON audit_events WHEN NEW.event_type='action.disabled' BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            true,
        ),
    ] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let (credential, first) = seed(&handle).await;
        let before = verified_rows(&paths::vault_db(&vault.state_dir));
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch(trigger).unwrap();
        let result = if disable {
            handle
                .action_disable(first.id, common::password_proof())
                .await
        } else {
            handle
                .action_upsert(
                    Some(first.id),
                    definition(credential),
                    common::password_proof(),
                )
                .await
                .map(|_| ())
        };
        assert!(result.is_err(), "{trigger}");
        db.execute_batch("DROP TRIGGER fail_action").unwrap();
        let after = verified_rows(&paths::vault_db(&vault.state_dir));
        assert_eq!(after.len(), 1);
        assert_eq!(
            (
                before[0].state,
                before[0].seal_nonce,
                before[0].seal_ciphertext
            ),
            (
                after[0].state,
                after[0].seal_nonce,
                after[0].seal_ciphertext
            )
        );
        finish(handle, join).await;
    }
}

#[tokio::test]
async fn templates_require_opaque_credentials_and_fixed_header_ownership() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let (opaque, _) = seed(&handle).await;
    let app = handle
        .credential_add(
            CredentialLabel::new("synthetic-app").unwrap(),
            CredentialKind::GitHubAppInstallation,
            SecretInput::from_slice(b"synthetic-profile"),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert!(matches!(
        handle
            .action_upsert(None, definition(app.id), common::password_proof())
            .await,
        Err(AuthorityError::Domain(_))
    ));
    let mut invalid = definition(opaque);
    invalid
        .request_policy
        .allowed_extra_headers
        .insert(HeaderName::new("x-fixed").unwrap());
    assert!(matches!(
        handle
            .action_upsert(None, invalid, common::password_proof())
            .await,
        Err(AuthorityError::Domain(_))
    ));
    assert_eq!(handle.action_list().await.unwrap().len(), 1);
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    finish(handle, join).await;
}

#[tokio::test]
async fn negative_persisted_limits_are_integrity_failures_at_every_read_boundary() {
    for (column, operation) in [
        ("timeout_ms", "get"),
        ("request_max_bytes", "list"),
        ("response_max_bytes", "backup"),
        ("timeout_ms", "rotation"),
    ] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let (_, action) = seed(&handle).await;
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        // These columns are INTEGER without a range CHECK: the SQL is valid,
        // while u32 decoding must fail as persisted-data integrity, not IO.
        assert_eq!(
            db.execute(&format!("UPDATE actions SET {column}=-1"), [])
                .unwrap(),
            1
        );
        let output = vault.dir.path().join("must-not-release.rkbackup");
        let result = match operation {
            "get" => handle.action_get(action.id, 1).await.map(|_| ()),
            "list" => handle.action_list().await.map(|_| ()),
            "backup" => handle
                .backup(output.clone(), common::password_proof())
                .await
                .map(|_| ()),
            "rotation" => {
                handle.lock("negative-action-field").await.unwrap();
                handle
                    .rotate_vrk_before(
                        common::password_input(),
                        SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
                        None,
                    )
                    .await
                    .map(|_| ())
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(result, Err(AuthorityError::StorageIntegrityFailed)),
            "{column}/{operation}: {result:?}"
        );
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert!(!output.exists());
        assert!(!paths::backup_snapshot(&vault.state_dir).exists());
        finish(handle, join).await;
    }
}
