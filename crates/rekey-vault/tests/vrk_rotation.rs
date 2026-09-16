//! VRK replacement preserves logical state while replacing every root dependency.
mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{CredentialId, VaultId};
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::command::UnlockProof;
use rekey_vault::crypto::aad::{AadPurpose, AadV1};
use rekey_vault::crypto::aead;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::error::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::WrapperKind;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use rusqlite::{Connection, types::Value};
use zeroize::Zeroizing;

const FIRST: &[u8] = b"VRK-PRIVATE-CANARY-version-one";
const SECOND: &[u8] = b"VRK-PRIVATE-CANARY-version-two";

fn rows(db: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = db.prepare(sql).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn ciphertexts(db: &Connection) -> Vec<Vec<Value>> {
    rows(
        db,
        "SELECT credential_id, version, dek_nonce, wrapped_dek, payload_nonce, encrypted_payload FROM credential_versions ORDER BY credential_id, version",
    )
}

fn immutable_state(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "SELECT singleton,format_version,vault_id,crypto_suite,created_at_ms,schema_digest FROM vault_header",
        "SELECT credential_id,label,kind,state,current_version,created_at_ms,updated_at_ms,revoked_at_ms FROM credentials ORDER BY credential_id",
        "SELECT credential_id,version,state,aad_version,crypto_suite,created_at_ms,retired_at_ms FROM credential_versions ORDER BY credential_id,version",
        "SELECT singleton,trust_installed,bundle_activated,signer_id,highest_version,policy_digest,bundle_digest,updated_at_ms FROM policy_state",
        "SELECT singleton,signer_id,algorithm,public_key,installed_at_ms FROM policy_trust",
        "SELECT singleton,signer_id,version,expires_at_ms,policy_digest,bundle_digest,bundle_json,activated_at_ms FROM policy_bundle",
        "SELECT * FROM workload_token_uses ORDER BY replay_digest",
        "SELECT * FROM actions ORDER BY action_id,version",
    ].map(|sql| rows(db, sql)).to_vec()
}

fn protected_state(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "SELECT * FROM vault_header",
        "SELECT * FROM key_wrappers ORDER BY wrapper_id",
        "SELECT * FROM credentials ORDER BY credential_id",
        "SELECT * FROM credential_versions ORDER BY credential_id,version",
        "SELECT * FROM policy_state",
        "SELECT * FROM policy_trust",
        "SELECT * FROM policy_bundle",
        "SELECT * FROM workload_token_uses ORDER BY replay_digest",
    ]
    .map(|sql| rows(db, sql))
    .to_vec()
}

fn seals(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "SELECT state_nonce,state_ciphertext FROM credentials ORDER BY credential_id",
        "SELECT seal_nonce,seal_ciphertext FROM policy_state",
        "SELECT seal_nonce,seal_ciphertext FROM policy_trust",
        "SELECT seal_nonce,seal_ciphertext FROM policy_bundle",
        "SELECT integrity_nonce,integrity_ciphertext FROM vault_header",
    ]
    .map(|sql| rows(db, sql))
    .to_vec()
}

fn recovery(vault: &common::TestVault) -> SecretInput {
    SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes())
}

fn successes(db: &Connection) -> i64 {
    db.query_row("SELECT count(*) FROM audit_events WHERE event_type = 'vault.vrk_rotated' AND outcome = 'success'", [], |row| row.get(0)).unwrap()
}

async fn two_versions(handle: &AuthorityHandle, kind: CredentialKind, label: &str) -> CredentialId {
    let credential = handle
        .credential_add(
            CredentialLabel::new(label).unwrap(),
            kind,
            SecretInput::from_slice(FIRST),
            common::password_proof(),
        )
        .await
        .unwrap();
    handle
        .credential_rotate_typed_before(
            credential.id,
            kind,
            Some(1),
            SecretInput::from_slice(SECOND),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    credential.id
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
        constraints_hash: [0u8; 32],
    }
    .encode();
    let plaintext = aead::open(&kek, &aad, &wrapper.nonce, &wrapper.wrapped_vrk).unwrap();
    (
        header.vault_id,
        Zeroizing::new(plaintext.as_slice().try_into().unwrap()),
    )
}

fn verify_every_payload(state: &Path) {
    let store = SqliteRecordStore::open(&paths::vault_db(state)).unwrap();
    let (vault_id, vrk) = root_key(&store);
    for (kind, version) in store.list_all_versions().unwrap() {
        let aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id,
            object_id: *version.credential_id.as_bytes(),
            object_version: version.version,
            credential_kind: 0,
            constraints_hash: [0u8; 32],
        }
        .encode();
        let raw = aead::open(&vrk, &aad, &version.dek_nonce, &version.wrapped_dek).unwrap();
        let dek = Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).unwrap());
        let aad = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id,
            object_id: *version.credential_id.as_bytes(),
            object_version: version.version,
            credential_kind: kind.aad_code(),
            constraints_hash: [0u8; 32],
        }
        .encode();
        let plaintext = aead::open(
            &dek,
            &aad,
            &version.payload_nonce,
            &version.encrypted_payload,
        )
        .unwrap();
        assert!(plaintext.as_slice() == if version.version == 1 { FIRST } else { SECOND });
    }
}

fn workload_audit() -> rekey_vault::command::AuditDraft {
    rekey_vault::command::AuditDraft {
        request_id: None,
        session_id: Some(rekey_domain::ids::SessionId::new_random()),
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: "session.created",
        outcome: "success",
        reason_code: "workload-attested".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

async fn install_policy(handle: &AuthorityHandle, bundle: bool, expires_at_ms: i64) {
    use rekey_vault::command::{PolicyBundleInput, PolicyTrustInput};
    use sha2::{Digest, Sha256};
    let signer_id = rekey_domain::ids::PolicySignerId::new_random();
    handle
        .policy_trust_install_before(
            PolicyTrustInput {
                signer_id,
                public_key: [7; 32],
            },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    if bundle {
        let bundle_json = b"root-rotation-policy-fixture".to_vec();
        handle
            .policy_bundle_activate_before(
                PolicyBundleInput {
                    signer_id,
                    version: 1,
                    expires_at_ms,
                    policy_digest: [8; 32],
                    bundle_digest: Sha256::digest(&bundle_json).into(),
                    bundle_json,
                },
                common::password_proof(),
                None,
            )
            .await
            .unwrap();
        handle
            .consume_workload_token_before([9; 32], 4_102_444_800_000, workload_audit(), None)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn vrk_rotation_all_kinds_all_states_policy_replay_and_two_backup_generations() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    for kind in [
        CredentialKind::OpaqueToken,
        CredentialKind::GitHubAppInstallation,
        CredentialKind::VaultKvV2Source,
        CredentialKind::VaultDynamicSource,
        CredentialKind::KeycloakTokenExchange,
    ] {
        let id = two_versions(&handle, kind, kind.as_str()).await;
        if kind == CredentialKind::GitHubAppInstallation {
            handle
                .credential_revoke(id, common::password_proof())
                .await
                .unwrap();
        }
    }
    install_policy(&handle, true, 4_102_444_800_000).await;
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(
        rows(
            &db,
            "SELECT state,count(*) FROM credential_versions GROUP BY state"
        )
        .len(),
        3
    );
    let immutable = immutable_state(&db);
    let before = ciphertexts(&db);
    let before_seals = seals(&db);
    let (_, old_root) =
        root_key(&SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap());
    let old_origin = handle.approval_origin_public_key().await.unwrap();
    let old_backup = vault.dir.path().join("before.rkbackup");
    let old_receipt = handle
        .backup(old_backup.clone(), common::password_proof())
        .await
        .unwrap();
    let (desktop_key, _) = handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    handle
        .lock_for_restart("root-rotation-fixture")
        .await
        .unwrap();
    let desktop = vault.state_dir.join("desktop-unlock.bin");
    assert!(desktop.exists());
    let receipt = handle
        .rotate_vrk_before(common::password_input(), recovery(&vault), None)
        .await
        .unwrap();
    receipt.validate().unwrap();
    assert_eq!(receipt.vault_id, vault.outcome.vault_id);
    assert_eq!(receipt.rotated_versions, 10);
    assert_eq!(receipt.resealed_credentials, 5);
    assert_eq!(handle.status().await.unwrap().state, "locked");
    assert!(!desktop.exists());
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(&desktop_key), None)
            .await
            .is_err()
    );
    let after = ciphertexts(&db);
    let (_, new_root) =
        root_key(&SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap());
    assert!(*old_root != *new_root);
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(&old[..2], &new[..2]);
        for i in 2..6 {
            assert_ne!(old[i], new[i]);
        }
        let blob = |r: &Vec<Value>, i: usize| match &r[i] {
            Value::Blob(b) => b.clone(),
            _ => panic!("blob"),
        };
        let version = match old[1] {
            Value::Integer(v) => v as u64,
            _ => panic!("version"),
        };
        let aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id: receipt.vault_id,
            object_id: blob(old, 0).try_into().unwrap(),
            object_version: version,
            credential_kind: 0,
            constraints_hash: [0; 32],
        }
        .encode();
        let old_dek = aead::open(
            &old_root,
            &aad,
            &blob(old, 2).try_into().unwrap(),
            &blob(old, 3),
        )
        .unwrap();
        let new_dek = aead::open(
            &new_root,
            &aad,
            &blob(new, 2).try_into().unwrap(),
            &blob(new, 3),
        )
        .unwrap();
        assert!(old_dek.as_slice() != new_dek.as_slice());
        assert!(
            aead::open(
                &old_root,
                &aad,
                &blob(new, 2).try_into().unwrap(),
                &blob(new, 3)
            )
            .is_err()
        );
        assert!(
            aead::open(
                &new_root,
                &aad,
                &blob(old, 2).try_into().unwrap(),
                &blob(old, 3)
            )
            .is_err()
        );
    }
    for (old, new) in before_seals.iter().zip(seals(&db)) {
        assert_eq!(old.len(), new.len());
        for (old, new) in old.iter().zip(new) {
            assert_ne!(old[0], new[0]);
            assert_ne!(old[1], new[1]);
        }
    }
    assert_eq!(immutable_state(&db), immutable);
    assert_eq!(successes(&db), 1);
    assert_eq!(
        rows(
            &db,
            "SELECT wrapper_kind,state FROM key_wrappers WHERE state='active' ORDER BY wrapper_kind"
        )
        .len(),
        2
    );
    assert_eq!(rows(&db,"SELECT wrapper_id FROM key_wrappers WHERE state='disabled' AND salt=zeroblob(16) AND nonce=zeroblob(12) AND wrapped_vrk=zeroblob(48) AND disabled_at_ms IS NOT NULL").len(),2);
    verify_every_payload(&vault.state_dir);
    handle
        .unlock(UnlockProof::Recovery(recovery(&vault)))
        .await
        .unwrap();
    let origin = handle.approval_origin_public_key().await.unwrap();
    assert_ne!(old_origin, origin);
    assert_eq!(
        receipt.approval_origin.public_key,
        data_encoding::HEXLOWER.encode(&origin)
    );
    assert!(
        handle
            .consume_workload_token_before([9; 32], 4_102_444_800_000, workload_audit(), None)
            .await
            .is_err()
    );
    handle.lock("password-verification").await.unwrap();
    handle.unlock(common::password_proof()).await.unwrap();
    let new_backup = vault.dir.path().join("after.rkbackup");
    let new_receipt = handle
        .backup(new_backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    for (name, backup, receipt, generation) in [
        ("old", old_backup, old_receipt, before),
        ("new", new_backup, new_receipt, after),
    ] {
        let state = vault.dir.path().join(name);
        restore_vault(
            &backup,
            &state,
            RestoreProof::Password(common::password_input()),
            &receipt.sha256_hex,
        )
        .unwrap();
        let restored_db = Connection::open(paths::vault_db(&state)).unwrap();
        assert_eq!(ciphertexts(&restored_db), generation);
        assert_eq!(immutable_state(&restored_db), immutable);
        verify_every_payload(&state);
        let (h, j) = common::spawn(&state);
        h.unlock(UnlockProof::Recovery(recovery(&vault)))
            .await
            .unwrap();
        assert!(
            h.consume_workload_token_before([9; 32], 4_102_444_800_000, workload_audit(), None)
                .await
                .is_err()
        );
        h.shutdown(Some(common::password_proof())).await.unwrap();
        j.join().unwrap();
        let bytes = std::fs::read(backup).unwrap();
        for canary in [
            FIRST,
            SECOND,
            common::PASSWORD,
            vault.outcome.recovery_key_display.as_bytes(),
        ] {
            assert!(!bytes.windows(canary.len()).any(|w| w == canary));
        }
    }
}

#[tokio::test]
async fn vrk_rotation_empty_trust_only_and_expired_policy_remain_exactly_as_stored() {
    for mode in ["empty", "trust", "expired"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        if mode != "empty" {
            handle.unlock(common::password_proof()).await.unwrap();
            let expires = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
                + 1000;
            install_policy(&handle, mode == "expired", expires).await;
            handle.lock("fixture").await.unwrap();
            if mode == "expired" {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
        }
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        let before = immutable_state(&db);
        let old_seals = seals(&db);
        let result = handle
            .rotate_vrk_before(common::password_input(), recovery(&vault), None)
            .await
            .unwrap();
        assert_eq!(result.rotated_versions, 0);
        assert_eq!(result.resealed_credentials, 0);
        assert_eq!(immutable_state(&db), before);
        assert_ne!(seals(&db), old_seals);
        assert_eq!(handle.status().await.unwrap().state, "locked");
        handle.unlock(common::password_proof()).await.unwrap();
        let material = handle.policy_material().await.unwrap();
        if mode == "expired" {
            assert!(
                material.bundle.unwrap().expires_at_ms
                    < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as i64
            );
        }
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn vrk_rotation_rejects_unlocked_wrong_factors_and_applies_shared_backoff() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    assert!(
        handle
            .rotate_vrk_before(common::password_input(), recovery(&vault), None)
            .await
            .is_err()
    );
    handle.lock("fixture").await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let before = protected_state(&db);
    for (password, recovery_input) in [
        (SecretInput::from_slice(b"wrong"), recovery(&vault)),
        (common::password_input(), SecretInput::from_slice(b"wrong")),
        (
            SecretInput::from_slice(b"wrong"),
            SecretInput::from_slice(b"wrong"),
        ),
    ] {
        assert!(matches!(
            handle
                .rotate_vrk_before(password, recovery_input, None)
                .await,
            Err(AuthorityError::InvalidUnlockCredential)
        ));
    }
    assert!(matches!(
        handle
            .rotate_vrk_before(common::password_input(), recovery(&vault), None)
            .await,
        Err(AuthorityError::UnlockRateLimited)
    ));
    assert_eq!(protected_state(&db), before);
    assert_eq!(successes(&db), 0);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(matches!(
        handle
            .rotate_vrk_before(
                common::password_input(),
                recovery(&vault),
                Some(Instant::now())
            )
            .await,
        Err(AuthorityError::AuthorityBusy)
    ));
    assert_eq!(protected_state(&db), before);
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn vrk_rotation_late_corruption_sql_rowcount_audit_and_commit_fail_closed() {
    for mode in ["corrupt", "update", "missing", "wrapper", "audit", "commit"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        two_versions(&handle, CredentialKind::OpaqueToken, "rollback").await;
        let (desktop_key, _) = handle
            .desktop_remember(common::password_proof(), None)
            .await
            .unwrap();
        handle.lock_for_restart("fixture").await.unwrap();
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        match mode {
            "corrupt"=>{db.execute("UPDATE credential_versions SET encrypted_payload=zeroblob(length(encrypted_payload)) WHERE version=2",[]).unwrap();},
            "update"=>db.execute_batch("CREATE TRIGGER fail_later BEFORE UPDATE ON credential_versions WHEN OLD.version=2 BEGIN SELECT RAISE(ABORT,'later update'); END;").unwrap(),
            "missing"=>db.execute_batch("CREATE TRIGGER skip_later BEFORE UPDATE ON credential_versions WHEN OLD.version=2 BEGIN SELECT RAISE(IGNORE); END;").unwrap(),
            "wrapper"=>db.execute_batch("CREATE TRIGGER skip_wrapper BEFORE INSERT ON key_wrappers WHEN NEW.wrapper_kind='recovery' BEGIN SELECT RAISE(IGNORE); END;").unwrap(),
            "audit"=>db.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.vrk_rotated' BEGIN SELECT RAISE(ABORT,'audit'); END;").unwrap(),
            "commit"=>db.execute_batch("CREATE TABLE test_parent(id INTEGER PRIMARY KEY); CREATE TABLE test_child(id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON audit_events WHEN NEW.event_type='vault.vrk_rotated' BEGIN INSERT INTO test_child VALUES(1); END;").unwrap(),
            _=>unreachable!(),
        }
        let before = protected_state(&db);
        let error = handle
            .rotate_vrk_before(common::password_input(), recovery(&vault), None)
            .await
            .unwrap_err();
        match mode {
            "corrupt" => assert!(matches!(error, AuthorityError::CryptoFailure)),
            "update" => assert!(matches!(error, AuthorityError::StorageUnavailable(_))),
            "missing" | "wrapper" => {
                assert!(matches!(error, AuthorityError::StorageIntegrityFailed))
            }
            "audit" | "commit" => assert!(matches!(error, AuthorityError::AuditCommitFailed)),
            _ => unreachable!(),
        }
        assert_eq!(protected_state(&db), before, "rollback {mode}");
        assert_eq!(successes(&db), 0);
        assert_eq!(
            handle.status().await.unwrap().state,
            if mode == "update" {
                "locked"
            } else {
                "faulted"
            }
        );
        // Later SQL failure has already revoked the external remembered grant.
        if mode != "corrupt" {
            assert!(!vault.state_dir.join("desktop-unlock.bin").exists());
            assert!(
                handle
                    .desktop_resume(SecretInput::from_slice(&desktop_key), None)
                    .await
                    .is_err()
            );
        }
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn vrk_rotation_missing_wrapper_uses_denial_backoff_but_corrupt_kdf_faults() {
    for mode in ["missing-password", "missing-recovery", "kdf"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        if mode == "kdf" {
            db.execute(
                "UPDATE key_wrappers SET kdf_params_json='{}' WHERE wrapper_kind='password'",
                [],
            )
            .unwrap();
        } else {
            db.execute(
                "DELETE FROM key_wrappers WHERE wrapper_kind=?1",
                [if mode == "missing-password" {
                    "password"
                } else {
                    "recovery"
                }],
            )
            .unwrap();
        }
        let before = protected_state(&db);
        if mode == "kdf" {
            assert!(matches!(
                handle
                    .rotate_vrk_before(common::password_input(), recovery(&vault), None)
                    .await,
                Err(AuthorityError::CryptoFailure)
            ));
            assert_eq!(handle.status().await.unwrap().state, "faulted");
        } else {
            for _ in 0..3 {
                assert!(matches!(
                    handle
                        .rotate_vrk_before(common::password_input(), recovery(&vault), None)
                        .await,
                    Err(AuthorityError::InvalidUnlockCredential)
                ));
            }
            assert!(matches!(
                handle
                    .rotate_vrk_before(common::password_input(), recovery(&vault), None)
                    .await,
                Err(AuthorityError::UnlockRateLimited)
            ));
            let count:i64=db.query_row("SELECT count(*) FROM audit_events WHERE event_type='vault.unlock_failed' AND reason_code='invalid-credential'",[],|r|r.get(0)).unwrap();
            assert_eq!(count, 3);
        }
        assert_eq!(protected_state(&db), before);
        assert_eq!(successes(&db), 0);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

// The child is a test-only worker harness. It does not add a production hook:
// precommit is held by SQLite work in an audit INSERT trigger; postcommit holds
// an already-returned worker receipt without publishing it to a client.
#[test]
fn vrk_process_fixture() {
    use std::io::BufRead;
    let Ok(root) = std::env::var("REKEY_TEST_VRK_PROCESS_DIR") else {
        return;
    };
    let mode = std::env::var("REKEY_TEST_VRK_PROCESS_MODE").unwrap();
    let root = std::path::PathBuf::from(root);
    let state = root.join("state");
    let outcome =
        rekey_vault::bootstrap::init_vault(&state, &common::password_input(), common::TEST_PARAMS)
            .unwrap();
    rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (handle,_join)=common::spawn(&state);
        handle.unlock(common::password_proof()).await.unwrap();
        two_versions(&handle,CredentialKind::OpaqueToken,"process-canary").await;
        handle.desktop_remember(common::password_proof(),None).await.unwrap();
        handle.lock_for_restart("process-fixture").await.unwrap();
        if mode=="precommit" {
            let db=Connection::open(paths::vault_db(&state)).unwrap();
            db.execute_batch("CREATE TRIGGER slow_root_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.vrk_rotated' BEGIN SELECT sum(n) FROM (WITH RECURSIVE delay(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM delay WHERE n<100000000) SELECT n FROM delay); END;").unwrap();
        }
        std::fs::write(root.join("ready"),b"ready").unwrap();
        let mut line=String::new();std::io::stdin().lock().read_line(&mut line).unwrap();
        let receipt=handle.rotate_vrk_before(common::password_input(),SecretInput::from_slice(outcome.recovery_key_display.as_bytes()),None).await.unwrap();
        assert!(receipt.locked);
        std::fs::write(root.join("committed"),b"committed-without-client-receipt").unwrap();
        line.clear();std::io::stdin().lock().read_line(&mut line).unwrap();
    });
}

#[test]
fn vrk_sigkill_before_commit_and_after_commit_without_client_receipt_reopens_whole_generation() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for mode in ["precommit", "postcommit"] {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "vrk_process_fixture", "--nocapture"])
            .env("REKEY_TEST_VRK_PROCESS_DIR", dir.path())
            .env("REKEY_TEST_VRK_PROCESS_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(25);
        while !dir.path().join("ready").exists() {
            assert!(child.try_wait().unwrap().is_none(), "child setup failed");
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let db = Connection::open(paths::vault_db(&state)).unwrap();
        db.busy_timeout(Duration::ZERO).unwrap();
        let before = protected_state(&db);
        let immutable = immutable_state(&db);
        child.stdin.as_mut().unwrap().write_all(b"start\n").unwrap();
        if mode == "precommit" {
            loop {
                if !state.join("desktop-unlock.bin").exists() {
                    match db.execute_batch("BEGIN IMMEDIATE;") {
                        Ok(()) => db.execute_batch("ROLLBACK;").unwrap(),
                        Err(rusqlite::Error::SqliteFailure(e, _))
                            if e.code == rusqlite::ErrorCode::DatabaseBusy =>
                        {
                            break;
                        }
                        Err(e) => panic!("unexpected lock probe: {e}"),
                    }
                }
                assert!(child.try_wait().unwrap().is_none());
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            // The worker owns the SQL write transaction, while its final audit
            // trigger still prevents reaching COMMIT. No production timing hook.
            assert!(!dir.path().join("committed").exists());
        } else {
            while !dir.path().join("committed").exists() {
                assert!(child.try_wait().unwrap().is_none());
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        child.kill().unwrap();
        let killed = child.wait().unwrap();
        assert!(!killed.success());
        assert!(!state.join("desktop-unlock.bin").exists());
        assert!(state.join(".desktop-runtime-active").exists());
        assert_eq!(immutable_state(&db), immutable);
        assert_eq!(successes(&db), if mode == "precommit" { 0 } else { 1 });
        if mode == "precommit" {
            assert_eq!(protected_state(&db), before);
        } else {
            assert_ne!(protected_state(&db), before);
        }
        if mode == "precommit" {
            db.execute_batch("DROP TRIGGER slow_root_audit;").unwrap();
        }
        drop(db);
        verify_every_payload(&state);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (handle, join) = common::spawn(&state);
            assert_eq!(handle.status().await.unwrap().state, "locked");
            handle.unlock(common::password_proof()).await.unwrap();
            handle
                .shutdown(Some(common::password_proof()))
                .await
                .unwrap();
            join.join().unwrap();
        });
    }
}

#[tokio::test]
async fn vrk_precommit_deadline_rolls_back_after_final_audit_sql_work() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    two_versions(&handle, CredentialKind::OpaqueToken, "deadline").await;
    handle
        .desktop_remember(common::password_proof(), None)
        .await
        .unwrap();
    handle.lock_for_restart("deadline-fixture").await.unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let before = protected_state(&db);
    // Keep the final audit INSERT busy longer than the whole command deadline.
    // Reaching this SQL also asserts wrappers/header already changed in-tx.
    db.execute_batch("CREATE TRIGGER delay_final_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.vrk_rotated' BEGIN SELECT CASE WHEN (SELECT count(*) FROM key_wrappers WHERE state='disabled') != 2 THEN RAISE(ABORT,'wrappers not yet replaced') END; SELECT sum(n) FROM (WITH RECURSIVE delay(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM delay WHERE n<30000000) SELECT n FROM delay); END;").unwrap();
    let start = Instant::now();
    let result = handle
        .rotate_vrk_before(
            common::password_input(),
            recovery(&vault),
            Some(start + Duration::from_secs(3)),
        )
        .await;
    assert!(matches!(result, Err(AuthorityError::AuthorityBusy)));
    assert!(start.elapsed() > Duration::from_secs(3));
    assert!(
        !vault.state_dir.join("desktop-unlock.bin").exists(),
        "preparation and desktop revocation completed before SQL deadline"
    );
    assert_eq!(protected_state(&db), before);
    assert_eq!(successes(&db), 0);
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn vrk_corrupt_header_state_policy_and_desktop_delete_failure_leave_database_unchanged() {
    for mode in ["header", "credential", "policy", "desktop"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        two_versions(&handle, CredentialKind::OpaqueToken, "integrity").await;
        install_policy(&handle, true, 4_102_444_800_000).await;
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        match mode {
            "header" => {
                db.execute("UPDATE vault_header SET integrity_ciphertext=zeroblob(length(integrity_ciphertext))",[]).unwrap();
            }
            "credential" => {
                db.execute("UPDATE credentials SET state_ciphertext=zeroblob(16)", [])
                    .unwrap();
            }
            "policy" => {
                db.execute("UPDATE policy_bundle SET seal_ciphertext=zeroblob(16)", [])
                    .unwrap();
            }
            "desktop" => {}
            _ => unreachable!(),
        }
        let before = protected_state(&db);
        let (handle, join) = common::spawn(&vault.state_dir);
        if mode == "desktop" {
            std::fs::create_dir(vault.state_dir.join("desktop-unlock.bin")).unwrap();
        }
        let error = handle
            .rotate_vrk_before(common::password_input(), recovery(&vault), None)
            .await
            .unwrap_err();
        match mode {
            "header" => assert!(matches!(error, AuthorityError::CryptoFailure)),
            "credential" | "policy" => {
                assert!(matches!(error, AuthorityError::StorageIntegrityFailed))
            }
            "desktop" => assert!(matches!(error, AuthorityError::StorageUnavailable(_))),
            _ => unreachable!(),
        }
        assert_eq!(protected_state(&db), before);
        assert_eq!(successes(&db), 0);
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        // Remove only our invalid filesystem fixture so shutdown can clean up.
        if mode == "desktop" {
            std::fs::remove_dir(vault.state_dir.join("desktop-unlock.bin")).unwrap();
        }
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn vrk_current_wrappers_must_unwrap_the_same_root() {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    let wrapper = store.active_wrapper(WrapperKind::Recovery).unwrap();
    let recovery_key =
        rekey_vault::crypto::recovery::parse_recovery_key(&vault.outcome.recovery_key_display)
            .unwrap();
    let mut kek = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&wrapper.salt), recovery_key.as_slice())
        .expand(rekey_vault::crypto::kdf::RECOVERY_KEK_INFO, &mut *kek)
        .unwrap();
    let aad = AadV1 {
        purpose: AadPurpose::WrapVrk,
        vault_id: vault.outcome.vault_id,
        object_id: *wrapper.wrapper_id.as_bytes(),
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0; 32],
    }
    .encode();
    let sealed = aead::seal(&kek, &aad, &[31; 32]).unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    db.execute(
        "UPDATE key_wrappers SET nonce=?1,wrapped_vrk=?2 WHERE wrapper_kind='recovery'",
        rusqlite::params![sealed.nonce.as_slice(), sealed.ciphertext],
    )
    .unwrap();
    let before = protected_state(&db);
    assert!(matches!(
        handle
            .rotate_vrk_before(common::password_input(), recovery(&vault), None)
            .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert_eq!(protected_state(&db), before);
    assert_eq!(successes(&db), 0);
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}
