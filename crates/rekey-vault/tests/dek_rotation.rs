//! DEK-only rotation: authenticated equivalence, immutable metadata and atomic failure.
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

const FIRST: &[u8] = b"DEK-PRIVATE-CANARY-version-one";
const SECOND: &[u8] = b"DEK-PRIVATE-CANARY-version-two";

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
        "SELECT * FROM vault_header",
        "SELECT * FROM key_wrappers ORDER BY wrapper_id",
        "SELECT * FROM credentials ORDER BY credential_id",
        "SELECT credential_id, version, state, aad_version, crypto_suite, created_at_ms, retired_at_ms FROM credential_versions ORDER BY credential_id, version",
        "SELECT * FROM policy_state",
        "SELECT * FROM actions ORDER BY action_id, version",
    ].map(|sql| rows(db, sql)).to_vec()
}

fn successes(db: &Connection) -> i64 {
    db.query_row("SELECT count(*) FROM audit_events WHERE event_type = 'vault.dek_rotated' AND outcome = 'success'", [], |row| row.get(0)).unwrap()
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

fn assert_resealed(state: &Path, old: &[Vec<Value>], new: &[Vec<Value>]) {
    let store = SqliteRecordStore::open(&paths::vault_db(state)).unwrap();
    let (vault_id, vrk) = root_key(&store);
    assert_eq!(old.len(), new.len());
    for (old, new) in old.iter().zip(new) {
        assert_eq!(&old[..2], &new[..2]);
        for field in 2..6 {
            assert_ne!(old[field], new[field], "each ciphertext/nonce changes");
        }
        let blob = |row: &Vec<Value>, index: usize| match &row[index] {
            Value::Blob(bytes) => bytes.clone(),
            _ => panic!("expected ciphertext blob"),
        };
        let version = match old[1] {
            Value::Integer(version) => version as u64,
            _ => panic!("expected version"),
        };
        let aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id,
            object_id: blob(old, 0).try_into().unwrap(),
            object_version: version,
            credential_kind: 0,
            constraints_hash: [0u8; 32],
        }
        .encode();
        let old_dek =
            aead::open(&vrk, &aad, &blob(old, 2).try_into().unwrap(), &blob(old, 3)).unwrap();
        let new_dek =
            aead::open(&vrk, &aad, &blob(new, 2).try_into().unwrap(), &blob(new, 3)).unwrap();
        assert!(
            old_dek.as_slice() != new_dek.as_slice(),
            "the DEK itself must change"
        );
    }
}

#[tokio::test]
async fn dek_rotation_preserves_all_kinds_versions_state_and_both_backup_generations() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let kinds = [
        CredentialKind::OpaqueToken,
        CredentialKind::GitHubAppInstallation,
        CredentialKind::VaultKvV2Source,
        CredentialKind::VaultDynamicSource,
        CredentialKind::KeycloakTokenExchange,
    ];
    for kind in kinds {
        let id = two_versions(&handle, kind, kind.as_str()).await;
        if kind == CredentialKind::GitHubAppInstallation {
            handle
                .credential_revoke(id, common::password_proof())
                .await
                .unwrap();
        }
    }
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let immutable = immutable_state(&db);
    let before = ciphertexts(&db);
    assert_eq!(before.len(), 10);
    let states = rows(
        &db,
        "SELECT state, count(*) FROM credential_versions GROUP BY state ORDER BY state",
    );
    assert_eq!(
        states.len(),
        3,
        "active, retired and revoked versions all exist"
    );
    verify_every_payload(&vault.state_dir);
    let old_backup = vault.dir.path().join("before.rkbackup");
    let old_receipt = handle
        .backup(old_backup.clone(), common::password_proof())
        .await
        .unwrap();
    assert_eq!(
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap(),
        10
    );
    let first = ciphertexts(&db);
    assert_resealed(&vault.state_dir, &before, &first);
    assert_eq!(immutable_state(&db), immutable);
    verify_every_payload(&vault.state_dir);
    assert_eq!(successes(&db), 1);
    let new_backup = vault.dir.path().join("after.rkbackup");
    let new_receipt = handle
        .backup(new_backup.clone(), common::password_proof())
        .await
        .unwrap();

    let recovery = UnlockProof::Recovery(SecretInput::from_slice(
        vault.outcome.recovery_key_display.as_bytes(),
    ));
    assert_eq!(handle.rotate_dek_before(recovery, None).await.unwrap(), 10);
    assert_resealed(&vault.state_dir, &first, &ciphertexts(&db));
    assert_eq!(immutable_state(&db), immutable);
    verify_every_payload(&vault.state_dir);
    assert_eq!(successes(&db), 2);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    for (name, backup, receipt, generation) in [
        ("old", old_backup, old_receipt, &before),
        ("new", new_backup, new_receipt, &first),
    ] {
        let restored = vault.dir.path().join(name);
        restore_vault(
            &backup,
            &restored,
            RestoreProof::Password(common::password_input()),
            &receipt.sha256_hex,
        )
        .unwrap();
        verify_every_payload(&restored);
        assert_eq!(
            &ciphertexts(&Connection::open(paths::vault_db(&restored)).unwrap()),
            generation
        );
        assert_eq!(
            immutable_state(&Connection::open(paths::vault_db(&restored)).unwrap()),
            immutable
        );
        let bytes = std::fs::read(backup).unwrap();
        for canary in [FIRST, SECOND, common::PASSWORD] {
            assert!(!bytes.windows(canary.len()).any(|window| window == canary));
        }
    }
}

#[tokio::test]
async fn dek_rotation_empty_vault_still_requires_current_step_up_and_audits_success() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(matches!(
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await,
        Err(AuthorityError::Locked)
    ));
    handle.unlock(common::password_proof()).await.unwrap();
    let wrong = UnlockProof::Password(SecretInput::from_slice(b"wrong-step-up"));
    assert!(matches!(
        handle.rotate_dek_before(wrong, None).await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert!(matches!(
        handle
            .rotate_dek_before(common::password_proof(), Some(Instant::now()))
            .await,
        Err(AuthorityError::AuthorityBusy)
    ));
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(successes(&db), 0);
    assert_eq!(
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap(),
        0
    );
    assert_eq!(successes(&db), 2);
    assert!(ciphertexts(&db).is_empty());
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn dek_rotation_later_corruption_update_audit_and_commit_failures_never_partially_replace() {
    for mode in ["corrupt", "update", "missing", "audit", "commit"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        two_versions(&handle, CredentialKind::OpaqueToken, "failure-fixture").await;
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        match mode {
            "corrupt" => { db.execute("UPDATE credential_versions SET encrypted_payload = zeroblob(length(encrypted_payload)) WHERE version = 2", []).unwrap(); }
            "update" => db.execute_batch("CREATE TRIGGER fail_later_update BEFORE UPDATE ON credential_versions WHEN OLD.version = 2 BEGIN SELECT RAISE(ABORT, 'injected later update'); END;").unwrap(),
            "missing" => db.execute_batch("CREATE TRIGGER skip_later_update BEFORE UPDATE ON credential_versions WHEN OLD.version = 2 BEGIN SELECT RAISE(IGNORE); END;").unwrap(),
            "audit" => db.execute_batch("CREATE TRIGGER fail_dek_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = 'vault.dek_rotated' BEGIN SELECT RAISE(ABORT, 'injected audit'); END;").unwrap(),
            "commit" => db.execute_batch("CREATE TABLE test_parent(id INTEGER PRIMARY KEY); CREATE TABLE test_child(id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_dek_commit AFTER INSERT ON audit_events WHEN NEW.event_type = 'vault.dek_rotated' BEGIN INSERT INTO test_child VALUES(1); END;").unwrap(),
            _ => unreachable!(),
        }
        let before = ciphertexts(&db);
        let immutable = immutable_state(&db);
        let error = handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap_err();
        match mode {
            "corrupt" => assert!(matches!(error, AuthorityError::CryptoFailure)),
            "update" => assert!(matches!(error, AuthorityError::StorageUnavailable(_))),
            "missing" => assert!(matches!(error, AuthorityError::StorageIntegrityFailed)),
            "audit" | "commit" => assert!(matches!(error, AuthorityError::AuditCommitFailed)),
            _ => unreachable!(),
        }
        assert_eq!(
            ciphertexts(&db),
            before,
            "all ciphertext rows roll back in {mode}"
        );
        assert_eq!(immutable_state(&db), immutable);
        assert_eq!(successes(&db), 0);
        let expected_state = if mode == "update" {
            "unlocked"
        } else {
            "faulted"
        };
        assert_eq!(handle.status().await.unwrap().state, expected_state);
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn dek_rotation_deadline_expiring_during_sql_wait_rolls_back_updates_and_audit() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    two_versions(&handle, CredentialKind::OpaqueToken, "deadline-fixture").await;
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let before = ciphertexts(&db);
    let immutable = immutable_state(&db);
    db.execute_batch("BEGIN IMMEDIATE;").unwrap();
    let deadline = Instant::now() + Duration::from_millis(300);
    let pending = tokio::spawn({
        let handle = handle.clone();
        async move {
            handle
                .rotate_dek_before(common::password_proof(), Some(deadline))
                .await
        }
    });
    // The single worker cannot answer status while its admitted rotation is
    // blocked by the competing writer; this excludes an expired-at-admission test.
    tokio::task::yield_now().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), handle.status())
            .await
            .is_err()
    );
    // Once it can write, the final worker-side gate must roll back.
    tokio::time::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(200),
    )
    .await;
    db.execute_batch("ROLLBACK;").unwrap();
    assert!(matches!(
        pending.await.unwrap(),
        Err(AuthorityError::AuthorityBusy)
    ));
    assert_eq!(ciphertexts(&db), before);
    assert_eq!(immutable_state(&db), immutable);
    assert_eq!(successes(&db), 0);
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    verify_every_payload(&vault.state_dir);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
