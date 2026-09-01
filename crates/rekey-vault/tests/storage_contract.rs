//! SQLite record-store contract: transactional invariants, single active
//! version, and audit rows written atomically with mutations.

mod common;

use rekey_domain::credential::{CredentialKind, CredentialState, VersionState};
use rekey_domain::ids::{CredentialId, RequestId};
use rekey_vault::crypto::{AAD_VERSION_V1, CRYPTO_SUITE_V1};
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{
    AuditEvent, CredentialRecord, CredentialVersionRecord, event_type, outcome,
};
use rekey_vault::paths;
use rekey_vault::store::SqliteRecordStore;

fn audit(event_type: &'static str) -> AuditEvent {
    AuditEvent {
        event_id: rand_bytes(),
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        event_type,
        outcome: outcome::SUCCESS,
        reason_code: "test".to_owned(),
        upstream_status: None,
        latency_ms: None,
        created_at_ms: 0,
    }
}

fn execution_audit(request_id: RequestId, event_type: &'static str) -> AuditEvent {
    let mut event = audit(event_type);
    event.request_id = Some(request_id);
    event
}

fn rand_bytes() -> [u8; 16] {
    *rekey_domain::ids::RequestId::new_random().as_bytes()
}

fn version(credential_id: CredentialId, version: u64) -> CredentialVersionRecord {
    CredentialVersionRecord {
        credential_id,
        version,
        state: VersionState::Active,
        aad_version: AAD_VERSION_V1,
        crypto_suite: CRYPTO_SUITE_V1.to_owned(),
        dek_nonce: [0u8; 12],
        wrapped_dek: vec![1, 2, 3],
        payload_nonce: [0u8; 12],
        encrypted_payload: vec![4, 5, 6],
        created_at_ms: 0,
        retired_at_ms: None,
    }
}

fn credential(label: &str) -> CredentialRecord {
    CredentialRecord {
        credential_id: CredentialId::new_random(),
        label: label.to_owned(),
        kind: CredentialKind::OpaqueToken,
        state: CredentialState::Active,
        current_version: 1,
        created_at_ms: 0,
        updated_at_ms: 0,
        revoked_at_ms: None,
        state_nonce: [0u8; 12],
        state_ciphertext: [0u8; 16],
    }
}

fn open_store() -> (common::TestVault, SqliteRecordStore) {
    let vault = common::init_test_vault();
    let store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    (vault, store)
}

fn assert_reopen_rejects_unknown_discriminator(update: &str) {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection.execute(update, []).unwrap();
    drop(connection);

    assert!(matches!(
        SqliteRecordStore::open(&db),
        Err(AuthorityError::UnsupportedFormatVersion | AuthorityError::StorageIntegrityFailed)
    ));
}

fn assert_reopen_rejects_null_discriminator(table: &str, declaration: &str, update: &str) {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = ON;")
        .unwrap();
    let nullable = declaration.replace(" NOT NULL", "");
    assert_eq!(
        connection
            .execute(
                "UPDATE sqlite_schema SET sql = replace(sql, ?2, ?3)
                 WHERE type = 'table' AND name = ?1",
                [table, declaration, &nullable],
            )
            .unwrap(),
        1
    );
    drop(connection);

    let connection = rusqlite::Connection::open(&db).unwrap();
    connection.execute(update, []).unwrap();
    drop(connection);
    assert!(matches!(
        SqliteRecordStore::open(&db),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
}

#[test]
fn opening_rejects_unknown_header_suite_and_wrapper_algorithm() {
    assert_reopen_rejects_unknown_discriminator(
        "UPDATE vault_header SET crypto_suite = 'future-suite'",
    );
    assert_reopen_rejects_unknown_discriminator(
        "UPDATE key_wrappers SET state = 'disabled', kdf_algorithm = 'future-kdf' WHERE wrapper_kind = 'recovery'",
    );
}

#[test]
fn opening_rejects_corrupt_persisted_kdf_parameters() {
    for update in [
        "UPDATE key_wrappers SET kdf_params_json = 'not-json' WHERE wrapper_kind = 'password'",
        "UPDATE key_wrappers SET kdf_params_json = '{\"memory_kib\":4294967295,\"iterations\":3,\"parallelism\":4}' WHERE wrapper_kind = 'password'",
        "UPDATE key_wrappers SET kdf_params_json = '{\"unexpected\":true}' WHERE wrapper_kind = 'recovery'",
    ] {
        let vault = common::init_test_vault();
        let db = paths::vault_db(&vault.state_dir);
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection.execute(update, []).unwrap();
        drop(connection);

        assert!(matches!(
            SqliteRecordStore::open(&db),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }
}

#[test]
fn opening_rejects_malformed_wrapper_crypto_fields() {
    for update in [
        "UPDATE key_wrappers SET salt = zeroblob(15) WHERE wrapper_kind = 'password'",
        "UPDATE key_wrappers SET wrapped_vrk = zeroblob(47) WHERE wrapper_kind = 'recovery'",
    ] {
        let vault = common::init_test_vault();
        let db = paths::vault_db(&vault.state_dir);
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection.execute(update, []).unwrap();
        drop(connection);

        assert!(matches!(
            SqliteRecordStore::open(&db),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }
}

#[test]
fn opening_rejects_v4_without_migration() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection
        .execute("UPDATE vault_header SET format_version = 4", [])
        .unwrap();
    drop(connection);

    assert!(matches!(
        SqliteRecordStore::open(&db),
        Err(AuthorityError::UnsupportedFormatVersion | AuthorityError::StorageIntegrityFailed)
    ));
}

#[test]
fn opening_rejects_unknown_credential_suite_and_aad_version() {
    for update in [
        "UPDATE credential_versions SET state = 'retired', crypto_suite = 'future-suite'",
        "UPDATE credential_versions SET state = 'revoked', aad_version = 2",
    ] {
        let (vault, mut store) = open_store();
        let record = credential("format-marker");
        store
            .insert_credential(
                &record,
                &version(record.credential_id, 1),
                audit(event_type::CREDENTIAL_CREATED),
            )
            .unwrap();
        drop(store);

        let db = paths::vault_db(&vault.state_dir);
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection.execute(update, []).unwrap();
        drop(connection);

        assert!(matches!(
            SqliteRecordStore::open(&db),
            Err(AuthorityError::UnsupportedFormatVersion | AuthorityError::StorageIntegrityFailed)
        ));
    }
}

#[test]
fn opening_rejects_null_crypto_discriminators() {
    assert_reopen_rejects_null_discriminator(
        "vault_header",
        "crypto_suite       TEXT NOT NULL",
        "UPDATE vault_header SET crypto_suite = NULL",
    );
    assert_reopen_rejects_null_discriminator(
        "key_wrappers",
        "kdf_algorithm      TEXT NOT NULL",
        "UPDATE key_wrappers SET kdf_algorithm = NULL WHERE wrapper_kind = 'recovery'",
    );

    for (declaration, update) in [
        (
            "aad_version        INTEGER NOT NULL",
            "UPDATE credential_versions SET aad_version = NULL",
        ),
        (
            "crypto_suite       TEXT NOT NULL",
            "UPDATE credential_versions SET crypto_suite = NULL",
        ),
    ] {
        let (vault, mut store) = open_store();
        let record = credential("nullable-marker");
        store
            .insert_credential(
                &record,
                &version(record.credential_id, 1),
                audit(event_type::CREDENTIAL_CREATED),
            )
            .unwrap();
        drop(store);
        let db = paths::vault_db(&vault.state_dir);
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection
            .execute_batch("PRAGMA writable_schema = ON;")
            .unwrap();
        let nullable = declaration.replace(" NOT NULL", "");
        connection
            .execute(
                "UPDATE sqlite_schema SET sql = replace(sql, ?2, ?3)
                 WHERE type = 'table' AND name = ?1",
                ["credential_versions", declaration, &nullable],
            )
            .unwrap();
        drop(connection);
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection.execute(update, []).unwrap();
        drop(connection);
        assert!(matches!(
            SqliteRecordStore::open(&db),
            Err(AuthorityError::UnsupportedFormatVersion)
        ));
    }
}

#[test]
fn empty_or_incomplete_database_is_unsupported_layout() {
    let empty = tempfile::tempdir().unwrap();
    let empty_db = empty.path().join("empty.sqlite3");
    drop(rusqlite::Connection::open(&empty_db).unwrap());
    assert!(matches!(
        SqliteRecordStore::open(&empty_db),
        Err(AuthorityError::UnsupportedVaultLayout)
    ));

    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch("DROP TABLE key_wrappers;")
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteRecordStore::open(&db),
        Err(AuthorityError::UnsupportedVaultLayout)
    ));
}

#[test]
fn opening_rejects_missing_key_wrappers() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection.execute("DELETE FROM key_wrappers", []).unwrap();
    drop(connection);

    assert!(matches!(
        SqliteRecordStore::open(&db),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
}

#[test]
fn opening_rejects_orphan_credential_version() {
    let (vault, mut store) = open_store();
    let record = credential("orphan-source");
    store
        .insert_credential(
            &record,
            &version(record.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap();
    drop(store);

    let orphan = CredentialId::new_random();
    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_versions (
                credential_id, version, state, aad_version, crypto_suite,
                dek_nonce, wrapped_dek, payload_nonce, encrypted_payload,
                created_at_ms, retired_at_ms
             )
             SELECT ?1, 1, state, aad_version, crypto_suite, dek_nonce,
                    wrapped_dek, payload_nonce, encrypted_payload,
                    created_at_ms, retired_at_ms
             FROM credential_versions WHERE credential_id = ?2 AND version = 1",
            rusqlite::params![
                orphan.as_bytes().as_slice(),
                record.credential_id.as_bytes().as_slice()
            ],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
}

#[test]
fn opening_rejects_current_version_state_mismatch() {
    let (vault, mut store) = open_store();
    let record = credential("state-mismatch");
    store
        .insert_credential(
            &record,
            &version(record.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute(
            "UPDATE credential_versions SET state = 'retired', retired_at_ms = 1
             WHERE credential_id = ?1 AND version = 1",
            [record.credential_id.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)),
        Err(AuthorityError::StorageIntegrityFailed)
    ));
}

#[test]
fn duplicate_label_leaves_no_partial_rows() {
    let (_vault, mut store) = open_store();
    let a = credential("dup");
    store
        .insert_credential(
            &a,
            &version(a.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap();

    let b = credential("dup");
    let err = store
        .insert_credential(
            &b,
            &version(b.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap_err();
    assert!(matches!(err, AuthorityError::CredentialConflict));

    // The failed transaction must not leave a version row behind.
    assert!(matches!(
        store.get_version(b.credential_id, 1).unwrap_err(),
        AuthorityError::CredentialNotFound
    ));
    assert_eq!(store.list_credentials().unwrap().len(), 1);
}

#[test]
fn rotate_keeps_single_active_version() {
    let (_vault, mut store) = open_store();
    let c = credential("rotating");
    store
        .insert_credential(
            &c,
            &version(c.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap();
    let mut rotated = c.clone();
    rotated.current_version = 2;
    rotated.updated_at_ms = 1000;
    store
        .rotate_credential(
            &rotated,
            &version(c.credential_id, 2),
            1000,
            audit(event_type::CREDENTIAL_ROTATED),
        )
        .unwrap();

    let v1 = store.get_version(c.credential_id, 1).unwrap();
    assert_eq!(v1.state, VersionState::Retired);
    assert_eq!(v1.retired_at_ms, Some(1000));
    let v2 = store.get_version(c.credential_id, 2).unwrap();
    assert_eq!(v2.state, VersionState::Active);
    assert_eq!(
        store
            .get_credential(c.credential_id)
            .unwrap()
            .current_version,
        2
    );
}

#[test]
fn revoke_is_terminal_and_transactional() {
    let (_vault, mut store) = open_store();
    let c = credential("revoking");
    store
        .insert_credential(
            &c,
            &version(c.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap();
    let mut revoked = c.clone();
    revoked.state = CredentialState::Revoked;
    revoked.updated_at_ms = 2000;
    revoked.revoked_at_ms = Some(2000);
    store
        .revoke_credential(&revoked, 2000, audit(event_type::CREDENTIAL_REVOKED))
        .unwrap();

    let rec = store.get_credential(c.credential_id).unwrap();
    assert_eq!(rec.state, CredentialState::Revoked);
    assert_eq!(rec.revoked_at_ms, Some(2000));
    assert_eq!(
        store.get_version(c.credential_id, 1).unwrap().state,
        VersionState::Revoked
    );

    // Rotating a revoked credential fails and adds nothing.
    let mut rejected = revoked.clone();
    rejected.current_version = 2;
    rejected.updated_at_ms = 3000;
    let err = store
        .rotate_credential(
            &rejected,
            &version(c.credential_id, 2),
            3000,
            audit(event_type::CREDENTIAL_ROTATED),
        )
        .unwrap_err();
    assert!(matches!(err, AuthorityError::CredentialNotFound));
    assert!(store.get_version(c.credential_id, 2).is_err());
}

#[test]
fn audit_rows_commit_with_mutations() {
    let (_vault, mut store) = open_store();
    let c = credential("audited");
    store
        .insert_credential(
            &c,
            &version(c.credential_id, 1),
            audit(event_type::CREDENTIAL_CREATED),
        )
        .unwrap();
    let types = store.audit_event_types().unwrap();
    assert!(types.contains(&event_type::VAULT_INITIALIZED.to_owned()));
    assert!(types.contains(&event_type::CREDENTIAL_CREATED.to_owned()));
}

#[test]
fn execution_audit_rejects_duplicate_started_and_terminal() {
    let (_vault, mut store) = open_store();
    let request_id = RequestId::new_random();
    store
        .append_audit(&execution_audit(request_id, event_type::EXECUTION_STARTED))
        .unwrap();
    assert!(matches!(
        store.append_audit(&execution_audit(request_id, event_type::EXECUTION_STARTED)),
        Err(AuthorityError::AuditCommitFailed)
    ));

    store
        .append_audit(&execution_audit(request_id, event_type::EXECUTION_BLOCKED))
        .unwrap();
    assert!(matches!(
        store.append_audit(&execution_audit(request_id, event_type::EXECUTION_FINISHED)),
        Err(AuthorityError::AuditCommitFailed)
    ));
}

#[test]
fn reopen_after_clean_close_succeeds() {
    let (vault, store) = open_store();
    drop(store);
    let store = SqliteRecordStore::open(&paths::vault_db(&vault.state_dir)).unwrap();
    store.quick_check().unwrap();
}
