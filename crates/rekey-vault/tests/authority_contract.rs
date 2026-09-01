//! Authority contract: single state owner, unlock proofs, credential
//! lifecycle, action pinning, and prepared-credential semantics.

mod common;

use std::collections::BTreeSet;

use argon2::{Algorithm, Argon2, Params, Version};
use rekey_domain::action::{
    ActionName, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName, HeaderPrefix, HttpsOrigin,
    RequestPolicy, ResponsePolicy,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialState};
use rekey_vault::command::{ActionDefinition, UnlockProof};
use rekey_vault::crypto::aad::{AadPurpose, AadV1};
use rekey_vault::crypto::aead;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{ActionState, WrapperKind};
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use zeroize::Zeroize;

fn action_definition(credential_id: rekey_domain::ids::CredentialId) -> ActionDefinition {
    ActionDefinition {
        name: ActionName::new("github-create-issue").unwrap(),
        credential_id,
        origin: HttpsOrigin::parse("https://api.github.com").unwrap(),
        method: FixedMethod::Post,
        exact_path: ExactPath::parse("/repos/acme/rekey/issues").unwrap(),
        auth: HeaderCredentialUse::new(
            HeaderName::new("authorization").unwrap(),
            HeaderPrefix::new("Bearer ").unwrap(),
        )
        .unwrap(),
        timeout_ms: 30_000,
        request_policy: RequestPolicy {
            max_body_bytes: 64 * 1024,
            allowed_extra_headers: BTreeSet::from([HeaderName::new("x-request-id").unwrap()]),
        },
        response_policy: ResponsePolicy {
            max_body_bytes: 256 * 1024,
            allowed_headers: BTreeSet::from([HeaderName::new("content-type").unwrap()]),
        },
    }
}

#[tokio::test]
async fn unlock_and_credential_lifecycle() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);

    // Locked at start; reads, mutations, and leases must all fail closed.
    assert_eq!(handle.status().await.unwrap().state, "locked");
    let err = handle.credential_list().await.unwrap_err();
    assert!(matches!(err, AuthorityError::Locked));
    let err = handle
        .credential_add(
            CredentialLabel::new("gh").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"tok"),
            common::password_proof(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::Locked));

    // Wrong password: uniform error.
    let err = handle
        .unlock(UnlockProof::Password(SecretInput::from_slice(b"wrong")))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::InvalidUnlockCredential));

    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(handle.status().await.unwrap().state, "unlocked");

    // Recovery key also unlocks (after re-lock).
    handle.lock("test").await.unwrap();
    handle
        .unlock(UnlockProof::Recovery(SecretInput::from_slice(
            vault.outcome.recovery_key_display.as_bytes(),
        )))
        .await
        .unwrap();

    // Mutation with a wrong step-up proof is rejected even while unlocked.
    let err = handle
        .credential_add(
            CredentialLabel::new("gh").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"tok"),
            UnlockProof::Password(SecretInput::from_slice(b"wrong")),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::InvalidUnlockCredential));

    // Add, list, prepare.
    let meta = handle
        .credential_add(
            CredentialLabel::new("github token").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"ghp_secret_v1"),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert_eq!(meta.current_version, 1);
    assert_eq!(meta.state, CredentialState::Active);

    let listed = handle.credential_list().await.unwrap();
    assert_eq!(listed.len(), 1);

    let prepared = handle.prepare_credential(meta.id).await.unwrap();
    assert_eq!(prepared.version(), 1);
    prepared.consume(|bytes| assert_eq!(bytes, b"ghp_secret_v1"));

    // Duplicate label rejected.
    let err = handle
        .credential_add(
            CredentialLabel::new("github token").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"other"),
            common::password_proof(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::CredentialConflict));

    // Empty rotations fail without retiring the current usable version.
    let err = handle
        .credential_rotate(
            meta.id,
            SecretInput::from_slice(b""),
            common::password_proof(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        AuthorityError::Domain(rekey_domain::DomainError::InvalidCapability)
    ));
    let unchanged = handle
        .credential_list()
        .await
        .unwrap()
        .into_iter()
        .find(|credential| credential.id == meta.id)
        .unwrap();
    assert_eq!(unchanged.current_version, 1);

    // Rotate: new version becomes the only preparable one.
    let rotated = handle
        .credential_rotate(
            meta.id,
            SecretInput::from_slice(b"ghp_secret_v2"),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.current_version, 2);
    let prepared = handle.prepare_credential(meta.id).await.unwrap();
    assert_eq!(prepared.version(), 2);
    prepared.consume(|bytes| assert_eq!(bytes, b"ghp_secret_v2"));

    // Action pinning.
    let action = handle
        .action_upsert(None, action_definition(meta.id), common::password_proof())
        .await
        .unwrap();
    assert_eq!(action.version, 1);
    let pinned = handle.action_get(action.id, 1).await.unwrap();
    assert_eq!(pinned.state, ActionState::Active);

    let replacement = handle
        .credential_add(
            CredentialLabel::new("replacement token").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"replacement_secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let updated = handle
        .action_upsert(
            Some(action.id),
            action_definition(replacement.id),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert_eq!(updated.version, 2);
    // The old version is retired but still pinned-executable.
    let pinned_v1 = handle.action_get(action.id, 1).await.unwrap();
    assert_eq!(pinned_v1.state, ActionState::Retired);
    assert!(pinned_v1.action.enabled);
    assert_eq!(
        handle.action_ids_for_credential(meta.id).await.unwrap(),
        vec![action.id]
    );
    assert_eq!(
        handle
            .action_ids_for_credential(replacement.id)
            .await
            .unwrap(),
        vec![action.id]
    );

    handle
        .action_disable(action.id, common::password_proof())
        .await
        .unwrap();
    let pinned_v2 = handle.action_get(action.id, 2).await.unwrap();
    assert_eq!(pinned_v2.state, ActionState::Disabled);
    assert!(!pinned_v2.action.enabled);

    // Revoke: leases stop immediately.
    handle
        .credential_revoke(meta.id, common::password_proof())
        .await
        .unwrap();
    let err = handle.prepare_credential(meta.id).await.unwrap_err();
    assert!(matches!(err, AuthorityError::CredentialRevoked));

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn audit_trail_is_written() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let meta = handle
        .credential_add(
            CredentialLabel::new("audited").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"v"),
            common::password_proof(),
        )
        .await
        .unwrap();
    handle
        .credential_rotate(
            meta.id,
            SecretInput::from_slice(b"v2"),
            common::password_proof(),
        )
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let events = store.audit_event_types().unwrap();
    for expected in [
        "vault.initialized",
        "vault.unlocked",
        "credential.created",
        "credential.rotated",
    ] {
        assert!(
            events.iter().any(|e| e == expected),
            "missing audit event {expected}; got {events:?}"
        );
    }
}

#[tokio::test]
async fn no_secret_export_api() {
    // Type-level: the only way to observe a credential value is consuming a
    // PreparedCredential once. This test documents the runtime side: listing
    // and status responses never carry payload bytes.
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let secret = b"super-secret-payload-canary";
    handle
        .credential_add(
            CredentialLabel::new("canary").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(secret),
            common::password_proof(),
        )
        .await
        .unwrap();
    let listed = handle.credential_list().await.unwrap();
    let as_json = serde_json::to_string(&listed).unwrap();
    assert!(!as_json.contains("super-secret-payload-canary"));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn step_up_rejects_valid_wrapper_for_a_different_root_key() {
    let vault = common::init_test_vault();
    let db = rekey_vault::paths::vault_db(&vault.state_dir);
    let store = SqliteRecordStore::open(&db).unwrap();
    let header = store.load_header().unwrap();
    let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
    let params = Argon2Params::from_json(&wrapper.kdf_params_json).unwrap();
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(rekey_vault::crypto::KEY_LEN),
    )
    .unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = [0u8; rekey_vault::crypto::KEY_LEN];
    argon
        .hash_password_into(common::PASSWORD, &wrapper.salt, &mut kek)
        .unwrap();
    let mut alternate_vrk =
        rekey_vault::crypto::random_array::<{ rekey_vault::crypto::KEY_LEN }>().unwrap();
    let aad = AadV1 {
        purpose: AadPurpose::WrapVrk,
        vault_id: header.vault_id,
        object_id: *wrapper.wrapper_id.as_bytes(),
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0u8; 32],
    }
    .encode();
    let alternate = aead::seal(&kek, &aad, &alternate_vrk).unwrap();
    kek.zeroize();
    alternate_vrk.zeroize();
    drop(store);

    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute(
            "UPDATE key_wrappers SET nonce = ?1, wrapped_vrk = ?2 WHERE wrapper_id = ?3",
            rusqlite::params![
                alternate.nonce.as_slice(),
                alternate.ciphertext,
                wrapper.wrapper_id.as_bytes().as_slice()
            ],
        )
        .unwrap();
    drop(connection);

    let err = handle
        .verify_proof(common::password_proof())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::InvalidUnlockCredential));
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    handle.lock("test").await.unwrap();
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn payload_authentication_failure_faults_and_zeroizes_authority() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let meta = handle
        .credential_add(
            CredentialLabel::new("tampered-payload").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute(
            "UPDATE credential_versions SET encrypted_payload = X'00' WHERE credential_id = ?1",
            [meta.id.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    let err = handle.prepare_credential(meta.id).await.unwrap_err();
    assert!(matches!(err, AuthorityError::CryptoFailure));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    let err = handle.prepare_credential(meta.id).await.unwrap_err();
    assert!(matches!(err, AuthorityError::Faulted));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn malformed_runtime_record_faults_and_zeroizes_authority() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let meta = handle
        .credential_add(
            CredentialLabel::new("malformed-record").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE credential_versions SET payload_nonce = X'00' WHERE credential_id = ?1",
            [meta.id.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    let err = handle.prepare_credential(meta.id).await.unwrap_err();
    assert!(matches!(err, AuthorityError::StorageIntegrityFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    let err = handle
        .verify_proof(common::password_proof())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthorityError::Faulted));
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}
