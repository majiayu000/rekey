//! Authority contract: single state owner, unlock proofs, credential
//! lifecycle, action pinning, and prepared-credential semantics.

mod common;

use std::collections::BTreeSet;

use argon2::{Algorithm, Argon2, Params, Version};
use rekey_domain::action::{
    ActionName, AnthropicTextStream, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, NativePlugin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialState};
use rekey_vault::command::{ActionDefinition, AuditDraft, UnlockProof};
use rekey_vault::crypto::aad::{AadPurpose, AadV1};
use rekey_vault::crypto::aead;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{ActionState, WrapperKind, event_type, outcome};
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use zeroize::Zeroize;

fn action_definition(credential_id: rekey_domain::ids::CredentialId) -> ActionDefinition {
    ActionDefinition {
        native_plugin: None,
        text_stream: None,
        name: ActionName::new("github-create-issue").unwrap(),
        credential_id,
        origin: HttpsOrigin::parse("https://api.github.com").unwrap(),
        method: FixedMethod::Post,
        target: rekey_domain::action::ActionTarget::Fixed {
            path: ExactPath::parse("/repos/acme/rekey/issues").unwrap(),
        },
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
async fn expired_mutation_command_never_commits_later() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();

    let error = handle
        .credential_add_before(
            CredentialLabel::new("expired").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"must-not-persist"),
            common::password_proof(),
            Some(std::time::Instant::now()),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::AuthorityBusy));
    assert!(handle.credential_list().await.unwrap().is_empty());

    let audit_error = handle
        .commit_audit_before(
            AuditDraft {
                request_id: None,
                session_id: Some(rekey_domain::ids::SessionId::new_random()),
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                approval: None,
                request_context: None,
                usage: None,
                event_type: event_type::SESSION_CREATED,
                outcome: outcome::SUCCESS,
                reason_code: "expired-test".to_owned(),
                upstream_status: None,
                latency_ms: None,
            },
            Some(std::time::Instant::now()),
        )
        .await
        .unwrap_err();
    assert!(matches!(audit_error, AuthorityError::AuthorityBusy));

    let wall_expired_error = handle
        .commit_audits_before(
            vec![AuditDraft {
                request_id: None,
                session_id: Some(rekey_domain::ids::SessionId::new_random()),
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                approval: None,
                request_context: None,
                usage: None,
                event_type: event_type::SESSION_REVOKED,
                outcome: outcome::SUCCESS,
                reason_code: "wall-expired-test".to_owned(),
                upstream_status: None,
                latency_ms: None,
            }],
            None,
            Some(0),
        )
        .await
        .unwrap_err();
    assert!(matches!(wall_expired_error, AuthorityError::AuthorityBusy));

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    assert!(!store.audit_event_types().unwrap().iter().any(|kind| {
        kind == event_type::SESSION_CREATED || kind == event_type::SESSION_REVOKED
    }));
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
async fn metadata_never_contains_secret_values() {
    // Explicit human reveal is separate; listing and status never carry payload bytes.
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

#[tokio::test]
async fn malformed_action_record_faults_and_zeroizes_authority() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("action-integrity").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let action = handle
        .action_upsert(
            None,
            action_definition(credential.id),
            common::password_proof(),
        )
        .await
        .unwrap();

    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute(
            "UPDATE actions SET origin = 'http://not-https.example' WHERE action_id = ?1",
            [action.id.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    let err = handle
        .action_get(action.id, action.version)
        .await
        .unwrap_err();
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

#[tokio::test]
async fn negative_action_version_faults_and_zeroizes_authority() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("negative-action-version").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"secret"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let action = handle
        .action_upsert(
            None,
            action_definition(credential.id),
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
            "UPDATE actions SET version = -1 WHERE action_id = ?1",
            [action.id.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    let err = handle.action_get(action.id, u64::MAX).await.unwrap_err();
    assert!(matches!(err, AuthorityError::StorageIntegrityFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn password_replacement_supports_password_and_recovery_step_up() {
    const NEW_PASSWORD: &[u8] = b"new password after ordinary change";
    const RECOVERED_PASSWORD: &[u8] = b"new password after recovery";

    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("password-lifecycle").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"preserved-secret"),
            common::password_proof(),
        )
        .await
        .unwrap();

    let error = handle
        .password_change_before(
            UnlockProof::Password(SecretInput::from_slice(b"wrong")),
            SecretInput::from_slice(NEW_PASSWORD),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));

    for invalid in [Vec::new(), vec![b'x'; 64 * 1024 + 1]] {
        let error = handle
            .password_change_before(common::password_proof(), SecretInput::new(invalid), None)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthorityError::Domain(rekey_domain::DomainError::InvalidActionDefinition(_))
        ));
    }

    handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(NEW_PASSWORD),
            None,
        )
        .await
        .unwrap();
    handle
        .prepare_credential(credential.id)
        .await
        .unwrap()
        .consume(|secret| assert_eq!(secret, b"preserved-secret"));

    handle.lock("password-change-test").await.unwrap();
    let error = handle.unlock(common::password_proof()).await.unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));
    handle
        .unlock(UnlockProof::Password(SecretInput::from_slice(NEW_PASSWORD)))
        .await
        .unwrap();
    handle.lock("recovery-change-test").await.unwrap();
    let recovery = || {
        UnlockProof::Recovery(SecretInput::from_slice(
            vault.outcome.recovery_key_display.as_bytes(),
        ))
    };
    handle.unlock(recovery()).await.unwrap();
    let error = handle
        .password_change_before(
            UnlockProof::Recovery(SecretInput::from_slice(b"RKREC1-WRONG")),
            SecretInput::from_slice(RECOVERED_PASSWORD),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));
    handle
        .password_change_before(
            recovery(),
            SecretInput::from_slice(RECOVERED_PASSWORD),
            None,
        )
        .await
        .unwrap();

    handle.lock("recovered-password-test").await.unwrap();
    let error = handle
        .unlock(UnlockProof::Password(SecretInput::from_slice(NEW_PASSWORD)))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));
    let recovered_proof = || UnlockProof::Password(SecretInput::from_slice(RECOVERED_PASSWORD));
    handle.unlock(recovered_proof()).await.unwrap();
    handle
        .prepare_credential(credential.id)
        .await
        .unwrap()
        .consume(|secret| assert_eq!(secret, b"preserved-secret"));
    handle.shutdown(Some(recovered_proof())).await.unwrap();
    join.join().unwrap();

    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let tombstones: i64 = connection
        .query_row(
            "SELECT count(*) FROM key_wrappers
             WHERE wrapper_kind = 'password' AND state = 'disabled'
               AND salt = zeroblob(16) AND nonce = zeroblob(12)
               AND wrapped_vrk = zeroblob(48)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstones, 2);
    let events = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&vault.state_dir))
        .unwrap()
        .audit_event_types()
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == event_type::VAULT_PASSWORD_CHANGED)
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == event_type::VAULT_PASSWORD_CHANGE_FAILED)
            .count(),
        2
    );
}

#[tokio::test]
async fn recovery_rotation_is_retryable_when_the_first_response_is_lost() {
    let vault = common::init_test_vault();
    let old_recovery = vault.outcome.recovery_key_display.as_bytes();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("recovery-lifecycle").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"preserved-secret"),
            common::password_proof(),
        )
        .await
        .unwrap();

    let error = handle
        .recovery_rotate_before(
            rekey_vault::command::UnlockProof::Password(SecretInput::from_slice(b"wrong")),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));

    let first_recovery = handle
        .recovery_rotate_before(common::password_proof(), None)
        .await
        .unwrap();
    let current_recovery = handle
        .recovery_rotate_before(common::password_proof(), None)
        .await
        .unwrap();

    handle.lock("recovery-rotation-test").await.unwrap();
    for stale in [old_recovery, first_recovery.as_bytes()] {
        let error = handle
            .unlock(UnlockProof::Recovery(SecretInput::from_slice(stale)))
            .await
            .unwrap_err();
        assert!(matches!(error, AuthorityError::InvalidUnlockCredential));
    }
    handle
        .unlock(UnlockProof::Recovery(SecretInput::from_slice(
            current_recovery.as_bytes(),
        )))
        .await
        .unwrap();
    handle
        .prepare_credential(credential.id)
        .await
        .unwrap()
        .consume(|secret| assert_eq!(secret, b"preserved-secret"));
    handle.lock("password-remains-valid").await.unwrap();
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let connection =
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let tombstones: i64 = connection
        .query_row(
            "SELECT count(*) FROM key_wrappers
             WHERE wrapper_kind = 'recovery' AND state = 'disabled'
               AND salt = zeroblob(16) AND nonce = zeroblob(12)
               AND wrapped_vrk = zeroblob(48)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstones, 2);
    let events = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&vault.state_dir))
        .unwrap()
        .audit_event_types()
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == event_type::VAULT_RECOVERY_ROTATED)
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == event_type::VAULT_RECOVERY_ROTATION_FAILED)
            .count(),
        1
    );
}

#[tokio::test]
async fn desktop_session_saves_but_reveal_requires_each_password_or_recovery_proof() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(handle.desktop_issue().await.is_err());
    handle.unlock(common::password_proof()).await.unwrap();
    let existing = handle
        .credential_add(
            CredentialLabel::new("existing GLM").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"existing-key-canary"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let token = handle.desktop_issue().await.unwrap();
    let saved = handle
        .desktop_add(
            SecretInput::from_slice(&token),
            CredentialLabel::new("new GLM").unwrap(),
            SecretInput::from_slice(b"new-key-canary"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        &*handle
            .desktop_reveal(common::password_proof(), existing.id, None)
            .await
            .unwrap(),
        b"existing-key-canary"
    );
    assert_eq!(
        &*handle
            .desktop_reveal(
                UnlockProof::Recovery(SecretInput::from_slice(
                    vault.outcome.recovery_key_display.as_bytes()
                )),
                saved.id,
                None
            )
            .await
            .unwrap(),
        b"new-key-canary"
    );
    assert!(
        handle
            .desktop_reveal(
                UnlockProof::Password(SecretInput::from_slice(&token)),
                saved.id,
                None
            )
            .await
            .is_err()
    );
    assert!(
        handle
            .desktop_add(
                SecretInput::from_slice(b"wrong"),
                CredentialLabel::new("must not save").unwrap(),
                SecretInput::from_slice(b"x"),
                None
            )
            .await
            .is_err()
    );
    let expired = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    assert!(matches!(
        handle
            .desktop_add(
                SecretInput::from_slice(&token),
                CredentialLabel::new("expired save").unwrap(),
                SecretInput::from_slice(b"must-not-save"),
                expired,
            )
            .await,
        Err(AuthorityError::AuthorityBusy)
    ));
    assert!(matches!(
        handle
            .desktop_reveal(common::password_proof(), saved.id, expired)
            .await,
        Err(AuthorityError::AuthorityBusy)
    ));
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let denied: i64 = db.query_row("SELECT count(*) FROM audit_events WHERE event_type = 'credential.reveal_failed' AND outcome = 'denied'", [], |r| r.get(0)).unwrap();
    let failed: i64 = db.query_row("SELECT count(*) FROM audit_events WHERE event_type = 'credential.reveal_failed' AND outcome = 'failure'", [], |r| r.get(0)).unwrap();
    let revealed: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type = 'credential.revealed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(denied, 1);
    assert_eq!(failed, 1);
    assert_eq!(revealed, 2, "expired reveal never decrypts or succeeds");
    let reasons: Vec<String> = db.prepare("SELECT reason_code FROM audit_events WHERE event_type='credential.revealed' ORDER BY sequence").unwrap()
        .query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert_eq!(reasons, ["step-up-password", "step-up-recovery"]);
    drop(db);
    assert_eq!(handle.credential_list().await.unwrap().len(), 2);
    handle.lock("test").await.unwrap();
    assert!(
        handle
            .desktop_reveal(common::password_proof(), saved.id, None)
            .await
            .is_err()
    );
    handle.unlock(common::password_proof()).await.unwrap();
    assert!(
        handle
            .desktop_reveal(
                UnlockProof::Password(SecretInput::from_slice(&token)),
                saved.id,
                None
            )
            .await
            .is_err()
    );

    handle
        .credential_revoke(saved.id, common::password_proof())
        .await
        .unwrap();
    assert!(
        handle
            .desktop_reveal(common::password_proof(), saved.id, None)
            .await
            .is_err()
    );
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn remembered_desktop_survives_restart_but_not_manual_lock() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let saved = handle
        .credential_add(
            CredentialLabel::new("restart").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"restart-canary"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let (key, expires) = handle
        .desktop_remember(common::password_proof(), None, 604_800_000)
        .await
        .unwrap();
    assert_eq!(key.len(), 64);
    let path = vault.state_dir.join("desktop-unlock.bin");
    let encrypted = std::fs::read(&path).unwrap();
    assert_eq!(encrypted.len(), 84);
    assert!(!encrypted.windows(key.len()).any(|v| v == *key));
    handle
        .lock_for_restart("service-manager-signal")
        .await
        .unwrap();
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
    assert!(vault.state_dir.join(".desktop-runtime-active").exists());
    rekey_vault::authority::finish_runtime(&vault.state_dir).unwrap();
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(b"forged"), None)
            .await
            .is_err()
    );
    assert_eq!(handle.status().await.unwrap().state, "locked");
    assert_eq!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .unwrap(),
        expires
    );
    assert_eq!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .unwrap(),
        expires,
        "restart cannot extend expiry"
    );
    assert_eq!(
        &*handle
            .desktop_reveal(common::password_proof(), saved.id, None)
            .await
            .unwrap(),
        b"restart-canary"
    );
    handle.lock("explicit").await.unwrap();
    assert!(!path.exists());
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .is_err()
    );
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn remembered_desktop_rejects_tampering_expiry_and_cross_vault_use() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None, 604_800_000)
        .await
        .unwrap();
    let path = vault.state_dir.join("desktop-unlock.bin");
    let original = std::fs::read(&path).unwrap();
    handle.lock_for_restart("restart").await.unwrap();
    let mut tampered = original.clone();
    tampered[83] ^= 1;
    std::fs::write(&path, &tampered).unwrap();
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .is_err()
    );
    let mut expired = original.clone();
    expired[8..16].copy_from_slice(&0i64.to_be_bytes());
    expired[16..24].copy_from_slice(&(7i64 * 24 * 60 * 60 * 1000).to_be_bytes());
    std::fs::write(&path, &expired).unwrap();
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .is_err()
    );
    std::fs::write(&path, &original).unwrap();
    let other = common::init_test_vault();
    use std::os::unix::fs::PermissionsExt;
    let other_path = other.state_dir.join("desktop-unlock.bin");
    std::fs::write(&other_path, &original).unwrap();
    std::fs::set_permissions(&other_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (other_handle, other_join) = common::spawn(&other.state_dir);
    assert!(
        other_handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .is_err()
    );
    other_handle.shutdown(None).await.unwrap();
    other_join.join().unwrap();
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn wrapper_changes_revoke_remembered_access_only_after_valid_proof() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None, 604_800_000)
        .await
        .unwrap();
    let path = vault.state_dir.join("desktop-unlock.bin");
    assert!(
        handle
            .password_change_before(
                UnlockProof::Password(SecretInput::from_slice(b"wrong")),
                SecretInput::from_slice(b"new-password-for-test"),
                None
            )
            .await
            .is_err()
    );
    assert!(path.exists());
    handle
        .password_change_before(
            common::password_proof(),
            SecretInput::from_slice(b"new-password-for-test"),
            None,
        )
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .is_err()
    );
    let (key, _) = handle
        .desktop_remember(
            UnlockProof::Password(SecretInput::from_slice(b"new-password-for-test")),
            None,
            604_800_000,
        )
        .await
        .unwrap();
    handle
        .recovery_rotate_before(
            rekey_vault::command::UnlockProof::Password(SecretInput::from_slice(
                b"new-password-for-test",
            )),
            None,
        )
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(
        handle
            .desktop_resume(SecretInput::from_slice(&key), None)
            .await
            .is_err()
    );
    handle.lock("test").await.unwrap();
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn slow_resume_audit_rolls_back_before_reporting_timeout() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None, 604_800_000)
        .await
        .unwrap();
    handle.lock_for_restart("restart").await.unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let task = tokio::spawn({
        let handle = handle.clone();
        async move {
            handle
                .desktop_resume(
                    SecretInput::from_slice(&key),
                    Some(std::time::Instant::now() + std::time::Duration::from_millis(500)),
                )
                .await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    db.execute_batch("COMMIT").unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(AuthorityError::AuthorityBusy)
    ));
    assert_eq!(handle.status().await.unwrap().state, "locked");
    assert!(handle.desktop_issue().await.is_err());
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn unclean_worker_exit_revokes_before_next_resume() {
    for worker_shutdown in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let (key, _) = handle
            .desktop_remember(common::password_proof(), None, 604_800_000)
            .await
            .unwrap();
        if worker_shutdown {
            handle
                .shutdown(Some(common::password_proof()))
                .await
                .unwrap();
        }
        drop(handle);
        join.join().unwrap();
        let (handle, join) = common::spawn(&vault.state_dir);
        assert!(
            handle
                .desktop_resume(SecretInput::from_slice(&key), None)
                .await
                .is_err()
        );
        assert!(!vault.state_dir.join("desktop-unlock.bin").exists());
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
#[tokio::test]
async fn explicit_github_plugin_registration_fails_closed_on_unsupported_platform() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let credential = handle
        .credential_add(
            CredentialLabel::new("github-plugin-source").unwrap(),
            CredentialKind::GitHubAppInstallation,
            SecretInput::from_slice(b"fixture-profile"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let mut definition = action_definition(credential.id);
    definition.native_plugin = Some(rekey_domain::action::NativePlugin {
        path: "/tmp/native-plugin".into(),
        sha256: "0".repeat(64),
        protocol: "github-issues-v1".into(),
    });
    for path in [
        "/repos/acme/rekey/issues",
        "/repos/acme/rekey/issues/1/comments",
    ] {
        definition.target = rekey_domain::action::ActionTarget::Fixed {
            path: ExactPath::parse(path).unwrap(),
        };
        let error = handle
            .action_upsert(None, definition.clone(), common::password_proof())
            .await
            .unwrap_err();
        assert!(
            matches!(error,AuthorityError::Domain(rekey_domain::DomainError::InvalidActionDefinition(ref message)) if message=="native plugins require macOS or Linux GNU x86_64/aarch64")
        );
    }
    assert!(handle.action_list().await.unwrap().is_empty());
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn native_plugin_rejects_wrong_credential_kind() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let opaque = handle
        .credential_add(
            CredentialLabel::new("opaque-plugin-source").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"opaque-token"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let github = handle
        .credential_add(
            CredentialLabel::new("github-plugin-kind-source").unwrap(),
            CredentialKind::GitHubAppInstallation,
            SecretInput::from_slice(b"fixture-profile"),
            common::password_proof(),
        )
        .await
        .unwrap();
    let mut github_plugin = action_definition(opaque.id);
    github_plugin.native_plugin = Some(NativePlugin {
        path: "/tmp/native-plugin".into(),
        sha256: "0".repeat(64),
        protocol: "github-issues-v1".into(),
    });
    let error = handle
        .action_upsert(None, github_plugin, common::password_proof())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthorityError::Domain(rekey_domain::DomainError::InvalidActionDefinition(ref message)) if message == "GitHub issue plugins require a GitHub App credential")
    );
    let mut anthropic_plugin = action_definition(github.id);
    anthropic_plugin.native_plugin = Some(NativePlugin {
        path: "/tmp/native-plugin".into(),
        sha256: "0".repeat(64),
        protocol: "anthropic-messages-v1".into(),
    });
    anthropic_plugin.text_stream = Some(AnthropicTextStream {
        model: "fixed-test-model".into(),
        max_tokens: 128,
    });
    anthropic_plugin.origin = HttpsOrigin::parse("https://api.anthropic.com").unwrap();
    anthropic_plugin.target = rekey_domain::action::ActionTarget::Fixed {
        path: ExactPath::parse("/v1/messages").unwrap(),
    };
    anthropic_plugin.auth = HeaderCredentialUse::new(
        HeaderName::new("x-api-key").unwrap(),
        HeaderPrefix::new("").unwrap(),
    )
    .unwrap();
    anthropic_plugin
        .request_policy
        .allowed_extra_headers
        .clear();
    anthropic_plugin.response_policy.allowed_headers.clear();
    let error = handle
        .action_upsert(None, anthropic_plugin, common::password_proof())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthorityError::Domain(rekey_domain::DomainError::InvalidActionDefinition(ref message)) if message == "Anthropic message plugins require an opaque-token credential")
    );
    assert!(handle.action_list().await.unwrap().is_empty());
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

mod lease_journal_tests {
    use super::*;
    use rekey_domain::ids::{RequestId, SessionId};
    use rekey_vault::handle::AuthorityHandle;
    use rekey_vault::model::{LeaseExecutionContext, LeaseReceipt, LeaseSourceRef};
    use rusqlite::{Connection, params};
    const PROFILE: &[u8] = br#"{"credential_type":"vault-dynamic-source-v2","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","renew_increment_seconds":60,"vault_token":"JOURNAL-PRIVATE-TOKEN-CANARY"}"#;
    const LEASE_ID: &[u8] = b"database/role/JOURNAL-PRIVATE-LEASE-CANARY";
    fn source() -> LeaseSourceRef {
        LeaseSourceRef {
            origin: HttpsOrigin::parse("https://vault.example.com").unwrap(),
            mount: "database".into(),
            role: "role".into(),
        }
    }
    #[tokio::test]
    async fn lease_batch_reports_locked_unlocked_and_faulted_from_one_snapshot() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let locked = handle.lease_recovery_batch().await.unwrap();
        assert!(matches!(locked.unavailable, Some(AuthorityError::Locked)));
        assert!(!locked.counts.verified);
        assert!(locked.known.is_empty());
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "snapshot").await;
        let receipt = begin(&handle, &c).await;
        issued(&handle, &receipt).await;
        let unlocked = handle.lease_recovery_batch().await.unwrap();
        assert!(unlocked.unavailable.is_none());
        assert!(unlocked.counts.verified);
        assert_eq!(unlocked.counts.pending, 1);
        assert_eq!(unlocked.known.len(), 1);
        let database = Connection::open(vault.state_dir.join("vault.sqlite3")).unwrap();
        database
            .execute(
                "UPDATE vault_lease_journal SET payload_nonce=zeroblob(12)",
                [],
            )
            .unwrap();
        assert!(matches!(
            handle.lease_recovery_batch().await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        let faulted = handle.lease_recovery_batch().await.unwrap();
        assert!(matches!(faulted.unavailable, Some(AuthorityError::Faulted)));
        assert!(!faulted.counts.verified);
        assert_eq!(faulted.counts.pending, 1);
        assert!(faulted.known.is_empty());
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert!(matches!(
            handle
                .lease_prepare_cleanup(receipt.registration_id, None)
                .await,
            Err(AuthorityError::Faulted)
        ));
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }

    async fn fixture(handle: &AuthorityHandle, label: &str) -> LeaseExecutionContext {
        let credential = handle
            .credential_add(
                CredentialLabel::new(label).unwrap(),
                CredentialKind::VaultDynamicSource,
                SecretInput::from_slice(PROFILE),
                common::password_proof(),
            )
            .await
            .unwrap();
        let action = handle
            .action_upsert(
                None,
                action_definition(credential.id),
                common::password_proof(),
            )
            .await
            .unwrap();
        LeaseExecutionContext {
            request_id: RequestId::new_random(),
            session_id: SessionId::new_random(),
            action_id: action.id,
            action_version: action.version,
            credential_id: credential.id,
            credential_version: 1,
        }
    }
    async fn started(handle: &AuthorityHandle, c: &LeaseExecutionContext) {
        handle
            .append_audit(AuditDraft {
                request_id: Some(c.request_id),
                session_id: Some(c.session_id),
                action_id: Some(c.action_id),
                action_version: Some(c.action_version),
                credential_id: Some(c.credential_id),
                credential_version: None,
                authorization: None,
                approval: None,
                request_context: None,
                usage: None,
                event_type: event_type::EXECUTION_STARTED,
                outcome: outcome::SUCCESS,
                reason_code: "allowed".into(),
                upstream_status: None,
                latency_ms: None,
            })
            .await
            .unwrap();
    }
    async fn begin(handle: &AuthorityHandle, c: &LeaseExecutionContext) -> LeaseReceipt {
        started(handle, c).await;
        handle
            .lease_acquire_begin(c.clone(), source(), None)
            .await
            .unwrap()
    }
    async fn issued(handle: &AuthorityHandle, receipt: &LeaseReceipt) -> LeaseReceipt {
        handle
            .lease_record_issued(
                receipt.registration_id,
                SecretInput::from_slice(LEASE_ID),
                receipt.updated_at_ms,
                60,
                true,
                None,
            )
            .await
            .unwrap()
    }
    fn db(state: &std::path::Path) -> Connection {
        Connection::open(rekey_vault::paths::vault_db(state)).unwrap()
    }
    fn count(db: &Connection, table: &str) -> i64 {
        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    type JournalStateRow = (i64, i64, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
    fn set(db: &Connection) -> JournalStateRow {
        db.query_row("SELECT revision,record_count,records_digest,seal_nonce,seal_ciphertext,last_audit_event_id FROM vault_lease_journal_state",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap()
    }
    #[tokio::test]
    async fn journal_source_gate_definite_abort_restart_and_locked_counts() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-source").await;
        let other = fixture(&handle, "journal-same-source").await;
        assert!(matches!(
            handle.lease_acquire_begin(c.clone(), source(), None).await,
            Err(AuthorityError::Domain(_))
        ));
        let intent = begin(&handle, &c).await;
        started(&handle, &other).await;
        assert!(matches!(
            handle
                .lease_acquire_begin(other.clone(), source(), None)
                .await,
            Err(AuthorityError::AuthorityBusy)
        ));
        assert_eq!(
            handle.lease_recovery_batch().await.unwrap().counts.unknown,
            1
        );
        handle.lock("journal-test").await.unwrap();
        let locked = handle.lease_recovery_batch().await.unwrap();
        assert!(!locked.counts.verified);
        assert_eq!(locked.counts.pending, 1);
        assert!(locked.known.is_empty());
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        assert!(matches!(
            handle
                .lease_acquire_begin(other.clone(), source(), None)
                .await,
            Err(AuthorityError::AuthorityBusy)
        ));
        handle
            .lease_abort_definite(intent.registration_id, None)
            .await
            .unwrap();
        let next = handle
            .lease_acquire_begin(other, source(), None)
            .await
            .unwrap();
        assert_ne!(intent.registration_id, next.registration_id);
        let batch = handle.lease_recovery_batch().await.unwrap();
        assert!(batch.counts.verified);
        assert_eq!(
            (
                batch.counts.pending,
                batch.counts.unknown,
                batch.counts.complete
            ),
            (1, 1, 1)
        );
        let database = db(&vault.state_dir);
        for table in ["audit_events", "vault_lease_journal"] {
            let mut stmt = database.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let column_count = stmt.column_count();
            let bytes = stmt
                .query_map([], |r| {
                    Ok((0..column_count)
                        .filter_map(|i| match r.get::<_, rusqlite::types::Value>(i).ok()? {
                            rusqlite::types::Value::Text(t) => Some(t.into_bytes()),
                            rusqlite::types::Value::Blob(b) => Some(b),
                            _ => None,
                        })
                        .flatten()
                        .collect::<Vec<u8>>())
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .concat();
            for canary in [b"JOURNAL-PRIVATE-TOKEN-CANARY".as_slice(), LEASE_ID] {
                assert!(!bytes.windows(canary.len()).any(|v| v == canary));
            }
        }
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_cleanup_uses_retired_revoked_exact_version_only() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-history").await;
        let intent = begin(&handle, &c).await;
        let lease = issued(&handle, &intent).await;
        let replacement = std::str::from_utf8(PROFILE)
            .unwrap()
            .replace("JOURNAL-PRIVATE-TOKEN-CANARY", "REPLACEMENT-PRIVATE-TOKEN")
            .replace("\"role\":\"role\"", "\"role\":\"different\"");
        handle
            .credential_rotate_typed_before(
                c.credential_id,
                CredentialKind::VaultDynamicSource,
                Some(1),
                SecretInput::from_slice(replacement.as_bytes()),
                common::password_proof(),
                None,
            )
            .await
            .unwrap();
        handle
            .credential_revoke(c.credential_id, common::password_proof())
            .await
            .unwrap();
        assert!(matches!(
            common::expect_err(handle.prepare_credential(c.credential_id).await),
            AuthorityError::CredentialRevoked
        ));
        let cleanup = handle
            .lease_prepare_cleanup(lease.registration_id, None)
            .await
            .unwrap();
        assert_eq!(cleanup.receipt().credential_version, 1);
        cleanup.consume(|profile, id| {
            assert_eq!(profile, PROFILE);
            assert_eq!(id, LEASE_ID);
        });
        let database = db(&vault.state_dir);
        database.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        assert!(
            database
                .execute(
                    "DELETE FROM credential_versions WHERE credential_id=?1 AND version=1",
                    params![c.credential_id.as_bytes().as_slice()]
                )
                .is_err()
        );
        handle
            .lease_finish_cleanup(lease.registration_id, false, None)
            .await
            .unwrap();
        assert_eq!(handle.lease_recovery_batch().await.unwrap().known.len(), 1);
        handle
            .lease_prepare_cleanup(lease.registration_id, None)
            .await
            .unwrap()
            .consume(|profile, id| {
                assert_eq!(profile, PROFILE);
                assert_eq!(id, LEASE_ID);
            });
        handle
            .lease_finish_cleanup(lease.registration_id, true, None)
            .await
            .unwrap();
        assert!(matches!(
            common::expect_err(
                handle
                    .lease_prepare_cleanup(lease.registration_id, None)
                    .await
            ),
            AuthorityError::AuthorityBusy
        ));
        let batch = handle.lease_recovery_batch().await.unwrap();
        assert_eq!((batch.counts.pending, batch.counts.complete), (0, 1));
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_renewal_records_actual_ttl_and_expired_command_is_atomic() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-renew").await;
        let intent = begin(&handle, &c).await;
        let lease = issued(&handle, &intent).await;
        let renewal = handle
            .lease_renew_begin(lease.registration_id, None)
            .await
            .unwrap();
        handle
            .lease_record_renewal(
                lease.registration_id,
                renewal.updated_at_ms,
                Some(17),
                true,
                None,
            )
            .await
            .unwrap();
        let database = db(&vault.state_dir);
        let expires: i64 = database
            .query_row(
                "SELECT last_confirmed_expires_at_ms FROM vault_lease_journal",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(expires, renewal.updated_at_ms + 17000);
        handle
            .lease_renew_begin(lease.registration_id, None)
            .await
            .unwrap();
        handle
            .lease_record_renewal(lease.registration_id, 0, None, false, None)
            .await
            .unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT last_confirmed_expires_at_ms FROM vault_lease_journal",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            expires
        );
        let manifest = set(&database);
        let audit_count = count(&database, "audit_events");
        assert!(matches!(
            common::expect_err(
                handle
                    .lease_prepare_cleanup(lease.registration_id, Some(std::time::Instant::now()))
                    .await
            ),
            AuthorityError::AuthorityBusy
        ));
        assert_eq!(set(&database), manifest);
        assert_eq!(count(&database, "audit_events"), audit_count);
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_audit_failure_rolls_back_entire_mutation_and_faults() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-audit-fault").await;
        started(&handle, &c).await;
        let database = db(&vault.state_dir);
        let before = set(&database);
        let audits = count(&database, "audit_events");
        database.execute_batch("CREATE TRIGGER reject_journal_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='vault.lease.acquire_intent' BEGIN SELECT RAISE(ABORT,'private-canary'); END;").unwrap();
        assert!(matches!(
            handle.lease_acquire_begin(c, source(), None).await,
            Err(AuthorityError::AuditCommitFailed)
        ));
        assert_eq!(set(&database), before);
        assert_eq!(count(&database, "vault_lease_journal"), 0);
        assert_eq!(count(&database, "audit_events"), audits + 1);
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_sql_failure_rolls_back_audit_row_and_manifest() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-sql-fault").await;
        started(&handle, &c).await;
        let database = db(&vault.state_dir);
        let before = set(&database);
        let audits = count(&database, "audit_events");
        database.execute_batch("CREATE TRIGGER reject_journal BEFORE INSERT ON vault_lease_journal BEGIN SELECT RAISE(ABORT,'private-canary'); END;").unwrap();
        let error = handle
            .lease_acquire_begin(c.clone(), source(), None)
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-canary"));
        assert!(matches!(error, AuthorityError::StorageUnavailable(_)));
        assert_eq!(set(&database), before);
        assert_eq!(count(&database, "vault_lease_journal"), 0);
        assert_eq!(count(&database, "audit_events"), audits);
        database
            .execute_batch("DROP TRIGGER reject_journal")
            .unwrap();
        handle.lease_acquire_begin(c, source(), None).await.unwrap();
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_deleted_tampered_or_missing_history_faults_before_unlock() {
        for sql in [
            "DELETE FROM vault_lease_journal",
            "UPDATE vault_lease_journal SET source_ref_hash=zeroblob(32)",
            "UPDATE vault_lease_journal SET credential_version=2",
            "UPDATE vault_lease_journal SET phase='complete',completed_at_ms=updated_at_ms",
            "DELETE FROM credential_versions WHERE version=1",
        ] {
            let vault = common::init_test_vault();
            let (handle, join) = common::spawn(&vault.state_dir);
            handle.unlock(common::password_proof()).await.unwrap();
            let c = fixture(&handle, "journal-tamper").await;
            begin(&handle, &c).await;
            handle.lock("journal-tamper").await.unwrap();
            let database = db(&vault.state_dir);
            database.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            database.execute_batch(sql).unwrap();
            assert!(matches!(
                handle.unlock(common::password_proof()).await,
                Err(AuthorityError::StorageIntegrityFailed)
            ));
            assert_eq!(handle.status().await.unwrap().state, "faulted");
            handle.shutdown(None).await.unwrap();
            join.join().unwrap();
        }
    }
    #[tokio::test]
    async fn journal_desktop_resume_deleted_row_fails_closed() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-desktop").await;
        begin(&handle, &c).await;
        let (token, _) = handle
            .desktop_remember(common::password_proof(), None, 604_800_000)
            .await
            .unwrap();
        handle.lock_for_restart("journal-desktop").await.unwrap();
        db(&vault.state_dir)
            .execute("DELETE FROM vault_lease_journal", [])
            .unwrap();
        assert!(matches!(
            handle
                .desktop_resume(SecretInput::from_slice(&token), None)
                .await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_pending_unknown_complete_backup_restore_is_authenticated() {
        use rekey_vault::bootstrap::{RestoreProof, restore_vault};
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-backup").await;
        let first = begin(&handle, &c).await;
        handle
            .lease_abort_definite(first.registration_id, None)
            .await
            .unwrap();
        let mut next = c.clone();
        next.request_id = RequestId::new_random();
        let second = begin(&handle, &next).await;
        issued(&handle, &second).await;
        let mut other = fixture(&handle, "journal-unknown").await;
        let other_profile = std::str::from_utf8(PROFILE)
            .unwrap()
            .replace("\"role\":\"role\"", "\"role\":\"other\"");
        handle
            .credential_rotate_typed_before(
                other.credential_id,
                CredentialKind::VaultDynamicSource,
                Some(1),
                SecretInput::from_slice(other_profile.as_bytes()),
                common::password_proof(),
                None,
            )
            .await
            .unwrap();
        other.credential_version = 2;
        started(&handle, &other).await;
        let mut other_source = source();
        other_source.role = "other".into();
        handle
            .lease_acquire_begin(other, other_source, None)
            .await
            .unwrap();
        let path = vault.dir.path().join("journal.rkbackup");
        let info = handle
            .backup(path.clone(), common::password_proof())
            .await
            .unwrap();
        let archived = Connection::open(&path).unwrap();
        let archived_sequence: u64 = archived
            .query_row("SELECT MAX(sequence) FROM audit_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(info.snapshot_cut.audit_sequence, archived_sequence);
        drop(archived);
        handle
            .lease_prepare_cleanup(second.registration_id, None)
            .await
            .unwrap()
            .consume(|profile, id| {
                assert_eq!(profile, PROFILE);
                assert_eq!(id, LEASE_ID);
            });
        handle
            .lease_finish_cleanup(second.registration_id, true, None)
            .await
            .unwrap();
        assert_eq!(
            handle.lease_recovery_batch().await.unwrap().counts.complete,
            2
        );
        let restored = vault.dir.path().join("restored");
        let recovered = restore_vault(
            &path,
            &restored,
            RestoreProof::Password(common::password_input()),
            &info.sha256_hex,
            rekey_vault::bootstrap::inspect_restore(
                &path,
                &restored,
                RestoreProof::Password(common::password_input()),
                &info.sha256_hex,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.snapshot_cut, info.snapshot_cut);
        assert_eq!(recovered.input_sha256_hex, info.sha256_hex);
        let installed = Connection::open(rekey_vault::paths::vault_db(&restored)).unwrap();
        let restore_sequence: u64 = installed
            .query_row(
                "SELECT sequence FROM audit_events WHERE event_type='restore.completed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restore_sequence, archived_sequence + 1);
        drop(installed);
        let (restored_handle, restored_join) = common::spawn(&restored);
        assert!(
            !restored_handle
                .lease_recovery_batch()
                .await
                .unwrap()
                .counts
                .verified
        );
        restored_handle
            .unlock(common::password_proof())
            .await
            .unwrap();
        let batch = restored_handle.lease_recovery_batch().await.unwrap();
        assert_eq!(
            (
                batch.counts.pending,
                batch.counts.unknown,
                batch.counts.complete,
                batch.known.len()
            ),
            (2, 1, 1, 1)
        );
        restored_handle
            .lease_prepare_cleanup(second.registration_id, None)
            .await
            .unwrap()
            .consume(|profile, id| {
                assert_eq!(profile, PROFILE);
                assert_eq!(id, LEASE_ID);
            });
        restored_handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        restored_join.join().unwrap();
        Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM vault_lease_journal", [])
            .unwrap();
        let digest = rekey_vault::durable::sha256_file(&path).unwrap();
        let tampered = vault.dir.path().join("tampered");
        assert!(matches!(
            restore_vault(
                &path,
                &tampered,
                RestoreProof::Password(common::password_input()),
                &digest,
                common::unconfirmed_restore_context()
            ),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert!(!rekey_vault::paths::vault_db(&tampered).exists());
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_both_rotations_preserve_exact_cleanup_and_change_all_ciphertexts() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let c = fixture(&handle, "journal-rotations").await;
        let intent = begin(&handle, &c).await;
        let lease = issued(&handle, &intent).await;
        let database = db(&vault.state_dir);
        let cipher = |db: &Connection| -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
            db.query_row("SELECT dek_nonce,wrapped_dek,payload_nonce,encrypted_payload FROM vault_lease_journal",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
        };
        let before = cipher(&database);
        let manifest = set(&database);
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap();
        assert_ne!(cipher(&database), before);
        assert_ne!(set(&database), manifest);
        let before = cipher(&database);
        handle.lock("journal-vrk").await.unwrap();
        handle
            .rotate_vrk_before(
                common::password_input(),
                SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
                None,
            )
            .await
            .unwrap();
        assert_ne!(cipher(&database), before);
        handle.unlock(common::password_proof()).await.unwrap();
        handle
            .lease_prepare_cleanup(lease.registration_id, None)
            .await
            .unwrap()
            .consume(|profile, id| {
                assert_eq!(profile, PROFILE);
                assert_eq!(id, LEASE_ID);
            });
        handle
            .lease_finish_cleanup(lease.registration_id, true, None)
            .await
            .unwrap();
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_corruption_rejects_both_rotations_without_any_ciphertext_writes() {
        for vrk in [false, true] {
            let vault = common::init_test_vault();
            let (handle, join) = common::spawn(&vault.state_dir);
            handle.unlock(common::password_proof()).await.unwrap();
            let c = fixture(&handle, "journal-bad-rotation").await;
            begin(&handle, &c).await;
            if vrk {
                handle.lock("journal-bad-vrk").await.unwrap();
            }
            let database = db(&vault.state_dir);
            database
                .execute(
                    "UPDATE vault_lease_journal SET payload_nonce=zeroblob(12)",
                    [],
                )
                .unwrap();
            let before: Vec<u8> = database
                .query_row("SELECT wrapped_dek FROM credential_versions", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let manifest = set(&database);
            let result = if vrk {
                handle
                    .rotate_vrk_before(
                        common::password_input(),
                        SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
                        None,
                    )
                    .await
                    .map(|_| ())
            } else {
                handle
                    .rotate_dek_before(common::password_proof(), None)
                    .await
                    .map(|_| ())
            };
            assert!(matches!(
                result,
                Err(AuthorityError::StorageIntegrityFailed)
            ));
            assert_eq!(
                database
                    .query_row("SELECT wrapped_dek FROM credential_versions", [], |r| r
                        .get::<_, Vec<u8>>(0))
                    .unwrap(),
                before
            );
            assert_eq!(set(&database), manifest);
            assert_eq!(handle.status().await.unwrap().state, "faulted");
            handle.shutdown(None).await.unwrap();
            join.join().unwrap();
        }
    }
    #[tokio::test]
    async fn journal_late_sql_failure_in_both_rotations_rolls_back_every_dependency() {
        fn snapshot(db: &Connection) -> Vec<Vec<rusqlite::types::Value>> {
            [
                "vault_header",
                "key_wrappers",
                "credentials",
                "credential_versions",
                "policy_state",
                "vault_lease_journal",
                "vault_lease_journal_state",
            ]
            .iter()
            .flat_map(|table| {
                let mut stmt = db
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let n = stmt.column_count();
                stmt.query_map([], |r| {
                    (0..n).map(|i| r.get(i)).collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
            })
            .collect()
        }
        for vrk in [false, true] {
            let vault = common::init_test_vault();
            let (handle, join) = common::spawn(&vault.state_dir);
            handle.unlock(common::password_proof()).await.unwrap();
            let c = fixture(&handle, "journal-late-rotation").await;
            let intent = begin(&handle, &c).await;
            issued(&handle, &intent).await;
            if vrk {
                handle.lock("journal-late-vrk").await.unwrap();
            }
            let database = db(&vault.state_dir);
            let before = snapshot(&database);
            database.execute_batch("CREATE TRIGGER reject_manifest_rotation BEFORE UPDATE ON vault_lease_journal_state BEGIN SELECT RAISE(ABORT,'private-rotation-canary'); END;").unwrap();
            let result = if vrk {
                handle
                    .rotate_vrk_before(
                        common::password_input(),
                        SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
                        None,
                    )
                    .await
                    .map(|_| ())
            } else {
                handle
                    .rotate_dek_before(common::password_proof(), None)
                    .await
                    .map(|_| ())
            };
            let error = result.unwrap_err();
            assert!(matches!(error, AuthorityError::StorageUnavailable(_)));
            assert!(!error.to_string().contains("private-rotation-canary"));
            assert_eq!(snapshot(&database), before);
            database
                .execute_batch("DROP TRIGGER reject_manifest_rotation")
                .unwrap();
            if vrk {
                handle.unlock(common::password_proof()).await.unwrap();
            }
            let cleanup = handle
                .lease_prepare_cleanup(intent.registration_id, None)
                .await
                .unwrap();
            cleanup.consume(|profile, id| {
                assert_eq!(profile, PROFILE);
                assert_eq!(id, LEASE_ID);
            });
            handle
                .shutdown(Some(common::password_proof()))
                .await
                .unwrap();
            join.join().unwrap();
        }
    }
    #[tokio::test]
    async fn journal_recovery_batch_bounds_known_ids_without_dropping_backlog() {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        for index in 0..10 {
            let mut c = fixture(&handle, &format!("journal-batch-{index}")).await;
            let role = format!("role_{index}");
            let profile = std::str::from_utf8(PROFILE)
                .unwrap()
                .replace("\"role\":\"role\"", &format!("\"role\":\"{role}\""));
            handle
                .credential_rotate_typed_before(
                    c.credential_id,
                    CredentialKind::VaultDynamicSource,
                    Some(1),
                    SecretInput::from_slice(profile.as_bytes()),
                    common::password_proof(),
                    None,
                )
                .await
                .unwrap();
            c.credential_version = 2;
            started(&handle, &c).await;
            let mut source = source();
            source.role = role;
            let receipt = handle.lease_acquire_begin(c, source, None).await.unwrap();
            if index < 9 {
                issued(&handle, &receipt).await;
            }
        }
        let batch = handle.lease_recovery_batch().await.unwrap();
        assert_eq!(
            (
                batch.counts.pending,
                batch.counts.unknown,
                batch.known.len()
            ),
            (10, 1, 8)
        );
        let first = batch.known[0].registration_id;
        handle
            .lease_prepare_cleanup(first, None)
            .await
            .unwrap()
            .consume(|_, id| assert_eq!(id, LEASE_ID));
        handle
            .lease_finish_cleanup(first, true, None)
            .await
            .unwrap();
        let remaining = handle.lease_recovery_batch().await.unwrap();
        assert_eq!(
            (
                remaining.counts.pending,
                remaining.counts.unknown,
                remaining.counts.complete,
                remaining.known.len()
            ),
            (9, 1, 1, 8)
        );
        assert!(!remaining.known.iter().any(|r| r.registration_id == first));
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
    #[tokio::test]
    async fn journal_old_valid_empty_or_complete_set_cannot_erase_new_lease_with_retained_audit() {
        for old_complete in [false, true] {
            let vault = common::init_test_vault();
            let (handle, join) = common::spawn(&vault.state_dir);
            handle.unlock(common::password_proof()).await.unwrap();
            let mut c = fixture(&handle, "journal-selective-replay").await;
            if old_complete {
                let old = begin(&handle, &c).await;
                handle
                    .lease_abort_definite(old.registration_id, None)
                    .await
                    .unwrap();
                c.request_id = RequestId::new_random();
            }
            let database = db(&vault.state_dir);
            database.execute_batch("CREATE TEMP TABLE old_journal AS SELECT * FROM vault_lease_journal; CREATE TEMP TABLE old_manifest AS SELECT * FROM vault_lease_journal_state;").unwrap();
            let intent = begin(&handle, &c).await;
            let lease = issued(&handle, &intent).await;
            let latest_before:Vec<u8>=database.query_row("SELECT event_id FROM audit_events WHERE event_type GLOB 'vault.lease.*' ORDER BY sequence DESC LIMIT 1",[],|r|r.get(0)).unwrap();
            assert_eq!(latest_before, lease.last_audit_event_id);
            handle.lock("selective-journal-replay").await.unwrap();
            database.execute_batch("BEGIN; DELETE FROM vault_lease_journal; INSERT INTO vault_lease_journal SELECT * FROM old_journal; DELETE FROM vault_lease_journal_state; INSERT INTO vault_lease_journal_state SELECT * FROM old_manifest; COMMIT;").unwrap();
            assert_eq!(database.query_row("SELECT event_id FROM audit_events WHERE event_type GLOB 'vault.lease.*' ORDER BY sequence DESC LIMIT 1",[],|r|r.get::<_,Vec<u8>>(0)).unwrap(),latest_before);
            assert!(matches!(
                handle.unlock(common::password_proof()).await,
                Err(AuthorityError::StorageIntegrityFailed)
            ));
            assert_eq!(handle.status().await.unwrap().state, "faulted");
            assert!(!handle.lease_recovery_batch().await.unwrap().counts.verified);
            assert!(matches!(
                handle.lease_acquire_begin(c, source(), None).await,
                Err(AuthorityError::Faulted)
            ));
            handle.shutdown(None).await.unwrap();
            join.join().unwrap();
        }
    }
}

#[tokio::test]
async fn azure_source_storage_is_typed_consume_once_and_generic_rotation_cannot_downgrade() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let original = br#"{"credential_type":"azure-key-vault-source-v1","access_token":"synthetic-authority-bootstrap"}"#;
    let next = br#"{"credential_type":"azure-key-vault-source-v1","access_token":"synthetic-authority-rotated"}"#;
    let metadata = handle
        .credential_add(
            CredentialLabel::new("azure-authority").unwrap(),
            CredentialKind::AzureKeyVaultSource,
            SecretInput::from_slice(original),
            common::password_proof(),
        )
        .await
        .unwrap();
    let prepared = handle.prepare_credential(metadata.id).await.unwrap();
    assert_eq!(prepared.kind(), CredentialKind::AzureKeyVaultSource);
    assert_eq!(prepared.version(), 1);
    prepared.consume(|bytes| assert_eq!(bytes, original));
    assert!(
        handle
            .credential_rotate(
                metadata.id,
                SecretInput::from_slice(b"downgrade"),
                common::password_proof()
            )
            .await
            .is_err()
    );
    assert!(
        handle
            .credential_rotate_typed_before(
                metadata.id,
                CredentialKind::GcpSecretManagerSource,
                None,
                SecretInput::from_slice(b"wrong-kind"),
                common::password_proof(),
                None
            )
            .await
            .is_err()
    );
    let rotated = handle
        .credential_rotate_typed_before(
            metadata.id,
            CredentialKind::AzureKeyVaultSource,
            Some(1),
            SecretInput::from_slice(next),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(rotated.current_version, 2);
    let prepared = handle.prepare_credential(metadata.id).await.unwrap();
    assert_eq!(prepared.kind(), CredentialKind::AzureKeyVaultSource);
    prepared.consume(|bytes| assert_eq!(bytes, next));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn onepassword_source_storage_is_typed_consume_once_and_generic_rotation_cannot_downgrade() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let original = br#"{"credential_type":"onepassword-connect-source-v1","access_token":"synthetic-authority-bootstrap"}"#;
    let next = br#"{"credential_type":"onepassword-connect-source-v1","access_token":"synthetic-authority-rotated"}"#;
    let metadata = handle
        .credential_add(
            CredentialLabel::new("onepassword-authority").unwrap(),
            CredentialKind::OnePasswordConnectSource,
            SecretInput::from_slice(original),
            common::password_proof(),
        )
        .await
        .unwrap();
    let prepared = handle.prepare_credential(metadata.id).await.unwrap();
    assert_eq!(prepared.kind(), CredentialKind::OnePasswordConnectSource);
    assert_eq!(prepared.version(), 1);
    prepared.consume(|bytes| assert_eq!(bytes, original));
    assert!(
        handle
            .credential_rotate(
                metadata.id,
                SecretInput::from_slice(b"downgrade"),
                common::password_proof()
            )
            .await
            .is_err()
    );
    assert!(
        handle
            .credential_rotate_typed_before(
                metadata.id,
                CredentialKind::GcpSecretManagerSource,
                None,
                SecretInput::from_slice(b"wrong-kind"),
                common::password_proof(),
                None
            )
            .await
            .is_err()
    );
    let rotated = handle
        .credential_rotate_typed_before(
            metadata.id,
            CredentialKind::OnePasswordConnectSource,
            Some(1),
            SecretInput::from_slice(next),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(rotated.current_version, 2);
    let prepared = handle.prepare_credential(metadata.id).await.unwrap();
    assert_eq!(prepared.kind(), CredentialKind::OnePasswordConnectSource);
    prepared.consume(|bytes| assert_eq!(bytes, next));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[test]
fn keychain_format_twenty_rejects_old_nineteen_state_without_migration() {
    let vault = common::init_test_vault();
    let db_path = rekey_vault::paths::vault_db(&vault.state_dir);
    let db = rusqlite::Connection::open(&db_path).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 19') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&db_path).unwrap();
    db.execute("UPDATE vault_header SET format_version=19", [])
        .unwrap();
    drop(db);
    assert!(matches!(
        rekey_vault::authority::spawn_authority(common::test_config(&vault.state_dir)),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    let db = rusqlite::Connection::open(&db_path).unwrap();
    assert_eq!(
        db.query_row("SELECT format_version FROM vault_header", [], |row| row
            .get::<_, u32>(0))
            .unwrap(),
        19
    );
}

#[tokio::test]
async fn desktop_reveal_audit_failures_never_release_plaintext() {
    for event in ["credential.reveal_started", "credential.revealed"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let saved = handle
            .credential_add(
                CredentialLabel::new("reveal-audit-canary").unwrap(),
                CredentialKind::OpaqueToken,
                SecretInput::from_slice(b"REVEAL-AUDIT-SECRET-CANARY"),
                common::password_proof(),
            )
            .await
            .unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER fail_reveal_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT, 'fixture'); END;")).unwrap();
        assert!(matches!(
            handle
                .desktop_reveal(common::password_proof(), saved.id, None)
                .await,
            Err(AuthorityError::AuditCommitFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        let completed: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='credential.revealed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(completed, 0);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}
