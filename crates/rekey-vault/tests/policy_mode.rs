mod common;

use std::path::Path;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rekey_domain::Timestamp;
use rekey_domain::authorization::{PolicyMode, PolicyTrustAlgorithm};
use rekey_domain::ids::{PolicySignerId, VaultId};
use rekey_policy::{PolicyVerificationKey, ValidatedPolicyTrust};
use rekey_vault::bootstrap::{RestoreProof, confirm_vault_init, init_vault, restore_vault};
use rekey_vault::command::{PolicyBundleInput, PolicyMaterial, PolicyTrustInput};
use rekey_vault::error::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::model::event_type;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use rusqlite::Connection;

fn vault(mode: PolicyMode) -> common::TestVault {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let outcome = init_vault(
        &state_dir,
        &common::password_input(),
        common::TEST_PARAMS,
        mode,
    )
    .unwrap();
    confirm_vault_init(&state_dir).unwrap();
    common::TestVault {
        dir,
        state_dir,
        outcome,
    }
}

fn personal_signer() -> (EcdsaKeyPair, PolicyTrustInput) {
    // Software-only fixture: the algorithm label is not hardware provenance.
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).unwrap();
    let input = PolicyTrustInput {
        signer_id: PolicySignerId::new_random(),
        key: PolicyVerificationKey::from_bytes(
            PolicyTrustAlgorithm::SecureEnclaveP256,
            pair.public_key().as_ref(),
        )
        .unwrap(),
    };
    (pair, input)
}

fn bundle(
    pair: &EcdsaKeyPair,
    trust: &PolicyTrustInput,
    vault_id: VaultId,
    version: u64,
) -> PolicyBundleInput {
    // These ASCII keys and integer values are already in JCS order. The actual
    // policy parser verifies the signature and supplies canonical stored bytes.
    let unsigned = format!(
        r#"{{"format_version":1,"signer_id":"{}","snapshot":{{"approvers":[],"bindings":[],"connections":[],"derived_credentials":[],"expires_at_ms":4102444800000,"format_version":7,"profiles":[],"rules":[],"ssh_keys":[],"version":{},"workload_identities":[]}}}}"#,
        trust.signer_id, version
    );
    let mut message = b"RKPOLICY\0\x01".to_vec();
    message.extend_from_slice(unsigned.as_bytes());
    let signature = pair.sign(&SystemRandom::new(), &message).unwrap();
    let mut signed: serde_json::Value = serde_json::from_str(&unsigned).unwrap();
    signed["signature"] = data_encoding::BASE64URL_NOPAD
        .encode(signature.as_ref())
        .into();
    let validated = rekey_policy::parse_and_verify_policy_bundle(
        &serde_json::to_vec(&signed).unwrap(),
        &ValidatedPolicyTrust::from_parts(trust.signer_id, trust.key.clone()),
        Timestamp::from_unix_ms(1),
    )
    .unwrap();
    PolicyBundleInput {
        expected_vault_id: vault_id,
        expected_trust_sha256: rekey_policy::policy_trust_sha256(trust.signer_id, &trust.key)
            .unwrap(),
        signer_id: trust.signer_id,
        version,
        expires_at_ms: validated.snapshot().expires_at_ms(),
        policy_digest: validated.policy_digest(),
        bundle_digest: validated.bundle_digest(),
        bundle_json: validated.canonical_bytes().to_vec(),
    }
}

async fn seed(
    handle: &AuthorityHandle,
    vault_id: VaultId,
) -> (PolicyTrustInput, PolicyBundleInput) {
    handle.unlock(common::password_proof()).await.unwrap();
    let (pair, trust) = personal_signer();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let input = bundle(&pair, &trust, vault_id, 1);
    handle
        .policy_bundle_activate_before(input.clone(), common::password_proof(), None)
        .await
        .unwrap();
    (trust, input)
}

async fn finish(handle: AuthorityHandle, join: std::thread::JoinHandle<()>) {
    let proof = (handle.status().await.unwrap().state == "unlocked").then(common::password_proof);
    handle.shutdown(proof).await.unwrap();
    join.join().unwrap();
}

fn assert_material(material: &PolicyMaterial, trust: &PolicyTrustInput, input: &PolicyBundleInput) {
    assert_eq!(material.state.mode, PolicyMode::Personal);
    assert_eq!(material.state.highest_version, Some(input.version));
    let stored_trust = material.trust.as_ref().unwrap();
    assert_eq!(stored_trust.signer_id, trust.signer_id);
    assert_eq!(stored_trust.key, trust.key);
    let stored_bundle = material.bundle.as_ref().unwrap();
    assert_eq!(stored_bundle.bundle_json, input.bundle_json);
    assert_eq!(stored_bundle.bundle_digest, input.bundle_digest);
    let verified = rekey_policy::parse_and_verify_policy_bundle_for_load(
        &stored_bundle.bundle_json,
        &ValidatedPolicyTrust::from_parts(stored_trust.signer_id, stored_trust.key.clone()),
    )
    .unwrap();
    assert_eq!(verified.policy_digest(), input.policy_digest);
}

fn count(db: &Connection, event: &str) -> i64 {
    db.query_row(
        "SELECT count(*) FROM audit_events WHERE event_type=?1",
        [event],
        |r| r.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn modes_are_explicit_sealed_and_immutable_and_trust_is_same_root_only() {
    for mode in [PolicyMode::Personal, PolicyMode::Team] {
        let vault = vault(mode);
        let (handle, join) = common::spawn(&vault.state_dir);
        assert!(matches!(
            handle.policy_material().await,
            Err(AuthorityError::Locked)
        ));
        handle.unlock(common::password_proof()).await.unwrap();
        let initial = handle.policy_material().await.unwrap();
        assert_eq!(initial.state.mode, mode);
        assert!(!initial.state.trust_installed);
        assert!(initial.trust.is_none());
        assert!(initial.bundle.is_none());
        let (_, personal) = personal_signer();
        let team = PolicyTrustInput {
            signer_id: PolicySignerId::new_random(),
            key: common::policy_key(42),
        };
        let (correct, wrong, opposite) = match mode {
            PolicyMode::Personal => (personal, team, PolicyMode::Team),
            PolicyMode::Team => (team, personal, PolicyMode::Personal),
        };
        assert!(matches!(
            handle
                .policy_trust_install_before(wrong, common::password_proof(), None)
                .await,
            Err(AuthorityError::PolicyTrustConflict)
        ));
        assert!(matches!(
            common::expect_err(init_vault(
                &vault.state_dir,
                &common::password_input(),
                common::TEST_PARAMS,
                opposite
            )),
            AuthorityError::StateDirectoryNotEmpty
        ));
        let installed = handle
            .policy_trust_install_before(correct.clone(), common::password_proof(), None)
            .await
            .unwrap();
        let retry = handle
            .policy_trust_install_before(correct.clone(), common::password_proof(), None)
            .await
            .unwrap();
        assert_eq!(
            installed.trust.unwrap().installed_at_ms,
            retry.trust.unwrap().installed_at_ms
        );
        let mut different_signer = correct.clone();
        different_signer.signer_id = PolicySignerId::new_random();
        let mut different_key = correct.clone();
        different_key.key = match mode {
            PolicyMode::Personal => personal_signer().1.key,
            PolicyMode::Team => common::policy_key(43),
        };
        for replacement in [different_signer, different_key] {
            assert!(matches!(
                handle
                    .policy_trust_install_before(replacement, common::password_proof(), None)
                    .await,
                Err(AuthorityError::PolicyTrustConflict)
            ));
        }
        assert_eq!(handle.policy_material().await.unwrap().state.mode, mode);
        if mode == PolicyMode::Personal {
            let rejected = handle
                .template_catalog_before(
                    rekey_domain::ipc::TemplateSource::SignedPackage {},
                    Vec::new(),
                    None,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(rejected, AuthorityError::Domain(rekey_domain::DomainError::InvalidActionDefinition(message)) if message == "signed template packages require team mode")
            );
        }
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        assert_eq!(count(&db, event_type::POLICY_TRUST_INSTALLED), 1);
        assert_eq!(count(&db, event_type::POLICY_ACTIVATED), 0);
        drop(db);
        finish(handle, join).await;
    }
}

#[tokio::test]
async fn personal_policy_survives_reopen_rotation_and_both_backup_generations() {
    let vault = vault(PolicyMode::Personal);
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let (pair, trust) = personal_signer();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let first = bundle(&pair, &trust, vault.outcome.vault_id, 1);
    let first_material = handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let retry = handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(
        first_material.bundle.unwrap().activated_at_ms,
        retry.bundle.unwrap().activated_at_ms
    );
    for version in [1, 3] {
        let mut invalid = bundle(&pair, &trust, vault.outcome.vault_id, version);
        if version == 1 {
            invalid.expected_trust_sha256[0] ^= 1;
        }
        assert!(matches!(
            handle
                .policy_bundle_activate_before(invalid, common::password_proof(), None)
                .await,
            Err(AuthorityError::PolicyVersionConflict)
        ));
    }
    let second = bundle(&pair, &trust, vault.outcome.vault_id, 2);
    handle
        .policy_bundle_activate_before(second.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(count(&db, event_type::POLICY_ACTIVATED), 2);
    drop(db);
    let before = handle.policy_material().await.unwrap();
    assert_material(&before, &trust, &second);
    let old_backup = vault.dir.path().join("before.rkbackup");
    handle
        .backup(old_backup.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;

    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_material(&handle.policy_material().await.unwrap(), &trust, &second);
    handle.lock("policy-mode-test").await.unwrap();
    handle
        .rotate_vrk_before(
            common::password_input(),
            SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(handle.status().await.unwrap().state, "locked");
    handle.unlock(common::password_proof()).await.unwrap();
    let after = handle.policy_material().await.unwrap();
    assert_material(&after, &trust, &second);
    assert_ne!(before.state.seal_ciphertext, after.state.seal_ciphertext);
    assert_ne!(
        before.trust.unwrap().seal_ciphertext,
        after.trust.unwrap().seal_ciphertext
    );
    assert_ne!(
        before.bundle.unwrap().seal_ciphertext,
        after.bundle.unwrap().seal_ciphertext
    );
    let new_backup = vault.dir.path().join("after.rkbackup");
    handle
        .backup(new_backup.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;

    for (index, archive) in [old_backup, new_backup].iter().enumerate() {
        let target = vault.dir.path().join(format!("restored-{index}"));
        restore_vault(
            archive,
            &target,
            RestoreProof::Password(common::password_input()),
            &rekey_vault::durable::sha256_file(archive).unwrap(),
            rekey_vault::bootstrap::inspect_restore(
                archive,
                &target,
                RestoreProof::Password(common::password_input()),
                &rekey_vault::durable::sha256_file(archive).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let (handle, join) = common::spawn(&target);
        handle.unlock(common::password_proof()).await.unwrap();
        assert_material(&handle.policy_material().await.unwrap(), &trust, &second);
        finish(handle, join).await;
    }
}

fn tamper(db: &Connection, field: &str) {
    match field {
        "mode" => {
            db.execute("UPDATE policy_state SET mode='team'", [])
                .unwrap();
        }
        "key" => {
            db.execute(
                "UPDATE policy_trust SET public_key=?1",
                [personal_signer().1.key.as_bytes()],
            )
            .unwrap();
        }
        "algorithm" => {
            db.execute(
                "UPDATE policy_trust SET algorithm='ed25519',public_key=?1",
                [common::policy_key(91).as_bytes()],
            )
            .unwrap();
        }
        "bundle" => {
            db.execute("UPDATE policy_bundle SET bundle_json=x'7b7d'", [])
                .unwrap();
        }
        "unknown-mode" => {
            db.execute_batch(
                "PRAGMA ignore_check_constraints=ON; UPDATE policy_state SET mode='unknown';",
            )
            .unwrap();
        }
        "unknown-algorithm" => {
            db.execute_batch(
                "PRAGMA ignore_check_constraints=ON; UPDATE policy_trust SET algorithm='unknown';",
            )
            .unwrap();
        }
        "invalid-key" => {
            db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE policy_trust SET public_key=zeroblob(65);").unwrap();
        }
        _ => panic!("unknown test case"),
    }
}

#[tokio::test]
async fn valid_sql_rewrites_fail_reads_backup_and_rotation_and_fault() {
    for operation in ["read", "backup", "rotation"] {
        for field in ["mode", "algorithm", "key", "bundle"] {
            let vault = vault(PolicyMode::Personal);
            let (handle, join) = common::spawn(&vault.state_dir);
            seed(&handle, vault.outcome.vault_id).await;
            let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
            tamper(&db, field);
            let released_before = count(&db, event_type::BACKUP_RELEASE_AUTHORIZED);
            let output = vault.dir.path().join("must-not-release.rkbackup");
            let result = match operation {
                "read" => handle.policy_material().await.map(|_| ()),
                "backup" => handle
                    .backup(output.clone(), common::password_proof())
                    .await
                    .map(|_| ()),
                "rotation" => {
                    handle.lock("policy-test").await.unwrap();
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
                "{operation}/{field}: {result:?}"
            );
            assert_eq!(handle.status().await.unwrap().state, "faulted");
            assert_eq!(
                count(&db, event_type::BACKUP_RELEASE_AUTHORIZED),
                released_before
            );
            assert_eq!(count(&db, event_type::VAULT_VRK_ROTATED), 0);
            assert!(!output.exists());
            assert!(!paths::backup_snapshot(&vault.state_dir).exists());
            drop(db);
            finish(handle, join).await;
        }
    }
}

#[tokio::test]
async fn newly_typed_column_decode_errors_are_integrity_failures() {
    for field in ["unknown-mode", "unknown-algorithm", "invalid-key"] {
        let vault = vault(PolicyMode::Personal);
        let (handle, join) = common::spawn(&vault.state_dir);
        seed(&handle, vault.outcome.vault_id).await;
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        tamper(&db, field);
        assert!(
            matches!(
                handle.policy_material().await,
                Err(AuthorityError::StorageIntegrityFailed)
            ),
            "{field}"
        );
        // Status also decodes persisted mode, so an unknown mode deliberately
        // remains an integrity error. A second privileged read proves faulting.
        assert!(matches!(
            handle.policy_material().await,
            Err(AuthorityError::Faulted)
        ));
        assert_eq!(count(&db, event_type::RUNTIME_FAULTED), 1);
        drop(db);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn initial_mode_is_authenticated_before_any_trust_is_installed() {
    for mode in [PolicyMode::Personal, PolicyMode::Team] {
        let vault = vault(mode);
        let (handle, join) = common::spawn(&vault.state_dir);
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        db.execute(
            "UPDATE policy_state SET mode=?1",
            [match mode {
                PolicyMode::Personal => "team",
                PolicyMode::Team => "personal",
            }],
        )
        .unwrap();
        assert!(matches!(
            handle.unlock(common::password_proof()).await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        drop(db);
        finish(handle, join).await;
    }
}

fn reject_restore(archive: &Path, target: &Path) -> AuthorityError {
    let error = restore_vault(
        archive,
        target,
        RestoreProof::Password(common::password_input()),
        &rekey_vault::durable::sha256_file(archive).unwrap(),
        common::unconfirmed_restore_context(),
    )
    .unwrap_err();
    assert!(!paths::vault_db(target).exists());
    error
}

#[tokio::test]
async fn modified_backup_policy_material_and_format_twenty_two_are_rejected() {
    let vault = vault(PolicyMode::Personal);
    let (handle, join) = common::spawn(&vault.state_dir);
    seed(&handle, vault.outcome.vault_id).await;
    let archive = vault.dir.path().join("valid.rkbackup");
    handle
        .backup(archive.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;
    for field in ["mode", "algorithm", "key", "bundle"] {
        let forged = vault.dir.path().join(format!("{field}.rkbackup"));
        std::fs::copy(&archive, &forged).unwrap();
        let db = Connection::open(&forged).unwrap();
        tamper(&db, field);
        drop(db);
        assert!(
            matches!(
                reject_restore(&forged, &vault.dir.path().join(format!("restore-{field}"))),
                AuthorityError::StorageIntegrityFailed
            ),
            "{field}"
        );
    }
    assert_eq!(rekey_vault::model::FORMAT_VERSION, 26);
    let old = vault.dir.path().join("v23.rkbackup");
    std::fs::copy(&archive, &old).unwrap();
    let db = Connection::open(&old).unwrap();
    db.execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = 26','format_version = 23') WHERE name='vault_header'; PRAGMA writable_schema=OFF;").unwrap();
    drop(db);
    let db = Connection::open(&old).unwrap();
    db.execute("UPDATE vault_header SET format_version=23", [])
        .unwrap();
    drop(db);
    assert!(matches!(
        SqliteRecordStore::open(&old),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(matches!(
        reject_restore(&old, &vault.dir.path().join("restore-v23")),
        AuthorityError::UnsupportedFormatVersion
    ));
}
