mod common;

use rekey_domain::ids::{PolicySignerId, SessionId, VaultId};
use rekey_vault::command::{AuditDraft, PolicyBundleInput, PolicyTrustInput};
use rekey_vault::crypto::policy_state;
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{
    PolicyBundleRecord, PolicyStateRecord, PolicyTrustRecord, event_type, outcome,
};
use rekey_vault::paths;
use rekey_vault::store::SqliteRecordStore;
use sha2::{Digest, Sha256};

fn trust_input() -> PolicyTrustInput {
    PolicyTrustInput {
        signer_id: PolicySignerId::new_random(),
        key: common::policy_key(7),
    }
}

fn bundle_input(
    vault_id: VaultId,
    signer_id: PolicySignerId,
    version: u64,
    marker: u8,
) -> PolicyBundleInput {
    let bundle_json = vec![marker; 32];
    PolicyBundleInput {
        expected_vault_id: vault_id,
        expected_trust_sha256: rekey_policy::policy_trust_sha256(signer_id, &common::policy_key(7))
            .unwrap(),
        signer_id,
        version,
        expires_at_ms: 4_102_444_800_000,
        policy_digest: [marker; 32],
        bundle_digest: Sha256::digest(&bundle_json).into(),
        bundle_json,
    }
}

fn workload_audit() -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: Some(SessionId::new_random()),
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: event_type::SESSION_CREATED,
        outcome: outcome::SUCCESS,
        reason_code: "workload-attested".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

async fn persist_policy(vault: &common::TestVault) -> PolicySignerId {
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let trust = trust_input();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    trust.signer_id
}

#[tokio::test]
async fn policy_target_is_checked_before_transaction_and_exact_retry() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let trust = trust_input();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let first = bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1);
    for committed in [false, true] {
        if committed {
            handle
                .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
                .await
                .unwrap();
        }
        for wrong_root in [false, true] {
            let mut wrong = first.clone();
            if wrong_root {
                wrong.expected_trust_sha256[0] ^= 1;
            } else {
                wrong.expected_vault_id = VaultId::new_random();
            }
            let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
            connection.execute_batch("BEGIN IMMEDIATE").unwrap();
            let error = handle
                .policy_bundle_activate_before(wrong, common::password_proof(), None)
                .await
                .unwrap_err();
            assert!(matches!(error, AuthorityError::PolicyVersionConflict));
            connection.execute_batch("ROLLBACK").unwrap();
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM audit_events WHERE event_type='policy.activated'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, i64::from(committed));
            let version: Option<u64> = connection
                .query_row("SELECT highest_version FROM policy_state", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, committed.then_some(1));
        }
    }
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn activation_time_exact_audit_and_trust_target_survive_backup_restore() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let trust = trust_input();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let first = bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1);
    let activated = handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap()
        .bundle
        .unwrap();
    let retry = handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap()
        .bundle
        .unwrap();
    assert_eq!(retry.activated_at_ms, activated.activated_at_ms);
    let bad_proof = rekey_vault::command::UnlockProof::Password(
        rekey_vault::secret::SecretInput::from_slice(b"wrong-test-proof"),
    );
    let error = handle
        .policy_bundle_activate_before(first.clone(), bad_proof, None)
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::InvalidUnlockCredential));
    let backup_path = vault.dir.path().join("policy.rkbackup");
    let receipt = handle
        .backup(backup_path.clone(), common::password_proof())
        .await
        .unwrap();
    let archived = rusqlite::Connection::open(&backup_path).unwrap();
    let archived_sequence: u64 = archived
        .query_row("SELECT MAX(sequence) FROM audit_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    let (archived_version, archived_digest): (u64, Vec<u8>) = archived
        .query_row(
            "SELECT version,bundle_digest FROM policy_bundle WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(receipt.snapshot_cut.audit_sequence, archived_sequence);
    assert_eq!(archived_version, 1);
    assert_eq!(archived_digest, first.bundle_digest);
    drop(archived);
    handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 2, 2),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let live = handle.policy_material().await.unwrap().bundle.unwrap();
    assert_eq!(live.version, 2);

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let restored = vault.dir.path().join("restored-policy");
    let id = rekey_vault::bootstrap::restore_vault(
        &backup_path,
        &restored,
        rekey_vault::bootstrap::RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    assert_eq!(id.vault_id, first.expected_vault_id);
    assert_eq!(id.snapshot_cut, receipt.snapshot_cut);
    assert_eq!(id.input_sha256_hex, receipt.sha256_hex);
    let policy_cut = receipt.snapshot_cut.policy.as_ref().unwrap();
    assert_eq!(policy_cut.version, 1);
    assert_eq!(
        policy_cut.bundle_sha256,
        data_encoding::HEXLOWER.encode(&first.bundle_digest)
    );
    let (handle, join) = common::spawn(&restored);
    handle.unlock(common::password_proof()).await.unwrap();
    let material = handle.policy_material().await.unwrap();
    let restored_trust = material.trust.unwrap();
    assert_eq!(
        rekey_policy::policy_trust_sha256(restored_trust.signer_id, &restored_trust.key).unwrap(),
        first.expected_trust_sha256
    );
    assert_eq!(
        material.bundle.unwrap().activated_at_ms,
        activated.activated_at_ms
    );
    handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(paths::vault_db(&restored)).unwrap();
    let (count, reason): (i64, String) = connection
        .query_row(
            "SELECT COUNT(*),reason_code FROM audit_events WHERE event_type='policy.activated'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        reason,
        format!(
            "policy-activated:1:{}",
            data_encoding::HEXLOWER.encode(&first.bundle_digest)
        )
    );
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn trust_is_immutable_and_policy_versions_are_consecutive_across_restart() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let trust = trust_input();
    let installed = handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    assert_eq!(installed.trust.unwrap().signer_id, trust.signer_id);
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let conflict = handle
        .policy_trust_install_before(trust_input(), common::password_proof(), None)
        .await
        .unwrap_err();
    assert!(matches!(conflict, AuthorityError::PolicyTrustConflict));

    let gap = handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 2, 2),
            common::password_proof(),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(gap, AuthorityError::PolicyVersionConflict));
    let expired = handle
        .policy_bundle_activate_before(
            PolicyBundleInput {
                expires_at_ms: 1,
                ..bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1)
            },
            common::password_proof(),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(expired, AuthorityError::PolicyVersionConflict));
    let first = bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1);
    handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap();
    handle
        .policy_bundle_activate_before(first, common::password_proof(), None)
        .await
        .unwrap();
    let same_version_different = handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 9),
            common::password_proof(),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        same_version_different,
        AuthorityError::PolicyVersionConflict
    ));
    handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 2, 2),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();

    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let material = handle.policy_material().await.unwrap();
    assert_eq!(material.state.highest_version, Some(2));
    assert_eq!(material.bundle.unwrap().version, 2);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn policy_roll_forward_clears_replays_but_exact_retry_does_not() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let trust = trust_input();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    let first = bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1);
    handle
        .policy_bundle_activate_before(first.clone(), common::password_proof(), None)
        .await
        .unwrap();
    handle
        .consume_workload_token_before([9; 32], 4_102_444_800_000, workload_audit(), None)
        .await
        .unwrap();

    handle
        .policy_bundle_activate_before(first, common::password_proof(), None)
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let after_retry: i64 = connection
        .query_row("SELECT COUNT(*) FROM workload_token_uses", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after_retry, 1);
    drop(connection);

    handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 2, 2),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let after_roll_forward: i64 = connection
        .query_row("SELECT COUNT(*) FROM workload_token_uses", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after_roll_forward, 0);
    drop(connection);

    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn policy_activation_audit_failure_rolls_back_and_faults() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let trust = trust_input();
    handle
        .policy_trust_install_before(trust.clone(), common::password_proof(), None)
        .await
        .unwrap();
    handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 1, 1),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    handle
        .consume_workload_token_before([8; 32], 4_102_444_800_000, workload_audit(), None)
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_policy_audit
             BEFORE INSERT ON audit_events
             WHEN NEW.event_type = 'policy.activated'
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    drop(connection);
    let error = handle
        .policy_bundle_activate_before(
            bundle_input(vault.outcome.vault_id, trust.signer_id, 2, 2),
            common::password_proof(),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthorityError::AuditCommitFailed));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let bundle_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM policy_bundle", [], |row| row.get(0))
        .unwrap();
    let activated: bool = connection
        .query_row(
            "SELECT bundle_activated FROM policy_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: i64 = connection
        .query_row(
            "SELECT version FROM policy_bundle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let replay_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM workload_token_uses", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(bundle_count, 1);
    assert!(activated);
    assert_eq!(version, 1);
    assert_eq!(replay_count, 1);
}

#[test]
fn missing_mandatory_or_named_policy_rows_fail_closed_on_open() {
    let vault = common::init_test_vault();
    let db = paths::vault_db(&vault.state_dir);
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute("DELETE FROM policy_state WHERE singleton=1", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        common::expect_err(SqliteRecordStore::open(&db)),
        AuthorityError::StorageIntegrityFailed
    ));
}

#[tokio::test]
async fn deleted_or_tampered_policy_records_fail_closed_on_unlock() {
    for statement in ["DELETE FROM policy_trust", "DELETE FROM policy_bundle"] {
        let vault = common::init_test_vault();
        persist_policy(&vault).await;
        let db = paths::vault_db(&vault.state_dir);
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection.execute(statement, []).unwrap();
        drop(connection);
        assert!(matches!(
            common::expect_err(SqliteRecordStore::open(&db)),
            AuthorityError::StorageIntegrityFailed
        ));
    }

    for statement in [
        format!(
            "UPDATE policy_trust SET public_key=x'{}'",
            data_encoding::HEXLOWER.encode(common::policy_key(8).as_bytes())
        ),
        "UPDATE policy_bundle SET bundle_json=x'00'".to_owned(),
    ] {
        let vault = common::init_test_vault();
        persist_policy(&vault).await;
        let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        connection.execute(&statement, []).unwrap();
        drop(connection);

        let (handle, join) = common::spawn(&vault.state_dir);
        assert!(matches!(
            handle.unlock(common::password_proof()).await.unwrap_err(),
            AuthorityError::StorageIntegrityFailed
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }

    let vault = common::init_test_vault();
    persist_policy(&vault).await;
    let connection = rusqlite::Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    connection
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON;
             UPDATE policy_trust SET algorithm='unknown' WHERE singleton=1;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        common::expect_err(rekey_vault::authority::spawn_authority(
            common::test_config(&vault.state_dir,)
        )),
        AuthorityError::StorageIntegrityFailed
    ));
}

#[test]
fn lifecycle_seals_bind_every_canonical_record_field() {
    let key = [42u8; 32];
    let vault_id: VaultId = "00112233-4455-4677-8899-aabbccddeeff".parse().unwrap();
    let signer_id: PolicySignerId = "10213243-5465-4768-899a-abbccddeeff0".parse().unwrap();
    let mut state = PolicyStateRecord {
        mode: rekey_domain::authorization::PolicyMode::Team,
        trust_installed: true,
        bundle_activated: true,
        signer_id: Some(signer_id),
        highest_version: Some(7),
        policy_digest: Some([0x11; 32]),
        bundle_digest: Some([0x22; 32]),
        updated_at_ms: 9,
        seal_nonce: [0u8; 12],
        seal_ciphertext: [0u8; 16],
    };
    assert_eq!(
        data_encoding::HEXLOWER.encode(&policy_state::canonical_state(vault_id, &state).unwrap()),
        "524b5053000200112233445546778899aabbccddeeff0201011021324354654768899aabbccddeeff00000000000000007111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000009"
    );
    let seal = policy_state::seal_state(&key, vault_id, &state).unwrap();
    state.seal_nonce = seal.nonce;
    state.seal_ciphertext = seal.ciphertext;
    policy_state::verify_state(&key, vault_id, &state).unwrap();
    assert!(
        policy_state::verify_state(&key, VaultId::new_random(), &state).is_err(),
        "vault ID must be bound"
    );
    let mut mutations = Vec::new();
    let mut changed = state.clone();
    changed.mode = rekey_domain::authorization::PolicyMode::Personal;
    mutations.push(changed);
    let mut changed = state.clone();
    changed.signer_id = Some(PolicySignerId::new_random());
    mutations.push(changed);
    let mut changed = state.clone();
    changed.highest_version = Some(8);
    mutations.push(changed);
    let mut changed = state.clone();
    changed.policy_digest = Some([9u8; 32]);
    mutations.push(changed);
    let mut changed = state.clone();
    changed.bundle_digest = Some([8u8; 32]);
    mutations.push(changed);
    let mut changed = state.clone();
    changed.updated_at_ms += 1;
    mutations.push(changed);
    for changed in mutations {
        assert!(policy_state::verify_state(&key, vault_id, &changed).is_err());
    }
    let mut partial = state.clone();
    partial.bundle_activated = false;
    partial.highest_version = None;
    assert!(policy_state::canonical_state(vault_id, &partial).is_err());

    let mut trust = PolicyTrustRecord {
        signer_id,
        key: common::policy_key(0x33),
        installed_at_ms: 10,
        seal_nonce: [0u8; 12],
        seal_ciphertext: [0u8; 16],
    };
    assert_eq!(
        data_encoding::HEXLOWER.encode(&policy_state::canonical_trust(vault_id, &trust)),
        format!(
            "524b5054000200112233445546778899aabbccddeeff1021324354654768899aabbccddeeff000010020{}000000000000000a",
            data_encoding::HEXLOWER.encode(trust.key.as_bytes())
        )
    );
    let seal = policy_state::seal_trust(&key, vault_id, &trust).unwrap();
    trust.seal_nonce = seal.nonce;
    trust.seal_ciphertext = seal.ciphertext;
    policy_state::verify_trust(&key, vault_id, &trust).unwrap();
    assert!(policy_state::verify_trust(&key, VaultId::new_random(), &trust).is_err());
    for changed in [
        {
            let mut value = trust.clone();
            value.signer_id = PolicySignerId::new_random();
            value
        },
        {
            let mut value = trust.clone();
            value.key = common::policy_key(0x34);
            value
        },
        {
            let mut value = trust.clone();
            value.installed_at_ms += 1;
            value
        },
    ] {
        assert!(policy_state::verify_trust(&key, vault_id, &changed).is_err());
    }

    let mut bundle = PolicyBundleRecord {
        signer_id,
        version: 7,
        expires_at_ms: 11,
        policy_digest: [0x11; 32],
        bundle_digest: [0x22; 32],
        bundle_json: Vec::new(),
        activated_at_ms: 12,
        seal_nonce: [0u8; 12],
        seal_ciphertext: [0u8; 16],
    };
    assert_eq!(
        data_encoding::HEXLOWER.encode(&policy_state::canonical_bundle(vault_id, &bundle)),
        "524b5042000100112233445546778899aabbccddeeff1021324354654768899aabbccddeeff00000000000000007000000000000000b11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000c"
    );
    let seal = policy_state::seal_bundle(&key, vault_id, &bundle).unwrap();
    bundle.seal_nonce = seal.nonce;
    bundle.seal_ciphertext = seal.ciphertext;
    policy_state::verify_bundle(&key, vault_id, &bundle).unwrap();
    assert!(policy_state::verify_bundle(&key, VaultId::new_random(), &bundle).is_err());
    for changed in [
        {
            let mut value = bundle.clone();
            value.signer_id = PolicySignerId::new_random();
            value
        },
        {
            let mut value = bundle.clone();
            value.version += 1;
            value
        },
        {
            let mut value = bundle.clone();
            value.expires_at_ms += 1;
            value
        },
        {
            let mut value = bundle.clone();
            value.policy_digest[0] ^= 1;
            value
        },
        {
            let mut value = bundle.clone();
            value.bundle_digest[0] ^= 1;
            value
        },
        {
            let mut value = bundle.clone();
            value.activated_at_ms += 1;
            value
        },
    ] {
        assert!(policy_state::verify_bundle(&key, vault_id, &changed).is_err());
    }
}
