#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_vault::bootstrap::{InitOutcome, confirm_vault_init, init_vault};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::handle::{AuthorityConfig, AuthorityHandle};
use rekey_vault::secret::SecretInput;

pub const TEST_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};

pub const PASSWORD: &[u8] = b"correct horse battery staple";

pub struct TestVault {
    pub dir: tempfile::TempDir,
    pub state_dir: PathBuf,
    pub outcome: InitOutcome,
}

pub fn init_test_vault() -> TestVault {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let outcome = init_vault(
        &state_dir,
        &SecretInput::from_slice(PASSWORD),
        TEST_PARAMS,
        rekey_domain::authorization::PolicyMode::Team,
    )
    .expect("init vault");
    confirm_vault_init(&state_dir).expect("confirm init");
    TestVault {
        dir,
        state_dir,
        outcome,
    }
}

pub fn test_config(state_dir: &Path) -> AuthorityConfig {
    let mut config = AuthorityConfig::new(state_dir.to_owned());
    config.unlock_backoff_base = Duration::from_millis(20);
    config
}

pub fn spawn(state_dir: &Path) -> (AuthorityHandle, std::thread::JoinHandle<()>) {
    rekey_vault::authority::spawn_authority(test_config(state_dir)).expect("spawn authority")
}

pub fn password_input() -> SecretInput {
    SecretInput::from_slice(PASSWORD)
}

pub fn password_proof() -> rekey_vault::command::UnlockProof {
    rekey_vault::command::UnlockProof::Password(password_input())
}

/// `unwrap_err` needs `T: Debug`; secret-bearing types deliberately are not.
pub fn expect_err<T>(
    result: Result<T, rekey_vault::error::AuthorityError>,
) -> rekey_vault::error::AuthorityError {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(err) => err,
    }
}

/// Deterministic synthetic Ed25519 public verification material for team fixtures.
pub fn policy_key(seed: u8) -> rekey_policy::PolicyVerificationKey {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    rekey_policy::PolicyVerificationKey::from_bytes(
        rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519,
        pair.public_key().as_ref(),
    )
    .unwrap()
}

/// Opens synthetic fixture material only; this is not a product restore preview.
pub fn fixture_root(state: &Path) -> zeroize::Zeroizing<[u8; 32]> {
    use rekey_vault::{
        crypto::{
            aad::{AadPurpose, AadV1},
            aead, kdf,
        },
        model::WrapperKind,
        store::SqliteRecordStore,
    };
    let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(state)).unwrap();
    let header = store.load_header().unwrap();
    let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
    let params = kdf::Argon2Params::from_json(&wrapper.kdf_params_json).unwrap();
    let mut kek = zeroize::Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(32),
        )
        .unwrap(),
    )
    .hash_password_into(PASSWORD, &wrapper.salt, &mut *kek)
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
    let bytes = aead::open(&kek, &aad, &wrapper.nonce, &wrapper.wrapped_vrk).unwrap();
    zeroize::Zeroizing::new(bytes.as_slice().try_into().unwrap())
}

pub fn fixture_anchors(state: &Path) -> rekey_vault::generation_anchor::GenerationAnchors {
    let header = rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(state))
        .unwrap()
        .load_header()
        .unwrap();
    rekey_vault::generation_anchor::GenerationAnchors::open(state, header.vault_id).unwrap()
}
pub fn generation_attempt<'a>(
    state: &Path,
    anchors: &'a rekey_vault::generation_anchor::GenerationAnchors,
) -> rekey_vault::store::generation::GenerationAttempt<'a> {
    let header = rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(state))
        .unwrap()
        .load_header()
        .unwrap();
    rekey_vault::store::generation::GenerationAttempt::new(
        anchors,
        &header,
        anchors.read().unwrap(),
        &fixture_root(state),
        header.generation + 1,
        None,
        None,
    )
    .unwrap()
}

/// Negative restore fixtures only: proof/format/seal/SHA errors must be
/// exercised by restore itself before context comparison. Never use for success.
pub fn unconfirmed_restore_context() -> rekey_domain::ipc::RollbackContext {
    rekey_domain::ipc::RollbackContext {
        vault_id: rekey_domain::ids::VaultId::from_bytes([0x59; 16]).unwrap(),
        source_generation: 1,
        high_water: None,
        history_missing: true,
    }
}
