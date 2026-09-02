//! Offline bootstrap: `init` and `restore`. Both run while no broker holds
//! the state directory and never touch a v1 vault.

use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rekey_domain::ids::{VaultId, WrapperId};
use zeroize::Zeroizing;

use crate::crypto::aad::{AadPurpose, AadV1};
use crate::crypto::credential_state;
use crate::crypto::kdf::{
    Argon2Params, KDF_ALGORITHM_ARGON2ID, KDF_ALGORITHM_HKDF_SHA256, derive_password_kek,
    derive_recovery_kek,
};
use crate::crypto::keys::{DataKey, Kek, RootKey};
use crate::crypto::policy_state;

/// Known plaintext sealed under the VRK so an empty vault still has an
/// internal AEAD check at restore time.
const VAULT_INTEGRITY_MARK: &[u8] = b"rekey-vault-integrity-v1";
use crate::crypto::recovery::{encode_recovery_key, parse_recovery_key};
use crate::crypto::{CRYPTO_SUITE_V1, KEY_LEN, SALT_LEN, aead, random_array};
use crate::error::AuthorityError;
use crate::model::{
    AuditEvent, FORMAT_VERSION, KeyWrapperRecord, PolicyStateRecord, VaultHeaderRecord,
    WrapperKind, WrapperState, event_type, outcome,
};
use crate::now_ms;
use crate::paths;
use crate::secret::SecretInput;
use crate::store::SqliteRecordStore;
use crate::store::schema::schema_digest;

pub struct InitOutcome {
    pub vault_id: VaultId,
    /// Displayed exactly once; never persisted anywhere.
    pub recovery_key_display: Zeroizing<String>,
}

pub enum RestoreProof {
    Password(SecretInput),
    RecoveryKey(SecretInput),
}

fn dir_is_empty(dir: &Path) -> Result<bool, AuthorityError> {
    let mut entries = fs::read_dir(dir).map_err(AuthorityError::storage)?;
    Ok(entries.next().is_none())
}

fn dir_is_restore_empty(dir: &Path) -> Result<bool, AuthorityError> {
    let mut entries = fs::read_dir(dir).map_err(AuthorityError::storage)?;
    Ok(entries.all(|entry| {
        entry
            .map(|entry| entry.file_name() == paths::BROKER_LOCK_FILE)
            .unwrap_or(false)
    }))
}

pub fn verify_state_dir_permissions(dir: &Path) -> Result<(), AuthorityError> {
    let meta = fs::metadata(dir).map_err(AuthorityError::storage)?;
    if !state_dir_metadata_is_secure(&meta, unsafe { libc::geteuid() }) {
        return Err(AuthorityError::InsecureStatePermissions);
    }
    Ok(())
}

fn state_dir_metadata_is_secure(meta: &fs::Metadata, expected_uid: u32) -> bool {
    meta.uid() == expected_uid && meta.permissions().mode() & 0o077 == 0
}

fn sqlite_sidecars(db: &Path) -> [PathBuf; 2] {
    let name = db
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir = db.parent().unwrap_or_else(|| Path::new("."));
    [
        dir.join(format!("{name}-wal")),
        dir.join(format!("{name}-shm")),
    ]
}

fn remove_sqlite_bundle(db: &Path) -> std::io::Result<()> {
    remove_if_present(db)?;
    for side in sqlite_sidecars(db) {
        remove_if_present(&side)?;
    }
    crate::durable::fsync_parent(db)
}

/// Drops a vault written by a failed init (including confirmation abort).
pub fn discard_vault_files(state_dir: &Path) -> Result<(), AuthorityError> {
    if !state_dir.exists() {
        return Ok(());
    }
    let lock = BootstrapLock::acquire(state_dir)?;
    ensure_init_marker(state_dir)?;
    remove_sqlite_bundle(&paths::vault_db(state_dir)).map_err(AuthorityError::storage)?;
    let runtime = paths::runtime_dir(state_dir);
    match fs::remove_dir(&runtime) {
        Ok(()) => crate::durable::fsync(state_dir).map_err(AuthorityError::storage)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(AuthorityError::storage(err)),
    }
    drop(lock);
    crate::durable::remove_file_and_sync(&paths::broker_lock(state_dir))
        .map_err(AuthorityError::storage)?;
    remove_init_marker(state_dir)?;
    if dir_is_empty(state_dir)? {
        fs::remove_dir(state_dir).map_err(AuthorityError::storage)?;
        crate::durable::fsync_parent(state_dir).map_err(AuthorityError::storage)?;
    }
    Ok(())
}

/// Marks the recovery-key confirmation boundary durable. Until this succeeds,
/// the authority refuses to serve the newly-created database.
pub fn confirm_vault_init(state_dir: &Path) -> Result<(), AuthorityError> {
    let _lock = BootstrapLock::acquire(state_dir)?;
    if !init_marker_is_regular(state_dir)? {
        return Err(AuthorityError::UnsupportedVaultLayout);
    }
    SqliteRecordStore::open(&paths::vault_db(state_dir))?;
    remove_init_marker(state_dir)
}

/// Held for the duration of an offline bootstrap operation.
struct BootstrapLock {
    _file: fs::File,
}

impl BootstrapLock {
    fn acquire(state_dir: &Path) -> Result<Self, AuthorityError> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths::broker_lock(state_dir))
            .map_err(AuthorityError::storage)?;
        fs::set_permissions(
            paths::broker_lock(state_dir),
            fs::Permissions::from_mode(0o600),
        )
        .map_err(AuthorityError::storage)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(AuthorityError::storage(std::io::Error::last_os_error()));
        }
        Ok(Self { _file: file })
    }
}

pub(crate) fn wrap_vrk(
    vault_id: VaultId,
    wrapper_id: WrapperId,
    kek: &Kek,
    vrk: &RootKey,
) -> Result<([u8; 12], Vec<u8>), AuthorityError> {
    let aad = AadV1 {
        purpose: AadPurpose::WrapVrk,
        vault_id,
        object_id: *wrapper_id.as_bytes(),
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0u8; 32],
    }
    .encode();
    let sealed = aead::seal(kek.bytes(), &aad, vrk.bytes())?;
    Ok((sealed.nonce, sealed.ciphertext))
}

pub(crate) fn unwrap_vrk(
    vault_id: VaultId,
    wrapper: &KeyWrapperRecord,
    kek: &Kek,
) -> Result<RootKey, AuthorityError> {
    let aad = AadV1 {
        purpose: AadPurpose::WrapVrk,
        vault_id,
        object_id: *wrapper.wrapper_id.as_bytes(),
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0u8; 32],
    }
    .encode();
    let plain = aead::open(kek.bytes(), &aad, &wrapper.nonce, &wrapper.wrapped_vrk)
        .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
    let mut bytes: [u8; KEY_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
    Ok(RootKey::from_bytes(&mut bytes))
}

pub(crate) fn kek_for_wrapper(
    wrapper: &KeyWrapperRecord,
    proof: &SecretInput,
) -> Result<Kek, AuthorityError> {
    match wrapper.kind {
        WrapperKind::Password => {
            if wrapper.kdf_algorithm != KDF_ALGORITHM_ARGON2ID {
                return Err(AuthorityError::CryptoFailure);
            }
            let params = Argon2Params::from_json(&wrapper.kdf_params_json)?;
            derive_password_kek(proof.expose(), &wrapper.salt, &params)
        }
        WrapperKind::Recovery => {
            if wrapper.kdf_algorithm != KDF_ALGORITHM_HKDF_SHA256 {
                return Err(AuthorityError::CryptoFailure);
            }
            let text = std::str::from_utf8(proof.expose())
                .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
            let key = parse_recovery_key(text)?;
            derive_recovery_kek(&key, &wrapper.salt)
        }
    }
}

pub fn init_vault(
    state_dir: &Path,
    password: &SecretInput,
    params: Argon2Params,
) -> Result<InitOutcome, AuthorityError> {
    params.validate()?;
    if password.is_empty() {
        return Err(AuthorityError::InvalidUnlockCredential);
    }
    if state_dir.exists() {
        let interrupted = init_marker_is_regular(state_dir)?;
        if !interrupted && !dir_is_empty(state_dir)? {
            return Err(AuthorityError::StateDirectoryNotEmpty);
        }
        if interrupted && !dir_has_only_init_artifacts(state_dir)? {
            return Err(AuthorityError::StateDirectoryNotEmpty);
        }
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
            .map_err(AuthorityError::storage)?;
    } else {
        fs::create_dir_all(state_dir).map_err(AuthorityError::storage)?;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
            .map_err(AuthorityError::storage)?;
    }
    verify_state_dir_permissions(state_dir)?;

    match init_vault_inner(state_dir, password, params) {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            discard_vault_files(state_dir)?;
            Err(err)
        }
    }
}

fn init_vault_inner(
    state_dir: &Path,
    password: &SecretInput,
    params: Argon2Params,
) -> Result<InitOutcome, AuthorityError> {
    let _lock = BootstrapLock::acquire(state_dir)?;
    if init_marker_is_regular(state_dir)? {
        remove_sqlite_bundle(&paths::vault_db(state_dir)).map_err(AuthorityError::storage)?;
    } else {
        create_init_marker(state_dir)?;
    }

    let vault_id = VaultId::from_random_bytes(random_array()?);
    let vrk = RootKey::generate()?;
    let recovery_key: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(random_array()?);
    let password_salt: [u8; SALT_LEN] = random_array()?;
    let recovery_salt: [u8; SALT_LEN] = random_array()?;
    let password_wrapper_id = WrapperId::from_random_bytes(random_array()?);
    let recovery_wrapper_id = WrapperId::from_random_bytes(random_array()?);
    let now = now_ms()?;

    let password_kek = derive_password_kek(password.expose(), &password_salt, &params)?;
    let recovery_kek = derive_recovery_kek(&recovery_key, &recovery_salt)?;

    let (pw_nonce, pw_ct) = wrap_vrk(vault_id, password_wrapper_id, &password_kek, &vrk)?;
    let (rk_nonce, rk_ct) = wrap_vrk(vault_id, recovery_wrapper_id, &recovery_kek, &vrk)?;
    let integrity = seal_integrity(vault_id, &vrk)?;

    let wrappers = [
        KeyWrapperRecord {
            wrapper_id: password_wrapper_id,
            kind: WrapperKind::Password,
            state: WrapperState::Active,
            kdf_algorithm: KDF_ALGORITHM_ARGON2ID.to_owned(),
            kdf_params_json: params.to_json(),
            salt: password_salt,
            nonce: pw_nonce,
            wrapped_vrk: pw_ct,
            created_at_ms: now,
            disabled_at_ms: None,
        },
        KeyWrapperRecord {
            wrapper_id: recovery_wrapper_id,
            kind: WrapperKind::Recovery,
            state: WrapperState::Active,
            kdf_algorithm: KDF_ALGORITHM_HKDF_SHA256.to_owned(),
            kdf_params_json: "{}".to_owned(),
            salt: recovery_salt,
            nonce: rk_nonce,
            wrapped_vrk: rk_ct,
            created_at_ms: now,
            disabled_at_ms: None,
        },
    ];

    let header = VaultHeaderRecord {
        vault_id,
        format_version: FORMAT_VERSION,
        crypto_suite: CRYPTO_SUITE_V1.to_owned(),
        created_at_ms: now,
        schema_digest: schema_digest(),
        integrity_nonce: integrity.nonce,
        integrity_ciphertext: integrity.ciphertext,
    };

    let mut policy_state_record = PolicyStateRecord {
        trust_installed: false,
        bundle_activated: false,
        signer_id: None,
        highest_version: None,
        policy_digest: None,
        bundle_digest: None,
        updated_at_ms: now,
        seal_nonce: [0u8; 12],
        seal_ciphertext: [0u8; 16],
    };
    let policy_seal = policy_state::seal_state(vrk.bytes(), vault_id, &policy_state_record)?;
    policy_state_record.seal_nonce = policy_seal.nonce;
    policy_state_record.seal_ciphertext = policy_seal.ciphertext;

    let mut store = SqliteRecordStore::create(&paths::vault_db(state_dir))?;
    store.initialize(
        &header,
        &wrappers,
        &policy_state_record,
        AuditEvent {
            event_id: random_array()?,
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            event_type: event_type::VAULT_INITIALIZED,
            outcome: outcome::SUCCESS,
            reason_code: "init".to_owned(),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: now,
        },
    )?;
    drop(store);

    // Re-open and prove both wrappers recover the same VRK before reporting
    // success to the human.
    let reopened = SqliteRecordStore::open(&paths::vault_db(state_dir))?;
    let pw_wrapper = reopened.active_wrapper(WrapperKind::Password)?;
    let rk_wrapper = reopened.active_wrapper(WrapperKind::Recovery)?;
    let recovery_display = encode_recovery_key(&recovery_key);
    let vrk_a = unwrap_vrk(
        vault_id,
        &pw_wrapper,
        &kek_for_wrapper(&pw_wrapper, password)?,
    )?;
    let recovery_input = SecretInput::from_slice(recovery_display.as_bytes());
    let vrk_b = unwrap_vrk(
        vault_id,
        &rk_wrapper,
        &kek_for_wrapper(&rk_wrapper, &recovery_input)?,
    )?;
    if vrk_a.bytes() != vrk.bytes() || vrk_b.bytes() != vrk.bytes() {
        return Err(AuthorityError::CryptoFailure);
    }

    Ok(InitOutcome {
        vault_id,
        recovery_key_display: recovery_display,
    })
}

fn init_marker_is_regular(state_dir: &Path) -> Result<bool, AuthorityError> {
    match fs::symlink_metadata(paths::init_incomplete(state_dir)) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(AuthorityError::UnsupportedVaultLayout),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(AuthorityError::storage(err)),
    }
}

fn dir_has_only_init_artifacts(state_dir: &Path) -> Result<bool, AuthorityError> {
    let db = paths::vault_db(state_dir);
    let sidecars = sqlite_sidecars(&db);
    let allowed = [
        paths::init_incomplete(state_dir),
        paths::broker_lock(state_dir),
        db,
        sidecars[0].clone(),
        sidecars[1].clone(),
    ];
    for entry in fs::read_dir(state_dir).map_err(AuthorityError::storage)? {
        let path = entry.map_err(AuthorityError::storage)?.path();
        if !allowed.iter().any(|candidate| candidate == &path) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn create_init_marker(state_dir: &Path) -> Result<(), AuthorityError> {
    let marker = paths::init_incomplete(state_dir);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)
        .map_err(AuthorityError::storage)?;
    file.write_all(b"rekey-init-incomplete-v1\n")
        .map_err(AuthorityError::storage)?;
    file.sync_all().map_err(AuthorityError::storage)?;
    crate::durable::fsync(state_dir).map_err(AuthorityError::storage)
}

fn ensure_init_marker(state_dir: &Path) -> Result<(), AuthorityError> {
    if init_marker_is_regular(state_dir)? {
        Ok(())
    } else {
        create_init_marker(state_dir)
    }
}

fn remove_init_marker(state_dir: &Path) -> Result<(), AuthorityError> {
    crate::durable::remove_file_and_sync(&paths::init_incomplete(state_dir))
        .map_err(AuthorityError::storage)
}

/// Offline restore of a v5 backup into an empty target state directory.
/// `expected_sha256_hex` is the backup receipt hash and is mandatory.
pub fn restore_vault(
    backup_file: &Path,
    target_state_dir: &Path,
    proof: RestoreProof,
    expected_sha256_hex: &str,
) -> Result<VaultId, AuthorityError> {
    if target_state_dir.exists() {
        if !restore_marker_is_regular(target_state_dir)? && !dir_is_restore_empty(target_state_dir)?
        {
            return Err(AuthorityError::StateDirectoryNotEmpty);
        }
    } else {
        fs::create_dir_all(target_state_dir).map_err(AuthorityError::storage)?;
    }
    fs::set_permissions(target_state_dir, fs::Permissions::from_mode(0o700))
        .map_err(AuthorityError::storage)?;
    verify_state_dir_permissions(target_state_dir)?;

    let _lock = BootstrapLock::acquire(target_state_dir)?;
    if restore_marker_is_regular(target_state_dir)? {
        cleanup_restore_artifacts(target_state_dir).map_err(|_| AuthorityError::RestoreFailed)?;
        remove_restore_marker(target_state_dir).map_err(|_| AuthorityError::RestoreFailed)?;
    }
    if !dir_is_restore_empty(target_state_dir)? {
        return Err(AuthorityError::StateDirectoryNotEmpty);
    }
    create_restore_marker(target_state_dir).map_err(|_| AuthorityError::RestoreFailed)?;

    let result = restore_inner(backup_file, target_state_dir, proof, expected_sha256_hex);
    if result.is_err() {
        if cleanup_failed_restore(target_state_dir).is_err() {
            return Err(AuthorityError::RestoreFailed);
        }
        return result;
    }
    result
}

fn restore_inner(
    backup_file: &Path,
    target_state_dir: &Path,
    proof: RestoreProof,
    expected_sha256_hex: &str,
) -> Result<VaultId, AuthorityError> {
    if !is_sha256_hex(expected_sha256_hex) {
        return Err(AuthorityError::RestoreFailed);
    }
    let staging = target_state_dir.join(".incoming-vault.sqlite3");
    let digest = crate::durable::copy_and_sha256(backup_file, &staging)
        .map_err(|_| AuthorityError::RestoreFailed)?;
    if !digest.eq_ignore_ascii_case(expected_sha256_hex) {
        return Err(AuthorityError::RestoreFailed);
    }

    let mut store = SqliteRecordStore::open(&staging).map_err(|err| match err {
        AuthorityError::StorageIntegrityFailed
        | AuthorityError::UnsupportedFormatVersion
        | AuthorityError::UnsupportedVaultLayout => err,
        _ => AuthorityError::RestoreFailed,
    })?;
    let header = store.load_header()?;

    let (wrapper, secret) = match &proof {
        RestoreProof::Password(secret) => (store.active_wrapper(WrapperKind::Password)?, secret),
        RestoreProof::RecoveryKey(secret) => (store.active_wrapper(WrapperKind::Recovery)?, secret),
    };
    let kek = kek_for_wrapper(&wrapper, secret)?;
    let vrk = unwrap_vrk(header.vault_id, &wrapper, &kek)?;
    prove_integrity(&header, &vrk)?;
    prove_all_credential_states(&store, header.vault_id, &vrk)?;
    prove_all_payloads(&store, header.vault_id, &vrk)?;
    store.verified_policy_material(vrk.bytes(), header.vault_id)?;

    store.append_audit(&AuditEvent {
        event_id: random_array()?,
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        event_type: event_type::RESTORE_COMPLETED,
        outcome: outcome::SUCCESS,
        reason_code: "restore".to_owned(),
        upstream_status: None,
        latency_ms: None,
        created_at_ms: now_ms()?,
    })?;
    store.wal_checkpoint()?;
    drop(store);

    crate::durable::fsync(&staging).map_err(|_| AuthorityError::RestoreFailed)?;
    install_staging(&staging, target_state_dir)?;
    for side in sqlite_sidecars(&staging) {
        remove_if_present(&side).map_err(|_| AuthorityError::RestoreFailed)?;
    }
    crate::durable::fsync(target_state_dir).map_err(|_| AuthorityError::RestoreFailed)?;
    remove_restore_marker(target_state_dir).map_err(|_| AuthorityError::RestoreFailed)?;
    Ok(header.vault_id)
}

fn install_staging(staging: &Path, target_state_dir: &Path) -> Result<(), AuthorityError> {
    fs::rename(staging, paths::vault_db(target_state_dir))
        .map_err(|_| AuthorityError::RestoreFailed)?;
    crate::durable::fsync(target_state_dir).map_err(|_| AuthorityError::RestoreFailed)
}

fn restore_marker_is_regular(state_dir: &Path) -> Result<bool, AuthorityError> {
    match fs::symlink_metadata(paths::restore_incomplete(state_dir)) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(AuthorityError::UnsupportedVaultLayout),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(AuthorityError::storage(err)),
    }
}

fn create_restore_marker(state_dir: &Path) -> std::io::Result<()> {
    let marker = paths::restore_incomplete(state_dir);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)?;
    file.write_all(b"rekey-restore-incomplete-v1\n")?;
    file.sync_all()?;
    crate::durable::fsync(state_dir)
}

fn remove_restore_marker(state_dir: &Path) -> std::io::Result<()> {
    crate::durable::remove_file_and_sync(&paths::restore_incomplete(state_dir))
}

fn cleanup_failed_restore(state_dir: &Path) -> std::io::Result<()> {
    if !paths::restore_incomplete(state_dir).exists() {
        create_restore_marker(state_dir)?;
    }
    cleanup_restore_artifacts(state_dir)?;
    remove_restore_marker(state_dir)
}

fn cleanup_restore_artifacts(state_dir: &Path) -> std::io::Result<()> {
    let staging = state_dir.join(".incoming-vault.sqlite3");
    let installed = paths::vault_db(state_dir);
    for path in [
        installed.clone(),
        sqlite_sidecars(&installed)[0].clone(),
        sqlite_sidecars(&installed)[1].clone(),
        staging.clone(),
        sqlite_sidecars(&staging)[0].clone(),
        sqlite_sidecars(&staging)[1].clone(),
    ] {
        remove_if_present(&path)?;
    }
    crate::durable::fsync(state_dir)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn integrity_aad(vault_id: VaultId) -> [u8; crate::crypto::aad::AAD_LEN] {
    AadV1 {
        purpose: AadPurpose::VaultIntegrity,
        vault_id,
        object_id: *vault_id.as_bytes(),
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0u8; 32],
    }
    .encode()
}

fn seal_integrity(vault_id: VaultId, vrk: &RootKey) -> Result<aead::Sealed, AuthorityError> {
    aead::seal(vrk.bytes(), &integrity_aad(vault_id), VAULT_INTEGRITY_MARK)
}

fn prove_integrity(header: &VaultHeaderRecord, vrk: &RootKey) -> Result<(), AuthorityError> {
    let plain = aead::open(
        vrk.bytes(),
        &integrity_aad(header.vault_id),
        &header.integrity_nonce,
        &header.integrity_ciphertext,
    )
    .map_err(|_| AuthorityError::CryptoFailure)?;
    if plain.as_slice() != VAULT_INTEGRITY_MARK {
        return Err(AuthorityError::CryptoFailure);
    }
    Ok(())
}

fn prove_all_payloads(
    store: &SqliteRecordStore,
    vault_id: VaultId,
    vrk: &RootKey,
) -> Result<(), AuthorityError> {
    for (kind, version) in store.list_all_versions()? {
        let dek_aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id,
            object_id: *version.credential_id.as_bytes(),
            object_version: version.version,
            credential_kind: 0,
            constraints_hash: [0u8; 32],
        }
        .encode();
        let dek_bytes = aead::open(
            vrk.bytes(),
            &dek_aad,
            &version.dek_nonce,
            &version.wrapped_dek,
        )
        .map_err(|_| AuthorityError::CryptoFailure)?;
        let mut dek_arr: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityError::CryptoFailure)?;
        let dek = DataKey::from_bytes(&mut dek_arr);
        let payload_aad = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id,
            object_id: *version.credential_id.as_bytes(),
            object_version: version.version,
            credential_kind: kind.aad_code(),
            constraints_hash: [0u8; 32],
        }
        .encode();
        let payload = aead::open(
            dek.bytes(),
            &payload_aad,
            &version.payload_nonce,
            &version.encrypted_payload,
        )
        .map_err(|_| AuthorityError::CryptoFailure)?;
        drop(payload);
    }
    Ok(())
}

fn prove_all_credential_states(
    store: &SqliteRecordStore,
    vault_id: VaultId,
    vrk: &RootKey,
) -> Result<(), AuthorityError> {
    store.validate_credential_version_invariants()?;
    for record in store.list_credentials()? {
        credential_state::verify(vrk.bytes(), vault_id, &record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_directory_security_requires_the_broker_owner() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(dir.path()).unwrap();
        assert!(state_dir_metadata_is_secure(&metadata, metadata.uid()));
        assert!(!state_dir_metadata_is_secure(
            &metadata,
            metadata.uid().wrapping_add(1)
        ));
    }

    #[test]
    fn final_rename_failure_keeps_restore_blocked_until_cleanup() {
        let target = tempfile::tempdir().unwrap();
        create_restore_marker(target.path()).unwrap();
        let staging = target.path().join(".incoming-vault.sqlite3");
        fs::write(&staging, b"staged vault").unwrap();
        let installed = paths::vault_db(target.path());
        fs::create_dir(&installed).unwrap();

        assert!(matches!(
            install_staging(&staging, target.path()),
            Err(AuthorityError::RestoreFailed)
        ));
        assert!(cleanup_failed_restore(target.path()).is_err());
        assert!(paths::restore_incomplete(target.path()).exists());
        assert!(staging.exists());

        fs::remove_dir(&installed).unwrap();
        cleanup_failed_restore(target.path()).unwrap();
        assert!(!paths::restore_incomplete(target.path()).exists());
        assert!(!staging.exists());

        create_restore_marker(target.path()).unwrap();
        fs::write(&staging, b"retry vault").unwrap();
        install_staging(&staging, target.path()).unwrap();
        remove_restore_marker(target.path()).unwrap();
        assert!(installed.is_file());
    }
}
