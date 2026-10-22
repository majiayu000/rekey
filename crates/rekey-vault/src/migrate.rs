//! Offline upgrade migration from a released vault line (vault25 / 0.3,
//! vault26 / 0.4, vault27 / 0.5) into a new vault27 with a new vault id.
//!
//! The source directory is never written: its database is copied into a
//! private scratch directory and read there while a shared lock on the
//! source's `broker.lock` keeps a broker from starting. Every credential
//! version is decrypted inside this process with the source VRK and
//! re-encrypted under the new vault; plaintext is never exported. Policy
//! trust carries over; the signed policy does not (its signature binds the
//! old vault), so the Connection set becomes an unsigned draft request the
//! owner re-signs. Audit history, usage ledgers and replay state are not
//! imported; one `migration.completed` event names the source.

mod policy;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use aws_lc_rs::hmac;
use hkdf::Hkdf;
use rekey_domain::authorization::PolicyMode;
use rekey_domain::credential::CredentialKind;
use rekey_domain::ids::{CredentialId, VaultId};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::bootstrap::{
    RestoreProof, authenticate_restore, init_vault, kek_for_wrapper, unwrap_vrk,
    verify_integrity_mark, verify_state_dir_permissions,
};
use crate::crypto::aad::{AadPurpose, AadV1};
use crate::crypto::kdf::Argon2Params;
use crate::crypto::keys::DataKey;
use crate::crypto::{AAD_VERSION_V1, CRYPTO_SUITE_V1, aead, credential_state, policy_state};
use crate::error::AuthorityError;
use crate::generation_anchor::GenerationAnchors;
use crate::model::{
    AuditEvent, AuditRetentionRecord, CredentialRecord, CredentialVersionRecord, FORMAT_VERSION,
    PolicyStateRecord, PolicyTrustRecord, VaultHeaderRecord, WrapperKind, event_type, outcome,
};
use crate::secret::SecretInput;
use crate::store::SqliteRecordStore;
use crate::store::generation::GenerationAttempt;
use crate::store::legacy::{LegacyTable, LegacyVault};
use crate::{now_ms, paths};

/// Unsigned Connection draft request written beside the new vault.
pub const MIGRATED_POLICY_REQUEST_FILE: &str = "migrated-policy-request.json";
/// Basic-mode software policy signer created by `rekey add`.
pub const SOFTWARE_POLICY_SIGNER_FILE: &str = "policy-signer-p256.p8";

pub struct MigrateOutcome {
    pub vault_id: VaultId,
    pub source_vault_id: VaultId,
    pub source_format: u32,
    pub source_generation: u64,
    pub mode: PolicyMode,
    pub credentials: usize,
    pub versions: usize,
    pub trust_carried: bool,
    pub signer_key_copied: bool,
    /// Present when the source had a signed policy to re-sign.
    pub policy_request: Option<PathBuf>,
    pub connections: usize,
    pub ssh_keys: usize,
    pub derived_credentials: usize,
    /// Items the owner must confirm before re-signing; no secret material.
    pub review: Vec<String>,
    /// Displayed exactly once; never persisted anywhere.
    pub recovery_key_display: Zeroizing<String>,
}

/// One decrypted source credential, held only for re-encryption.
struct SourceCredential {
    record: CredentialRecord,
    versions: Vec<(CredentialVersionRecord, Zeroizing<Vec<u8>>)>,
}

struct Source {
    header: VaultHeaderRecord,
    mode: PolicyMode,
    credentials: Vec<SourceCredential>,
    trust: Option<PolicyTrustRecord>,
    retention_days: Option<u64>,
    bundle_json: Option<Vec<u8>>,
}

/// Migrates `source_dir` into the empty `target_dir`. The new vault keeps the
/// init marker: the caller shows the new recovery key, then calls
/// [`crate::bootstrap::confirm_vault_init`].
pub fn migrate_vault(
    source_dir: &Path,
    target_dir: &Path,
    password: &SecretInput,
    params: Argon2Params,
) -> Result<MigrateOutcome, AuthorityError> {
    if password.is_empty() {
        return Err(AuthorityError::InvalidUnlockCredential);
    }
    let source_dir = source_dir.canonicalize().map_err(AuthorityError::storage)?;
    // A not-yet-created target is resolved through its parent, so a nested
    // `--to` can never make init write into the source directory.
    let target = match target_dir.canonicalize() {
        Ok(target) => target,
        Err(_) => {
            let parent = target_dir
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let name = target_dir
                .file_name()
                .ok_or(AuthorityError::StateDirectoryNotEmpty)?;
            parent
                .canonicalize()
                .map_err(AuthorityError::storage)?
                .join(name)
        }
    };
    if target.starts_with(&source_dir) {
        return Err(AuthorityError::MigrationRefused(
            "the target must be a separate directory outside the source",
        ));
    }
    verify_state_dir_permissions(&source_dir)?;
    for marker in [
        paths::init_incomplete(&source_dir),
        paths::restore_incomplete(&source_dir),
    ] {
        if fs::symlink_metadata(&marker).is_ok() {
            return Err(AuthorityError::MigrationRefused(
                "the source has an unfinished init or restore",
            ));
        }
    }
    let _source_lock = SourceLock::acquire(&source_dir)?;
    let source = read_source(&source_dir, password)?;

    let credential_ids: BTreeSet<CredentialId> = source
        .credentials
        .iter()
        .map(|credential| credential.record.credential_id)
        .collect();
    let carried = source
        .bundle_json
        .as_deref()
        .map(|bundle| policy::carry_over(bundle, &credential_ids, now_ms()?))
        .transpose()?;

    let init = init_vault(target_dir, password, params, source.mode)?;
    import(target_dir, password, &source, init.vault_id)?;
    verify_target(target_dir, password, &source)?;

    let mut outcome = MigrateOutcome {
        vault_id: init.vault_id,
        source_vault_id: source.header.vault_id,
        source_format: source.header.format_version,
        source_generation: source.header.generation,
        mode: source.mode,
        credentials: source.credentials.len(),
        versions: source.credentials.iter().map(|c| c.versions.len()).sum(),
        trust_carried: source.trust.is_some(),
        signer_key_copied: false,
        policy_request: None,
        connections: 0,
        ssh_keys: 0,
        derived_credentials: 0,
        review: Vec::new(),
        recovery_key_display: init.recovery_key_display,
    };
    if let Some(carried) = carried {
        let path = target_dir.join(MIGRATED_POLICY_REQUEST_FILE);
        let json = serde_json::to_vec_pretty(&carried.request)
            .map_err(|_| AuthorityError::CryptoFailure)?;
        write_private(&path, &json)?;
        outcome.connections = carried.request.connections.len();
        outcome.ssh_keys = carried.request.ssh_keys.as_ref().map_or(0, Vec::len);
        outcome.derived_credentials = carried
            .request
            .derived_credentials
            .as_ref()
            .map_or(0, Vec::len);
        outcome.review = carried.review;
        outcome.policy_request = Some(path);
    }
    let signer = source_dir.join(SOFTWARE_POLICY_SIGNER_FILE);
    if source.trust.is_some() && fs::symlink_metadata(&signer).is_ok_and(|m| m.is_file()) {
        let bytes = Zeroizing::new(fs::read(&signer).map_err(AuthorityError::storage)?);
        write_private(&target_dir.join(SOFTWARE_POLICY_SIGNER_FILE), &bytes)?;
        outcome.signer_key_copied = true;
    }
    Ok(outcome)
}

/// Shared lock on the source `broker.lock`: a running broker holds it
/// exclusively, and a broker cannot start while migration reads.
struct SourceLock {
    _file: Option<fs::File>,
}

impl SourceLock {
    fn acquire(source_dir: &Path) -> Result<Self, AuthorityError> {
        let path = paths::broker_lock(source_dir);
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { _file: None });
            }
            Err(error) => return Err(AuthorityError::storage(error)),
        };
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if rc != 0 {
            return Err(AuthorityError::MigrationRefused(
                "the source vault is in use; stop rekeyd and quit the App first",
            ));
        }
        Ok(Self { _file: Some(file) })
    }
}

fn read_source(source_dir: &Path, password: &SecretInput) -> Result<Source, AuthorityError> {
    let db = paths::vault_db(source_dir);
    if !fs::symlink_metadata(&db).is_ok_and(|m| m.is_file()) {
        return Err(AuthorityError::NotInitialized);
    }
    let scratch = std::env::temp_dir().join(format!(
        "rekey-migrate-{}",
        data_encoding::HEXLOWER.encode(&crate::crypto::random_array::<16>()?)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&scratch)
        .map_err(AuthorityError::storage)?;
    let result = (|| {
        let copy = scratch.join(paths::VAULT_DB_FILE);
        copy_private(&db, &copy)?;
        let wal = source_dir.join(format!("{}-wal", paths::VAULT_DB_FILE));
        if fs::symlink_metadata(&wal).is_ok_and(|m| m.is_file()) {
            copy_private(&wal, &scratch.join(format!("{}-wal", paths::VAULT_DB_FILE)))?;
        }
        let legacy = LegacyVault::open(&copy)?;
        read_legacy(source_dir, &legacy, password)
    })();
    fs::remove_dir_all(&scratch).map_err(AuthorityError::storage)?;
    result
}

fn read_legacy(
    source_dir: &Path,
    legacy: &LegacyVault,
    password: &SecretInput,
) -> Result<Source, AuthorityError> {
    let header = legacy.header.clone();
    let wrapper = legacy.password_wrapper()?;
    let vrk = unwrap_vrk(
        header.vault_id,
        &wrapper,
        &kek_for_wrapper(&wrapper, password)?,
    )?;
    if header.format_version == FORMAT_VERSION {
        crate::crypto::generation::verify(vrk.bytes(), &header)?;
    } else {
        verify_generation_v1(vrk.bytes(), &header)?;
    }
    verify_integrity_mark(&header, vrk.bytes())?;

    // Same rule as unlock: the source must be at its own recorded high-water.
    let observed = GenerationAnchors::open(source_dir, header.vault_id)?.read()?;
    if observed.file != Some(header.generation)
        || observed.protected.is_some_and(|g| g != header.generation)
    {
        return Err(AuthorityError::RollbackSuspected);
    }
    for (table, reason) in [
        (
            LegacyTable::LeaseJournal,
            "the source has open dynamic-credential leases; let them finish or clean up first",
        ),
        (
            LegacyTable::Actions,
            "the source has lab Actions, which migration does not carry",
        ),
        (
            LegacyTable::PkiCertificates,
            "the source has PKI issuance history, which migration does not carry",
        ),
    ] {
        if legacy.count(table)? != 0 {
            return Err(AuthorityError::MigrationRefused(reason));
        }
    }

    let mut credentials = Vec::new();
    for legacy_credential in legacy.credentials()? {
        let record = legacy_credential.record;
        credential_state::verify(vrk.bytes(), header.vault_id, &record)?;
        let mut versions = Vec::with_capacity(legacy_credential.versions.len());
        for version in legacy_credential.versions {
            let plaintext = open_version(vrk.bytes(), header.vault_id, record.kind, &version)?;
            versions.push((version, plaintext));
        }
        credentials.push(SourceCredential { record, versions });
    }
    let material = legacy.verified_policy_material(vrk.bytes(), header.vault_id)?;
    let retention = legacy.verified_audit_retention(vrk.bytes(), header.vault_id)?;
    Ok(Source {
        header,
        mode: material.state.mode,
        credentials,
        trust: material.trust,
        retention_days: retention.days,
        bundle_json: material.bundle.map(|bundle| bundle.bundle_json),
    })
}

fn import(
    target_dir: &Path,
    password: &SecretInput,
    source: &Source,
    vault_id: VaultId,
) -> Result<(), AuthorityError> {
    let mut store = SqliteRecordStore::open(&paths::vault_db(target_dir))?;
    let header = store.load_header()?;
    if header.vault_id != vault_id {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    let wrapper = store.active_wrapper(WrapperKind::Password)?;
    let vrk = unwrap_vrk(vault_id, &wrapper, &kek_for_wrapper(&wrapper, password)?)?;
    let now = now_ms()?;

    let mut credentials = Vec::with_capacity(source.credentials.len());
    for credential in &source.credentials {
        let mut record = credential.record.clone();
        let seal = credential_state::seal(vrk.bytes(), vault_id, &record)?;
        record.state_nonce = seal.nonce;
        record.state_ciphertext = seal.ciphertext;
        let versions = credential
            .versions
            .iter()
            .map(|(version, plaintext)| {
                seal_version(vrk.bytes(), vault_id, record.kind, version, plaintext)
            })
            .collect::<Result<Vec<_>, _>>()?;
        credentials.push((record, versions));
    }

    let mut policy_state_record = store.load_policy_state()?;
    let trust = match &source.trust {
        Some(trust) => {
            let mut trust = PolicyTrustRecord {
                signer_id: trust.signer_id,
                key: trust.key.clone(),
                installed_at_ms: trust.installed_at_ms,
                seal_nonce: [0; 12],
                seal_ciphertext: [0; 16],
            };
            let seal = policy_state::seal_trust(vrk.bytes(), vault_id, &trust)?;
            trust.seal_nonce = seal.nonce;
            trust.seal_ciphertext = seal.ciphertext;
            policy_state_record = PolicyStateRecord {
                trust_installed: true,
                signer_id: Some(trust.signer_id),
                updated_at_ms: now,
                ..policy_state_record
            };
            let seal = policy_state::seal_state(vrk.bytes(), vault_id, &policy_state_record)?;
            policy_state_record.seal_nonce = seal.nonce;
            policy_state_record.seal_ciphertext = seal.ciphertext;
            Some(trust)
        }
        None => None,
    };
    let mut retention = AuditRetentionRecord {
        days: source.retention_days,
        updated_at_ms: now,
        seal_nonce: [0; 12],
        seal_ciphertext: [0; 16],
    };
    let seal = policy_state::seal_retention(vrk.bytes(), vault_id, &retention)?;
    retention.seal_nonce = seal.nonce;
    retention.seal_ciphertext = seal.ciphertext;

    let anchors = GenerationAnchors::open(target_dir, vault_id)?;
    let observed = anchors.read()?;
    let next = header
        .generation
        .checked_add(1)
        .ok_or(AuthorityError::StorageIntegrityFailed)?;
    let mut generation =
        GenerationAttempt::new(&anchors, &header, observed, vrk.bytes(), next, None, None)?;
    let result = store.import_migrated(
        crate::store::migration::MigratedRecords {
            credentials: &credentials,
            trust: trust.as_ref().map(|trust| (&policy_state_record, trust)),
            retention: &retention,
        },
        AuditEvent {
            event_id: crate::crypto::random_array()?,
            request_id: None,
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            request_context: None,
            usage: None,
            event_type: event_type::MIGRATION_COMPLETED,
            outcome: outcome::SUCCESS,
            reason_code: format!(
                "from-vault-{}-format-{}-generation-{}",
                source.header.vault_id, source.header.format_version, source.header.generation
            ),
            upstream_status: None,
            latency_ms: None,
            created_at_ms: now,
        },
        &mut generation,
    );
    generation.finish();
    result?;
    store.wal_checkpoint()
}

/// Re-opens the new vault through the normal integrity path and proves every
/// carried credential decrypts to exactly the source payload.
fn verify_target(
    target_dir: &Path,
    password: &SecretInput,
    source: &Source,
) -> Result<(), AuthorityError> {
    let store = SqliteRecordStore::open(&paths::vault_db(target_dir))?;
    let header = store.load_header()?;
    let proof = RestoreProof::Password(SecretInput::from_slice(password.expose()));
    let (vrk, _) = authenticate_restore(&store, &header, &proof)?;
    let mismatch = || AuthorityError::StorageIntegrityFailed;

    let expected: BTreeMap<_, _> = source
        .credentials
        .iter()
        .map(|c| (c.record.credential_id, &c.record))
        .collect();
    let actual = store.list_credentials()?;
    if actual.len() != expected.len() {
        return Err(mismatch());
    }
    for record in &actual {
        let old = expected.get(&record.credential_id).ok_or_else(mismatch)?;
        if record.label != old.label
            || record.kind != old.kind
            || record.state != old.state
            || record.current_version != old.current_version
            || record.created_at_ms != old.created_at_ms
            || record.updated_at_ms != old.updated_at_ms
            || record.revoked_at_ms != old.revoked_at_ms
        {
            return Err(mismatch());
        }
    }
    let source_digests: BTreeMap<(CredentialId, u64), [u8; 32]> = source
        .credentials
        .iter()
        .flat_map(|c| {
            c.versions.iter().map(|(version, plaintext)| {
                ((version.credential_id, version.version), digest(plaintext))
            })
        })
        .collect();
    let mut target_digests = BTreeMap::new();
    for (kind, version) in store.list_all_versions()? {
        let plaintext = open_version(vrk.bytes(), header.vault_id, kind, &version)?;
        target_digests.insert((version.credential_id, version.version), digest(&plaintext));
    }
    if source_digests != target_digests {
        return Err(mismatch());
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn dek_aad(vault_id: VaultId, version: &CredentialVersionRecord) -> [u8; 84] {
    AadV1 {
        purpose: AadPurpose::WrapDek,
        vault_id,
        object_id: *version.credential_id.as_bytes(),
        object_version: version.version,
        credential_kind: 0,
        constraints_hash: [0u8; 32],
    }
    .encode()
}

fn payload_aad(
    vault_id: VaultId,
    kind: CredentialKind,
    version: &CredentialVersionRecord,
) -> [u8; 84] {
    AadV1 {
        purpose: AadPurpose::CredentialPayload,
        vault_id,
        object_id: *version.credential_id.as_bytes(),
        object_version: version.version,
        credential_kind: kind.aad_code(),
        constraints_hash: [0u8; 32],
    }
    .encode()
}

fn open_version(
    vrk: &[u8; 32],
    vault_id: VaultId,
    kind: CredentialKind,
    version: &CredentialVersionRecord,
) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
    let dek_bytes = aead::open(
        vrk,
        &dek_aad(vault_id, version),
        &version.dek_nonce,
        &version.wrapped_dek,
    )
    .map_err(|_| AuthorityError::CryptoFailure)?;
    let mut dek_arr: [u8; 32] = dek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)?;
    let dek = DataKey::from_bytes(&mut dek_arr);
    drop(dek_bytes);
    aead::open(
        dek.bytes(),
        &payload_aad(vault_id, kind, version),
        &version.payload_nonce,
        &version.encrypted_payload,
    )
    .map_err(|_| AuthorityError::CryptoFailure)
}

/// Same version number, state and timestamps under a fresh DEK and new vault id.
fn seal_version(
    vrk: &[u8; 32],
    vault_id: VaultId,
    kind: CredentialKind,
    version: &CredentialVersionRecord,
    plaintext: &[u8],
) -> Result<CredentialVersionRecord, AuthorityError> {
    let dek = DataKey::generate()?;
    let payload = aead::seal(
        dek.bytes(),
        &payload_aad(vault_id, kind, version),
        plaintext,
    )?;
    let wrapped = aead::seal(vrk, &dek_aad(vault_id, version), dek.bytes())?;
    Ok(CredentialVersionRecord {
        credential_id: version.credential_id,
        version: version.version,
        state: version.state,
        aad_version: AAD_VERSION_V1,
        crypto_suite: CRYPTO_SUITE_V1.to_owned(),
        dek_nonce: wrapped.nonce,
        wrapped_dek: wrapped.ciphertext,
        payload_nonce: payload.nonce,
        encrypted_payload: payload.ciphertext,
        created_at_ms: version.created_at_ms,
        retired_at_ms: version.retired_at_ms,
    })
}

/// Header generation MAC used by vault25 and vault26 (frozen; vault27 binds
/// the PKI digest under a v2 key and domain).
fn verify_generation_v1(vrk: &[u8; 32], header: &VaultHeaderRecord) -> Result<(), AuthorityError> {
    let hk = Hkdf::<Sha256>::new(Some(header.vault_id.as_bytes()), vrk);
    let mut bytes = Zeroizing::new([0u8; 32]);
    hk.expand(b"rekey/header-generation-hmac-sha256/v1", bytes.as_mut())
        .map_err(|_| AuthorityError::CryptoFailure)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, bytes.as_ref());
    let mut message = Vec::with_capacity(14 + 16 + 4 + 8);
    message.extend_from_slice(b"RKGENERATION\0\x01");
    message.extend_from_slice(header.vault_id.as_bytes());
    message.extend_from_slice(&header.format_version.to_be_bytes());
    message.extend_from_slice(&header.generation.to_be_bytes());
    hmac::verify(&key, &message, &header.generation_mac)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)
}

fn copy_private(from: &Path, to: &Path) -> Result<(), AuthorityError> {
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(from)
        .map_err(AuthorityError::storage)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)
        .map_err(AuthorityError::storage)?;
    std::io::copy(&mut input, &mut output).map_err(AuthorityError::storage)?;
    output.sync_all().map_err(AuthorityError::storage)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AuthorityError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(AuthorityError::storage)?;
    file.write_all(bytes).map_err(AuthorityError::storage)?;
    file.sync_all().map_err(AuthorityError::storage)?;
    crate::durable::fsync_parent(path).map_err(AuthorityError::storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_generation_mac_rejects_tampering() {
        let vrk = [7u8; 32];
        let vault_id = VaultId::from_bytes([3; 16]).unwrap();
        let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), &vrk);
        let mut bytes = [0u8; 32];
        hk.expand(b"rekey/header-generation-hmac-sha256/v1", &mut bytes)
            .unwrap();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &bytes);
        let mut message = b"RKGENERATION\0\x01".to_vec();
        message.extend_from_slice(vault_id.as_bytes());
        message.extend_from_slice(&26u32.to_be_bytes());
        message.extend_from_slice(&5u64.to_be_bytes());
        let mut header = VaultHeaderRecord {
            vault_id,
            format_version: 26,
            generation: 5,
            generation_mac: hmac::sign(&key, &message).as_ref().try_into().unwrap(),
            pki_digest: crate::store::pki::empty_digest(),
            crypto_suite: CRYPTO_SUITE_V1.to_owned(),
            created_at_ms: 1,
            schema_digest: [0; 32],
            integrity_nonce: [0; 12],
            integrity_ciphertext: Vec::new(),
        };
        verify_generation_v1(&vrk, &header).unwrap();
        header.generation = 6;
        assert!(matches!(
            verify_generation_v1(&vrk, &header),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }
}
