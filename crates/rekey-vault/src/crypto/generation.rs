//! Header generation authentication only. External rollback anchors are separate.
use aws_lc_rs::hmac;
use hkdf::Hkdf;
use rekey_domain::ids::VaultId;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::AuthorityError;
use crate::model::VaultHeaderRecord;

const KEY_INFO: &[u8] = b"rekey/header-generation-hmac-sha256/v1";
const MESSAGE_DOMAIN: &[u8] = b"RKGENERATION\0\x01";

fn key(vrk: &[u8; 32], vault_id: VaultId) -> Result<hmac::Key, AuthorityError> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), vrk);
    let mut bytes = Zeroizing::new([0u8; 32]);
    hk.expand(KEY_INFO, bytes.as_mut())
        .map_err(|_| AuthorityError::CryptoFailure)?;
    Ok(hmac::Key::new(hmac::HMAC_SHA256, bytes.as_ref()))
}

fn message(vault_id: VaultId, format: u32, generation: u64) -> Result<Vec<u8>, AuthorityError> {
    if generation == 0 {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    let mut bytes = Vec::with_capacity(MESSAGE_DOMAIN.len() + 16 + 4 + 8);
    bytes.extend_from_slice(MESSAGE_DOMAIN);
    bytes.extend_from_slice(vault_id.as_bytes());
    bytes.extend_from_slice(&format.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    Ok(bytes)
}

pub(crate) fn seal(
    vrk: &[u8; 32],
    vault_id: VaultId,
    format: u32,
    generation: u64,
) -> Result<[u8; 32], AuthorityError> {
    let tag = hmac::sign(
        &key(vrk, vault_id)?,
        &message(vault_id, format, generation)?,
    );
    tag.as_ref()
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)
}

pub(crate) fn verify(vrk: &[u8; 32], header: &VaultHeaderRecord) -> Result<(), AuthorityError> {
    // aws-lc-rs verifies HMAC tags in constant time.
    hmac::verify(
        &key(vrk, header.vault_id)?,
        &message(header.vault_id, header.format_version, header.generation)?,
        &header.generation_mac,
    )
    .map_err(|_| AuthorityError::StorageIntegrityFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{prove_integrity, seal_integrity};
    use crate::crypto::keys::RootKey;
    use crate::model::FORMAT_VERSION;

    fn header(key: &RootKey, generation: u64) -> VaultHeaderRecord {
        let vault_id = VaultId::from_bytes([1; 16]).unwrap();
        let integrity = seal_integrity(vault_id, key).unwrap();
        VaultHeaderRecord {
            vault_id,
            format_version: FORMAT_VERSION,
            generation,
            generation_mac: seal(key.bytes(), vault_id, FORMAT_VERSION, generation).unwrap(),
            crypto_suite: crate::crypto::CRYPTO_SUITE_V1.to_owned(),
            created_at_ms: 1,
            schema_digest: [0; 32],
            integrity_nonce: integrity.nonce,
            integrity_ciphertext: integrity.ciphertext,
        }
    }

    #[test]
    fn every_header_mac_field_and_root_are_bound_across_full_u64_range() {
        let root = RootKey::from_bytes(&mut [7; 32]);
        for generation in [1, 2, i64::MAX as u64, (i64::MAX as u64) + 1, u64::MAX] {
            let good = header(&root, generation);
            prove_integrity(&good, root.bytes()).unwrap();
            for field in ["generation", "vault", "format", "mac"] {
                let mut bad = good.clone();
                match field {
                    "generation" => bad.generation ^= 1,
                    "vault" => bad.vault_id = VaultId::from_bytes([2; 16]).unwrap(),
                    "format" => bad.format_version += 1,
                    "mac" => bad.generation_mac[0] ^= 1,
                    _ => unreachable!(),
                }
                assert!(
                    matches!(
                        prove_integrity(&bad, root.bytes()),
                        Err(AuthorityError::StorageIntegrityFailed)
                    ),
                    "{field}"
                );
            }
            assert!(matches!(
                verify(&[8; 32], &good),
                Err(AuthorityError::StorageIntegrityFailed)
            ));
        }
        assert!(matches!(
            seal(
                root.bytes(),
                VaultId::from_bytes([1; 16]).unwrap(),
                FORMAT_VERSION,
                0
            ),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }

    #[test]
    fn new_root_requires_new_mac_and_existing_integrity_error_is_preserved() {
        let old = RootKey::from_bytes(&mut [7; 32]);
        let new = RootKey::from_bytes(&mut [8; 32]);
        let mut h = header(&old, 1);
        h.integrity_ciphertext[0] ^= 1;
        assert!(matches!(
            prove_integrity(&h, old.bytes()),
            Err(AuthorityError::CryptoFailure)
        ));
        h.generation_mac[0] ^= 1;
        assert!(matches!(
            prove_integrity(&h, old.bytes()),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        h = header(&old, 1);
        let encrypted = seal_integrity(h.vault_id, &new).unwrap();
        h.integrity_nonce = encrypted.nonce;
        h.integrity_ciphertext = encrypted.ciphertext;
        assert!(matches!(
            prove_integrity(&h, new.bytes()),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        h.generation_mac = seal(new.bytes(), h.vault_id, h.format_version, h.generation).unwrap();
        prove_integrity(&h, new.bytes()).unwrap();
        assert!(matches!(
            prove_integrity(&h, old.bytes()),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
    }

    #[tokio::test]
    async fn maximum_generation_is_readable_but_cannot_rotate_or_restore() {
        use crate::bootstrap::{
            RestoreProof, confirm_vault_init, init_vault, inspect_restore, kek_for_wrapper,
            restore_vault, unwrap_vrk,
        };
        use crate::command::UnlockProof;
        use crate::handle::AuthorityConfig;
        use crate::model::WrapperKind;
        use crate::secret::SecretInput;
        use crate::store::SqliteRecordStore;
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let password = || SecretInput::from_slice(b"synthetic-header-password");
        let proof = || UnlockProof::Password(password());
        let outcome = init_vault(
            &state,
            &password(),
            crate::crypto::kdf::Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        confirm_vault_init(&state).unwrap();
        let store = SqliteRecordStore::open(&crate::paths::vault_db(&state)).unwrap();
        let mut header = store.load_header().unwrap();
        let wrapper = store.active_wrapper(WrapperKind::Password).unwrap();
        let key = unwrap_vrk(
            header.vault_id,
            &wrapper,
            &kek_for_wrapper(&wrapper, &password()).unwrap(),
        )
        .unwrap();
        header.generation = u64::MAX;
        header.generation_mac = seal(
            key.bytes(),
            header.vault_id,
            header.format_version,
            header.generation,
        )
        .unwrap();
        let db = rusqlite::Connection::open(crate::paths::vault_db(&state)).unwrap();
        db.execute(
            "UPDATE vault_header SET generation=?1,generation_mac=?2",
            rusqlite::params![
                header.generation.to_be_bytes().as_slice(),
                header.generation_mac.as_slice()
            ],
        )
        .unwrap();
        drop(db);
        drop(store);
        let anchors =
            crate::generation_anchor::GenerationAnchors::open(&state, header.vault_id).unwrap();
        anchors
            .reserve(anchors.read().unwrap(), u64::MAX, &mut false)
            .unwrap();
        let (handle, join) =
            crate::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        handle.unlock(proof()).await.unwrap();
        let backup = tmp.path().join("backup");
        let receipt = handle.backup(backup.clone(), proof()).await.unwrap();
        assert_eq!(receipt.generation, u64::MAX);
        handle.lock("rotation").await.unwrap();
        assert!(matches!(
            handle
                .rotate_vrk_before(
                    password(),
                    SecretInput::from_slice(outcome.recovery_key_display.as_bytes()),
                    None
                )
                .await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        let unchanged = SqliteRecordStore::open(&crate::paths::vault_db(&state))
            .unwrap()
            .load_header()
            .unwrap();
        assert_eq!(unchanged.generation, u64::MAX);
        assert_eq!(unchanged.generation_mac, header.generation_mac);
        verify(key.bytes(), &unchanged).unwrap();
        assert_eq!(anchors.read().unwrap().file, Some(u64::MAX));
        drop(handle);
        join.join().unwrap();
        let restored = tmp.path().join("restored");
        let expected = inspect_restore(
            &backup,
            &restored,
            RestoreProof::Password(password()),
            &receipt.sha256_hex,
        )
        .unwrap();
        assert_eq!(expected.source_generation, u64::MAX);
        assert!(matches!(
            restore_vault(
                &backup,
                &restored,
                RestoreProof::Password(password()),
                &receipt.sha256_hex,
                expected
            ),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert!(!crate::paths::vault_db(&restored).exists());
        assert_eq!(
            crate::generation_anchor::GenerationAnchors::open(&restored, header.vault_id)
                .unwrap()
                .read()
                .unwrap()
                .file,
            None
        );
    }
}
