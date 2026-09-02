//! Envelope crypto contract: AAD binding, purpose separation, and
//! record-swap rejection.
//!
//! KEK derivation-domain separation (password vs recovery paths yielding
//! different keys) is asserted inside the crate's kdf unit tests; key bytes
//! are deliberately unreadable from integration tests.

use rekey_domain::ids::VaultId;
use rekey_vault::crypto::aad::{AadPurpose, AadV1};
use rekey_vault::crypto::{KEY_LEN, aead};

fn vault_id() -> VaultId {
    VaultId::from_bytes([9u8; 16]).unwrap()
}

fn payload_aad(object_id: [u8; 16], version: u64) -> [u8; 84] {
    AadV1 {
        purpose: AadPurpose::CredentialPayload,
        vault_id: vault_id(),
        object_id,
        object_version: version,
        credential_kind: 1,
        constraints_hash: [0u8; 32],
    }
    .encode()
}

#[test]
fn ciphertext_record_swap_rejected() {
    let key = [1u8; 32];
    let sealed_a = aead::seal(&key, &payload_aad([0xaa; 16], 1), b"secret-a").unwrap();
    let sealed_b = aead::seal(&key, &payload_aad([0xbb; 16], 1), b"secret-b").unwrap();

    // Same key, swapped record identity: must fail authentication.
    assert!(
        aead::open(
            &key,
            &payload_aad([0xbb; 16], 1),
            &sealed_a.nonce,
            &sealed_a.ciphertext
        )
        .is_err()
    );
    assert!(
        aead::open(
            &key,
            &payload_aad([0xaa; 16], 1),
            &sealed_b.nonce,
            &sealed_b.ciphertext
        )
        .is_err()
    );
    // Correct identity still opens.
    assert_eq!(
        aead::open(
            &key,
            &payload_aad([0xaa; 16], 1),
            &sealed_a.nonce,
            &sealed_a.ciphertext
        )
        .unwrap()
        .as_slice(),
        b"secret-a"
    );
}

#[test]
fn version_rollback_swap_rejected() {
    let key = [2u8; 32];
    let v1 = aead::seal(&key, &payload_aad([0xcc; 16], 1), b"old").unwrap();
    // Presenting version-1 ciphertext under version-2 identity fails.
    assert!(aead::open(&key, &payload_aad([0xcc; 16], 2), &v1.nonce, &v1.ciphertext).is_err());
}

#[test]
fn purpose_separation_rejected() {
    let key = [3u8; 32];
    let wrap_aad = AadV1 {
        purpose: AadPurpose::WrapDek,
        vault_id: vault_id(),
        object_id: [0xdd; 16],
        object_version: 1,
        credential_kind: 0,
        constraints_hash: [0u8; 32],
    }
    .encode();
    let sealed = aead::seal(&key, &wrap_aad, &[7u8; KEY_LEN]).unwrap();
    let payload_purpose = payload_aad([0xdd; 16], 1);
    assert!(aead::open(&key, &payload_purpose, &sealed.nonce, &sealed.ciphertext).is_err());
}

#[test]
fn cross_vault_swap_rejected() {
    let key = [4u8; 32];
    let aad_a = payload_aad([0xee; 16], 1);
    let sealed = aead::seal(&key, &aad_a, b"secret").unwrap();
    let aad_other_vault = AadV1 {
        purpose: AadPurpose::CredentialPayload,
        vault_id: VaultId::from_bytes([8u8; 16]).unwrap(),
        object_id: [0xee; 16],
        object_version: 1,
        credential_kind: 1,
        constraints_hash: [0u8; 32],
    }
    .encode();
    assert!(aead::open(&key, &aad_other_vault, &sealed.nonce, &sealed.ciphertext).is_err());
}
