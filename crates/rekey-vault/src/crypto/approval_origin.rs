use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use rekey_domain::ids::VaultId;
use zeroize::Zeroizing;

use super::kdf::derive_approval_origin_seed;
use super::keys::RootKey;
use crate::error::AuthorityError;

const SIGN_MESSAGE_MAX: usize = 64 * 1024;

fn origin_keypair(vrk: &RootKey, vault_id: VaultId) -> Result<Ed25519KeyPair, AuthorityError> {
    let seed = Zeroizing::new(derive_approval_origin_seed(
        vrk.bytes(),
        vault_id.as_bytes(),
    )?);
    Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).map_err(|_| AuthorityError::CryptoFailure)
}

pub(crate) fn approval_origin_public_key(
    vrk: &RootKey,
    vault_id: VaultId,
) -> Result<[u8; 32], AuthorityError> {
    origin_keypair(vrk, vault_id)?
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)
}

pub(crate) fn sign_approval_origin(
    vrk: &RootKey,
    vault_id: VaultId,
    message: &[u8],
) -> Result<[u8; 64], AuthorityError> {
    if message.len() > SIGN_MESSAGE_MAX {
        return Err(AuthorityError::Domain(
            rekey_domain::DomainError::InvalidActionDefinition(
                "approval origin message is too large".to_owned(),
            ),
        ));
    }
    origin_keypair(vrk, vault_id)?
        .sign(message)
        .as_ref()
        .try_into()
        .map_err(|_| AuthorityError::CryptoFailure)
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    use rekey_domain::ids::VaultId;

    use super::*;
    use crate::crypto::KEY_LEN;

    fn vrk(byte: u8) -> RootKey {
        let mut bytes = [byte; KEY_LEN];
        RootKey::from_bytes(&mut bytes)
    }

    #[test]
    fn origin_signatures_verify_and_depend_on_vault_id() {
        let vault_a = VaultId::from_bytes([1u8; 16]).unwrap();
        let vault_b = VaultId::from_bytes([2u8; 16]).unwrap();
        let key = vrk(7);
        let public_a = approval_origin_public_key(&key, vault_a).unwrap();
        let public_b = approval_origin_public_key(&key, vault_b).unwrap();
        assert_ne!(public_a, public_b);
        assert_eq!(approval_origin_public_key(&key, vault_a).unwrap(), public_a);
        let message = b"RKCHALLENGE\0\x01test";
        let signature = sign_approval_origin(&key, vault_a, message).unwrap();
        UnparsedPublicKey::new(&ED25519, &public_a)
            .verify(message, &signature)
            .unwrap();
        assert!(
            UnparsedPublicKey::new(&ED25519, &public_b)
                .verify(message, &signature)
                .is_err()
        );
        assert!(matches!(
            sign_approval_origin(&key, vault_a, &vec![0u8; SIGN_MESSAGE_MAX + 1]),
            Err(AuthorityError::Domain(_))
        ));
    }
}
