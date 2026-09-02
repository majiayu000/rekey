use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use super::NONCE_LEN;
use crate::error::AuthorityError;

/// Nonce plus ciphertext (tag included). Nonces are always freshly random;
/// callers can never supply one.
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, AuthorityError> {
    let nonce = super::random_array::<NONCE_LEN>()?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AuthorityError::CryptoFailure)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AuthorityError::CryptoFailure)?;
    Ok(Sealed { nonce, ciphertext })
}

pub fn open(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AuthorityError::CryptoFailure)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| AuthorityError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_rejection() {
        let key = [3u8; 32];
        let aad = b"context";
        let sealed = seal(&key, aad, b"payload").unwrap();
        assert_eq!(
            open(&key, aad, &sealed.nonce, &sealed.ciphertext)
                .unwrap()
                .as_slice(),
            b"payload"
        );

        let wrong_key = [4u8; 32];
        assert!(open(&wrong_key, aad, &sealed.nonce, &sealed.ciphertext).is_err());
        assert!(open(&key, b"other", &sealed.nonce, &sealed.ciphertext).is_err());

        let mut wrong_nonce = sealed.nonce;
        wrong_nonce[0] ^= 1;
        assert!(open(&key, aad, &wrong_nonce, &sealed.ciphertext).is_err());

        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 1;
        assert!(open(&key, aad, &sealed.nonce, &tampered).is_err());
    }

    #[test]
    fn nonces_are_unique_per_seal() {
        let key = [5u8; 32];
        let a = seal(&key, b"", b"x").unwrap();
        let b = seal(&key, b"", b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
