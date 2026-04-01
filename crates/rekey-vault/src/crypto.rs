// Argon2id key derivation + AES-256-GCM encrypt/decrypt

use aes_gcm::{
    AeadCore, Aes256Gcm,
    aead::{Aead, KeyInit, OsRng},
};
use anyhow::Result;
use secrecy::{ExposeSecret, SecretBox};

/// Master key type: a zeroize-on-drop secret byte slice.
pub type MasterKey = SecretBox<[u8]>;

pub struct EncryptedBlob {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<MasterKey> {
    let params = argon2::Params::new(65536, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;
    Ok(key.into())
}

pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    Ok(EncryptedBlob {
        iv: nonce.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(key: &MasterKey, blob: &EncryptedBlob) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(&blob.iv);
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"rekey-test-salt!";

    #[test]
    fn derive_key_deterministic() {
        let k1 = derive_master_key("hunter2", SALT).unwrap();
        let k2 = derive_master_key("hunter2", SALT).unwrap();
        assert_eq!(k1.expose_secret(), k2.expose_secret());
    }

    #[test]
    fn derive_key_different_passwords() {
        let k1 = derive_master_key("password-a", SALT).unwrap();
        let k2 = derive_master_key("password-b", SALT).unwrap();
        assert_ne!(k1.expose_secret(), k2.expose_secret());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_master_key("roundtrip", SALT).unwrap();
        let plaintext = b"sensitive api key data";
        let blob = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = derive_master_key("correct-password", SALT).unwrap();
        let key2 = derive_master_key("wrong-password", SALT).unwrap();
        let blob = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &blob);
        assert!(result.is_err());
    }
}
