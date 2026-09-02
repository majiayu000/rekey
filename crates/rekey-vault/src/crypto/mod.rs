pub mod aad;
pub mod aead;
pub mod credential_state;
pub mod kdf;
pub mod keys;
pub mod policy_state;
pub mod recovery;

/// CryptoSuite v1 identifier persisted with every encrypted record.
pub const CRYPTO_SUITE_V1: &str = "rkca-aes256gcm-argon2id-hkdfsha256-v1";
pub const CRYPTO_SUITE_V1_CODE: u16 = 1;
pub const AAD_VERSION_V1: u16 = 1;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

use crate::error::AuthorityError;

/// Fills `buf` from the OS CSPRNG. Failure is fatal `EntropyUnavailable`;
/// there is no fallback source.
pub fn fill_random(buf: &mut [u8]) -> Result<(), AuthorityError> {
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| AuthorityError::EntropyUnavailable)
}

pub fn random_array<const N: usize>() -> Result<[u8; N], AuthorityError> {
    let mut buf = [0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}
