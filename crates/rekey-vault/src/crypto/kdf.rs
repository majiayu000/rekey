use super::keys::Kek;
use super::{KEY_LEN, SALT_LEN};
use crate::error::AuthorityError;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const KDF_ALGORITHM_ARGON2ID: &str = "argon2id";
pub const KDF_ALGORITHM_HKDF_SHA256: &str = "hkdf-sha256";
pub const RECOVERY_KEK_INFO: &[u8] = b"rekey/recovery-kek/v1";

/// Argon2id parameters persisted per wrapper row. The persisted values are
/// authoritative when opening an existing wrapper; compiled defaults apply
/// only to newly created wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// RFC 9106 second recommended profile: 64 MiB, 3 passes, 4 lanes.
    pub const RFC9106_LOW_MEMORY: Self = Self {
        memory_kib: 65536,
        iterations: 3,
        parallelism: 4,
    };

    pub fn to_json(&self) -> String {
        // Fixed field order; failure is impossible for this plain struct.
        format!(
            "{{\"memory_kib\":{},\"iterations\":{},\"parallelism\":{}}}",
            self.memory_kib, self.iterations, self.parallelism
        )
    }

    pub fn from_json(json: &str) -> Result<Self, AuthorityError> {
        let params: Self = serde_json::from_str(json).map_err(|_| AuthorityError::CryptoFailure)?;
        params.validate()?;
        Ok(params)
    }

    /// Floor covers in-tree test vectors (8 KiB / 1 / 1). Ceiling stops a
    /// tampered wrapper from turning unlock into an allocator DoS.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        const MIN_MEMORY_KIB: u32 = 8;
        const MAX_MEMORY_KIB: u32 = 256 * 1024;
        const MIN_ITERS: u32 = 1;
        const MAX_ITERS: u32 = 16;
        const MIN_PARALLELISM: u32 = 1;
        const MAX_PARALLELISM: u32 = 8;
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ITERS..=MAX_ITERS).contains(&self.iterations)
            || !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
        Ok(())
    }
}

pub fn derive_password_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &Argon2Params,
) -> Result<Kek, AuthorityError> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| AuthorityError::CryptoFailure)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| AuthorityError::CryptoFailure)?;
    let kek = Kek::from_bytes(&mut out);
    Ok(kek)
}

pub fn derive_recovery_kek(
    recovery_key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<Kek, AuthorityError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), recovery_key);
    let mut out = [0u8; KEY_LEN];
    hk.expand(RECOVERY_KEK_INFO, &mut out)
        .map_err(|_| AuthorityError::CryptoFailure)?;
    let kek = Kek::from_bytes(&mut out);
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny parameters keep tests fast; production defaults are covered by
    /// the persisted-parameter roundtrip below.
    pub(crate) const TEST_PARAMS: Argon2Params = Argon2Params {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn password_kek_is_deterministic_per_salt_and_params() {
        let salt = [7u8; SALT_LEN];
        let a = derive_password_kek(b"pw", &salt, &TEST_PARAMS).unwrap();
        let b = derive_password_kek(b"pw", &salt, &TEST_PARAMS).unwrap();
        assert_eq!(a.bytes(), b.bytes());

        let other_salt = [8u8; SALT_LEN];
        let c = derive_password_kek(b"pw", &other_salt, &TEST_PARAMS).unwrap();
        assert_ne!(a.bytes(), c.bytes());

        let d = derive_password_kek(b"pw2", &salt, &TEST_PARAMS).unwrap();
        assert_ne!(a.bytes(), d.bytes());

        let more_iters = Argon2Params {
            iterations: 2,
            ..TEST_PARAMS
        };
        let e = derive_password_kek(b"pw", &salt, &more_iters).unwrap();
        assert_ne!(a.bytes(), e.bytes());
    }

    #[test]
    fn params_json_roundtrip() {
        let p = Argon2Params::RFC9106_LOW_MEMORY;
        assert_eq!(Argon2Params::from_json(&p.to_json()).unwrap(), p);
        assert_eq!(p.memory_kib, 65536);
        assert_eq!(p.iterations, 3);
        assert_eq!(p.parallelism, 4);
        assert!(Argon2Params::from_json("not json").is_err());
        assert!(TEST_PARAMS.validate().is_ok());
        let huge = Argon2Params {
            memory_kib: u32::MAX,
            iterations: 3,
            parallelism: 4,
        };
        assert!(matches!(
            huge.validate(),
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert!(Argon2Params::from_json(&huge.to_json()).is_err());
    }

    #[test]
    fn recovery_kek_depends_on_key_and_salt() {
        let key = [1u8; KEY_LEN];
        let salt = [2u8; SALT_LEN];
        let a = derive_recovery_kek(&key, &salt).unwrap();
        let b = derive_recovery_kek(&key, &salt).unwrap();
        assert_eq!(a.bytes(), b.bytes());
        let c = derive_recovery_kek(&[9u8; KEY_LEN], &salt).unwrap();
        assert_ne!(a.bytes(), c.bytes());
    }
}
