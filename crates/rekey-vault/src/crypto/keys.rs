use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::error::AuthorityError;

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(SecretBox<[u8; super::KEY_LEN]>);

        impl $name {
            /// Copies bytes into protected ownership and zeroizes the caller buffer.
            pub fn from_bytes(bytes: &mut [u8; super::KEY_LEN]) -> Self {
                let boxed = SecretBox::new(Box::new(*bytes));
                bytes.zeroize();
                Self(boxed)
            }

            pub fn generate() -> Result<Self, AuthorityError> {
                let mut bytes = super::random_array()?;
                Ok(Self::from_bytes(&mut bytes))
            }

            pub(crate) fn bytes(&self) -> &[u8; super::KEY_LEN] {
                self.0.expose_secret()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

key_type!(
    /// Key-encryption key derived from a password or recovery key. Only ever
    /// wraps and unwraps the VRK; never touches credential payloads.
    Kek
);
key_type!(
    /// Vault Root Key. Exists in memory only inside the AuthorityWorker while
    /// the vault is unlocked.
    RootKey
);
key_type!(
    /// Per-credential-version data encryption key.
    DataKey
);
