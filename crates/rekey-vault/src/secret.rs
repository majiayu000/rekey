use std::fmt;

use rekey_domain::credential::CredentialKind;
use rekey_domain::ids::CredentialId;
use zeroize::Zeroizing;

/// Secret bytes received from an admin (password, recovery key, credential
/// value). Never `Clone`, `Copy`, `Serialize`, or `Display`; zeroized on drop.
pub struct SecretInput(Zeroizing<Vec<u8>>);

impl SecretInput {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}

/// A decrypted credential payload prepared for exactly one upstream use.
/// Constructed only inside this crate; the executor consumes it once through
/// a closure so the bytes never escape as an owned value.
pub struct PreparedCredential {
    bytes: Zeroizing<Vec<u8>>,
    credential_id: CredentialId,
    kind: CredentialKind,
    version: u64,
}

impl PreparedCredential {
    pub(crate) fn new(
        bytes: Zeroizing<Vec<u8>>,
        credential_id: CredentialId,
        kind: CredentialKind,
        version: u64,
    ) -> Self {
        Self {
            bytes,
            credential_id,
            kind,
            version,
        }
    }

    pub fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Consumes the credential; drop zeroizes the backing buffer.
    pub fn consume<R>(self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }
}

impl fmt::Debug for PreparedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedCredential([REDACTED])")
    }
}
