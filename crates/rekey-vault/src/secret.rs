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

    /// The trusted mTLS decoder is reused for the sole authorized runner.
    /// Raw and private DER buffers remain wipe-on-drop and are not cloneable.
    pub fn consume_mtls<R>(
        self,
        f: impl FnOnce(&[u8], PreparedMtlsIdentity) -> R,
    ) -> Result<R, crate::AuthorityError> {
        if self.kind != CredentialKind::MtlsIdentity {
            return Err(crate::AuthorityError::CredentialSourceUnavailable);
        }
        let text = std::str::from_utf8(&self.bytes)
            .map_err(|_| crate::AuthorityError::CredentialSourceUnavailable)?;
        let material = crate::private_material::decode_mtls(text)?;
        Ok(f(&self.bytes, material))
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

/// Historical profile/ID can only be consumed by the internal exact-revoke path.
/// Never supplies a PreparedCredential usable for acquire or business execution.
pub struct PreparedLeaseCleanup {
    profile: Zeroizing<Vec<u8>>,
    lease_id: Zeroizing<Vec<u8>>,
    receipt: crate::model::LeaseReceipt,
}
impl PreparedLeaseCleanup {
    pub(crate) fn new(
        profile: Zeroizing<Vec<u8>>,
        lease_id: Zeroizing<Vec<u8>>,
        receipt: crate::model::LeaseReceipt,
    ) -> Self {
        Self {
            profile,
            lease_id,
            receipt,
        }
    }
    pub fn receipt(&self) -> &crate::model::LeaseReceipt {
        &self.receipt
    }
    pub fn consume<R>(self, f: impl FnOnce(&[u8], &[u8]) -> R) -> R {
        f(&self.profile, &self.lease_id)
    }
}
/// Concrete one-use identity. Certificates are public; private DER is owned
/// and zeroized. Provider/parser internal copies are outside this guarantee.
pub struct PreparedMtlsIdentity {
    pub certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub private_key: Zeroizing<rustls::pki_types::PrivateKeyDer<'static>>,
}
