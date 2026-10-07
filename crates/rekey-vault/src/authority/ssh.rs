//! SSH private keys are consumed here, never returned as PreparedCredential.

use std::time::Instant;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::CredentialId;
use zeroize::Zeroizing;

use super::{Worker, ensure_mutation_current};
use crate::AuthorityError;
use crate::command::{AuditDraft, SshIdentity, SshKeyMode, UnlockProof};
use crate::model::{event_type, outcome};
use crate::secret::SecretInput;

const ED: &[u8] = b"ssh-ed25519";
const EC: &[u8] = b"ecdsa-sha2-nistp256";
const CURVE: &[u8] = b"nistp256";

fn invalid() -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition(
        "invalid or unsupported SSH key input".into(),
    )
    .into()
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn public_blob(kind: CredentialKind, public: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if kind == CredentialKind::SshEd25519 {
        string(&mut out, ED);
    } else {
        string(&mut out, EC);
        string(&mut out, CURVE);
    }
    string(&mut out, public);
    out
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], AuthorityError> {
        if len > self.0.len() {
            return Err(invalid());
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, AuthorityError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn string(&mut self) -> Result<&'a [u8], AuthorityError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// Imports only unencrypted, single-key OpenSSH files. Encrypted files are
/// explicitly unsupported; the daemon never guesses a password or format.
fn import_private(input: &[u8]) -> Result<(CredentialKind, SecretInput, Vec<u8>), AuthorityError> {
    if input.len() > 64 * 1024 {
        return Err(invalid());
    }
    let text = std::str::from_utf8(input).map_err(|_| invalid())?.trim();
    let content = text
        .strip_prefix("-----BEGIN OPENSSH PRIVATE KEY-----")
        .and_then(|s| s.strip_suffix("-----END OPENSSH PRIVATE KEY-----"))
        .ok_or_else(invalid)?;
    let encoded = Zeroizing::new(
        content
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    let bytes = Zeroizing::new(
        data_encoding::BASE64
            .decode(&encoded)
            .map_err(|_| invalid())?,
    );
    let mut r = Reader(&bytes);
    if r.take(15)? != b"openssh-key-v1\0"
        || r.string()? != b"none"
        || r.string()? != b"none"
        || !r.string()?.is_empty()
        || r.u32()? != 1
    {
        return Err(invalid());
    }
    let expected_public = r.string()?;
    let private = r.string()?;
    if !r.0.is_empty() || private.len() % 8 != 0 {
        return Err(invalid());
    }
    let mut r = Reader(private);
    if r.u32()? != r.u32()? {
        return Err(invalid());
    }
    let algorithm = r.string()?;
    let (kind, secret, public) = if algorithm == ED {
        let public = r.string()?;
        let private = r.string()?;
        if public.len() != 32 || private.len() != 64 || &private[32..] != public {
            return Err(invalid());
        }
        let key = signature::Ed25519KeyPair::from_seed_and_public_key(&private[..32], public)
            .map_err(|_| invalid())?;
        let pkcs8 = key.to_pkcs8().map_err(|_| AuthorityError::CryptoFailure)?;
        (
            CredentialKind::SshEd25519,
            SecretInput::from_slice(pkcs8.as_ref()),
            public_blob(CredentialKind::SshEd25519, key.public_key().as_ref()),
        )
    } else if algorithm == EC {
        if r.string()? != CURVE {
            return Err(invalid());
        }
        let public = r.string()?;
        let scalar = positive_scalar(r.string()?)?;
        let key = signature::EcdsaKeyPair::from_private_key_and_public_key(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &scalar[..],
            public,
        )
        .map_err(|_| invalid())?;
        let pkcs8 = key
            .to_pkcs8v1()
            .map_err(|_| AuthorityError::CryptoFailure)?;
        (
            CredentialKind::SshP256,
            SecretInput::from_slice(pkcs8.as_ref()),
            public_blob(CredentialKind::SshP256, key.public_key().as_ref()),
        )
    } else {
        return Err(invalid());
    };
    r.string()?; // comment is intentionally not persisted or logged
    if r.0.is_empty()
        || r.0.len() > 8
        || !r
            .0
            .iter()
            .enumerate()
            .all(|(i, b)| usize::from(*b) == i + 1)
        || public.as_slice() != expected_public
    {
        return Err(invalid());
    }
    Ok((kind, secret, public))
}

fn positive_scalar(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, AuthorityError> {
    if bytes.is_empty()
        || bytes[0] & 0x80 != 0
        || (bytes[0] == 0 && (bytes.len() == 1 || bytes[1] & 0x80 == 0))
    {
        return Err(invalid());
    }
    let bytes = if bytes[0] == 0 { &bytes[1..] } else { bytes };
    if bytes.len() > 32 {
        return Err(invalid());
    }
    let mut scalar = Zeroizing::new([0; 32]);
    scalar[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(scalar)
}

fn mpint(out: &mut Vec<u8>, scalar: &[u8]) {
    let scalar = &scalar[scalar.iter().position(|b| *b != 0).unwrap_or(scalar.len())..];
    if scalar.first().is_some_and(|b| b & 0x80 != 0) {
        out.extend_from_slice(&((scalar.len() + 1) as u32).to_be_bytes());
        out.push(0);
        out.extend_from_slice(scalar);
    } else {
        string(out, scalar);
    }
}

fn signature_blob(kind: CredentialKind, signature: &[u8]) -> Result<Vec<u8>, AuthorityError> {
    let mut out = Vec::new();
    if kind == CredentialKind::SshEd25519 {
        if signature.len() != 64 {
            return Err(AuthorityError::CryptoFailure);
        }
        string(&mut out, ED);
        string(&mut out, signature);
    } else {
        if signature.len() != 64 {
            return Err(AuthorityError::CryptoFailure);
        }
        let mut body = Vec::new();
        mpint(&mut body, &signature[..32]);
        mpint(&mut body, &signature[32..]);
        string(&mut out, EC);
        string(&mut out, &body);
    }
    Ok(out)
}

fn software_sign(
    kind: CredentialKind,
    private: &[u8],
    expected: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AuthorityError> {
    if kind == CredentialKind::SshEd25519 {
        let key = signature::Ed25519KeyPair::from_pkcs8(private)
            .map_err(|_| AuthorityError::CryptoFailure)?;
        if public_blob(kind, key.public_key().as_ref()) != expected {
            return Err(AuthorityError::AuthenticationFailed);
        }
        let sig = key
            .try_sign(data)
            .map_err(|_| AuthorityError::CryptoFailure)?;
        signature_blob(kind, sig.as_ref())
    } else {
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            private,
        )
        .map_err(|_| AuthorityError::CryptoFailure)?;
        if public_blob(kind, key.public_key().as_ref()) != expected {
            return Err(AuthorityError::AuthenticationFailed);
        }
        let sig = key
            .sign(&SystemRandom::new(), data)
            .map_err(|_| AuthorityError::CryptoFailure)?;
        signature_blob(kind, sig.as_ref())
    }
}

impl Worker {
    pub(super) fn ssh_generate(
        &mut self,
        label: CredentialLabel,
        mode: SshKeyMode,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<SshIdentity, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        drop(proof);
        ensure_mutation_current(not_after)?;
        #[cfg(target_os = "macos")]
        if matches!(mode, SshKeyMode::Default) {
            let (key, secret, public_key) = enclave::generate(self.header.vault_id)?;
            let result = self.insert_credential(
                label,
                CredentialKind::SshSecureEnclaveP256,
                secret,
                not_after,
            );
            return match result {
                Ok(credential) => Ok(SshIdentity {
                    credential,
                    public_key,
                }),
                Err(error) => {
                    if key.delete().is_err() {
                        tracing::warn!(
                            event = "ssh.enclave_cleanup_failed",
                            code = "CREDENTIAL_UNAVAILABLE"
                        );
                    }
                    Err(error)
                }
            };
        }
        let kind = if matches!(mode, SshKeyMode::P256Software) {
            CredentialKind::SshP256
        } else {
            CredentialKind::SshEd25519
        };
        let pkcs8 = if kind == CredentialKind::SshEd25519 {
            signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        } else {
            signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &SystemRandom::new(),
            )
        }
        .map_err(|_| AuthorityError::CryptoFailure)?;
        let public_key = if kind == CredentialKind::SshEd25519 {
            let key = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .map_err(|_| AuthorityError::CryptoFailure)?;
            public_blob(kind, key.public_key().as_ref())
        } else {
            let key = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
            )
            .map_err(|_| AuthorityError::CryptoFailure)?;
            public_blob(kind, key.public_key().as_ref())
        };
        let credential = self.insert_credential(
            label,
            kind,
            SecretInput::from_slice(pkcs8.as_ref()),
            not_after,
        )?;
        Ok(SshIdentity {
            credential,
            public_key,
        })
    }

    pub(super) fn ssh_import(
        &mut self,
        label: CredentialLabel,
        private_key: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<SshIdentity, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        drop(proof);
        ensure_mutation_current(not_after)?;
        let (kind, secret, public_key) = import_private(private_key.expose())?;
        drop(private_key);
        let credential = self.insert_credential(label, kind, secret, not_after)?;
        Ok(SshIdentity {
            credential,
            public_key,
        })
    }

    pub(super) fn ssh_sign(
        &mut self,
        credential_id: CredentialId,
        public_key: Vec<u8>,
        data: Vec<u8>,
        mut started: AuditDraft,
        not_after: Instant,
    ) -> Result<Vec<u8>, AuthorityError> {
        self.require_unlocked()?;
        ensure_mutation_current(Some(not_after))?;
        if started.event_type != event_type::EXECUTION_STARTED
            || started.outcome != outcome::SUCCESS
            || started.request_id.is_none()
            || started.credential_id != Some(credential_id)
            || started.credential_version.is_some()
            || started.authorization.is_none()
            || started.request_context.as_ref().is_none_or(|c| {
                !matches!(c, rekey_domain::audit::RequestAuditContext::Connection(_))
            })
            || data.is_empty()
            || data.len() > 256 * 1024
            || public_key.len() > 1024
        {
            return Err(invalid());
        }
        let kind = self.load_verified_credential(credential_id)?.kind;
        if !matches!(
            kind,
            CredentialKind::SshEd25519
                | CredentialKind::SshP256
                | CredentialKind::SshSecureEnclaveP256
        ) {
            return Err(AuthorityError::CredentialSourceUnavailable);
        }
        // UNIQUE request_id prevents the same authorization executing twice.
        self.append_audit(started.clone())?;
        let result = (|| {
            ensure_mutation_current(Some(not_after))?;
            let prepared = self.prepare_internal_credential(credential_id)?;
            let kind = prepared.kind();
            started.credential_version = Some(prepared.version());
            prepared.consume(|private| match kind {
                CredentialKind::SshEd25519 | CredentialKind::SshP256 => {
                    software_sign(kind, private, &public_key, &data)
                }
                CredentialKind::SshSecureEnclaveP256 => enclave::sign(private, &public_key, &data),
                _ => Err(AuthorityError::CredentialSourceUnavailable),
            })
        })();
        let mut terminal = started;
        terminal.event_type = event_type::EXECUTION_FINISHED;
        terminal.outcome = if result.is_ok() {
            outcome::SUCCESS
        } else {
            outcome::FAILURE
        };
        terminal.reason_code = "ssh-sign".into();
        if result.is_ok() {
            let mut signed = terminal.clone();
            signed.event_type = "ssh.sign";
            self.append_audit(signed)?;
        }
        // Even a produced signature is discarded on a terminal audit failure.
        self.append_audit(terminal)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_openssh() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let seed = Zeroizing::new([7; 32]);
        let key = signature::Ed25519KeyPair::from_seed_unchecked(&seed[..]).unwrap();
        let public = public_blob(CredentialKind::SshEd25519, key.public_key().as_ref());
        let mut private = Zeroizing::new(Vec::new());
        private.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 7]);
        string(&mut private, ED);
        string(&mut private, key.public_key().as_ref());
        let mut raw = Zeroizing::new(seed.to_vec());
        raw.extend_from_slice(key.public_key().as_ref());
        string(&mut private, &raw);
        string(&mut private, b"synthetic-fixture");
        let padding = 8 - private.len() % 8;
        private.extend((1..=padding).map(|i| i as u8));
        let mut binary = Zeroizing::new(b"openssh-key-v1\0".to_vec());
        string(&mut binary, b"none");
        string(&mut binary, b"none");
        string(&mut binary, b"");
        binary.extend_from_slice(&1_u32.to_be_bytes());
        string(&mut binary, &public);
        string(&mut binary, &private);
        let encoded = Zeroizing::new(data_encoding::BASE64.encode(&binary));
        let mut pem = Zeroizing::new(b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec());
        pem.extend_from_slice(encoded.as_bytes());
        pem.extend_from_slice(b"\n-----END OPENSSH PRIVATE KEY-----");
        (pem, public)
    }

    #[test]
    fn import_checks_pair_and_canonical_padding_and_preserves_no_private_format() {
        let (pem, public) = synthetic_openssh();
        let (kind, private, imported_public) = import_private(&pem).unwrap();
        assert_eq!(kind, CredentialKind::SshEd25519);
        assert_eq!(imported_public, public);
        let sig = software_sign(kind, private.expose(), &public, b"synthetic request").unwrap();
        let mut r = Reader(&sig);
        assert_eq!(r.string().unwrap(), ED);
        let signature = r.string().unwrap();
        let mut public_reader = Reader(&public);
        public_reader.string().unwrap();
        signature::UnparsedPublicKey::new(&signature::ED25519, public_reader.string().unwrap())
            .verify(b"synthetic request", signature)
            .unwrap();
        assert!(import_private(b"not a key").is_err());
        let r = Reader(
            pem.strip_prefix(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
                .unwrap()
                .strip_suffix(b"\n-----END OPENSSH PRIVATE KEY-----")
                .unwrap(),
        );
        let mut binary = Zeroizing::new(data_encoding::BASE64.decode(r.0).unwrap());
        *binary.last_mut().unwrap() = 0;
        let encoded = Zeroizing::new(data_encoding::BASE64.encode(&binary));
        let malformed = Zeroizing::new(format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
            &*encoded
        ));
        assert!(import_private(malformed.as_bytes()).is_err());
    }
}

#[cfg(not(target_os = "macos"))]
mod enclave {
    use super::*;
    pub(super) fn sign(_: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        Err(AuthorityError::CredentialSourceUnavailable)
    }
}

#[cfg(target_os = "macos")]
mod enclave {
    use super::*;
    use security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
        key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    };

    pub(super) fn generate(
        vault_id: rekey_domain::ids::VaultId,
    ) -> Result<(SecKey, SecretInput, Vec<u8>), AuthorityError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|_| AuthorityError::CredentialSourceUnavailable)?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(format!(
                "rekey.ssh.{}.{}",
                vault_id,
                data_encoding::HEXLOWER.encode(&crate::crypto::random_array::<16>()?)
            ))
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(|_| AuthorityError::CredentialSourceUnavailable)?;
        let result = (|| {
            // Export only the public half. The private key has no export path.
            let public = key
                .public_key()
                .and_then(|k| k.external_representation())
                .ok_or(AuthorityError::CredentialSourceUnavailable)?;
            if public.len() != 65 || public[0] != 4 {
                return Err(AuthorityError::CredentialSourceUnavailable);
            }
            let label = key
                .application_label()
                .ok_or(AuthorityError::CredentialSourceUnavailable)?;
            let public_key = public_blob(CredentialKind::SshSecureEnclaveP256, &public);
            let mut descriptor = Vec::new();
            string(&mut descriptor, &label);
            string(&mut descriptor, &public_key);
            Ok((SecretInput::new(descriptor), public_key))
        })();
        match result {
            Ok((secret, public)) => Ok((key, secret, public)),
            Err(error) => {
                if key.delete().is_err() {
                    tracing::warn!(
                        event = "ssh.enclave_cleanup_failed",
                        code = "CREDENTIAL_UNAVAILABLE"
                    );
                }
                Err(error)
            }
        }
    }

    pub(super) fn sign(
        descriptor: &[u8],
        expected: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, AuthorityError> {
        let mut r = Reader(descriptor);
        let label = r.string()?;
        let public = r.string()?;
        if !r.0.is_empty() || public != expected || label.is_empty() || label.len() > 128 {
            return Err(AuthorityError::AuthenticationFailed);
        }
        let results = ItemSearchOptions::new()
            .key_class(KeyClass::private())
            .application_label(label)
            .load_refs(true)
            .ignore_legacy_keychains()
            .limit(1)
            .search()
            .map_err(|_| AuthorityError::CredentialSourceUnavailable)?;
        let [SearchResult::Ref(Reference::Key(key))] = results.as_slice() else {
            return Err(AuthorityError::CredentialSourceUnavailable);
        };
        let actual = key
            .public_key()
            .and_then(|k| k.external_representation())
            .ok_or(AuthorityError::CredentialSourceUnavailable)?;
        if public_blob(CredentialKind::SshSecureEnclaveP256, &actual) != expected {
            return Err(AuthorityError::AuthenticationFailed);
        }
        let der = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|_| AuthorityError::CredentialSourceUnavailable)?;
        // P-256 DER values are short-form and contain exactly two INTEGERs.
        let mut r = Reader(&der);
        if r.take(1)? != [0x30] {
            return Err(AuthorityError::CryptoFailure);
        }
        let len = usize::from(r.take(1)?[0]);
        if len != r.0.len() || len >= 128 {
            return Err(AuthorityError::CryptoFailure);
        }
        let mut fixed = [0; 64];
        for half in fixed.chunks_mut(32) {
            if r.take(1)? != [2] {
                return Err(AuthorityError::CryptoFailure);
            }
            let len = usize::from(r.take(1)?[0]);
            let scalar = positive_scalar(r.take(len)?)?;
            half.copy_from_slice(&*scalar);
        }
        if !r.0.is_empty() {
            return Err(AuthorityError::CryptoFailure);
        }
        signature_blob(CredentialKind::SshSecureEnclaveP256, &fixed)
    }
}
