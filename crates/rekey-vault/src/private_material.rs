//! Trusted import and consume boundary for private credential material.

use rekey_domain::{DomainError, credential::CredentialKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::ParsedCertificate;
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use crate::AuthorityError;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fn invalid() -> AuthorityError {
    DomainError::InvalidActionDefinition("invalid private credential material".into()).into()
}

pub(crate) fn validate(kind: CredentialKind, bytes: &[u8]) -> Result<(), AuthorityError> {
    if !matches!(
        kind,
        CredentialKind::MtlsIdentity | CredentialKind::PkiCaSigner
    ) {
        return Ok(());
    }
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    match kind {
        CredentialKind::MtlsIdentity => validate_mtls(text),
        CredentialKind::PkiCaSigner => validate_ca(text),
        _ => unreachable!(),
    }
}

pub(crate) fn decode_mtls(
    text: &str,
) -> Result<crate::secret::PreparedMtlsIdentity, AuthorityError> {
    let mut lines = text.split_inclusive('\n');
    let mut offset = 0;
    let mut certificates = Vec::new();
    let mut private_key = None;
    while let Some(line) = lines.next() {
        let start = offset;
        offset += line.len();
        let marker = match line.strip_suffix('\n') {
            Some(marker) => marker.strip_suffix('\r').unwrap_or(marker),
            None => line,
        };
        if marker.contains('\r') {
            return Err(invalid());
        }
        if marker.trim().is_empty() {
            continue;
        }
        let (end, is_certificate) = match marker {
            "-----BEGIN CERTIFICATE-----" => ("-----END CERTIFICATE-----", true),
            "-----BEGIN PRIVATE KEY-----" => ("-----END PRIVATE KEY-----", false),
            "-----BEGIN RSA PRIVATE KEY-----" => ("-----END RSA PRIVATE KEY-----", false),
            "-----BEGIN EC PRIVATE KEY-----" => ("-----END EC PRIVATE KEY-----", false),
            _ => return Err(invalid()),
        };
        let mut ended = false;
        for body_line in lines.by_ref() {
            offset += body_line.len();
            let body_marker = match body_line.strip_suffix('\n') {
                Some(marker) => marker.strip_suffix('\r').unwrap_or(marker),
                None => body_line,
            };
            if body_marker.contains('\r') {
                return Err(invalid());
            }
            if body_marker == end {
                ended = true;
                break;
            }
            if body_marker.starts_with("-----") {
                return Err(invalid());
            }
        }
        if !ended {
            return Err(invalid());
        }
        let block = &text.as_bytes()[start..offset];
        if is_certificate {
            let certificate = CertificateDer::from_pem_slice(block).map_err(|_| invalid())?;
            ParsedCertificate::try_from(&certificate).map_err(|_| invalid())?;
            certificates.push(certificate);
        } else {
            if private_key.is_some() {
                return Err(invalid());
            }
            private_key = Some(Zeroizing::new(
                PrivateKeyDer::from_pem_slice(block).map_err(|_| invalid())?,
            ));
        }
    }
    if certificates.is_empty() {
        return Err(invalid());
    }
    Ok(crate::secret::PreparedMtlsIdentity {
        certificates,
        private_key: private_key.ok_or_else(invalid)?,
    })
}

fn validate_ca(text: &str) -> Result<(), AuthorityError> {
    let material = decode_mtls(text)?;
    if material.certificates.len() != 1 {
        return Err(invalid());
    }
    let (remaining, certificate) =
        x509_parser::parse_x509_certificate(material.certificates[0].as_ref())
            .map_err(|_| invalid())?;
    if !remaining.is_empty()
        || certificate.version() != x509_parser::x509::X509Version::V3
        || certificate.subject() != certificate.issuer()
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
        || !certificate.validity().is_valid()
    {
        return Err(invalid());
    }
    certificate.extensions_map().map_err(|_| invalid())?;
    let constraints = certificate
        .basic_constraints()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let usage = certificate
        .key_usage()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if !constraints.critical
        || !constraints.value.ca
        || !usage.value.key_cert_sign()
        || certificate
            .name_constraints()
            .map_err(|_| invalid())?
            .is_some()
    {
        return Err(invalid());
    }
    for extension in certificate.extensions() {
        if extension.critical
            && !matches!(
                extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::BasicConstraints(_)
                    | x509_parser::extensions::ParsedExtension::KeyUsage(_)
            )
        {
            return Err(invalid());
        }
    }
    certificate.verify_signature(None).map_err(|_| invalid())?;
    validate_identity_key(material)
}

fn validate_mtls(text: &str) -> Result<(), AuthorityError> {
    validate_identity_key(decode_mtls(text)?)
}

fn validate_identity_key(
    mut material: crate::secret::PreparedMtlsIdentity,
) -> Result<(), AuthorityError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(std::mem::replace(
            &mut *material.private_key,
            PrivateKeyDer::Pkcs8(Vec::new().into()),
        ))
        .map_err(|_| invalid())?;
    CertifiedKey::new(material.certificates, signing_key)
        .keys_match()
        .map_err(|_| invalid())
}
