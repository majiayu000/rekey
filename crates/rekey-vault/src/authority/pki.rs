//! Local step-up-authorized client certificate issuance. CA material never leaves Worker.
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rcgen_signing::{
    CertificateParams, CertificateRevocationListParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyUsagePurpose, PublicKeyData, RevokedCertParams, SerialNumber,
    SignatureAlgorithm, SigningKey, SubjectPublicKeyInfo,
};
use rekey_domain::credential::{CredentialKind, CredentialState, VersionState};
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{
    PkiCertificateResponse, PkiCrlResponse, PkiGenerateCrlMeta, PkiIssueClientCsrMeta,
    PkiRevocationResponse, PkiRevokeCertificateMeta,
};
use rustls::SignatureScheme;
use rustls::pki_types::PrivateKeyDer;
use sha2::{Digest, Sha256};
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509CertificationRequest, X509Version};
use zeroize::Zeroizing;

use super::Worker;
use crate::command::{AuditDraft, Reply, UnlockProof};
use crate::crypto::random_array;
use crate::error::AuthorityError;
use crate::model::{PkiCertificateRecord, PkiCertificateState, PkiCrlRecord, event_type, outcome};
use crate::secret::SecretInput;

fn invalid() -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition("invalid client certificate request".into())
        .into()
}

/// Parse and authorize the public request once, independently of CA key loading.
fn client_request(
    bytes: &[u8],
) -> Result<(CertificateParams, SubjectPublicKeyInfo), AuthorityError> {
    if bytes.is_empty() || bytes.len() > rekey_domain::ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?.trim();
    if !text.starts_with("-----BEGIN CERTIFICATE REQUEST-----") {
        return Err(invalid());
    }
    let (rest, pem) = x509_parser::pem::parse_x509_pem(text.as_bytes()).map_err(|_| invalid())?;
    if pem.label != "CERTIFICATE REQUEST" || !rest.iter().all(u8::is_ascii_whitespace) {
        return Err(invalid());
    }
    let (rest, csr) = X509CertificationRequest::from_der(&pem.contents).map_err(|_| invalid())?;
    let info = &csr.certification_request_info;
    if !rest.is_empty()
        || info.version != X509Version::V1
        || info.subject_pki.subject_public_key.unused_bits != 0
    {
        return Err(invalid());
    }
    csr.verify_signature().map_err(|_| invalid())?;
    let mut attributes = info.subject.iter_attributes();
    let cn = attributes.next().ok_or_else(invalid)?;
    if cn.attr_type().to_id_string() != "2.5.4.3" || attributes.next().is_some() {
        return Err(invalid());
    }
    let cn = cn.as_str().map_err(|_| invalid())?;
    if cn.is_empty() || cn.len() > 253 || cn.trim() != cn || cn.chars().any(char::is_control) {
        return Err(invalid());
    }
    let mut dns = BTreeSet::new();
    if info.attributes().len() > 1 {
        return Err(invalid());
    }
    for attribute in info.iter_attributes() {
        let ParsedCriAttribute::ExtensionRequest(request) = attribute.parsed_attribute() else {
            return Err(invalid());
        };
        let mut extensions = BTreeSet::new();
        for extension in &request.extensions {
            if !extensions.insert(extension.oid.to_id_string()) {
                return Err(invalid());
            }
            match extension.parsed_extension() {
                ParsedExtension::BasicConstraints(bc)
                    if !bc.ca && bc.path_len_constraint.is_none() => {}
                ParsedExtension::KeyUsage(ku) if ku.flags == 1 => {}
                ParsedExtension::ExtendedKeyUsage(eku)
                    if eku.client_auth
                        && !eku.any
                        && !eku.server_auth
                        && !eku.code_signing
                        && !eku.email_protection
                        && !eku.time_stamping
                        && !eku.ocsp_signing
                        && eku.other.is_empty() => {}
                ParsedExtension::SubjectAlternativeName(san)
                    if !san.general_names.is_empty() && san.general_names.len() <= 16 =>
                {
                    for name in &san.general_names {
                        let GeneralName::DNSName(name) = name else {
                            return Err(invalid());
                        };
                        let valid = name.len() <= 253
                            && name.parse::<std::net::IpAddr>().is_err()
                            && name.split('.').all(|label| {
                                !label.is_empty()
                                    && label.len() <= 63
                                    && label.as_bytes()[0].is_ascii_alphanumeric()
                                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                                    && label
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            });
                        if !valid || !dns.insert(name.to_ascii_lowercase()) {
                            return Err(invalid());
                        }
                    }
                }
                _ => return Err(invalid()),
            }
        }
    }
    let key = SubjectPublicKeyInfo::from_der(info.subject_pki.raw).map_err(|_| invalid())?;
    let mut params =
        CertificateParams::new(dns.into_iter().collect::<Vec<_>>()).map_err(|_| invalid())?;
    params.distinguished_name = rcgen_signing::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.use_authority_key_identifier_extension = true;
    Ok((params, key))
}

// Private adapter over the existing AWS-LC signer: no rcgen private KeyPair or raw-sign API.
struct CaSigner {
    signer: Box<dyn rustls::sign::Signer>,
    public: Vec<u8>,
    algorithm: &'static SignatureAlgorithm,
}
impl PublicKeyData for CaSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}
impl SigningKey for CaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen_signing::Error> {
        self.signer
            .sign(message)
            .map_err(|_| rcgen_signing::Error::RemoteKeyError)
    }
}

impl Worker {
    pub(super) fn pki_issue_client_csr(
        &mut self,
        input: PkiIssueClientCsrMeta,
        csr: SecretInput,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Instant,
        reply: &Reply<PkiCertificateResponse>,
    ) -> Result<PkiCertificateResponse, AuthorityError> {
        self.require_unlocked()?;
        Self::pki_current(not_after, reply)?;
        let verified = self.verify_proof(&proof);
        drop(proof);
        verified?;
        let (mut params, public) = client_request(csr.expose())?;
        let request_digest = Sha256::digest(csr.expose()).into();
        drop(csr);
        let credential = self.load_verified_credential(input.credential_id)?;
        if credential.kind != CredentialKind::PkiCaSigner
            || credential.current_version != input.expected_version
        {
            return Err(invalid());
        }
        if credential.state != CredentialState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        let version = self
            .store
            .get_version(input.credential_id, input.expected_version)?;
        if version.state != VersionState::Active {
            return Err(AuthorityError::CredentialRevoked);
        }
        Self::pki_current(not_after, reply)?;
        let draft = |event_type, outcome, reason: &str| AuditDraft {
            request_id: Some(request_id),
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: Some(input.credential_id),
            credential_version: Some(input.expected_version),
            authorization: None,
            approval: None,
            usage: None,
            request_context: None,
            event_type,
            outcome,
            reason_code: reason.into(),
            upstream_status: None,
            latency_ms: None,
        };
        let mut serial: [u8; 16] = random_array()?;
        serial[0] &= 0x7f;
        if serial.iter().all(|b| *b == 0) {
            serial[15] = 1;
        }
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let mut record = PkiCertificateRecord {
            serial,
            credential_id: input.credential_id,
            credential_version: input.expected_version,
            request_id,
            request_digest,
            created_at_ms: crate::now_ms()?,
            state: PkiCertificateState::Reserved,
            finished_at_ms: None,
            certificate_der: None,
            issuer_der: None,
            revoked_at_ms: None,
        };
        // Durable serial reservation and started audit precede CA key decryption.
        self.commit_pki_record(
            &record,
            draft(
                event_type::PKI_CERTIFICATE_STARTED,
                outcome::UNKNOWN,
                "client-auth",
            ),
            true,
            Some(not_after),
        )?;
        let issued = (|| {
            Self::pki_current(not_after, reply)?;
            let payload = self.decrypt_credential_payload(&credential, &version)?;
            let text = std::str::from_utf8(&payload).map_err(|_| AuthorityError::CryptoFailure)?;
            let mut material = crate::private_material::decode_mtls(text)?;
            drop(payload);
            let ca_der = material
                .certificates
                .pop()
                .ok_or(AuthorityError::CryptoFailure)?;
            if !material.certificates.is_empty() {
                return Err(AuthorityError::CryptoFailure);
            }
            let (_, ca) = x509_parser::parse_x509_certificate(&ca_der)
                .map_err(|_| AuthorityError::CryptoFailure)?;
            let now = x509_parser::time::ASN1Time::now().to_datetime();
            params.not_before = now;
            params.not_after = now + Duration::from_secs(3600);
            if params.not_before < ca.validity().not_before.to_datetime()
                || params.not_after > ca.validity().not_after.to_datetime()
            {
                return Err(invalid());
            }
            let key = rustls::crypto::aws_lc_rs::default_provider()
                .key_provider
                .load_private_key(std::mem::replace(
                    &mut *material.private_key,
                    PrivateKeyDer::Pkcs8(Vec::new().into()),
                ))
                .map_err(|_| AuthorityError::CryptoFailure)?;
            drop(material);
            let signer = key
                .choose_scheme(&[
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ED25519,
                    SignatureScheme::RSA_PKCS1_SHA256,
                ])
                .ok_or(AuthorityError::CredentialSourceUnavailable)?;
            let algorithm = match signer.scheme() {
                SignatureScheme::ECDSA_NISTP256_SHA256 => &rcgen_signing::PKCS_ECDSA_P256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384 => &rcgen_signing::PKCS_ECDSA_P384_SHA384,
                SignatureScheme::ED25519 => &rcgen_signing::PKCS_ED25519,
                SignatureScheme::RSA_PKCS1_SHA256 => &rcgen_signing::PKCS_RSA_SHA256,
                _ => return Err(AuthorityError::CredentialSourceUnavailable),
            };
            let ca_signer = CaSigner {
                signer,
                public: ca.public_key().subject_public_key.data.to_vec(),
                algorithm,
            };
            drop(key);
            let issuer = Issuer::from_ca_cert_der(&ca_der, ca_signer)
                .map_err(|_| AuthorityError::CryptoFailure)?;

            Self::pki_current(not_after, reply)?;
            let certificate = params
                .signed_by(&public, &issuer)
                .map_err(|_| AuthorityError::CryptoFailure)?;
            drop(issuer);
            // Keep the generated certificate even when delivery has expired.
            Ok((
                PkiCertificateResponse {
                    certificate_pem: certificate.pem(),
                    serial_hex: data_encoding::HEXLOWER.encode(&serial),
                    issuer_version: version.version,
                },
                certificate.der().to_vec(),
                ca_der.to_vec(),
            ))
        })();
        let issued = match issued {
            Ok((response, certificate_der, issuer_der)) => {
                record.state = PkiCertificateState::Issued;
                record.certificate_der = Some(certificate_der);
                record.issuer_der = Some(issuer_der);
                Ok(response)
            }
            Err(error) => {
                record.state = PkiCertificateState::Failed;
                Err(error)
            }
        };
        record.finished_at_ms = Some(crate::now_ms()?);
        let (result_outcome, reason) = match &issued {
            Ok(_) => (outcome::SUCCESS, "client-auth"),
            Err(AuthorityError::AuthorityBusy) => (outcome::FAILURE, "cancelled-or-expired"),
            Err(_) => (outcome::FAILURE, "issuance-failed"),
        };
        // Terminal facts must survive cancellation; delivery deadline is checked
        // after this commit, without replacing an original issuance error.
        self.commit_pki_record(
            &record,
            draft(event_type::PKI_CERTIFICATE_FINISHED, result_outcome, reason),
            false,
            None,
        )?;
        // Finished success records generation, not delivery. Cancelled/expired
        // receivers cannot obtain the certificate after this durable commit.
        if issued.is_ok() {
            Self::pki_current(not_after, reply)?;
        }
        issued
    }

    pub(super) fn pki_generate_crl(
        &mut self,
        input: PkiGenerateCrlMeta,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Instant,
        reply: &Reply<(PkiCrlResponse, Vec<u8>)>,
    ) -> Result<(PkiCrlResponse, Vec<u8>), AuthorityError> {
        self.require_unlocked()?;
        Self::pki_current(not_after, reply)?;
        let verified = self.verify_proof(&proof);
        drop(proof);
        verified?;
        let credential = self.load_verified_credential(input.credential_id)?;
        if credential.kind != CredentialKind::PkiCaSigner || input.version == 0 {
            return Err(invalid());
        }
        // CRL-only historical access: ordinary leaf issuance remains current+Active.
        let version = self.store.get_version(input.credential_id, input.version)?;
        let certificates = self.store.verified_certificates(&self.header);
        let certificates = self.fault_on_integrity(certificates)?;
        // No issuer projection exists for a crashed reservation. Conservatively
        // refuse a full CRL rather than silently omit a potentially signed leaf.
        if certificates
            .iter()
            .any(|r| r.state == PkiCertificateState::Reserved)
        {
            return Err(invalid());
        }
        let number = self
            .header
            .generation
            .checked_add(1)
            .ok_or(AuthorityError::StorageIntegrityFailed)?;
        let mut record = PkiCrlRecord {
            number,
            credential_id: input.credential_id,
            credential_version: input.version,
            request_id,
            snapshot_digest: self.header.pki_digest,
            created_at_ms: crate::now_ms()?,
            state: PkiCertificateState::Reserved,
            finished_at_ms: None,
            crl_der: None,
            issuer_der: None,
        };
        let draft = |event_type, outcome, reason: &str| AuditDraft {
            request_id: Some(request_id),
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: Some(input.credential_id),
            credential_version: Some(input.version),
            authorization: None,
            approval: None,
            usage: None,
            request_context: None,
            event_type,
            outcome,
            reason_code: reason.into(),
            upstream_status: None,
            latency_ms: None,
        };
        Self::pki_current(not_after, reply)?;
        self.commit_pki_crl(
            &record,
            draft(event_type::PKI_CRL_STARTED, outcome::UNKNOWN, "full-crl"),
            true,
            Some(not_after),
        )?;
        let generated = (|| {
            Self::pki_current(not_after, reply)?;
            let payload = self.decrypt_credential_payload(&credential, &version)?;
            let text = std::str::from_utf8(&payload).map_err(|_| AuthorityError::CryptoFailure)?;
            let mut material = crate::private_material::decode_mtls(text)?;
            drop(payload);
            let ca_der = material
                .certificates
                .pop()
                .ok_or(AuthorityError::CryptoFailure)?;
            if !material.certificates.is_empty() {
                return Err(AuthorityError::CryptoFailure);
            }
            let (rest, ca) = x509_parser::parse_x509_certificate(&ca_der)
                .map_err(|_| AuthorityError::CryptoFailure)?;
            if !rest.is_empty() {
                return Err(AuthorityError::CryptoFailure);
            }
            let now_ms = crate::now_ms()?;
            let now = x509_parser::time::ASN1Time::from_timestamp(now_ms / 1000)
                .map_err(|_| AuthorityError::ClockUnavailable)?
                .to_datetime();
            let next = now + Duration::from_secs(3600);
            if now < ca.validity().not_before.to_datetime()
                || next > ca.validity().not_after.to_datetime()
                || !ca
                    .key_usage()
                    .map_err(|_| invalid())?
                    .is_some_and(|ku| ku.value.crl_sign())
            {
                return Err(invalid());
            }
            let mut ski = None;
            for extension in ca.extensions() {
                if let ParsedExtension::SubjectKeyIdentifier(id) = extension.parsed_extension()
                    && (ski.replace(id.0.to_vec()).is_some() || id.0.is_empty())
                {
                    return Err(invalid());
                }
            }
            let ski = ski.ok_or_else(invalid)?;
            let mut revoked_certs = Vec::new();
            for row in &certificates {
                if row.state != PkiCertificateState::Issued {
                    continue;
                }
                let issuer_der = row
                    .issuer_der
                    .as_deref()
                    .ok_or(AuthorityError::StorageIntegrityFailed)?;
                let (rest, original_issuer) = x509_parser::parse_x509_certificate(issuer_der)
                    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                if !rest.is_empty() {
                    return Err(AuthorityError::StorageIntegrityFailed);
                }
                if original_issuer.subject().as_raw() != ca.subject().as_raw()
                    || original_issuer.public_key().raw != ca.public_key().raw
                {
                    continue;
                }
                let der = row
                    .certificate_der
                    .as_deref()
                    .ok_or(AuthorityError::StorageIntegrityFailed)?;
                let (rest, leaf) = x509_parser::parse_x509_certificate(der)
                    .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
                let trim = |bytes: &[u8]| bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
                if !rest.is_empty()
                    || leaf.issuer().as_raw() != ca.subject().as_raw()
                    || leaf.raw_serial()[trim(leaf.raw_serial())..]
                        != row.serial[trim(&row.serial)..]
                    || leaf.verify_signature(Some(ca.public_key())).is_err()
                {
                    return Err(AuthorityError::StorageIntegrityFailed);
                }
                if let Some(revoked_at_ms) = row.revoked_at_ms {
                    if revoked_at_ms > now_ms {
                        return Err(invalid());
                    }
                    revoked_certs.push(RevokedCertParams {
                        serial_number: SerialNumber::from_slice(&row.serial),
                        revocation_time: x509_parser::time::ASN1Time::from_timestamp(
                            revoked_at_ms / 1000,
                        )
                        .map_err(|_| AuthorityError::ClockUnavailable)?
                        .to_datetime(),
                        reason_code: None,
                        invalidity_date: None,
                    });
                }
            }
            let key = rustls::crypto::aws_lc_rs::default_provider()
                .key_provider
                .load_private_key(std::mem::replace(
                    &mut *material.private_key,
                    PrivateKeyDer::Pkcs8(Vec::new().into()),
                ))
                .map_err(|_| AuthorityError::CryptoFailure)?;
            drop(material);
            let signer = key
                .choose_scheme(&[
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ED25519,
                    SignatureScheme::RSA_PKCS1_SHA256,
                ])
                .ok_or(AuthorityError::CredentialSourceUnavailable)?;
            let algorithm = match signer.scheme() {
                SignatureScheme::ECDSA_NISTP256_SHA256 => &rcgen_signing::PKCS_ECDSA_P256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384 => &rcgen_signing::PKCS_ECDSA_P384_SHA384,
                SignatureScheme::ED25519 => &rcgen_signing::PKCS_ED25519,
                SignatureScheme::RSA_PKCS1_SHA256 => &rcgen_signing::PKCS_RSA_SHA256,
                _ => return Err(AuthorityError::CredentialSourceUnavailable),
            };
            let ca_signer = CaSigner {
                signer,
                public: ca.public_key().subject_public_key.data.to_vec(),
                algorithm,
            };
            drop(key);
            let issuer = Issuer::from_ca_cert_der(&ca_der, ca_signer)
                .map_err(|_| AuthorityError::CryptoFailure)?;
            Self::pki_current(not_after, reply)?;
            let crl = CertificateRevocationListParams {
                this_update: now,
                next_update: next,
                crl_number: SerialNumber::from(number),
                issuing_distribution_point: None,
                revoked_certs,
                key_identifier_method: KeyIdMethod::PreSpecified(ski),
            }
            .signed_by(&issuer)
            .map_err(|_| AuthorityError::CryptoFailure)?;
            drop(issuer);
            Ok((crl, ca_der.to_vec()))
        })();
        let generated = match generated {
            Ok((crl, issuer_der)) => {
                record.state = PkiCertificateState::Issued;
                record.crl_der = Some(crl.der().to_vec());
                record.issuer_der = Some(issuer_der);
                Ok(crl)
            }
            Err(error) => {
                record.state = PkiCertificateState::Failed;
                Err(error)
            }
        };
        record.finished_at_ms = Some(crate::now_ms()?);
        let (result_outcome, reason) = match &generated {
            Ok(_) => (outcome::SUCCESS, "full-crl"),
            Err(AuthorityError::AuthorityBusy) => (outcome::FAILURE, "cancelled-or-expired"),
            Err(_) => (outcome::FAILURE, "crl-failed"),
        };
        // Generated DER is committed even when delivery has expired or is too large.
        self.commit_pki_crl(
            &record,
            draft(event_type::PKI_CRL_FINISHED, result_outcome, reason),
            false,
            None,
        )?;
        let crl = generated?;
        Self::pki_current(not_after, reply)?;
        let pem = crl
            .pem()
            .map_err(|_| AuthorityError::CryptoFailure)?
            .into_bytes();
        if pem.len() > rekey_domain::ipc::RESPONSE_BODY_MAX_BYTES as usize {
            return Err(invalid());
        }
        Ok((
            PkiCrlResponse {
                number,
                issuer_version: input.version,
            },
            pem,
        ))
    }

    fn commit_pki_crl(
        &mut self,
        record: &PkiCrlRecord,
        draft: AuditDraft,
        insert: bool,
        not_after: Option<Instant>,
    ) -> Result<(), AuthorityError> {
        let audit = self.audit_event_or_fault(draft)?;
        let observed = self.mutation_observation()?;
        let key = Zeroizing::new(*self.require_unlocked()?.bytes());
        let mut generation = crate::store::generation::GenerationAttempt::new(
            &self.anchors,
            &self.header,
            observed,
            &key,
            self.header
                .generation
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            not_after,
            None,
        )?;
        let result = self
            .store
            .commit_crl(record, &audit, insert, &key, &mut generation);
        let completed = generation.finish();
        let result = self.complete_generation(result, completed);
        self.fault_on_audit_failure(result)
    }

    pub(super) fn pki_revoke_certificate(
        &mut self,
        input: PkiRevokeCertificateMeta,
        proof: UnlockProof,
        request_id: RequestId,
        not_after: Instant,
        reply: &Reply<PkiRevocationResponse>,
    ) -> Result<PkiRevocationResponse, AuthorityError> {
        self.require_unlocked()?;
        Self::pki_current(not_after, reply)?;
        let verified = self.verify_proof(&proof);
        drop(proof);
        verified?;
        let serial: [u8; 16] = data_encoding::HEXLOWER
            .decode(input.serial_hex.as_bytes())
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        if serial == [0; 16] || serial[0] & 0x80 != 0 {
            return Err(invalid());
        }
        let audit = self.audit_event_or_fault(AuditDraft {
            request_id: Some(request_id),
            session_id: None,
            action_id: None,
            action_version: None,
            credential_id: None,
            credential_version: None,
            authorization: None,
            approval: None,
            usage: None,
            request_context: None,
            event_type: event_type::PKI_CERTIFICATE_REVOKED,
            outcome: outcome::SUCCESS,
            reason_code: format!("serial:{}", input.serial_hex),
            upstream_status: None,
            latency_ms: None,
        })?;
        let now = crate::now_ms()?;
        let observed = self.mutation_observation()?;
        let key = Zeroizing::new(*self.require_unlocked()?.bytes());
        Self::pki_current(not_after, reply)?;
        let mut generation = crate::store::generation::GenerationAttempt::new(
            &self.anchors,
            &self.header,
            observed,
            &key,
            self.header
                .generation
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            Some(not_after),
            None,
        )?;
        let result = self
            .store
            .revoke_certificate(serial, now, audit, &key, &mut generation);
        let completed = generation.finish();
        let result = self.complete_generation(result, completed);
        let revoked_at_ms = self.fault_on_audit_failure(result)?;
        Self::pki_current(not_after, reply)?;
        Ok(PkiRevocationResponse {
            serial_hex: input.serial_hex,
            revoked_at_ms,
        })
    }

    fn commit_pki_record(
        &mut self,
        record: &PkiCertificateRecord,
        draft: AuditDraft,
        insert: bool,
        not_after: Option<Instant>,
    ) -> Result<(), AuthorityError> {
        let audit = self.audit_event_or_fault(draft)?;
        let observed = self.mutation_observation()?;
        let key = Zeroizing::new(*self.require_unlocked()?.bytes());
        let mut generation = crate::store::generation::GenerationAttempt::new(
            &self.anchors,
            &self.header,
            observed,
            &key,
            self.header
                .generation
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?,
            not_after,
            None,
        )?;
        let result = self
            .store
            .commit_certificate(record, &audit, insert, &key, &mut generation);
        let completed = generation.finish();
        let result = self.complete_generation(result, completed);
        self.fault_on_audit_failure(result)
    }

    fn pki_current<T>(deadline: Instant, reply: &Reply<T>) -> Result<(), AuthorityError> {
        if Instant::now() >= deadline || reply.is_closed() {
            Err(AuthorityError::AuthorityBusy)
        } else {
            Ok(())
        }
    }
}
