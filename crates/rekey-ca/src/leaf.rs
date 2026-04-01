use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, SanType};
use rustls_pki_types::CertificateDer;
use std::time::{Duration, Instant};

use crate::authority::CertificateAuthority;

#[derive(Clone)]
pub struct LeafCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    created_at: Instant,
}

impl LeafCert {
    fn is_expired(&self) -> bool {
        // Refresh 1h before 24h expiry
        self.created_at.elapsed() > Duration::from_secs(23 * 3600)
    }
}

pub struct LeafCertCache {
    cache: DashMap<String, LeafCert>,
}

impl LeafCertCache {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    pub fn get_or_create(&self, hostname: &str, ca: &CertificateAuthority) -> Result<LeafCert> {
        if let Some(entry) = self.cache.get(hostname) {
            if !entry.is_expired() {
                return Ok(entry.clone());
            }
        }

        let leaf = generate_leaf(hostname, ca)?;
        self.cache.insert(hostname.to_string(), leaf.clone());
        Ok(leaf)
    }
}

fn generate_leaf(hostname: &str, ca: &CertificateAuthority) -> Result<LeafCert> {
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate leaf key")?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        DnValue::PrintableString(hostname.try_into().context("invalid hostname for CN")?),
    );
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(
        hostname.try_into().context("invalid hostname for SAN")?,
    )];
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2034, 1, 1);

    let ca_der: CertificateDer<'_> = ca.ca_cert_der().into();
    let ca_cert_params =
        CertificateParams::from_ca_cert_der(&ca_der).context("failed to parse CA cert")?;
    let ca_cert = ca_cert_params
        .self_signed(ca.key_pair())
        .context("failed to reconstruct CA cert for signing")?;

    let leaf_cert = params
        .signed_by(&leaf_key, &ca_cert, ca.key_pair())
        .context("failed to sign leaf cert")?;

    Ok(LeafCert {
        cert_der: leaf_cert.der().to_vec(),
        key_der: leaf_key.serialize_der(),
        created_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::CertificateAuthority;
    use tempfile::TempDir;

    #[test]
    fn generate_leaf_cert_for_host() {
        let dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate(dir.path()).unwrap();
        let cache = LeafCertCache::new();
        let leaf = cache.get_or_create("api.anthropic.com", &ca).unwrap();
        assert!(!leaf.cert_der.is_empty());
        assert!(!leaf.key_der.is_empty());
    }

    #[test]
    fn cache_returns_same_cert() {
        let dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate(dir.path()).unwrap();
        let cache = LeafCertCache::new();
        let c1 = cache.get_or_create("api.anthropic.com", &ca).unwrap();
        let c2 = cache.get_or_create("api.anthropic.com", &ca).unwrap();
        assert_eq!(c1.cert_der, c2.cert_der);
    }

    #[test]
    fn different_hosts_get_different_certs() {
        let dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate(dir.path()).unwrap();
        let cache = LeafCertCache::new();
        let c1 = cache.get_or_create("api.anthropic.com", &ca).unwrap();
        let c2 = cache.get_or_create("api.openai.com", &ca).unwrap();
        assert_ne!(c1.cert_der, c2.cert_der);
    }
}
