use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, SanType};
use rustls_pki_types::CertificateDer;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let (y, m, d) = current_utc_ymd();
    let (next_y, next_m, next_d) = add_days(y, m, d, 1);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    params.not_after = rcgen::date_time_ymd(next_y, next_m, next_d);

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

fn current_utc_ymd() -> (i32, u8, u8) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = now / 86_400;
    civil_from_days(days)
}

fn add_days(year: i32, month: u8, day: u8, delta: i64) -> (i32, u8, u8) {
    let z = days_from_civil(year, month, day) + delta;
    civil_from_days(z)
}

fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    (year as i32, m as u8, d as u8)
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

    #[test]
    fn add_days_rollover() {
        assert_eq!(add_days(2026, 12, 31, 1), (2027, 1, 1));
        assert_eq!(add_days(2024, 2, 28, 1), (2024, 2, 29));
        assert_eq!(add_days(2025, 2, 28, 1), (2025, 3, 1));
    }
}
