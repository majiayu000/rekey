use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::fs;
use std::path::{Path, PathBuf};

pub struct CertificateAuthority {
    key_pair: KeyPair,
    cert_pem: String,
    cert_der: Vec<u8>,
    base_dir: PathBuf,
}

impl CertificateAuthority {
    /// Generate a new CA and persist to disk.
    pub fn generate(base_dir: &Path) -> Result<Self> {
        fs::create_dir_all(base_dir)?;

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("failed to generate CA key pair")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "rekey Local CA");
        dn.push(DnType::OrganizationName, "rekey");
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);

        let cert = params
            .self_signed(&key_pair)
            .context("failed to self-sign CA cert")?;

        let cert_pem = cert.pem();
        let cert_der = cert.der().to_vec();
        let key_pem = key_pair.serialize_pem();

        let key_path = base_dir.join("ca.key");
        fs::write(&key_path, &key_pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }

        fs::write(base_dir.join("ca.pem"), &cert_pem)?;

        Ok(Self {
            key_pair,
            cert_pem,
            cert_der,
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Load an existing CA from disk.
    pub fn load(base_dir: &Path) -> Result<Self> {
        let key_pem = fs::read_to_string(base_dir.join("ca.key"))
            .context("CA key not found — run `rekey init` first")?;
        let cert_pem = fs::read_to_string(base_dir.join("ca.pem")).context("CA cert not found")?;

        let key_pair = KeyPair::from_pem(&key_pem).context("failed to parse CA key")?;

        let cert_der = pem_to_der(&cert_pem)?;

        Ok(Self {
            key_pair,
            cert_pem,
            cert_der,
            base_dir: base_dir.to_path_buf(),
        })
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn ca_cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Install CA cert into system trust store.
    pub fn install_to_system(&self) -> Result<()> {
        let pem_path = self.base_dir.join("ca.pem");
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("security")
                .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k"])
                .arg("/Library/Keychains/System.keychain")
                .arg(&pem_path)
                .status()
                .context("failed to run security command")?;
            if !status.success() {
                anyhow::bail!("failed to install CA cert (try with sudo)");
            }
        }
        #[cfg(target_os = "linux")]
        {
            let dest = Path::new("/usr/local/share/ca-certificates/rekey-ca.crt");
            fs::copy(&pem_path, dest).context("failed to copy CA cert (try with sudo)")?;
            let status = std::process::Command::new("update-ca-certificates")
                .status()
                .context("failed to run update-ca-certificates")?;
            if !status.success() {
                anyhow::bail!("update-ca-certificates failed");
            }
        }
        tracing::info!("CA cert installed to system trust store");
        Ok(())
    }

    /// Remove CA cert from system trust store.
    pub fn remove_from_system(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        let pem_path = self.base_dir.join("ca.pem");
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("security")
                .args(["remove-trusted-cert", "-d"])
                .arg(&pem_path)
                .status()
                .context("failed to run security remove-trusted-cert")?;
            if !status.success() {
                tracing::warn!("failed to remove CA cert from system keychain");
            }
        }
        #[cfg(target_os = "linux")]
        {
            let dest = Path::new("/usr/local/share/ca-certificates/rekey-ca.crt");
            if let Err(e) = fs::remove_file(dest) {
                tracing::warn!("failed to remove CA cert file: {e}");
            }
            if let Err(e) = std::process::Command::new("update-ca-certificates").status() {
                tracing::warn!("failed to run update-ca-certificates: {e}");
            }
        }
        Ok(())
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let b64: String = pem
        .trim()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("invalid PEM encoding")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_creates_files() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::generate(tmp.path()).unwrap();

        assert!(tmp.path().join("ca.key").exists());
        assert!(tmp.path().join("ca.pem").exists());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!ca.ca_cert_der().is_empty());
    }

    #[test]
    fn load_existing_ca() {
        let tmp = tempfile::tempdir().unwrap();
        let original = CertificateAuthority::generate(tmp.path()).unwrap();
        let loaded = CertificateAuthority::load(tmp.path()).unwrap();

        assert_eq!(original.ca_cert_pem(), loaded.ca_cert_pem());
        assert_eq!(original.ca_cert_der(), loaded.ca_cert_der());
    }
}
