use anyhow::Result;
use std::fs;

pub fn run() -> Result<()> {
    super::cmd_runtime::cleanup_runtime_files();
    let dir = super::cmd_init::rekey_dir();
    if !dir.exists() {
        println!("Nothing to destroy");
        return Ok(());
    }

    if let Ok(ca) = rekey_ca::authority::CertificateAuthority::load(&dir) {
        if let Err(e) = ca.remove_from_system() {
            tracing::warn!("failed to remove CA from system: {e}");
        }
    }

    fs::remove_dir_all(&dir)?;
    println!("All rekey data removed from {}", dir.display());
    Ok(())
}
