use anyhow::{Context, Result, bail};
use std::path::PathBuf;

pub fn rekey_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rekey")
}

pub fn db_path() -> PathBuf {
    rekey_dir().join("vault.db")
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    if let Ok(pw) = std::env::var("REKEY_PASSWORD") {
        return Ok(pw);
    }
    rpassword::prompt_password(prompt).context("failed to read password")
}

pub fn open_vault() -> Result<(rusqlite::Connection, rekey_vault::crypto::MasterKey)> {
    let path = db_path();
    if !path.exists() {
        bail!("vault not found — run `rekey init` first");
    }
    let conn = rekey_vault::db::open_connection(&path)?;
    let password = prompt_password("Master password: ")?;

    let salt: Vec<u8> = conn
        .query_row("SELECT value FROM config WHERE key = 'salt'", [], |row| {
            row.get(0)
        })
        .context("salt not found in vault")?;

    let master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;
    Ok((conn, master_key))
}

pub fn run() -> Result<()> {
    let dir = rekey_dir();
    if db_path().exists() {
        bail!("rekey already initialized at {}", dir.display());
    }

    std::fs::create_dir_all(&dir)?;

    let password = prompt_password("Set master password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        bail!("passwords don't match");
    }

    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut salt);

    let _master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;

    let conn = rekey_vault::db::open_connection(db_path())?;
    rekey_vault::db::init_db(&conn)?;
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('salt', ?1)",
        [salt.as_slice()],
    )?;

    let ca = rekey_ca::authority::CertificateAuthority::generate(&dir)?;

    println!("Installing CA certificate to system trust store...");
    if let Err(e) = ca.install_to_system() {
        println!("Warning: could not install CA to system trust store: {e}");
        println!(
            "You may need to run with sudo or install manually: {}/ca.pem",
            dir.display()
        );
    }

    println!("rekey initialized at {}", dir.display());
    println!("CA certificate: {}/ca.pem", dir.display());
    println!("\nAdd your first secret: rekey add anthropic <your-api-key>");

    Ok(())
}
