use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

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

fn read_salt(conn: &rusqlite::Connection) -> Result<Vec<u8>> {
    conn.query_row("SELECT value FROM config WHERE key = 'salt'", [], |row| {
        row.get(0)
    })
    .context("salt not found in vault")
}

pub(crate) fn open_vault_with_password(
    path: &Path,
    password: &str,
) -> Result<(rusqlite::Connection, rekey_vault::crypto::MasterKey)> {
    if !path.exists() {
        bail!("vault not found — run `rekey init` first");
    }
    let conn = rusqlite::Connection::open(path)?;
    let salt = read_salt(&conn)?;
    let master_key = rekey_vault::crypto::derive_master_key(password, &salt)?;
    rekey_vault::db::verify_password(&conn, &master_key)?;

    Ok((conn, master_key))
}

pub fn open_vault() -> Result<(rusqlite::Connection, rekey_vault::crypto::MasterKey)> {
    let path = db_path();
    if !path.exists() {
        bail!("vault not found — run `rekey init` first");
    }
    let password = prompt_password("Master password: ")?;
    open_vault_with_password(&path, &password)
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

    let master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;

    let conn = rusqlite::Connection::open(db_path())?;
    rekey_vault::db::init_db(&conn)?;
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('salt', ?1)",
        [salt.as_slice()],
    )?;
    rekey_vault::db::store_password_verifier(&conn, &master_key)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn temp_vault_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("vault").with_extension("db")
    }

    fn init_test_vault(
        path: &Path,
        password: &str,
        salt: &[u8],
    ) -> Result<rekey_vault::crypto::MasterKey> {
        let conn = rusqlite::Connection::open(path)?;
        rekey_vault::db::init_db(&conn)?;
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('salt', ?1)",
            [salt],
        )?;
        let master_key = rekey_vault::crypto::derive_master_key(password, salt)?;
        rekey_vault::db::store_password_verifier(&conn, &master_key)?;
        Ok(master_key)
    }

    #[test]
    fn open_vault_with_password_accepts_correct_password() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = temp_vault_path(&dir);
        let salt = [13u8; 16];
        let expected_key = init_test_vault(&path, "correct-password", &salt)?;

        let (_conn, actual_key) = open_vault_with_password(&path, "correct-password")?;

        assert_eq!(expected_key.expose_secret(), actual_key.expose_secret());
        Ok(())
    }

    #[test]
    fn open_vault_with_password_rejects_wrong_password() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = temp_vault_path(&dir);
        init_test_vault(&path, "correct-password", &[13u8; 16])?;

        let result = open_vault_with_password(&path, "wrong-password");

        let err = match result {
            Ok(_) => bail!("wrong password opened vault successfully"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("invalid master password"));
        Ok(())
    }
}
