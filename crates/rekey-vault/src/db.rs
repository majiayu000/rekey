use anyhow::{Context, Result, bail};
use rusqlite::Connection;

use crate::crypto::{EncryptedBlob, MasterKey, decrypt, encrypt};

const PASSWORD_VERIFIER_KEY: &str = "password_verifier";
const PASSWORD_VERIFIER_PLAINTEXT: &[u8] = b"rekey-password-verifier-v1";

#[derive(serde::Deserialize, serde::Serialize)]
struct StoredEncryptedBlob {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS secrets (
            id              TEXT PRIMARY KEY,
            name            TEXT UNIQUE NOT NULL,
            provider        TEXT NOT NULL DEFAULT '',
            credential_type TEXT NOT NULL DEFAULT 'api-key',
            ciphertext      BLOB NOT NULL,
            iv              BLOB NOT NULL,
            host_pattern    TEXT NOT NULL DEFAULT '',
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS injection_rules (
            id          TEXT PRIMARY KEY,
            secret_id   TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
            header_name TEXT NOT NULL,
            value_format TEXT NOT NULL,
            path_pattern TEXT NOT NULL,
            method      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            secret_name TEXT NOT NULL,
            target_host TEXT NOT NULL,
            target_path TEXT NOT NULL,
            status_code INTEGER,
            latency_ms  INTEGER,
            source      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        PRAGMA foreign_keys = ON;",
    )?;
    Ok(())
}

pub fn store_password_verifier(conn: &Connection, master_key: &MasterKey) -> Result<()> {
    let blob = encrypt(master_key, PASSWORD_VERIFIER_PLAINTEXT)?;
    let stored = StoredEncryptedBlob {
        iv: blob.iv,
        ciphertext: blob.ciphertext,
    };
    let value = serde_json::to_vec(&stored)?;

    conn.execute(
        "INSERT INTO config (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![PASSWORD_VERIFIER_KEY, value],
    )
    .context("failed to store password verifier")?;

    Ok(())
}

pub fn verify_password(conn: &Connection, master_key: &MasterKey) -> Result<()> {
    let value: Vec<u8> = conn
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            [PASSWORD_VERIFIER_KEY],
            |row| row.get(0),
        )
        .context("password verifier not found in vault")?;
    let stored: StoredEncryptedBlob =
        serde_json::from_slice(&value).context("password verifier is invalid")?;
    let blob = EncryptedBlob {
        iv: stored.iv,
        ciphertext: stored.ciphertext,
    };
    let plaintext = decrypt(master_key, &blob).context("invalid master password")?;
    if plaintext != PASSWORD_VERIFIER_PLAINTEXT {
        bail!("invalid master password");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_master_key;

    fn test_conn() -> Result<(Connection, MasterKey)> {
        let conn = Connection::open_in_memory()?;
        init_db(&conn)?;
        let key = derive_master_key("correct-password", &[7u8; 16])?;
        Ok((conn, key))
    }

    #[test]
    fn password_verifier_accepts_original_key() -> Result<()> {
        let (conn, key) = test_conn()?;
        store_password_verifier(&conn, &key)?;

        verify_password(&conn, &key)
    }

    #[test]
    fn password_verifier_rejects_wrong_key() -> Result<()> {
        let (conn, key) = test_conn()?;
        store_password_verifier(&conn, &key)?;
        let wrong_key = derive_master_key("wrong-password", &[7u8; 16])?;

        let result = verify_password(&conn, &wrong_key);

        let err = match result {
            Ok(()) => bail!("wrong key verified successfully"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("invalid master password"));
        Ok(())
    }
}
