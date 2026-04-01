use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{EncryptedBlob, MasterKey, decrypt, encrypt};
use crate::providers::get_provider;
use crate::rules::add_injection_rule;

#[derive(Debug, serde::Serialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub host_pattern: String,
    pub created_at: i64,
    pub updated_at: i64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn add_secret(
    conn: &Connection,
    master_key: &MasterKey,
    name: &str,
    provider: &str,
    value: &str,
    host_pattern: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let blob = encrypt(master_key, value.as_bytes())?;
    let now = now_unix();
    conn.execute(
        "INSERT INTO secrets (id, name, provider, ciphertext, iv, host_pattern, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![id, name, provider, blob.ciphertext, blob.iv, host_pattern, now, now],
    )
    .context("failed to insert secret (name may already exist)")?;
    if let Some(pc) = get_provider(provider) {
        add_injection_rule(
            conn,
            &id,
            pc.header_name,
            pc.value_format,
            pc.path_pattern,
            "*",
        )?;
    }
    Ok(id)
}

pub fn list_secrets(conn: &Connection) -> Result<Vec<SecretEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, provider, host_pattern, created_at, updated_at FROM secrets ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SecretEntry {
            id: row.get(0)?,
            name: row.get(1)?,
            provider: row.get(2)?,
            host_pattern: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn get_secret_value(conn: &Connection, master_key: &MasterKey, name: &str) -> Result<String> {
    let (ciphertext, iv): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT ciphertext, iv FROM secrets WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("secret not found")?;
    let blob = EncryptedBlob { iv, ciphertext };
    let plaintext = decrypt(master_key, &blob)?;
    String::from_utf8(plaintext).context("secret is not valid UTF-8")
}

pub fn get_secret_value_by_id(
    conn: &Connection,
    master_key: &MasterKey,
    secret_id: &str,
) -> Result<String> {
    let (ciphertext, iv): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT ciphertext, iv FROM secrets WHERE id = ?1",
            [secret_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("secret not found")?;
    let blob = EncryptedBlob { iv, ciphertext };
    let plaintext = decrypt(master_key, &blob)?;
    String::from_utf8(plaintext).context("secret is not valid UTF-8")
}

pub fn remove_secret(conn: &Connection, name: &str) -> Result<()> {
    let changes = conn.execute("DELETE FROM secrets WHERE name = ?1", [name])?;
    if changes == 0 {
        bail!("secret '{name}' not found");
    }
    Ok(())
}

pub fn rotate_secret(
    conn: &Connection,
    master_key: &MasterKey,
    name: &str,
    new_value: &str,
) -> Result<()> {
    let blob = encrypt(master_key, new_value.as_bytes())?;
    let now = now_unix();
    let changes = conn.execute(
        "UPDATE secrets SET ciphertext = ?1, iv = ?2, updated_at = ?3 WHERE name = ?4",
        rusqlite::params![blob.ciphertext, blob.iv, now, name],
    )?;
    if changes == 0 {
        bail!("secret '{name}' not found");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_master_key;
    use crate::db::init_db;

    fn test_db() -> (rusqlite::Connection, MasterKey) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let key = derive_master_key("test", &[0u8; 16]).unwrap();
        (conn, key)
    }

    #[test]
    fn add_and_list_secret() {
        let (conn, key) = test_db();
        add_secret(
            &conn,
            &key,
            "anthropic",
            "anthropic",
            "sk-ant-123",
            "api.anthropic.com",
        )
        .unwrap();
        let secrets = list_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "anthropic");
        assert_eq!(secrets[0].provider, "anthropic");
        assert_eq!(secrets[0].host_pattern, "api.anthropic.com");
    }

    #[test]
    fn get_secret_value_decrypts() {
        let (conn, key) = test_db();
        add_secret(
            &conn,
            &key,
            "anthropic",
            "anthropic",
            "sk-ant-123",
            "api.anthropic.com",
        )
        .unwrap();
        let value = get_secret_value(&conn, &key, "anthropic").unwrap();
        assert_eq!(value, "sk-ant-123");
    }

    #[test]
    fn remove_secret_works() {
        let (conn, key) = test_db();
        add_secret(
            &conn,
            &key,
            "anthropic",
            "anthropic",
            "sk-ant-123",
            "api.anthropic.com",
        )
        .unwrap();
        remove_secret(&conn, "anthropic").unwrap();
        let secrets = list_secrets(&conn).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn rotate_secret_updates_value() {
        let (conn, key) = test_db();
        add_secret(
            &conn,
            &key,
            "anthropic",
            "anthropic",
            "sk-ant-old",
            "api.anthropic.com",
        )
        .unwrap();
        rotate_secret(&conn, &key, "anthropic", "sk-ant-new").unwrap();
        let value = get_secret_value(&conn, &key, "anthropic").unwrap();
        assert_eq!(value, "sk-ant-new");
    }

    #[test]
    fn duplicate_name_fails() {
        let (conn, key) = test_db();
        add_secret(
            &conn,
            &key,
            "anthropic",
            "anthropic",
            "sk-1",
            "api.anthropic.com",
        )
        .unwrap();
        let result = add_secret(
            &conn,
            &key,
            "anthropic",
            "anthropic",
            "sk-2",
            "api.anthropic.com",
        );
        assert!(result.is_err());
    }
}
