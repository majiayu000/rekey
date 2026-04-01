use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{EncryptedBlob, MasterKey, decrypt, encrypt};
use crate::providers::get_provider;
use crate::rules::add_injection_rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialType {
    ApiKey,
    Basic,
    Bearer,
    Custom,
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey => write!(f, "api-key"),
            Self::Basic => write!(f, "basic"),
            Self::Bearer => write!(f, "bearer"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for CredentialType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "api-key" => Ok(Self::ApiKey),
            "basic" => Ok(Self::Basic),
            "bearer" => Ok(Self::Bearer),
            "custom" => Ok(Self::Custom),
            _ => bail!("unknown credential type: {s}"),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub credential_type: String,
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

fn encrypt_fields(
    master_key: &MasterKey,
    fields: &HashMap<String, String>,
) -> Result<EncryptedBlob> {
    let json = serde_json::to_string(fields)?;
    encrypt(master_key, json.as_bytes())
}

fn decrypt_fields(
    master_key: &MasterKey,
    blob: &EncryptedBlob,
) -> Result<HashMap<String, String>> {
    let plaintext = decrypt(master_key, blob)?;
    let json_str = String::from_utf8(plaintext).context("credential data is not valid UTF-8")?;
    serde_json::from_str(&json_str).context("credential data is not valid JSON")
}

/// Store a multi-field credential.
pub fn store_credential(
    conn: &Connection,
    master_key: &MasterKey,
    name: &str,
    credential_type: CredentialType,
    fields: &HashMap<String, String>,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let blob = encrypt_fields(master_key, fields)?;
    let now = now_unix();
    let cred_type_str = credential_type.to_string();
    conn.execute(
        "INSERT INTO secrets (id, name, provider, credential_type, ciphertext, iv, host_pattern, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![id, name, "", cred_type_str, blob.ciphertext, blob.iv, "", now, now],
    )
    .context("failed to store credential (name may already exist)")?;
    Ok(id)
}

/// Get decrypted credential fields and type.
pub fn get_credential_fields(
    conn: &Connection,
    master_key: &MasterKey,
    name: &str,
) -> Result<(CredentialType, HashMap<String, String>)> {
    let (ciphertext, iv, cred_type_str): (Vec<u8>, Vec<u8>, String) = conn
        .query_row(
            "SELECT ciphertext, iv, credential_type FROM secrets WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .context("credential not found")?;
    let blob = EncryptedBlob { iv, ciphertext };
    let fields = decrypt_fields(master_key, &blob)?;
    let cred_type: CredentialType = cred_type_str.parse()?;
    Ok((cred_type, fields))
}

/// Add a single-value API key secret (convenience for proxy injection).
pub fn add_secret(
    conn: &Connection,
    master_key: &MasterKey,
    name: &str,
    provider: &str,
    value: &str,
    host_pattern: &str,
) -> Result<String> {
    let mut fields = HashMap::new();
    fields.insert("value".to_string(), value.to_string());

    let id = uuid::Uuid::new_v4().to_string();
    let blob = encrypt_fields(master_key, &fields)?;
    let now = now_unix();
    conn.execute(
        "INSERT INTO secrets (id, name, provider, credential_type, ciphertext, iv, host_pattern, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![id, name, provider, "api-key", blob.ciphertext, blob.iv, host_pattern, now, now],
    )
    .context("failed to insert secret (name may already exist)")?;
    if let Some(pc) = get_provider(provider) {
        add_injection_rule(conn, &id, pc.header_name, pc.value_format, pc.path_pattern, "*")?;
    }
    Ok(id)
}

pub fn list_secrets(conn: &Connection) -> Result<Vec<SecretEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, provider, credential_type, host_pattern, created_at, updated_at
         FROM secrets ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SecretEntry {
            id: row.get(0)?,
            name: row.get(1)?,
            provider: row.get(2)?,
            credential_type: row.get(3)?,
            host_pattern: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Get the raw API key value (for proxy injection).
pub fn get_secret_value(conn: &Connection, master_key: &MasterKey, name: &str) -> Result<String> {
    let (ciphertext, iv): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT ciphertext, iv FROM secrets WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("secret not found")?;
    let blob = EncryptedBlob { iv, ciphertext };
    let fields = decrypt_fields(master_key, &blob)?;
    fields
        .get("value")
        .cloned()
        .context("credential has no 'value' field")
}

/// Get the raw API key value by ID (for proxy injection).
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
    let fields = decrypt_fields(master_key, &blob)?;
    fields
        .get("value")
        .cloned()
        .context("credential has no 'value' field")
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
    let mut fields = HashMap::new();
    fields.insert("value".to_string(), new_value.to_string());
    let blob = encrypt_fields(master_key, &fields)?;
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
        assert_eq!(secrets[0].credential_type, "api-key");
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

    #[test]
    fn store_and_get_basic_credential() {
        let (conn, key) = test_db();
        let mut fields = HashMap::new();
        fields.insert("username".to_string(), "admin".to_string());
        fields.insert("password".to_string(), "secret123".to_string());

        store_credential(&conn, &key, "my-service", CredentialType::Basic, &fields).unwrap();

        let (cred_type, retrieved) = get_credential_fields(&conn, &key, "my-service").unwrap();
        assert_eq!(cred_type, CredentialType::Basic);
        assert_eq!(retrieved["username"], "admin");
        assert_eq!(retrieved["password"], "secret123");
    }

    #[test]
    fn store_and_get_custom_credential() {
        let (conn, key) = test_db();
        let mut fields = HashMap::new();
        fields.insert("x-api-token".to_string(), "tok-123".to_string());
        fields.insert("cookie".to_string(), "session=abc".to_string());

        store_credential(&conn, &key, "custom-svc", CredentialType::Custom, &fields).unwrap();

        let (cred_type, retrieved) = get_credential_fields(&conn, &key, "custom-svc").unwrap();
        assert_eq!(cred_type, CredentialType::Custom);
        assert_eq!(retrieved["x-api-token"], "tok-123");
        assert_eq!(retrieved["cookie"], "session=abc");
    }

    #[test]
    fn store_and_list_shows_credential_type() {
        let (conn, key) = test_db();
        let mut fields = HashMap::new();
        fields.insert("token".to_string(), "ghp_xxx".to_string());
        store_credential(&conn, &key, "gh-token", CredentialType::Bearer, &fields).unwrap();

        let secrets = list_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].credential_type, "bearer");
    }
}
