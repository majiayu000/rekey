# rekey Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `rekey`, a single-binary Rust MITM proxy that injects API keys for AI agents so they never touch real credentials.

**Architecture:** Cargo workspace with 5 crates (cli, vault, ca, proxy, web) compiled into a single binary. SQLite stores encrypted secrets, rcgen generates TLS certs, axum/hyper handles HTTP proxy + API gateway + embedded web dashboard on a single port.

**Tech Stack:** Rust, axum, hyper, rustls, tokio-rustls, rcgen, reqwest, rusqlite, aes-gcm, argon2, secrecy, clap, rust-embed

---

## File Structure

```
~/Desktop/code/AI/tools/rekey/
├── Cargo.toml                          # workspace definition
├── crates/
│   ├── rekey-vault/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # pub mod re-exports
│   │       ├── crypto.rs               # Argon2id key derivation + AES-256-GCM encrypt/decrypt
│   │       ├── db.rs                   # SQLite schema creation + migrations
│   │       ├── secrets.rs              # CRUD for secrets table
│   │       ├── rules.rs                # CRUD for injection_rules table
│   │       ├── audit.rs                # insert + query audit_log
│   │       └── providers.rs            # predefined provider configs (anthropic, openai, github)
│   ├── rekey-ca/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # pub mod re-exports
│   │       ├── authority.rs            # CA key generation + persistence + system trust install
│   │       └── leaf.rs                 # dynamic leaf cert generation + in-memory cache
│   ├── rekey-proxy/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # pub mod re-exports
│   │       ├── server.rs               # hyper server, route CONNECT vs normal HTTP
│   │       ├── mitm.rs                 # MITM tunnel: TLS termination + header injection + forwarding
│   │       ├── tunnel.rs               # passthrough TCP tunnel for unmatched hosts
│   │       ├── gateway.rs              # /proxy/{provider}/* API gateway routes
│   │       └── inject.rs               # header injection logic shared by mitm + gateway
│   ├── rekey-web/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs                  # pub mod re-exports
│   │   │   ├── routes.rs               # axum routes: /api/secrets, /api/audit, /api/stats, /api/traffic
│   │   │   └── sse.rs                  # SSE stream for real-time traffic
│   │   └── assets/                     # static HTML + JS + CSS (embedded via rust-embed)
│   │       ├── index.html              # dashboard SPA shell
│   │       ├── app.js                  # vanilla JS dashboard logic
│   │       └── style.css               # minimal styles
│   └── rekey-cli/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                 # clap entry point, subcommand dispatch
│           ├── cmd_init.rs             # rekey init
│           ├── cmd_add.rs              # rekey add
│           ├── cmd_list.rs             # rekey list
│           ├── cmd_remove.rs           # rekey remove
│           ├── cmd_rotate.rs           # rekey rotate
│           ├── cmd_start.rs            # rekey start [-d]
│           ├── cmd_stop.rs             # rekey stop
│           ├── cmd_status.rs           # rekey status
│           ├── cmd_env.rs              # rekey env
│           ├── cmd_destroy.rs          # rekey destroy
│           └── cmd_dashboard.rs        # rekey dashboard
```

---

## Task 1: Workspace Scaffolding

**Files:**
- Create: `~/Desktop/code/AI/tools/rekey/Cargo.toml`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-vault/Cargo.toml`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-vault/src/lib.rs`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-ca/Cargo.toml`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-ca/src/lib.rs`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-proxy/Cargo.toml`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-proxy/src/lib.rs`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-web/Cargo.toml`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-web/src/lib.rs`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-cli/Cargo.toml`
- Create: `~/Desktop/code/AI/tools/rekey/crates/rekey-cli/src/main.rs`

- [ ] **Step 1: Create project directory and init git**

```bash
mkdir -p ~/Desktop/code/AI/tools/rekey
cd ~/Desktop/code/AI/tools/rekey
git init
```

- [ ] **Step 2: Create workspace Cargo.toml**

```toml
# ~/Desktop/code/AI/tools/rekey/Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/rekey-vault",
    "crates/rekey-ca",
    "crates/rekey-proxy",
    "crates/rekey-web",
    "crates/rekey-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
repository = "https://github.com/majiayu000/rekey"

[workspace.dependencies]
rekey-vault = { path = "crates/rekey-vault" }
rekey-ca = { path = "crates/rekey-ca" }
rekey-proxy = { path = "crates/rekey-proxy" }
rekey-web = { path = "crates/rekey-web" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 3: Create rekey-vault crate**

```toml
# crates/rekey-vault/Cargo.toml
[package]
name = "rekey-vault"
version.workspace = true
edition.workspace = true

[dependencies]
rusqlite = { version = "0.34", features = ["bundled"] }
aes-gcm = "0.10"
argon2 = "0.5"
secrecy = { version = "0.10", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
anyhow.workspace = true
tracing.workspace = true
serde.workspace = true
serde_json.workspace = true
rand = "0.9"
```

```rust
// crates/rekey-vault/src/lib.rs
pub mod crypto;
pub mod db;
pub mod secrets;
pub mod rules;
pub mod audit;
pub mod providers;
```

- [ ] **Step 4: Create rekey-ca crate**

```toml
# crates/rekey-ca/Cargo.toml
[package]
name = "rekey-ca"
version.workspace = true
edition.workspace = true

[dependencies]
rcgen = { version = "0.13", features = ["pem"] }
rustls = "0.23"
rustls-pki-types = "1"
anyhow.workspace = true
tracing.workspace = true
dashmap = "6"
tokio.workspace = true
```

```rust
// crates/rekey-ca/src/lib.rs
pub mod authority;
pub mod leaf;
```

- [ ] **Step 5: Create rekey-proxy crate**

```toml
# crates/rekey-proxy/Cargo.toml
[package]
name = "rekey-proxy"
version.workspace = true
edition.workspace = true

[dependencies]
rekey-vault.workspace = true
rekey-ca.workspace = true
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "server-auto"] }
http-body-util = "0.1"
tokio.workspace = true
tokio-rustls = "0.26"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream"] }
anyhow.workspace = true
tracing.workspace = true
serde.workspace = true
serde_json.workspace = true
bytes = "1"
futures-util = "0.3"
```

```rust
// crates/rekey-proxy/src/lib.rs
pub mod server;
pub mod mitm;
pub mod tunnel;
pub mod gateway;
pub mod inject;
```

- [ ] **Step 6: Create rekey-web crate**

```toml
# crates/rekey-web/Cargo.toml
[package]
name = "rekey-web"
version.workspace = true
edition.workspace = true

[dependencies]
rekey-vault.workspace = true
axum = "0.8"
tokio.workspace = true
anyhow.workspace = true
tracing.workspace = true
serde.workspace = true
serde_json.workspace = true
rust-embed = "8"
mime_guess = "2"
tokio-stream = "0.1"
```

```rust
// crates/rekey-web/src/lib.rs
pub mod routes;
pub mod sse;
```

- [ ] **Step 7: Create rekey-cli crate**

```toml
# crates/rekey-cli/Cargo.toml
[package]
name = "rekey-cli"
version.workspace = true
edition.workspace = true

[[bin]]
name = "rekey"
path = "src/main.rs"

[dependencies]
rekey-vault.workspace = true
rekey-ca.workspace = true
rekey-proxy.workspace = true
rekey-web.workspace = true
clap = { version = "4", features = ["derive"] }
tokio.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
rpassword = "7"
open = "5"
```

```rust
// crates/rekey-cli/src/main.rs
fn main() {
    println!("rekey - AI agent API key proxy");
}
```

- [ ] **Step 8: Verify workspace compiles**

Run: `cd ~/Desktop/code/AI/tools/rekey && cargo check`
Expected: compiles with no errors

- [ ] **Step 9: Create .gitignore and commit**

```gitignore
/target
.env
```

```bash
git add -A
git commit -m "feat: scaffold workspace with 5 crates"
```

---

## Task 2: Vault Crypto Layer

**Files:**
- Create: `crates/rekey-vault/src/crypto.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing test for key derivation**

```rust
// crates/rekey-vault/src/crypto.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let salt = [0u8; 16];
        let k1 = derive_master_key("password123", &salt).unwrap();
        let k2 = derive_master_key("password123", &salt).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn derive_key_different_passwords() {
        let salt = [0u8; 16];
        let k1 = derive_master_key("password1", &salt).unwrap();
        let k2 = derive_master_key("password2", &salt).unwrap();
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let salt = [0u8; 16];
        let key = derive_master_key("test", &salt).unwrap();
        let plaintext = b"sk-ant-api03-secret-key-12345";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let salt = [0u8; 16];
        let key1 = derive_master_key("right", &salt).unwrap();
        let key2 = derive_master_key("wrong", &salt).unwrap();
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rekey-vault`
Expected: FAIL — functions not defined

- [ ] **Step 3: Implement crypto module**

```rust
// crates/rekey-vault/src/crypto.rs
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore,
};
use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretVec};

/// 12-byte IV prepended to ciphertext, followed by AES-GCM output (ciphertext + 16-byte tag).
pub struct EncryptedBlob {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Derive a 256-bit master key from password + salt using Argon2id.
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<SecretVec<u8>> {
    let params = argon2::Params::new(65536, 3, 1, Some(32))
        .context("invalid argon2 params")?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?;
    Ok(SecretVec::new(key))
}

/// Encrypt plaintext with AES-256-GCM. Returns IV + ciphertext.
pub fn encrypt(key: &SecretVec<u8>, plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    Ok(EncryptedBlob {
        iv: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypt ciphertext with AES-256-GCM.
pub fn decrypt(key: &SecretVec<u8>, blob: &EncryptedBlob) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(&blob.iv);
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    // ... tests from Step 1
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rekey-vault`
Expected: 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/rekey-vault/src/crypto.rs
git commit -m "feat(vault): add AES-256-GCM encryption + Argon2id key derivation"
```

---

## Task 3: SQLite Database + Secrets CRUD

**Files:**
- Create: `crates/rekey-vault/src/db.rs`
- Create: `crates/rekey-vault/src/secrets.rs`
- Create: `crates/rekey-vault/src/rules.rs`
- Create: `crates/rekey-vault/src/providers.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing test for DB initialization + secret CRUD**

```rust
// crates/rekey-vault/src/secrets.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_master_key;
    use crate::db::init_db;

    fn test_db() -> (rusqlite::Connection, secrecy::SecretVec<u8>) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let key = derive_master_key("test", &[0u8; 16]).unwrap();
        (conn, key)
    }

    #[test]
    fn add_and_list_secret() {
        let (conn, key) = test_db();
        add_secret(&conn, &key, "anthropic", "anthropic", "sk-ant-123", "api.anthropic.com").unwrap();
        let secrets = list_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "anthropic");
        assert_eq!(secrets[0].provider, "anthropic");
        assert_eq!(secrets[0].host_pattern, "api.anthropic.com");
    }

    #[test]
    fn get_secret_value_decrypts() {
        let (conn, key) = test_db();
        add_secret(&conn, &key, "anthropic", "anthropic", "sk-ant-123", "api.anthropic.com").unwrap();
        let value = get_secret_value(&conn, &key, "anthropic").unwrap();
        assert_eq!(value, "sk-ant-123");
    }

    #[test]
    fn remove_secret() {
        let (conn, key) = test_db();
        add_secret(&conn, &key, "anthropic", "anthropic", "sk-ant-123", "api.anthropic.com").unwrap();
        remove_secret(&conn, "anthropic").unwrap();
        let secrets = list_secrets(&conn).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn rotate_secret() {
        let (conn, key) = test_db();
        add_secret(&conn, &key, "anthropic", "anthropic", "sk-ant-old", "api.anthropic.com").unwrap();
        rotate_secret(&conn, &key, "anthropic", "sk-ant-new").unwrap();
        let value = get_secret_value(&conn, &key, "anthropic").unwrap();
        assert_eq!(value, "sk-ant-new");
    }

    #[test]
    fn duplicate_name_fails() {
        let (conn, key) = test_db();
        add_secret(&conn, &key, "anthropic", "anthropic", "sk-1", "api.anthropic.com").unwrap();
        let result = add_secret(&conn, &key, "anthropic", "anthropic", "sk-2", "api.anthropic.com");
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rekey-vault`
Expected: FAIL — `init_db`, `add_secret`, etc. not defined

- [ ] **Step 3: Implement db.rs**

```rust
// crates/rekey-vault/src/db.rs
use anyhow::Result;
use rusqlite::Connection;

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS secrets (
            id          TEXT PRIMARY KEY,
            name        TEXT UNIQUE NOT NULL,
            provider    TEXT NOT NULL,
            ciphertext  BLOB NOT NULL,
            iv          BLOB NOT NULL,
            host_pattern TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
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
```

- [ ] **Step 4: Implement providers.rs**

```rust
// crates/rekey-vault/src/providers.rs
pub struct ProviderConfig {
    pub host_pattern: &'static str,
    pub header_name: &'static str,
    pub value_format: &'static str,
    pub path_pattern: &'static str,
}

pub fn get_provider(name: &str) -> Option<ProviderConfig> {
    match name {
        "anthropic" => Some(ProviderConfig {
            host_pattern: "api.anthropic.com",
            header_name: "x-api-key",
            value_format: "{value}",
            path_pattern: "*",
        }),
        "openai" => Some(ProviderConfig {
            host_pattern: "api.openai.com",
            header_name: "authorization",
            value_format: "Bearer {value}",
            path_pattern: "*",
        }),
        "github" => Some(ProviderConfig {
            host_pattern: "api.github.com",
            header_name: "authorization",
            value_format: "Bearer {value}",
            path_pattern: "*",
        }),
        _ => None,
    }
}

pub fn all_provider_names() -> &'static [&'static str] {
    &["anthropic", "openai", "github"]
}
```

- [ ] **Step 5: Implement secrets.rs**

```rust
// crates/rekey-vault/src/secrets.rs
use anyhow::{bail, Context, Result};
use rusqlite::Connection;
use secrecy::SecretVec;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{decrypt, encrypt, EncryptedBlob};
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
        .unwrap()
        .as_secs() as i64
}

pub fn add_secret(
    conn: &Connection,
    master_key: &SecretVec<u8>,
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

    // Auto-create injection rule from provider config or defaults
    if let Some(pc) = get_provider(provider) {
        add_injection_rule(conn, &id, pc.header_name, pc.value_format, pc.path_pattern, "*")?;
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

pub fn get_secret_value(
    conn: &Connection,
    master_key: &SecretVec<u8>,
    name: &str,
) -> Result<String> {
    let (ciphertext, iv): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT ciphertext, iv FROM secrets WHERE name = ?1",
        [name],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).context("secret not found")?;

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
    master_key: &SecretVec<u8>,
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
    // ... tests from Step 1
}
```

- [ ] **Step 6: Implement rules.rs**

```rust
// crates/rekey-vault/src/rules.rs
use anyhow::{Context, Result};
use rusqlite::Connection;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InjectionRule {
    pub id: String,
    pub secret_id: String,
    pub header_name: String,
    pub value_format: String,
    pub path_pattern: String,
    pub method: String,
}

pub fn add_injection_rule(
    conn: &Connection,
    secret_id: &str,
    header_name: &str,
    value_format: &str,
    path_pattern: &str,
    method: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO injection_rules (id, secret_id, header_name, value_format, path_pattern, method)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, secret_id, header_name, value_format, path_pattern, method],
    )
    .context("failed to insert injection rule")?;
    Ok(id)
}

/// Find injection rules for a given host. Joins secrets + injection_rules.
pub fn find_rules_for_host(conn: &Connection, host: &str) -> Result<Vec<(InjectionRule, String)>> {
    let mut stmt = conn.prepare(
        "SELECT r.id, r.secret_id, r.header_name, r.value_format, r.path_pattern, r.method, s.name
         FROM injection_rules r
         JOIN secrets s ON s.id = r.secret_id
         WHERE s.host_pattern = ?1 OR s.host_pattern = '*'",
    )?;
    let rows = stmt.query_map([host], |row| {
        Ok((
            InjectionRule {
                id: row.get(0)?,
                secret_id: row.get(1)?,
                header_name: row.get(2)?,
                value_format: row.get(3)?,
                path_pattern: row.get(4)?,
                method: row.get(5)?,
            },
            row.get::<_, String>(6)?, // secret_name for audit
        ))
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p rekey-vault`
Expected: all tests PASS

- [ ] **Step 8: Commit**

```bash
git add crates/rekey-vault/src/
git commit -m "feat(vault): SQLite schema + secrets CRUD + injection rules + provider presets"
```

---

## Task 4: Audit Log

**Files:**
- Create: `crates/rekey-vault/src/audit.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing test**

```rust
// crates/rekey-vault/src/audit.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::init_db;

    #[test]
    fn insert_and_query_audit() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        log_access(&conn, "anthropic", "api.anthropic.com", "/v1/messages", Some(200), Some(150), "proxy").unwrap();
        log_access(&conn, "openai", "api.openai.com", "/v1/chat/completions", Some(429), Some(50), "gateway").unwrap();

        let logs = query_audit(&conn, None, None, 100).unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].secret_name, "openai"); // most recent first
        assert_eq!(logs[1].secret_name, "anthropic");
    }

    #[test]
    fn query_audit_filter_by_provider() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        log_access(&conn, "anthropic", "api.anthropic.com", "/v1/messages", Some(200), Some(100), "proxy").unwrap();
        log_access(&conn, "openai", "api.openai.com", "/v1/chat/completions", Some(200), Some(100), "proxy").unwrap();

        let logs = query_audit(&conn, Some("anthropic"), None, 100).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].secret_name, "anthropic");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rekey-vault -- audit`
Expected: FAIL

- [ ] **Step 3: Implement audit.rs**

```rust
// crates/rekey-vault/src/audit.rs
use anyhow::Result;
use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: i64,
    pub secret_name: String,
    pub target_host: String,
    pub target_path: String,
    pub status_code: Option<i32>,
    pub latency_ms: Option<i64>,
    pub source: String,
}

pub fn log_access(
    conn: &Connection,
    secret_name: &str,
    target_host: &str,
    target_path: &str,
    status_code: Option<i32>,
    latency_ms: Option<i64>,
    source: &str,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    conn.execute(
        "INSERT INTO audit_log (timestamp, secret_name, target_host, target_path, status_code, latency_ms, source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![now, secret_name, target_host, target_path, status_code, latency_ms, source],
    )?;
    Ok(())
}

pub fn query_audit(
    conn: &Connection,
    secret_name_filter: Option<&str>,
    since: Option<i64>,
    limit: u32,
) -> Result<Vec<AuditEntry>> {
    let mut sql = String::from(
        "SELECT id, timestamp, secret_name, target_host, target_path, status_code, latency_ms, source
         FROM audit_log WHERE 1=1",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(name) = secret_name_filter {
        sql.push_str(" AND secret_name = ?");
        params.push(Box::new(name.to_string()));
    }
    if let Some(ts) = since {
        sql.push_str(" AND timestamp >= ?");
        params.push(Box::new(ts));
    }
    sql.push_str(" ORDER BY timestamp DESC LIMIT ?");
    params.push(Box::new(limit));

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            secret_name: row.get(2)?,
            target_host: row.get(3)?,
            target_path: row.get(4)?,
            status_code: row.get(5)?,
            latency_ms: row.get(6)?,
            source: row.get(7)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    // ... tests from Step 1
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rekey-vault`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/rekey-vault/src/audit.rs
git commit -m "feat(vault): audit log insert + query with filters"
```

---

## Task 5: CA Generation + System Trust

**Files:**
- Create: `crates/rekey-ca/src/authority.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing test**

```rust
// crates/rekey-ca/src/authority.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn generate_ca_creates_files() {
        let dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate(dir.path()).unwrap();
        assert!(dir.path().join("ca.key").exists());
        assert!(dir.path().join("ca.pem").exists());
        assert!(!ca.ca_cert_pem().is_empty());
    }

    #[test]
    fn load_existing_ca() {
        let dir = TempDir::new().unwrap();
        let ca1 = CertificateAuthority::generate(dir.path()).unwrap();
        let ca2 = CertificateAuthority::load(dir.path()).unwrap();
        assert_eq!(ca1.ca_cert_pem(), ca2.ca_cert_pem());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rekey-ca`
Expected: FAIL

- [ ] **Step 3: Add tempfile dev-dependency**

Add to `crates/rekey-ca/Cargo.toml`:
```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 4: Implement authority.rs**

```rust
// crates/rekey-ca/src/authority.rs
use anyhow::{Context, Result};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    BasicConstraints, KeyUsagePurpose,
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
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "rekey Local CA");
        dn.push(DnType::OrganizationName, "rekey");
        params.distinguished_name = dn;
        // 10-year validity
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);

        let cert = params
            .self_signed(&key_pair)
            .context("failed to self-sign CA cert")?;

        let cert_pem = cert.pem();
        let cert_der = cert.der().to_vec();
        let key_pem = key_pair.serialize_pem();

        // Write key with restrictive permissions
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
        let cert_pem = fs::read_to_string(base_dir.join("ca.pem"))
            .context("CA cert not found")?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .context("failed to parse CA key")?;

        // Parse PEM to get DER
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
        let pem_path = self.base_dir.join("ca.pem");
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("security")
                .args(["remove-trusted-cert", "-d"])
                .arg(&pem_path)
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            let dest = Path::new("/usr/local/share/ca-certificates/rekey-ca.crt");
            let _ = fs::remove_file(dest);
            let _ = std::process::Command::new("update-ca-certificates").status();
        }
        Ok(())
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let pem = pem.trim();
    let b64: String = pem
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
    // ... tests from Step 1
}
```

Add `base64 = "0.22"` to rekey-ca's Cargo.toml dependencies.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rekey-ca`
Expected: 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add crates/rekey-ca/
git commit -m "feat(ca): CA generation, persistence, system trust install/remove"
```

---

## Task 6: Leaf Certificate Generation + Cache

**Files:**
- Create: `crates/rekey-ca/src/leaf.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing test**

```rust
// crates/rekey-ca/src/leaf.rs
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
        let cert_der = cache.get_or_create("api.anthropic.com", &ca).unwrap();
        assert!(!cert_der.cert_der.is_empty());
        assert!(!cert_der.key_der.is_empty());
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rekey-ca -- leaf`
Expected: FAIL

- [ ] **Step 3: Implement leaf.rs**

```rust
// crates/rekey-ca/src/leaf.rs
use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, SanType};
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
        self.created_at.elapsed() > Duration::from_secs(23 * 3600) // refresh 1h before 24h expiry
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
    dn.push(DnType::CommonName, DnValue::PrintableString(hostname.into()));
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(hostname.try_into()?)];
    // 24h validity
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2034, 1, 1);

    let ca_cert_params = CertificateParams::from_ca_cert_der(ca.ca_cert_der())
        .context("failed to parse CA cert")?;
    let ca_cert = ca_cert_params
        .self_signed(ca.key_pair())
        .context("failed to reconstruct CA cert for signing")?;

    let leaf_cert = params
        .signed_by(&leaf_key, &ca_cert, ca.key_pair())
        .context("failed to sign leaf cert")?;

    Ok(LeafCert {
        cert_der: leaf_cert.der().to_vec(),
        key_der: leaf_key.serialize_der().to_vec(),
        created_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    // ... tests from Step 1
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rekey-ca`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/rekey-ca/src/leaf.rs
git commit -m "feat(ca): leaf cert generation with DashMap cache"
```

---

## Task 7: Header Injection Logic

**Files:**
- Create: `crates/rekey-proxy/src/inject.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing test**

```rust
// crates/rekey-proxy/src/inject.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_value_simple() {
        assert_eq!(format_header_value("{value}", "sk-ant-123"), "sk-ant-123");
    }

    #[test]
    fn format_value_bearer() {
        assert_eq!(
            format_header_value("Bearer {value}", "sk-proj-456"),
            "Bearer sk-proj-456"
        );
    }

    #[test]
    fn inject_replaces_existing_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-key", "REKEY_PLACEHOLDER".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        inject_header(&mut headers, "x-api-key", "sk-ant-real");

        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-real");
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn inject_adds_missing_header() {
        let mut headers = http::HeaderMap::new();
        inject_header(&mut headers, "authorization", "Bearer sk-real");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-real");
    }

    #[test]
    fn path_matches_wildcard() {
        assert!(path_matches("*", "/v1/messages"));
        assert!(path_matches("/v1/*", "/v1/messages"));
        assert!(path_matches("/v1/*", "/v1/chat/completions"));
        assert!(!path_matches("/v2/*", "/v1/messages"));
        assert!(path_matches("/v1/messages", "/v1/messages"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rekey-proxy -- inject`
Expected: FAIL

- [ ] **Step 3: Add http dependency to rekey-proxy**

Add to `crates/rekey-proxy/Cargo.toml`:
```toml
http = "1"
```

- [ ] **Step 4: Implement inject.rs**

```rust
// crates/rekey-proxy/src/inject.rs
use http::HeaderMap;

/// Replace `{value}` in format string with the actual secret.
pub fn format_header_value(format: &str, secret: &str) -> String {
    format.replace("{value}", secret)
}

/// Set or replace a header in the map.
pub fn inject_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let Ok(header_name) = name.parse::<http::header::HeaderName>() {
        if let Ok(header_value) = value.parse::<http::header::HeaderValue>() {
            headers.insert(header_name, header_value);
        }
    }
}

/// Check if a request path matches a pattern.
/// Supports: "*" (match all), "/prefix/*" (prefix match), exact match.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix);
    }
    pattern == path
}

#[cfg(test)]
mod tests {
    // ... tests from Step 1
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rekey-proxy -- inject`
Expected: 5 tests PASS

- [ ] **Step 6: Commit**

```bash
git add crates/rekey-proxy/src/inject.rs crates/rekey-proxy/Cargo.toml
git commit -m "feat(proxy): header injection + path matching logic"
```

---

## Task 8: TCP Tunnel (Passthrough)

**Files:**
- Create: `crates/rekey-proxy/src/tunnel.rs`

- [ ] **Step 1: Implement tunnel.rs**

```rust
// crates/rekey-proxy/src/tunnel.rs
use anyhow::Result;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

/// Plain TCP tunnel — no MITM, no inspection. Used for unmatched hosts.
pub async fn tunnel_passthrough(
    mut client: tokio::io::DuplexStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let addr = format!("{host}:{port}");
    let mut upstream = TcpStream::connect(&addr).await?;
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
```

Note: The actual integration will use `hyper::upgrade::on` to get the upgraded connection, then split it. This is the core logic; wiring happens in Task 10 (server.rs).

- [ ] **Step 2: Verify compilation**

Run: `cargo check -p rekey-proxy`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add crates/rekey-proxy/src/tunnel.rs
git commit -m "feat(proxy): TCP tunnel passthrough for unmatched hosts"
```

---

## Task 9: MITM Core

**Files:**
- Create: `crates/rekey-proxy/src/mitm.rs`

- [ ] **Step 1: Implement mitm.rs**

```rust
// crates/rekey-proxy/src/mitm.rs
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use rekey_ca::{authority::CertificateAuthority, leaf::LeafCertCache};
use rekey_vault::rules::InjectionRule;
use rustls::ServerConfig;
use secrecy::SecretVec;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::inject::{format_header_value, inject_header, path_matches};

/// Perform MITM on an upgraded connection:
/// 1. TLS handshake with client using leaf cert
/// 2. Read plaintext HTTP request
/// 3. Inject secret into headers
/// 4. Forward to real server
/// 5. Stream response back
pub async fn mitm_intercept<S>(
    stream: S,
    hostname: &str,
    port: u16,
    ca: &CertificateAuthority,
    leaf_cache: &LeafCertCache,
    rules: &[(InjectionRule, String)],
    master_key: &SecretVec<u8>,
    db_path: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let start = Instant::now();

    // 1. Generate leaf cert and build TLS config
    let leaf = leaf_cache.get_or_create(hostname, ca)?;
    let cert_chain = vec![rustls_pki_types::CertificateDer::from(leaf.cert_der.clone())];
    let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key_der.clone())
        .map_err(|e| anyhow::anyhow!("invalid leaf key: {e}"))?;

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("TLS config failed")?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    // 2. TLS handshake with client
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let tls_stream = acceptor.accept(stream).await.context("TLS handshake failed")?;

    // 3. Read HTTP request from client over TLS
    let (reader, writer) = tokio::io::split(tls_stream);
    let io = hyper_util::rt::TokioIo::new(tokio::io::join(reader, writer));

    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let hostname = hostname.to_string();
        let port = port;
        let rules = rules.to_vec();
        let master_key_clone = master_key.clone();
        let db_path = db_path.to_string();
        let start = start;

        async move {
            handle_mitm_request(req, &hostname, port, &rules, &master_key_clone, &db_path, start).await
        }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await
        .context("HTTP/1.1 serve failed")?;

    Ok(())
}

async fn handle_mitm_request(
    mut req: hyper::Request<hyper::body::Incoming>,
    hostname: &str,
    port: u16,
    rules: &[(InjectionRule, String)],
    master_key: &SecretVec<u8>,
    db_path: &str,
    start: Instant,
) -> Result<hyper::Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    // 4. Inject headers based on matching rules
    for (rule, _secret_name) in rules {
        if !path_matches(&rule.path_pattern, &path) {
            continue;
        }
        // Decrypt the secret value
        let conn = rusqlite::Connection::open(db_path).unwrap();
        let secret_value = rekey_vault::secrets::get_secret_value_by_id(&conn, master_key, &rule.secret_id)
            .unwrap_or_default();
        let formatted = format_header_value(&rule.value_format, &secret_value);
        inject_header(req.headers_mut(), &rule.header_name, &formatted);
    }

    // 5. Forward to real server
    let scheme = if port == 443 { "https" } else { "http" };
    let url = format!("{scheme}://{hostname}{path}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let method = match *req.method() {
        hyper::Method::GET => reqwest::Method::GET,
        hyper::Method::POST => reqwest::Method::POST,
        hyper::Method::PUT => reqwest::Method::PUT,
        hyper::Method::DELETE => reqwest::Method::DELETE,
        hyper::Method::PATCH => reqwest::Method::PATCH,
        _ => reqwest::Method::GET,
    };

    let body_bytes = req.collect().await.unwrap().to_bytes();
    let mut forward = client.request(method, &url);

    // Copy headers (skip hop-by-hop)
    for (name, value) in req.headers() {
        let n = name.as_str();
        if n == "host" || n == "connection" || n == "proxy-authorization" || n == "transfer-encoding" {
            continue;
        }
        forward = forward.header(n, value.as_bytes());
    }
    forward = forward.header("host", hostname);
    forward = forward.body(body_bytes.to_vec());

    let resp = forward.send().await.unwrap();
    let status = resp.status().as_u16();

    // 6. Audit log
    let latency = start.elapsed().as_millis() as i64;
    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        for (_rule, secret_name) in rules {
            let _ = rekey_vault::audit::log_access(
                &conn,
                secret_name,
                hostname,
                &path,
                Some(status as i32),
                Some(latency),
                "proxy",
            );
        }
    }

    // 7. Build response to send back to client
    let resp_status = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    let resp_bytes = resp.bytes().await.unwrap();

    Ok(hyper::Response::builder()
        .status(resp_status)
        .body(Full::new(resp_bytes))
        .unwrap())
}
```

Note: This is a working first pass. Streaming response support (SSE) will be refined in a later task. The `get_secret_value_by_id` function needs to be added to `secrets.rs`.

- [ ] **Step 2: Add `get_secret_value_by_id` to secrets.rs**

Add to `crates/rekey-vault/src/secrets.rs`:

```rust
pub fn get_secret_value_by_id(
    conn: &Connection,
    master_key: &SecretVec<u8>,
    secret_id: &str,
) -> Result<String> {
    let (ciphertext, iv): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT ciphertext, iv FROM secrets WHERE id = ?1",
        [secret_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).context("secret not found")?;

    let blob = EncryptedBlob { iv, ciphertext };
    let plaintext = decrypt(master_key, &blob)?;
    String::from_utf8(plaintext).context("secret is not valid UTF-8")
}
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p rekey-proxy`
Expected: compiles (may have warnings)

- [ ] **Step 4: Commit**

```bash
git add crates/rekey-proxy/src/mitm.rs crates/rekey-vault/src/secrets.rs
git commit -m "feat(proxy): MITM intercept core — TLS termination + header injection + forwarding"
```

---

## Task 10: Proxy Server (CONNECT routing)

**Files:**
- Create: `crates/rekey-proxy/src/server.rs`

- [ ] **Step 1: Implement server.rs**

```rust
// crates/rekey-proxy/src/server.rs
use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper::body::Incoming;
use http_body_util::Full;
use bytes::Bytes;
use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use secrecy::SecretVec;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct ProxyServer {
    ca: Arc<CertificateAuthority>,
    leaf_cache: Arc<LeafCertCache>,
    master_key: Arc<SecretVec<u8>>,
    db_path: String,
    addr: SocketAddr,
}

impl ProxyServer {
    pub fn new(
        ca: CertificateAuthority,
        master_key: SecretVec<u8>,
        db_path: String,
        port: u16,
    ) -> Self {
        Self {
            ca: Arc::new(ca),
            leaf_cache: Arc::new(LeafCertCache::new()),
            master_key: Arc::new(master_key),
            db_path,
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!("rekey proxy listening on {}", self.addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let ca = self.ca.clone();
            let leaf_cache = self.leaf_cache.clone();
            let master_key = self.master_key.clone();
            let db_path = self.db_path.clone();

            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);

                let service = service_fn(move |req: Request<Incoming>| {
                    let ca = ca.clone();
                    let leaf_cache = leaf_cache.clone();
                    let master_key = master_key.clone();
                    let db_path = db_path.clone();

                    async move {
                        if req.method() == Method::CONNECT {
                            handle_connect(req, ca, leaf_cache, master_key, db_path).await
                        } else {
                            handle_http(req, master_key, db_path).await
                        }
                    }
                });

                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::error!("connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    leaf_cache: Arc<LeafCertCache>,
    master_key: Arc<SecretVec<u8>>,
    db_path: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host_port = req.uri().authority().map(|a| a.as_str()).unwrap_or("");
    let (hostname, port) = parse_host_port(host_port);

    tracing::debug!("CONNECT {hostname}:{port}");

    // Check if we have rules for this host
    let has_rules = if let Ok(conn) = rusqlite::Connection::open(&db_path) {
        rekey_vault::rules::find_rules_for_host(&conn, &hostname)
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    } else {
        false
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = hyper_util::rt::TokioIo::new(upgraded);
                let (reader, writer) = tokio::io::split(io);
                let stream = tokio::io::join(reader, writer);

                if has_rules {
                    let conn = rusqlite::Connection::open(&db_path).unwrap();
                    let rules = rekey_vault::rules::find_rules_for_host(&conn, &hostname).unwrap();
                    if let Err(e) = crate::mitm::mitm_intercept(
                        stream, &hostname, port, &ca, &leaf_cache, &rules, &master_key, &db_path,
                    ).await {
                        tracing::error!("MITM error for {hostname}: {e}");
                    }
                } else {
                    // Pure TCP tunnel
                    let mut upstream = match tokio::net::TcpStream::connect(format!("{hostname}:{port}")).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("tunnel connect failed for {hostname}:{port}: {e}");
                            return;
                        }
                    };
                    let mut io_rw = hyper_util::rt::TokioIo::new(stream);
                    let _ = tokio::io::copy_bidirectional(&mut io_rw, &mut upstream).await;
                }
            }
            Err(e) => tracing::error!("upgrade failed: {e}"),
        }
    });

    Ok(Response::new(Full::new(Bytes::new())))
}

async fn handle_http(
    req: Request<Incoming>,
    master_key: Arc<SecretVec<u8>>,
    db_path: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    // Route /proxy/* to API gateway
    if path.starts_with("/proxy/") {
        return crate::gateway::handle_gateway_request(req, &master_key, &db_path).await;
    }

    // Route /dashboard and /api/* to web UI
    if path.starts_with("/dashboard") || path.starts_with("/api/") {
        return Ok(Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("dashboard placeholder")))
            .unwrap());
    }

    Ok(Response::builder()
        .status(404)
        .body(Full::new(Bytes::from("not found")))
        .unwrap())
}

fn parse_host_port(authority: &str) -> (String, u16) {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443)
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check -p rekey-proxy`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add crates/rekey-proxy/src/server.rs
git commit -m "feat(proxy): server with CONNECT routing — MITM or tunnel based on host match"
```

---

## Task 11: API Gateway

**Files:**
- Create: `crates/rekey-proxy/src/gateway.rs`

- [ ] **Step 1: Implement gateway.rs**

```rust
// crates/rekey-proxy/src/gateway.rs
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use secrecy::SecretVec;
use std::time::Instant;

use crate::inject::{format_header_value, path_matches};

/// Handle /proxy/{provider}/{path...}
/// Example: POST /proxy/anthropic/v1/messages
pub async fn handle_gateway_request(
    req: Request<Incoming>,
    master_key: &SecretVec<u8>,
    db_path: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let start = Instant::now();

    // Parse: /proxy/{provider}/{rest...}
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    // parts = ["", "proxy", "anthropic", "v1/messages"]
    if parts.len() < 4 {
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("usage: /proxy/{provider}/{path}")))
            .unwrap());
    }

    let provider_name = parts[2];
    let api_path = format!("/{}", parts[3]);

    // Look up provider config
    let provider = match rekey_vault::providers::get_provider(provider_name) {
        Some(p) => p,
        None => {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from(format!("unknown provider: {provider_name}"))))
                .unwrap());
        }
    };

    // Get secret value
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Response::builder()
                .status(500)
                .body(Full::new(Bytes::from(format!("db error: {e}"))))
                .unwrap());
        }
    };

    let secret_value = match rekey_vault::secrets::get_secret_value(&conn, master_key, provider_name) {
        Ok(v) => v,
        Err(e) => {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from(format!("secret not found: {e}"))))
                .unwrap());
        }
    };

    // Build forwarding request
    let url = format!("https://{}{api_path}", provider.host_pattern);
    let formatted_value = format_header_value(provider.value_format, &secret_value);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let method = match *req.method() {
        hyper::Method::GET => reqwest::Method::GET,
        hyper::Method::POST => reqwest::Method::POST,
        hyper::Method::PUT => reqwest::Method::PUT,
        hyper::Method::DELETE => reqwest::Method::DELETE,
        hyper::Method::PATCH => reqwest::Method::PATCH,
        _ => reqwest::Method::GET,
    };

    let body_bytes = req.collect().await.unwrap().to_bytes();
    let mut forward = client.request(method, &url);

    // Copy headers (skip hop-by-hop and proxy-specific)
    for (name, value) in req.headers() {
        let n = name.as_str();
        if n == "host" || n == "connection" || n == "transfer-encoding" {
            continue;
        }
        forward = forward.header(n, value.as_bytes());
    }

    // Inject the real key
    forward = forward.header(provider.header_name, &formatted_value);
    forward = forward.header("host", provider.host_pattern);
    forward = forward.body(body_bytes.to_vec());

    let resp = match forward.send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("upstream error: {e}"))))
                .unwrap());
        }
    };

    let status = resp.status().as_u16();
    let latency = start.elapsed().as_millis() as i64;

    // Audit log
    let _ = rekey_vault::audit::log_access(
        &conn,
        provider_name,
        provider.host_pattern,
        &api_path,
        Some(status as i32),
        Some(latency),
        "gateway",
    );

    let resp_status = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    let resp_bytes = resp.bytes().await.unwrap_or_default();

    Ok(Response::builder()
        .status(resp_status)
        .body(Full::new(resp_bytes))
        .unwrap())
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check -p rekey-proxy`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add crates/rekey-proxy/src/gateway.rs
git commit -m "feat(proxy): API gateway — /proxy/{provider}/* with key injection"
```

---

## Task 12: CLI Commands

**Files:**
- Create: all `cmd_*.rs` files in `crates/rekey-cli/src/`
- Modify: `crates/rekey-cli/src/main.rs`

- [ ] **Step 1: Implement main.rs with clap**

```rust
// crates/rekey-cli/src/main.rs
mod cmd_init;
mod cmd_add;
mod cmd_list;
mod cmd_remove;
mod cmd_rotate;
mod cmd_start;
mod cmd_stop;
mod cmd_status;
mod cmd_env;
mod cmd_destroy;
mod cmd_dashboard;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rekey", about = "AI agent API key proxy", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize rekey: set password, generate CA, create vault
    Init,
    /// Add a secret
    Add {
        /// Provider name (anthropic, openai, github) or arbitrary name
        name: String,
        /// Secret value (API key)
        value: String,
        /// Host pattern (required for generic provider)
        #[arg(long)]
        host: Option<String>,
        /// Header name (required for generic provider)
        #[arg(long)]
        header: Option<String>,
    },
    /// List all secrets
    List,
    /// Remove a secret
    Remove {
        /// Secret name
        name: String,
    },
    /// Rotate a secret value
    Rotate {
        /// Secret name
        name: String,
        /// New secret value
        value: String,
    },
    /// Start the proxy
    Start {
        /// Run as daemon
        #[arg(short, long)]
        daemon: bool,
        /// Port to listen on
        #[arg(short, long, default_value = "10800")]
        port: u16,
    },
    /// Stop the proxy daemon
    Stop,
    /// Show proxy status
    Status,
    /// Print environment variables for agent configuration
    Env,
    /// Open web dashboard
    Dashboard,
    /// Remove all rekey data and CA from system
    Destroy,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rekey=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init::run()?,
        Commands::Add { name, value, host, header } => cmd_add::run(&name, &value, host.as_deref(), header.as_deref())?,
        Commands::List => cmd_list::run()?,
        Commands::Remove { name } => cmd_remove::run(&name)?,
        Commands::Rotate { name, value } => cmd_rotate::run(&name, &value)?,
        Commands::Start { daemon, port } => cmd_start::run(daemon, port)?,
        Commands::Stop => cmd_stop::run()?,
        Commands::Status => cmd_status::run()?,
        Commands::Env => cmd_env::run()?,
        Commands::Dashboard => cmd_dashboard::run()?,
        Commands::Destroy => cmd_destroy::run()?,
    }

    Ok(())
}
```

- [ ] **Step 2: Implement shared helpers — rekey_dir() and prompt_password()**

```rust
// crates/rekey-cli/src/cmd_init.rs (also used by others)
use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn rekey_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".rekey")
}

pub fn db_path() -> PathBuf {
    rekey_dir().join("vault.db")
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("failed to read password")
}

pub fn open_vault() -> Result<(rusqlite::Connection, secrecy::SecretVec<u8>)> {
    let path = db_path();
    if !path.exists() {
        anyhow::bail!("vault not found — run `rekey init` first");
    }
    let conn = rusqlite::Connection::open(&path)?;
    let password = prompt_password("Master password: ")?;

    // Read salt from config table
    let salt: Vec<u8> = conn.query_row(
        "SELECT value FROM config WHERE key = 'salt'",
        [],
        |row| row.get(0),
    ).context("salt not found in vault")?;

    let master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;
    Ok((conn, master_key))
}
```

- [ ] **Step 3: Implement cmd_init.rs**

```rust
// crates/rekey-cli/src/cmd_init.rs
use anyhow::{bail, Result};
use std::fs;

// ... rekey_dir, db_path, prompt_password, open_vault from Step 2 above ...

pub fn run() -> Result<()> {
    let dir = rekey_dir();
    if db_path().exists() {
        bail!("rekey already initialized at {}", dir.display());
    }

    fs::create_dir_all(&dir)?;

    // 1. Set master password
    let password = prompt_password("Set master password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        bail!("passwords don't match");
    }

    // 2. Generate salt and derive key
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut salt);

    let _master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;

    // 3. Create database
    let conn = rusqlite::Connection::open(db_path())?;
    rekey_vault::db::init_db(&conn)?;
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('salt', ?1)",
        [salt.as_slice()],
    )?;

    // 4. Generate CA
    let ca = rekey_ca::authority::CertificateAuthority::generate(&dir)?;

    // 5. Install to system trust store
    println!("Installing CA certificate to system trust store...");
    ca.install_to_system()?;

    println!("rekey initialized at {}", dir.display());
    println!("CA certificate: {}/ca.pem", dir.display());
    println!("\nAdd your first secret: rekey add anthropic <your-api-key>");

    Ok(())
}
```

- [ ] **Step 4: Implement remaining cmd files (stub implementations)**

Each of these is a short file. Create them all:

```rust
// cmd_add.rs
use anyhow::{bail, Result};
use super::cmd_init::{open_vault, db_path};

pub fn run(name: &str, value: &str, host: Option<&str>, header: Option<&str>) -> Result<()> {
    let (conn, master_key) = open_vault()?;
    let provider = rekey_vault::providers::get_provider(name);
    let host_pattern = match (host, &provider) {
        (Some(h), _) => h.to_string(),
        (None, Some(p)) => p.host_pattern.to_string(),
        (None, None) => bail!("--host required for generic provider"),
    };
    let provider_name = if provider.is_some() { name } else { "generic" };
    rekey_vault::secrets::add_secret(&conn, &master_key, name, provider_name, value, &host_pattern)?;

    // For generic provider, add custom injection rule
    if provider.is_none() {
        let header = header.unwrap_or("authorization");
        let secret_id = conn.query_row("SELECT id FROM secrets WHERE name = ?1", [name], |r| r.get::<_, String>(0))?;
        rekey_vault::rules::add_injection_rule(&conn, &secret_id, header, "{value}", "*", "*")?;
    }

    println!("Added secret: {name} -> {host_pattern}");
    Ok(())
}
```

```rust
// cmd_list.rs
use anyhow::Result;
use super::cmd_init::db_path;

pub fn run() -> Result<()> {
    let conn = rusqlite::Connection::open(db_path())?;
    rekey_vault::db::init_db(&conn)?;
    let secrets = rekey_vault::secrets::list_secrets(&conn)?;
    if secrets.is_empty() {
        println!("No secrets configured. Run: rekey add <provider> <key>");
        return Ok(());
    }
    println!("{:<15} {:<12} {:<30}", "NAME", "PROVIDER", "HOST");
    println!("{}", "-".repeat(57));
    for s in &secrets {
        println!("{:<15} {:<12} {:<30}", s.name, s.provider, s.host_pattern);
    }
    Ok(())
}
```

```rust
// cmd_remove.rs
use anyhow::Result;
use super::cmd_init::open_vault;

pub fn run(name: &str) -> Result<()> {
    let (conn, _) = open_vault()?;
    rekey_vault::secrets::remove_secret(&conn, name)?;
    println!("Removed secret: {name}");
    Ok(())
}
```

```rust
// cmd_rotate.rs
use anyhow::Result;
use super::cmd_init::open_vault;

pub fn run(name: &str, new_value: &str) -> Result<()> {
    let (conn, master_key) = open_vault()?;
    rekey_vault::secrets::rotate_secret(&conn, &master_key, name, new_value)?;
    println!("Rotated secret: {name}");
    Ok(())
}
```

```rust
// cmd_start.rs
use anyhow::Result;
use super::cmd_init::{rekey_dir, db_path, prompt_password};

pub fn run(daemon: bool, port: u16) -> Result<()> {
    let dir = rekey_dir();
    let ca = rekey_ca::authority::CertificateAuthority::load(&dir)?;
    let password = prompt_password("Master password: ")?;

    let conn = rusqlite::Connection::open(db_path())?;
    let salt: Vec<u8> = conn.query_row("SELECT value FROM config WHERE key = 'salt'", [], |r| r.get(0))?;
    let master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;
    drop(conn);

    if daemon {
        println!("Daemon mode not yet implemented — running in foreground");
    }

    println!("rekey proxy starting on 127.0.0.1:{port}");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let server = rekey_proxy::server::ProxyServer::new(
            ca,
            master_key,
            db_path().to_string_lossy().to_string(),
            port,
        );
        server.run().await
    })
}
```

```rust
// cmd_stop.rs
use anyhow::Result;

pub fn run() -> Result<()> {
    println!("Stop not yet implemented (daemon mode pending)");
    Ok(())
}
```

```rust
// cmd_status.rs
use anyhow::Result;

pub fn run() -> Result<()> {
    println!("Status not yet implemented (daemon mode pending)");
    Ok(())
}
```

```rust
// cmd_env.rs
use anyhow::Result;
use super::cmd_init::db_path;

pub fn run() -> Result<()> {
    let conn = rusqlite::Connection::open(db_path())?;
    rekey_vault::db::init_db(&conn)?;
    let secrets = rekey_vault::secrets::list_secrets(&conn)?;

    println!("export HTTPS_PROXY=http://localhost:10800");
    println!("export HTTP_PROXY=http://localhost:10800");
    for s in &secrets {
        let env_name = match s.provider.as_str() {
            "anthropic" => "ANTHROPIC_API_KEY",
            "openai" => "OPENAI_API_KEY",
            "github" => "GITHUB_TOKEN",
            _ => continue,
        };
        println!("export {env_name}=REKEY_PLACEHOLDER");
    }
    Ok(())
}
```

```rust
// cmd_dashboard.rs
use anyhow::Result;

pub fn run() -> Result<()> {
    let url = "http://localhost:10800/dashboard";
    println!("Opening {url}");
    open::that(url)?;
    Ok(())
}
```

```rust
// cmd_destroy.rs
use anyhow::Result;
use super::cmd_init::rekey_dir;
use std::fs;

pub fn run() -> Result<()> {
    let dir = rekey_dir();
    if !dir.exists() {
        println!("Nothing to destroy");
        return Ok(());
    }

    // Remove CA from system trust store
    if let Ok(ca) = rekey_ca::authority::CertificateAuthority::load(&dir) {
        let _ = ca.remove_from_system();
    }

    fs::remove_dir_all(&dir)?;
    println!("All rekey data removed from {}", dir.display());
    Ok(())
}
```

- [ ] **Step 5: Add `dirs` and `rand` dependencies to rekey-cli**

Add to `crates/rekey-cli/Cargo.toml`:
```toml
dirs = "6"
rand = "0.9"
rusqlite = { version = "0.34", features = ["bundled"] }
```

- [ ] **Step 6: Verify full workspace compiles**

Run: `cargo check --workspace`
Expected: compiles

- [ ] **Step 7: Commit**

```bash
git add crates/rekey-cli/
git commit -m "feat(cli): all CLI commands — init, add, list, remove, rotate, start, env, destroy"
```

---

## Task 13: Web Dashboard — Backend API

**Files:**
- Create: `crates/rekey-web/src/routes.rs`
- Create: `crates/rekey-web/src/sse.rs`

- [ ] **Step 1: Implement routes.rs**

```rust
// crates/rekey-web/src/routes.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::{Json, IntoResponse},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct WebState {
    pub db_path: String,
}

pub fn api_router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/api/secrets", get(list_secrets))
        .route("/api/audit", get(list_audit))
        .route("/api/stats", get(get_stats))
        .with_state(state)
}

async fn list_secrets(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let conn = match rusqlite::Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    };
    match rekey_vault::secrets::list_secrets(&conn) {
        Ok(secrets) => (StatusCode::OK, Json(json!(secrets))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

async fn list_audit(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let conn = match rusqlite::Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    };
    match rekey_vault::audit::query_audit(&conn, None, None, 200) {
        Ok(logs) => (StatusCode::OK, Json(json!(logs))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

async fn get_stats(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let conn = match rusqlite::Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    };

    let today_start = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        now - (now % 86400)
    };

    let total_today: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1",
            [today_start],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let errors_today: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1 AND (status_code >= 400 OR status_code IS NULL)",
            [today_start],
            |r| r.get(0),
        )
        .unwrap_or(0);

    (StatusCode::OK, Json(json!({
        "today_requests": total_today,
        "today_errors": errors_today,
    })))
}
```

- [ ] **Step 2: Implement sse.rs (placeholder)**

```rust
// crates/rekey-web/src/sse.rs
// SSE for real-time traffic will be wired in a follow-up iteration.
// The broadcast channel pattern: proxy writes to sender, SSE endpoint reads from receiver.
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p rekey-web`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add crates/rekey-web/src/
git commit -m "feat(web): dashboard API routes — /api/secrets, /api/audit, /api/stats"
```

---

## Task 14: Web Dashboard — Frontend

**Files:**
- Create: `crates/rekey-web/assets/index.html`
- Create: `crates/rekey-web/assets/app.js`
- Create: `crates/rekey-web/assets/style.css`

- [ ] **Step 1: Create index.html**

```html
<!-- crates/rekey-web/assets/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>rekey dashboard</title>
  <link rel="stylesheet" href="/dashboard/style.css">
</head>
<body>
  <header>
    <h1>rekey</h1>
    <nav>
      <button data-tab="secrets" class="active">Secrets</button>
      <button data-tab="traffic">Traffic</button>
      <button data-tab="audit">Audit Log</button>
    </nav>
  </header>

  <main>
    <section id="secrets" class="tab active">
      <h2>Secrets</h2>
      <table id="secrets-table">
        <thead><tr><th>Name</th><th>Provider</th><th>Host</th><th>Created</th></tr></thead>
        <tbody></tbody>
      </table>
    </section>

    <section id="traffic" class="tab">
      <h2>Traffic Monitor</h2>
      <div id="stats"></div>
      <table id="traffic-table">
        <thead><tr><th>Time</th><th>Host</th><th>Path</th><th>Secret</th><th>Status</th><th>Latency</th></tr></thead>
        <tbody></tbody>
      </table>
    </section>

    <section id="audit" class="tab">
      <h2>Audit Log</h2>
      <table id="audit-table">
        <thead><tr><th>Time</th><th>Secret</th><th>Host</th><th>Path</th><th>Status</th><th>Source</th></tr></thead>
        <tbody></tbody>
      </table>
    </section>
  </main>

  <script src="/dashboard/app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create app.js**

```javascript
// crates/rekey-web/assets/app.js
document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');

    if (btn.dataset.tab === 'secrets') loadSecrets();
    if (btn.dataset.tab === 'audit') loadAudit();
    if (btn.dataset.tab === 'traffic') loadStats();
  });
});

async function loadSecrets() {
  const resp = await fetch('/api/secrets');
  const data = await resp.json();
  const tbody = document.querySelector('#secrets-table tbody');
  tbody.innerHTML = data.map(s =>
    `<tr><td>${s.name}</td><td>${s.provider}</td><td>${s.host_pattern}</td><td>${new Date(s.created_at * 1000).toLocaleDateString()}</td></tr>`
  ).join('');
}

async function loadAudit() {
  const resp = await fetch('/api/audit');
  const data = await resp.json();
  const tbody = document.querySelector('#audit-table tbody');
  tbody.innerHTML = data.map(a =>
    `<tr><td>${new Date(a.timestamp * 1000).toLocaleTimeString()}</td><td>${a.secret_name}</td><td>${a.target_host}</td><td>${a.target_path}</td><td>${a.status_code || '-'}</td><td>${a.source}</td></tr>`
  ).join('');
}

async function loadStats() {
  const resp = await fetch('/api/stats');
  const data = await resp.json();
  document.getElementById('stats').innerHTML =
    `<p>Today: ${data.today_requests} requests, ${data.today_errors} errors</p>`;
  loadAudit(); // reuse audit data for traffic table
}

// Initial load
loadSecrets();
```

- [ ] **Step 3: Create style.css**

```css
/* crates/rekey-web/assets/style.css */
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
header { display: flex; align-items: center; gap: 24px; margin-bottom: 24px; }
h1 { font-size: 20px; color: #58a6ff; }
nav { display: flex; gap: 8px; }
nav button { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 16px; border-radius: 6px; cursor: pointer; }
nav button.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
.tab { display: none; }
.tab.active { display: block; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-weight: 600; }
h2 { font-size: 16px; color: #c9d1d9; }
#stats { margin: 12px 0; padding: 12px; background: #161b22; border-radius: 6px; }
```

- [ ] **Step 4: Wire up rust-embed to serve static assets**

Add to `crates/rekey-web/src/routes.rs`:

```rust
use rust_embed::Embed;
use axum::response::Response;
use axum::body::Body;

#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

async fn serve_dashboard(axum::extract::Path(path): axum::extract::Path<String>) -> Response<Body> {
    let path = if path.is_empty() { "index.html".to_string() } else { path };
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .header("content-type", mime.as_ref())
                .body(Body::from(content.data.to_vec()))
                .unwrap()
        }
        None => Response::builder()
            .status(404)
            .body(Body::from("not found"))
            .unwrap(),
    }
}
```

Add route to `api_router`:
```rust
.route("/dashboard/*path", get(serve_dashboard))
.route("/dashboard", get(|| async { axum::response::Redirect::to("/dashboard/index.html") }))
```

- [ ] **Step 5: Verify compilation**

Run: `cargo check --workspace`
Expected: compiles

- [ ] **Step 6: Commit**

```bash
git add crates/rekey-web/
git commit -m "feat(web): embedded dashboard — secrets, traffic, audit log pages"
```

---

## Task 15: Integration Test — Full Flow

**Files:**
- Create: `tests/integration.rs` (workspace-level)

- [ ] **Step 1: Write integration test**

```rust
// tests/integration.rs
use rekey_vault::{crypto, db, secrets, rules, audit, providers};
use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use tempfile::TempDir;

#[test]
fn full_vault_lifecycle() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("vault.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    db::init_db(&conn).unwrap();

    // Derive key
    let salt = [42u8; 16];
    let key = crypto::derive_master_key("test-password", &salt).unwrap();

    // Add secrets
    secrets::add_secret(&conn, &key, "anthropic", "anthropic", "sk-ant-test-123", "api.anthropic.com").unwrap();
    secrets::add_secret(&conn, &key, "openai", "openai", "sk-proj-test-456", "api.openai.com").unwrap();

    // List
    let list = secrets::list_secrets(&conn).unwrap();
    assert_eq!(list.len(), 2);

    // Retrieve value
    let val = secrets::get_secret_value(&conn, &key, "anthropic").unwrap();
    assert_eq!(val, "sk-ant-test-123");

    // Rules auto-created by provider
    let anthropic_rules = rules::find_rules_for_host(&conn, "api.anthropic.com").unwrap();
    assert_eq!(anthropic_rules.len(), 1);
    assert_eq!(anthropic_rules[0].0.header_name, "x-api-key");

    let openai_rules = rules::find_rules_for_host(&conn, "api.openai.com").unwrap();
    assert_eq!(openai_rules.len(), 1);
    assert_eq!(openai_rules[0].0.header_name, "authorization");
    assert_eq!(openai_rules[0].0.value_format, "Bearer {value}");

    // No rules for unknown host
    let no_rules = rules::find_rules_for_host(&conn, "api.unknown.com").unwrap();
    assert!(no_rules.is_empty());

    // Rotate
    secrets::rotate_secret(&conn, &key, "anthropic", "sk-ant-new-789").unwrap();
    let val = secrets::get_secret_value(&conn, &key, "anthropic").unwrap();
    assert_eq!(val, "sk-ant-new-789");

    // Audit
    audit::log_access(&conn, "anthropic", "api.anthropic.com", "/v1/messages", Some(200), Some(100), "proxy").unwrap();
    let logs = audit::query_audit(&conn, None, None, 10).unwrap();
    assert_eq!(logs.len(), 1);

    // Remove
    secrets::remove_secret(&conn, "anthropic").unwrap();
    let list = secrets::list_secrets(&conn).unwrap();
    assert_eq!(list.len(), 1);
}

#[test]
fn ca_and_leaf_cert_lifecycle() {
    let dir = TempDir::new().unwrap();
    let ca = CertificateAuthority::generate(dir.path()).unwrap();
    let cache = LeafCertCache::new();

    // Generate leaf certs
    let leaf1 = cache.get_or_create("api.anthropic.com", &ca).unwrap();
    let leaf2 = cache.get_or_create("api.openai.com", &ca).unwrap();

    assert!(!leaf1.cert_der.is_empty());
    assert_ne!(leaf1.cert_der, leaf2.cert_der);

    // Cache hit
    let leaf1_again = cache.get_or_create("api.anthropic.com", &ca).unwrap();
    assert_eq!(leaf1.cert_der, leaf1_again.cert_der);

    // Reload CA from disk
    let ca2 = CertificateAuthority::load(dir.path()).unwrap();
    assert_eq!(ca.ca_cert_pem(), ca2.ca_cert_pem());
}
```

- [ ] **Step 2: Add dev-dependencies to workspace Cargo.toml**

```toml
[workspace.dependencies]
tempfile = "3"

# tests/integration.rs needs these in root Cargo.toml
[dev-dependencies]
rekey-vault = { path = "crates/rekey-vault" }
rekey-ca = { path = "crates/rekey-ca" }
rusqlite = { version = "0.34", features = ["bundled"] }
tempfile.workspace = true
```

- [ ] **Step 3: Run integration tests**

Run: `cargo test --test integration`
Expected: 2 tests PASS

- [ ] **Step 4: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add tests/ Cargo.toml
git commit -m "test: integration tests — full vault lifecycle + CA/leaf cert lifecycle"
```

---

## Task 16: Final Verification + README

**Files:**
- Create: `README.md`
- Create: `LICENSE`

- [ ] **Step 1: Full build check**

Run: `cargo build --release`
Expected: builds successfully, single binary at `target/release/rekey`

- [ ] **Step 2: Check binary size**

Run: `ls -lh target/release/rekey`
Expected: ~10-20MB

- [ ] **Step 3: Verify CLI help**

Run: `./target/release/rekey --help`
Expected: shows all subcommands

- [ ] **Step 4: Create README.md**

```markdown
# rekey

AI agent API key proxy — single binary, zero dependencies, 30-second setup.

Agents never touch your real API keys. rekey intercepts HTTP requests via MITM proxy and injects credentials at the transport layer.

## Install

```bash
cargo install rekey
```

## Quick Start

```bash
rekey init                          # Set password, generate CA
rekey add anthropic sk-ant-xxx      # Add your API key
rekey start                         # Start proxy

# In your agent's terminal:
eval $(rekey env)                   # Set proxy + placeholder keys
```

## How It Works

1. Agent sends requests through `HTTPS_PROXY=localhost:10800`
2. Agent uses placeholder API keys (`REKEY_PLACEHOLDER`)
3. rekey intercepts via MITM, replaces placeholders with real keys
4. Real keys never enter the agent's process memory

## License

MIT
```

- [ ] **Step 5: Create LICENSE (MIT)**

- [ ] **Step 6: Final commit**

```bash
git add README.md LICENSE
git commit -m "docs: add README and MIT license"
```

---

## Deferred (v2)

These are explicitly out of scope for this plan:

- **SSE real-time traffic stream** in dashboard (backend channel exists, frontend wiring deferred)
- **Daemon mode** (`rekey start -d`) with PID file management
- **Streaming response support** (SSE passthrough for Claude/OpenAI streaming APIs)
- **Wildcard host_pattern matching** (`*.openai.com`)
- **Multiple secrets per provider** (e.g., multiple OpenAI keys with rotation)
- **MCP Server mode** (expose as MCP tool)
