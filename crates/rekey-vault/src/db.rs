use anyhow::Result;
use rusqlite::Connection;

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
