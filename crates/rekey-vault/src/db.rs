use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub fn prepare_connection(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

pub fn open_connection(path: impl AsRef<Path>) -> Result<Connection> {
    let conn = Connection::open(path)?;
    prepare_connection(&conn)?;
    Ok(conn)
}

pub fn init_db(conn: &Connection) -> Result<()> {
    prepare_connection(conn)?;
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
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_log_secret_name ON audit_log(secret_name);
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        PRAGMA foreign_keys = ON;",
    )?;
    Ok(())
}
