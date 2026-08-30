use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rusqlite::Connection;

use crate::error::AuthorityError;

pub(super) fn open_new(path: &Path) -> Result<Connection, AuthorityError> {
    let conn = Connection::open(path).map_err(AuthorityError::storage)?;
    secure_file(path)?;
    configure(&conn)?;
    secure_sqlite_bundle(path)?;
    Ok(conn)
}

pub(super) fn open_existing(path: &Path) -> Result<Connection, AuthorityError> {
    let conn = Connection::open(path).map_err(AuthorityError::storage)?;
    secure_file(path)?;
    configure(&conn)?;
    secure_sqlite_bundle(path)?;
    Ok(conn)
}

pub(super) fn secure_file(path: &Path) -> Result<(), AuthorityError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(AuthorityError::storage)?;
    let mode = std::fs::metadata(path)
        .map_err(AuthorityError::storage)?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(AuthorityError::InsecureStatePermissions);
    }
    Ok(())
}

pub(super) fn secure_sqlite_bundle(path: &Path) -> Result<(), AuthorityError> {
    let name = path
        .file_name()
        .ok_or(AuthorityError::StorageIntegrityFailed)?
        .to_string_lossy();
    let parent = path
        .parent()
        .ok_or(AuthorityError::StorageIntegrityFailed)?;
    for sidecar in [
        parent.join(format!("{name}-wal")),
        parent.join(format!("{name}-shm")),
    ] {
        if sidecar.exists() {
            secure_file(&sidecar)?;
        }
    }
    Ok(())
}

/// Sets and verifies every connection pragma the contract requires.
fn configure(conn: &Connection) -> Result<(), AuthorityError> {
    let journal: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .map_err(AuthorityError::storage)?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(AuthorityError::StorageIntegrityFailed);
    }
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA synchronous = FULL;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(AuthorityError::storage)?;
    for (pragma, expected) in [
        ("PRAGMA foreign_keys", 1),
        ("PRAGMA synchronous", 2),
        ("PRAGMA trusted_schema", 0),
        ("PRAGMA secure_delete", 1),
        ("PRAGMA busy_timeout", 5000),
    ] {
        let got: i64 = conn
            .query_row(pragma, [], |r| r.get(0))
            .map_err(AuthorityError::storage)?;
        if got != expected {
            return Err(AuthorityError::StorageIntegrityFailed);
        }
    }
    Ok(())
}
