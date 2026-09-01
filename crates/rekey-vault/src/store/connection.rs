use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rusqlite::Connection;

use crate::error::AuthorityError;

pub(super) fn open_new(path: &Path) -> Result<Connection, AuthorityError> {
    validate_existing_sqlite_bundle(path)?;
    let conn = Connection::open(path).map_err(AuthorityError::storage)?;
    secure_file(path)?;
    configure(&conn)?;
    secure_sqlite_bundle(path)?;
    Ok(conn)
}

pub(super) fn open_existing(path: &Path) -> Result<Connection, AuthorityError> {
    validate_existing_sqlite_bundle(path)?;
    let conn = Connection::open(path).map_err(AuthorityError::storage)?;
    secure_file(path)?;
    configure(&conn)?;
    secure_sqlite_bundle(path)?;
    Ok(conn)
}

pub(super) fn secure_file(path: &Path) -> Result<(), AuthorityError> {
    let expected_uid = unsafe { libc::geteuid() };
    validate_owned_regular_file(path, expected_uid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(AuthorityError::storage)?;
    let metadata = validate_owned_regular_file(path, expected_uid)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(AuthorityError::InsecureStatePermissions);
    }
    Ok(())
}

fn validate_owned_regular_file(
    path: &Path,
    expected_uid: u32,
) -> Result<std::fs::Metadata, AuthorityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(AuthorityError::storage)?;
    if !metadata.file_type().is_file() || metadata.uid() != expected_uid {
        return Err(AuthorityError::InsecureStatePermissions);
    }
    Ok(metadata)
}

fn validate_existing_sqlite_bundle(path: &Path) -> Result<(), AuthorityError> {
    validate_owned_regular_file_if_present(path, unsafe { libc::geteuid() })?;
    for sidecar in sqlite_sidecars(path)? {
        validate_owned_regular_file_if_present(&sidecar, unsafe { libc::geteuid() })?;
    }
    Ok(())
}

fn validate_owned_regular_file_if_present(
    path: &Path,
    expected_uid: u32,
) -> Result<(), AuthorityError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.uid() == expected_uid => Ok(()),
        Ok(_) => Err(AuthorityError::InsecureStatePermissions),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuthorityError::storage(error)),
    }
}

fn sqlite_sidecars(path: &Path) -> Result<[std::path::PathBuf; 2], AuthorityError> {
    let name = path
        .file_name()
        .ok_or(AuthorityError::StorageIntegrityFailed)?
        .to_string_lossy();
    let parent = path
        .parent()
        .ok_or(AuthorityError::StorageIntegrityFailed)?;
    Ok([
        parent.join(format!("{name}-wal")),
        parent.join(format!("{name}-shm")),
    ])
}

pub(super) fn secure_sqlite_bundle(path: &Path) -> Result<(), AuthorityError> {
    for sidecar in sqlite_sidecars(path)? {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => secure_file(&sidecar)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(AuthorityError::storage(error)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_file_validation_rejects_wrong_owner_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vault.db");
        std::fs::write(&file, b"test").unwrap();
        let current_uid = unsafe { libc::geteuid() };
        assert!(validate_owned_regular_file(&file, current_uid).is_ok());
        assert!(matches!(
            validate_owned_regular_file(&file, current_uid.wrapping_add(1)),
            Err(AuthorityError::InsecureStatePermissions)
        ));

        let alias = dir.path().join("alias.db");
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(matches!(
            validate_owned_regular_file(&alias, current_uid),
            Err(AuthorityError::InsecureStatePermissions)
        ));
    }
}
