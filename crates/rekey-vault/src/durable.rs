//! Durability helpers: fsync a file or its parent directory. Callers map
//! `io::Error` onto BackupFailed / RestoreFailed; this module never ignores
//! a failed open or sync.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

pub fn fsync(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    file.sync_all()?;
    Ok(())
}

pub fn fsync_parent(path: &Path) -> io::Result<()> {
    fsync(parent_dir(path))
}

fn resolved_destination(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let name = absolute
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no name"))?;
    Ok(parent_dir(&absolute).canonicalize()?.join(name))
}

/// Rejects backup destinations that could replace live state, including
/// relative paths and symlink aliases into the protected tree.
pub fn ensure_outside_tree(destination: &Path, protected_root: &Path) -> io::Result<()> {
    let root = protected_root.canonicalize()?;
    let destination = resolved_destination(destination)?;
    if destination == root || destination.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination overlaps protected state",
        ));
    }
    if destination.exists() {
        let existing = destination.canonicalize()?;
        if existing == root || existing.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination aliases protected state",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn missing_parent_open_fails() {
        let err =
            fsync_parent(Path::new("/no/such/rekey-durable-parent/out.rkbackup")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn unreadable_directory_open_fails() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("noread");
        fs::create_dir(&nested).unwrap();
        let mut perms = fs::metadata(&nested).unwrap().permissions();
        perms.set_mode(0o300);
        fs::set_permissions(&nested, perms).unwrap();
        let err = fsync(&nested).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let mut perms = fs::metadata(&nested).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&nested, perms).unwrap();
    }

    #[test]
    fn writable_tempdir_fsyncs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("leaf");
        fs::write(&file, b"x").unwrap();
        fsync(&file).unwrap();
        fsync_parent(&file).unwrap();
    }

    #[test]
    fn protected_tree_and_symlink_alias_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let outside = dir.path().join("outside");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&outside).unwrap();
        assert_eq!(
            ensure_outside_tree(&state.join("vault.sqlite3"), &state)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        std::os::unix::fs::symlink(&state, outside.join("state-alias")).unwrap();
        assert_eq!(
            ensure_outside_tree(&outside.join("state-alias/vault.sqlite3"), &state)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
