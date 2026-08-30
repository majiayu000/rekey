//! Durability helpers: fsync a file or its parent directory. Callers map
//! `io::Error` onto BackupFailed / RestoreFailed; this module never ignores
//! a failed open or sync.

use std::fs;
use std::io;
use std::path::Path;

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
}
