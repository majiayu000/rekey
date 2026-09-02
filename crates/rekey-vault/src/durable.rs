//! Durability helpers: fsync a file or its parent directory. Callers map
//! `io::Error` onto BackupFailed / RestoreFailed; this module never ignores
//! a failed open or sync.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const COPY_BUFFER_BYTES: usize = 64 * 1024;

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

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut source = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

pub fn create_new_file(path: &Path) -> io::Result<fs::File> {
    let resolved = resolve_destination(path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(resolved)?;
    // `.mode(0o600)` is still filtered by the process umask. Set and verify
    // the authority boundary on the already-open fd so pathname replacement
    // cannot redirect the permission change.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if file.metadata()?.mode() & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "created file is not mode 0600",
        ));
    }
    Ok(file)
}

pub fn same_file(file: &fs::File, path: &Path) -> io::Result<bool> {
    let open = file.metadata()?;
    let entry = fs::symlink_metadata(path)?;
    Ok(open.dev() == entry.dev() && open.ino() == entry.ino())
}

pub fn copy_files_and_sha256(
    source: &mut fs::File,
    destination: &mut fs::File,
) -> io::Result<String> {
    source.seek(SeekFrom::Start(0))?;
    destination.seek(SeekFrom::Start(0))?;
    copy_reader_and_sha256(source, destination)
}

fn copy_reader_and_sha256(
    source: &mut impl Read,
    destination: &mut fs::File,
) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        destination.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    destination.sync_all()?;
    Ok(hex_digest(hasher.finalize().as_slice()))
}

/// Copies one immutable input into a new mode-0600 destination while hashing it.
/// Memory use is independent of the input size.
pub fn copy_and_sha256(source: &Path, destination: &Path) -> io::Result<String> {
    let mut source = fs::File::open(source)?;
    let mut destination = create_new_file(destination)?;
    copy_reader_and_sha256(&mut source, &mut destination)
}

pub fn remove_file_and_sync(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => fsync_parent(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn hex_digest(digest: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(digest)
}

pub fn resolve_destination(path: &Path) -> io::Result<PathBuf> {
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
    let destination = resolve_destination(destination)?;
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
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
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
    fn streaming_copy_hashes_and_durably_removes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        fs::write(&source, vec![0x5a; COPY_BUFFER_BYTES * 3 + 17]).unwrap();

        let copied_hash = copy_and_sha256(&source, &destination).unwrap();
        assert_eq!(copied_hash, sha256_file(&source).unwrap());
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());

        remove_file_and_sync(&destination).unwrap();
        assert!(!destination.exists());
    }

    #[test]
    fn streaming_copy_accepts_fifo_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.fifo");
        let destination = dir.path().join("destination");
        let source_c = CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(source_c.as_ptr(), 0o600) }, 0);

        let payload = vec![0x5a; COPY_BUFFER_BYTES * 3 + 17];
        let writer_payload = payload.clone();
        let writer_source = source.clone();
        let writer = std::thread::spawn(move || fs::write(writer_source, writer_payload));

        let copied_hash = copy_and_sha256(&source, &destination).unwrap();
        writer.join().unwrap().unwrap();
        assert_eq!(copied_hash, sha256_file(&destination).unwrap());
        assert_eq!(fs::read(destination).unwrap(), payload);
    }

    #[test]
    fn create_new_does_not_follow_symlinks_and_forces_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        let link = dir.path().join("link");
        fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(create_new_file(&link).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");

        let owned_path = dir.path().join("owned");
        let owned = create_new_file(&owned_path).unwrap();
        assert_eq!(
            owned.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
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
