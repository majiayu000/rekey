use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use rand::TryRngCore;

use crate::client::CliError;

const OUTPUT: &CStr = c"rekey.prom";

fn failure(message: impl std::fmt::Display) -> CliError {
    CliError::local("OUTPUT_FAILED", format!("metrics textfile: {message}"))
}

fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

// Walk with directory descriptors so no path component can redirect publication
// through a symlink. The final descriptor anchors all subsequent mutations.
fn directory(path: &Path, state: &Path) -> Result<File, CliError> {
    let path = std::path::absolute(path).map_err(failure)?;
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(failure)?;
    let mut ancestors = vec![identity(&dir.metadata().map_err(failure)?)];
    for part in path.components() {
        let name = match part {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => return Err(failure("directory path must not contain parent traversal")),
        };
        let name = CString::new(name.as_bytes()).map_err(failure)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(failure(io::Error::last_os_error()));
        }
        dir = unsafe { File::from_raw_fd(fd) };
        let metadata = dir.metadata().map_err(failure)?;
        // Sticky shared roots (e.g. /tmp) protect our owned child from other
        // users' renames. All other writable ancestors are rejected.
        if (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & libc::S_ISVTX as u32 == 0)
        {
            return Err(failure(
                "directory ancestors must be trusted and not writable by other users",
            ));
        }
        ancestors.push(identity(&metadata));
    }
    let metadata = dir.metadata().map_err(failure)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o027 != 0 {
        return Err(failure(
            "directory must be owned by the current user, without group write or other access",
        ));
    }
    let state = std::path::absolute(state).map_err(failure)?;
    let mut existing_state = state.as_path();
    let physical_state = loop {
        match existing_state.canonicalize() {
            Ok(path) => break path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                existing_state = existing_state.parent().ok_or_else(|| failure(error))?;
            }
            Err(error) => return Err(failure(error)),
        }
    };
    for (index, parent) in physical_state.ancestors().enumerate() {
        let state_metadata = match std::fs::metadata(parent) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(failure(error)),
        };
        if identity(&metadata) == identity(&state_metadata)
            || (existing_state == state
                && index == 0
                && ancestors.contains(&identity(&state_metadata)))
        {
            return Err(failure(
                "directory must not overlap the Rekey state directory",
            ));
        }
    }
    Ok(dir)
}

fn check_output(dir: &File) -> Result<(), CliError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            OUTPUT.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(failure(error))
        };
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_nlink != 1
    {
        return Err(failure(
            "rekey.prom must be an owned regular file with one link",
        ));
    }
    Ok(())
}

fn remove(dir: &File, name: &CStr) -> Result<(), CliError> {
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(failure(format!(
                "cannot remove {}: {error}",
                name.to_string_lossy()
            )));
        }
    }
    Ok(())
}

pub(super) fn publish(
    path: &Path,
    state: &Path,
    sample: impl FnOnce() -> Result<String, CliError>,
) -> Result<(), CliError> {
    let dir = directory(path, state)?;
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(failure(format!(
            "cannot acquire exclusive directory lock: {}",
            io::Error::last_os_error()
        )));
    }
    check_output(&dir)?;
    let mut temporary = None;
    let result = (|| {
        let mut random = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(failure)?;
        let name = CString::new(format!(".rekey-{:032x}.tmp", u128::from_ne_bytes(random)))
            .map_err(failure)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(failure(format!(
                "cannot create exclusive temporary file: {}",
                io::Error::last_os_error()
            )));
        }
        temporary = Some(name.clone());
        let mut temp = unsafe { File::from_raw_fd(fd) };
        temp.set_permissions(Permissions::from_mode(0o600))
            .map_err(failure)?;
        temp.write_all(sample()?.as_bytes()).map_err(failure)?;
        let group = dir.metadata().map_err(failure)?.gid();
        if unsafe { libc::fchown(temp.as_raw_fd(), !0, group) } < 0 {
            return Err(failure(io::Error::last_os_error()));
        }
        temp.set_permissions(Permissions::from_mode(0o640))
            .map_err(failure)?;
        temp.sync_all().map_err(failure)?;
        // Close before rename. Do not retry close: a failed close may already
        // have released the fd on this platform.
        if unsafe { libc::close(temp.into_raw_fd()) } < 0 {
            return Err(failure(io::Error::last_os_error()));
        }
        check_output(&dir)?;
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                name.as_ptr(),
                dir.as_raw_fd(),
                OUTPUT.as_ptr(),
            )
        } < 0
        {
            return Err(failure(io::Error::last_os_error()));
        }
        temporary = None;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(mut error) => {
            // Revalidate before removal so a changed link or special file is
            // never removed as if it were the previous metrics file.
            if let Err(cleanup) = check_output(&dir).and_then(|()| remove(&dir, OUTPUT)) {
                error.message.push_str(&format!(
                    "; stale output cleanup failed: {}",
                    cleanup.message
                ));
            }
            if let Some(name) = temporary
                && let Err(cleanup) = remove(&dir, &name)
            {
                error
                    .message
                    .push_str(&format!("; temporary cleanup failed: {}", cleanup.message));
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let physical = root.path().canonicalize().unwrap();
        let output = physical.join("metrics");
        let state = physical.join("state");
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, Permissions::from_mode(0o750)).unwrap();
        std::fs::create_dir(&state).unwrap();
        (root, output, state)
    }

    fn temporary_files(path: &Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| {
                entry
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .collect()
    }

    #[test]
    fn metrics_textfile_atomic_replacement_and_permissions() {
        let (_root, output, state) = fixture();
        std::fs::write(output.join("rekey.prom"), "old\n").unwrap();
        let old = File::open(output.join("rekey.prom")).unwrap();
        publish(&output, &state, || {
            assert_eq!(
                std::fs::read_to_string(output.join("rekey.prom")).unwrap(),
                "old\n"
            );
            assert_eq!(
                std::fs::metadata(&temporary_files(&output)[0])
                    .unwrap()
                    .mode()
                    & 0o777,
                0o600
            );
            Ok("new\n".to_string())
        })
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(output.join("rekey.prom")).unwrap(),
            "new\n"
        );
        let current = std::fs::metadata(output.join("rekey.prom")).unwrap();
        assert_ne!(identity(&old.metadata().unwrap()), identity(&current));
        assert_eq!(current.mode() & 0o777, 0o640);
        assert_eq!(current.gid(), std::fs::metadata(&output).unwrap().gid());
        assert!(temporary_files(&output).is_empty());
    }

    #[test]
    fn metrics_textfile_sampling_failure_invalidates_old_data() {
        let (_root, output, state) = fixture();
        std::fs::write(output.join("rekey.prom"), "old").unwrap();
        let error = publish(&output, &state, || {
            Err(CliError::local("INVALID_FRAME", "bad snapshot"))
        })
        .unwrap_err();
        assert_eq!(error.code, "INVALID_FRAME");
        assert!(!output.join("rekey.prom").exists());
        assert!(temporary_files(&output).is_empty());
    }

    #[test]
    fn metrics_textfile_rejects_links_permissions_and_state_overlap() {
        let (_root, output, state) = fixture();
        let target = output.join("rekey.prom");
        let other = state.join("untouched");
        std::fs::write(&other, "private").unwrap();
        symlink(&other, &target).unwrap();
        assert!(publish(&output, &state, || panic!("must not sample")).is_err());
        std::fs::remove_file(&target).unwrap();
        std::fs::hard_link(&other, &target).unwrap();
        assert!(publish(&output, &state, || panic!("must not sample")).is_err());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "private");
        std::fs::remove_file(&target).unwrap();
        let link = output.with_file_name("link");
        symlink(&output, &link).unwrap();
        assert!(publish(&link, &state, || panic!("must not sample")).is_err());
        std::fs::set_permissions(&output, Permissions::from_mode(0o770)).unwrap();
        assert!(publish(&output, &state, || panic!("must not sample")).is_err());
        std::fs::set_permissions(&output, Permissions::from_mode(0o750)).unwrap();
        for forbidden in [&state, state.parent().unwrap()] {
            assert!(publish(forbidden, &state, || panic!("must not sample")).is_err());
        }
        let inside = output.join("state");
        std::fs::create_dir(&inside).unwrap();
        let state_link = output.with_file_name("state-link");
        symlink(&inside, &state_link).unwrap();
        assert!(publish(&output, &state_link, || panic!("must not sample")).is_err());
        assert!(
            publish(&output, &state_link.join("missing"), || panic!(
                "must not sample"
            ))
            .is_err()
        );
        let untrusted = output.with_file_name("untrusted");
        std::fs::create_dir(&untrusted).unwrap();
        std::fs::set_permissions(&untrusted, Permissions::from_mode(0o777)).unwrap();
        let child = untrusted.join("metrics");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, Permissions::from_mode(0o750)).unwrap();
        assert!(publish(&child, &state, || panic!("must not sample")).is_err());
        let nested = state.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::set_permissions(&nested, Permissions::from_mode(0o750)).unwrap();
        assert!(publish(&nested, &state, || panic!("must not sample")).is_err());
    }

    #[test]
    fn metrics_textfile_single_writer_and_crash_residue_does_not_block() {
        let (_root, output, state) = fixture();
        publish(&output, &state, || {
            let result = publish(&output, &state, || panic!("must not sample"));
            assert!(
                result
                    .unwrap_err()
                    .message
                    .contains("exclusive directory lock")
            );
            Ok("winner\n".into())
        })
        .unwrap();
        std::fs::write(
            output.join(".rekey-00000000000000000000000000000000.tmp"),
            "crashed",
        )
        .unwrap();
        publish(&output, &state, || Ok("next\n".into())).unwrap();
        assert_eq!(
            std::fs::read_to_string(output.join("rekey.prom")).unwrap(),
            "next\n"
        );
        assert_eq!(
            std::fs::read_to_string(output.join(".rekey-00000000000000000000000000000000.tmp"))
                .unwrap(),
            "crashed"
        );
    }

    #[test]
    fn metrics_textfile_cleanup_failure_is_reported() {
        let (_root, output, state) = fixture();
        let error = publish(&output, &state, || {
            // A replacement directory cannot be unlinked as a metrics file.
            std::fs::create_dir(output.join("rekey.prom")).unwrap();
            Err(failure("sampling failed"))
        })
        .unwrap_err();
        assert!(error.message.contains("sampling failed"));
        assert!(error.message.contains("stale output cleanup failed"));
        assert!(temporary_files(&output).is_empty());
    }
}
