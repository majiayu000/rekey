//! OS-verified peer identity for Unix sockets. Never trusts anything the
//! client sends; a failed lookup rejects the connection.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use tokio::net::UnixStream;

use crate::error::BrokerError;
use rekey_vault::AuthorityError;

#[cfg(target_os = "macos")]
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

pub fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// A cross-UID Agent endpoint must not sit below a path an admitted Agent can
/// rename or replace. Validate every existing component through the mount
/// boundary before the Broker creates the final runtime directory.
pub(crate) fn verify_cross_uid_runtime_ancestors(
    path: &Path,
    broker_uid: u32,
    allowed_agent_uids: &[u32],
) -> Result<(), BrokerError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(BrokerError::Io)?.join(path)
    };
    let mut cursor = PathBuf::new();
    let mut deepest_existing = None;
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => cursor.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                cursor.pop();
                continue;
            }
            Component::Normal(_) => cursor.push(component.as_os_str()),
        }
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => return insecure(),
            Ok(metadata) => deepest_existing = Some((cursor.clone(), metadata.dev())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(BrokerError::Io(error)),
        }
    }

    let (mut ancestor, device) = deepest_existing.ok_or_else(|| {
        BrokerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "agent runtime has no existing ancestor",
        ))
    })?;
    loop {
        let metadata = fs::symlink_metadata(&ancestor).map_err(BrokerError::Io)?;
        if metadata.file_type().is_symlink() {
            return insecure();
        }
        if metadata.dev() != device {
            return Ok(());
        }
        let mode = metadata.permissions().mode();
        let agent_owned = metadata.uid() != broker_uid
            && allowed_agent_uids.contains(&metadata.uid())
            && mode & 0o200 != 0;
        if !metadata.is_dir() || mode & 0o022 != 0 || agent_owned {
            return insecure();
        }
        let Some(parent) = ancestor.parent() else {
            return Ok(());
        };
        ancestor = parent.to_owned();
    }
}

fn insecure<T>() -> Result<T, BrokerError> {
    Err(BrokerError::Authority(
        AuthorityError::InsecureStatePermissions,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_uid_runtime_rejects_agent_owned_or_group_writable_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(dir.path()).unwrap();
        assert!(
            verify_cross_uid_runtime_ancestors(
                &dir.path().join("agent"),
                metadata.uid().wrapping_add(1),
                &[metadata.uid()],
            )
            .is_err()
        );

        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            verify_cross_uid_runtime_ancestors(
                &dir.path().join("agent"),
                metadata.uid(),
                &[metadata.uid().wrapping_add(1)],
            )
            .is_err()
        );
    }
}
