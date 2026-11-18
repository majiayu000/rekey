//! Symlink-safe, previewed edits of user-owned files for `rekey connect`:
//! exact private backups, exclusive staging and atomic publication.
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use rand::TryRngCore;

use super::{invalid, io_error};
use crate::client::CliError;

pub(super) const MAX_CONFIG: usize = 1024 * 1024;

fn name(value: &std::ffi::OsStr) -> Result<CString, CliError> {
    CString::new(value.as_bytes()).map_err(|_| invalid("configuration path contains NUL"))
}
fn open_at(dir: &File, entry: &CStr, flags: i32, mode: libc::c_uint) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            entry.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn directory(path: &Path) -> Result<File, CliError> {
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")
        .map_err(|e| io_error("cannot open filesystem root", e))?;
    for component in path.components() {
        let part = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(part) => part,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            _ => return Err(invalid("project must have an absolute Unix path")),
        };
        dir = open_at(&dir, &name(part)?, libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(|e| {
            io_error(
                "cannot open project directory without following symlinks",
                e,
            )
        })?;
    }
    Ok(dir)
}
fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn id(file: &File) -> Result<(u64, u64), CliError> {
    file.metadata()
        .map(|m| identity(&m))
        .map_err(|e| io_error("cannot inspect configuration identity", e))
}
fn parent(project: &File, subdir: Option<&str>) -> Result<Option<File>, CliError> {
    match subdir {
        None => project
            .try_clone()
            .map(Some)
            .map_err(|e| io_error("cannot retain project directory", e)),
        Some(part) => match open_at(
            project,
            &name(part.as_ref())?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(dir) => Ok(Some(dir)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(
                "cannot open client directory without following symlinks",
                e,
            )),
        },
    }
}
#[derive(PartialEq)]
pub(super) struct Snapshot {
    identity: (u64, u64),
    pub(super) mode: u32,
    pub(super) bytes: Vec<u8>,
}
fn read(dir: Option<&File>, target: &CStr) -> Result<Option<Snapshot>, CliError> {
    let Some(dir) = dir else { return Ok(None) };
    let file = match open_at(dir, target, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(io_error(
                "cannot open configuration without following symlinks",
                e,
            ));
        }
    };
    let meta = file
        .metadata()
        .map_err(|e| io_error("cannot inspect configuration", e))?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.len() > MAX_CONFIG as u64
    {
        return Err(invalid(
            "configuration must be an owned regular file no larger than 1 MiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("cannot read configuration", e))?;
    if bytes.len() > MAX_CONFIG {
        return Err(invalid("configuration exceeds 1 MiB"));
    }
    Ok(Some(Snapshot {
        identity: identity(&meta),
        mode: meta.mode() & 0o777,
        bytes,
    }))
}
fn unchanged(
    path: &Path,
    project: &File,
    subdir: Option<&str>,
    dir: Option<&File>,
    target: &CStr,
    original: &Option<Snapshot>,
) -> Result<(), CliError> {
    let current_project = directory(path)?;
    let current_parent = parent(&current_project, subdir)?;
    if id(&current_project)? != id(project)?
        || current_parent.as_ref().map(id).transpose()? != dir.map(id).transpose()?
        || &read(current_parent.as_ref(), target)? != original
    {
        return Err(invalid(
            "configuration changed after preview; nothing was replaced",
        ));
    }
    Ok(())
}
fn create_sibling(dir: &File, target: &str, role: &str) -> Result<(CString, File), CliError> {
    let mut random = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| invalid("cannot generate a private staging filename"))?;
    let entry = CString::new(format!(
        ".{target}.rekey-{role}-{:032x}",
        u128::from_ne_bytes(random)
    ))
    .expect("static filename has no NUL");
    let file = open_at(
        dir,
        &entry,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .map_err(|e| io_error("cannot create exclusive configuration staging file", e))?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io_error(
            &format!(
                "cannot protect configuration staging file; {} may remain",
                entry.to_string_lossy()
            ),
            io::Error::last_os_error(),
        ));
    }
    Ok((entry, file))
}
fn publish(dir: &File, stage: &CStr, target: &CStr, replace: bool) -> io::Result<()> {
    // POSIX rename has no inode-CAS: the immediate recheck detects observed
    // races, but cannot prevent an uncooperative last-instant replacement.
    let rc = unsafe {
        if replace {
            libc::renameat(
                dir.as_raw_fd(),
                stage.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
            )
        } else {
            libc::linkat(
                dir.as_raw_fd(),
                stage.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if !replace && unsafe { libc::unlinkat(dir.as_raw_fd(), stage.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.sync_all()
}

pub(super) fn marked(
    original: &[u8],
    replacement: &str,
    begin: &str,
    end: &str,
) -> Result<Vec<u8>, CliError> {
    let text = std::str::from_utf8(original).map_err(|_| invalid("managed text must be UTF-8"))?;
    let starts: Vec<_> = text.match_indices(begin).map(|(i, _)| i).collect();
    let ends: Vec<_> = text.match_indices(end).map(|(i, _)| i).collect();
    let updated = match (starts.as_slice(), ends.as_slice()) {
        ([], []) if replacement.is_empty() => text.to_owned(),
        ([], []) => format!(
            "{text}{}{replacement}",
            if text.is_empty() || text.ends_with("\n\n") {
                ""
            } else if text.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            }
        ),
        ([start], [finish]) if start < finish => {
            let finish = finish + end.len();
            let finish = finish + usize::from(text[finish..].starts_with('\n'));
            format!("{}{}{}", &text[..*start], replacement, &text[finish..])
        }
        _ => {
            return Err(invalid(
                "Rekey markers are malformed or duplicated; repair them before connecting",
            ));
        }
    };
    Ok(updated.into_bytes())
}

pub(super) struct Edit {
    pub(super) root_path: PathBuf,
    root: File,
    subdir: Option<&'static str>,
    filename: &'static str,
    parent: Option<File>,
    pub(super) original: Option<Snapshot>,
    pub(super) updated: Vec<u8>,
    /// Permission bits to publish with and to compare (Git hooks). None keeps
    /// 0600 and ignores the current mode.
    pub(super) mode: Option<u32>,
    /// Delete the target instead of writing `updated`.
    pub(super) remove: bool,
    /// Atomically rename this verified sibling over the target instead of writing.
    pub(super) restore: Option<(&'static str, Snapshot)>,
    pub(super) before: String,
    pub(super) after: String,
    /// Shown after the preview, e.g. when a project file names a local path.
    pub(super) warning: Option<&'static str>,
}
impl Edit {
    pub(super) fn load(
        root_path: PathBuf,
        subdir: Option<&'static str>,
        filename: &'static str,
    ) -> Result<Self, CliError> {
        let root = directory(&root_path)?;
        let parent = parent(&root, subdir)?;
        let original = read(parent.as_ref(), &name(filename.as_ref())?)?;
        Ok(Self {
            root_path,
            root,
            subdir,
            filename,
            parent,
            original,
            updated: Vec::new(),
            mode: None,
            remove: false,
            restore: None,
            before: String::new(),
            after: String::new(),
            warning: None,
        })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        self.original.as_ref().map_or(&[], |s| &s.bytes)
    }
    pub(super) fn changed(&self) -> bool {
        match &self.original {
            None => !self.remove,
            Some(old) => {
                self.remove
                    || self.restore.is_some()
                    || old.bytes != self.updated
                    || self.mode.is_some_and(|mode| old.mode != mode)
            }
        }
    }
    pub(super) fn path(&self) -> PathBuf {
        self.subdir
            .map_or_else(|| self.root_path.clone(), |d| self.root_path.join(d))
            .join(self.filename)
    }
    pub(super) fn verify(&self) -> Result<(), CliError> {
        unchanged(
            &self.root_path,
            &self.root,
            self.subdir,
            self.parent.as_ref(),
            &name(self.filename.as_ref())?,
            &self.original,
        )?;
        if let Some((sibling, snapshot)) = &self.restore
            && read(self.parent.as_ref(), &name(sibling.as_ref())?)?.as_ref() != Some(snapshot)
        {
            return Err(invalid(
                "configuration changed after preview; nothing was replaced",
            ));
        }
        Ok(())
    }
    pub(super) fn apply(&mut self) -> Result<(), CliError> {
        self.verify()?;
        if self.remove || self.restore.is_some() {
            let dir = self
                .parent
                .as_ref()
                .ok_or_else(|| invalid("hooks directory disappeared"))?;
            let target = name(self.filename.as_ref())?;
            let result = match &self.restore {
                Some((sibling, _)) => publish(dir, &name(sibling.as_ref())?, &target, true),
                None if unsafe { libc::unlinkat(dir.as_raw_fd(), target.as_ptr(), 0) } != 0 => {
                    Err(io::Error::last_os_error())
                }
                None => dir.sync_all(),
            };
            return result.map_err(|e| {
                io_error(
                    "hook removal or directory sync failed; inspect the hooks directory",
                    e,
                )
            });
        }
        if self.parent.is_none() {
            let part = name(
                self.subdir
                    .expect("missing parent has a subdirectory")
                    .as_ref(),
            )?;
            if unsafe { libc::mkdirat(self.root.as_raw_fd(), part.as_ptr(), 0o700) } != 0 {
                return Err(io_error(
                    "cannot create client directory",
                    io::Error::last_os_error(),
                ));
            }
            self.root
                .sync_all()
                .map_err(|e| io_error("cannot sync project directory", e))?;
            self.parent = parent(&self.root, self.subdir)?;
        }
        let dir = self
            .parent
            .as_ref()
            .ok_or_else(|| invalid("client directory disappeared"))?;
        let mut retained = Vec::new();
        let result = (|| {
            if let Some(old) = &self.original {
                let (backup, mut file) = create_sibling(dir, self.filename, "backup")?;
                retained.push(backup.to_string_lossy().into_owned());
                file.write_all(&old.bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|e| io_error("cannot sync exact configuration backup", e))?;
            }
            let (stage, mut file) = create_sibling(dir, self.filename, "staging")?;
            retained.push(stage.to_string_lossy().into_owned());
            file.write_all(&self.updated)
                .and_then(|()| file.sync_all())
                .map_err(|e| io_error("cannot sync new configuration", e))?;
            if let Some(mode) = self.mode
                && unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0
            {
                return Err(io_error(
                    "cannot set the hook file mode",
                    io::Error::last_os_error(),
                ));
            }
            self.verify()?;
            publish(dir, &stage, &name(self.filename.as_ref())?, self.original.is_some()).map_err(|e| io_error("configuration publication or directory sync failed; inspect targets before retrying", e))?;
            retained.pop();
            Ok(())
        })();
        let report = if retained.is_empty() {
            Ok(())
        } else {
            writeln!(
                io::stderr(),
                "Private backup/staging files beside {} (may remain on failure): {}",
                self.path().display(),
                retained.join(", ")
            )
            .map_err(|e| io_error("cannot report backup paths", e))
        };
        result?;
        report
    }
}

/// Preview every edit, then apply them only after an explicit terminal "yes".
pub(super) fn review(
    mut edits: Vec<Edit>,
    print: bool,
    question: &str,
    done: &str,
) -> Result<(), CliError> {
    let mut output = io::stdout().lock();
    for edit in &edits {
        if edit.updated.len() > MAX_CONFIG {
            return Err(invalid("updated configuration exceeds 1 MiB"));
        }
        writeln!(
            output,
            "Target: {}\n--- before\n- {}\n+++ after",
            edit.path().display(),
            edit.before
        )
        .map_err(|e| io_error("cannot write preview", e))?;
        for line in edit.after.lines() {
            writeln!(output, "+ {line}").map_err(|e| io_error("cannot write preview", e))?;
        }
        if let Some(warning) = edit.warning {
            writeln!(output, "{warning}").map_err(|e| io_error("cannot write preview", e))?;
        }
    }
    if print {
        return Ok(());
    }
    if !edits.iter().any(Edit::changed) {
        writeln!(output, "Already configured; no files changed.")
            .map_err(|e| io_error("cannot write result", e))?;
        return Ok(());
    }
    output
        .flush()
        .map_err(|e| io_error("cannot write preview", e))?;
    if !io::stdin().is_terminal() {
        return Err(invalid(
            "TTY confirmation is required; use --print to preview without writing",
        ));
    }
    write!(io::stderr(), "{question} [y/N] ")
        .and_then(|()| io::stderr().flush())
        .map_err(|e| io_error("cannot write confirmation", e))?;
    let mut answer = String::new();
    io::stdin()
        .lock()
        .take(32)
        .read_line(&mut answer)
        .map_err(|e| io_error("cannot read confirmation", e))?;
    if answer.len() == 32 || !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        return Ok(());
    }
    for edit in &edits {
        edit.verify()?;
    }
    for edit in edits.iter_mut().filter(|e| e.changed()) {
        edit.apply()?;
    }
    writeln!(output, "{done}").map_err(|e| io_error("cannot write result", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publish_new_file_never_clobbers_racing_creator() {
        let temp = tempfile::tempdir().unwrap();
        let dir = File::open(temp.path()).unwrap();
        std::fs::write(temp.path().join("stage"), b"new").unwrap();
        std::fs::write(temp.path().join("target"), b"racer").unwrap();
        let error = publish(&dir, c"stage", c"target", false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(temp.path().join("target")).unwrap(), b"racer");
        assert_eq!(std::fs::read(temp.path().join("stage")).unwrap(), b"new");
    }
}
