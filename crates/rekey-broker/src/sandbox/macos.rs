//! Experimental, fixed Seatbelt adapter. No general policy or proxy surface.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr;

use rekey_domain::sandbox::MACOS_SEATBELT_V1;

use super::{BrokerError, PreparedLaunch};

// Available since macOS 10.15; libc 0.2.183 does not declare this SDK symbol.
unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

const PROGRAM: &str = "/usr/bin/sandbox-exec";
const PROFILE: &str = include_str!("macos.sb");
// Must match macos.sb's fixed filesystem grants. Keep protected trees outside
// these roots instead of relying on ordering between SBPL allow/deny rules.
const RUNTIME_ROOTS: &[&str] = &[
    "/System/Library",
    "/usr/lib",
    "/usr/share",
    "/bin",
    "/usr/bin",
    "/usr/libexec",
    "/opt/homebrew/Cellar",
    "/usr/local/Cellar",
];

fn invalid(message: &str) -> BrokerError {
    rekey_domain::DomainError::InvalidLaunchPlan(message.to_owned()).into()
}

// realpath does not unify APFS firmlinks or case on case-insensitive volumes.
// All inputs exist at this boundary; compare directory identity, not spelling.
fn contains(root: &Path, path: &Path) -> Result<bool, BrokerError> {
    let root = fs::metadata(root).map_err(BrokerError::Io)?;
    for ancestor in path.ancestors() {
        let entry = fs::metadata(ancestor).map_err(BrokerError::Io)?;
        if (root.dev(), root.ino()) == (entry.dev(), entry.ino()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn overlaps(a: &Path, b: &Path) -> Result<bool, BrokerError> {
    Ok(contains(a, b)? || contains(b, a)?)
}

fn user_home() -> io::Result<PathBuf> {
    let mut record = MaybeUninit::uninit();
    let mut result = ptr::null_mut();
    let mut buffer = vec![0u8; 64 * 1024];
    // SAFETY: reentrant lookup writes only to the supplied live buffers. Copy
    // pw_dir before freeing them. Identity comes from the OS, not HOME env.
    unsafe {
        checked(libc::getpwuid_r(
            libc::geteuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        ))?;
        if result.is_null() || (*result).pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "cannot resolve launcher home",
            ));
        }
        Path::new(OsStr::from_bytes(
            CStr::from_ptr((*result).pw_dir).to_bytes(),
        ))
        .canonicalize()
    }
}

pub(super) fn prepare(
    state: &Path,
    socket: &Path,
    argv: &[OsString],
    mut env: Vec<(OsString, OsString)>,
) -> Result<PreparedLaunch, BrokerError> {
    let program = PathBuf::from(PROGRAM);
    match fs::metadata(&program) {
        Ok(meta) if meta.is_file() && meta.permissions().mode() & 0o111 != 0 => {}
        Ok(_) => return Err(BrokerError::LauncherUnavailable),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(BrokerError::LauncherUnavailable);
        }
        Err(e) => return Err(BrokerError::Io(e)),
    }
    let code = std::env::current_dir()
        .and_then(|p| p.canonicalize())
        .map_err(BrokerError::Io)?;
    let home = user_home().map_err(BrokerError::Io)?;
    let temporary_parent = std::env::temp_dir()
        .canonicalize()
        .map_err(BrokerError::Io)?;
    if contains(&code, &home)?
        || contains(&code, Path::new("/private/tmp"))?
        || contains(&code, Path::new("/private/var/tmp"))?
        || contains(&code, &temporary_parent)?
        || overlaps(&code, Path::new("/System/Volumes"))?
    {
        return Err(invalid(
            "launch from a code directory, not HOME or a shared temporary parent",
        ));
    }
    let endpoint_dir = socket
        .parent()
        .ok_or_else(|| invalid("invalid Agent socket"))?;
    if overlaps(state, endpoint_dir)?
        || overlaps(&code, state)?
        || overlaps(&code, endpoint_dir)?
        || contains(state, Path::new(&argv[0]))?
    {
        return Err(invalid(
            "code directory and executable must not expose state or Agent endpoint directory",
        ));
    }
    for root in RUNTIME_ROOTS {
        let root = Path::new(root);
        // System roots may be absent (e.g. Homebrew); no fallback on other IO errors.
        let canonical = match root.canonicalize() {
            Ok(path) => path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(BrokerError::Io(e)),
        };
        if overlaps(&canonical, state)? || overlaps(&canonical, endpoint_dir)? {
            return Err(invalid(
                "protected paths overlap a fixed macOS runtime root",
            ));
        }
    }
    let scratch = tempfile::Builder::new()
        .prefix("rekey-agent-")
        .tempdir_in("/private/tmp")
        .map_err(BrokerError::Io)?;
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700))
        .map_err(BrokerError::Io)?;
    let scratch_path = scratch.path().canonicalize().map_err(BrokerError::Io)?;
    if overlaps(&scratch_path, state)? || overlaps(&scratch_path, endpoint_dir)? {
        return Err(invalid("temporary directory overlaps protected paths"));
    }
    env.retain(|(key, _)| key != "HOME");
    env.push(("HOME".into(), scratch_path.as_os_str().to_owned()));
    env.push(("TMPDIR".into(), scratch_path.as_os_str().to_owned()));
    let mut args = vec!["-p".into(), PROFILE.into()];
    for (name, value) in [
        ("CODE", code.as_os_str()),
        ("EXEC", argv[0].as_os_str()),
        ("AGENT", socket.as_os_str()),
        ("SCRATCH", scratch_path.as_os_str()),
    ] {
        let mut parameter = OsString::from(name);
        parameter.push("=");
        parameter.push(value);
        args.extend(["-D".into(), parameter]);
    }
    args.push("--".into());
    args.extend_from_slice(argv);
    Ok(PreparedLaunch {
        profile: MACOS_SEATBELT_V1,
        program,
        args,
        env,
        scratch,
    })
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in launch input"))
}

fn checked(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

/// POSIX_SPAWN_CLOEXEC_DEFAULT closes even descriptors the caller forgot to
/// mark CLOEXEC. Command::pre_exec(close loop) would close Rust's error pipe.
pub(super) fn spawn(prepared: &PreparedLaunch) -> io::Result<i32> {
    let argv = std::iter::once(prepared.program.as_os_str())
        .chain(prepared.args.iter().map(OsString::as_os_str))
        .map(cstring)
        .collect::<io::Result<Vec<_>>>()?;
    let env = prepared
        .env
        .iter()
        .map(|(key, value)| {
            let mut entry = key.clone();
            entry.push("=");
            entry.push(value);
            cstring(&entry)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut argv_ptrs: Vec<_> = argv.iter().map(|s| s.as_ptr().cast_mut()).collect();
    argv_ptrs.push(ptr::null_mut());
    let mut env_ptrs: Vec<_> = env.iter().map(|s| s.as_ptr().cast_mut()).collect();
    env_ptrs.push(ptr::null_mut());
    let cwd = cstring(prepared.scratch.path().as_os_str())?;
    // SAFETY: all buffers/attributes live through synchronous posix_spawn;
    // initialized OS objects are destroyed on every return path. No post-fork Rust.
    unsafe {
        let mut attr = MaybeUninit::uninit();
        checked(libc::posix_spawnattr_init(attr.as_mut_ptr()))?;
        let mut attr = attr.assume_init();
        let mut actions = MaybeUninit::uninit();
        if let Err(e) = checked(libc::posix_spawn_file_actions_init(actions.as_mut_ptr())) {
            libc::posix_spawnattr_destroy(&mut attr);
            return Err(e);
        }
        let mut actions = actions.assume_init();
        let result = (|| -> io::Result<libc::pid_t> {
            checked(libc::posix_spawnattr_setflags(
                &mut attr,
                libc::POSIX_SPAWN_CLOEXEC_DEFAULT as i16,
            ))?;
            checked(libc::posix_spawn_file_actions_addopen(
                &mut actions,
                0,
                c"/dev/null".as_ptr(),
                libc::O_RDONLY,
                0,
            ))?;
            let null_device = fs::metadata("/dev/null")?;
            for fd in [1, 2] {
                let mut st = MaybeUninit::uninit();
                if libc::fstat(fd, st.as_mut_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let st = st.assume_init();
                let kind = st.st_mode & libc::S_IFMT;
                let safe_character = kind == libc::S_IFCHR
                    && (libc::isatty(fd) == 1 || st.st_rdev as u64 == null_device.rdev());
                if kind != libc::S_IFREG && kind != libc::S_IFIFO && !safe_character {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Agent output must be a file, pipe, or TTY",
                    ));
                }
                checked(libc::posix_spawn_file_actions_adddup2(&mut actions, fd, fd))?;
            }
            checked(posix_spawn_file_actions_addchdir_np(
                &mut actions,
                cwd.as_ptr(),
            ))?;
            let mut pid = 0;
            checked(libc::posix_spawn(
                &mut pid,
                argv[0].as_ptr(),
                &actions,
                &attr,
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            ))?;
            Ok(pid)
        })();
        libc::posix_spawn_file_actions_destroy(&mut actions);
        libc::posix_spawnattr_destroy(&mut attr);
        let pid = result?;
        let mut status = 0;
        loop {
            if libc::waitpid(pid, &mut status, 0) >= 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        if libc::WIFEXITED(status) {
            Ok(libc::WEXITSTATUS(status))
        } else {
            Ok(5)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn malformed_profile_and_missing_launcher_never_execute_payload() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let agent = root.path().join("agent");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&agent).unwrap();
        let socket = agent.join("agent.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let mut plan = prepare(
            &state.canonicalize().unwrap(),
            &socket.canonicalize().unwrap(),
            &[
                "/bin/sh".into(),
                "-c".into(),
                "echo executed > marker".into(),
            ],
            vec![("REKEY_CAPABILITY".into(), "test-capability-canary".into())],
        )
        .unwrap();
        assert_eq!(plan.profile, MACOS_SEATBELT_V1);
        assert!(!plan.args.iter().any(|a| {
            a.as_bytes()
                .windows(22)
                .any(|w| w == b"test-capability-canary")
        }));
        plan.args[1] = "(invalid-profile".into();
        assert_ne!(spawn(&plan).unwrap(), 0);
        assert!(!plan.scratch.path().join("marker").exists());
        plan.program = root.path().join("missing-sandbox-exec");
        assert_eq!(spawn(&plan).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(!plan.scratch.path().join("marker").exists());
    }
}
