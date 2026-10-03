//! Experimental, fixed Seatbelt adapter. No general policy or proxy surface.

use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::num::NonZeroU16;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rekey_domain::sandbox::MACOS_SEATBELT_V1;

use super::profile::{contains, overlaps, user_home};
use super::{BrokerError, PreparedLaunch};

// Available since macOS 10.15; libc 0.2.183 does not declare this SDK symbol.
unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

const PROGRAM: &str = "/usr/bin/sandbox-exec";
// Public Darwin sys/spawn.h flag; not exposed by the pinned libc crate.
const POSIX_SPAWN_SETSID: libc::c_int = 0x0400;
const PROFILE: &str = include_str!("macos.sb");

// A profile-child process launches exactly one Agent. Signals may be delivered
// on another runtime thread; only this atomic flag is touched by the handler.
static PROFILE_TERMINATION: AtomicBool = AtomicBool::new(false);

extern "C" fn profile_terminate(_: libc::c_int) {
    PROFILE_TERMINATION.store(true, Ordering::Relaxed);
}

pub(super) struct ProfileTermination {
    previous: libc::sigaction,
    installed: bool,
}

impl ProfileTermination {
    pub(super) fn install() -> io::Result<Self> {
        // SAFETY: both sigaction buffers are valid. The handler only performs a
        // lock-free atomic store and never allocates, locks or uses stdio.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = profile_terminate as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous = MaybeUninit::uninit();
            PROFILE_TERMINATION.store(false, Ordering::Relaxed);
            if libc::sigaction(libc::SIGTERM, &action, previous.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                previous: previous.assume_init(),
                installed: true,
            })
        }
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        if self.installed {
            // SAFETY: restore the exact disposition returned at installation.
            if unsafe { libc::sigaction(libc::SIGTERM, &self.previous, ptr::null_mut()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.installed = false;
        }
        Ok(())
    }
}

impl Drop for ProfileTermination {
    fn drop(&mut self) {
        // Normal/error returns restore explicitly so an error prevents the
        // cleanup acknowledgement. This is only the unwinding fallback.
        if let Err(error) = self.restore() {
            tracing::error!(event = "launcher.signal_restore_failed", %error);
        }
    }
}

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

pub(super) fn prepare(
    state: &Path,
    socket: &Path,
    argv: &[OsString],
    mut env: Vec<(OsString, OsString)>,
    profile_gateway: Option<Option<NonZeroU16>>,
) -> Result<PreparedLaunch, BrokerError> {
    let profile_child = profile_gateway.is_some();
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
    if profile_child {
        super::profile::private_environment(&mut env, &scratch_path);
        for leaf in ["codex", "claude", "claude-tmp"] {
            fs::create_dir(scratch_path.join(leaf)).map_err(BrokerError::Io)?;
            fs::set_permissions(scratch_path.join(leaf), fs::Permissions::from_mode(0o700))
                .map_err(BrokerError::Io)?;
        }
    }
    let mut policy = PROFILE.to_owned();
    if profile_child {
        policy.push_str("\n(allow file-write* (subpath (param \"CODE\")))\n");
    }
    if profile_gateway.flatten().is_some() {
        policy.push_str("(allow system-socket (socket-domain AF_INET))\n(allow network-outbound (remote tcp (param \"GATEWAY\")))\n");
    }
    let mut args = vec!["-p".into(), policy.into()];
    if let Some(port) = profile_gateway.flatten() {
        args.extend(["-D".into(), format!("GATEWAY=localhost:{port}").into()]);
    }
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
        cwd: if profile_child { code } else { scratch_path },
        scratch,
        profile_child,
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
    let cwd = cstring(prepared.cwd.as_os_str())?;
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
        let result = (|| -> io::Result<Option<libc::pid_t>> {
            checked(libc::posix_spawnattr_setflags(
                &mut attr,
                (libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                    | if prepared.profile_child {
                        POSIX_SPAWN_SETSID
                    } else {
                        0
                    }) as i16,
            ))?;
            if !prepared.profile_child {
                checked(libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    0,
                    c"/dev/null".as_ptr(),
                    libc::O_RDONLY,
                    0,
                ))?;
            }
            for fd in (if prepared.profile_child { 0 } else { 1 })..=2 {
                super::profile::check_stdio_fd(fd)?;
                checked(libc::posix_spawn_file_actions_adddup2(&mut actions, fd, fd))?;
            }
            checked(posix_spawn_file_actions_addchdir_np(
                &mut actions,
                cwd.as_ptr(),
            ))?;
            if prepared.profile_child && PROFILE_TERMINATION.load(Ordering::Relaxed) {
                return Ok(None);
            }
            let mut pid = 0;
            checked(libc::posix_spawn(
                &mut pid,
                argv[0].as_ptr(),
                &actions,
                &attr,
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            ))?;
            Ok(Some(pid))
        })();
        libc::posix_spawn_file_actions_destroy(&mut actions);
        libc::posix_spawnattr_destroy(&mut attr);
        let Some(pid) = result? else {
            // No Agent was started; run_profile still closes scratch and
            // restores the handler before acknowledging TERM with exit 143.
            return Ok(128 + libc::SIGTERM);
        };
        let mut status = 0;
        let mut terminated = false;
        loop {
            let waited = libc::waitpid(
                pid,
                &mut status,
                if prepared.profile_child {
                    libc::WNOHANG
                } else {
                    0
                },
            );
            if waited == pid {
                break;
            }
            if waited < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
            if prepared.profile_child {
                if !terminated && PROFILE_TERMINATION.load(Ordering::Relaxed) {
                    // pid is our unreaped child, so it cannot have been reused.
                    // Only that direct child is stopped, never a process group.
                    if libc::kill(pid, libc::SIGKILL) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    terminated = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if terminated {
            Ok(128 + libc::SIGTERM)
        } else if libc::WIFEXITED(status) {
            Ok(libc::WEXITSTATUS(status))
        } else if prepared.profile_child && libc::WIFSIGNALED(status) {
            Ok(128 + libc::WTERMSIG(status))
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
    fn profile_term_during_prepare_does_not_spawn_and_restores_handler() {
        const CHILD: &str = "REKEY_PROFILE_TERM_PREPARE_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "sandbox::macos::tests::profile_term_during_prepare_does_not_spawn_and_restores_handler"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, ptr::null(), &mut previous) },
            0
        );
        let mut termination = ProfileTermination::install().unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let agent = root.path().join("agent");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&agent).unwrap();
        let socket = agent.join("agent.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let marker = root.path().join("must-not-start");
        let plan = prepare(
            &state.canonicalize().unwrap(),
            &socket.canonicalize().unwrap(),
            &["/usr/bin/touch".into(), marker.as_os_str().to_owned()],
            vec![],
            Some(None),
        )
        .unwrap();
        let scratch = plan.scratch.path().to_owned();
        assert_eq!(super::super::finish(plan).unwrap(), 143);
        assert!(!marker.exists());
        assert!(!scratch.exists());
        termination.restore().unwrap();
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction, previous.sa_sigaction);
        assert_eq!(after.sa_mask, previous.sa_mask);
        assert_eq!(after.sa_flags, previous.sa_flags);
    }

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
            None,
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
