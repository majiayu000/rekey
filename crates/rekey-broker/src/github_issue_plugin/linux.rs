//! Explicit GNU Linux artifacts in a fixed, read-only bubblewrap root.
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use tokio::process::Command;

use super::{BrokerError, denied};

#[cfg(target_arch = "x86_64")]
const RUNTIME_FILES: [&str; 4] = [
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
];
#[cfg(target_arch = "aarch64")]
const RUNTIME_FILES: [&str; 4] = [
    "/lib/ld-linux-aarch64.so.1",
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib/aarch64-linux-gnu/libm.so.6",
    "/lib/aarch64-linux-gnu/libgcc_s.so.1",
];

pub(super) fn launch_command(executable: &Path, deadline: Instant) -> Result<Command, BrokerError> {
    require_unprivileged_bwrap()?;
    let filter = filter_file()?;
    let mut command = Command::new("/usr/bin/bwrap");
    command.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--new-session",
        "--clearenv",
        "--die-with-parent",
    ]);
    for path in RUNTIME_FILES {
        command.args(["--ro-bind", path, path]);
    }
    command
        .arg("--ro-bind")
        .arg(executable)
        .arg("/plugin")
        .args(["--chdir", "/", "--remount-ro", "/", "--seccomp"])
        .arg(filter.as_raw_fd().to_string())
        .args(["--", "/plugin"])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if Instant::now() >= deadline {
        return Err(denied("plugin-deadline"));
    }
    // Broker PID at spawn-prep time; the child checks getppid against this after
    // installing PDEATHSIG so a dead parent cannot leave an unregistered first hop.
    // SAFETY: getpid is an async-signal-safe query of this process.
    let parent = unsafe { libc::getpid() };
    // The closure owns the file until spawn completes. Only its FD survives exec
    // into bwrap, which consumes and closes it before starting the plugin.
    // SAFETY: only async-signal-safe libc operations, no allocation or locks.
    unsafe {
        command.pre_exec(move || {
            for (resource, soft, hard) in [
                (libc::RLIMIT_CPU, 1, 2),
                (libc::RLIMIT_CORE, 0, 0),
                (libc::RLIMIT_AS, 64 * 1024 * 1024, 64 * 1024 * 1024),
                (libc::RLIMIT_NOFILE, 128, 128),
            ] {
                if libc::setrlimit(
                    resource,
                    &libc::rlimit {
                        rlim_cur: soft,
                        rlim_max: hard,
                    },
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            // Unlike scanning up to NOFILE, this includes descriptors that were
            // opened above a subsequently lowered hard limit.
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
                || libc::fcntl(filter.as_raw_fd(), libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    Ok(command)
}

fn require_unprivileged_bwrap() -> Result<(), BrokerError> {
    let metadata = std::fs::symlink_metadata("/usr/bin/bwrap").map_err(BrokerError::Io)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o6000 != 0 {
        return Err(denied("plugin-spawn"));
    }
    let mut probe = [0u8; 1];
    // Parent-side check, not pre_exec: lgetxattr may not be async-signal-safe.
    // SAFETY: path and attribute names are static C strings; the buffer is stack-local.
    let result = unsafe {
        libc::lgetxattr(
            c"/usr/bin/bwrap".as_ptr(),
            c"security.capability".as_ptr(),
            probe.as_mut_ptr().cast(),
            probe.len(),
        )
    };
    if result > 0 {
        return Err(denied("plugin-spawn"));
    }
    if result == 0 {
        return Ok(());
    }
    let errno = io::Error::last_os_error().raw_os_error();
    if errno == Some(libc::ENODATA)
        || errno == Some(libc::ENOTSUP)
        || errno == Some(libc::EOPNOTSUPP)
    {
        Ok(())
    } else {
        Err(denied("plugin-spawn"))
    }
}

fn filter_file() -> Result<File, BrokerError> {
    let mut file = tempfile::tempfile().map_err(BrokerError::Io)?;
    for (code, jt, jf, value) in filter_program() {
        file.write_all(&code.to_ne_bytes())
            .map_err(BrokerError::Io)?;
        file.write_all(&[jt, jf]).map_err(BrokerError::Io)?;
        file.write_all(&value.to_ne_bytes())
            .map_err(BrokerError::Io)?;
    }
    file.seek(SeekFrom::Start(0)).map_err(BrokerError::Io)?;
    Ok(file)
}

fn filter_program() -> Vec<(u16, u8, u8, u32)> {
    const LOAD_WORD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const EQUAL: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RETURN: u16 = 0x06; // BPF_RET | BPF_K
    const KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
    const ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    let mut filter = vec![
        (LOAD_WORD, 0, 0, 4), // seccomp_data.arch
        (EQUAL, 1, 0, ARCH),
        (RETURN, 0, 0, KILL),
        (LOAD_WORD, 0, 0, 0), // seccomp_data.nr
    ];
    #[cfg(target_arch = "x86_64")]
    filter.extend([(0x35, 0, 1, 0x4000_0000), (RETURN, 0, 0, KILL)]); // reject x32
    // Permit rlimit queries only; never let the payload mutate the reaper's limits.
    // A non-prlimit syscall skips the complete terminating argument check.
    filter.extend([
        (EQUAL, 0, 6, libc::SYS_prlimit64 as u32),
        (LOAD_WORD, 0, 0, 32), // args[2], new_limit low word
        (EQUAL, 0, 3, 0),
        (LOAD_WORD, 0, 0, 36), // new_limit high word
        (EQUAL, 0, 1, 0),
        (RETURN, 0, 0, ALLOW),
        (RETURN, 0, 0, 0x0005_0000 | libc::EPERM as u32),
    ]);
    // Loader, single-threaded GNU C/Rust, and bwrap's trusted PID 1 reaper.
    // No creation of tasks, sockets, namespaces, mounts, anonymous executables,
    // cross-process access, io_uring, seccomp changes, or execveat.
    let allowed = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_openat,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getcwd,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_ppoll,
        libc::SYS_rt_sigsuspend,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_kill,
        libc::SYS_tgkill,
    ];
    for nr in allowed {
        filter.extend([(EQUAL, 0, 1, nr as u32), (RETURN, 0, 0, ALLOW)]);
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [
        libc::SYS_arch_prctl,
        libc::SYS_access,
        libc::SYS_readlink,
        libc::SYS_poll,
    ] {
        filter.extend([(EQUAL, 0, 1, nr as u32), (RETURN, 0, 0, ALLOW)]);
    }
    filter.push((RETURN, 0, 0, 0x0005_0000 | libc::EPERM as u32));
    filter
}
