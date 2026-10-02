//! Explicit GNU Linux artifacts in a fixed, read-only bubblewrap root.
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use tokio::process::Command;

use super::{BrokerError, denied, linux_cgroup as cgroup, linux_tree::KillPluginTree};

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

pub(super) fn launch_command(
    executable: &Path,
    deadline: Instant,
) -> Result<(Command, KillPluginTree), BrokerError> {
    let end = cgroup::deadline_ns(deadline).map_err(launch_error)?;
    require_unprivileged_bwrap()?;
    let filter = filter_file()?;
    let (tree, ready, lifetime) = KillPluginTree::prepare(end).map_err(launch_error)?;
    let fds = GuardianFds {
        ack: tree.ack.as_raw_fd(),
        ready: ready.as_raw_fd(),
        lifetime: lifetime.as_raw_fd(),
        kill: tree.payload.kill.as_raw_fd(),
        events: tree.payload.events.as_raw_fd(),
        root: tree.payload.root.as_raw_fd(),
        membership: tree.payload.membership.as_raw_fd(),
    };
    let name = tree.payload.name.clone();
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
    // All allocation, cgroup initialization and FD binding precede pre_exec.
    // SAFETY: getpid is an async-signal-safe query.
    let parent = unsafe { libc::getpid() };
    let _ = REAPER_HOOK;
    // The closure owns the file until spawn completes. Only its FD survives exec
    // into bwrap, which consumes and closes it before starting the plugin.
    // SAFETY: only async-signal-safe libc operations, no allocation or locks.
    unsafe {
        command.pre_exec(move || {
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            let _keep_files_alive = (&ready, &lifetime);
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            let guardian = arm_descendant_reaper(parent, fds, &name, end)?;
            guardian_alive(guardian, end)?;
            // Membership is established before bwrap can fork even its init.
            cgroup::write_fd(fds.membership, b"0")?;
            guardian_alive(guardian, end)?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
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
            guardian_alive(guardian, end)?;
            libc::close(guardian);
            Ok(())
        });
    }
    Ok((command, tree))
}

#[used]
#[unsafe(link_section = ".init_array.00001")]
static REAPER_HOOK: unsafe extern "C" fn() = plugin_reaper_hook;

pub(super) fn launch_error(error: io::Error) -> BrokerError {
    if error.raw_os_error() == Some(libc::ETIMEDOUT) {
        denied("plugin-deadline")
    } else {
        BrokerError::Io(error)
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn plugin_reaper_hook() {
    let value = libc::getenv(c"REKEY_PLUGIN_REAPER".as_ptr());
    if value.is_null() || libc::strcmp(value, c"v2".as_ptr()) != 0 {
        return;
    }
    let mut raw = [0u8; 1024];
    let fd = libc::open(c"/proc/self/cmdline".as_ptr(), libc::O_RDONLY);
    if fd < 0 {
        libc::_exit(127);
    }
    let n = libc::read(fd, raw.as_mut_ptr().cast(), raw.len());
    libc::close(fd);
    if n <= 0 || n == raw.len() as isize {
        libc::_exit(127);
    }
    let mut args = [std::ptr::null::<u8>(); 11];
    let mut count = 0usize;
    let mut start = 0usize;
    for (index, byte) in raw[..n as usize].iter().enumerate() {
        if *byte == 0 {
            if count >= args.len() {
                libc::_exit(127);
            }
            args[count] = raw[start..].as_ptr();
            count += 1;
            start = index + 1;
        }
    }
    if count != args.len() || !arg_eq(args[1], b"rekey.plugin.reaper.v2\0") {
        libc::_exit(127);
    }
    let mut numbers = [0i64; 8];
    for (value, arg) in numbers.iter_mut().zip(&args[2..10]) {
        let Some(number) = parse_number(*arg) else {
            libc::_exit(127);
        };
        *value = number;
    }
    if numbers[..7].iter().any(|v| *v > i64::from(i32::MAX)) {
        libc::_exit(127);
    }
    let [broker, launcher, ready, lifetime, kill, events, root, end] = numbers;
    let name = std::ffi::CStr::from_ptr(args[10].cast());
    if !name.to_bytes().starts_with(b"rekey-payload-") || name.to_bytes().contains(&b'/') {
        libc::_exit(127);
    }
    if cgroup::empty(events as i32).is_err() || cgroup::budget(end).is_err() {
        guardian_cleanup(kill as i32, events as i32, root as i32, name);
        libc::_exit(127);
    }
    if send_armed(ready as i32).is_err() {
        guardian_cleanup(kill as i32, events as i32, root as i32, name);
        libc::_exit(127);
    }
    // Keep ACK writer alive for the complete lifetime, not just one armed byte.
    let mut fds = [
        libc::pollfd {
            fd: broker as i32,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: launcher as i32,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: lifetime as i32,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    while let Ok(budget) = cgroup::budget(end) {
        let ready = libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, budget);
        if ready < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if ready < 0 {
            break;
        }
        if fds[0].revents != 0 || fds[2].revents != 0 {
            break;
        }
        if fds[1].revents != 0 {
            // Kill immediately when the launcher exits, but retain ACK and the
            // empty leaf until the live Broker verifies drain and closes its
            // lifetime pipe. Normal launcher exit is not guardian failure.
            if cgroup::write_fd(kill as i32, b"1").is_err() {
                break;
            }
            fds[1].fd = -1;
        }
    }
    guardian_cleanup(kill as i32, events as i32, root as i32, name);
    libc::_exit(0);
}

fn guardian_cleanup(kill: i32, events: i32, root: i32, name: &std::ffi::CStr) {
    // Cleanup remains bounded even after the execution deadline. A nonempty
    // leaf is left in the kernel; this path never publishes plugin success.
    if let Ok(now) = cgroup::clock_ns()
        && cgroup::kill_and_drain(kill, events, now.saturating_add(2_000_000_000)).is_ok()
    {
        let _ = cgroup::remove(root, name);
    }
}
fn arg_eq(arg: *const u8, expected: &[u8]) -> bool {
    !arg.is_null()
        && expected
            .iter()
            .enumerate()
            .all(|(index, byte)| unsafe { *arg.add(index) == *byte })
}
fn parse_number(arg: *const u8) -> Option<i64> {
    if arg.is_null() {
        return None;
    }
    let mut value = 0i64;
    for index in 0..20 {
        let byte = unsafe { *arg.add(index) };
        if byte == 0 {
            return (index > 0).then_some(value);
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
    }
    None
}
fn decimal(value: i64, buf: &mut [u8; 24]) -> Option<()> {
    if value < 0 {
        return None;
    }
    let mut digits = [0u8; 24];
    let mut n = 0;
    let mut rest = value;
    loop {
        digits[n] = b'0' + (rest % 10) as u8;
        n += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for (index, digit) in digits[..n].iter().rev().enumerate() {
        buf[index] = *digit;
    }
    Some(())
}

#[derive(Clone, Copy)]
struct GuardianFds {
    ack: i32,
    ready: i32,
    lifetime: i32,
    kill: i32,
    events: i32,
    root: i32,
    membership: i32,
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn arm_descendant_reaper(
    broker: i32,
    fds: GuardianFds,
    name: &std::ffi::CStr,
    end: i64,
) -> io::Result<i32> {
    let broker_pidfd = libc::syscall(libc::SYS_pidfd_open, broker, 0) as i32;
    if broker_pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let launcher_pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32;
    if launcher_pidfd < 0 {
        libc::close(broker_pidfd);
        return Err(io::Error::last_os_error());
    }
    let middle = libc::fork();
    if middle < 0 {
        libc::close(broker_pidfd);
        libc::close(launcher_pidfd);
        return Err(io::Error::last_os_error());
    }
    if middle == 0 {
        let grand = libc::fork();
        if grand != 0 {
            libc::_exit(if grand < 0 { 127 } else { 0 });
        }
        if libc::setsid() < 0 {
            libc::_exit(127);
        }
        let keep = [
            broker_pidfd,
            launcher_pidfd,
            fds.ready,
            fds.lifetime,
            fds.kill,
            fds.events,
            fds.root,
        ];
        if close_except(&keep).is_err() {
            libc::_exit(127);
        }
        for fd in keep {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                libc::_exit(127);
            }
        }
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull < 0 {
            libc::_exit(127);
        }
        for target in 0..3 {
            if !keep.contains(&target) && libc::dup2(devnull, target) < 0 {
                libc::_exit(127);
            }
        }
        if devnull > 2 {
            libc::close(devnull);
        }
        let mut exe = [0u8; 4096];
        let n = libc::readlink(
            c"/proc/self/exe".as_ptr(),
            exe.as_mut_ptr().cast(),
            exe.len() - 1,
        );
        if n < 0 {
            libc::_exit(127);
        }
        exe[n as usize] = 0;
        let mut values = [[0u8; 24]; 8];
        for (buffer, number) in values.iter_mut().zip([
            i64::from(broker_pidfd),
            i64::from(launcher_pidfd),
            i64::from(fds.ready),
            i64::from(fds.lifetime),
            i64::from(fds.kill),
            i64::from(fds.events),
            i64::from(fds.root),
            end,
        ]) {
            if decimal(number, buffer).is_none() {
                libc::_exit(127);
            }
        }
        let argv = [
            exe.as_ptr().cast(),
            c"rekey.plugin.reaper.v2".as_ptr(),
            values[0].as_ptr().cast(),
            values[1].as_ptr().cast(),
            values[2].as_ptr().cast(),
            values[3].as_ptr().cast(),
            values[4].as_ptr().cast(),
            values[5].as_ptr().cast(),
            values[6].as_ptr().cast(),
            values[7].as_ptr().cast(),
            name.as_ptr(),
            std::ptr::null(),
        ];
        let envp = [c"REKEY_PLUGIN_REAPER=v2".as_ptr(), std::ptr::null()];
        libc::execve(exe.as_ptr().cast(), argv.as_ptr(), envp.as_ptr());
        libc::_exit(127);
    }
    libc::close(broker_pidfd);
    libc::close(launcher_pidfd);
    libc::close(fds.ready);
    libc::close(fds.lifetime);
    let mut status = 0;
    loop {
        let budget = match cgroup::budget(end) {
            Ok(budget) => budget,
            Err(error) => {
                libc::kill(middle, libc::SIGKILL);
                let _ = libc::waitpid(middle, &mut status, libc::WNOHANG);
                return Err(error);
            }
        };
        let waited = libc::waitpid(middle, &mut status, libc::WNOHANG);
        if waited == middle {
            break;
        }
        if waited < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(io::Error::last_os_error());
        }
        libc::poll(std::ptr::null_mut(), 0, budget.min(1));
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::from_raw_os_error(libc::ECHILD));
    }
    let mut fd = libc::pollfd {
        fd: fds.ack,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let budget = cgroup::budget(end)?;
        let ready = libc::poll(&mut fd, 1, budget);
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            return Err(cgroup::timeout());
        }
        let guardian = match receive_armed(fds.ack, fd.revents) {
            Ok(guardian) => guardian,
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => return Err(error),
        };
        if let Err(error) = guardian_alive(guardian, end) {
            libc::close(guardian);
            return Err(error);
        }
        return Ok(guardian);
    }
}
// The parent's pre-spawn copy of the ACK writer prevents reliable startup EOF.
// Pass the execed guardian's own pidfd atomically with ACK, so launcher gates
// cannot accept a byte from an already dead guardian even during spawn.
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn send_armed(socket: i32) -> io::Result<()> {
    let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32;
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut byte = 1u8;
    let mut data = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = std::mem::zeroed();
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
    let header = libc::CMSG_FIRSTHDR(&message);
    (*header).cmsg_level = libc::SOL_SOCKET;
    (*header).cmsg_type = libc::SCM_RIGHTS;
    (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
    std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), pidfd);
    let n = libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL);
    let error = io::Error::last_os_error();
    libc::close(pidfd);
    if n == 1 { Ok(()) } else { Err(error) }
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn receive_armed(socket: i32, revents: i16) -> io::Result<i32> {
    let mut byte = 0;
    let mut data = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = std::mem::zeroed();
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let n = libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC);
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let header = libc::CMSG_FIRSTHDR(&message);
    if header.is_null()
        || (*header).cmsg_level != libc::SOL_SOCKET
        || (*header).cmsg_type != libc::SCM_RIGHTS
        || (*header).cmsg_len != libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize
    {
        return Err(io::Error::from_raw_os_error(libc::EPROTO));
    }
    let pidfd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>());
    if let Err(error) = cgroup::validate_ack(
        n,
        byte,
        revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0,
    ) {
        libc::close(pidfd);
        return Err(error);
    }
    Ok(pidfd)
}

fn guardian_alive(ack: i32, end: i64) -> io::Result<()> {
    cgroup::budget(end)?;
    let mut fd = libc::pollfd {
        fd: ack,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut fd, 1, 0) };
        if ready < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            cgroup::budget(end)?;
            continue;
        }
        if ready == 0 {
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(libc::EPIPE));
    }
}
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn close_except(keep: &[i32]) -> io::Result<()> {
    for fd in 0..256 {
        if !keep.contains(&fd) {
            libc::close(fd);
        }
    }
    // FDs above 255 can include pre-opened cgroup handles. Mark CLOEXEC then
    // explicitly retain only the listed manager handles through guardian exec.
    if libc::syscall(
        libc::SYS_close_range,
        256u32,
        u32::MAX,
        libc::CLOSE_RANGE_CLOEXEC,
    ) != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
