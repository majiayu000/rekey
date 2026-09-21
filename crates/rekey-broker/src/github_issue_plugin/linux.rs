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
    // Broker PID captured before spawn. The reaper is armed before exec; bwrap is
    // left alive so that reaper can still see its children and SIGKILL the tree.
    // PDEATHSIG and --die-with-parent kill only the outer process, which is the
    // bubblewrap startup race (containers/bubblewrap#633).
    // SAFETY: getpid is an async-signal-safe query of this process.
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
            // Own process group so a later group kill cannot include the broker.
            let _ = libc::setpgid(0, 0);
            arm_descendant_reaper(parent)?;
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
            Ok(())
        });
    }
    Ok(command)
}

#[used(linker)]
#[link_section = ".init_array.00001"]
static REAPER_HOOK: unsafe extern "C" fn() = plugin_reaper_hook;

unsafe extern "C" fn plugin_reaper_hook() {
    let value = libc::getenv(c"REKEY_PLUGIN_REAPER".as_ptr());
    if value.is_null() || libc::strcmp(value, c"v1".as_ptr()) != 0 {
        return;
    }
    let mut raw = [0u8; 512];
    let fd = libc::open(c"/proc/self/cmdline".as_ptr(), libc::O_RDONLY);
    if fd < 0 {
        libc::_exit(127);
    }
    let n = libc::read(fd, raw.as_mut_ptr().cast(), raw.len());
    libc::close(fd);
    if n <= 0 {
        libc::_exit(127);
    }
    let bytes = &raw[..n as usize];
    let mut args = [std::ptr::null::<u8>(); 6];
    let mut count = 0usize;
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            if count < args.len() {
                args[count] = bytes[start..].as_ptr();
                count += 1;
            }
            start = index + 1;
        }
    }
    if count < 6 || !arg_eq(args[1], b"rekey.plugin.reaper.v1\0") {
        libc::_exit(127);
    }
    let Some(broker_pidfd) = parse_i32(args[2]) else {
        libc::_exit(127);
    };
    let Some(launcher_pidfd) = parse_i32(args[3]) else {
        libc::_exit(127);
    };
    let Some(launcher) = parse_i32(args[4]) else {
        libc::_exit(127);
    };
    let Some(ready_fd) = parse_i32(args[5]) else {
        libc::_exit(127);
    };
    let armed = 1u8;
    if libc::write(ready_fd, (&armed as *const u8).cast(), 1) != 1 {
        libc::_exit(127);
    }
    libc::close(ready_fd);
    reap_until_launcher_gone(broker_pidfd, launcher_pidfd, launcher);
    libc::_exit(0);
}

fn arg_eq(arg: *const u8, expected: &[u8]) -> bool {
    if arg.is_null() {
        return false;
    }
    for (index, byte) in expected.iter().enumerate() {
        if unsafe { *arg.add(index) } != *byte {
            return false;
        }
    }
    true
}

fn parse_i32(arg: *const u8) -> Option<i32> {
    if arg.is_null() {
        return None;
    }
    let mut value: i32 = 0;
    let mut index = 0usize;
    loop {
        let byte = unsafe { *arg.add(index) };
        if byte == 0 {
            return if index == 0 { None } else { Some(value) };
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
        index += 1;
        if index > 10 {
            return None;
        }
    }
}

fn reap_until_launcher_gone(broker_pidfd: i32, launcher_pidfd: i32, launcher: i32) {
    let mut known = [0i32; 96];
    let mut len = 0usize;
    let mut fds = [
        libc::pollfd {
            fd: broker_pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: launcher_pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        collect_descendants(launcher, &mut known, &mut len);
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
        if ready < 0 {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::EINTR {
                continue;
            }
            break;
        }
        if ready == 0 {
            continue;
        }
        let broker_gone = fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
        if broker_gone {
            // The launcher is still running, so its children remain listed.
            collect_descendants(launcher, &mut known, &mut len);
            signal_group(launcher);
            kill_pids(&known[..len]);
            unsafe { libc::kill(launcher, libc::SIGKILL) };
            kill_pids(&known[..len]);
        } else {
            // Launcher already exited (normal finish or direct SIGKILL). Kill only
            // the pids recorded while it was alive; do not signal the process
            // group, because that id can be reused.
            kill_pids(&known[..len]);
        }
        break;
    }
}

fn kill_pids(pids: &[i32]) {
    for pid in pids.iter().copied() {
        if pid > 1 {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

fn signal_group(launcher: i32) {
    let group = unsafe { libc::getpgid(launcher) };
    let own = unsafe { libc::getpgrp() };
    if group > 1 && group != own {
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
}

fn collect_descendants(root: i32, known: &mut [i32; 96], len: &mut usize) {
    let mut stack = [0i32; 96];
    let mut depth = 1usize;
    stack[0] = root;
    let self_pid = unsafe { libc::getpid() };
    while depth > 0 {
        depth -= 1;
        let pid = stack[depth];
        let mut children = [0i32; 32];
        let count = read_children(pid, &mut children);
        for child in children[..count].iter().copied() {
            if child <= 1 || child == self_pid || known[..*len].contains(&child) {
                continue;
            }
            if *len == known.len() || depth == stack.len() {
                unsafe { libc::kill(child, libc::SIGKILL) };
                continue;
            }
            known[*len] = child;
            *len += 1;
            stack[depth] = child;
            depth += 1;
        }
    }
}

fn read_children(pid: i32, out: &mut [i32; 32]) -> usize {
    let mut dir_path = [0u8; 64];
    if write_proc_path(&mut dir_path, pid, b"/task").is_none() {
        return 0;
    }
    let dir = unsafe { libc::opendir(dir_path.as_ptr().cast()) };
    if dir.is_null() {
        return 0;
    }
    let mut count = 0usize;
    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { (*entry).d_name.as_ptr() };
        if name.is_null() {
            continue;
        }
        let Some(tid) = parse_i32(name.cast()) else {
            continue;
        };
        let mut child_path = [0u8; 80];
        if write_proc_task_children(&mut child_path, pid, tid).is_none() {
            continue;
        }
        let fd = unsafe { libc::open(child_path.as_ptr().cast(), libc::O_RDONLY) };
        if fd < 0 {
            continue;
        }
        let mut raw = [0u8; 256];
        let n = unsafe { libc::read(fd, raw.as_mut_ptr().cast(), raw.len()) };
        unsafe { libc::close(fd) };
        if n <= 0 {
            continue;
        }
        let mut number: i32 = 0;
        let mut in_number = false;
        for byte in &raw[..n as usize] {
            if byte.is_ascii_digit() {
                in_number = true;
                number = number
                    .saturating_mul(10)
                    .saturating_add(i32::from(byte - b'0'));
            } else if in_number {
                if count < out.len() {
                    out[count] = number;
                    count += 1;
                } else {
                    unsafe { libc::kill(number, libc::SIGKILL) };
                }
                number = 0;
                in_number = false;
            }
        }
        if in_number {
            if count < out.len() {
                out[count] = number;
                count += 1;
            } else {
                unsafe { libc::kill(number, libc::SIGKILL) };
            }
        }
    }
    unsafe { libc::closedir(dir) };
    count
}

fn write_proc_path(buf: &mut [u8], pid: i32, suffix: &[u8]) -> Option<()> {
    write_prefix(buf, b"/proc/", pid, suffix)
}

fn write_proc_task_children(buf: &mut [u8], pid: i32, tid: i32) -> Option<()> {
    let mut prefix = [0u8; 48];
    write_prefix(&mut prefix, b"/proc/", pid, b"/task/")?;
    let prefix_len = prefix.iter().position(|byte| *byte == 0)?;
    let mut tid_buf = [0u8; 16];
    let tid_n = decimal(tid, &mut tid_buf)?;
    let suffix = b"/children";
    if prefix_len + tid_n + suffix.len() + 1 > buf.len() {
        return None;
    }
    buf[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    buf[prefix_len..prefix_len + tid_n].copy_from_slice(&tid_buf[..tid_n]);
    let end = prefix_len + tid_n;
    buf[end..end + suffix.len()].copy_from_slice(suffix);
    buf[end + suffix.len()] = 0;
    Some(())
}

fn write_prefix(buf: &mut [u8], head: &[u8], pid: i32, suffix: &[u8]) -> Option<()> {
    let mut pid_buf = [0u8; 16];
    let pid_n = decimal(pid, &mut pid_buf)?;
    if head.len() + pid_n + suffix.len() + 1 > buf.len() {
        return None;
    }
    buf[..head.len()].copy_from_slice(head);
    buf[head.len()..head.len() + pid_n].copy_from_slice(&pid_buf[..pid_n]);
    let end = head.len() + pid_n;
    buf[end..end + suffix.len()].copy_from_slice(suffix);
    buf[end + suffix.len()] = 0;
    Some(())
}

fn decimal(value: i32, buf: &mut [u8]) -> Option<usize> {
    if value < 0 || buf.len() < 2 {
        return None;
    }
    let mut digits = [0u8; 16];
    let mut n = 0usize;
    let mut rest = value;
    loop {
        digits[n] = b'0' + (rest % 10) as u8;
        n += 1;
        rest /= 10;
        if rest == 0 || n == digits.len() {
            break;
        }
    }
    if n > buf.len() {
        return None;
    }
    for (index, digit) in digits[..n].iter().rev().enumerate() {
        buf[index] = *digit;
    }
    Some(n)
}

fn pid_alive(pid: i32) -> bool {
    let mut path = [0u8; 64];
    if write_proc_path(&mut path, pid, b"/stat").is_none() {
        return false;
    }
    let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY) };
    if fd < 0 {
        return false;
    }
    let mut raw = [0u8; 256];
    let n = unsafe { libc::read(fd, raw.as_mut_ptr().cast(), raw.len()) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return false;
    }
    let bytes = &raw[..n as usize];
    let Some(split) = bytes.windows(2).rposition(|pair| pair == b") ") else {
        return true;
    };
    !bytes[split + 2..].starts_with(b"Z")
}

unsafe fn arm_descendant_reaper(broker: i32) -> io::Result<()> {
    let broker_pidfd = libc::syscall(libc::SYS_pidfd_open, broker, 0);
    if broker_pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let launcher_pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
    if launcher_pidfd < 0 {
        libc::close(broker_pidfd as i32);
        return Err(io::Error::last_os_error());
    }
    if libc::fcntl(broker_pidfd as i32, libc::F_SETFD, 0) < 0
        || libc::fcntl(launcher_pidfd as i32, libc::F_SETFD, 0) < 0
    {
        libc::close(broker_pidfd as i32);
        libc::close(launcher_pidfd as i32);
        return Err(io::Error::last_os_error());
    }
    let mut handshake = [0; 2];
    // The reaper writes one armed byte after exec. CLOEXEC would close the
    // pipe during exec and look like success before the hook runs.
    if libc::pipe2(handshake.as_mut_ptr(), 0) != 0 {
        libc::close(broker_pidfd as i32);
        libc::close(launcher_pidfd as i32);
        return Err(io::Error::last_os_error());
    }
    let launcher_pid = libc::getpid();
    let middle = libc::fork();
    if middle < 0 {
        libc::close(handshake[0]);
        libc::close(handshake[1]);
        libc::close(broker_pidfd as i32);
        libc::close(launcher_pidfd as i32);
        return Err(io::Error::last_os_error());
    }
    if middle == 0 {
        let grand = libc::fork();
        if grand != 0 {
            libc::_exit(if grand < 0 { 127 } else { 0 });
        }
        libc::close(handshake[0]);
        if libc::setsid() < 0 {
            let _ = libc::write(handshake[1], (&1u8 as *const u8).cast(), 1);
            libc::_exit(127);
        }
        let _ = libc::prctl(libc::PR_SET_PDEATHSIG, 0);
        close_except(&[handshake[1], broker_pidfd as i32, launcher_pidfd as i32]);
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            for target in 0..3 {
                if target != handshake[1]
                    && target != broker_pidfd as i32
                    && target != launcher_pidfd as i32
                {
                    libc::dup2(devnull, target);
                }
            }
            if devnull > 2 {
                libc::close(devnull);
            }
        }
        let mut exe = [0u8; 4096];
        let n = libc::readlink(
            c"/proc/self/exe".as_ptr(),
            exe.as_mut_ptr().cast(),
            exe.len() - 1,
        );
        if n < 0 {
            let _ = libc::write(handshake[1], (&1u8 as *const u8).cast(), 1);
            libc::_exit(127);
        }
        exe[n as usize] = 0;
        let mut broker_fd = [0u8; 16];
        let mut launcher_fd = [0u8; 16];
        let mut launcher_text = [0u8; 16];
        let mut ready_fd = [0u8; 16];
        if decimal(broker_pidfd as i32, &mut broker_fd).is_none()
            || decimal(launcher_pidfd as i32, &mut launcher_fd).is_none()
            || decimal(launcher_pid, &mut launcher_text).is_none()
            || decimal(handshake[1], &mut ready_fd).is_none()
        {
            let failed = 2u8;
            let _ = libc::write(handshake[1], (&failed as *const u8).cast(), 1);
            libc::_exit(127);
        }
        let marker = c"rekey.plugin.reaper.v1".as_ptr().cast_mut();
        let env = c"REKEY_PLUGIN_REAPER=v1".as_ptr();
        let mut argv = [
            exe.as_mut_ptr().cast::<libc::c_char>(),
            marker,
            broker_fd.as_mut_ptr().cast(),
            launcher_fd.as_mut_ptr().cast(),
            launcher_text.as_mut_ptr().cast(),
            ready_fd.as_mut_ptr().cast(),
            std::ptr::null_mut(),
        ];
        let mut envp = [env.cast_mut(), std::ptr::null_mut()];
        libc::execve(exe.as_ptr().cast(), argv.as_mut_ptr(), envp.as_mut_ptr());
        let failed = 2u8;
        let _ = libc::write(handshake[1], (&failed as *const u8).cast(), 1);
        libc::_exit(127);
    }
    libc::close(handshake[1]);
    libc::close(broker_pidfd as i32);
    libc::close(launcher_pidfd as i32);
    let mut status = 0;
    loop {
        let waited = libc::waitpid(middle, &mut status, 0);
        if waited < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            libc::close(handshake[0]);
            return Err(io::Error::last_os_error());
        }
        break;
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        libc::close(handshake[0]);
        return Err(io::Error::other("plugin descendant reaper failed to fork"));
    }
    let mut result = [0u8; 1];
    loop {
        let n = libc::read(handshake[0], result.as_mut_ptr().cast(), 1);
        if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        libc::close(handshake[0]);
        if n == 1 && result[0] == 1 {
            return Ok(());
        }
        return Err(io::Error::other("plugin descendant reaper failed to exec"));
    }
}

unsafe fn close_except(keep: &[i32]) {
    let mut fd = 0i32;
    while fd < 256 {
        if !keep.contains(&fd) {
            libc::close(fd);
        }
        fd += 1;
    }
    let _ = libc::syscall(libc::SYS_close_range, 256u32, u32::MAX, 0u32);
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
