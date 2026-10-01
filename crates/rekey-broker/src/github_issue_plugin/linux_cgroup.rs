//! Mandatory delegated cgroup-v2 containment. Pure parsers also run on Darwin.
use std::io;

fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn absolute_path(path: &str) -> io::Result<()> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.contains('\n')
        || path.contains('\r')
        || path
            .split('/')
            .skip(1)
            .any(|v| v == "." || v == ".." || v.is_empty())
            && path != "/"
    {
        return Err(invalid());
    }
    Ok(())
}

fn mount_path(encoded: &str) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut input = encoded.bytes();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let escape = [input.next(), input.next(), input.next()];
        let value = match escape {
            [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
            [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
            [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
            _ => return Err(invalid()),
        };
        bytes.push(value);
    }
    let path = String::from_utf8(bytes).map_err(|_| invalid())?;
    absolute_path(&path)?;
    Ok(path)
}

fn delegated_path(cgroup: &str, mounts: &str) -> io::Result<String> {
    for line in cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or_else(invalid)?;
        let controllers = fields.next().ok_or_else(invalid)?;
        let path = fields.next().ok_or_else(invalid)?;
        absolute_path(path)?;
        if (hierarchy == 0) != controllers.is_empty() {
            return Err(invalid());
        }
    }
    let mut paths = cgroup.lines().filter_map(|line| line.strip_prefix("0::"));
    let current = paths.next().ok_or_else(invalid)?;
    absolute_path(current)?;
    if current == "/" || paths.next().is_some() {
        return Err(invalid());
    }
    let mut selected = None;
    for line in mounts.lines() {
        let (before, after) = line.split_once(" - ").ok_or_else(invalid)?;
        if after.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = before.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(invalid());
        }
        let root = mount_path(fields[3])?;
        let mount = mount_path(fields[4])?;
        let relative = if root == "/" {
            &current[1..]
        } else if current == root {
            ""
        } else if let Some(relative) = current.strip_prefix(&(root + "/")) {
            relative
        } else {
            continue;
        };
        if selected.is_some() {
            return Err(invalid());
        }
        selected = Some(if relative.is_empty() {
            mount
        } else {
            format!("{mount}/{relative}")
        });
    }
    selected.ok_or_else(invalid)
}

fn require_memory(text: &str) -> io::Result<()> {
    if text.split_whitespace().any(|v| v == "memory") {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn validate_limits(max: &str, swap: &str, group: &str) -> io::Result<()> {
    if max.trim() == "67108864" && swap.trim() == "0" && group.trim() == "1" {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn populated(text: &str) -> io::Result<bool> {
    let mut result = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("populated ") {
            if result.is_some() {
                return Err(invalid());
            }
            result = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err(invalid()),
            });
        }
    }
    result.ok_or_else(invalid)
}
// Round up so sub-millisecond budget remains usable; every EINTR recomputes this.
pub(super) fn remaining_millis(end_ns: i64, now_ns: i64) -> Option<i32> {
    let remaining = end_ns.checked_sub(now_ns)?;
    if remaining <= 0 {
        None
    } else {
        Some(((remaining - 1) / 1_000_000 + 1).min(i64::from(i32::MAX)) as i32)
    }
}
pub(super) fn validate_ack(count: isize, byte: u8, dead: bool) -> io::Result<()> {
    if count == 1 && byte == 1 && !dead {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(target_os = "linux")]
mod kernel {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Instant;

    static ROOT: OnceLock<Result<Arc<File>, i32>> = OnceLock::new();
    static NEXT: AtomicU64 = AtomicU64::new(0);
    const CONTROL: &CStr = c"rekey-control";

    pub(in crate::github_issue_plugin) fn clock_ns() -> io::Result<i64> {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes one initialized timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
            return Err(io::Error::last_os_error());
        }
        value
            .tv_sec
            .checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(value.tv_nsec))
            .ok_or_else(invalid)
    }
    pub(in crate::github_issue_plugin) fn deadline_ns(deadline: Instant) -> io::Result<i64> {
        // Sample monotonic first: conversion must never extend the original budget.
        let now = clock_ns()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout)?;
        now.checked_add(i64::try_from(remaining.as_nanos()).map_err(|_| invalid())?)
            .ok_or_else(invalid)
    }
    pub(in crate::github_issue_plugin) fn timeout() -> io::Error {
        io::Error::from_raw_os_error(libc::ETIMEDOUT)
    }
    pub(in crate::github_issue_plugin) fn budget(end: i64) -> io::Result<i32> {
        remaining_millis(end, clock_ns()?).ok_or_else(timeout)
    }

    fn own_fd(fd: i32) -> io::Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Keep manager descriptors away from child's stdio remapping.
        let high = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if high < 0 {
            return Err(error);
        }
        Ok(unsafe { File::from_raw_fd(high) })
    }
    pub(in crate::github_issue_plugin) fn pipe() -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let first = own_fd(fds[0]);
        let second = own_fd(fds[1]);
        Ok((first?, second?))
    }
    pub(in crate::github_issue_plugin) fn ack_socket() -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let first = own_fd(fds[0]);
        let second = own_fd(fds[1]);
        Ok((first?, second?))
    }
    fn open_at(dir: i32, name: &CStr, flags: i32) -> io::Result<File> {
        own_fd(unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })
    }
    fn open_directory(path: &str) -> io::Result<File> {
        let mut current = open_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY)?;
        for component in path.split('/').skip(1) {
            let name = CString::new(component).map_err(|_| invalid())?;
            current = open_at(
                current.as_raw_fd(),
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
        }
        Ok(current)
    }
    pub(in crate::github_issue_plugin) fn read_fd(fd: i32, bytes: &mut [u8]) -> io::Result<usize> {
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n >= 0 {
            Ok(n as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn read_at(root: &File, name: &CStr) -> io::Result<String> {
        let file = open_at(root.as_raw_fd(), name, libc::O_RDONLY)?;
        let mut raw = [0; 8192];
        let n = read_fd(file.as_raw_fd(), &mut raw)?;
        if n == raw.len() {
            return Err(invalid());
        }
        String::from_utf8(raw[..n].to_vec()).map_err(|_| invalid())
    }
    pub(in crate::github_issue_plugin) fn write_fd(fd: i32, value: &[u8]) -> io::Result<()> {
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = unsafe { libc::write(fd, value.as_ptr().cast(), value.len()) };
        if n == value.len() as isize {
            Ok(())
        } else if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(invalid())
        }
    }

    fn write_at(root: &File, name: &CStr, value: &[u8]) -> io::Result<()> {
        let file = open_at(root.as_raw_fd(), name, libc::O_WRONLY)?;
        write_fd(file.as_raw_fd(), value)
    }
    fn make_directory(root: &File, name: &CStr) -> io::Result<File> {
        if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        match open_at(root.as_raw_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(file) => Ok(file),
            Err(error) => {
                let _ = remove(root.as_raw_fd(), name);
                Err(error)
            }
        }
    }
    fn initialize() -> io::Result<Arc<File>> {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 || unsafe { libc::getuid() } != uid {
            return Err(invalid());
        }
        let path = delegated_path(
            &std::fs::read_to_string("/proc/self/cgroup")?,
            &std::fs::read_to_string("/proc/self/mountinfo")?,
        )?;
        let root = open_directory(&path)?;
        let metadata = root.metadata()?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { stat.assume_init() }.f_type != 0x6367_7270 || metadata.uid() != uid {
            return Err(invalid());
        }
        if read_at(&root, c"cgroup.type")?.trim() != "domain" {
            return Err(invalid());
        }
        let pid = unsafe { libc::getpid() }.to_string();
        if read_at(&root, c"cgroup.procs")?
            .split_whitespace()
            .collect::<Vec<_>>()
            != [pid.as_str()]
        {
            return Err(invalid());
        }
        // A dedicated delegation starts with no child domains. /proc/self/fd
        // resolves this already pinned descriptor, never an inferred parent.
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))? {
            if entry?.file_type()?.is_dir() {
                return Err(invalid());
            }
        }
        require_memory(&read_at(&root, c"cgroup.controllers")?)?;
        let control = make_directory(&root, CONTROL)?;
        write_at(&control, c"cgroup.procs", pid.as_bytes())?;
        write_at(&root, c"cgroup.subtree_control", b"+memory")?;
        require_memory(&read_at(&root, c"cgroup.subtree_control")?)?;
        Ok(Arc::new(root))
    }
    fn root() -> io::Result<Arc<File>> {
        // Cache failure too: initialization may already have moved the Broker.
        // A later call must never rediscover control as a new delegated root.
        let saved = ROOT.get_or_init(|| {
            initialize().map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
        });
        let root = match saved {
            Ok(root) => Arc::clone(root),
            Err(errno) => return Err(io::Error::from_raw_os_error(*errno)),
        };
        let control = open_at(
            root.as_raw_fd(),
            CONTROL,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let pid = unsafe { libc::getpid() }.to_string();
        if !read_at(&control, c"cgroup.procs")?
            .split_whitespace()
            .any(|v| v == pid)
        {
            return Err(invalid());
        }
        Ok(root)
    }
    pub(in crate::github_issue_plugin) struct Payload {
        pub(in crate::github_issue_plugin) root: Arc<File>,
        pub(in crate::github_issue_plugin) name: CString,
        pub(in crate::github_issue_plugin) membership: File,
        pub(in crate::github_issue_plugin) kill: File,
        pub(in crate::github_issue_plugin) events: File,
    }
    pub(in crate::github_issue_plugin) fn prepare(end: i64) -> io::Result<Payload> {
        budget(end)?;
        let root = root()?;
        budget(end)?;
        let name = CString::new(format!(
            "rekey-payload-{}-{}",
            unsafe { libc::getpid() },
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
        .map_err(|_| invalid())?;
        let directory = make_directory(&root, &name)?;
        let prepared = (|| {
            write_at(&directory, c"memory.max", b"67108864")?;
            write_at(&directory, c"memory.swap.max", b"0")?;
            write_at(&directory, c"memory.oom.group", b"1")?;
            validate_limits(
                &read_at(&directory, c"memory.max")?,
                &read_at(&directory, c"memory.swap.max")?,
                &read_at(&directory, c"memory.oom.group")?,
            )?;
            let membership = open_at(directory.as_raw_fd(), c"cgroup.procs", libc::O_WRONLY)?;
            let kill = open_at(directory.as_raw_fd(), c"cgroup.kill", libc::O_WRONLY)?;
            let events = open_at(directory.as_raw_fd(), c"cgroup.events", libc::O_RDONLY)?;
            budget(end)?;
            Ok((membership, kill, events))
        })();
        match prepared {
            Ok((membership, kill, events)) => Ok(Payload {
                root,
                name,
                membership,
                kill,
                events,
            }),
            Err(error) => {
                let _ = remove(root.as_raw_fd(), &name);
                Err(error)
            }
        }
    }
    pub(in crate::github_issue_plugin) fn remove(root: i32, name: &CStr) -> io::Result<()> {
        if unsafe { libc::unlinkat(root, name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub(in crate::github_issue_plugin) fn empty(events: i32) -> io::Result<bool> {
        let mut raw = [0; 512];
        let n = read_fd(events, &mut raw)?;
        if n == raw.len() {
            return Err(invalid());
        }
        Ok(!populated(
            std::str::from_utf8(&raw[..n]).map_err(|_| invalid())?,
        )?)
    }
    pub(in crate::github_issue_plugin) fn kill_and_drain(
        kill: i32,
        events: i32,
        end: i64,
    ) -> io::Result<()> {
        write_fd(kill, b"1")?;
        loop {
            budget(end)?;
            if empty(events)? {
                return Ok(());
            }
            let delay = budget(end)?.min(10);
            if unsafe { libc::poll(std::ptr::null_mut(), 0, delay) } < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINTR) {
                    return Err(error);
                }
            }
        }
    }
}
#[cfg(target_os = "linux")]
pub(super) use kernel::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_and_escaped_identity() {
        assert_eq!(
            delegated_path(
                "0::/broker\n",
                "31 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
            )
            .unwrap(),
            "/sys/fs/cgroup/broker"
        );
        for input in ["0::/\n", "0::/broker/../other\n", "0::/broker\n0::/other\n"] {
            assert!(
                delegated_path(
                    input,
                    "31 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
                )
                .is_err()
            );
        }
    }
    #[test]
    fn malformed_proc_records_rejected() {
        for input in [
            "0::/broker\nbroken\n",
            "0:memory:/broker\n",
            "x:cpu:/old\n0::/broker\n",
        ] {
            assert!(
                delegated_path(
                    input,
                    "31 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
                )
                .is_err(),
                "{input:?}"
            );
        }
    }
    #[test]
    fn mount_subroot_and_escaped_mountpoint_are_bound_exactly() {
        assert_eq!(
            delegated_path(
                "0::/delegated/broker\n",
                "31 23 0:27 /delegated /cg\\040mount rw - cgroup2 cgroup rw\n"
            )
            .unwrap(),
            "/cg mount/broker"
        );
        assert!(
            delegated_path(
                "0::/delegated-other/broker\n",
                "31 23 0:27 /delegated /cg rw - cgroup2 cgroup rw\n"
            )
            .is_err()
        );
        assert!(
            delegated_path(
                "0::/broker\n",
                "31 23 0:27 / /a rw - cgroup2 cgroup rw\n32 23 0:27 / /b rw - cgroup2 cgroup rw\n"
            )
            .is_err()
        );
    }
    #[test]
    fn malformed_mount_and_escape_are_rejected() {
        for mount in [
            "bad",
            "31 23 0:27 / /cg\\012mount rw - cgroup2 cgroup rw",
            "31 23 0:27 / /cg/../outside rw - cgroup2 cgroup rw",
            "31 23 0:27 / /cg\\041 rw - cgroup2 cgroup rw",
        ] {
            assert!(delegated_path("0::/broker\n", mount).is_err(), "{mount}");
        }
    }
    #[test]
    fn events_missing_or_invalid_population_is_an_error() {
        for events in [
            "frozen 0\n",
            "populated max\n",
            "populated 2\n",
            "populated 0\npopulated 0\n",
        ] {
            assert!(populated(events).is_err(), "{events:?}");
        }
    }
    #[test]
    fn every_required_limit_and_controller_is_exact() {
        for (max, swap, group) in [
            ("67108863", "0", "1"),
            ("67108864", "1", "1"),
            ("67108864", "0", "0"),
            ("67108864 extra", "0", "1"),
        ] {
            assert!(validate_limits(max, swap, group).is_err());
        }
        assert!(require_memory("cpu memory io\n").is_ok());
        assert!(require_memory("cpu memory_extra io").is_err());
    }
    #[test]
    fn deadline_rounding_and_overflow_never_extend_budget() {
        assert_eq!(remaining_millis(1, 0), Some(1));
        assert_eq!(remaining_millis(1, 2), None);
        assert_eq!(remaining_millis(i64::MAX, -1), None);
        assert_eq!(remaining_millis(i64::MAX, 0), Some(i32::MAX));
    }
    #[test]
    fn partial_or_extra_ack_is_rejected() {
        for count in [-1, 0, 2] {
            assert!(validate_ack(count, 1, false).is_err());
        }
        assert!(validate_ack(1, 0, false).is_err());
    }
    #[test]
    fn limits_and_controller_fail_closed() {
        assert!(validate_limits("67108864\n", "0\n", "1\n").is_ok());
        assert!(validate_limits("max\n", "0\n", "1\n").is_err());
        assert!(validate_limits("67108864\n", "max\n", "1\n").is_err());
        assert!(require_memory("cpu io").is_err());
    }
    #[test]
    fn original_deadline_is_not_reset_by_interruptions() {
        assert_eq!(remaining_millis(100_000_000, 1), Some(100));
        assert_eq!(remaining_millis(100_000_000, 99_000_000), Some(1));
        assert_eq!(remaining_millis(100_000_000, 100_000_000), None);
    }
    #[test]
    fn ack_eof_and_population_state_are_distinct() {
        assert!(validate_ack(1, 1, false).is_ok());
        for (count, byte, dead) in [(0, 0, false), (1, 2, false), (1, 1, true)] {
            assert!(validate_ack(count, byte, dead).is_err());
        }
        assert!(populated("populated 0\nfrozen 0\n").is_ok_and(|v| !v));
        assert!(populated("populated 1\n").is_ok_and(|v| v));
        assert!(populated("populated 0\npopulated 1\n").is_err());
    }
}
