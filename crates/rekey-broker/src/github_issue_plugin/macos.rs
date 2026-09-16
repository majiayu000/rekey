//! Existing Seatbelt backend; resource and FD behavior is unchanged.
use super::{BrokerError, denied};
use std::io;
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

const PROFILE: &str = include_str!("../github_issue_plugin.sb");
const MAX_RSS: u64 = 64 * 1024 * 1024;

pub(super) fn launch_command(executable: &Path, deadline: Instant) -> Result<Command, BrokerError> {
    let mut parameter = std::ffi::OsString::from("EXEC=");
    parameter.push(executable);
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", PROFILE, "-D"])
        .arg(parameter)
        .arg("--")
        .arg(executable)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // Snapshot every existing FD, including descriptors above a lowered limit.
    // Trusted Broker threads do not concurrently create non-CLOEXEC descriptors;
    // Rust/Tokio's subsequent spawn pipes and sockets are created CLOEXEC.
    let inherited_fds = inherited_descriptors()?;
    if Instant::now() >= deadline {
        return Err(denied("plugin-deadline"));
    }
    // SAFETY: no allocation, locks, or Rust runtime calls in the post-fork closure.
    unsafe {
        command.pre_exec(move || {
            for (resource, limit) in [
                (
                    libc::RLIMIT_CPU,
                    libc::rlimit {
                        rlim_cur: 1,
                        rlim_max: 2,
                    },
                ),
                (
                    libc::RLIMIT_CORE,
                    libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    },
                ),
            ] {
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for fd in inherited_fds.iter().copied() {
                if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0
                    && *libc::__error() != libc::EBADF
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(command)
}

// Capture high descriptors which survived a previous lowering of soft/hard
// limits. Broker code does not concurrently raise limits or inject high FDs.
fn inherited_descriptors() -> Result<Vec<i32>, BrokerError> {
    const SLOTS: usize = 65_536;
    let mut descriptors = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0
        };
        SLOTS
    ];
    let size = std::mem::size_of_val(descriptors.as_slice());
    // SAFETY: initialized, correctly aligned output array, bounded C byte count.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            descriptors.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if written <= 0
        || written as usize >= size
        || !(written as usize).is_multiple_of(std::mem::size_of::<libc::proc_fdinfo>())
    {
        return Err(denied("plugin-fd-snapshot"));
    }
    descriptors.truncate(written as usize / std::mem::size_of::<libc::proc_fdinfo>());
    Ok(descriptors
        .into_iter()
        .map(|entry| entry.proc_fd)
        .filter(|fd| *fd >= 3)
        .collect())
}

pub(super) async fn monitor_memory(pid: i32) -> BrokerError {
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut usage = MaybeUninit::<libc::rusage_info_v0>::uninit();
        // SAFETY: flavor 0 writes exactly rusage_info_v0 to live output storage.
        let result = unsafe { libc::proc_pid_rusage(pid, 0, usage.as_mut_ptr().cast()) };
        if result != 0 {
            let error = io::Error::last_os_error();
            // The wait future owns exit status. A vanished PID has no live RSS.
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return denied("plugin-resource-query");
        }
        // SAFETY: proc_pid_rusage succeeded.
        if unsafe { usage.assume_init() }.ri_resident_size > MAX_RSS {
            return denied("plugin-memory-budget");
        }
    }
}
