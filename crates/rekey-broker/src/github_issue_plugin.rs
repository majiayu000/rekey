//! Fixed macOS reference sidecar, not a general plugin registration system.
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use rekey_connector::github_issue::{MAX_ISSUE_WIRE_BYTES, normalize_issue_body};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::error::BrokerError;

const PROFILE: &str = include_str!("github_issue_plugin.sb");
const MAX_ARTIFACT: u64 = 32 * 1024 * 1024;
const MAX_RSS: u64 = 64 * 1024 * 1024;

fn denied(reason: &'static str) -> BrokerError {
    BrokerError::Denied(reason)
}

fn packaged_artifact() -> Result<PathBuf, BrokerError> {
    let exe = std::env::current_exe().map_err(BrokerError::Io)?;
    let mut directory = exe.parent().ok_or_else(|| denied("plugin-artifact-path"))?;
    // Cargo test/example hosts share the same built package directory.
    if matches!(
        directory.file_name().and_then(|s| s.to_str()),
        Some("deps" | "examples")
    ) {
        directory = directory
            .parent()
            .ok_or_else(|| denied("plugin-artifact-path"))?;
    }
    Ok(directory.join("rekey-github-create-issue"))
}

/// Only the public body crosses the process boundary. The result cannot alter
/// any approved parameter: the trusted Broker checks the complete canonical body.
pub(crate) async fn normalize(input: &[u8], deadline: Instant) -> Result<Vec<u8>, BrokerError> {
    normalize_with_artifact(&packaged_artifact()?, input, deadline).await
}

async fn normalize_with_artifact(
    artifact: &Path,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, BrokerError> {
    let expected = normalize_issue_body(input).map_err(|_| denied("plugin-invalid-input"))?;
    let output = run(artifact, input, deadline).await?;
    if output != expected {
        return Err(denied("plugin-output-mismatch"));
    }
    Ok(output)
}

/// Copy an opened artifact to a private immutable-for-the-child execution file.
/// This pins this execution's bytes, not the provenance of an installed package.
fn snapshot(artifact: &Path) -> Result<(tempfile::TempDir, PathBuf), BrokerError> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(artifact)
        .map_err(BrokerError::Io)?;
    let meta = source.metadata().map_err(BrokerError::Io)?;
    if !meta.is_file() || meta.len() > MAX_ARTIFACT || meta.permissions().mode() & 0o111 == 0 {
        return Err(denied("plugin-artifact-invalid"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut source)
        .take(MAX_ARTIFACT + 1)
        .read_to_end(&mut bytes)
        .map_err(BrokerError::Io)?;
    if bytes.len() as u64 > MAX_ARTIFACT {
        return Err(denied("plugin-artifact-too-large"));
    }
    let directory = tempfile::Builder::new()
        .prefix("rekey-issue-plugin-")
        .tempdir_in("/private/tmp")
        .map_err(BrokerError::Io)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .map_err(BrokerError::Io)?;
    let path = directory.path().join("plugin");
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&path)
        .map_err(BrokerError::Io)?;
    copy.write_all(&bytes).map_err(BrokerError::Io)?;
    drop(copy);
    if Sha256::digest(fs::read(&path).map_err(BrokerError::Io)?) != Sha256::digest(&bytes) {
        return Err(denied("plugin-artifact-mismatch"));
    }
    Ok((directory, path))
}

async fn run(artifact: &Path, input: &[u8], deadline: Instant) -> Result<Vec<u8>, BrokerError> {
    if input.len() > MAX_ISSUE_WIRE_BYTES {
        return Err(denied("plugin-input-too-large"));
    }
    if Instant::now() >= deadline {
        return Err(denied("plugin-deadline"));
    }
    let (_snapshot, executable) = snapshot(artifact)?;
    let mut command = launch_command(&executable, deadline)?;
    let mut child = command.spawn().map_err(BrokerError::Io)?;
    let pid = child.id().ok_or_else(|| denied("plugin-spawn"))? as i32;
    let mut stdin = child.stdin.take().ok_or_else(|| denied("plugin-stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| denied("plugin-stdout"))?;
    let exchange = async {
        let write = async {
            stdin.write_all(input).await.map_err(BrokerError::Io)?;
            stdin.shutdown().await.map_err(BrokerError::Io)?;
            drop(stdin);
            Ok::<_, BrokerError>(())
        };
        let read = async {
            let mut output = Vec::new();
            stdout
                .take((MAX_ISSUE_WIRE_BYTES + 1) as u64)
                .read_to_end(&mut output)
                .await
                .map_err(BrokerError::Io)?;
            if output.len() > MAX_ISSUE_WIRE_BYTES {
                return Err(denied("plugin-output-too-large"));
            }
            Ok(output)
        };
        let (_, output) = tokio::try_join!(write, read)?;
        Ok::<_, BrokerError>(output)
    };
    let result = {
        let completed = async {
            let (output, status) = tokio::try_join!(exchange, async {
                child.wait().await.map_err(BrokerError::Io)
            })?;
            if !status.success() {
                return Err(denied("plugin-exit"));
            }
            Ok(output)
        };
        tokio::pin!(completed);
        tokio::select! {
            result = &mut completed => result,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Err(denied("plugin-deadline")),
            result = monitor_memory(pid) => Err(result),
        }
    };
    if result.is_err() {
        // start_kill followed by wait reaps even when the error was EOF/limit.
        // A process which already exited requires no signal, but is still reaped.
        child.start_kill().map_err(BrokerError::Io)?;
        child.wait().await.map_err(BrokerError::Io)?;
    }
    result
}

fn launch_command(executable: &Path, deadline: Instant) -> Result<Command, BrokerError> {
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

async fn monitor_memory(pid: i32) -> BrokerError {
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

#[cfg(test)]
#[path = "github_issue_plugin_tests.rs"]
mod tests;
