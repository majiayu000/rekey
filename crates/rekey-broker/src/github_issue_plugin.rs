//! Native sandboxed GitHub issue operations protocol with an optional Admin-pinned artifact.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use data_encoding::HEXLOWER;
use rekey_connector::github_issue::{IssueOperation, MAX_ISSUE_WIRE_BYTES};
use rekey_domain::action::NativePlugin;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::BrokerError;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::launch_command;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::launch_command;
const MAX_ARTIFACT: u64 = 32 * 1024 * 1024;

fn denied(reason: &'static str) -> BrokerError {
    BrokerError::Denied(reason)
}

#[cfg(target_os = "macos")]
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

/// Only the operation and public body cross the process boundary. The result cannot alter
/// any approved parameter: the trusted Broker checks the complete canonical envelope.
pub(crate) async fn normalize(
    registration: Option<&NativePlugin>,
    operation: IssueOperation,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, BrokerError> {
    match registration {
        Some(plugin) => {
            normalize_with_artifact(
                Path::new(&plugin.path),
                Some(&plugin.sha256),
                operation,
                input,
                deadline,
            )
            .await
        }
        #[cfg(target_os = "macos")]
        None => {
            normalize_with_artifact(&packaged_artifact()?, None, operation, input, deadline).await
        }
        #[cfg(target_os = "linux")]
        None => operation
            .normalize_body(input)
            .map_err(|_| denied("github-profile-mismatch")),
    }
}

pub(crate) async fn normalize_anthropic(
    registration: &NativePlugin,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, BrokerError> {
    if registration.protocol != rekey_domain::action::ANTHROPIC_MESSAGES_PROTOCOL {
        return Err(denied("plugin-protocol-mismatch"));
    }
    let (expected, body) = rekey_connector::anthropic_message::prepare(input)
        .map_err(|_| denied("plugin-invalid-input"))?;
    let output = run(
        Path::new(&registration.path),
        Some(&registration.sha256),
        &expected,
        deadline,
    )
    .await?;
    if output != expected {
        return Err(denied("plugin-output-mismatch"));
    }
    Ok(body)
}

async fn normalize_with_artifact(
    artifact: &Path,
    expected_sha256: Option<&str>,
    operation: IssueOperation,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, BrokerError> {
    let (expected, body) = operation
        .prepare(input)
        .map_err(|_| denied("plugin-invalid-input"))?;
    let output = run(artifact, expected_sha256, &expected, deadline).await?;
    if output != expected {
        return Err(denied("plugin-output-mismatch"));
    }
    Ok(body)
}

/// Copy an opened artifact to a private immutable-for-the-child execution file.
/// Explicit registrations first require these bytes to match the Admin digest.
/// The packaged default pins only this execution, not package provenance.
fn snapshot(
    artifact: &Path,
    expected_sha256: Option<&str>,
) -> Result<(tempfile::TempDir, PathBuf), BrokerError> {
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
    let digest = Sha256::digest(&bytes);
    if let Some(expected) = expected_sha256
        && HEXLOWER.encode(&digest) != expected
    {
        return Err(denied("plugin-artifact-digest-mismatch"));
    }
    #[cfg(target_os = "macos")]
    let temp_root = "/private/tmp";
    #[cfg(target_os = "linux")]
    let temp_root = "/tmp";
    let directory = tempfile::Builder::new()
        .prefix("rekey-issue-plugin-")
        .tempdir_in(temp_root)
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
    if Sha256::digest(fs::read(&path).map_err(BrokerError::Io)?) != digest {
        return Err(denied("plugin-artifact-mismatch"));
    }
    Ok((directory, path))
}

async fn run(
    artifact: &Path,
    expected_sha256: Option<&str>,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, BrokerError> {
    if input.len() > MAX_ISSUE_WIRE_BYTES {
        return Err(denied("plugin-input-too-large"));
    }
    if Instant::now() >= deadline {
        return Err(denied("plugin-deadline"));
    }
    let (_snapshot, executable) = snapshot(artifact, expected_sha256)?;
    let mut command = launch_command(&executable, deadline)?;
    let mut child = command.spawn().map_err(BrokerError::Io)?;
    #[cfg(target_os = "macos")]
    let memory_monitor =
        macos::monitor_memory(child.id().ok_or_else(|| denied("plugin-spawn"))? as i32);
    #[cfg(target_os = "linux")]
    let memory_monitor = std::future::pending::<BrokerError>();
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
            result = memory_monitor => Err(result),
        }
    };
    if result.is_err() {
        // Reap the launcher; Linux PID namespace teardown kills its payload too.
        // A process which already exited requires no signal, but is still reaped.
        child.start_kill().map_err(BrokerError::Io)?;
        child.wait().await.map_err(BrokerError::Io)?;
    }
    result
}

#[cfg(all(test, target_os = "macos"))]
#[path = "github_issue_plugin_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "github_issue_plugin/linux_tests.rs"]
mod linux_tests;
