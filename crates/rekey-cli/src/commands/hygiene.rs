//! File contents travel only in bounded Agent frame bodies. Import is daemon-owned.
use std::io::Read;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rekey_domain::ipc::{self, Channel, ProofKind, ScanMeta, ScanResponse, agent_msg};
use serde_json::json;
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

const FILE_LIMIT: usize = 10 * 1024 * 1024;
const TOTAL_LIMIT: usize = 100 * 1024 * 1024;
fn usage(message: &str) -> CliError {
    CliError::local("USAGE", message)
}
fn git_bytes(arguments: &[&std::ffi::OsStr], limit: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut child = Command::new("git")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| usage("cannot run git"))?;
    let result = super::read_bounded(
        child
            .stdout
            .take()
            .ok_or_else(|| usage("cannot read git output"))?,
        limit,
        "git output",
    );
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| usage("cannot wait for git"))?;
    let bytes = result?;
    if !status.success() {
        return Err(usage("git could not read the repository or staged content"));
    }
    Ok(bytes)
}
fn repository_files(staged: bool) -> Result<Vec<PathBuf>, CliError> {
    let arguments: Vec<_> = if staged {
        vec![
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ]
    } else {
        vec![
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ]
    }
    .into_iter()
    .map(std::ffi::OsStr::new)
    .collect();
    git_bytes(&arguments, TOTAL_LIMIT)?
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| {
            std::str::from_utf8(name)
                .map(PathBuf::from)
                .map_err(|_| usage("staged paths must be UTF-8"))
        })
        .collect()
}
fn collect(path: &Path, paths: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| usage("cannot inspect scan path"))?;
    if metadata.is_file() {
        paths.push(path.to_owned());
        return Ok(());
    }
    if metadata.file_type().is_symlink() {
        return Err(usage("scan paths must not be symlinks"));
    }
    if !metadata.is_dir() {
        return Err(usage("scan paths must be regular files or directories"));
    }
    let mut entries: Vec<_> = std::fs::read_dir(path)
        .map_err(|_| usage("cannot read scan directory"))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| usage("cannot read scan directory entry"))
        })
        .collect::<Result<_, _>>()?;
    entries.sort();
    for entry in entries {
        if std::fs::symlink_metadata(&entry)
            .map_err(|_| usage("cannot inspect scan directory entry"))?
            .file_type()
            .is_symlink()
        {
            continue;
        }
        collect(&entry, paths)?;
    }
    Ok(())
}
fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| usage("cannot open scan file without following symlinks"))?;
    if !file
        .metadata()
        .map_err(|_| usage("cannot inspect scan file"))?
        .is_file()
    {
        return Err(usage("scan input must be a regular file"));
    }
    super::read_bounded(file, FILE_LIMIT, "scan file")
}
fn scan_one(socket: &Path, path: String, bytes: &[u8]) -> Result<ScanResponse, CliError> {
    let metadata =
        serde_json::to_vec(&ScanMeta { path }).map_err(|_| usage("cannot encode scan path"))?;
    let (metadata, body) =
        Client::connect(socket, Channel::Agent)?.call(agent_msg::SCAN, &metadata, bytes)?;
    if serde_json::from_slice::<serde_json::Value>(&metadata).ok() != Some(json!({})) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "scan metadata must be empty",
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid scan findings"))
}
pub fn scan(
    socket: &Path,
    paths: Vec<PathBuf>,
    staged: bool,
    stdin: bool,
    strict: bool,
) -> Result<(), CliError> {
    let mut inputs = Vec::new();
    if staged || (paths.is_empty() && !stdin) {
        inputs = repository_files(staged)?;
    } else {
        for path in paths {
            collect(&path, &mut inputs)?;
        }
    }
    let mut findings = Vec::new();
    let mut total = 0usize;
    let stdin_bytes = if stdin {
        Some(super::read_bounded(
            std::io::stdin().lock(),
            FILE_LIMIT,
            "scan stdin",
        )?)
    } else {
        None
    };
    let mut run_one = |path: String, bytes: &[u8]| -> Result<(), CliError> {
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| usage("scan total exceeds 100 MiB"))?;
        if total > TOTAL_LIMIT {
            return Err(usage("scan total exceeds 100 MiB"));
        }
        findings.extend(scan_one(socket, path, bytes)?.findings);
        Ok(())
    };
    let result: Result<(), CliError> = (|| {
        if let Some(bytes) = &stdin_bytes {
            run_one("<stdin>".into(), bytes)?;
        }
        for path in inputs {
            let name = path
                .to_str()
                .ok_or_else(|| usage("scan paths must be UTF-8"))?;
            let bytes = if staged {
                git_bytes(
                    &[
                        std::ffi::OsStr::new("cat-file"),
                        std::ffi::OsStr::new("blob"),
                        std::ffi::OsStr::new(&format!(":{name}")),
                    ],
                    FILE_LIMIT,
                )?
            } else {
                read_file(&path)?
            };
            run_one(name.into(), &bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        if staged && !strict && error.code == "LOCKED" {
            eprintln!(
                "Warning: Rekey is locked; staged credentials could not be scanned. Unlock Rekey or use --strict to block the commit."
            );
            return super::write_json(&json!([]));
        }
        return Err(error);
    }
    super::write_json(&findings)?;
    if !findings.is_empty() {
        return Err(CliError::local(
            "LEAK_DETECTED",
            "credential material was detected; replace it with rekey call or a local service placeholder",
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvPreviewEntry {
    key: String,
    preset_hint: Option<String>,
    unsupported_protocol: Option<String>,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct UnsupportedEnvEntry {
    line: u64,
    key: Option<String>,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvPreview {
    entries: Vec<EnvPreviewEntry>,
    unsupported: Vec<UnsupportedEnvEntry>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvSelection {
    key: String,
    label: String,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvReplacement {
    key: String,
    connection: String,
    base_url_variable: String,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvImportedEntry {
    key: String,
    credential: rekey_domain::credential::CredentialMetadata,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvImportReport {
    entries: Vec<EnvImportedEntry>,
    unsupported: Vec<UnsupportedEnvEntry>,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EnvRewriteReceipt {
    backup: PathBuf,
}

/// Agent-call 7.3: the backup keeps the original values, so the receipt says
/// whether git ignores it. Git runs only inside a repository, without reading
/// the index, and is stopped after five seconds.
fn backup_git(backup: &Path) -> &'static str {
    let (Some(directory), Some(name)) = (backup.parent(), backup.file_name()) else {
        return "unknown";
    };
    if !directory
        .ancestors()
        .any(|parent| parent.join(".git").symlink_metadata().is_ok())
    {
        return "no-repository";
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = std::env::var_os("PATH");
    let Some(git) = git_program(path.as_deref(), || developer_dir(deadline)) else {
        return "unknown";
    };
    // The "./" prefix keeps a name that starts with ':' from being read as
    // pathspec magic; check-ignore refuses GIT_LITERAL_PATHSPECS.
    let Ok(mut child) = Command::new(git)
        .arg("-C")
        .arg(directory)
        .args(["check-ignore", "-q", "--no-index", "--"])
        .arg(Path::new(".").join(name))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return "unknown";
    };
    match wait_until(&mut child, deadline).and_then(|status| status.code()) {
        Some(0) => "ignored",
        Some(1) => "not-ignored",
        _ => "unknown",
    }
}

/// The git `backup_git` runs, found on PATH here so that the check and the
/// spawn agree; relative PATH entries are skipped. On macOS /usr/bin/git is an
/// xcode-select shim: without developer tools it asks to install them and
/// exits 1, which would read as not-ignored, so it runs only when the selected
/// developer directory has a git to forward to.
fn git_program(
    path: Option<&std::ffi::OsStr>,
    developer_dir: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    let program = std::env::split_paths(path?)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("git"))
        .find(|candidate| executable(candidate))?;
    if cfg!(target_os = "macos") && program == Path::new("/usr/bin/git") {
        let tools = developer_dir()?;
        if !["usr/bin/git", "Contents/Developer/usr/bin/git"]
            .iter()
            .any(|git| executable(&tools.join(git)))
        {
            return None;
        }
    }
    Some(program)
}

fn executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

/// `xcode-select -p` prints the selected developer directory (DEVELOPER_DIR
/// first) without prompting, even when that directory does not exist.
fn developer_dir(deadline: Instant) -> Option<PathBuf> {
    let mut child = Command::new("/usr/bin/xcode-select")
        .arg("-p")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let status = wait_until(&mut child, deadline)?;
    let mut output = Vec::new();
    child
        .stdout
        .take()?
        .take(4096)
        .read_to_end(&mut output)
        .ok()?;
    let directory = PathBuf::from(String::from_utf8(output).ok()?.trim_end());
    (status.success() && directory.is_absolute()).then_some(directory)
}

/// Waits for `child` until `deadline`, then stops it.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn import_mutation(
    state_dir: &Path,
    path: &Path,
    rewrite: bool,
    kind: ProofKind,
) -> Result<(), CliError> {
    let mut client = super::admin(state_dir)?;
    let mut lines = super::stdin_lines(2)?;
    let payload = lines.remove(1);
    let proof = lines.remove(0);
    let metadata = if rewrite {
        let replacements: Vec<EnvReplacement> = serde_json::from_slice(&payload)
            .map_err(|_| usage("invalid public replacement array"))?;
        json!({"path":path,"action":"rewrite","replacements":replacements})
    } else {
        let selections: Vec<EnvSelection> = serde_json::from_slice(&payload)
            .map_err(|_| usage("invalid public selection array"))?;
        json!({"path":path,"selections":selections})
    };
    let metadata =
        serde_json::to_vec(&metadata).map_err(|_| usage("cannot encode import request"))?;
    let body = super::proof_body(kind, &proof);
    let (metadata, body) = client.call(ipc::admin_msg::IMPORT_ENV, &metadata, &body)?;
    if serde_json::from_slice::<serde_json::Value>(&metadata).ok() != Some(json!({})) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "import response metadata must be empty",
        ));
    }
    if rewrite {
        let receipt: EnvRewriteReceipt = serde_json::from_slice(&body)
            .map_err(|_| CliError::local("INVALID_FRAME", "invalid import rewrite receipt"))?;
        if !receipt.backup.is_absolute() {
            return Err(CliError::local(
                "INVALID_FRAME",
                "import backup path must be absolute",
            ));
        }
        let backup_git = backup_git(&receipt.backup);
        super::write_json(&json!({"backup":receipt.backup,"backup_git":backup_git}))
    } else {
        let report: EnvImportReport = serde_json::from_slice(&body)
            .map_err(|_| CliError::local("INVALID_FRAME", "invalid import report"))?;
        super::write_json(&report)
    }
}

fn import_url(path: &Path) -> Result<String, CliError> {
    let path = path
        .to_str()
        .ok_or_else(|| usage("import path must be UTF-8"))?;
    let mut escaped = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(format!("rekey://import?path={escaped}"))
}
pub fn import(
    state_dir: &Path,
    path: PathBuf,
    dry_run: bool,
    selections_stdin: bool,
    rewrite_stdin: bool,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let path = std::path::absolute(path).map_err(|_| usage("cannot resolve import path"))?;
    if selections_stdin || rewrite_stdin {
        return import_mutation(state_dir, &path, rewrite_stdin, kind);
    }
    if password_stdin || kind != ProofKind::Password {
        return Err(usage(
            "import proof flags require --selections-stdin or --rewrite-stdin",
        ));
    }
    let name = path
        .to_str()
        .ok_or_else(|| usage("import path must be UTF-8"))?;
    let metadata = serde_json::to_vec(&json!({"path":name,"dry_run":true}))
        .map_err(|_| usage("cannot encode import request"))?;
    let (metadata, body) =
        super::admin(state_dir)?.call(ipc::admin_msg::IMPORT_ENV, &metadata, &[])?;
    if serde_json::from_slice::<serde_json::Value>(&metadata).ok() != Some(json!({})) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "import preview metadata must be empty",
        ));
    }
    let preview: EnvPreview = serde_json::from_slice(&body)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid import preview"))?;
    super::write_json(&preview)?;
    if dry_run {
        return Ok(());
    }
    if state_dir != super::resolve_state_dir(None)? {
        return Err(usage(
            "App import requires the default state directory; use --dry-run to preview a custom vault",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        if !Path::new("/Applications/Rekey.app").is_dir() {
            return Err(CliError::local(
                "LAUNCHER_UNAVAILABLE",
                "Install Rekey.app in /Applications to approve import",
            ));
        }
        let status = Command::new("/usr/bin/open")
            .args(["-a", "/Applications/Rekey.app", &import_url(&path)?])
            .stdin(Stdio::null())
            .status()
            .map_err(|_| CliError::local("LAUNCHER_UNAVAILABLE", "cannot open Rekey import"))?;
        if !status.success() {
            return Err(CliError::local(
                "LAUNCHER_UNAVAILABLE",
                "Rekey import could not be opened",
            ));
        }
        writeln!(
            std::io::stdout(),
            "已打开 Rekey 导入确认；请在 App 中选择项目、签名规则并完成导入。"
        )
        .map_err(|_| CliError::local("OUTPUT_FAILED", "cannot report import status"))?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = import_url(&path)?;
        Err(CliError::local(
            "LAUNCHER_UNAVAILABLE",
            "Import confirmation requires the Rekey App; the preview did not change any file",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_url_transports_only_an_encoded_path() {
        assert_eq!(
            import_url(Path::new("/tmp/project #1/.env")).unwrap(),
            "rekey://import?path=%2Ftmp%2Fproject%20%231%2F.env"
        );
    }
    #[test]
    fn backup_git_runs_the_first_executable_git_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let (plain, tool) = (dir.path().join("plain"), dir.path().join("tool"));
        for directory in [&plain, &tool] {
            std::fs::create_dir(directory).unwrap();
            std::fs::write(directory.join("git"), b"#!/bin/sh\n").unwrap();
        }
        std::fs::set_permissions(tool.join("git"), std::fs::Permissions::from_mode(0o755)).unwrap();
        // Only /usr/bin/git consults the developer directory.
        let unused = || -> Option<PathBuf> { panic!("developer directory read for another git") };
        let path = std::env::join_paths([plain.as_path(), tool.as_path()]).unwrap();
        assert_eq!(git_program(Some(&path), unused), Some(tool.join("git")));
        let plain_only = std::env::join_paths([plain.as_path()]).unwrap();
        assert_eq!(git_program(Some(&plain_only), unused), None);
        assert_eq!(git_program(None, unused), None);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_git_shim_runs_only_when_the_developer_tools_have_git() {
        let shim = std::ffi::OsStr::new("/usr/bin");
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(git_program(Some(shim), || None), None);
        assert_eq!(
            git_program(Some(shim), || Some(empty.path().to_path_buf())),
            None
        );
        for layout in ["usr/bin", "Contents/Developer/usr/bin"] {
            let tools = tempfile::tempdir().unwrap();
            let bin = tools.path().join(layout);
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::write(bin.join("git"), b"").unwrap();
            std::fs::set_permissions(bin.join("git"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            assert_eq!(
                git_program(Some(shim), || Some(tools.path().to_path_buf())),
                Some(PathBuf::from("/usr/bin/git")),
                "{layout}"
            );
        }
    }
    #[test]
    fn scan_reader_rejects_symlinks_and_oversized_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("content");
        std::fs::write(&file, vec![b'x'; FILE_LIMIT + 1]).unwrap();
        assert!(read_file(&file).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(file, &link).unwrap();
        assert!(read_file(&link).is_err());
    }
}
