//! Closed `linux-netns-v1` Agent launcher. Credential IO stays in the Broker.

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_domain::sandbox::{
    CAPABILITY_ENV, CHILD_HOME, CHILD_LANG, CHILD_PATH, LINUX_NETNS_V1, validate_capability_token,
    validate_command_argv, validate_launch_plan,
};
use zeroize::Zeroizing;

use crate::error::BrokerError;

const DOCKER_SOCKETS: &[&str] = &["/var/run/docker.sock", "/run/docker.sock"];

pub struct LaunchRequest {
    pub state_dir: PathBuf,
    pub agent_socket: PathBuf,
    pub argv: Vec<OsString>,
    pub capability: Option<Zeroizing<String>>,
}

pub struct PreparedLaunch {
    pub profile: &'static str,
    pub bwrap: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
}

pub fn run(request: LaunchRequest) -> Result<i32, BrokerError> {
    let prepared = prepare(request)?;
    spawn(&prepared)
}

pub fn prepare(request: LaunchRequest) -> Result<PreparedLaunch, BrokerError> {
    let state_dir = path_to_utf8(&request.state_dir, "state directory")?;
    let agent_socket = path_to_utf8(&request.agent_socket, "agent socket")?;
    let argv_utf8 = argv_to_utf8(&request.argv)?;
    let argv_refs: Vec<&str> = argv_utf8.iter().map(String::as_str).collect();
    validate_launch_plan(state_dir, agent_socket, &argv_refs)?;
    if let Some(capability) = request.capability.as_deref() {
        validate_capability_token(capability)?;
    }

    let state_meta = require_dir_not_symlink(&request.state_dir)?;
    let socket_meta = require_socket_not_symlink(&request.agent_socket)?;
    if state_meta.uid() != socket_meta.uid() {
        return Err(BrokerError::Io(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "agent socket owner does not match the state directory",
        )));
    }
    let canonical_command = require_launch_executable(Path::new(&argv_utf8[0]))?;
    let mut resolved_argv = request.argv.clone();
    resolved_argv[0] = canonical_command.into_os_string();
    let resolved_utf8 = argv_to_utf8(&resolved_argv)?;
    let resolved_refs: Vec<&str> = resolved_utf8.iter().map(String::as_str).collect();

    let canonical_state = request.state_dir.canonicalize().map_err(BrokerError::Io)?;
    let canonical_socket = request
        .agent_socket
        .canonicalize()
        .map_err(BrokerError::Io)?;
    let canonical_state_str = path_to_utf8(&canonical_state, "state directory")?;
    let canonical_socket_str = path_to_utf8(&canonical_socket, "agent socket")?;
    validate_launch_plan(canonical_state_str, canonical_socket_str, &resolved_refs)?;

    verify_agent_peer(&canonical_socket, state_meta.uid())?;

    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let args = bwrap_args(
        &canonical_state,
        &canonical_socket,
        &resolved_argv,
        uid,
        gid,
        docker_hides(&canonical_socket),
    );
    forbid_capability_in_argv(&args, request.capability.as_deref().map(String::as_str))?;

    let mut env = vec![
        (OsString::from("PATH"), OsString::from(CHILD_PATH)),
        (OsString::from("HOME"), OsString::from(CHILD_HOME)),
        (OsString::from("LANG"), OsString::from(CHILD_LANG)),
    ];
    if let Some(capability) = request.capability.as_deref() {
        env.push((
            OsString::from(CAPABILITY_ENV),
            OsString::from(capability.as_str()),
        ));
    }

    Ok(PreparedLaunch {
        profile: LINUX_NETNS_V1,
        bwrap: PathBuf::from("/usr/bin/bwrap"),
        args,
        env,
    })
}

fn spawn(prepared: &PreparedLaunch) -> Result<i32, BrokerError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = prepared;
        Err(BrokerError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::{Command, Stdio};

        let bwrap = find_bwrap()?;
        let mut command = Command::new(&bwrap);
        command
            .args(&prepared.args)
            .env_clear()
            .envs(prepared.env.iter().cloned())
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = command.status().map_err(BrokerError::Io)?;
        Ok(status.code().unwrap_or(5))
    }
}

#[cfg(target_os = "linux")]
fn find_bwrap() -> Result<PathBuf, BrokerError> {
    use rekey_domain::sandbox::BWRAP_CANDIDATES;
    for candidate in BWRAP_CANDIDATES {
        let path = Path::new(candidate);
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                return Ok(path.to_path_buf());
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(BrokerError::Io(error)),
        }
    }
    Err(BrokerError::LauncherUnavailable)
}

fn bwrap_args(
    state_dir: &Path,
    agent_socket: &Path,
    argv: &[OsString],
    uid: u32,
    gid: u32,
    docker_hides: Vec<PathBuf>,
) -> Vec<OsString> {
    let _ = agent_socket;
    let mut args = vec![
        OsString::from("--die-with-parent"),
        OsString::from("--new-session"),
        OsString::from("--unshare-user"),
        OsString::from("--uid"),
        OsString::from(uid.to_string()),
        OsString::from("--gid"),
        OsString::from(gid.to_string()),
        OsString::from("--unshare-net"),
        OsString::from("--unshare-pid"),
        OsString::from("--ro-bind"),
        OsString::from("/"),
        OsString::from("/"),
        OsString::from("--proc"),
        OsString::from("/proc"),
        OsString::from("--dev"),
        OsString::from("/dev"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp"),
        OsString::from("--tmpfs"),
        state_dir.as_os_str().to_owned(),
    ];
    for hide in docker_hides {
        args.push(OsString::from("--bind"));
        args.push(OsString::from("/dev/null"));
        args.push(hide.into_os_string());
    }
    args.push(OsString::from("--chdir"));
    args.push(OsString::from("/tmp"));
    args.push(OsString::from("--"));
    args.extend(argv.iter().cloned());
    args
}

fn docker_hides(agent_socket: &Path) -> Vec<PathBuf> {
    let mut hides = Vec::new();
    for candidate in DOCKER_SOCKETS {
        let path = Path::new(candidate);
        if path == agent_socket {
            continue;
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => hides.push(path.to_path_buf()),
            _ => {}
        }
    }
    hides
}

fn forbid_capability_in_argv(
    args: &[OsString],
    capability: Option<&str>,
) -> Result<(), BrokerError> {
    let flags = args.split(|arg| arg == "--").next().unwrap_or(args);
    for arg in flags {
        let Some(text) = arg.to_str() else {
            continue;
        };
        if text == CAPABILITY_ENV || text == "--share-net" || text == "--setenv" {
            return Err(BrokerError::from(
                rekey_domain::DomainError::InvalidLaunchPlan(
                    "launcher argv must not contain capability or shared networking".into(),
                ),
            ));
        }
        if capability == Some(text) {
            return Err(BrokerError::from(
                rekey_domain::DomainError::InvalidLaunchPlan(
                    "launcher argv must not contain the capability".into(),
                ),
            ));
        }
    }
    Ok(())
}

fn argv_to_utf8(argv: &[OsString]) -> Result<Vec<String>, BrokerError> {
    argv.iter()
        .map(|arg| {
            arg.to_str()
                .map(str::to_owned)
                .ok_or_else(|| {
                    rekey_domain::DomainError::InvalidLaunchPlan("command must be UTF-8".into())
                })
                .map_err(BrokerError::from)
        })
        .collect()
}

fn path_to_utf8<'a>(path: &'a Path, what: &str) -> Result<&'a str, BrokerError> {
    path.to_str().ok_or_else(|| {
        BrokerError::from(rekey_domain::DomainError::InvalidLaunchPlan(format!(
            "{what} must be UTF-8"
        )))
    })
}

fn require_dir_not_symlink(path: &Path) -> Result<fs::Metadata, BrokerError> {
    let metadata = fs::symlink_metadata(path).map_err(BrokerError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BrokerError::from(
            rekey_domain::DomainError::InvalidLaunchPlan(
                "state directory must be a real directory".into(),
            ),
        ));
    }
    Ok(metadata)
}

fn require_socket_not_symlink(path: &Path) -> Result<fs::Metadata, BrokerError> {
    let metadata = fs::symlink_metadata(path).map_err(BrokerError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(BrokerError::from(
            rekey_domain::DomainError::InvalidLaunchPlan(
                "agent socket must be a real Unix socket".into(),
            ),
        ));
    }
    Ok(metadata)
}

fn require_launch_executable(path: &Path) -> Result<PathBuf, BrokerError> {
    let metadata = fs::symlink_metadata(path).map_err(BrokerError::Io)?;
    if !metadata.file_type().is_symlink() && !metadata.is_file() {
        return Err(BrokerError::from(
            rekey_domain::DomainError::InvalidLaunchPlan(
                "command must be a regular executable".into(),
            ),
        ));
    }
    let canonical = path.canonicalize().map_err(BrokerError::Io)?;
    let utf8 = path_to_utf8(&canonical, "command")?;
    validate_command_argv(&[utf8])?;
    let canonical_meta = fs::metadata(&canonical).map_err(BrokerError::Io)?;
    if !canonical_meta.is_file() || canonical_meta.mode() & 0o111 == 0 {
        return Err(BrokerError::from(
            rekey_domain::DomainError::InvalidLaunchPlan(
                "command must be a regular executable".into(),
            ),
        ));
    }
    Ok(canonical)
}

fn verify_agent_peer(socket: &Path, expected_uid: u32) -> Result<(), BrokerError> {
    let stream = UnixStream::connect(socket).map_err(BrokerError::Io)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(BrokerError::Io)?;
    let peer = peer_uid(&stream).map_err(BrokerError::Io)?;
    if peer != expected_uid {
        return Err(BrokerError::Io(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "connected peer is not the Broker",
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn hold_socket(path: &Path) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let _ = listener.accept();
        })
    }

    #[test]
    fn prepared_argv_is_closed_and_hides_state() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let agent_dir = root.path().join("agent");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&agent_dir).unwrap();
        let socket = agent_dir.join("agent.sock");
        let _server = hold_socket(&socket);
        let command = PathBuf::from("/bin/echo");
        if !command.exists() {
            return;
        }

        let prepared = prepare(LaunchRequest {
            state_dir: state.clone(),
            agent_socket: socket,
            argv: vec![command.into(), OsString::from("ok")],
            capability: Some(Zeroizing::new("cap-token-example".into())),
        })
        .unwrap();

        assert_eq!(prepared.profile, LINUX_NETNS_V1);
        let args: Vec<String> = prepared
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let joined = args.join("\n");
        assert!(joined.contains("--unshare-net"));
        assert!(joined.contains("--unshare-pid"));
        assert!(joined.contains("--unshare-user"));
        assert!(joined.contains("--die-with-parent"));
        assert!(joined.contains(&format!(
            "--tmpfs\n{}",
            state.canonicalize().unwrap().display()
        )));
        assert!(!joined.contains("--share-net"));
        assert!(!joined.contains(CAPABILITY_ENV));
        assert!(!joined.contains("cap-token-example"));
        assert!(
            prepared
                .env
                .iter()
                .any(|(key, value)| key == CAPABILITY_ENV && value == "cap-token-example")
        );
        assert!(prepared.env.iter().all(|(key, _)| key == "PATH"
            || key == "HOME"
            || key == "LANG"
            || key == CAPABILITY_ENV));
    }

    #[test]
    fn overlapping_socket_is_rejected_before_spawn() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        let runtime = state.join("runtime");
        fs::create_dir(&runtime).unwrap();
        let socket = runtime.join("agent.sock");
        let _server = hold_socket(&socket);
        let error = match prepare(LaunchRequest {
            state_dir: state,
            agent_socket: socket,
            argv: vec![OsString::from("/bin/echo")],
            capability: None,
        }) {
            Ok(_) => panic!("colocated agent socket must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "INVALID_INPUT");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_returns_unsupported_after_a_valid_plan() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let agent_dir = root.path().join("agent");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&agent_dir).unwrap();
        let socket = agent_dir.join("agent.sock");
        let _server = hold_socket(&socket);
        let error = match run(LaunchRequest {
            state_dir: state,
            agent_socket: socket,
            argv: vec![OsString::from("/bin/echo")],
            capability: None,
        }) {
            Ok(_) => panic!("non-Linux agent-run must not spawn"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "UNSUPPORTED_PLATFORM");
    }
}
