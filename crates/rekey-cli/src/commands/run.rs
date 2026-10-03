//! A named Profile owns exactly one child and one live Broker control connection.
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use rekey_domain::ids::SessionId;
use rekey_domain::ipc::{
    ProfileGatewayEndpoint, ProfileGatewayProvider, ProfileGetResponse, ProfileNameMeta,
    ProfileSessionCreatedResponse,
};
use rekey_domain::profile::{AgentProfile, ProfileEgress, ProfileIsolation};

use super::{CliError, ProofKind, Zeroizing, admin, admin_msg, proof_body, read_step_up};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RunClient {
    ClaudeCode,
    Codex,
}

fn invalid() -> CliError {
    CliError::local("INVALID_FRAME", "invalid Profile response")
}

fn empty_metadata(metadata: &[u8]) -> Result<(), CliError> {
    let value: serde_json::Value = serde_json::from_slice(metadata).map_err(|_| invalid())?;
    if value.as_object().is_none_or(|object| !object.is_empty()) {
        return Err(invalid());
    }
    Ok(())
}

fn now_ms() -> Result<i64, CliError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or_else(|| CliError::local("CLOCK_UNAVAILABLE", "system clock is unavailable"))
}

pub fn run_profile(
    state_dir: &Path,
    agent_socket: &Path,
    name: &str,
    kind: ProofKind,
    proof_stdin: bool,
    adapter: Option<RunClient>,
    command: Vec<OsString>,
) -> Result<i32, CliError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CliError::local("USAGE", "a command is required"))?;
    if adapter == Some(RunClient::Codex) {
        for arg in args.iter().take_while(|arg| *arg != "--") {
            if matches!(
                arg.as_encoded_bytes().split(|byte| *byte == b'=').next(),
                Some(b"--oss" | b"--local-provider" | b"--remote")
            ) {
                return Err(CliError::local(
                    "USAGE",
                    "Codex provider or remote selection conflicts with the Profile gateway",
                ));
            }
        }
    }
    let metadata = serde_json::to_vec(&ProfileNameMeta {
        profile: name.into(),
    })
    .map_err(|_| invalid())?;
    let (meta, body) = admin(state_dir)?.call(admin_msg::PROFILE_GET, &metadata, &[])?;
    empty_metadata(&meta)?;
    let before: ProfileGetResponse = serde_json::from_slice(&body).map_err(|_| invalid())?;
    drop(body);
    before.profile.validate().map_err(|_| invalid())?;
    if before.profile.name != name
        || before.policy_sha256.len() != 64
        || !before
            .policy_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    if before.expires_at_ms <= now_ms()? {
        return Err(CliError::local(
            "REQUEST_DENIED",
            "Profile policy has expired",
        ));
    }
    let isolated = cfg!(target_os = "macos")
        && before.profile.isolation == ProfileIsolation::Seatbelt
        && before.profile.egress == ProfileEgress::DenyOther;
    if !isolated
        && (before.profile.isolation != ProfileIsolation::None
            || before.profile.egress != ProfileEgress::Allow)
    {
        return Err(CliError::local(
            "UNSUPPORTED_PLATFORM",
            "this launcher does not yet support the Profile's isolation or egress requirements",
        ));
    }
    if !before.profile.confirm_each_run && (proof_stdin || kind != ProofKind::Password) {
        return Err(CliError::local(
            "USAGE",
            "this Profile does not accept a per-run proof",
        ));
    }
    // Validate this connection's peer before reading any authentication input.
    let mut client = admin(state_dir)?;
    let proof = if before.profile.confirm_each_run {
        let secret = if proof_stdin {
            // std::io::stdin may buffer the child's subsequent input. Read
            // only the proof line through an unbuffered, privately owned fd.
            let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return Err(CliError::local("USAGE", "cannot read proof input"));
            }
            let input = unsafe { std::fs::File::from_raw_fd(fd) };
            super::read_lines_bounded(
                input,
                1,
                rekey_domain::ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
                "stdin",
            )?
            .remove(0)
        } else {
            read_step_up(kind, false)?
        };
        proof_body(kind, &secret)
    } else {
        Zeroizing::new(Vec::new())
    };
    let (meta, body) = client.call(admin_msg::PROFILE_SESSION_CREATE, &metadata, &proof)?;
    drop(proof);
    empty_metadata(&meta)?;
    let mut created: ProfileSessionCreatedResponse =
        serde_json::from_slice(&body).map_err(|_| invalid())?;
    drop(body);
    let capability = Zeroizing::new(std::mem::take(&mut created.session.capability_token));
    if created.profile != before.profile || created.policy_sha256 != before.policy_sha256 {
        return Err(CliError::local(
            "REQUEST_DENIED",
            "Profile policy changed; command was not started",
        ));
    }
    if created.session.principal_id != before.profile.principal_id
        || created.session.expires_at_ms <= now_ms()?
        || created.session.expires_at_ms > before.expires_at_ms
        || created.session.max_uses != before.profile.session.max_uses
        || capability.is_empty()
        || capability.contains('\0')
    {
        return Err(invalid());
    }
    let control = client.into_owner_control()?;
    let mut launch = Command::new(program);
    if isolated {
        // A loader or proxy variable must not affect the helper before it
        // installs the sandbox. Only explicit session bindings cross exec.
        launch.env_clear();
        for key in ["TERM", "COLORTERM"] {
            if let Some(value) = std::env::var_os(key) {
                launch.env(key, value);
            }
        }
    }
    launch
        .env("REKEY_CAPABILITY", capability.as_str())
        .env("REKEY_AGENT_SOCKET", agent_socket);
    configure_gateway(
        &mut launch,
        &before.profile,
        created.gateway.as_ref(),
        &capability,
        adapter,
        created.session.session_id,
        args,
    )?;
    if isolated {
        launch = isolated_launch(state_dir, agent_socket, created.gateway.as_ref(), launch)?;
    }
    let spawned = launch.spawn();
    drop(launch);
    drop(capability);
    let mut child = spawned
        .map_err(|_| CliError::local("LAUNCHER_UNAVAILABLE", "cannot start Profile command"))?;
    let result = wait_child(&control, &mut child);
    // Closing revokes before returning/printing any failure or child exit status.
    drop(control);
    if result.is_err() {
        if isolated {
            finish_isolated_termination(&mut child)?;
        } else {
            let killed = child.kill();
            finish_termination(&mut child, killed)?;
        }
    }
    result
}

// Resolve the user's selected executable before clearing PATH. The helper is
// always the installed sibling, never an ambient PATH command.
fn isolated_launch(
    state_dir: &Path,
    agent_socket: &Path,
    gateway: Option<&ProfileGatewayEndpoint>,
    child: Command,
) -> Result<Command, CliError> {
    let unavailable = || {
        CliError::local(
            "LAUNCHER_UNAVAILABLE",
            "cannot prepare isolated Profile command",
        )
    };
    let executable = resolve_executable(Path::new(child.get_program())).ok_or_else(unavailable)?;
    let current = std::env::current_exe().map_err(|_| unavailable())?;
    let helper = current.parent().ok_or_else(unavailable)?.join("rekeyd");
    let helper = resolve_executable(&helper).ok_or_else(unavailable)?;
    let state_dir = state_dir.canonicalize().map_err(|_| unavailable())?;
    let agent_socket = agent_socket.canonicalize().map_err(|_| unavailable())?;
    let mut launch = Command::new(helper);
    launch
        .env_clear()
        .env("PATH", rekey_domain::sandbox::CHILD_PATH)
        .env("LANG", rekey_domain::sandbox::CHILD_LANG)
        .envs(
            child
                .get_envs()
                .filter_map(|(key, value)| value.map(|value| (key, value))),
        )
        .arg("profile-child")
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--agent-socket")
        .arg(agent_socket)
        .args(["--isolation", "seatbelt"]);
    if let Some(gateway) = gateway {
        launch.arg("--gateway-port").arg(gateway.port.to_string());
    }
    launch.arg("--").arg(executable).args(child.get_args());
    Ok(launch)
}

fn resolve_executable(program: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let executable = |path: PathBuf| {
        let path = path.canonicalize().ok()?;
        let metadata = path.metadata().ok()?;
        (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).then_some(path)
    };
    if program.as_os_str().as_encoded_bytes().contains(&b'/') {
        return executable(program.to_owned());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .find_map(|directory| executable(directory.join(program)))
}

// The endpoint comes only from the authenticated CREATE response, never a
// discovery file or inherited environment. Profile validation already fixes slugs.
fn configure_gateway(
    launch: &mut Command,
    profile: &AgentProfile,
    gateway: Option<&ProfileGatewayEndpoint>,
    capability: &str,
    adapter: Option<RunClient>,
    session_id: SessionId,
    args: &[OsString],
) -> Result<(), CliError> {
    if profile.llm_limits.is_empty() {
        if gateway.is_some() {
            return Err(invalid());
        }
        if adapter.is_some() {
            return Err(missing_provider());
        }
        launch.args(args);
        return Ok(());
    }
    let gateway = gateway.ok_or_else(|| {
        CliError::local("LAUNCHER_UNAVAILABLE", "Profile SDK gateway is unavailable")
    })?;
    let mut expected: BTreeSet<_> = profile
        .llm_limits
        .iter()
        .map(|limit| limit.instance.as_str())
        .collect();
    if gateway.port == 0 || gateway.instances.len() != expected.len() {
        return Err(invalid());
    }
    let mut anthropic = None;
    let mut openai = None;
    for mapping in &gateway.instances {
        if !expected.remove(mapping.instance.as_str()) {
            return Err(invalid());
        }
        let provider = match mapping.provider {
            ProfileGatewayProvider::Anthropic => &mut anthropic,
            ProfileGatewayProvider::OpenAi => &mut openai,
        };
        if provider.replace(mapping.instance.as_str()).is_some() {
            return Err(CliError::local(
                "UNSUPPORTED_PLATFORM",
                "SDK environment supports one instance per provider; split the Profile",
            ));
        }
    }
    if (adapter == Some(RunClient::ClaudeCode) && anthropic.is_none())
        || (adapter == Some(RunClient::Codex) && openai.is_none())
    {
        return Err(missing_provider());
    }
    let sdk_key = Zeroizing::new(format!("rkc_{capability}"));
    if let Some(instance) = anthropic {
        launch
            .env(
                "ANTHROPIC_BASE_URL",
                format!("http://127.0.0.1:{}/p/{instance}", gateway.port),
            )
            .env_remove("ANTHROPIC_CUSTOM_HEADERS");
        if adapter == Some(RunClient::ClaudeCode) {
            launch
                .env("ANTHROPIC_AUTH_TOKEN", sdk_key.as_str())
                .env_remove("ANTHROPIC_API_KEY")
                .env_remove("CLAUDE_CODE_USE_BEDROCK")
                .env_remove("CLAUDE_CODE_USE_VERTEX")
                .env_remove("CLAUDE_CODE_USE_FOUNDRY");
        } else {
            launch
                .env("ANTHROPIC_API_KEY", sdk_key.as_str())
                .env_remove("ANTHROPIC_AUTH_TOKEN");
        }
    }
    if let Some(instance) = openai {
        let url = format!("http://127.0.0.1:{}/p/{instance}/v1", gateway.port);
        launch
            .env("OPENAI_BASE_URL", &url)
            .env("OPENAI_API_KEY", sdk_key.as_str())
            .env_remove("OPENAI_CUSTOM_HEADERS");
        if adapter == Some(RunClient::Codex) {
            let provider = format!("rekey_{}", session_id.to_string().replace('-', ""));
            let split = args
                .iter()
                .position(|arg| arg == "--")
                .unwrap_or(args.len());
            launch
                .arg("--no-daemon")
                .args(args[..split].iter().filter(|arg| *arg != "--no-daemon"))
                .arg("-c")
                .arg(format!("model_provider=\"{provider}\""))
                .arg("-c")
                .arg(format!("model_providers.{provider}={{name=\"Rekey\",base_url=\"{url}\",env_key=\"OPENAI_API_KEY\",wire_api=\"responses\",requires_openai_auth=false,supports_websockets=false}}"))
                .args(&args[split..]);
        }
    }
    if adapter != Some(RunClient::Codex) {
        launch.args(args);
    }
    Ok(())
}

fn missing_provider() -> CliError {
    CliError::local(
        "UNSUPPORTED_PLATFORM",
        "Profile has no endpoint for the selected client",
    )
}

// The isolated helper must reap its directly launched Agent and close scratch
// before exiting. SIGKILL first would strand that Agent in its new session.
fn finish_isolated_termination(child: &mut Child) -> Result<(), CliError> {
    let unavailable = || {
        CliError::local(
            "LAUNCHER_UNAVAILABLE",
            "Profile session ended; isolated command cleanup could not be confirmed",
        )
    };
    let confirmed = |status: std::process::ExitStatus| {
        // Only this normal exit acknowledges direct-child reaping and scratch
        // cleanup; a default signal death is not a cleanup receipt.
        if status.code() == Some(128 + libc::SIGTERM) {
            Ok(())
        } else {
            Err(unavailable())
        }
    };
    if let Some(status) = child.try_wait().map_err(|_| unavailable())? {
        return confirmed(status);
    }
    // SAFETY: this is our unreaped child PID, so it cannot have been reused.
    if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) } != 0 {
        return if let Some(status) = child.try_wait().map_err(|_| unavailable())? {
            confirmed(status)
        } else {
            Err(unavailable())
        };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().map_err(|_| unavailable())? {
            return confirmed(status);
        }
        if std::time::Instant::now() >= deadline {
            let killed = child.kill();
            finish_termination(child, killed)?;
            return Err(unavailable());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn finish_termination(child: &mut Child, killed: std::io::Result<()>) -> Result<(), CliError> {
    if killed.is_err() {
        return match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            // A failed kill does not establish that wait will ever finish.
            _ => Err(CliError::local(
                "LAUNCHER_UNAVAILABLE",
                "Profile control closed; command termination could not be confirmed",
            )),
        };
    }
    child
        .wait()
        .map(|_| ())
        .map_err(|_| CliError::local("LAUNCHER_UNAVAILABLE", "cannot reap Profile command"))
}

fn wait_child(
    control: &std::os::unix::net::UnixStream,
    child: &mut Child,
) -> Result<i32, CliError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| {
            CliError::local("LAUNCHER_UNAVAILABLE", "cannot wait for Profile command")
        })? {
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
        }
        let mut descriptor = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(CliError::local(
                "IPC_UNAVAILABLE",
                "Profile control connection failed",
            ));
        }
        if ready > 0 {
            // No post-CREATE message is valid: bytes, EOF and error all revoke.
            return Err(CliError::local(
                "IPC_UNAVAILABLE",
                "Profile session ended; command stopped",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exited_isolated_helper_requires_normal_cleanup_acknowledgement() {
        for (script, acknowledged) in [
            ("exit 0", false),
            ("exit 143", true),
            ("kill -TERM $$", false),
        ] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", script])
                .spawn()
                .unwrap();
            // Real exited processes exercise the early-return path, including
            // the distinction between a normal status and signal termination.
            child.wait().unwrap();
            let result = finish_isolated_termination(&mut child);
            if acknowledged {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code, "LAUNCHER_UNAVAILABLE");
                assert!(error.message.contains("could not be confirmed"));
            }
        }
    }

    #[test]
    fn failed_kill_of_live_child_returns_without_waiting_or_claiming_cleanup() {
        let mut child = Command::new("/bin/sleep").arg("2").spawn().unwrap();
        let start = std::time::Instant::now();
        // Inject only the OS kill result; process liveness and reaping are real.
        let result = finish_termination(
            &mut child,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        );
        let elapsed = start.elapsed();
        let alive = child.try_wait().unwrap().is_none();
        if alive {
            child.kill().unwrap();
        }
        child.wait().unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.code, "LAUNCHER_UNAVAILABLE");
        assert!(error.message.contains("could not be confirmed"));
        assert!(alive);
        assert!(elapsed < std::time::Duration::from_secs(1));
    }

    #[test]
    fn failed_kill_after_child_exit_keeps_original_control_result() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        child.wait().unwrap();
        assert!(
            finish_termination(
                &mut child,
                Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
            )
            .is_ok()
        );
    }
}
