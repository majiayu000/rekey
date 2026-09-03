//! Command implementations. Secrets are read from a hidden TTY prompt or,
//! for automation, explicit stdin flags — never argv or environment.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_domain::ids::{ActionId, CredentialId, SessionId};
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg, agent_msg};
use rekey_domain::{action::FixedHttpAction, credential::CredentialMetadata};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

mod password_lifecycle;
pub use password_lifecycle::{password_change, recovery_rotate};
mod github_admin;
pub use github_admin::{credential_apply_github_webhook, credential_rotate_github_app};
mod audit;
pub use audit::{audit_export, audit_list};
mod policy_approval;
pub use policy_approval::{approval_prepare, policy_activate, policy_status, policy_trust_install};
mod vault_admin;
pub use vault_admin::{credential_add_vault_kv, credential_rotate_vault_kv};

const ACTION_RESPONSE_TIMEOUT: Duration = Duration::from_secs(130);
const DRAIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(130);
const BACKUP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);
const LIFECYCLE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(130);

#[derive(Deserialize)]
struct GitHubProfileMarker<'a> {
    #[serde(borrow)]
    credential_type: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnlockResponse {
    unlocked: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LockResponse {
    locked: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShutdownResponse {
    shutdown: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevokeResponse {
    revoked: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DisableResponse {
    disabled: bool,
}

pub fn resolve_state_dir(flag: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(dir) = flag {
        return Ok(dir);
    }
    std::env::home_dir()
        .map(|home| home.join(".rekey"))
        .ok_or_else(|| CliError::local("USAGE", "cannot resolve home directory; pass --state-dir"))
}

fn admin_socket(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("admin.sock")
}

fn admin(state_dir: &Path) -> Result<Client, CliError> {
    Client::connect(&admin_socket(state_dir), Channel::Admin)
}

fn admin_with_response_timeout(
    state_dir: &Path,
    response_timeout: Duration,
) -> Result<Client, CliError> {
    Client::connect_with_response_timeout(
        &admin_socket(state_dir),
        Channel::Admin,
        response_timeout,
    )
}

fn print_json<T: DeserializeOwned + Serialize>(metadata: &[u8]) -> Result<(), CliError> {
    let value = serde_json::from_slice::<T>(metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    let mut output = serde_json::to_vec_pretty(&value)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    output.push(b'\n');
    std::io::stdout()
        .write_all(&output)
        .map_err(|err| CliError::local("OUTPUT_FAILED", format!("cannot write output: {err}")))
}

fn prompt_secret(prompt: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|err| CliError::local("USAGE", format!("cannot read from tty: {err}")))?,
    );
    if value.is_empty() || value.len() > ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize {
        return Err(CliError::local("USAGE", "empty or oversized input"));
    }
    Ok(Zeroizing::new(value.as_bytes().to_vec()))
}

fn read_bounded(
    reader: impl Read,
    limit: usize,
    label: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let capacity = limit + 1;
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    reader
        .take(capacity as u64)
        .read_to_end(&mut buf)
        .map_err(|err| CliError::local("USAGE", format!("failed to read {label}: {err}")))?;
    debug_assert_eq!(buf.capacity(), capacity);
    if buf.len() > limit {
        return Err(CliError::local(
            "INVALID_FRAME",
            format!("{label} exceeds {limit} bytes"),
        ));
    }
    Ok(buf)
}

fn read_regular_file_bounded(
    path: &Path,
    limit: usize,
    label: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let metadata = std::fs::metadata(path)
        .map_err(|err| CliError::local("USAGE", format!("cannot inspect {label}: {err}")))?;
    if !metadata.is_file() {
        return Err(CliError::local(
            "USAGE",
            format!("{label} must be a regular file"),
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|err| CliError::local("USAGE", format!("cannot open {label}: {err}")))?;
    read_bounded(file, limit, label)
}

fn read_regular_file_bounded_nofollow(
    path: &Path,
    limit: usize,
    label: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| CliError::local("USAGE", format!("cannot open {label}: {err}")))?;
    let metadata = file
        .metadata()
        .map_err(|err| CliError::local("USAGE", format!("cannot inspect {label}: {err}")))?;
    if !metadata.is_file() {
        return Err(CliError::local(
            "USAGE",
            format!("{label} must be a regular non-symlink file"),
        ));
    }
    read_bounded(file, limit, label)
}

fn stdin_lines(expected: usize) -> Result<Vec<Zeroizing<Vec<u8>>>, CliError> {
    read_lines_bounded(
        std::io::stdin().lock(),
        expected,
        ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
        "stdin",
    )
}

fn read_lines_bounded(
    mut reader: impl Read,
    expected: usize,
    limit: usize,
    label: &'static str,
) -> Result<Vec<Zeroizing<Vec<u8>>>, CliError> {
    let capacity = expected
        .checked_mul(limit + 2)
        .ok_or_else(|| CliError::local("USAGE", "stdin size limit overflow"))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    let mut newlines = 0;
    let mut line_len = 0;
    while newlines < expected {
        let mut byte = [0u8; 1];
        let read = reader
            .read(&mut byte)
            .map_err(|err| CliError::local("USAGE", format!("failed to read {label}: {err}")))?;
        if read == 0 {
            break;
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            newlines += 1;
            line_len = 0;
        } else {
            line_len += 1;
            if line_len > limit && !(line_len == limit + 1 && byte[0] == b'\r') {
                return Err(CliError::local(
                    "INVALID_FRAME",
                    format!("{label} line exceeds {limit} bytes"),
                ));
            }
        }
    }
    debug_assert_eq!(buf.capacity(), capacity);
    let lines: Vec<Zeroizing<Vec<u8>>> = buf
        .split(|byte| *byte == b'\n')
        .take(expected)
        .map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            Zeroizing::new(line.to_vec())
        })
        .collect();
    if lines.len() != expected || lines.iter().any(|l| l.is_empty()) {
        return Err(CliError::local(
            "USAGE",
            format!("expected {expected} non-empty line(s) on stdin"),
        ));
    }
    Ok(lines)
}

fn read_password(password_stdin: bool, prompt: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if password_stdin {
        Ok(stdin_lines(1)?.remove(0))
    } else {
        prompt_secret(prompt)
    }
}

fn proof_kind(recovery: bool) -> ProofKind {
    if recovery {
        ProofKind::Recovery
    } else {
        ProofKind::Password
    }
}

fn step_up_prompt(recovery: bool) -> &'static str {
    if recovery {
        "Recovery key (step-up): "
    } else {
        "Vault password (step-up): "
    }
}

fn read_step_up(recovery: bool, proof_stdin: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    read_password(proof_stdin, step_up_prompt(recovery))
}

fn proof_body(recovery: bool, proof: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(proof.len() + 8));
    ipc::encode_proof_body(proof_kind(recovery), proof, &mut body);
    body
}

fn parse_action_ref(input: &str) -> Result<(ActionId, u64), CliError> {
    let (id, version) = input
        .split_once('@')
        .ok_or_else(|| CliError::local("USAGE", "expected ACTION_ID@VERSION"))?;
    let action_id: ActionId = id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action id"))?;
    let version: u64 = version
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action version"))?;
    Ok((action_id, version))
}

fn parse_ttl_ms(input: &str) -> Result<i64, CliError> {
    let (value, unit) = input.split_at(input.len().saturating_sub(1));
    let n: i64 = value
        .parse()
        .map_err(|_| CliError::local("USAGE", format!("invalid ttl: {input}")))?;
    let multiplier = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => {
            return Err(CliError::local(
                "USAGE",
                format!("invalid ttl unit: {input}"),
            ));
        }
    };
    n.checked_mul(multiplier)
        .ok_or_else(|| CliError::local("USAGE", format!("invalid ttl: {input}")))
}

/// Locates the rekeyd binary: next to the current executable first, then PATH.
fn rekeyd_binary() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("rekeyd");
        if sibling.exists() {
            return sibling;
        }
    }
    PathBuf::from("rekeyd")
}

pub fn delegate_rekeyd(
    state_dir: &Path,
    subcommand: &str,
    extra_args: &[std::ffi::OsString],
    password_stdin: bool,
) -> Result<(), CliError> {
    let mut cmd = std::process::Command::new(rekeyd_binary());
    cmd.arg(subcommand)
        .arg("--state-dir")
        .arg(state_dir)
        .args(extra_args);
    if password_stdin {
        cmd.arg("--password-stdin");
    }
    let status = cmd
        .status()
        .map_err(|err| CliError::local("IPC_UNAVAILABLE", format!("cannot run rekeyd: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        std::process::exit(status.code().unwrap_or(5));
    }
}

pub fn unlock(state_dir: &Path, recovery: bool, password_stdin: bool) -> Result<(), CliError> {
    let prompt = if recovery {
        "Recovery key: "
    } else {
        "Vault password: "
    };
    let secret = read_password(password_stdin, prompt)?;
    let message = if recovery {
        admin_msg::UNLOCK_RECOVERY
    } else {
        admin_msg::UNLOCK_PASSWORD
    };
    let (meta, _) = admin(state_dir)?.call(message, b"{}", &secret)?;
    print_json::<UnlockResponse>(&meta)?;
    Ok(())
}

pub fn lock(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin_with_response_timeout(state_dir, DRAIN_RESPONSE_TIMEOUT)?.call(
        admin_msg::LOCK,
        b"{}",
        &[],
    )?;
    print_json::<LockResponse>(&meta)?;
    Ok(())
}

pub fn status(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::STATUS, b"{}", &[])?;
    print_json::<ipc::StatusResponse>(&meta)?;
    Ok(())
}

pub fn shutdown(state_dir: &Path, recovery: bool, password_stdin: bool) -> Result<(), CliError> {
    let mut client = admin_with_response_timeout(state_dir, DRAIN_RESPONSE_TIMEOUT)?;
    // Locked brokers shut down without proof; unlocked brokers require it.
    match client.call(admin_msg::SHUTDOWN, b"{}", &[]) {
        Ok((meta, _)) => {
            print_json::<ShutdownResponse>(&meta)?;
            Ok(())
        }
        Err(err) if err.code == "AUTHENTICATION_FAILED" => {
            let proof = read_step_up(recovery, password_stdin)?;
            let body = proof_body(recovery, &proof);
            let (meta, _) = admin_with_response_timeout(state_dir, DRAIN_RESPONSE_TIMEOUT)?.call(
                admin_msg::SHUTDOWN,
                b"{}",
                &body,
            )?;
            print_json::<ShutdownResponse>(&meta)?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

pub fn credential_add(
    state_dir: &Path,
    label: &str,
    recovery: bool,
    stdin_secrets: bool,
) -> Result<(), CliError> {
    let (proof, secret) = if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let secret = lines.remove(1);
        let proof = lines.remove(0);
        (proof, secret)
    } else {
        (
            prompt_secret(step_up_prompt(recovery))?,
            prompt_secret("Credential value: ")?,
        )
    };
    let metadata = serde_json::json!({ "label": label, "kind": "opaque-token" });
    let body_len = 1 + 4 + proof.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(proof_kind(recovery), &proof, &secret, &mut body);
    debug_assert_eq!(body.len(), body_len);
    debug_assert_eq!(body.capacity(), body_capacity);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

pub fn credential_add_github_app(
    state_dir: &Path,
    label: &str,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let limit = ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize;
    let secret = read_regular_file_bounded(file, limit, "GitHub App profile")?;
    if secret.is_empty() {
        return Err(CliError::local(
            "USAGE",
            "GitHub App profile must be 1..=64 KiB",
        ));
    }
    let marker: GitHubProfileMarker<'_> = serde_json::from_slice(&secret)
        .map_err(|_| CliError::local("USAGE", "invalid GitHub App profile JSON"))?;
    if marker.credential_type != "github-app-installation-v2" {
        return Err(CliError::local(
            "USAGE",
            "GitHub App profile has the wrong credential_type",
        ));
    }
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({
        "label": label,
        "kind": "github-app-installation"
    });
    let body_len = 1 + 4 + proof.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(proof_kind(recovery), &proof, &secret, &mut body);
    debug_assert_eq!(body.len(), body_len);
    debug_assert_eq!(body.capacity(), body_capacity);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

pub fn credential_list(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::CREDENTIAL_LIST, b"{}", &[])?;
    print_json::<ipc::CredentialListResponse>(&meta)?;
    Ok(())
}

pub fn credential_rotate(
    state_dir: &Path,
    credential_id: &str,
    recovery: bool,
    stdin_secrets: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let (proof, secret) = if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let secret = lines.remove(1);
        let proof = lines.remove(0);
        (proof, secret)
    } else {
        (
            prompt_secret(step_up_prompt(recovery))?,
            prompt_secret("New credential value: ")?,
        )
    };
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body_len = 1 + 4 + proof.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(proof_kind(recovery), &proof, &secret, &mut body);
    debug_assert_eq!(body.len(), body_len);
    debug_assert_eq!(body.capacity(), body_capacity);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ROTATE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

pub fn credential_revoke(
    state_dir: &Path,
    credential_id: &str,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_REVOKE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

pub fn action_create(
    state_dir: &Path,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let definition =
        read_regular_file_bounded(file, ipc::METADATA_MAX_BYTES as usize, "action file")?;
    // Validate shape client-side for a friendly error; the broker re-validates.
    serde_json::from_slice::<ipc::ActionCreateMeta>(&definition)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let proof = read_step_up(recovery, password_stdin)?;
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_CREATE, &definition, &body)?;
    print_json::<FixedHttpAction>(&meta)?;
    Ok(())
}

pub fn action_update(
    state_dir: &Path,
    action_id: &str,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let action_id: ActionId = action_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action id"))?;
    let definition =
        read_regular_file_bounded(file, ipc::METADATA_MAX_BYTES as usize, "action file")?;
    let definition: ipc::ActionCreateMeta = serde_json::from_slice(&definition)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let metadata = ipc::ActionUpdateMeta {
        action_id,
        definition,
    };
    let metadata = serde_json::to_vec(&metadata)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let proof = read_step_up(recovery, password_stdin)?;
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_UPDATE, &metadata, &body)?;
    print_json::<FixedHttpAction>(&meta)?;
    Ok(())
}

pub fn action_list(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_LIST, b"{}", &[])?;
    print_json::<ipc::ActionListResponse>(&meta)?;
    Ok(())
}

pub fn action_disable(
    state_dir: &Path,
    action_id: &str,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let action_id: ActionId = action_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action id"))?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({ "action_id": action_id.to_string() });
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::ACTION_DISABLE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<DisableResponse>(&meta)?;
    Ok(())
}

pub fn session_create(
    state_dir: &Path,
    actions: &[String],
    ttl: &str,
    max_uses: u32,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let mut refs = Vec::new();
    for action in actions {
        let (action_id, version) = parse_action_ref(action)?;
        refs.push(serde_json::json!({
            "action_id": action_id.to_string(),
            "version": version,
        }));
    }
    let ttl_ms = parse_ttl_ms(ttl)?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({
        "actions": refs,
        "ttl_ms": ttl_ms,
        "max_uses": max_uses,
    });
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::SESSION_CREATE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    // Shown exactly once; prefer piping to the agent instead of shell history.
    print_json::<ipc::SessionCreatedResponse>(&meta)?;
    Ok(())
}

pub fn workload_session_create(
    agent_socket: &Path,
    actions: &[String],
    ttl: &str,
    max_uses: u32,
) -> Result<(), CliError> {
    let actions = actions
        .iter()
        .map(|action| {
            let (action_id, version) = parse_action_ref(action)?;
            Ok(rekey_domain::capability::ActionVersionRef { action_id, version })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let metadata = ipc::SessionCreateMeta {
        actions,
        ttl_ms: parse_ttl_ms(ttl)?,
        max_uses,
    };
    let metadata = serde_json::to_vec(&metadata)
        .map_err(|_| CliError::local("USAGE", "cannot encode session request"))?;
    let token = read_bounded(
        std::io::stdin().lock(),
        ipc::WORKLOAD_TOKEN_MAX_BYTES as usize,
        "workload token",
    )?;
    if token.is_empty() {
        return Err(CliError::local("USAGE", "workload token is empty"));
    }
    let (response, body) = Client::connect(agent_socket, Channel::Agent)?.call(
        agent_msg::WORKLOAD_SESSION_CREATE,
        &metadata,
        &token,
    )?;
    if !body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "broker returned an unexpected response body",
        ));
    }
    print_json::<ipc::SessionCreatedResponse>(&response)
}

pub fn session_revoke(
    state_dir: &Path,
    session_id: &str,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let session_id: SessionId = session_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid session id"))?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({ "session_id": session_id.to_string() });
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::SESSION_REVOKE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<RevokeResponse>(&meta)?;
    Ok(())
}

pub fn execute(
    agent_socket: &Path,
    action: &str,
    capability: &str,
    body_file: Option<&Path>,
    content_type: Option<String>,
    headers: &[String],
    approvals: &[PathBuf],
) -> Result<(), CliError> {
    let (action_id, version) = parse_action_ref(action)?;
    let capability_token = policy_approval::capability_value(capability)?;
    let body = policy_approval::request_body(body_file)?;
    let extra_headers = policy_approval::request_headers(headers)?;
    let approval_grants = policy_approval::read_approval_files(approvals)?;
    let metadata = serde_json::json!({
        "capability_token": capability_token,
        "action_id": action_id.to_string(),
        "action_version": version,
        "content_type": content_type,
        "extra_headers": extra_headers,
        "approval_grants": approval_grants,
    });
    let (meta, response_body) = Client::connect_with_response_timeout(
        agent_socket,
        Channel::Agent,
        ACTION_RESPONSE_TIMEOUT,
    )?
    .call(
        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<ipc::ExecuteResponseMeta>(&meta)?;
    if !response_body.is_empty() {
        let mut stdout = std::io::stdout();
        stdout.write_all(&response_body).map_err(|err| {
            CliError::local(
                "OUTPUT_FAILED",
                format!("cannot write response body: {err}"),
            )
        })?;
        stdout.write_all(b"\n").map_err(|err| {
            CliError::local(
                "OUTPUT_FAILED",
                format!("cannot finish response body: {err}"),
            )
        })?;
    }
    Ok(())
}

pub fn backup(
    state_dir: &Path,
    output: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let output_path = output
        .to_str()
        .ok_or_else(|| CliError::local("USAGE", "backup output path must be valid UTF-8"))?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({ "output_path": output_path });
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin_with_response_timeout(state_dir, BACKUP_RESPONSE_TIMEOUT)?.call(
        admin_msg::BACKUP,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<ipc::BackupReceipt>(&meta)?;
    Ok(())
}

#[cfg(test)]
mod tests;
