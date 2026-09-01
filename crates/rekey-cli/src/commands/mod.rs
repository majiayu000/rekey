//! Command implementations. Secrets are read from a hidden TTY prompt or,
//! for automation, explicit stdin flags — never argv or environment.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_domain::ids::{ActionId, CredentialId, SessionId};
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg, agent_msg};
use rekey_domain::{action::FixedHttpAction, credential::CredentialMetadata};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

const ACTION_RESPONSE_TIMEOUT: Duration = Duration::from_secs(130);
const DRAIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(130);
const BACKUP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);

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
    if value.is_empty() {
        return Err(CliError::local("USAGE", "empty input"));
    }
    Ok(Zeroizing::new(value.as_bytes().to_vec()))
}

fn stdin_lines(expected: usize) -> Result<Vec<Zeroizing<Vec<u8>>>, CliError> {
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|err| CliError::local("USAGE", format!("failed to read stdin: {err}")))?;
    let lines: Vec<Zeroizing<Vec<u8>>> = buf
        .lines()
        .take(expected)
        .map(|l| Zeroizing::new(l.trim_end_matches('\r').as_bytes().to_vec()))
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

fn proof_body(password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(password.len() + 8));
    ipc::encode_proof_body(ProofKind::Password, password, &mut body);
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
    match unit {
        "s" => Ok(n * 1000),
        "m" => Ok(n * 60 * 1000),
        "h" => Ok(n * 3600 * 1000),
        _ => Err(CliError::local(
            "USAGE",
            format!("invalid ttl unit: {input}"),
        )),
    }
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
    extra_args: &[String],
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

pub fn shutdown(state_dir: &Path, password_stdin: bool) -> Result<(), CliError> {
    let mut client = admin_with_response_timeout(state_dir, DRAIN_RESPONSE_TIMEOUT)?;
    // Locked brokers shut down without proof; unlocked brokers require it.
    match client.call(admin_msg::SHUTDOWN, b"{}", &[]) {
        Ok((meta, _)) => {
            print_json::<ShutdownResponse>(&meta)?;
            Ok(())
        }
        Err(err) if err.code == "AUTHENTICATION_FAILED" => {
            let password = read_password(password_stdin, "Vault password: ")?;
            let body = proof_body(&password);
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

pub fn credential_add(state_dir: &Path, label: &str, stdin_secrets: bool) -> Result<(), CliError> {
    let (password, secret) = if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let secret = lines.remove(1);
        let password = lines.remove(0);
        (password, secret)
    } else {
        (
            prompt_secret("Vault password (step-up): ")?,
            prompt_secret("Credential value: ")?,
        )
    };
    let metadata = serde_json::json!({ "label": label, "kind": "opaque-token" });
    let body_len = 1 + 4 + password.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(ProofKind::Password, &password, &secret, &mut body);
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
    password_stdin: bool,
) -> Result<(), CliError> {
    let profile_file = std::fs::File::open(file)
        .map_err(|err| CliError::local("USAGE", format!("cannot open profile file: {err}")))?;
    let limit = ipc::ADMIN_SECRET_BODY_MAX_BYTES as usize;
    let profile_capacity = limit + 1;
    let mut secret = Zeroizing::new(Vec::with_capacity(profile_capacity));
    profile_file
        .take((limit + 1) as u64)
        .read_to_end(&mut secret)
        .map_err(|err| CliError::local("USAGE", format!("cannot read profile file: {err}")))?;
    debug_assert_eq!(secret.capacity(), profile_capacity);
    if secret.is_empty() || secret.len() > ipc::ADMIN_SECRET_BODY_MAX_BYTES as usize {
        return Err(CliError::local(
            "USAGE",
            "GitHub App profile must be 1..=64 KiB",
        ));
    }
    let marker: GitHubProfileMarker<'_> = serde_json::from_slice(&secret)
        .map_err(|_| CliError::local("USAGE", "invalid GitHub App profile JSON"))?;
    if marker.credential_type != "github-app-installation-v1" {
        return Err(CliError::local(
            "USAGE",
            "GitHub App profile has the wrong credential_type",
        ));
    }
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let metadata = serde_json::json!({
        "label": label,
        "kind": "github-app-installation"
    });
    let body_len = 1 + 4 + password.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(ProofKind::Password, &password, &secret, &mut body);
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
    stdin_secrets: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let (password, secret) = if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let secret = lines.remove(1);
        let password = lines.remove(0);
        (password, secret)
    } else {
        (
            prompt_secret("Vault password (step-up): ")?,
            prompt_secret("New credential value: ")?,
        )
    };
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body_len = 1 + 4 + password.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(ProofKind::Password, &password, &secret, &mut body);
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
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body = proof_body(&password);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_REVOKE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

pub fn action_create(state_dir: &Path, file: &Path, password_stdin: bool) -> Result<(), CliError> {
    let definition = std::fs::read(file)
        .map_err(|err| CliError::local("USAGE", format!("cannot read action file: {err}")))?;
    // Validate shape client-side for a friendly error; the broker re-validates.
    serde_json::from_slice::<ipc::ActionCreateMeta>(&definition)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let body = proof_body(&password);
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_CREATE, &definition, &body)?;
    print_json::<FixedHttpAction>(&meta)?;
    Ok(())
}

pub fn action_update(
    state_dir: &Path,
    action_id: &str,
    file: &Path,
    password_stdin: bool,
) -> Result<(), CliError> {
    let action_id: ActionId = action_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action id"))?;
    let definition = std::fs::read(file)
        .map_err(|err| CliError::local("USAGE", format!("cannot read action file: {err}")))?;
    let definition: ipc::ActionCreateMeta = serde_json::from_slice(&definition)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let metadata = ipc::ActionUpdateMeta {
        action_id,
        definition,
    };
    let metadata = serde_json::to_vec(&metadata)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let body = proof_body(&password);
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
    password_stdin: bool,
) -> Result<(), CliError> {
    let action_id: ActionId = action_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action id"))?;
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let metadata = serde_json::json!({ "action_id": action_id.to_string() });
    let body = proof_body(&password);
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
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let metadata = serde_json::json!({
        "actions": refs,
        "ttl_ms": ttl_ms,
        "max_uses": max_uses,
    });
    let body = proof_body(&password);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::SESSION_CREATE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    // Shown exactly once; prefer piping to the agent instead of shell history.
    print_json::<ipc::SessionCreatedResponse>(&meta)?;
    Ok(())
}

pub fn session_revoke(
    state_dir: &Path,
    session_id: &str,
    password_stdin: bool,
) -> Result<(), CliError> {
    let session_id: SessionId = session_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid session id"))?;
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let metadata = serde_json::json!({ "session_id": session_id.to_string() });
    let body = proof_body(&password);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::SESSION_REVOKE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<RevokeResponse>(&meta)?;
    Ok(())
}

pub fn policy_activate(
    state_dir: &Path,
    file: &Path,
    password_stdin: bool,
) -> Result<(), CliError> {
    let snapshot = std::fs::read(file)
        .map_err(|err| CliError::local("USAGE", format!("cannot read policy file: {err}")))?;
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let body = proof_body(&password);
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_ACTIVATE, &snapshot, &body)?;
    print_json::<ipc::PolicyStatusResponse>(&meta)?;
    Ok(())
}

pub fn policy_status(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_STATUS, b"{}", &[])?;
    print_json::<ipc::PolicyStatusResponse>(&meta)?;
    Ok(())
}

pub fn execute(
    agent_socket: &Path,
    action: &str,
    capability: &str,
    body_file: Option<&Path>,
    content_type: Option<String>,
    headers: &[String],
) -> Result<(), CliError> {
    let (action_id, version) = parse_action_ref(action)?;
    let capability_token = if capability == "-" {
        String::from_utf8(stdin_lines(1)?.remove(0).to_vec())
            .map_err(|_| CliError::local("USAGE", "capability token must be utf-8"))?
    } else {
        capability.to_owned()
    };
    let body = match body_file {
        Some(path) => std::fs::read(path)
            .map_err(|err| CliError::local("USAGE", format!("cannot read body file: {err}")))?,
        None => Vec::new(),
    };
    let mut extra_headers = Vec::new();
    for header in headers {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| CliError::local("USAGE", "header must be NAME:VALUE"))?;
        extra_headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let metadata = serde_json::json!({
        "capability_token": capability_token,
        "action_id": action_id.to_string(),
        "action_version": version,
        "content_type": content_type,
        "extra_headers": extra_headers,
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

pub fn backup(state_dir: &Path, output: &Path, password_stdin: bool) -> Result<(), CliError> {
    let password = read_password(password_stdin, "Vault password (step-up): ")?;
    let metadata = serde_json::json!({ "output_path": output.display().to_string() });
    let body = proof_body(&password);
    let (meta, _) = admin_with_response_timeout(state_dir, BACKUP_RESPONSE_TIMEOUT)?.call(
        admin_msg::BACKUP,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<ipc::BackupReceipt>(&meta)?;
    Ok(())
}
