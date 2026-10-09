//! Command implementations. Secrets are read from a hidden TTY prompt or,
//! for automation, explicit stdin flags — never argv or environment.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "lab")]
use rekey_domain::action::FixedHttpAction;
use rekey_domain::credential::CredentialMetadata;
use rekey_domain::ids::CredentialId;
#[cfg(feature = "lab")]
use rekey_domain::ids::{ActionId, PrincipalId, SessionId};
#[cfg(feature = "lab")]
use rekey_domain::ipc::agent_msg;
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

#[cfg(feature = "lab")]
mod metrics;
#[cfg(feature = "lab")]
pub use metrics::metrics;
pub mod agent;
mod connect;
pub mod connections;
pub mod delegated;
pub mod hygiene;
pub mod ssh;
pub use connect::{ConnectClient, connect};
#[cfg(feature = "lab")]
mod run;
#[cfg(feature = "lab")]
pub use run::{RunClient, run_profile};
#[cfg(feature = "lab")]
mod templates;
#[cfg(feature = "lab")]
pub use templates::{template_catalog, template_install};

mod password_lifecycle;
pub use password_lifecycle::{key_rotate_dek, key_rotate_vrk, password_change, recovery_rotate};
mod github_admin;
pub use github_admin::{credential_apply_github_webhook, credential_rotate_github_app};
mod audit;
pub use audit::{
    audit_export, audit_list, audit_prune, audit_retention_set, audit_retention_status,
};
mod policy_approval;
pub use policy_approval::{
    approval_decide, approval_get, approval_origin, approval_pending, approval_review,
    approval_submit, policy_activate, policy_draft, policy_draft_request, policy_status,
    policy_trust_install,
};
#[cfg(feature = "lab")]
pub use policy_approval::{approval_prepare, profile_list};
#[cfg(feature = "lab")]
mod vault_admin;
#[cfg(feature = "lab")]
pub use vault_admin::{
    credential_add_aws_secrets_manager, credential_add_azure_key_vault,
    credential_add_gcp_secret_manager, credential_add_keycloak, credential_add_macos_keychain,
    credential_add_onepassword_connect, credential_add_vault_dynamic, credential_add_vault_kv,
    credential_rotate_aws_secrets_manager, credential_rotate_azure_key_vault,
    credential_rotate_gcp_secret_manager, credential_rotate_keycloak,
    credential_rotate_macos_keychain, credential_rotate_onepassword_connect,
    credential_rotate_vault_dynamic, credential_rotate_vault_kv,
};

#[cfg(feature = "lab")]
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
#[cfg(feature = "lab")]
struct RevokeResponse {
    revoked: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "lab")]
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
    write_json(&value)
}

fn write_json(value: &impl Serialize) -> Result<(), CliError> {
    let mut output = serde_json::to_vec_pretty(value)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    output.push(b'\n');
    std::io::stdout()
        .write_all(&output)
        .map_err(|err| CliError::local("OUTPUT_FAILED", format!("cannot write output: {err}")))
}

fn prompt_secret(prompt: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    crate::client::warn_before_secret_prompt()?;
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|err| CliError::local("USAGE", format!("cannot read from tty: {err}")))?,
    );
    if value.is_empty() || value.len() > ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize {
        return Err(CliError::local("USAGE", "empty or oversized input"));
    }
    Ok(Zeroizing::new(value.as_bytes().to_vec()))
}

pub(super) fn read_bounded(
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

/// Open with O_NOFOLLOW, require current-user ownership and mode & 0o077 == 0,
/// then read from the same validated descriptor (no path re-open).
pub(super) fn read_private_regular_file_bounded(
    path: &Path,
    limit: usize,
    label: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| CliError::local("USAGE", format!("cannot open {label}: {err}")))?;
    let metadata = opened
        .metadata()
        .map_err(|err| CliError::local("USAGE", format!("cannot inspect {label}: {err}")))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(CliError::local(
            "USAGE",
            format!(
                "{label} must be a current-user-owned regular file with no group/other permissions"
            ),
        ));
    }
    read_bounded(opened, limit, label)
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

fn step_up_prompt(kind: ProofKind) -> &'static str {
    match kind {
        ProofKind::Password => "Vault password (step-up): ",
        ProofKind::Recovery => "Recovery key (step-up): ",
        ProofKind::Presence => "Presence proof (stdin only): ",
    }
}

fn read_step_up(kind: ProofKind, proof_stdin: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if kind == ProofKind::Presence && !proof_stdin {
        return Err(CliError::local(
            "USAGE",
            "presence proof requires explicit stdin input",
        ));
    }
    read_password(proof_stdin, step_up_prompt(kind))
}

fn proof_body(kind: ProofKind, proof: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(proof.len() + 8));
    ipc::encode_proof_body(kind, proof, &mut body);
    body
}

#[cfg(feature = "lab")]
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

#[cfg(feature = "lab")]
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

#[cfg(feature = "lab")]
pub fn delegate_agent_run(
    state_dir: &Path,
    agent_socket: &Path,
    capability_stdin: bool,
    command: Vec<std::ffi::OsString>,
) -> Result<(), CliError> {
    let mut extra = vec![
        std::ffi::OsString::from("--agent-socket"),
        agent_socket.as_os_str().to_owned(),
    ];
    if capability_stdin {
        extra.push(std::ffi::OsString::from("--capability-stdin"));
    }
    extra.push(std::ffi::OsString::from("--"));
    extra.extend(command);
    delegate_rekeyd(state_dir, "agent-run", &extra, false)
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
    print_json::<ipc::UnlockResponse>(&meta)?;
    Ok(())
}

pub fn confirm_rollback(
    state_dir: &Path,
    expected_context: &str,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let expected =
        serde_json::from_str::<ipc::RollbackContext>(expected_context).map_err(|_| {
            CliError::local(
                "USAGE",
                "expected-context must be the complete context returned by status",
            )
        })?;
    let metadata = serde_json::to_vec(&ipc::RollbackConfirmMeta { expected })
        .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode rollback context"))?;
    let kind = proof_kind(recovery);
    let proof = read_step_up(kind, password_stdin)?;
    let body = proof_body(kind, &proof);
    let (metadata, _) = admin_with_response_timeout(state_dir, LIFECYCLE_RESPONSE_TIMEOUT)?.call(
        admin_msg::ROLLBACK_CONFIRM,
        &metadata,
        &body,
    )?;
    print_json::<LockResponse>(&metadata)
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

pub fn status(state_dir: &Path, passive: bool) -> Result<(), CliError> {
    let message = if passive {
        admin_msg::PASSIVE_STATUS
    } else {
        admin_msg::STATUS
    };
    let mut client = admin(state_dir)?;
    let (meta, _) = client.call(message, b"{}", &[])?;
    #[derive(Serialize)]
    struct LocalStatus {
        #[serde(flatten)]
        daemon: ipc::StatusResponse,
        peer_security: crate::client::PeerSecurity,
    }
    let daemon = serde_json::from_slice(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    write_json(&LocalStatus {
        daemon,
        peer_security: client.peer_security(),
    })
}

pub fn shutdown(state_dir: &Path, kind: ProofKind, password_stdin: bool) -> Result<(), CliError> {
    let mut client = admin_with_response_timeout(state_dir, DRAIN_RESPONSE_TIMEOUT)?;
    let proof = read_step_up(kind, password_stdin)?;
    let body = proof_body(kind, &proof);
    let (meta, _) = client.call(admin_msg::SHUTDOWN, b"{}", &body)?;
    print_json::<ShutdownResponse>(&meta)?;
    Ok(())
}

pub fn credential_add(
    state_dir: &Path,
    label: &str,
    credential_kind: &str,
    kind: ProofKind,
    stdin_secrets: bool,
) -> Result<(), CliError> {
    if credential_kind != "opaque-token" && !stdin_secrets {
        return Err(CliError::local(
            "USAGE",
            "typed credential JSON requires --stdin-secrets",
        ));
    }
    let (proof, secret) = if matches!(credential_kind, "mtls-identity" | "pki-ca-signer") {
        let mut input = std::io::stdin().lock();
        let proof = read_lines_bounded(
            &mut input,
            1,
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
            "proof",
        )?
        .remove(0);
        let secret = read_bounded(
            &mut input,
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
            "private material",
        )?;
        (proof, secret)
    } else if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let secret = lines.remove(1);
        let proof = lines.remove(0);
        (proof, secret)
    } else {
        (
            prompt_secret(step_up_prompt(kind))?,
            prompt_secret("Credential value: ")?,
        )
    };
    let metadata = serde_json::json!({ "label": label, "kind": credential_kind });
    let body_len = 1 + 4 + proof.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(kind, &proof, &secret, &mut body);
    debug_assert_eq!(body.len(), body_len);
    debug_assert_eq!(body.capacity(), body_capacity);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    if secret.len() < 16 {
        // A best-effort warning must not turn a completed mutation into failure.
        let _ = writeln!(
            std::io::stderr(),
            "warning: this credential is shorter than 16 bytes; reflected-secret sealing has limited coverage for embedded encodings. Use the provider's complete key."
        );
    }
    Ok(())
}

pub fn credential_add_github_app(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let limit = ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize;
    let secret = read_private_regular_file_bounded(file, limit, "GitHub App profile")?;
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
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({
        "label": label,
        "kind": "github-app-installation"
    });
    let body_len = 1 + 4 + proof.len() + 4 + secret.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    let body_capacity = body.capacity();
    ipc::encode_proof_and_secret_body(kind, &proof, &secret, &mut body);
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
    credential_kind: &str,
    expected_version: Option<u64>,
    kind: ProofKind,
    stdin_secrets: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let private = matches!(credential_kind, "mtls-identity" | "pki-ca-signer");
    let (message, metadata) = if private {
        if !stdin_secrets {
            return Err(CliError::local(
                "USAGE",
                "private credentials require --stdin-secrets",
            ));
        }
        let expected_version = expected_version.ok_or_else(|| {
            CliError::local("USAGE", "private rotation requires --expected-version")
        })?;
        (
            if credential_kind == "mtls-identity" {
                admin_msg::CREDENTIAL_ROTATE_MTLS
            } else {
                admin_msg::CREDENTIAL_ROTATE_CA
            },
            serde_json::json!({"credential_id":credential_id,"expected_version":expected_version}),
        )
    } else {
        if credential_kind != "opaque-token" || expected_version.is_some() {
            return Err(CliError::local("USAGE", "invalid rotation kind or version"));
        }
        (
            admin_msg::CREDENTIAL_ROTATE,
            serde_json::json!({"credential_id":credential_id}),
        )
    };
    let (proof, secret) = if private {
        let mut input = std::io::stdin().lock();
        let proof = read_lines_bounded(
            &mut input,
            1,
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
            "proof",
        )?
        .remove(0);
        let secret = read_bounded(
            &mut input,
            ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
            "private material",
        )?;
        (proof, secret)
    } else if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let secret = lines.remove(1);
        (lines.remove(0), secret)
    } else {
        (
            prompt_secret(step_up_prompt(kind))?,
            prompt_secret("New credential value: ")?,
        )
    };
    let mut body = Zeroizing::new(Vec::with_capacity(1 + 4 + proof.len() + 4 + secret.len()));
    ipc::encode_proof_and_secret_body(kind, &proof, &secret, &mut body);
    let (meta, _) = admin(state_dir)?.call(message, metadata.to_string().as_bytes(), &body)?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

pub fn pki_generate_crl(
    state_dir: &Path,
    credential_id: &str,
    version: u64,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::to_vec(&ipc::PkiGenerateCrlMeta {
        credential_id,
        version,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode CRL request"))?;
    let (meta, body) = admin(state_dir)?.call(
        admin_msg::PKI_GENERATE_CRL,
        &metadata,
        &proof_body(kind, &proof),
    )?;
    let _: ipc::PkiCrlResponse = serde_json::from_slice(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid CRL response"))?;
    std::io::stdout()
        .write_all(&body)
        .map_err(|err| CliError::local("OUTPUT_FAILED", format!("cannot write output: {err}")))?;
    Ok(())
}

pub fn pki_revoke_certificate(
    state_dir: &Path,
    serial_hex: &str,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::to_vec(&ipc::PkiRevokeCertificateMeta {
        serial_hex: serial_hex.into(),
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode certificate revocation"))?;
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::PKI_REVOKE_CERTIFICATE, &metadata, &body)?;
    print_json::<ipc::PkiRevocationResponse>(&meta)?;
    Ok(())
}

pub fn pki_issue_client_csr(
    state_dir: &Path,
    credential_id: &str,
    expected_version: u64,
    csr_file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let csr =
        read_regular_file_bounded(csr_file, ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize, "CSR")?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::to_vec(&ipc::PkiIssueClientCsrMeta {
        credential_id,
        expected_version,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode CSR metadata"))?;
    let mut body = Zeroizing::new(Vec::with_capacity(9 + proof.len() + csr.len()));
    ipc::encode_proof_and_secret_body(kind, &proof, &csr, &mut body);
    let (meta, _) = admin(state_dir)?.call(admin_msg::PKI_ISSUE_CLIENT_CSR, &metadata, &body)?;
    print_json::<ipc::PkiCertificateResponse>(&meta)?;
    Ok(())
}

pub fn credential_revoke(
    state_dir: &Path,
    credential_id: &str,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_REVOKE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
pub fn action_create(
    state_dir: &Path,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let definition =
        read_regular_file_bounded(file, ipc::METADATA_MAX_BYTES as usize, "action file")?;
    // Validate shape client-side for a friendly error; the broker re-validates.
    serde_json::from_slice::<ipc::ActionCreateMeta>(&definition)
        .map_err(|err| CliError::local("USAGE", format!("invalid action definition: {err}")))?;
    let proof = read_step_up(kind, password_stdin)?;
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_CREATE, &definition, &body)?;
    print_json::<FixedHttpAction>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
pub fn action_update(
    state_dir: &Path,
    action_id: &str,
    file: &Path,
    kind: ProofKind,
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
    let proof = read_step_up(kind, password_stdin)?;
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_UPDATE, &metadata, &body)?;
    print_json::<FixedHttpAction>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
pub fn action_list(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::ACTION_LIST, b"{}", &[])?;
    print_json::<ipc::ActionListResponse>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
pub fn action_disable(
    state_dir: &Path,
    action_id: &str,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let action_id: ActionId = action_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid action id"))?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({ "action_id": action_id.to_string() });
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::ACTION_DISABLE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<DisableResponse>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
pub fn session_create(
    state_dir: &Path,
    actions: &[String],
    ttl: &str,
    max_uses: u32,
    principal: Option<&str>,
    kind: ProofKind,
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
    let principal_id = principal
        .map(str::parse::<PrincipalId>)
        .transpose()
        .map_err(|_| CliError::local("USAGE", "invalid principal id"))?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({
        "actions": refs,
        "ttl_ms": ttl_ms,
        "max_uses": max_uses,
        "principal_id": principal_id,
    });
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::SESSION_CREATE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    // Shown exactly once; prefer piping to the agent instead of shell history.
    print_json::<ipc::SessionCreatedResponse>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
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

#[cfg(feature = "lab")]
pub fn session_revoke(
    state_dir: &Path,
    session_id: &str,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let session_id: SessionId = session_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid session id"))?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({ "session_id": session_id.to_string() });
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::SESSION_REVOKE,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<RevokeResponse>(&meta)?;
    Ok(())
}

#[cfg(feature = "lab")]
pub fn execute(
    agent_socket: &Path,
    action: &str,
    capability: &str,
    request: &crate::RequestArgs,
    approvals: &[PathBuf],
    challenge: Option<rekey_domain::ids::ApprovalRequestId>,
) -> Result<(), CliError> {
    if challenge.is_some() && !approvals.is_empty() {
        return Err(CliError::local(
            "USAGE",
            "--challenge conflicts with --approval",
        ));
    }
    let (action_id, version) = parse_action_ref(action)?;
    let capability_token = policy_approval::capability_value(capability)?;
    let body = policy_approval::request_body(request.body_file.as_deref())?;
    let extra_headers = policy_approval::request_headers(&request.headers)?;
    let approval_grants = policy_approval::read_approval_files(approvals)?;
    let metadata = serde_json::json!({
        "capability_token": capability_token,
        "action_id": action_id.to_string(),
        "action_version": version,
        "content_type": request.content_type,
        "params": policy_approval::request_values(&request.params)?,
        "query": policy_approval::request_values(&request.query)?,
        "extra_headers": extra_headers,
        "approval_grants": approval_grants,
        "local_approval_request_id": challenge,
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
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let output_path = output
        .to_str()
        .ok_or_else(|| CliError::local("USAGE", "backup output path must be valid UTF-8"))?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({ "output_path": output_path });
    let body = proof_body(kind, &proof);
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

pub fn desktop_login(state_dir: &Path, recovery: bool) -> Result<(), CliError> {
    let proof = read_step_up(proof_kind(recovery), true)?;
    let mut body = Zeroizing::new(Vec::with_capacity(5 + proof.len()));
    ipc::encode_proof_body(proof_kind(recovery), &proof, &mut body);
    let (_, token) = admin(state_dir)?.call(admin_msg::DESKTOP_LOGIN, b"{}", &body)?;
    std::io::stdout()
        .write_all(&token)
        .map_err(|e| CliError::local("IO", e.to_string()))
}

pub fn desktop_add(state_dir: &Path, label: &str) -> Result<(), CliError> {
    let mut lines = stdin_lines(2)?;
    let secret = lines.remove(1);
    let token = lines.remove(0);
    let mut body = Zeroizing::new(Vec::with_capacity(9 + token.len() + secret.len()));
    ipc::encode_proof_and_secret_body(ProofKind::Password, &token, &secret, &mut body);
    let metadata = serde_json::json!({"label":label,"kind":"opaque-token"});
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::DESKTOP_ADD,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&meta)?;
    if secret.len() < 16 {
        // A best-effort warning must not turn a completed mutation into failure.
        let _ = writeln!(
            std::io::stderr(),
            "warning: this credential is shorter than 16 bytes; reflected-secret sealing has limited coverage for embedded encodings. Use the provider's complete key."
        );
    }
    Ok(())
}

#[cfg(feature = "lab")]
pub fn desktop_reveal(
    state_dir: &Path,
    credential_id: &str,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let mut client = admin(state_dir)?;
    let proof = read_step_up(kind, password_stdin)?;
    let body = proof_body(kind, &proof);
    let metadata = serde_json::json!({"credential_id":credential_id});
    let (_, value) = client.call(
        admin_msg::DESKTOP_REVEAL,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    std::io::stdout()
        .write_all(&value)
        .map_err(|e| CliError::local("IO", e.to_string()))
}

// Expiry is public; the secret remains in the IPC body and explicit stdout pipe.
pub fn desktop_restore_access(
    state_dir: &Path,
    resume: bool,
    kind: ProofKind,
) -> Result<(), CliError> {
    let proof = read_step_up(kind, true)?;
    let mut body = Zeroizing::new(Vec::with_capacity(5 + proof.len()));
    ipc::encode_proof_body(kind, &proof, &mut body);
    let message = if resume {
        admin_msg::DESKTOP_RESUME
    } else {
        admin_msg::DESKTOP_REMEMBER
    };
    let (meta, secret) = admin(state_dir)?.call(message, b"{}", &body)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Expiry {
        expires_at_ms: i64,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResumedExpiry {
        expires_at_ms: i64,
        #[serde(rename = "lease_recovery")]
        _lease_recovery: ipc::LeaseRecoverySummary,
    }
    let expires_at_ms = if resume {
        serde_json::from_slice::<ResumedExpiry>(&meta).map(|reply| reply.expires_at_ms)
    } else {
        serde_json::from_slice::<Expiry>(&meta).map(|reply| reply.expires_at_ms)
    }
    .map_err(|_| CliError::local("INVALID_FRAME", "invalid desktop expiry"))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{expires_at_ms}")
        .and_then(|_| out.write_all(&secret))
        .map_err(|e| CliError::local("IO", e.to_string()))
}

#[cfg(feature = "lab")]
pub fn execute_text_stream(
    agent_socket: &Path,
    action: &str,
    capability: &str,
    body_file: &Path,
    approvals: &[PathBuf],
    challenge: Option<rekey_domain::ids::ApprovalRequestId>,
) -> Result<(), CliError> {
    if challenge.is_some() && !approvals.is_empty() {
        return Err(CliError::local(
            "USAGE",
            "--challenge conflicts with --approval",
        ));
    }
    let (action_id, version) = parse_action_ref(action)?;
    let capability_token = policy_approval::capability_value(capability)?;
    let body = policy_approval::request_body(Some(body_file))?;
    let approval_grants = policy_approval::read_approval_files(approvals)?;
    let metadata = serde_json::json!({
        "capability_token":capability_token,"action_id":action_id,"action_version":version,
        "content_type":"application/json","extra_headers":[],"approval_grants":approval_grants,
        "local_approval_request_id": challenge
    });
    Client::connect_with_response_timeout(agent_socket, Channel::Agent, ACTION_RESPONSE_TIMEOUT)?
        .text_stream(
        metadata.to_string().as_bytes(),
        &body,
        std::io::stdout().lock(),
    )?;
    eprintln!("text stream completed");
    Ok(())
}

#[cfg(feature = "lab")]
pub fn oidc_begin(state_dir: &Path) -> Result<(), CliError> {
    let (metadata, body) = admin(state_dir)?.call(admin_msg::OIDC_LOGIN_BEGIN, b"{}", &[])?;
    if !body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "unexpected OIDC response body",
        ));
    }
    print_json::<ipc::OidcBeginResponse>(&metadata)
}
#[cfg(feature = "lab")]
pub fn oidc_cancel(state_dir: &Path, flow_id: &str) -> Result<(), CliError> {
    let metadata = serde_json::to_vec(&ipc::OidcFlowMeta {
        flow_id: flow_id.to_owned(),
    })
    .map_err(|_| CliError::local("USAGE", "invalid flow"))?;
    let (metadata, body) = admin(state_dir)?.call(admin_msg::OIDC_LOGIN_CANCEL, &metadata, &[])?;
    if !body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "unexpected OIDC response body",
        ));
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Cancelled {
        cancelled: bool,
    }
    print_json::<Cancelled>(&metadata)
}
#[cfg(feature = "lab")]
pub fn oidc_finish(state_dir: &Path, flow_id: &str, path: &Path) -> Result<(), CliError> {
    let metadata = serde_json::to_vec(&ipc::OidcFlowMeta {
        flow_id: flow_id.to_owned(),
    })
    .map_err(|_| CliError::local("USAGE", "invalid flow"))?;
    let (metadata, token) = admin_with_response_timeout(state_dir, Duration::from_secs(125))?
        .call(admin_msg::OIDC_LOGIN_FINISH, &metadata, &[])?;
    let response: ipc::OidcSessionResponse = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid OIDC session response"))?;
    ipc::validate_management_token(&token)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid management token"))?;
    write_management_session(path, &token)?;
    print_json::<ipc::OidcSessionResponse>(
        &serde_json::to_vec(&response)
            .map_err(|_| CliError::local("INVALID_FRAME", "invalid OIDC response"))?,
    )
}
#[cfg(feature = "lab")]
pub fn oidc_logout(state_dir: &Path, path: &Path) -> Result<(), CliError> {
    let token = crate::client::private_session_file(path)?;
    let (metadata, body) = admin(state_dir)?.call(admin_msg::OIDC_LOGOUT, b"{}", &token)?;
    if !body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "unexpected OIDC response body",
        ));
    }
    print_json::<ipc::OidcLogoutResponse>(&metadata)
}
#[cfg(feature = "lab")]
fn write_management_session(path: &Path, token: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let invalid = || {
        CliError::local(
            "OUTPUT_FAILED",
            "cannot create protected management session file",
        )
    };
    let parent = path.parent().ok_or_else(invalid)?;
    let pm = std::fs::symlink_metadata(parent).map_err(|_| invalid())?;
    if !pm.is_dir() || pm.uid() != unsafe { libc::geteuid() } || pm.mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    for ancestor in parent.ancestors() {
        if std::fs::symlink_metadata(ancestor)
            .map_err(|_| invalid())?
            .file_type()
            .is_symlink()
        {
            return Err(invalid());
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| invalid())?;
    file.write_all(token)
        .and_then(|_| file.sync_all())
        .map_err(|_| invalid())?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| invalid())
}

fn onboarding_url(
    state_dir: &Path,
    provider: Option<&str>,
    inapplicable: bool,
) -> Result<String, CliError> {
    if inapplicable || state_dir != resolve_state_dir(None)? {
        return Err(CliError::local(
            "USAGE",
            "App onboarding requires the default state directory and no socket or management-session override",
        ));
    }
    Ok(match provider {
        Some(provider) => format!("rekey://add/{provider}"),
        None => "rekey://setup".into(),
    })
}

pub fn open_onboarding(
    state_dir: &Path,
    provider: Option<&str>,
    inapplicable: bool,
) -> Result<(), CliError> {
    let url = onboarding_url(state_dir, provider, inapplicable)?;
    #[cfg(target_os = "macos")]
    {
        if !Path::new("/Applications/Rekey.app").is_dir() {
            return Err(CliError::local(
                "LAUNCHER_UNAVAILABLE",
                "Install Rekey.app in /Applications before opening onboarding",
            ));
        }
        let status = std::process::Command::new("/usr/bin/open")
            .args(["-a", "/Applications/Rekey.app", &url])
            .stdin(std::process::Stdio::null())
            .status()
            .map_err(|_| {
                CliError::local(
                    "LAUNCHER_UNAVAILABLE",
                    "Could not open the installed Rekey App",
                )
            })?;
        if !status.success() {
            return Err(CliError::local(
                "LAUNCHER_UNAVAILABLE",
                "The system rejected the App opening request",
            ));
        }
        println!("已请求打开 Rekey；请在 App 中确认并完成设置。此消息不表示保险库或授权已创建。");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = url;
        Err(CliError::local(
            "LAUNCHER_UNAVAILABLE",
            "App onboarding is available only on macOS",
        ))
    }
}

#[cfg(test)]
mod onboarding_tests {
    use super::*;
    #[test]
    fn routes_are_fixed_and_overrides_fail_without_launching() {
        let state = resolve_state_dir(None).unwrap();
        assert_eq!(
            onboarding_url(&state, None, false).unwrap(),
            "rekey://setup"
        );
        assert_eq!(
            onboarding_url(&state, Some("anthropic"), false).unwrap(),
            "rekey://add/anthropic"
        );
        assert!(onboarding_url(&state, None, true).is_err());
        assert!(onboarding_url(&state.join("different"), Some("anthropic"), false).is_err());
    }
}
