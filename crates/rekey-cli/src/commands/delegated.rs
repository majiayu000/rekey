//! Explicit T1 adapters and human OAuth onboarding; root credentials remain in the daemon.
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use rekey_domain::ids::{ApprovalRequestId, RequestId};
use rekey_domain::ipc::{
    Channel, DeriveCredentialMeta, OAuthLoginMeta, ProofKind, admin_msg, agent_msg,
};
use serde::{Deserialize, Serialize};

use crate::client::{CliError, Client};

pub enum DerivedFormat {
    Aws,
    Kubectl,
    GitHub,
}
impl DerivedFormat {
    fn kind(&self) -> &'static str {
        match self {
            Self::Aws => "aws-assume-role",
            Self::Kubectl => "kubernetes-eks",
            Self::GitHub => "github-app",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedReceipt {
    connection: String,
    kind: String,
    expires_at_ms: i64,
}

pub fn derive(
    socket: &Path,
    connection: String,
    approval_request_id: Option<ApprovalRequestId>,
    format: DerivedFormat,
) -> Result<(), CliError> {
    let request = serde_json::to_vec(&DeriveCredentialMeta {
        connection: connection.clone(),
        approval_request_id,
    })
    .map_err(|_| {
        CliError::local(
            "INVALID_INPUT",
            "cannot encode temporary credential request",
        )
    })?;
    let (metadata, body) =
        Client::connect_with_response_timeout(socket, Channel::Agent, Duration::from_secs(40))?
            .call(agent_msg::DERIVE_CREDENTIAL, &request, &[])?;
    let receipt: DerivedReceipt = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid temporary credential receipt"))?;
    if receipt.connection != connection
        || receipt.kind != format.kind()
        || receipt.expires_at_ms <= 0
        || body.is_empty()
    {
        return Err(CliError::local(
            "INVALID_FRAME",
            "temporary credential does not match the requested adapter",
        ));
    }
    let _ = writeln!(
        std::io::stderr(),
        "T1：Agent 进程会拿到有效期受限的临时凭证；根凭证保留在 Rekey。"
    );
    std::io::stdout().lock().write_all(&body).map_err(|error| {
        CliError::local(
            "OUTPUT_FAILED",
            format!("cannot write temporary credential: {error}"),
        )
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OAuthLoginReceipt {
    authorization_url: String,
    request_id: RequestId,
    expires_at_ms: i64,
}

fn oauth_url(state_dir: &Path, connection: &str, inapplicable: bool) -> Result<String, CliError> {
    if inapplicable || state_dir != super::resolve_state_dir(None)? {
        return Err(CliError::local(
            "USAGE",
            "App OAuth login requires the default state directory and no socket or management-session override",
        ));
    }
    let mut escaped = String::new();
    for byte in connection.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(format!("rekey://oauth?connection={escaped}"))
}

pub fn oauth_login(
    state_dir: &Path,
    connection: String,
    redirect_uri: Option<String>,
    proof_stdin: bool,
    kind: ProofKind,
    inapplicable: bool,
) -> Result<(), CliError> {
    if proof_stdin {
        let mut client = super::admin(state_dir)?;
        let proof = super::read_step_up(kind, true)?;
        let request = serde_json::to_vec(&OAuthLoginMeta {
            connection,
            redirect_uri,
        })
        .map_err(|_| CliError::local("USAGE", "cannot encode OAuth login request"))?;
        let (metadata, body) = client.call(
            admin_msg::OAUTH_LOGIN,
            &request,
            &super::proof_body(kind, &proof),
        )?;
        let receipt: OAuthLoginReceipt = serde_json::from_slice(&metadata)
            .map_err(|_| CliError::local("INVALID_FRAME", "invalid OAuth login receipt"))?;
        if !body.is_empty() || receipt.authorization_url.is_empty() || receipt.expires_at_ms <= 0 {
            return Err(CliError::local(
                "INVALID_FRAME",
                "invalid OAuth login receipt",
            ));
        }
        return super::write_json(&receipt);
    }
    let url = oauth_url(state_dir, &connection, inapplicable)?;
    #[cfg(target_os = "macos")]
    {
        if !Path::new("/Applications/Rekey.app").is_dir() {
            return Err(CliError::local(
                "LAUNCHER_UNAVAILABLE",
                "Install Rekey.app in /Applications before opening OAuth login",
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
                "The system rejected the OAuth App opening request",
            ));
        }
        println!("已请求打开 Rekey；请在 App 中确认 OAuth 登录并在浏览器完成授权。");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CliError::local(
            "LAUNCHER_UNAVAILABLE",
            format!("Open {url} in the Rekey App to complete OAuth login"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oauth_front_door_encodes_names_and_rejects_wrong_vault_overrides() {
        let state_dir = super::super::resolve_state_dir(None).unwrap();
        assert_eq!(
            oauth_url(&state_dir, "google/name ?中", false).unwrap(),
            "rekey://oauth?connection=google%2Fname%20%3F%E4%B8%AD"
        );
        assert!(oauth_url(&state_dir, "google", true).is_err());
        assert!(oauth_url(Path::new("/synthetic/other-vault"), "google", false).is_err());
    }
}
