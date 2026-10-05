//! SSH key management is IPC-only; imported private bytes stay in raw frame bodies.
use std::path::Path;

use rekey_domain::connection::SshKeyConnection;
use rekey_domain::credential::CredentialMetadata;
use rekey_domain::ipc::{self, ProofKind, admin_msg};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::client::CliError;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SshKeyReceipt {
    credential: CredentialMetadata,
    public_key: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SshStatus {
    socket: std::path::PathBuf,
    ssh_keys: Vec<SshKeyConnection>,
}
fn response<T: DeserializeOwned + Serialize>(metadata: &[u8], body: &[u8]) -> Result<(), CliError> {
    if serde_json::from_slice::<Value>(metadata).ok() != Some(json!({})) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "SSH response metadata must be empty",
        ));
    }
    let response: T = serde_json::from_slice(body)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid public SSH response"))?;
    super::write_json(&response)
}
pub fn status(state_dir: &Path) -> Result<(), CliError> {
    let (metadata, body) =
        super::admin(state_dir)?.call(admin_msg::SSH_KEY, br#"{"action":"status"}"#, &[])?;
    response::<SshStatus>(&metadata, &body)
}
pub fn generate(
    state_dir: &Path,
    label: String,
    mode: &str,
    kind: ProofKind,
    stdin: bool,
) -> Result<(), CliError> {
    let mut client = super::admin(state_dir)?;
    let proof = super::read_step_up(kind, stdin)?;
    let body = super::proof_body(kind, &proof);
    let metadata = serde_json::to_vec(&json!({"action":"generate","label":label,"mode":mode}))
        .map_err(|_| CliError::local("USAGE", "cannot encode SSH generation request"))?;
    let (metadata, body) = client.call(admin_msg::SSH_KEY, &metadata, &body)?;
    response::<SshKeyReceipt>(&metadata, &body)
}
pub fn import(state_dir: &Path, label: String, kind: ProofKind) -> Result<(), CliError> {
    let mut client = super::admin(state_dir)?;
    let limit = ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize;
    let input = super::read_bounded(std::io::stdin().lock(), limit * 2 + 1, "SSH import stdin")?;
    let newline = input
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| {
            CliError::local(
                "USAGE",
                "SSH import requires a proof line followed by a complete private key",
            )
        })?;
    let proof = input[..newline]
        .strip_suffix(b"\r")
        .unwrap_or(&input[..newline]);
    let key = &input[newline + 1..];
    if proof.len() > limit || key.is_empty() || key.len() > limit {
        return Err(CliError::local(
            "USAGE",
            "SSH proof and private key must each fit in 64 KiB",
        ));
    }
    let mut body = Zeroizing::new(Vec::with_capacity(9 + proof.len() + key.len()));
    ipc::encode_proof_and_secret_body(kind, proof, key, &mut body);
    let metadata = serde_json::to_vec(&json!({"action":"import","label":label}))
        .map_err(|_| CliError::local("USAGE", "cannot encode SSH import request"))?;
    let (metadata, body) = client.call(admin_msg::SSH_KEY, &metadata, &body)?;
    response::<SshKeyReceipt>(&metadata, &body)
}
