//! File-based GitHub App Admin commands.

use std::path::Path;

use rekey_domain::credential::CredentialMetadata;
use rekey_domain::ids::CredentialId;
use rekey_domain::ipc::{self, admin_msg};
use zeroize::Zeroizing;

use super::{
    CliError, GitHubProfileMarker, admin, print_json, proof_kind, read_regular_file_bounded,
    read_step_up,
};

pub fn credential_rotate_github_app(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id = parse_credential_id(credential_id)?;
    let profile = github_file(file)?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body = proof_and_bytes(recovery, &proof, &profile);
    let (response, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ROTATE_GITHUB_APP,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&response)
}

#[allow(clippy::too_many_arguments)]
pub fn credential_apply_github_webhook(
    state_dir: &Path,
    credential_id: &str,
    expected_version: u64,
    event: &str,
    delivery: &str,
    signature: &str,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id = parse_credential_id(credential_id)?;
    if expected_version == 0 {
        return Err(CliError::local(
            "USAGE",
            "expected version must be positive",
        ));
    }
    let payload = read_regular_file_bounded(
        file,
        ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
        "GitHub webhook payload",
    )?;
    if payload.is_empty() {
        return Err(CliError::local(
            "USAGE",
            "GitHub webhook payload must be 1..=64 KiB",
        ));
    }
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = ipc::GitHubWebhookApplyMeta {
        credential_id,
        expected_version,
        event: event.to_owned(),
        delivery: delivery.to_owned(),
        signature: signature.to_owned(),
    };
    let encoded = serde_json::to_vec(&metadata)
        .map_err(|_| CliError::local("USAGE", "invalid GitHub webhook metadata"))?;
    let body = proof_and_bytes(recovery, &proof, &payload);
    let (response, _) = admin(state_dir)?.call(admin_msg::GITHUB_WEBHOOK_APPLY, &encoded, &body)?;
    print_json::<CredentialMetadata>(&response)
}

fn github_file(file: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let profile = read_regular_file_bounded(
        file,
        ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
        "GitHub App profile",
    )?;
    if profile.is_empty() {
        return Err(CliError::local(
            "USAGE",
            "GitHub App profile must be 1..=64 KiB",
        ));
    }
    let marker: GitHubProfileMarker<'_> = serde_json::from_slice(&profile)
        .map_err(|_| CliError::local("USAGE", "invalid GitHub App profile JSON"))?;
    if marker.credential_type != "github-app-installation-v2" {
        return Err(CliError::local(
            "USAGE",
            "GitHub App profile has the wrong credential_type",
        ));
    }
    Ok(profile)
}

fn parse_credential_id(value: &str) -> Result<CredentialId, CliError> {
    value
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))
}

fn proof_and_bytes(recovery: bool, proof: &[u8], value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(1 + 4 + proof.len() + 4 + value.len()));
    ipc::encode_proof_and_secret_body(proof_kind(recovery), proof, value, &mut body);
    body
}
