use std::path::Path;

use rekey_domain::credential::CredentialMetadata;
use rekey_domain::ids::CredentialId;
use rekey_domain::ipc::{self, admin_msg};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{CliError, admin, print_json, proof_kind, read_regular_file_bounded, read_step_up};

#[derive(Deserialize)]
struct VaultProfileMarker<'a> {
    #[serde(borrow)]
    credential_type: &'a str,
}

pub fn credential_add_vault_kv(
    state_dir: &Path,
    label: &str,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let profile = vault_profile_file(file)?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({
        "label": label,
        "kind": "vault-kv-v2-source"
    });
    let body = proof_and_profile(recovery, &proof, &profile);
    let (response, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&response)
}

pub fn credential_rotate_vault_kv(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let profile = vault_profile_file(file)?;
    let proof = read_step_up(recovery, password_stdin)?;
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body = proof_and_profile(recovery, &proof, &profile);
    let (response, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    print_json::<CredentialMetadata>(&response)
}

fn vault_profile_file(file: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let profile = read_regular_file_bounded(
        file,
        ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
        "Vault KV profile",
    )?;
    if profile.is_empty() {
        return Err(CliError::local(
            "USAGE",
            "Vault KV profile must be 1..=64 KiB",
        ));
    }
    let marker: VaultProfileMarker<'_> = serde_json::from_slice(&profile)
        .map_err(|_| CliError::local("USAGE", "invalid Vault KV profile JSON"))?;
    if marker.credential_type != "vault-kv-v2-source-v1" {
        return Err(CliError::local(
            "USAGE",
            "Vault KV profile has the wrong credential_type",
        ));
    }
    Ok(profile)
}

fn proof_and_profile(recovery: bool, proof: &[u8], profile: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(1 + 4 + proof.len() + 4 + profile.len()));
    ipc::encode_proof_and_secret_body(proof_kind(recovery), proof, profile, &mut body);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_profile_file_requires_the_closed_marker_and_bound() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("profile.json");
        std::fs::write(&file, br#"{"credential_type":"vault-kv-v2-source-v1"}"#).unwrap();
        assert!(vault_profile_file(&file).is_ok());

        std::fs::write(&file, br#"{"credential_type":"other"}"#).unwrap();
        assert_eq!(vault_profile_file(&file).unwrap_err().code, "USAGE");

        std::fs::write(&file, Vec::new()).unwrap();
        assert_eq!(vault_profile_file(&file).unwrap_err().code, "USAGE");

        std::fs::write(
            &file,
            vec![b'x'; ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(vault_profile_file(&file).unwrap_err().code, "INVALID_FRAME");
    }
}
