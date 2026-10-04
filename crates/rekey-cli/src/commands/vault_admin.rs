use rekey_domain::ipc::ProofKind;
use std::path::Path;

use rekey_domain::credential::CredentialMetadata;
use rekey_domain::ids::CredentialId;
use rekey_domain::ipc::{self, admin_msg};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{CliError, admin, print_json, read_private_regular_file_bounded, read_step_up};

#[derive(Deserialize)]
struct VaultProfileMarker<'a> {
    #[serde(borrow)]
    credential_type: &'a str,
}

pub fn credential_add_macos_keychain(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "macos-keychain-source-v1",
        "macos-keychain-source",
        "macOS Keychain reference",
    )
}
pub fn credential_rotate_macos_keychain(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "macos-keychain-source-v1",
        admin_msg::CREDENTIAL_ROTATE_MACOS_KEYCHAIN,
        "macOS Keychain reference",
    )
}

pub fn credential_add_gcp_secret_manager(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "gcp-secret-manager-source-v1",
        "gcp-secret-manager-source",
        "GCP Secret Manager profile",
    )
}

pub fn credential_rotate_gcp_secret_manager(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "gcp-secret-manager-source-v1",
        admin_msg::CREDENTIAL_ROTATE_GCP_SECRET_MANAGER,
        "GCP Secret Manager profile",
    )
}

pub fn credential_add_azure_key_vault(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "azure-key-vault-source-v1",
        "azure-key-vault-source",
        "Azure Key Vault profile",
    )
}

pub fn credential_rotate_azure_key_vault(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "azure-key-vault-source-v1",
        admin_msg::CREDENTIAL_ROTATE_AZURE_KEY_VAULT,
        "Azure Key Vault profile",
    )
}

pub fn credential_add_onepassword_connect(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "onepassword-connect-source-v1",
        "onepassword-connect-source",
        "1Password Connect profile",
    )
}

pub fn credential_rotate_onepassword_connect(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "onepassword-connect-source-v1",
        admin_msg::CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT,
        "1Password Connect profile",
    )
}

pub fn credential_add_aws_secrets_manager(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "aws-secrets-manager-source-v1",
        "aws-secrets-manager-source",
        "AWS Secrets Manager profile",
    )
}

pub fn credential_rotate_aws_secrets_manager(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "aws-secrets-manager-source-v1",
        admin_msg::CREDENTIAL_ROTATE_AWS_SECRETS_MANAGER,
        "AWS Secrets Manager profile",
    )
}

pub fn credential_add_keycloak(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "keycloak-token-exchange-v1",
        "keycloak-token-exchange",
        "Keycloak profile",
    )
}
pub fn credential_rotate_keycloak(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "keycloak-token-exchange-v1",
        admin_msg::CREDENTIAL_ROTATE_KEYCLOAK,
        "Keycloak profile",
    )
}

pub fn credential_add_vault_kv(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "vault-kv-v2-source-v1",
        "vault-kv-v2-source",
        "Vault KV profile",
    )
}

pub fn credential_add_vault_dynamic(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    add_vault_profile(
        state_dir,
        label,
        file,
        kind,
        password_stdin,
        "vault-dynamic-source-v2",
        "vault-dynamic-source",
        "Vault dynamic profile",
    )
}

#[allow(clippy::too_many_arguments)]
fn add_vault_profile(
    state_dir: &Path,
    label: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
    marker: &'static str,
    credential_kind: &'static str,
    profile_label: &'static str,
) -> Result<(), CliError> {
    let profile = vault_profile_file(file, marker, profile_label)?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({
        "label": label,
        "kind": credential_kind
    });
    let body = proof_and_profile(kind, &proof, &profile);
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
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "vault-kv-v2-source-v1",
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
        "Vault KV profile",
    )
}

pub fn credential_rotate_vault_dynamic(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    rotate_vault_profile(
        state_dir,
        credential_id,
        file,
        kind,
        password_stdin,
        "vault-dynamic-source-v2",
        admin_msg::CREDENTIAL_ROTATE_VAULT_DYNAMIC,
        "Vault dynamic profile",
    )
}

#[allow(clippy::too_many_arguments)]
fn rotate_vault_profile(
    state_dir: &Path,
    credential_id: &str,
    file: &Path,
    kind: ProofKind,
    password_stdin: bool,
    marker: &'static str,
    message_type: u16,
    profile_label: &'static str,
) -> Result<(), CliError> {
    let credential_id: CredentialId = credential_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid credential id"))?;
    let profile = vault_profile_file(file, marker, profile_label)?;
    let proof = read_step_up(kind, password_stdin)?;
    let metadata = serde_json::json!({ "credential_id": credential_id.to_string() });
    let body = proof_and_profile(kind, &proof, &profile);
    let (response, _) =
        admin(state_dir)?.call(message_type, metadata.to_string().as_bytes(), &body)?;
    print_json::<CredentialMetadata>(&response)
}

fn vault_profile_file(
    file: &Path,
    expected_marker: &str,
    profile_label: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let profile = read_private_regular_file_bounded(
        file,
        ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize,
        profile_label,
    )?;
    if profile.is_empty() {
        return Err(CliError::local(
            "USAGE",
            format!("{profile_label} must be 1..=64 KiB"),
        ));
    }
    let marker: VaultProfileMarker<'_> = serde_json::from_slice(&profile)
        .map_err(|_| CliError::local("USAGE", format!("invalid {profile_label} JSON")))?;
    if marker.credential_type != expected_marker
        && !(expected_marker == "vault-kv-v2-source-v1"
            && marker.credential_type == "vault-approle-kv-v2-source-v1")
    {
        return Err(CliError::local(
            "USAGE",
            format!("{profile_label} has the wrong credential_type"),
        ));
    }
    Ok(profile)
}

fn proof_and_profile(kind: ProofKind, proof: &[u8], profile: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(1 + 4 + proof.len() + 4 + profile.len()));
    ipc::encode_proof_and_secret_body(kind, proof, profile, &mut body);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn vault_profile_file_requires_the_closed_marker_and_bound() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("profile.json");
        write_private(
            &file,
            br#"{"credential_type":"gcp-secret-manager-source-v1"}"#,
        );
        assert!(
            vault_profile_file(
                &file,
                "gcp-secret-manager-source-v1",
                "GCP Secret Manager profile"
            )
            .is_ok()
        );
        write_private(
            &file,
            br#"{"credential_type":"aws-secrets-manager-source-v1"}"#,
        );
        assert!(
            vault_profile_file(
                &file,
                "aws-secrets-manager-source-v1",
                "AWS Secrets Manager profile"
            )
            .is_ok()
        );
        write_private(&file, br#"{"credential_type":"azure-key-vault-source-v1"}"#);
        assert!(
            vault_profile_file(
                &file,
                "azure-key-vault-source-v1",
                "Azure Key Vault profile"
            )
            .is_ok()
        );
        write_private(&file, br#"{"credential_type":"vault-kv-v2-source-v1"}"#);
        assert!(vault_profile_file(&file, "vault-kv-v2-source-v1", "Vault KV profile").is_ok());
        write_private(
            &file,
            br#"{"credential_type":"vault-approle-kv-v2-source-v1"}"#,
        );
        assert!(vault_profile_file(&file, "vault-kv-v2-source-v1", "Vault KV profile").is_ok());
        for marker in [
            "vault-dynamic-source-v2",
            "keycloak-token-exchange-v1",
            "gcp-secret-manager-source-v1",
            "aws-secrets-manager-source-v1",
            "azure-key-vault-source-v1",
            "onepassword-connect-source-v1",
            "macos-keychain-source-v1",
        ] {
            assert!(vault_profile_file(&file, marker, "Other profile").is_err());
        }
        write_private(&file, br#"{"credential_type":"vault-dynamic-source-v2"}"#);
        assert!(
            vault_profile_file(&file, "vault-dynamic-source-v2", "Vault dynamic profile").is_ok()
        );
        write_private(&file, br#"{"credential_type":"vault-kv-v2-source-v1"}"#);

        let symlink = dir.path().join("profile-link.json");
        std::os::unix::fs::symlink(&file, &symlink).unwrap();
        assert_eq!(
            vault_profile_file(&symlink, "vault-kv-v2-source-v1", "Vault KV profile")
                .unwrap_err()
                .code,
            "USAGE"
        );

        write_private(&file, br#"{"credential_type":"other"}"#);
        assert_eq!(
            vault_profile_file(&file, "vault-kv-v2-source-v1", "Vault KV profile")
                .unwrap_err()
                .code,
            "USAGE"
        );

        write_private(&file, &[]);
        assert_eq!(
            vault_profile_file(&file, "vault-kv-v2-source-v1", "Vault KV profile")
                .unwrap_err()
                .code,
            "USAGE"
        );

        write_private(&file, br#"{"credential_type":"vault-kv-v2-source-v1"}"#);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            vault_profile_file(&file, "vault-kv-v2-source-v1", "Vault KV profile")
                .unwrap_err()
                .code,
            "USAGE"
        );

        write_private(
            &file,
            &vec![b'x'; ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize + 1],
        );
        assert_eq!(
            vault_profile_file(&file, "vault-kv-v2-source-v1", "Vault KV profile")
                .unwrap_err()
                .code,
            "INVALID_FRAME"
        );
    }
    #[test]
    fn keychain_reference_file_and_proof_stay_in_the_frame_body() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("keychain.json");
        write_private(&file,br#"{"credential_type":"macos-keychain-source-v1","keychain_path":"/fixture.keychain","service":"exact","account":"exact","reference_expires_at_ms":2000}"#);
        let profile = vault_profile_file(
            &file,
            "macos-keychain-source-v1",
            "macOS Keychain reference",
        )
        .unwrap();
        let body = proof_and_profile(ProofKind::Password, b"synthetic-proof", &profile);
        let (kind, proof, reference) = ipc::parse_proof_and_secret_body(&body).unwrap();
        assert_eq!(kind, ipc::ProofKind::Password);
        assert_eq!(proof, b"synthetic-proof");
        assert_eq!(reference, profile.as_slice());
    }
}
