use rekey_domain::DomainError;
use rekey_domain::credential::CredentialKind;
use rekey_domain::ipc::ProofKind;

use super::{authority_until, proof_from};
use crate::error::BrokerError;
use crate::github_app::GitHubAppCredential;
use crate::runtime::BrokerCtx;

pub(super) async fn validate_add(
    ctx: &BrokerCtx,
    deadline: tokio::time::Instant,
    kind: CredentialKind,
    proof_kind: ProofKind,
    proof: &[u8],
    secret: &[u8],
) -> Result<(), BrokerError> {
    if matches!(
        kind,
        CredentialKind::OpaqueToken | CredentialKind::MacosKeychainSource
    ) {
        return Ok(());
    }
    authority_until(
        deadline,
        ctx.authority.verify_proof(proof_from(proof_kind, proof)),
    )
    .await?;
    let error = match kind {
        CredentialKind::OpaqueToken | CredentialKind::MacosKeychainSource => return Ok(()),
        CredentialKind::KeycloakTokenExchange => {
            crate::executor::keycloak::KeycloakProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Keycloak credential profile")
        }
        CredentialKind::GitHubAppInstallation => GitHubAppCredential::validate_profile(secret)
            .err()
            .map(|_| "invalid GitHub App credential profile"),
        CredentialKind::GcpSecretManagerSource => {
            crate::executor::gcp_source::GcpSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid GCP Secret Manager credential profile")
        }
        CredentialKind::AzureKeyVaultSource => {
            crate::executor::azure_source::AzureSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Azure Key Vault credential profile")
        }
        CredentialKind::OnePasswordConnectSource => {
            crate::executor::onepassword_source::OnePasswordSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid 1Password Connect credential profile")
        }
        CredentialKind::AwsSecretsManagerSource => {
            crate::executor::aws_source::AwsSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid AWS Secrets Manager credential profile")
        }
        CredentialKind::VaultKvV2Source => {
            crate::executor::vault_source::VaultKvProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Vault KV credential profile")
        }
        CredentialKind::VaultDynamicSource => {
            crate::executor::vault_dynamic::VaultDynamicProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Vault dynamic credential profile")
        }
    };
    if let Some(message) = error {
        return Err(BrokerError::Domain(DomainError::InvalidActionDefinition(
            message.to_owned(),
        )));
    }
    Ok(())
}
