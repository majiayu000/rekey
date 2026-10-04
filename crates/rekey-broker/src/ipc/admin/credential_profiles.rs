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
    if kind == CredentialKind::OpaqueToken {
        return Ok(());
    }
    #[cfg(feature = "lab")]
    if kind == CredentialKind::MacosKeychainSource {
        return Ok(());
    }
    authority_until(
        deadline,
        ctx.authority.verify_proof(proof_from(proof_kind, proof)),
    )
    .await?;
    let error = match kind {
        CredentialKind::OpaqueToken => return Ok(()),
        #[cfg(feature = "lab")]
        CredentialKind::MacosKeychainSource => return Ok(()),
        #[cfg(feature = "lab")]
        CredentialKind::KeycloakTokenExchange => {
            crate::executor::keycloak::KeycloakProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Keycloak credential profile")
        }
        CredentialKind::GitHubAppInstallation => GitHubAppCredential::validate_profile(secret)
            .err()
            .map(|_| "invalid GitHub App credential profile"),
        #[cfg(feature = "lab")]
        CredentialKind::GcpSecretManagerSource => {
            crate::executor::gcp_source::GcpSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid GCP Secret Manager credential profile")
        }
        #[cfg(feature = "lab")]
        CredentialKind::AzureKeyVaultSource => {
            crate::executor::azure_source::AzureSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Azure Key Vault credential profile")
        }
        #[cfg(feature = "lab")]
        CredentialKind::OnePasswordConnectSource => {
            crate::executor::onepassword_source::OnePasswordSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid 1Password Connect credential profile")
        }
        #[cfg(feature = "lab")]
        CredentialKind::AwsSecretsManagerSource => {
            crate::executor::aws_source::AwsSourceProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid AWS Secrets Manager credential profile")
        }
        #[cfg(feature = "lab")]
        CredentialKind::VaultKvV2Source => {
            crate::executor::vault_source::VaultKvProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Vault KV credential profile")
        }
        #[cfg(feature = "lab")]
        CredentialKind::VaultDynamicSource => {
            crate::executor::vault_dynamic::VaultDynamicProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Vault dynamic credential profile")
        }
        #[cfg(not(feature = "lab"))]
        _ => Some("credential source requires lab"),
    };
    if let Some(message) = error {
        return Err(BrokerError::Domain(DomainError::InvalidActionDefinition(
            message.to_owned(),
        )));
    }
    Ok(())
}
