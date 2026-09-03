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
    authority_until(
        deadline,
        ctx.authority.verify_proof(proof_from(proof_kind, proof)),
    )
    .await?;
    let error = match kind {
        CredentialKind::OpaqueToken => return Ok(()),
        CredentialKind::GitHubAppInstallation => GitHubAppCredential::validate_profile(secret)
            .err()
            .map(|_| "invalid GitHub App credential profile"),
        CredentialKind::VaultKvV2Source => {
            crate::executor::vault_source::VaultKvProfile::validate_profile(secret)
                .err()
                .map(|_| "invalid Vault KV credential profile")
        }
    };
    if let Some(message) = error {
        return Err(BrokerError::Domain(DomainError::InvalidActionDefinition(
            message.to_owned(),
        )));
    }
    Ok(())
}
