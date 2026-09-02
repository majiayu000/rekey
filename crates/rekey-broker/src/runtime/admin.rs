use std::sync::Arc;

use rekey_domain::ipc::PolicyStatusResponse;
use rekey_policy::{ValidatedPolicyTrust, parse_and_verify_policy_bundle_for_load};
use rekey_vault::AuthorityError;
use rekey_vault::command::UnlockProof;

use super::BrokerCtx;
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;

impl BrokerCtx {
    pub async fn policy_status(&self) -> Result<PolicyStatusResponse, BrokerError> {
        let authority = self.authority.admin_status().await?;
        let guard = self.policy.read().await;
        match guard.as_ref() {
            Some(active) => Ok(PolicyStatusResponse {
                trust_installed: authority.policy_trust_installed,
                bundle_persisted: authority.policy_bundle_persisted,
                status: if active.is_expired(crate::now_ts()?) {
                    "expired".to_owned()
                } else {
                    "active".to_owned()
                },
                signer_id: active.signer_id(),
                version: Some(active.snapshot().version().get()),
                expires_at_ms: Some(active.snapshot().expires_at_ms()),
                policy_sha256: Some(data_encoding::HEXLOWER.encode(&active.snapshot().digest())),
                bundle_sha256: active
                    .bundle_digest()
                    .map(|digest| data_encoding::HEXLOWER.encode(&digest)),
            }),
            None => Ok(PolicyStatusResponse {
                trust_installed: authority.policy_trust_installed,
                bundle_persisted: authority.policy_bundle_persisted,
                status: "unavailable".to_owned(),
                signer_id: None,
                version: None,
                expires_at_ms: None,
                policy_sha256: None,
                bundle_sha256: None,
            }),
        }
    }

    pub(crate) async fn reload_policy_after_unlock(&self) -> Result<(), BrokerError> {
        let material = self.authority.policy_material().await?;
        let trust = material
            .trust
            .map(|record| ValidatedPolicyTrust::from_parts(record.signer_id, record.public_key));
        let active = match (trust.as_ref(), material.bundle) {
            (_, None) => None,
            (Some(trust), Some(record)) => {
                let verified =
                    match parse_and_verify_policy_bundle_for_load(&record.bundle_json, trust) {
                        Ok(verified)
                            if verified.signer_id() == record.signer_id
                                && verified.snapshot().version().get() == record.version
                                && verified.snapshot().expires_at_ms() == record.expires_at_ms
                                && verified.policy_digest() == record.policy_digest
                                && verified.bundle_digest() == record.bundle_digest =>
                        {
                            verified
                        }
                        _ => {
                            drop(self.authority.fault_integrity().await);
                            return Err(BrokerError::Authority(
                                AuthorityError::StorageIntegrityFailed,
                            ));
                        }
                    };
                Some(Arc::new(ActivePolicy::load_bundle(
                    verified,
                    crate::now_ts()?,
                )))
            }
            (None, Some(_)) => {
                drop(self.authority.fault_integrity().await);
                return Err(BrokerError::Authority(
                    AuthorityError::StorageIntegrityFailed,
                ));
            }
        };
        *self.policy_trust.write().await = trust;
        *self.policy.write().await = active;
        Ok(())
    }

    pub async fn install_policy_trust_until(
        &self,
        trust: ValidatedPolicyTrust,
        proof: UnlockProof,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        authority_until(
            deadline,
            self.authority.policy_trust_install_before(
                rekey_vault::command::PolicyTrustInput {
                    signer_id: trust.signer_id(),
                    public_key: *trust.public_key(),
                },
                proof,
                Some(deadline.into_std()),
            ),
        )
        .await?;
        *self.policy_trust.write().await = Some(trust);
        Ok(())
    }

    pub async fn activate_policy_until(
        &self,
        bundle_bytes: &[u8],
        proof: UnlockProof,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        let trust = self
            .policy_trust
            .read()
            .await
            .clone()
            .ok_or(BrokerError::Authority(AuthorityError::PolicyUnavailable))?;
        let verified =
            rekey_policy::parse_and_verify_policy_bundle(bundle_bytes, &trust, crate::now_ts()?)?;
        let input = rekey_vault::command::PolicyBundleInput {
            signer_id: verified.signer_id(),
            version: verified.snapshot().version().get(),
            expires_at_ms: verified.snapshot().expires_at_ms(),
            policy_digest: verified.policy_digest(),
            bundle_digest: verified.bundle_digest(),
            bundle_json: verified.canonical_bytes().to_vec(),
        };
        let active = ActivePolicy::activate_bundle(verified, crate::now_ts()?)?;
        let mut guard = self.policy.write().await;
        let preserve_expiry_latch = guard.as_ref().is_some_and(|current| {
            current.signer_id() == Some(input.signer_id)
                && current.snapshot().version().get() == input.version
                && current.bundle_digest() == Some(input.bundle_digest)
        });
        authority_until(
            deadline,
            self.authority
                .policy_bundle_activate_before(input, proof, Some(deadline.into_std())),
        )
        .await?;
        if !preserve_expiry_latch {
            *guard = Some(Arc::new(active));
        }
        Ok(())
    }
}

async fn authority_until<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = Result<T, AuthorityError>>,
) -> Result<T, BrokerError> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?
        .map_err(BrokerError::Authority)
}
