use std::sync::Arc;

use rekey_domain::ipc::PolicyStatusResponse;
use rekey_policy::ValidatedSnapshot;
use rekey_vault::AuthorityError;
use rekey_vault::command::{AuditDraft, UnlockProof};

use super::BrokerCtx;
use crate::error::BrokerError;

impl BrokerCtx {
    pub async fn policy_status(&self) -> PolicyStatusResponse {
        let guard = self.policy.read().await;
        match guard.as_ref() {
            Some(snapshot) => PolicyStatusResponse {
                active: true,
                version: Some(snapshot.version().get()),
                expires_at_ms: Some(snapshot.expires_at_ms()),
                sha256_hex: Some(data_encoding::HEXLOWER.encode(&snapshot.digest())),
            },
            None => PolicyStatusResponse {
                active: false,
                version: None,
                expires_at_ms: None,
                sha256_hex: None,
            },
        }
    }

    pub async fn activate_policy_until(
        &self,
        snapshot: ValidatedSnapshot,
        proof: UnlockProof,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        authority_until(deadline, self.authority.verify_proof(proof)).await?;
        self.lifecycle.reject_if_not_running()?;
        let mut guard = self.policy.write().await;
        if guard
            .as_ref()
            .is_some_and(|current| snapshot.version() <= current.version())
        {
            return Err(BrokerError::Denied("policy-version-not-increasing"));
        }
        authority_until(
            deadline,
            self.authority.append_audit(AuditDraft {
                request_id: None,
                session_id: None,
                action_id: None,
                action_version: None,
                credential_id: None,
                credential_version: None,
                authorization: None,
                event_type: rekey_vault::model::event_type::POLICY_ACTIVATED,
                outcome: rekey_vault::model::outcome::SUCCESS,
                reason_code: "policy-activated".to_owned(),
                upstream_status: None,
                latency_ms: None,
            }),
        )
        .await?;
        reject_if_elapsed(deadline)?;
        *guard = Some(Arc::new(snapshot));
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

fn reject_if_elapsed(deadline: tokio::time::Instant) -> Result<(), BrokerError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
    }
    Ok(())
}
