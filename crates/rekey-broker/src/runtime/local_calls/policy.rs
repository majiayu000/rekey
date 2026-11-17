//! Local approvals stay bound to the signed policy they were requested under
//! (§5.4): a decision under another version or digest is refused.
use crate::error::BrokerError;
use crate::runtime::BrokerCtx;

impl BrokerCtx {
    pub(crate) async fn check_local_approval_policy(
        &self,
        challenge: &rekey_domain::ipc::ApprovalChallenge,
    ) -> Result<(), BrokerError> {
        let now = crate::now_ts()?;
        let policy = self.policy.read().await;
        let current = policy
            .as_ref()
            .filter(|p| !p.is_expired(now))
            .ok_or(BrokerError::Denied("policy-changed"))?;
        if current.snapshot().version().get() != challenge.policy_version
            || data_encoding::HEXLOWER.encode(&current.snapshot().digest())
                != challenge.policy_sha256
        {
            return Err(BrokerError::Denied("policy-changed"));
        }
        Ok(())
    }
}
