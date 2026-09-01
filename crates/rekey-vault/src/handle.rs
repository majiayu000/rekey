//! Cloneable async handle to the AuthorityWorker's bounded command queue.

use std::path::PathBuf;
use std::time::Duration;

use rekey_domain::action::FixedHttpAction;
use rekey_domain::credential::{CredentialKind, CredentialLabel, CredentialMetadata};
use rekey_domain::ids::{ActionId, CredentialId};
use tokio::sync::{mpsc, oneshot};

use crate::command::{
    ActionDefinition, AuditDraft, AuthorityCommand, BackupInfo, PinnedAction, StatusInfo,
    UnlockProof,
};
use crate::error::AuthorityError;
use crate::secret::{PreparedCredential, SecretInput};

pub const DEFAULT_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_IDLE_LOCK: Duration = Duration::from_secs(15 * 60);
pub const IDLE_LOCK_MIN: Duration = Duration::from_secs(60);
pub const IDLE_LOCK_MAX: Duration = Duration::from_secs(120 * 60);

#[derive(Clone)]
pub struct AuthorityConfig {
    pub state_dir: PathBuf,
    pub idle_lock: Duration,
    pub queue_capacity: usize,
    /// Base delay of the unlock backoff; production default is one second,
    /// tests may shorten it.
    pub unlock_backoff_base: Duration,
}

impl AuthorityConfig {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            idle_lock: DEFAULT_IDLE_LOCK,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            unlock_backoff_base: Duration::from_secs(1),
        }
    }

    /// The 1–120 minute idle-lock range is a product rule enforced where the
    /// duration is parsed (rekeyd serve); the worker itself only requires a
    /// nonzero value so tests can exercise idle locking quickly.
    pub(crate) fn validate(&self) -> Result<(), AuthorityError> {
        if self.idle_lock.is_zero() || self.idle_lock > IDLE_LOCK_MAX {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidActionDefinition(
                    "idle lock must be nonzero and at most 120 minutes".to_owned(),
                ),
            ));
        }
        if self.queue_capacity == 0 {
            return Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidActionDefinition(
                    "queue capacity must be nonzero".to_owned(),
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct AuthorityHandle {
    pub(crate) tx: mpsc::Sender<AuthorityCommand>,
}

macro_rules! call {
    ($self:ident, $variant:expr) => {{
        let (tx, rx) = oneshot::channel();
        let cmd = $variant(tx);
        match $self.tx.try_send(cmd) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Err(AuthorityError::AuthorityBusy),
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(AuthorityError::Faulted),
        }
        rx.await.map_err(|_| AuthorityError::Faulted)?
    }};
}

impl AuthorityHandle {
    pub async fn status(&self) -> Result<StatusInfo, AuthorityError> {
        call!(self, |reply| AuthorityCommand::Status {
            refresh_activity: false,
            reply
        })
    }

    pub async fn admin_status(&self) -> Result<StatusInfo, AuthorityError> {
        call!(self, |reply| AuthorityCommand::Status {
            refresh_activity: true,
            reply
        })
    }

    pub async fn unlock(&self, proof: UnlockProof) -> Result<(), AuthorityError> {
        call!(self, |reply| AuthorityCommand::Unlock { proof, reply })
    }

    pub async fn lock(&self, reason: &'static str) -> Result<(), AuthorityError> {
        call!(self, |reply| AuthorityCommand::Lock { reason, reply })
    }

    pub async fn shutdown(&self, proof: Option<UnlockProof>) -> Result<(), AuthorityError> {
        call!(self, |reply| AuthorityCommand::Shutdown { proof, reply })
    }

    pub async fn verify_proof(&self, proof: UnlockProof) -> Result<(), AuthorityError> {
        call!(self, |reply| AuthorityCommand::VerifyProof { proof, reply })
    }

    pub async fn credential_add(
        &self,
        label: CredentialLabel,
        kind: CredentialKind,
        secret: SecretInput,
        proof: UnlockProof,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.credential_add_before(label, kind, secret, proof, None)
            .await
    }

    pub async fn credential_add_before(
        &self,
        label: CredentialLabel,
        kind: CredentialKind,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        call!(self, |reply| AuthorityCommand::CredentialAdd {
            label,
            kind,
            secret,
            proof,
            not_after,
            reply
        })
    }

    pub async fn credential_list(&self) -> Result<Vec<CredentialMetadata>, AuthorityError> {
        call!(self, AuthorityCommand::CredentialList)
    }

    pub async fn credential_rotate(
        &self,
        credential_id: CredentialId,
        secret: SecretInput,
        proof: UnlockProof,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.credential_rotate_before(credential_id, secret, proof, None)
            .await
    }

    pub async fn credential_rotate_before(
        &self,
        credential_id: CredentialId,
        secret: SecretInput,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        call!(self, |reply| AuthorityCommand::CredentialRotate {
            credential_id,
            secret,
            proof,
            not_after,
            reply
        })
    }

    pub async fn credential_revoke(
        &self,
        credential_id: CredentialId,
        proof: UnlockProof,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.credential_revoke_before(credential_id, proof, None)
            .await
    }

    pub async fn credential_revoke_before(
        &self,
        credential_id: CredentialId,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        call!(self, |reply| AuthorityCommand::CredentialRevoke {
            credential_id,
            proof,
            not_after,
            reply
        })
    }

    pub async fn action_upsert(
        &self,
        existing: Option<ActionId>,
        definition: ActionDefinition,
        proof: UnlockProof,
    ) -> Result<FixedHttpAction, AuthorityError> {
        self.action_upsert_before(existing, definition, proof, None)
            .await
    }

    pub async fn action_upsert_before(
        &self,
        existing: Option<ActionId>,
        definition: ActionDefinition,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<FixedHttpAction, AuthorityError> {
        call!(self, |reply| AuthorityCommand::ActionUpsert {
            existing,
            definition: Box::new(definition),
            proof,
            not_after,
            reply
        })
    }

    pub async fn action_disable(
        &self,
        action_id: ActionId,
        proof: UnlockProof,
    ) -> Result<(), AuthorityError> {
        self.action_disable_before(action_id, proof, None).await
    }

    pub async fn action_disable_before(
        &self,
        action_id: ActionId,
        proof: UnlockProof,
        not_after: Option<std::time::Instant>,
    ) -> Result<(), AuthorityError> {
        call!(self, |reply| AuthorityCommand::ActionDisable {
            action_id,
            proof,
            not_after,
            reply
        })
    }

    pub async fn action_list(&self) -> Result<Vec<FixedHttpAction>, AuthorityError> {
        call!(self, AuthorityCommand::ActionList)
    }

    pub async fn action_get(
        &self,
        action_id: ActionId,
        version: u64,
    ) -> Result<PinnedAction, AuthorityError> {
        call!(self, |reply| AuthorityCommand::ActionGet {
            action_id,
            version,
            reply
        })
    }

    pub async fn action_ids_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<ActionId>, AuthorityError> {
        call!(self, |reply| AuthorityCommand::ActionIdsForCredential {
            credential_id,
            reply
        })
    }

    pub async fn prepare_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<PreparedCredential, AuthorityError> {
        call!(self, |reply| AuthorityCommand::PrepareCredential {
            credential_id,
            reply
        })
    }

    pub async fn append_audit(&self, draft: AuditDraft) -> Result<(), AuthorityError> {
        call!(self, |reply| AuthorityCommand::AppendAudit {
            draft,
            not_after: None,
            reply
        })
    }

    /// Wait for queue capacity, then commit. Used for terminal audits after
    /// `execution.started` so a full command queue cannot drop the pair.
    pub async fn commit_audit(&self, draft: AuditDraft) -> Result<(), AuthorityError> {
        self.commit_audit_before(draft, None).await
    }

    pub async fn commit_audit_before(
        &self,
        draft: AuditDraft,
        not_after: Option<std::time::Instant>,
    ) -> Result<(), AuthorityError> {
        let (tx, rx) = oneshot::channel();
        let command = AuthorityCommand::AppendAudit {
            draft,
            not_after,
            reply: tx,
        };
        if not_after.is_some() {
            self.tx.try_send(command).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AuthorityError::AuthorityBusy,
                mpsc::error::TrySendError::Closed(_) => AuthorityError::Faulted,
            })?;
        } else {
            self.tx
                .send(command)
                .await
                .map_err(|_| AuthorityError::Faulted)?;
        }
        rx.await.map_err(|_| AuthorityError::Faulted)?
    }

    pub async fn backup(
        &self,
        output: PathBuf,
        proof: UnlockProof,
    ) -> Result<BackupInfo, AuthorityError> {
        call!(self, |reply| AuthorityCommand::Backup {
            output,
            proof,
            reply
        })
    }

    pub fn check_idle(&self) {
        let _ = self.tx.try_send(AuthorityCommand::CheckIdle);
    }
}
