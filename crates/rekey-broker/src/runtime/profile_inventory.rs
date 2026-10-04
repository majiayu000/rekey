//! Read-only, authenticated public projection of the live Profile session.
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::ipc::{
    FrameError, ProfileActionDefinition, ProfileInventoryResponse, RESPONSE_BODY_MAX_BYTES,
};
use rekey_domain::profile::AgentProfile;
use rekey_policy::PolicyError;
use rekey_vault::AuthorityError;
use tokio::time::Instant;

use super::BrokerCtx;
use crate::error::BrokerError;

pub(super) struct ProfileMaterial {
    pub profile: AgentProfile,
    pub policy_sha256: [u8; 32],
    pub expires_at_ms: i64,
    pub actions: Vec<FixedHttpAction>,
}

impl BrokerCtx {
    pub(super) async fn profile_material_until(
        &self,
        token: &str,
        deadline: Instant,
    ) -> Result<ProfileMaterial, BrokerError> {
        let _coordinator = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        let (session_id, scope, expires_at_ms) =
            self.sessions.profile_inventory(token, crate::now_ts()?)?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .ok_or(AuthorityError::PolicyUnavailable)?;
        if active.signer_id().is_none() || active.snapshot().digest() != *scope.policy_sha256() {
            return Err(BrokerError::Denied("profile-policy-changed"));
        }
        if active.is_expired(crate::now_ts()?) {
            return Err(PolicyError::Expired.into());
        }
        let actions = tokio::time::timeout_at(deadline, self.authority.action_list())
            .await
            .map_err(|_| AuthorityError::AuthorityBusy)??;
        let selected: Vec<_> = actions
            .into_iter()
            .filter(|action| {
                scope.profile().action_refs().any(|reference| {
                    action.id == reference.action_id && action.version == reference.version
                })
            })
            .collect();
        super::profile::validate_profiles(std::slice::from_ref(scope.profile()), &selected)?;
        self.lifecycle.reject_if_not_running()?;
        if Instant::now() >= deadline {
            return Err(AuthorityError::AuthorityBusy.into());
        }
        if active.is_expired(crate::now_ts()?) {
            return Err(PolicyError::Expired.into());
        }
        self.sessions
            .ensure_inventory_live(session_id, crate::now_ts()?)?;
        Ok(ProfileMaterial {
            profile: scope.profile().clone(),
            policy_sha256: *scope.policy_sha256(),
            expires_at_ms,
            actions: selected,
        })
    }

    pub(crate) async fn profile_inventory_until(
        &self,
        token: &str,
        deadline: Instant,
    ) -> Result<Vec<u8>, BrokerError> {
        let material = self.profile_material_until(token, deadline).await?;
        let mut actions = Vec::with_capacity(material.actions.len());
        for action in material.actions {
            let ActionTarget::Template {
                target,
                body_schema,
                source,
                fixed_headers,
                ..
            } = action.target
            else {
                return Err(PolicyError::Invalid.into());
            };
            // Mint rejects legacy/native projections; never silently advertise one.
            if action.native_plugin.is_some() || action.text_stream.is_some() {
                return Err(PolicyError::Invalid.into());
            }
            actions.push(ProfileActionDefinition {
                action_id: action.id,
                version: action.version,
                action_index: u32::try_from(source.action_index)
                    .map_err(|_| PolicyError::Invalid)?,
                name: action.name,
                origin: action.origin,
                method: action.method,
                target,
                body_schema,
                fixed_content_type: fixed_headers
                    .keys()
                    .any(|name| name.as_str() == "content-type"),
            });
        }
        actions.sort_by_key(|action| (action.action_id, action.version));
        let response = ProfileInventoryResponse {
            profile: material.profile,
            policy_sha256: data_encoding::HEXLOWER.encode(&material.policy_sha256),
            expires_at_ms: material.expires_at_ms,
            actions,
        };
        let body = serde_json::to_vec(&response).map_err(|_| FrameError::InvalidField)?;
        if body.len() > RESPONSE_BODY_MAX_BYTES as usize {
            return Err(FrameError::SectionTooLarge.into());
        }
        Ok(body)
    }
}
