//! Signed Profile binding checks shared by policy8 activation. Profile lookup,
//! session issuance and inventory are lab-only (`issue`, `inventory`); the
//! registry remains the only capability store.
use std::collections::BTreeMap;

use rekey_domain::action::{ActionTarget, FixedHttpAction, TemplateActionSource};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::profile::AgentProfile;
use rekey_policy::{PolicyError, ValidatedSnapshot};
use rekey_vault::AuthorityError;

use crate::error::BrokerError;

#[cfg(feature = "lab")]
mod inventory;
#[cfg(feature = "lab")]
pub(crate) mod issue;

fn invalid() -> BrokerError {
    PolicyError::Invalid.into()
}

fn source(action: &FixedHttpAction) -> Result<&TemplateActionSource, BrokerError> {
    match &action.target {
        ActionTarget::Template { source, .. } => Ok(source),
        ActionTarget::Fixed { .. } => Err(invalid()),
    }
}

/// Pure Profile checks already ran. Only authenticated current Action facts belong here.
pub(super) fn validate_profile_actions(
    snapshot: &ValidatedSnapshot,
    actions: &[FixedHttpAction],
) -> Result<(), BrokerError> {
    validate_profiles(snapshot.profiles(), actions)
}

pub(super) fn validate_profiles(
    profiles: &[AgentProfile],
    actions: &[FixedHttpAction],
) -> Result<(), BrokerError> {
    let mut identities = BTreeMap::new();
    let mut indices = BTreeMap::new();
    for profile in profiles {
        for grant in &profile.grants {
            for capability in &grant.capabilities {
                for reference in &capability.actions {
                    let action = current_action(actions, *reference)?;
                    let source = source(action)?;
                    if source.capability != capability.capability {
                        return Err(invalid());
                    }
                    let binding = if source.signer_id.is_none() && source.template == "github-pat@1"
                    {
                        Some(github_binding(action)?)
                    } else {
                        None
                    };
                    let identity = (
                        binding,
                        action.credential_id,
                        source.template.as_str(),
                        source.digest,
                        source.signer_id,
                    );
                    if identities
                        .insert((profile.principal_id, grant.instance.as_str()), identity)
                        .is_some_and(|old| old != identity)
                    {
                        return Err(invalid());
                    }
                    let key = (
                        profile.principal_id,
                        grant.instance.as_str(),
                        capability.capability.as_str(),
                        source.action_index,
                    );
                    if indices
                        .insert(key, *reference)
                        .is_some_and(|old| old != *reference)
                    {
                        return Err(invalid());
                    }
                }
            }
        }
    }
    Ok(())
}

fn current_action(
    actions: &[FixedHttpAction],
    wanted: ActionVersionRef,
) -> Result<&FixedHttpAction, BrokerError> {
    actions
        .iter()
        .find(|action| {
            action.enabled && action.id == wanted.action_id && action.version == wanted.version
        })
        .ok_or(AuthorityError::PolicyVersionConflict.into())
}

fn github_binding(action: &FixedHttpAction) -> Result<(&str, &str), BrokerError> {
    let ActionTarget::Template { target, .. } = &action.target else {
        return Err(invalid());
    };
    let mut segments = target.path_pattern().split('/');
    if segments.next() != Some("") || segments.next() != Some("repos") {
        return Err(invalid());
    }
    let owner = segments.next().ok_or_else(invalid)?;
    let repo = segments.next().ok_or_else(invalid)?;
    Ok((owner, repo))
}
