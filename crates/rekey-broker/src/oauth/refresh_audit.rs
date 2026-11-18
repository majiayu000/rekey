//! The public audit row of a failed OAuth refresh (agent-call §7.4).
use rekey_domain::connection::Connection;
use rekey_vault::handle::AuthorityHandle;

use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;

/// Only a provider refusal (`NEEDS_REAUTH`: revoked or invalid grant) asks the
/// person to authorize again; the App shows 需重新授权 for this reason alone.
/// Network, 5xx, timeout and other refresh failures keep the grant.
const NEEDS_REAUTH: &str = "oauth-needs-reauth";
const FAILED: &str = "oauth-refresh-failed";

fn reason(error: &BrokerError) -> &'static str {
    if error.code() == "NEEDS_REAUTH" {
        NEEDS_REAUTH
    } else {
        FAILED
    }
}

/// Commits `oauth.refresh_failed` before the caller sees `error`; an audit
/// failure replaces it, so no refresh failure goes unrecorded.
pub(super) async fn record(
    authority: &AuthorityHandle,
    connection: &Connection,
    active: &ActivePolicy,
    error: BrokerError,
) -> Result<BrokerError, BrokerError> {
    let mut audit = crate::runtime::oauth_audit("oauth.refresh_failed", connection, active)?;
    audit.outcome = rekey_vault::model::outcome::DENIED;
    audit.reason_code = reason(&error).into();
    authority.append_audit(audit).await?;
    Ok(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_provider_refusal_is_recorded_as_needing_reauthorization() {
        assert_eq!(reason(&super::super::needs_reauth()), NEEDS_REAUTH);
        for transient in [
            BrokerError::Upstream("oauth-provider-unavailable"),
            BrokerError::Upstream("oauth-refresh-timeout"),
            BrokerError::UpstreamUnconfirmed("oauth-exchange-transport"),
            super::super::invalid(),
        ] {
            assert_eq!(reason(&transient), FAILED, "{}", transient.code());
        }
    }
}
