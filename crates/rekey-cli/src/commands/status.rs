//! `rekey status`: daemon state plus two separate public labels (v3 §3.3).
//! `peer_security` is only the service-identity label; it never doubles as
//! the protection level, which `protection_level` reports on its own.
use std::path::Path;

use rekey_domain::ipc::{self, admin_msg};
use serde::Serialize;

use crate::client::{CliError, PeerSecurity};

#[derive(Serialize)]
struct LocalStatus {
    #[serde(flatten)]
    daemon: ipc::StatusResponse,
    peer_security: PeerSecurity,
    protection_level: Option<&'static str>,
}

pub fn status(state_dir: &Path, passive: bool) -> Result<(), CliError> {
    let message = if passive {
        admin_msg::PASSIVE_STATUS
    } else {
        admin_msg::STATUS
    };
    let mut client = super::admin(state_dir)?;
    let (meta, _) = client.call(message, b"{}", &[])?;
    let daemon: ipc::StatusResponse = serde_json::from_slice(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    super::write_json(&LocalStatus {
        protection_level: protection_level(&daemon.state, daemon.sessions_active),
        daemon,
        peer_security: client.peer_security(),
    })
}

/// Only the confirmed floor: L0 while locked with no session, L1-dev while
/// unlocked (a verified service signature does not raise it before device
/// acceptance), and no level for any other or unknown state.
fn protection_level(state: &str, sessions_active: u32) -> Option<&'static str> {
    match state {
        "locked" if sessions_active == 0 => Some("L0"),
        "unlocked" => Some("L1-dev"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::protection_level;

    #[test]
    fn level_follows_state_and_never_claims_more_than_the_floor() {
        assert_eq!(protection_level("locked", 0), Some("L0"));
        assert_eq!(protection_level("unlocked", 0), Some("L1-dev"));
        assert_eq!(protection_level("unlocked", 3), Some("L1-dev"));
        for (state, sessions) in [
            ("locked", 1),
            ("faulted", 0),
            ("rollback-suspected", 0),
            ("draining", 0),
            ("", 0),
        ] {
            assert_eq!(protection_level(state, sessions), None, "{state}");
        }
    }
}
