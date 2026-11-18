//! Basic-mode remembered unlock (`rekey unlock --remember <duration>`): an
//! unlock-only DESKTOP_REMEMBER ticket kept in a 0600 state-directory file.
//! The lifetime is checked before any password is read or sent.
use std::io::Write;
use std::path::Path;

use rekey_domain::ipc::{self, admin_msg};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{REMEMBERED_UNLOCK_FILE, admin, parse_ttl_ms, proof_body, proof_kind};
use crate::client::CliError;

/// DESKTOP_REMEMBER accepts 1,000..=2,592,000,000 ms; the Worker checks it again.
const MAX_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Parses `--remember` and refuses anything outside 1s..=30d as a usage error.
pub(super) fn lifetime_ms(input: &str) -> Result<i64, CliError> {
    let lifetime_ms = parse_ttl_ms(input)?;
    if (1_000..=MAX_LIFETIME_MS).contains(&lifetime_ms) {
        Ok(lifetime_ms)
    } else {
        Err(CliError::local(
            "USAGE",
            format!("--remember must be between 1s and 30d: {input}"),
        ))
    }
}

pub(super) fn save(
    state_dir: &Path,
    recovery: bool,
    secret: &[u8],
    lifetime_ms: i64,
) -> Result<(), CliError> {
    let kind = proof_kind(recovery);
    let body = proof_body(kind, secret);
    // The file is same-user readable: request an unlock-only ticket that the
    // daemon never accepts as a presence proof (approvals, reveal, step-up).
    let metadata = serde_json::to_vec(&ipc::DesktopRememberMeta {
        lifetime_ms,
        unlock_only: true,
    })
    .map_err(|_| CliError::local("INVALID_FRAME", "invalid remember request"))?;
    let (meta, key) = admin(state_dir)?.call(admin_msg::DESKTOP_REMEMBER, &metadata, &body)?;
    let key = Zeroizing::new(key);
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Expiry {
        expires_at_ms: i64,
    }
    let expires_at_ms = serde_json::from_slice::<Expiry>(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid remember expiry"))?
        .expires_at_ms;
    // Write beside the vault, owner-only, then rename so rekeyd never reads a partial key.
    let path = state_dir.join(REMEMBERED_UNLOCK_FILE);
    let staging = state_dir.join(format!(".{REMEMBERED_UNLOCK_FILE}.tmp"));
    let _ = std::fs::remove_file(&staging);
    let write = || -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?;
        file.write_all(&key)?;
        file.sync_all()?;
        std::fs::rename(&staging, &path)
    };
    write().map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        CliError::local("IO", format!("cannot save remembered unlock: {error}"))
    })?;
    let days = lifetime_ms / (24 * 60 * 60 * 1000);
    eprintln!(
        "Remembered for {days} day(s) (until unix ms {expires_at_ms}): rekeyd unlocks itself after restarts. Basic mode: {} is a 0600 file readable by this user, not Secure Enclave. Forget it with `rekey lock --forget-remembered`.",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::lifetime_ms;

    #[test]
    fn remember_lifetime_accepts_only_one_second_through_thirty_days() {
        assert_eq!(lifetime_ms("1s").unwrap(), 1_000);
        assert_eq!(lifetime_ms("30d").unwrap(), 2_592_000_000);
        assert_eq!(lifetime_ms("720h").unwrap(), 2_592_000_000);
        for input in ["0s", "-1s", "31d", "2592001s", "721h", "7w", ""] {
            assert_eq!(lifetime_ms(input).unwrap_err().code, "USAGE", "{input}");
        }
    }
}
