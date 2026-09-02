//! Broker runtime: Admin/Agent IPC surfaces, capability sessions, and the
//! fixed HTTP action executor.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRngCore;
use rekey_domain::Timestamp;

use crate::error::BrokerError;

mod active_policy;
pub mod audit;
pub mod error;
pub(crate) mod execution_supervisor;
pub mod executor;
mod github_app;
pub mod ipc;
pub mod lifecycle;
pub mod runtime;
pub mod session;
pub mod testing;
pub mod upstream;

fn timestamp_at(time: SystemTime) -> Result<Timestamp, BrokerError> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| rekey_vault::AuthorityError::ClockUnavailable)?;
    let millis = i64::try_from(elapsed.as_millis())
        .map_err(|_| rekey_vault::AuthorityError::ClockUnavailable)?;
    Ok(Timestamp::from_unix_ms(millis))
}

pub(crate) fn now_ts() -> Result<Timestamp, BrokerError> {
    timestamp_at(SystemTime::now())
}

pub(crate) fn random_id<T>(
    from_random_bytes: impl FnOnce([u8; 16]) -> T,
) -> Result<T, BrokerError> {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| rekey_vault::AuthorityError::EntropyUnavailable)?;
    Ok(from_random_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pre_epoch_clock_fails_closed() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_millis(1))
            .expect("represent pre-epoch time");
        assert!(matches!(
            timestamp_at(before_epoch),
            Err(BrokerError::Authority(
                rekey_vault::AuthorityError::ClockUnavailable
            ))
        ));
    }
}
