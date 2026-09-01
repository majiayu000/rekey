//! First-party Credential Authority: encrypted storage, key hierarchy,
//! offline bootstrap, and the AuthorityWorker state machine.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod authority;
pub mod bootstrap;
pub mod command;
pub mod crypto;
pub mod durable;
pub mod error;
pub mod model;
pub mod secret;
pub mod store;

pub use error::AuthorityError;
pub mod convert;
pub mod handle;
pub mod paths;

fn millis_at(time: SystemTime) -> Result<i64, AuthorityError> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorityError::ClockUnavailable)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| AuthorityError::ClockUnavailable)
}

pub(crate) fn now_ms() -> Result<i64, AuthorityError> {
    millis_at(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pre_epoch_clock_fails_closed() {
        let Some(before_epoch) = UNIX_EPOCH.checked_sub(Duration::from_millis(1)) else {
            panic!("platform cannot represent pre-epoch time");
        };
        assert!(matches!(
            millis_at(before_epoch),
            Err(AuthorityError::ClockUnavailable)
        ));
    }
}
