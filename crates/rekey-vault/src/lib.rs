//! First-party Credential Authority: encrypted storage, key hierarchy,
//! offline bootstrap, and the AuthorityWorker state machine.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod authority;
pub mod bootstrap;
pub mod command;
pub mod crypto;
pub mod durable;
pub mod error;
pub mod generation_anchor;
pub mod hygiene;
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

#[cfg(all(test, not(debug_assertions)))]
pub(crate) trait TestRandomId {
    fn new_random() -> Self;
}

#[cfg(all(test, not(debug_assertions)))]
macro_rules! impl_test_random_id {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl TestRandomId for $ty {
                fn new_random() -> Self {
                    use std::sync::atomic::{AtomicU64, Ordering};
                    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
                    let value = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                    let mut bytes = [0u8; 16];
                    bytes[8..].copy_from_slice(&value.to_be_bytes());
                    Self::from_random_bytes(bytes)
                }
            }
        )+
    };
}

#[cfg(all(test, not(debug_assertions)))]
impl_test_random_id!(
    rekey_domain::ids::VaultId,
    rekey_domain::ids::CredentialId,
    rekey_domain::ids::ActionId,
    rekey_domain::ids::SessionId,
    rekey_domain::ids::RequestId,
    rekey_domain::ids::PrincipalId,
    rekey_domain::ids::PolicyRuleId,
    rekey_domain::ids::LeaseRegistrationId,
);

mod private_material;
