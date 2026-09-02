use std::future::Future;
use std::time::Instant;

use rekey_vault::AuthorityError;

use crate::error::BrokerError;

pub(super) async fn await_authority<T>(
    deadline: Instant,
    operation: impl Future<Output = Result<T, AuthorityError>>,
) -> Result<T, BrokerError> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation)
        .await
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))?
        .map_err(BrokerError::Authority)
}
