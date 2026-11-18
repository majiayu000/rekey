//! Per-connection SSH agent state. The caller label comes from the Unix peer
//! once per connection, exactly as for the CLI (§4.3); it is never an identity.
use std::time::Instant;

use tokio::net::UnixStream;

#[derive(Default)]
pub(super) struct AgentSession {
    pub(super) bound: Option<BoundSession>,
    pub(super) budgets: std::collections::BTreeMap<String, (Instant, u32)>,
    /// Keys approval ownership and time windows, like every local caller.
    pub(super) caller: String,
}
pub(super) struct BoundSession {
    pub(super) host: Vec<u8>,
    pub(super) session: Vec<u8>,
}

impl AgentSession {
    pub(super) async fn for_peer(stream: &UnixStream) -> Self {
        Self {
            caller: crate::ipc::caller::unix_caller(stream).await,
            ..Self::default()
        }
    }
}
