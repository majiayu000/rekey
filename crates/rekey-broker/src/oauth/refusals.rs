//! Provider refusals remembered per grant version (agent-call §7.4).
use std::collections::BTreeMap;
use std::sync::Mutex;

use rekey_domain::ids::CredentialId;

/// Grant versions the provider refused (`NEEDS_REAUTH`). Holds no secret, so
/// lock and policy changes keep it; a login callback or rotation writes a new
/// version and a revoke removes the grant. Lost on restart, where the next
/// call asks the provider once more.
#[derive(Default)]
pub(super) struct Refusals(Mutex<BTreeMap<CredentialId, u64>>);

impl Refusals {
    pub(super) fn remember(&self, id: CredentialId, version: u64) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, version);
    }
    pub(super) fn refused(&self, id: CredentialId, version: u64) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(&id) == Some(&version)
    }
}
