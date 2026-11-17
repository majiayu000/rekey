//! Public facts the Authority records on `ssh.sign`: the signing use and the
//! digest of the host key verified by `session-bind`.
use rekey_vault::command::{AuditDraft, SshSignPurpose, SshSignStart};
use sha2::{Digest, Sha256};

use super::{AgentSession, Purpose};

pub(super) fn start(draft: AuditDraft, session: &AgentSession, purpose: &Purpose) -> SshSignStart {
    SshSignStart {
        draft,
        purpose: match purpose {
            Purpose::Authentication { .. } => SshSignPurpose::Auth,
            Purpose::Git => SshSignPurpose::Git,
            Purpose::Other => SshSignPurpose::Unknown,
        },
        // An unverified hostbound name is never recorded as the target host.
        host_key_sha256: session
            .bound
            .as_ref()
            .map(|bound| Sha256::digest(&bound.host).into()),
    }
}
