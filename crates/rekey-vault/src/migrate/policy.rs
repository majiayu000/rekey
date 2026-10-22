//! Mechanical carry-over of the signed Connection set. The old signature binds
//! the old vault, so the result is only an unsigned draft request the owner
//! reviews and re-signs; nothing here activates policy.

use std::collections::BTreeSet;

use rekey_domain::connection::{
    Connection, DerivedCredentialConnection, SshKeyConnection, SshSessionBudget,
};
use rekey_domain::ids::CredentialId;
use rekey_domain::ipc::PersonalPolicyDraftMeta;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::AuthorityError;

const DRAFT_VALIDITY_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Conservative defaults for policy7 SSH keys, which predate both fields.
const DEFAULT_SSH_BUDGET: SshSessionBudget = SshSessionBudget {
    max_signatures: 100,
    max_seconds: 600,
};

pub(super) struct MigratedPolicy {
    pub request: PersonalPolicyDraftMeta,
    /// Human review items; never contains credential material.
    pub review: Vec<String>,
}

pub(super) fn carry_over(
    bundle_json: &[u8],
    credentials: &BTreeSet<CredentialId>,
    now_ms: i64,
) -> Result<MigratedPolicy, AuthorityError> {
    let bundle: Value =
        serde_json::from_slice(bundle_json).map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let snapshot = bundle
        .get("snapshot")
        .ok_or(AuthorityError::StorageIntegrityFailed)?;
    let format = snapshot
        .get("format_version")
        .and_then(Value::as_u64)
        .ok_or(AuthorityError::StorageIntegrityFailed)?;
    let mut review = Vec::new();
    let mut out = MigratedPolicy {
        request: PersonalPolicyDraftMeta {
            connections: Vec::new(),
            ssh_keys: Some(Vec::new()),
            derived_credentials: Some(Vec::new()),
            expected_policy_sha256: None,
            expires_at_ms: now_ms.saturating_add(DRAFT_VALIDITY_MS),
        },
        review: Vec::new(),
    };
    match format {
        // policy6 (0.3) had no Connections; Action bindings are not carried.
        6 => {
            for field in ["bindings", "rules", "profiles", "workload_identities"] {
                if array(snapshot, field).is_some_and(|items| !items.is_empty()) {
                    review.push(format!(
                        "policy6 {field} were not carried over; add Connections again"
                    ));
                }
            }
        }
        7 | 8 => {
            out.request.connections =
                entries::<Connection>(snapshot, "connections", credentials, &mut review, |_| {});
            let ssh_keys = entries::<SshKeyConnection>(
                snapshot,
                "ssh_keys",
                credentials,
                &mut review,
                |key| {
                    if format == 7
                        && let Some(object) = key.as_object_mut()
                    {
                        object.insert(
                            "approver".into(),
                            serde_json::json!({"kind": "local-presence"}),
                        );
                        object.insert(
                            "session_budget".into(),
                            serde_json::to_value(&DEFAULT_SSH_BUDGET).unwrap_or(Value::Null),
                        );
                    }
                },
            );
            if format == 7 {
                for key in &ssh_keys {
                    review.push(format!(
                        "SSH key {}: confirm the default local-presence approver and {} signatures / {} s session budget",
                        key.name, DEFAULT_SSH_BUDGET.max_signatures, DEFAULT_SSH_BUDGET.max_seconds
                    ));
                }
            }
            out.request.ssh_keys = Some(ssh_keys);
            out.request.derived_credentials = Some(entries::<DerivedCredentialConnection>(
                snapshot,
                "derived_credentials",
                credentials,
                &mut review,
                |_| {},
            ));
            for field in ["bindings", "rules", "profiles", "workload_identities"] {
                if array(snapshot, field).is_some_and(|items| !items.is_empty()) {
                    review.push(format!("lab policy {field} were not carried over"));
                }
            }
        }
        _ => return Err(AuthorityError::UnsupportedFormatVersion),
    }
    out.review = review;
    Ok(out)
}

fn array<'a>(snapshot: &'a Value, field: &str) -> Option<&'a Vec<Value>> {
    snapshot.get(field).and_then(Value::as_array)
}

trait Named {
    fn name(&self) -> &str;
    fn credential(&self) -> CredentialId;
}
impl Named for Connection {
    fn name(&self) -> &str {
        &self.name
    }
    fn credential(&self) -> CredentialId {
        self.credential_id
    }
}
impl Named for SshKeyConnection {
    fn name(&self) -> &str {
        &self.name
    }
    fn credential(&self) -> CredentialId {
        self.credential_id
    }
}
impl Named for DerivedCredentialConnection {
    fn name(&self) -> &str {
        &self.name
    }
    fn credential(&self) -> CredentialId {
        self.credential_id
    }
}

fn entries<T: DeserializeOwned + Named>(
    snapshot: &Value,
    field: &str,
    credentials: &BTreeSet<CredentialId>,
    review: &mut Vec<String>,
    upgrade: impl Fn(&mut Value),
) -> Vec<T> {
    let mut out = Vec::new();
    for (index, raw) in array(snapshot, field).into_iter().flatten().enumerate() {
        let name = raw
            .get("name")
            .and_then(Value::as_str)
            .map_or_else(|| format!("#{index}"), str::to_owned);
        let mut value = raw.clone();
        upgrade(&mut value);
        match serde_json::from_value::<T>(value) {
            Ok(entry) if credentials.contains(&entry.credential()) => out.push(entry),
            Ok(entry) => review.push(format!(
                "{field} {}: its credential was not migrated; dropped",
                entry.name()
            )),
            Err(_) => review.push(format!(
                "{field} {name}: does not match the current format; dropped, add it again"
            )),
        }
    }
    out
}
