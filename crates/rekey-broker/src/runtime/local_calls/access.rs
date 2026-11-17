//! Agent access requests (§7.2): in memory for ten minutes, never an
//! authorization. Completing one only confirms that signed rules allow it.
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use rekey_domain::audit::RequestAuditContext;
use rekey_domain::connection::{
    BUILTIN_PRESETS, Connection, ConnectionRequestAuditContext, MethodClass, PresetOperation,
    ReadSemantics,
};
use rekey_domain::ids::RequestId;
use rekey_domain::ipc;
use sha2::{Digest, Sha256};

use super::LocalCalls;
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;
use crate::runtime::BrokerCtx;

const LIFETIME: Duration = Duration::from_secs(600);
const REQUESTS_PER_MINUTE: u32 = 3;
/// Audit target of a block change that names no access request.
const BLOCK_SCOPE: &str = "access-requests";

#[derive(Clone, serde::Serialize)]
pub(crate) struct AccessRequest {
    pub(crate) request_id: RequestId,
    pub(crate) caller: String,
    pub(crate) provider: Option<String>,
    pub(crate) connection: Option<String>,
    pub(crate) operation: Option<String>,
    pub(crate) reason: String,
    pub(crate) created_at_ms: i64,
    pub(crate) expires_at_ms: i64,
    pub(crate) status: ipc::AccessRequestStatus,
    /// Presets that satisfy a provider request; empty for a connection request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) presets: Vec<String>,
    #[serde(skip)]
    deadline: Instant,
}
#[derive(serde::Serialize)]
pub(crate) struct AccessList {
    pub(crate) requests: Vec<AccessRequest>,
    pub(crate) blocked_callers: Vec<String>,
}
impl AccessRequest {
    fn refresh(&mut self, now: i64) {
        if self.status == ipc::AccessRequestStatus::Pending
            && (Instant::now() >= self.deadline
                || now < self.created_at_ms
                || now >= self.expires_at_ms)
        {
            self.status = ipc::AccessRequestStatus::Expired;
        }
    }
    /// Whether an enabled signed Connection already provides what was asked.
    fn satisfied_by(&self, connection: &Connection) -> bool {
        connection.enabled
            && self
                .connection
                .as_ref()
                .is_none_or(|v| &connection.name == v)
            && (self.provider.is_none() || self.presets.contains(&connection.preset))
            && self
                .operation
                .as_ref()
                .is_none_or(|v| connection.operations.iter().any(|o| &o.name == v))
    }
}

fn validate(request: &ipc::RequestAccessMeta) -> Result<(), BrokerError> {
    let name = |v: &String| !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control);
    if request.reason.is_empty()
        || request.reason.chars().count() > 500
        || request.provider.is_some() == request.connection.is_some()
        || !request.provider.as_ref().is_none_or(name)
        || !request
            .connection
            .as_ref()
            .is_none_or(|v| rekey_domain::template::slug(v, 100))
        || !request.operation.as_ref().is_none_or(name)
    {
        return Err(BrokerError::LocalCall(
            "INVALID_INPUT",
            "invalid access request",
            "Give exactly one of provider or connection (a Connection name), an optional full operation name such as github.list_issues, and a reason of 1 to 500 characters.",
        ));
    }
    Ok(())
}

impl LocalCalls {
    pub(crate) fn create_access(
        &self,
        caller: &str,
        request: ipc::RequestAccessMeta,
        presets: Vec<String>,
    ) -> Result<ipc::RequestAccessResponse, BrokerError> {
        validate(&request)?;
        if self
            .blocked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(caller)
        {
            return Err(BrokerError::LocalCall(
                "DENIED",
                "access requests from this caller are blocked",
                "Ask the user to review the caller block in Rekey.",
            ));
        }
        self.admit_rate(
            &format!("access:{caller}"),
            REQUESTS_PER_MINUTE,
            Duration::from_secs(60),
        )
        .map_err(|error| match error {
            BrokerError::BudgetExceeded { reset_at_ms } => BrokerError::RateLimited { reset_at_ms },
            other => other,
        })?;
        let now = crate::now_ts()?.as_unix_ms();
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries.values_mut() {
            entry.refresh(now);
        }
        entries.retain(|_, a| Instant::now() < a.deadline);
        if entries.len() >= ipc::APPROVAL_PENDING_MAX {
            return Err(rekey_vault::AuthorityError::AuthorityBusy.into());
        }
        let id = crate::random_id(RequestId::from_random_bytes)?;
        let expires_at_ms = now + LIFETIME.as_millis() as i64;
        entries.insert(
            id,
            AccessRequest {
                request_id: id,
                caller: caller.into(),
                provider: request.provider,
                connection: request.connection,
                operation: request.operation,
                reason: request.reason,
                created_at_ms: now,
                expires_at_ms,
                status: ipc::AccessRequestStatus::Pending,
                presets,
                deadline: Instant::now() + LIFETIME,
            },
        );
        self.changed.notify_waiters();
        Ok(ipc::RequestAccessResponse {
            request_id: id,
            expires_at_ms,
        })
    }
    pub(crate) fn access_list(&self) -> Result<AccessList, BrokerError> {
        let now = crate::now_ts()?.as_unix_ms();
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries.values_mut() {
            entry.refresh(now);
        }
        Ok(AccessList {
            requests: entries.values().cloned().collect(),
            blocked_callers: self
                .blocked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect(),
        })
    }
    pub(crate) fn access_get(&self, id: RequestId) -> Result<AccessRequest, BrokerError> {
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("access-request-unknown"))?;
        entry.refresh(crate::now_ts()?.as_unix_ms());
        Ok(entry.clone())
    }
    pub(crate) fn resolve_access(
        &self,
        id: RequestId,
        granted: bool,
    ) -> Result<ipc::AwaitAccessResponse, BrokerError> {
        let mut entries = self.access.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get_mut(&id)
            .ok_or(BrokerError::Denied("access-request-unknown"))?;
        entry.refresh(crate::now_ts()?.as_unix_ms());
        if entry.status != ipc::AccessRequestStatus::Pending {
            return Err(BrokerError::Denied("access-request-not-pending"));
        }
        entry.status = if granted {
            ipc::AccessRequestStatus::Granted
        } else {
            ipc::AccessRequestStatus::Rejected
        };
        self.changed.notify_waiters();
        Ok(ipc::AwaitAccessResponse {
            status: entry.status,
        })
    }
    pub(crate) fn block_caller(&self, caller: String, blocked: bool) {
        let mut entries = self.blocked.lock().unwrap_or_else(|e| e.into_inner());
        if blocked {
            entries.insert(caller);
        } else {
            entries.remove(&caller);
        }
    }
    pub(crate) async fn await_access(
        &self,
        id: RequestId,
        caller: &str,
        timeout_s: u16,
    ) -> Result<ipc::AwaitAccessResponse, BrokerError> {
        if timeout_s > 120 {
            return Err(ipc::FrameError::InvalidField.into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_s as u64);
        loop {
            let changed = self.changed.notified();
            let entry = self.access_get(id)?;
            if entry.caller != caller {
                return Err(BrokerError::Denied("access-owner-mismatch"));
            }
            if entry.status != ipc::AccessRequestStatus::Pending
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(ipc::AwaitAccessResponse {
                    status: entry.status,
                });
            }
            let _ = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::from_std(entry.deadline)),
                changed,
            )
            .await;
        }
    }
}

/// Builtin presets plus the presets of signed Connections, each with the
/// named operations it declares.
fn offered(active: Option<&ActivePolicy>) -> BTreeMap<String, BTreeSet<String>> {
    let mut offered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for name in BUILTIN_PRESETS {
        let operations = rekey_policy::presets::builtin_preset(name)
            .map(|preset| preset.operations.into_iter().map(|o| o.name).collect())
            .unwrap_or_default();
        offered.insert((*name).to_owned(), operations);
    }
    for connection in active.iter().flat_map(|a| a.snapshot().connections()) {
        offered
            .entry(connection.preset.clone())
            .or_default()
            .extend(connection.operations.iter().map(|o| o.name.clone()));
    }
    offered
}

/// A provider names a preset or a preset family (the part before the first
/// `-`); an operation keeps only the presets that declare it.
fn provider_presets(
    provider: &str,
    operation: Option<&str>,
    active: Option<&ActivePolicy>,
) -> Result<Vec<String>, BrokerError> {
    let offered = offered(active);
    let candidates: Vec<_> = offered
        .iter()
        .filter(|(preset, _)| {
            *preset == provider || preset.split_once('-').is_some_and(|(f, _)| f == provider)
        })
        .collect();
    if candidates.is_empty() {
        return Err(BrokerError::Guided(
            "INVALID_INPUT",
            "unknown provider",
            format!(
                "Use a preset name or family: {}. For another API ask for generic-bearer or generic-header; for an existing Connection pass connection from list_capabilities instead.",
                BUILTIN_PRESETS.join(", ")
            ),
        ));
    }
    let Some(operation) = operation else {
        return Ok(candidates.into_iter().map(|(p, _)| p.clone()).collect());
    };
    let matching: Vec<String> = candidates
        .iter()
        .filter(|(_, operations)| operations.contains(operation))
        .map(|(preset, _)| (*preset).clone())
        .collect();
    if matching.is_empty() {
        let declared: BTreeSet<&str> = candidates
            .iter()
            .flat_map(|(_, operations)| operations.iter().map(String::as_str))
            .collect();
        let next = if declared.is_empty() {
            format!("The presets of {provider} declare no named operations; omit operation.")
        } else {
            format!(
                "Use a full operation name declared by {provider}: {}; or omit operation.",
                declared.into_iter().collect::<Vec<_>>().join(", ")
            )
        };
        return Err(BrokerError::Guided(
            "INVALID_INPUT",
            "no preset of this provider declares the operation",
            next,
        ));
    }
    Ok(matching)
}

/// Public audit target: the requested Connection or provider, with the
/// operation's declared path when it resolves.
struct AccessTarget {
    name: String,
    class: MethodClass,
    path: String,
    parameter_hash: [u8; 32],
}
impl AccessTarget {
    fn of(request: &AccessRequest, active: Option<&ActivePolicy>) -> Self {
        let declared = |operations: &[PresetOperation]| {
            let wanted = request.operation.as_deref()?;
            operations.iter().find(|o| o.name == wanted).cloned()
        };
        let connections = active.map_or(&[][..], |a| a.snapshot().connections());
        let operation = match &request.connection {
            Some(name) => connections
                .iter()
                .find(|c| &c.name == name)
                .and_then(|c| declared(&c.operations)),
            None => request.presets.iter().find_map(|preset| {
                connections
                    .iter()
                    .filter(|c| &c.preset == preset)
                    .find_map(|c| declared(&c.operations))
                    .or_else(|| {
                        rekey_policy::presets::builtin_preset(preset)
                            .ok()
                            .and_then(|p| declared(&p.operations))
                    })
            }),
        };
        let (class, path) = operation.map_or((MethodClass::Read, "/".to_owned()), |o| {
            let read = matches!(
                (o.method, &o.read_semantics),
                (
                    rekey_domain::action::FixedMethod::Get
                        | rekey_domain::action::FixedMethod::Head,
                    _
                ) | (_, Some(ReadSemantics::Fixed))
            );
            (
                if read {
                    MethodClass::Read
                } else {
                    MethodClass::Write
                },
                o.path,
            )
        });
        Self {
            name: request
                .connection
                .clone()
                .or_else(|| request.provider.clone())
                .unwrap_or_default(),
            class,
            path,
            parameter_hash: parameter_hash(&serde_json::json!({
                "provider": request.provider,
                "connection": request.connection,
                "operation": request.operation,
            })),
        }
    }
    fn block(caller: &str, blocked: bool) -> Self {
        Self {
            name: BLOCK_SCOPE.into(),
            class: MethodClass::Read,
            path: "/".into(),
            parameter_hash: parameter_hash(&serde_json::json!({"caller":caller,"blocked":blocked})),
        }
    }
}

fn parameter_hash(value: &serde_json::Value) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"RKACCESSREQUEST\0\x01");
    hash.update(serde_jcs::to_vec(value).unwrap_or_default());
    hash.finalize().into()
}

/// The vault binds a Connection audit context to policy evidence, so the
/// context is kept only with an active signed policy and a valid label;
/// otherwise the row keeps its event, reason and request ID. Nothing is
/// fabricated, and untrusted reason text is never recorded.
fn access_audit(
    event: &'static str,
    reason: &str,
    request_id: Option<RequestId>,
    caller: &str,
    target: &AccessTarget,
    active: Option<&ActivePolicy>,
) -> Result<rekey_vault::command::AuditDraft, BrokerError> {
    let mut audit = crate::runtime::call_audit(event, &target.name, caller)?;
    audit.request_id = request_id.or(audit.request_id);
    audit.reason_code = reason.into();
    let context = RequestAuditContext::Connection(ConnectionRequestAuditContext {
        connection: target.name.clone(),
        caller: caller.to_owned(),
        method_class: target.class,
        normalized_path: target.path.clone(),
        rule_id: None,
    });
    // Attached below only together with the policy evidence it requires.
    audit.request_context = None;
    if let Some(active) = active
        && context.validate().is_ok()
    {
        let digest = Sha256::digest(format!("rekey.access-request.v1\0{}", target.name));
        let mut principal = [0; 16];
        principal.copy_from_slice(&digest[..16]);
        audit.authorization = Some(Box::new(rekey_vault::model::AuthorizationEvidence {
            principal_id: rekey_domain::ids::PrincipalId::from_random_bytes(principal),
            policy_version: active.snapshot().version().get(),
            policy_digest: active.snapshot().digest(),
            policy_rule_id: None,
            resource_type: "connection".into(),
            resource_id: target.name.clone(),
            parameter_hash: target.parameter_hash,
        }));
        audit.request_context = Some(context);
    }
    Ok(audit)
}

impl BrokerCtx {
    async fn signed_policy(&self) -> Option<std::sync::Arc<ActivePolicy>> {
        self.policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some())
    }

    /// REQUEST_ACCESS. Input and provider resolution come before the block
    /// and rate checks, so invalid requests never use the caller's window.
    pub(crate) async fn request_access(
        &self,
        caller: &str,
        meta: ipc::RequestAccessMeta,
    ) -> Result<ipc::RequestAccessResponse, BrokerError> {
        validate(&meta)?;
        let active = self.signed_policy().await;
        let presets = match &meta.provider {
            Some(provider) => {
                provider_presets(provider, meta.operation.as_deref(), active.as_deref())?
            }
            None => Vec::new(),
        };
        let response = self.local_calls.create_access(caller, meta, presets)?;
        let request = self.local_calls.access_get(response.request_id)?;
        let target = AccessTarget::of(&request, active.as_deref());
        let reason = if request.provider.is_some() {
            "provider-request"
        } else {
            "connection-request"
        };
        self.authority
            .append_audit(access_audit(
                "access_request.created",
                reason,
                Some(request.request_id),
                caller,
                &target,
                active.as_deref(),
            )?)
            .await?;
        Ok(response)
    }

    /// Records the user's decision. Granting requires an enabled signed
    /// Connection that already provides the request; it never grants itself.
    pub(crate) async fn resolve_access_request(
        &self,
        id: RequestId,
        granted: bool,
        block_caller: bool,
    ) -> Result<ipc::AwaitAccessResponse, BrokerError> {
        let request = self.local_calls.access_get(id)?;
        if request.status != ipc::AccessRequestStatus::Pending {
            return Err(BrokerError::Denied("access-request-not-pending"));
        }
        let active = self.signed_policy().await;
        if granted {
            let policy = active
                .as_ref()
                .ok_or(rekey_policy::PolicyError::NotConfigured)?;
            if policy.is_expired(crate::now_ts()?)
                || !policy
                    .snapshot()
                    .connections()
                    .iter()
                    .any(|c| request.satisfied_by(c))
            {
                return Err(BrokerError::Denied("access-connection-not-active"));
            }
        }
        let target = AccessTarget::of(&request, active.as_deref());
        let reason = if granted { "granted" } else { "rejected" };
        self.authority
            .append_audit(access_audit(
                "access_request.resolved",
                reason,
                Some(id),
                &request.caller,
                &target,
                active.as_deref(),
            )?)
            .await?;
        let response = self.local_calls.resolve_access(id, granted)?;
        if block_caller {
            self.authority
                .append_audit(access_audit(
                    "access_request.block_changed",
                    "blocked",
                    Some(id),
                    &request.caller,
                    &target,
                    active.as_deref(),
                )?)
                .await?;
            self.local_calls.block_caller(request.caller, true);
        }
        Ok(response)
    }

    pub(crate) async fn set_access_block(
        &self,
        caller: String,
        blocked: bool,
    ) -> Result<(), BrokerError> {
        let active = self.signed_policy().await;
        self.authority
            .append_audit(access_audit(
                "access_request.block_changed",
                if blocked { "blocked" } else { "unblocked" },
                None,
                &caller,
                &AccessTarget::block(&caller, blocked),
                active.as_deref(),
            )?)
            .await?;
        self.local_calls.block_caller(caller, blocked);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(
        provider: Option<&str>,
        connection: Option<&str>,
        reason: &str,
    ) -> ipc::RequestAccessMeta {
        ipc::RequestAccessMeta {
            provider: provider.map(str::to_owned),
            connection: connection.map(str::to_owned),
            operation: None,
            reason: reason.into(),
        }
    }

    #[tokio::test]
    async fn requests_expire_after_ten_minutes_by_either_clock() {
        for clock in ["monotonic", "wall", "wall-rollback"] {
            let calls = LocalCalls::default();
            let created = calls
                .create_access("codex", meta(Some("stripe"), None, "Billing"), Vec::new())
                .unwrap();
            let request = calls.access_get(created.request_id).unwrap();
            assert_eq!(request.expires_at_ms - request.created_at_ms, 600_000);
            assert!(request.deadline > Instant::now() + Duration::from_secs(590));
            {
                let mut entries = calls.access.lock().unwrap();
                let entry = entries.get_mut(&created.request_id).unwrap();
                match clock {
                    "monotonic" => entry.deadline = Instant::now(),
                    "wall" => entry.expires_at_ms = entry.created_at_ms,
                    _ => entry.created_at_ms = i64::MAX,
                }
            }
            let waited = calls
                .await_access(created.request_id, "codex", 1)
                .await
                .unwrap();
            assert_eq!(waited.status, ipc::AccessRequestStatus::Expired, "{clock}");
            assert_eq!(
                calls
                    .resolve_access(created.request_id, true)
                    .unwrap_err()
                    .code(),
                "REQUEST_DENIED",
                "{clock}: an expired request cannot be granted"
            );
        }
    }

    #[tokio::test]
    async fn only_the_owner_may_wait_and_bad_input_never_uses_the_window() {
        let calls = LocalCalls::default();
        for invalid in [
            meta(None, None, "Billing"),
            meta(Some("stripe"), Some("billing"), "Billing"),
            meta(Some("stripe"), None, ""),
            meta(None, Some("bad name"), "Billing"),
        ] {
            assert_eq!(
                calls
                    .create_access("codex", invalid, Vec::new())
                    .unwrap_err()
                    .code(),
                "INVALID_INPUT"
            );
        }
        let mut created = Vec::new();
        for _ in 0..REQUESTS_PER_MINUTE {
            created.push(
                calls
                    .create_access("codex", meta(None, Some("billing"), "Billing"), Vec::new())
                    .unwrap(),
            );
        }
        assert_eq!(
            calls
                .await_access(created[0].request_id, "claude-code", 1)
                .await
                .unwrap_err()
                .code(),
            "REQUEST_DENIED",
            "another caller label cannot wait on this request"
        );
        let limited = calls
            .create_access("codex", meta(None, Some("billing"), "Billing"), Vec::new())
            .unwrap_err();
        assert_eq!(limited.code(), "RATE_LIMITED");
        assert!(!limited.retryable());
        assert!(limited.agent_next().contains("UTC"));
        // Caller labels are advisory: another label has its own window.
        calls
            .create_access(
                "claude-code",
                meta(None, Some("billing"), "Billing"),
                Vec::new(),
            )
            .unwrap();
    }

    #[test]
    fn providers_resolve_presets_families_and_declared_operations() {
        assert_eq!(
            provider_presets("github", None, None).unwrap(),
            ["github-git", "github-oauth", "github-pat"]
        );
        assert_eq!(
            provider_presets("github", Some("github.list_issues"), None).unwrap(),
            ["github-oauth", "github-pat"]
        );
        assert_eq!(
            provider_presets("qwen", Some("qwen.chat"), None).unwrap(),
            ["qwen", "qwen-hk", "qwen-intl", "qwen-us"]
        );
        assert_eq!(provider_presets("stripe", None, None).unwrap(), ["stripe"]);
        let unknown = provider_presets("githubb", None, None).unwrap_err();
        assert_eq!(unknown.code(), "INVALID_INPUT");
        assert!(unknown.agent_next().contains("github-pat"));
        let undeclared = provider_presets("generic", Some("x.y"), None).unwrap_err();
        assert!(undeclared.agent_next().contains("no named operations"));
    }
}
