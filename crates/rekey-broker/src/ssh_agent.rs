//! OpenSSH agent protocol. Private keys remain in the Authority.
//! https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent

use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::signature;
use data_encoding::{BASE64, HEXLOWER};
use rekey_domain::audit::RequestAuditContext;
use rekey_domain::authorization::{ApprovalMode, ApproverSpec, ResourceRef, SchemaId};
use rekey_domain::connection::{
    ConnectionRequestAuditContext, MethodClass, RuleEffect, SshKeyConnection,
};
use rekey_domain::ids::{
    ActionId, ApprovalRequestId, PolicyRuleId, PrincipalId, RequestId, SessionId, TenantId,
};
use rekey_domain::ipc::{self, ApprovalChallenge, LocalApprovalState};
use rekey_vault::command::AuditDraft;
use rekey_vault::model::{ApprovalEvidence, AuthorizationEvidence, event_type, outcome};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::runtime::BrokerCtx;
use crate::runtime::local_calls::LocalCallApproval;

const MAX_PACKET: usize = 256 * 1024;
const ED: &[u8] = b"ssh-ed25519";
const EC: &[u8] = b"ecdsa-sha2-nistp256";
const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;

fn denied() -> BrokerError {
    BrokerError::Denied("invalid-ssh-request")
}
fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], BrokerError> {
        if len > self.0.len() {
            return Err(denied());
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, BrokerError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, BrokerError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| denied())?,
        ))
    }
    fn string(&mut self) -> Result<&'a [u8], BrokerError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn end(self) -> Result<(), BrokerError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(denied())
        }
    }
}

fn key_parts(blob: &[u8]) -> Result<(&[u8], &[u8]), BrokerError> {
    let mut r = Reader(blob);
    let alg = r.string()?;
    let public = match alg {
        ED => {
            let public = r.string()?;
            if public.len() != 32 {
                return Err(denied());
            }
            public
        }
        EC => {
            if r.string()? != b"nistp256" {
                return Err(denied());
            }
            let public = r.string()?;
            if public.len() != 65 || public[0] != 4 {
                return Err(denied());
            }
            public
        }
        _ => return Err(denied()),
    };
    r.end()?;
    Ok((alg, public))
}

fn scalar(bytes: &[u8]) -> Result<[u8; 32], BrokerError> {
    if bytes.is_empty()
        || bytes[0] & 0x80 != 0
        || (bytes[0] == 0 && (bytes.len() == 1 || bytes[1] & 0x80 == 0))
    {
        return Err(denied());
    }
    let bytes = if bytes[0] == 0 { &bytes[1..] } else { bytes };
    if bytes.len() > 32 {
        return Err(denied());
    }
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn verify_host_signature(host: &[u8], session: &[u8], sig: &[u8]) -> Result<(), BrokerError> {
    let (alg, public) = key_parts(host)?;
    let mut r = Reader(sig);
    if r.string()? != alg {
        return Err(denied());
    }
    let signature = r.string()?;
    r.end()?;
    if alg == ED {
        signature::UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(session, signature)
            .map_err(|_| denied())
    } else {
        let mut r = Reader(signature);
        let mut fixed = [0; 64];
        fixed[..32].copy_from_slice(&scalar(r.string()?)?);
        fixed[32..].copy_from_slice(&scalar(r.string()?)?);
        r.end()?;
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public)
            .verify(session, &fixed)
            .map_err(|_| denied())
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_wire(bytes: &[u8]) {
    if bytes.len() > MAX_PACKET {
        return;
    }
    let _ = key_parts(bytes);
    let _ = scalar(bytes);
    let Some((&message, contents)) = bytes.split_first() else {
        return;
    };
    let mut r = Reader(contents);
    match message {
        13 => {
            if let Ok(public) = r.string()
                && key_parts(public).is_ok()
                && let Ok(data) = r.string()
                && let Ok(0) = r.u32()
                && r.end().is_ok()
            {
                let _ = AgentSession::default().purpose(data, public);
            }
        }
        27 => {
            if let Ok(b"session-bind@openssh.com") = r.string() {
                let _ = AgentSession::default().bind(r);
            }
        }
        _ => {
            let _ = r.end();
        }
    }
}

#[derive(Default)]
struct AgentSession {
    bound: Option<BoundSession>,
    budgets: std::collections::BTreeMap<String, (Instant, u32)>,
}
struct BoundSession {
    host: Vec<u8>,
    session: Vec<u8>,
}
impl AgentSession {
    fn bind(&mut self, mut r: Reader<'_>) -> Result<(), BrokerError> {
        let host = r.string()?;
        let session = r.string()?;
        let signature = r.string()?;
        let forwarded = r.byte()?;
        r.end()?;
        // This release does not authorize forwarded chains. Their constraints
        // require each hop, not merely the last host key, to be authenticated.
        if forwarded != 0
            || self.bound.is_some()
            || !(16..=128).contains(&session.len())
            || host.len() > 1024
        {
            return Err(denied());
        }
        verify_host_signature(host, session, signature)?;
        self.bound = Some(BoundSession {
            host: host.to_vec(),
            session: session.to_vec(),
        });
        Ok(())
    }

    fn purpose(&self, data: &[u8], public: &[u8]) -> Result<Purpose, BrokerError> {
        if let Some(rest) = data.strip_prefix(b"SSHSIG") {
            let mut r = Reader(rest);
            let namespace = r.string()?;
            let reserved = r.string()?;
            let hash = r.string()?;
            let digest = r.string()?;
            r.end()?;
            if !reserved.is_empty()
                || !((hash == b"sha256" && digest.len() == 32)
                    || (hash == b"sha512" && digest.len() == 64))
            {
                return Err(denied());
            }
            return Ok(if namespace == b"git" {
                Purpose::Git
            } else {
                Purpose::Other
            });
        }
        let mut r = Reader(data);
        let session = r.string()?;
        if !(16..=128).contains(&session.len()) || r.byte()? != 50 {
            return Err(denied());
        }
        let username = std::str::from_utf8(r.string()?).map_err(|_| denied())?;
        if username.is_empty()
            || username.len() > 256
            || username.chars().any(char::is_control)
            || r.string()? != b"ssh-connection"
        {
            return Err(denied());
        }
        let method = r.string()?;
        if method != b"publickey" && method != b"publickey-hostbound-v00@openssh.com" {
            return Err(denied());
        }
        if r.byte()? != 1 || r.string()? != key_parts(public)?.0 || r.string()? != public {
            return Err(denied());
        }
        let embedded_host = if method == b"publickey-hostbound-v00@openssh.com" {
            Some(r.string()?)
        } else {
            None
        };
        r.end()?;
        if let Some(bound) = &self.bound
            && (bound.session != session || embedded_host.is_some_and(|host| host != bound.host))
        {
            return Err(denied());
        }
        Ok(Purpose::Authentication {
            username: username.to_owned(),
            unverified_host: embedded_host.map(|h| BASE64.encode(h)),
        })
    }
}

#[derive(serde::Serialize)]
#[serde(tag = "purpose", rename_all = "snake_case")]
enum Purpose {
    Git,
    Authentication {
        username: String,
        unverified_host: Option<String>,
    },
    Other,
}

fn effect(
    key: &SshKeyConnection,
    session: &AgentSession,
    purpose: &Purpose,
) -> (RuleEffect, Option<PolicyRuleId>, String) {
    if matches!(purpose, Purpose::Git) {
        return (key.git_signing, None, "git".into());
    }
    if !matches!(purpose, Purpose::Authentication { .. }) {
        return (RuleEffect::Approve, None, "unknown-purpose".into());
    }
    let Some(bound) = &session.bound else {
        return (RuleEffect::Approve, None, "unknown-host".into());
    };
    let encoded = BASE64.encode(&bound.host);
    // A reused host key may name multiple hosts. Apply the strictest signed
    // rule so an alias can never loosen an explicit denial.
    let host = key
        .hosts
        .iter()
        .filter(|h| h.host_key == encoded)
        .max_by_key(|h| h.effect);
    host.map(|h| (h.effect, Some(h.rule_id), h.host.clone()))
        .unwrap_or((RuleEffect::Approve, None, "unknown-host".into()))
}

fn id_bytes(input: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    digest[..16].try_into().expect("fixed digest")
}

pub(crate) fn verify_external_grants(
    challenge: &ApprovalChallenge,
    raw: &[Box<serde_json::value::RawValue>],
    snapshot: &rekey_policy::ValidatedSnapshot,
    now_ms: i64,
) -> Result<(Vec<ApprovalEvidence>, i64), BrokerError> {
    let ApproverSpec::Ed25519 { keys, threshold } = &challenge.approver else {
        return Err(BrokerError::Denied("approval-authority-mismatch"));
    };
    if challenge.schema_id.as_str() != "rekey.ssh-sign.v1"
        || raw.len() != usize::from(*threshold)
        || raw.len() > 2
        || now_ms < challenge.created_at_ms
        || now_ms >= challenge.max_expires_at_ms
    {
        return Err(BrokerError::Denied("approval-insufficient-quorum"));
    }
    let allowed = snapshot
        .ed25519_approver_ids(keys)
        .ok_or(BrokerError::Denied("approval-grant-invalid"))?;
    let mut approvers = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut evidence = Vec::new();
    let mut expires = challenge.max_expires_at_ms;
    for raw in raw {
        let verified =
            rekey_policy::parse_and_verify_approval_grant(raw.get().as_bytes(), snapshot)?;
        let g = verified.grant();
        if g.approval_request_id != challenge.approval_request_id
            || g.tenant_id != challenge.tenant_id
            || g.principal_id != challenge.principal_id
            || g.session_id != challenge.session_id
            || g.action_id != challenge.action_id
            || g.action_version != challenge.action_version
            || g.resource != challenge.resource
            || g.schema_id != challenge.schema_id
            || g.parameter_sha256 != challenge.parameter_sha256
            || g.policy_version.get() != challenge.policy_version
            || g.policy_sha256 != challenge.policy_sha256
            || g.policy_rule_id != challenge.policy_rule_id
            || g.mode != ApprovalMode::OneTime
            || g.max_uses != 1
            || g.not_before_ms < challenge.created_at_ms
            || now_ms < g.not_before_ms
            || now_ms >= g.expires_at_ms
            || g.expires_at_ms > challenge.max_expires_at_ms
            || !allowed.contains(&g.approver_id)
            || !approvers.insert(g.approver_id)
            || !ids.insert(g.approval_id)
        {
            return Err(BrokerError::Denied("approval-grant-mismatch"));
        }
        expires = expires.min(g.expires_at_ms);
        evidence.push(ApprovalEvidence {
            approval_request_id: g.approval_request_id,
            approval_id: Some(g.approval_id),
            approver_id: Some(g.approver_id),
        });
    }
    Ok((evidence, expires))
}

struct PendingApproval {
    calls: Arc<crate::runtime::local_calls::LocalCalls>,
    id: Option<ApprovalRequestId>,
}
impl Drop for PendingApproval {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.calls.cancel_unconfirmed(id);
        }
    }
}

async fn sign(
    ctx: &Arc<BrokerCtx>,
    session: &mut AgentSession,
    packet: &[u8],
    cancel: watch::Receiver<bool>,
) -> Result<Vec<u8>, BrokerError> {
    ctx.lifecycle.reject_if_not_running()?;
    let mut r = Reader(packet);
    let public = r.string()?.to_vec();
    key_parts(&public)?;
    let data = r.string()?.to_vec();
    if data.is_empty() || r.u32()? != 0 {
        return Err(denied());
    }
    r.end()?;
    let purpose = session.purpose(&data, &public)?;
    let active = ctx
        .policy
        .read()
        .await
        .clone()
        .filter(|p| p.signer_id().is_some())
        .ok_or(BrokerError::Denied("ssh-policy-unavailable"))?;
    let now = crate::now_ts()?;
    if active.is_expired(now) {
        return Err(BrokerError::Denied("policy-expired"));
    }
    let encoded = BASE64.encode(&public);
    let key = active
        .snapshot()
        .ssh_keys()
        .iter()
        .find(|k| k.user_public_key == encoded)
        .ok_or(BrokerError::Denied("ssh-key-unregistered"))?;
    let (effect, rule, host) = effect(key, session, &purpose);
    let matched_host_rule = rule.is_some();
    let request = crate::random_id(RequestId::from_random_bytes)?;
    let correlation = SessionId::from_random_bytes(*request.as_bytes());
    let action_id = ActionId::from_random_bytes(id_bytes(format!("ssh:{}", key.name).as_bytes()));
    let caller = "ssh-agent";
    let digest = active.snapshot().digest();
    let review_request = serde_json::json!({"key":key.name,"host":host,"bound_host_key":session.bound.as_ref().map(|b| BASE64.encode(&b.host)),"session_id":session.bound.as_ref().map(|b| HEXLOWER.encode(&b.session)),"public_key":encoded,"data_sha256":HEXLOWER.encode(&Sha256::digest(&data)),"data_base64":BASE64.encode(&data),"window_allowed":effect==RuleEffect::Approve && matched_host_rule && matches!(key.approver, ApproverSpec::LocalPresence {}),"use":purpose});
    let canonical = Zeroizing::new(serde_jcs::to_vec(&review_request).map_err(|_| denied())?);
    let parameter_hash: [u8; 32] = Sha256::digest(&*canonical).into();
    let rule = rule.unwrap_or_else(|| {
        PolicyRuleId::from_random_bytes(id_bytes(
            format!("{}:ssh-default:{host}", key.name).as_bytes(),
        ))
    });
    let mut started = AuditDraft {
        request_id: Some(request),
        session_id: Some(correlation),
        action_id: Some(action_id),
        action_version: Some(1),
        credential_id: Some(key.credential_id),
        credential_version: None,
        authorization: Some(Box::new(AuthorizationEvidence {
            principal_id: PrincipalId::from_random_bytes(id_bytes(caller.as_bytes())),
            policy_version: active.snapshot().version().get(),
            policy_digest: digest,
            policy_rule_id: Some(rule),
            resource_type: "connection".into(),
            resource_id: key.name.clone(),
            parameter_hash,
        })),
        approval: None,
        usage: None,
        request_context: Some(RequestAuditContext::Connection(
            ConnectionRequestAuditContext {
                connection: key.name.clone(),
                caller: caller.into(),
                method_class: MethodClass::Write,
                normalized_path: "/ssh/sign".into(),
                rule_id: Some(rule),
            },
        )),
        event_type: event_type::EXECUTION_STARTED,
        outcome: outcome::SUCCESS,
        reason_code: "ssh-sign".into(),
        upstream_status: None,
        latency_ms: None,
    };
    if effect == RuleEffect::Deny {
        started.event_type = event_type::EXECUTION_BLOCKED;
        started.outcome = outcome::DENIED;
        started.reason_code = "ssh-host-denied".into();
        ctx.authority.append_audit(started).await?;
        return Err(BrokerError::Denied("ssh-host-denied"));
    }
    let budget_started = session
        .budgets
        .get(&key.name)
        .map_or_else(Instant::now, |(start, _)| *start);
    let mut deadline = (budget_started
        + Duration::from_secs(u64::from(key.session_budget.max_seconds)))
    .min(Instant::now() + Duration::from_secs(600))
    .min(active.monotonic_deadline().into_std());
    if session
        .budgets
        .get(&key.name)
        .is_some_and(|(_, used)| *used >= key.session_budget.max_signatures)
        || Instant::now() >= deadline
    {
        return Err(BrokerError::Denied("ssh-session-budget-exceeded"));
    }
    let mut approvals = Vec::new();
    let mut pending = PendingApproval {
        calls: Arc::clone(&ctx.local_calls),
        id: None,
    };
    if effect == RuleEffect::Approve {
        let window = if matched_host_rule && matches!(key.approver, ApproverSpec::LocalPresence {})
        {
            ctx.local_calls.window(
                &HEXLOWER.encode(&digest),
                &key.name,
                Some(rule),
                caller,
                now.as_unix_ms(),
            )
        } else {
            None
        };
        if let Some(window) = window {
            let mut accepted = started.clone();
            accepted.event_type = event_type::APPROVAL_ACCEPTED;
            accepted.reason_code = "local-presence-window".into();
            accepted.approval = Some(ApprovalEvidence {
                approval_request_id: window.request_id,
                approval_id: Some(window.approval_id),
                approver_id: None,
            });
            approvals.push(accepted);
        } else {
            let approval_id = crate::random_id(ApprovalRequestId::from_random_bytes)?;
            let status = ctx.authority.status().await?;
            let parameter_sha256 = HEXLOWER.encode(&parameter_hash);
            let policy_sha256 = HEXLOWER.encode(&digest);
            let challenge = ApprovalChallenge {
                record_type: "rekey.approval.challenge.v2".into(),
                approval_request_id: approval_id,
                tenant_id: TenantId::from_random_bytes(*status.vault_id.as_bytes()),
                principal_id: started
                    .authorization
                    .as_ref()
                    .expect("constructed authorization")
                    .principal_id,
                session_id: correlation,
                action_id,
                action_version: 1,
                resource: ResourceRef::new("connection".into(), key.name.clone())?,
                schema_id: SchemaId::new("rekey.ssh-sign.v1".into())?,
                parameter_sha256: parameter_sha256.clone(),
                policy_version: active.snapshot().version().get(),
                policy_sha256: policy_sha256.clone(),
                policy_rule_id: rule,
                mode: ApprovalMode::OneTime,
                approver: key.approver.clone(),
                max_uses: 1,
                created_at_ms: now.as_unix_ms(),
                max_expires_at_ms: (now.as_unix_ms()
                    + deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis() as i64)
                    .min(active.snapshot().expires_at_ms()),
            };
            let review = Zeroizing::new(serde_jcs::to_vec(&serde_json::json!({"record_type":"rekey.approval.local-review.v1","challenge":challenge,"ssh":review_request})).map_err(|_| denied())?);
            let mut hash = Sha256::new();
            hash.update(ipc::LOCAL_APPROVAL_REVIEW_HASH_PREFIX);
            hash.update(&*review);
            let local = ctx.local_calls.register(
                LocalCallApproval {
                    challenge,
                    caller: caller.into(),
                    request_context: started.request_context.clone(),
                    review_sha256: HEXLOWER.encode(&hash.finalize()),
                    review,
                    deadline,
                    state: LocalApprovalState::Pending,
                    approval_id: None,
                    external_evidence: Vec::new(),
                    reserved: false,
                },
                now.as_unix_ms(),
            )?;
            let id = local.challenge.approval_request_id;
            pending.id = Some(id);
            if id == approval_id {
                let mut requested = started.clone();
                requested.event_type = event_type::APPROVAL_REQUESTED;
                requested.reason_code = "local-presence".into();
                requested.approval = Some(ApprovalEvidence {
                    approval_request_id: id,
                    approval_id: None,
                    approver_id: None,
                });
                ctx.authority.append_audit(requested).await?;
            }
            loop {
                let response = tokio::select! {
                    biased;
                    _ = crate::executor::wait_for_cancel(cancel.clone()) => return Err(BrokerError::Denied("ssh-peer-closed")),
                    _ = crate::executor::wait_for_cancel(ctx.lifecycle.subscribe_cancel()) => return Err(BrokerError::Denied("ssh-draining")),
                    _ = tokio::time::sleep_until(deadline.into()) => return Err(BrokerError::Denied("ssh-approval-expired")),
                    response = ctx.local_calls.await_state(id, caller, 120) => response?,
                };
                match response.state {
                    LocalApprovalState::Pending if Instant::now() < deadline => continue,
                    LocalApprovalState::Approved => break,
                    _ => return Err(BrokerError::Denied("ssh-approval-not-granted")),
                }
            }
            let consumed = ctx.local_calls.consume(
                id,
                caller,
                &parameter_sha256,
                &policy_sha256,
                crate::now_ts()?.as_unix_ms(),
            )?;
            let mut accepted = started.clone();
            accepted.event_type = event_type::APPROVAL_ACCEPTED;
            accepted.reason_code = "local-presence".into();
            accepted.approval = Some(ApprovalEvidence {
                approval_request_id: id,
                approval_id: consumed.approval_id,
                approver_id: None,
            });
            if consumed.external_evidence.is_empty() {
                approvals.push(accepted);
            } else {
                deadline = deadline.min(consumed.deadline);
                for evidence in consumed.external_evidence {
                    let mut accepted = accepted.clone();
                    accepted.reason_code = "ed25519".into();
                    accepted.approval = Some(evidence);
                    approvals.push(accepted);
                }
            }
        }
    }
    let _owner = ctx
        .lifecycle
        .coordinate_until(tokio::time::Instant::from_std(deadline))
        .await?;
    ctx.lifecycle.reject_if_not_running()?;
    let current = ctx
        .policy
        .read()
        .await
        .clone()
        .ok_or(BrokerError::Denied("ssh-policy-unavailable"))?;
    if current.snapshot().digest() != digest || current.is_expired(crate::now_ts()?) {
        return Err(BrokerError::Denied("ssh-policy-changed"));
    }
    if *cancel.borrow() || !ctx.lifecycle.try_begin_remote_effect() || Instant::now() >= deadline {
        return Err(BrokerError::Denied("ssh-peer-closed"));
    }
    let entry = session
        .budgets
        .entry(key.name.clone())
        .or_insert((budget_started, 0));
    entry.1 += 1;
    let _permit = ctx.lifecycle.local_permit();
    // Once queued, retain both permit and receiver through durable terminal completion.
    let result = ctx
        .authority
        .ssh_sign(
            key.credential_id,
            public,
            data,
            started,
            approvals,
            deadline,
        )
        .await;
    pending.id = None;
    result.map_err(Into::into)
}

async fn process(
    ctx: &Arc<BrokerCtx>,
    session: &mut AgentSession,
    packet: &[u8],
    cancel: watch::Receiver<bool>,
) -> Vec<u8> {
    let Some((&message, contents)) = packet.split_first() else {
        return vec![FAILURE];
    };
    let result: Result<Vec<u8>, BrokerError> = match message {
        11 if contents.is_empty() => {
            async {
                let active = ctx
                    .policy
                    .read()
                    .await
                    .clone()
                    .filter(|p| p.signer_id().is_some())
                    .ok_or_else(denied)?;
                if active.is_expired(crate::now_ts()?) {
                    return Err(denied());
                }
                let mut out = vec![12];
                out.extend_from_slice(&(active.snapshot().ssh_keys().len() as u32).to_be_bytes());
                for key in active.snapshot().ssh_keys() {
                    let public = BASE64
                        .decode(key.user_public_key.as_bytes())
                        .map_err(|_| denied())?;
                    key_parts(&public)?;
                    string(&mut out, &public);
                    string(&mut out, key.name.as_bytes());
                }
                Ok(out)
            }
            .await
        }
        13 => sign(ctx, session, contents, cancel).await.map(|sig| {
            let mut out = vec![14];
            string(&mut out, &sig);
            out
        }),
        27 => {
            let mut r = Reader(contents);
            match r.string() {
                Ok(b"session-bind@openssh.com") => session.bind(r).map(|_| vec![SUCCESS]),
                Ok(_) => return vec![28],
                Err(error) => Err(error),
            }
        }
        // add/remove identities, constraints, lock/unlock and arbitrary
        // extensions are not credential mutation entry points.
        _ => Err(denied()),
    };
    result.unwrap_or_else(|error| {
        tracing::debug!(event = "ssh.request_failed", code = error.code());
        vec![FAILURE]
    })
}

async fn write_live(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    ctx: &BrokerCtx,
    digest: [u8; 32],
    response: &[u8],
    deadline: tokio::time::Instant,
) -> Result<(), BrokerError> {
    use std::future::Future;
    use std::task::Poll;
    use tokio::io::AsyncWrite;
    let mut frame = Zeroizing::new(Vec::with_capacity(response.len() + 4));
    frame.extend_from_slice(&(response.len() as u32).to_be_bytes());
    frame.extend_from_slice(response);
    let mut written = 0;
    while written < frame.len() {
        let mut gate = None;
        let count = tokio::time::timeout_at(
            deadline,
            std::future::poll_fn(|cx| {
                if gate.is_none() {
                    gate = Some(Box::pin(async {
                        let owner = ctx.lifecycle.coordinate_until(deadline).await?;
                        ctx.lifecycle.reject_if_not_running()?;
                        if !ctx.lifecycle.try_begin_remote_effect() {
                            return Err(denied());
                        }
                        let policy = tokio::time::timeout_at(deadline, ctx.policy.read())
                            .await
                            .map_err(|_| denied())?;
                        let now = crate::now_ts()?;
                        if policy
                            .as_ref()
                            .is_none_or(|p| p.snapshot().digest() != digest || p.is_expired(now))
                        {
                            return Err(denied());
                        }
                        Ok::<_, BrokerError>((owner, policy))
                    }));
                }
                let live = match gate.as_mut().expect("live output gate").as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(live)) => live,
                };
                gate = None;
                let output = std::pin::Pin::new(&mut *writer).poll_write(cx, &frame[written..]);
                drop(live);
                output.map(|r| r.map_err(|_| denied()))
            }),
        )
        .await
        .map_err(|_| denied())??;
        if count == 0 {
            return Err(denied());
        }
        written += count;
    }
    Ok(())
}

pub(crate) async fn handle_connection(
    stream: UnixStream,
    ctx: Arc<BrokerCtx>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let mut session = AgentSession::default();
    loop {
        let packet = tokio::select! {
            biased;
            _=crate::executor::wait_for_cancel(shutdown.clone())=>break,
            packet=async {
                let length=reader.read_u32().await? as usize;
                if length==0 || length>MAX_PACKET { return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)); }
                let mut packet=Zeroizing::new(vec![0;length]);
                reader.read_exact(&mut packet).await?;
                Ok::<_,std::io::Error>(packet)
            }=>match packet {Ok(packet)=>packet,Err(_)=>break},
        };
        let active = ctx.policy.read().await.clone();
        let Some(active) = active else {
            break;
        };
        let (cancel, receiver) = watch::channel(false);
        let operation = process(&ctx, &mut session, &packet, receiver);
        tokio::pin!(operation);
        let response = tokio::select! {
            biased;
            _=shutdown.changed()=>{ cancel.send_replace(true); let _ = operation.await; break; },
            _=reader.read_u8()=>{ cancel.send_replace(true); let _ = operation.await; break; },
            response=&mut operation=>response,
        };
        if response.len() > MAX_PACKET {
            break;
        }
        let deadline = (tokio::time::Instant::now() + Duration::from_secs(10))
            .min(active.monotonic_deadline());
        let written = tokio::select! {
            biased;
            _=shutdown.changed()=>break,
            _=reader.read_u8()=>break,
            written=write_live(&mut writer, &ctx, active.snapshot().digest(), &response, deadline)=>written,
        };
        if written.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;
    use rekey_domain::ids::CredentialId;

    fn ed(seed: u8) -> (signature::Ed25519KeyPair, Vec<u8>) {
        let key = signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let mut public = Vec::new();
        string(&mut public, ED);
        string(&mut public, key.public_key().as_ref());
        (key, public)
    }
    fn bind(key: &signature::Ed25519KeyPair, public: &[u8], sid: &[u8], forward: u8) -> Vec<u8> {
        let mut signature = Vec::new();
        string(&mut signature, ED);
        string(&mut signature, key.try_sign(sid).unwrap().as_ref());
        let mut payload = Vec::new();
        string(&mut payload, public);
        string(&mut payload, sid);
        string(&mut payload, &signature);
        payload.push(forward);
        payload
    }
    fn auth(public: &[u8], sid: &[u8], user: &[u8], host: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        string(&mut out, sid);
        out.push(50);
        string(&mut out, user);
        string(&mut out, b"ssh-connection");
        string(
            &mut out,
            if host.is_some() {
                b"publickey-hostbound-v00@openssh.com"
            } else {
                b"publickey"
            },
        );
        out.push(1);
        string(&mut out, ED);
        string(&mut out, public);
        if let Some(host) = host {
            string(&mut out, host);
        }
        out
    }
    #[test]
    fn session_bind_requires_authentic_signature_and_refuses_rebind_or_forwarding() {
        let (host, public) = ed(3);
        let (_, other) = ed(4);
        let sid = [9; 32];
        let mut session = AgentSession::default();
        assert!(session.bind(Reader(&bind(&host, &other, &sid, 0))).is_err());
        assert!(session.bound.is_none());
        assert!(
            session
                .bind(Reader(&bind(&host, &public, &sid, 1)))
                .is_err()
        );
        let mut invalid = bind(&host, &public, &sid, 0);
        invalid[20] ^= 1;
        assert!(session.bind(Reader(&invalid)).is_err());
        session
            .bind(Reader(&bind(&host, &public, &sid, 0)))
            .unwrap();
        assert!(
            session
                .bind(Reader(&bind(&host, &public, &sid, 0)))
                .is_err()
        );
        assert_eq!(session.bound.unwrap().host, public);
    }
    #[test]
    fn bound_userauth_matches_session_userkey_hostbound_target_and_complete_wire() {
        let (host, host_public) = ed(3);
        let (_, public) = ed(4);
        let (_, other) = ed(5);
        let sid = [9; 32];
        let mut session = AgentSession::default();
        session
            .bind(Reader(&bind(&host, &host_public, &sid, 0)))
            .unwrap();
        let valid = auth(&public, &sid, b"git", Some(&host_public));
        assert!(
            matches!(session.purpose(&valid,&public).unwrap(),Purpose::Authentication{username,..} if username=="git")
        );
        assert!(
            session
                .purpose(&auth(&public, &[7; 32], b"git", None), &public)
                .is_err()
        );
        assert!(
            session
                .purpose(&auth(&other, &sid, b"git", None), &public)
                .is_err()
        );
        assert!(
            session
                .purpose(&auth(&public, &sid, b"git", Some(&other)), &public)
                .is_err()
        );
        assert!(
            session
                .purpose(&auth(&public, &sid, b"bad\nusername", None), &public)
                .is_err()
        );
        let mut trailing = valid;
        trailing.push(0);
        assert!(session.purpose(&trailing, &public).is_err());
    }
    #[test]
    fn unknown_bind_approves_but_signed_deny_and_stricter_alias_never_downgrade() {
        let (host, host_public) = ed(3);
        let (_, public) = ed(4);
        let sid = [9; 32];
        let rule = PolicyRuleId::new_random();
        let key = SshKeyConnection {
            name: "synthetic".into(),
            credential_id: CredentialId::new_random(),
            user_public_key: BASE64.encode(&public),
            git_signing: RuleEffect::Allow,
            approver: rekey_domain::authorization::ApproverSpec::LocalPresence {},
            session_budget: rekey_domain::connection::SshSessionBudget {
                max_signatures: 100,
                max_seconds: 600,
            },
            hosts: vec![
                rekey_domain::connection::SshHostRule {
                    host: "denied.example".into(),
                    host_key: BASE64.encode(&host_public),
                    rule_id: rule,
                    effect: RuleEffect::Deny,
                },
                rekey_domain::connection::SshHostRule {
                    host: "alias.example".into(),
                    host_key: BASE64.encode(&host_public),
                    rule_id: PolicyRuleId::new_random(),
                    effect: RuleEffect::Allow,
                },
            ],
        };
        let purpose = Purpose::Authentication {
            username: "git".into(),
            unverified_host: None,
        };
        let mut session = AgentSession::default();
        assert_eq!(effect(&key, &session, &purpose).0, RuleEffect::Approve);
        session
            .bind(Reader(&bind(&host, &host_public, &sid, 0)))
            .unwrap();
        assert_eq!(
            effect(&key, &session, &purpose),
            (RuleEffect::Deny, Some(rule), "denied.example".into())
        );
        assert_eq!(effect(&key, &session, &Purpose::Git).0, RuleEffect::Allow);
    }
    #[test]
    fn git_signature_requires_exact_namespace_digest_length_and_no_reserved_payload() {
        let (_, public) = ed(4);
        let session = AgentSession::default();
        let mut data = b"SSHSIG".to_vec();
        string(&mut data, b"git");
        string(&mut data, b"");
        string(&mut data, b"sha256");
        string(&mut data, &[1; 32]);
        assert!(matches!(
            session.purpose(&data, &public).unwrap(),
            Purpose::Git
        ));
        let mut truncated = data.clone();
        truncated.pop();
        assert!(session.purpose(&truncated, &public).is_err());
        data.push(0);
        assert!(session.purpose(&data, &public).is_err());
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn fuzz_wire_exercises_bounded_protocol_parsers_without_authority() {
        let (host, host_public) = ed(3);
        let (_, public) = ed(4);
        let sid = [9; 32];
        let mut session_bind = vec![27];
        string(&mut session_bind, b"session-bind@openssh.com");
        session_bind.extend_from_slice(&bind(&host, &host_public, &sid, 0));
        let mut sign = vec![13];
        string(&mut sign, &public);
        string(&mut sign, &auth(&public, &sid, b"git", None));
        sign.extend_from_slice(&0_u32.to_be_bytes());
        let mut ec_public = Vec::new();
        string(&mut ec_public, EC);
        string(&mut ec_public, b"nistp256");
        let mut point = [0; 65];
        point[0] = 4;
        string(&mut ec_public, &point);
        let mut scalars = Vec::new();
        string(&mut scalars, &[1]);
        string(&mut scalars, &[2]);
        let mut ec_signature = Vec::new();
        string(&mut ec_signature, EC);
        string(&mut ec_signature, &scalars);
        let mut ec_bind = vec![27];
        string(&mut ec_bind, b"session-bind@openssh.com");
        string(&mut ec_bind, &ec_public);
        string(&mut ec_bind, &sid);
        string(&mut ec_bind, &ec_signature);
        ec_bind.push(0);
        for packet in [&session_bind, &sign, &ec_bind] {
            for prefix in 0..=packet.len() {
                fuzz_wire(&packet[..prefix]);
            }
        }
        fuzz_wire(&[]);
        fuzz_wire(&[13, 255, 255, 255, 255]);
        fuzz_wire(&[0; 33]);
        fuzz_wire(&vec![0; MAX_PACKET + 1]);
    }
}
