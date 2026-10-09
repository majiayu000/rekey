//! Signed Profile binding and issuance. The registry remains the only capability store.
use std::collections::BTreeMap;
use std::sync::Arc;

use rekey_domain::action::{ActionTarget, ExactPath, FixedHttpAction, TemplateActionSource};
use rekey_domain::authorization::Principal;
use rekey_domain::capability::{ActionVersionRef, SessionGrant};
use rekey_domain::ids::{SessionId, TenantId};
use rekey_domain::ipc::{self, ProfileGetResponse, ProfileSessionCreatedResponse};
use rekey_domain::profile::AgentProfile;
use rekey_policy::templates::{BuiltinTemplate, ValidatedTemplatePackage, builtin_template};
use rekey_policy::{PolicyError, ValidatedSnapshot};
use rekey_vault::AuthorityError;
use rekey_vault::command::UnlockProof;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use super::BrokerCtx;
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;
use crate::session::{CreateSessionError, ProfileSessionGuard, ProfileSessionScope};

fn invalid() -> BrokerError {
    PolicyError::Invalid.into()
}

fn source(action: &FixedHttpAction) -> Result<&TemplateActionSource, BrokerError> {
    match &action.target {
        ActionTarget::Template { source, .. } => Ok(source),
        ActionTarget::Fixed { .. } => Err(invalid()),
    }
}

/// Pure Profile checks already ran. Only authenticated current Action facts belong here.
pub(super) fn validate_profile_actions(
    snapshot: &ValidatedSnapshot,
    actions: &[FixedHttpAction],
) -> Result<(), BrokerError> {
    validate_profiles(snapshot.profiles(), actions)
}

pub(super) fn validate_profiles(
    profiles: &[AgentProfile],
    actions: &[FixedHttpAction],
) -> Result<(), BrokerError> {
    let mut identities = BTreeMap::new();
    let mut indices = BTreeMap::new();
    for profile in profiles {
        for grant in &profile.grants {
            for capability in &grant.capabilities {
                for reference in &capability.actions {
                    let action = current_action(actions, *reference)?;
                    let source = source(action)?;
                    if source.capability != capability.capability {
                        return Err(invalid());
                    }
                    let binding = if source.signer_id.is_none() && source.template == "github-pat@1"
                    {
                        Some(github_binding(action)?)
                    } else {
                        None
                    };
                    let identity = (
                        binding,
                        action.credential_id,
                        source.template.as_str(),
                        source.digest,
                        source.signer_id,
                    );
                    if identities
                        .insert((profile.principal_id, grant.instance.as_str()), identity)
                        .is_some_and(|old| old != identity)
                    {
                        return Err(invalid());
                    }
                    let key = (
                        profile.principal_id,
                        grant.instance.as_str(),
                        capability.capability.as_str(),
                        source.action_index,
                    );
                    if indices
                        .insert(key, *reference)
                        .is_some_and(|old| old != *reference)
                    {
                        return Err(invalid());
                    }
                }
            }
        }
    }
    Ok(())
}

fn current_action(
    actions: &[FixedHttpAction],
    wanted: ActionVersionRef,
) -> Result<&FixedHttpAction, BrokerError> {
    actions
        .iter()
        .find(|action| {
            action.enabled && action.id == wanted.action_id && action.version == wanted.version
        })
        .ok_or(AuthorityError::PolicyVersionConflict.into())
}

fn same_json<T: serde::Serialize, U: serde::Serialize>(
    left: &T,
    right: &U,
) -> Result<bool, BrokerError> {
    Ok(serde_json::to_value(left).map_err(|_| invalid())?
        == serde_json::to_value(right).map_err(|_| invalid())?)
}

/// Current Actions were authenticated by the Authority and bound by validate_profiles.
/// Signed custom templates use the common executor; only built-in provider semantics
/// require reconstruction of the released declaration and its fixed bindings.
pub(super) fn require_supported_profile(
    profile: &AgentProfile,
    actions: &[FixedHttpAction],
) -> Result<(), BrokerError> {
    let isolated = cfg!(target_os = "macos")
        && profile.isolation == rekey_domain::profile::ProfileIsolation::Seatbelt
        && profile.egress == rekey_domain::profile::ProfileEgress::DenyOther;
    if !isolated
        && (profile.isolation != rekey_domain::profile::ProfileIsolation::None
            || profile.egress != rekey_domain::profile::ProfileEgress::Allow)
    {
        return Err(BrokerError::UnsupportedPlatform);
    }
    for grant in &profile.grants {
        let first_ref = grant.capabilities[0].actions[0];
        let first = current_action(actions, first_ref)?;
        let first_source = source(first)?;
        if first_source.signer_id.is_some() {
            if profile
                .llm_limits
                .iter()
                .any(|limit| limit.instance == grant.instance)
            {
                return Err(BrokerError::Denied("profile LLM limits mismatch"));
            }
            // Installation authenticated the package and sealed its complete Action.
            // A custom name never opts into built-in LLM or gateway behavior.
            continue;
        }
        let is_llm = matches!(
            first_source.template.as_str(),
            "anthropic@1" | "glm@1" | "glm-responses@1" | "openai@1"
        );
        if is_llm
            != profile
                .llm_limits
                .iter()
                .any(|limit| limit.instance == grant.instance)
        {
            return Err(BrokerError::Denied("profile LLM limits mismatch"));
        }
        let mut bindings = BTreeMap::new();
        let package = match first_source.template.as_str() {
            "github-pat@1" => {
                let (owner, repo) = github_binding(first)?;
                bindings.insert("owner".to_owned(), owner.to_owned());
                bindings.insert("repo".to_owned(), repo.to_owned());
                builtin_template(BuiltinTemplate::GitHubPat).map_err(|_| invalid())?
            }
            "generic-bearer@1" => generic_source(first, actions)?,
            "anthropic@1" => builtin_template(BuiltinTemplate::Anthropic).map_err(|_| invalid())?,
            "glm@1" => builtin_template(BuiltinTemplate::Glm).map_err(|_| invalid())?,
            "glm-responses@1" => {
                builtin_template(BuiltinTemplate::GlmResponses).map_err(|_| invalid())?
            }
            "openai@1" => builtin_template(BuiltinTemplate::OpenAi).map_err(|_| invalid())?,
            _ => {
                return Err(BrokerError::Denied(
                    "profile template execution is not available",
                ));
            }
        };
        if package.digest() != first_source.digest {
            return Err(invalid());
        }
        let bound = package.template().bind(&bindings)?;
        for capability in &grant.capabilities {
            for reference in &capability.actions {
                let action = current_action(actions, *reference)?;
                let source = source(action)?;
                let expected = bound.materialize(&capability.capability, source.action_index)?;
                let expected = expected.definition();
                let ActionTarget::Template {
                    target,
                    fixed_headers,
                    body_schema,
                    default_policy,
                    ..
                } = &action.target
                else {
                    return Err(invalid());
                };
                let schema = expected
                    .body_schema
                    .as_ref()
                    .map(|name| {
                        package
                            .schema(name)
                            .map(|schema| schema.definition().clone())
                            .map_err(|_| invalid())
                    })
                    .transpose()?;
                if action.origin != expected.origin
                    || action.method != expected.method
                    || action.auth.header_name != expected.credential.inject.header
                    || action.auth.prefix != expected.credential.inject.prefix
                    || action.native_plugin.is_some()
                    || action.text_stream.is_some()
                    || !same_json(target, &expected.target)?
                    || !same_json(fixed_headers, &expected.fixed_headers)?
                    || !same_json(default_policy, &expected.default_policy)?
                    || body_schema != &schema
                {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(())
}

fn github_binding(action: &FixedHttpAction) -> Result<(&str, &str), BrokerError> {
    let ActionTarget::Template { target, .. } = &action.target else {
        return Err(invalid());
    };
    let mut segments = target.path_pattern().split('/');
    if segments.next() != Some("") || segments.next() != Some("repos") {
        return Err(invalid());
    }
    let owner = segments.next().ok_or_else(invalid)?;
    let repo = segments.next().ok_or_else(invalid)?;
    Ok((owner, repo))
}

fn generic_source(
    first: &FixedHttpAction,
    actions: &[FixedHttpAction],
) -> Result<ValidatedTemplatePackage, BrokerError> {
    let expected_source = source(first)?;
    let mut ordered = BTreeMap::new();
    for action in actions {
        let Ok(candidate) = source(action) else {
            continue;
        };
        if action.credential_id != first.credential_id
            || candidate.template != expected_source.template
            || candidate.digest != expected_source.digest
            || candidate.signer_id != expected_source.signer_id
        {
            continue;
        }
        let ActionTarget::Template { target, .. } = &action.target else {
            unreachable!()
        };
        if candidate.capability != "fixed-actions" || action.origin != first.origin {
            return Err(invalid());
        }
        let value = (action.method, ExactPath::parse(target.path_pattern())?);
        if ordered
            .insert(candidate.action_index, value.clone())
            .is_some_and(|old| old != value)
        {
            return Err(invalid());
        }
    }
    if ordered.keys().copied().ne(0..ordered.len()) {
        return Err(invalid());
    }
    builtin_template(BuiltinTemplate::GenericBearer {
        origin: first.origin.clone(),
        actions: ordered.into_values().collect(),
    })
    .map_err(|_| invalid())
}

impl BrokerCtx {
    async fn active_profile(
        &self,
        name: &str,
    ) -> Result<(Arc<ActivePolicy>, AgentProfile), BrokerError> {
        self.lifecycle.reject_if_not_running()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .ok_or(AuthorityError::PolicyUnavailable)?;
        if active.signer_id().is_none() {
            return Err(AuthorityError::PolicyUnavailable.into());
        }
        if active.is_expired(crate::now_ts()?) {
            return Err(PolicyError::Expired.into());
        }
        let profile = active
            .snapshot()
            .profile(name)
            .cloned()
            .ok_or(BrokerError::Denied("profile unavailable"))?;
        Ok((active, profile))
    }

    pub(crate) async fn profile_get_until(
        &self,
        name: &str,
        #[cfg(feature = "lab")] admission: Option<&crate::oidc_admin::Admission>,
        deadline: Instant,
    ) -> Result<ProfileGetResponse, BrokerError> {
        let _coordinator = self.lifecycle.coordinate_until(deadline).await?;
        let (active, profile) = self.active_profile(name).await?;
        #[cfg(feature = "lab")]
        if admission.is_some_and(|identity| identity.principal != profile.principal_id) {
            return Err(BrokerError::Denied("management principal mismatch"));
        }
        Ok(ProfileGetResponse {
            profile,
            policy_sha256: data_encoding::HEXLOWER.encode(&active.snapshot().digest()),
            expires_at_ms: active.snapshot().expires_at_ms(),
        })
    }

    pub(crate) async fn profile_create_until(
        &self,
        name: &str,
        proof_body: &[u8],
        #[cfg(feature = "lab")] admission: Option<&crate::oidc_admin::Admission>,
        deadline: Instant,
    ) -> Result<(Zeroizing<Vec<u8>>, ProfileSessionGuard), BrokerError> {
        let _coordinator = self.lifecycle.coordinate_until(deadline).await?;
        let (active, profile) = self.active_profile(name).await?;
        if profile.confirm_each_run {
            let (kind, secret) = ipc::parse_proof_body(proof_body)?;
            let secret = rekey_vault::secret::SecretInput::from_slice(secret);
            let proof = match kind {
                ipc::ProofKind::Password => UnlockProof::Password(secret),
                ipc::ProofKind::Recovery => UnlockProof::Recovery(secret),
                ipc::ProofKind::Presence => UnlockProof::Presence(secret),
            };
            authority_until(deadline, self.authority.verify_proof(proof)).await?;
        } else if !proof_body.is_empty() {
            return Err(ipc::FrameError::InvalidField.into());
        }
        #[cfg(feature = "lab")]
        if admission.is_some_and(|identity| identity.principal != profile.principal_id) {
            return Err(BrokerError::Denied("management principal mismatch"));
        }
        let actions = authority_until(deadline, self.authority.action_list()).await?;
        // Other Profiles may reference Actions since retired; only this mint's
        // exact signed scope must remain current.
        validate_profiles(std::slice::from_ref(&profile), &actions)?;
        require_supported_profile(&profile, &actions)?;
        let action_timeouts = profile
            .action_refs()
            .map(|reference| {
                current_action(&actions, reference).map(|action| (reference, action.timeout_ms))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let session_id = crate::random_id(SessionId::from_random_bytes)?;
        let vault_id = authority_until(deadline, self.authority.status())
            .await?
            .vault_id;
        let issued_at = crate::now_ts()?;
        let ttl = profile.session.ttl_ms.min(
            active
                .snapshot()
                .expires_at_ms()
                .saturating_sub(issued_at.as_unix_ms()),
        );
        let monotonic_deadline = active.monotonic_deadline().into_std();
        #[cfg(feature = "lab")]
        let (ttl, monotonic_deadline) = admission.map_or((ttl, monotonic_deadline), |identity| {
            (
                ttl.min(
                    identity
                        .expires_at_ms
                        .saturating_sub(issued_at.as_unix_ms()),
                ),
                monotonic_deadline.min(identity.deadline.into_std()),
            )
        });
        let grant = SessionGrant::new(
            session_id,
            Principal {
                tenant_id: TenantId::from_bytes(*vault_id.as_bytes())?,
                principal_id: profile.principal_id,
                session_id,
            },
            profile.action_refs().collect(),
            issued_at,
            ttl,
            profile.session.max_uses,
        )?;
        check_live(self, &active, deadline)?;
        let expires_at_ms = grant.expires_at.as_unix_ms();
        let max_uses = grant.max_uses;
        let (token, guard) = self
            .sessions
            .admit_profile(
                grant,
                action_timeouts,
                ProfileSessionScope::new(profile.clone(), active.snapshot().digest()),
                monotonic_deadline,
            )
            .map_err(|error| match error {
                CreateSessionError::Closed => BrokerError::Authority(AuthorityError::Draining),
                CreateSessionError::Domain(error) => error.into(),
            })?;
        if let Err(error) = self
            .authority
            .commit_audit_before(
                session_audit(rekey_vault::model::event_type::SESSION_CREATED, session_id),
                Some(deadline.into_std()),
            )
            .await
        {
            drop(guard);
            self.request_fault();
            return Err(error.into());
        }
        let prepared = (|| {
            check_live(self, &active, deadline)?;
            if crate::now_ts()?.as_unix_ms() >= expires_at_ms {
                return Err(rekey_domain::DomainError::CapabilityExpired.into());
            }
            #[cfg(feature = "lab")]
            if let (Some(manager), Some(identity)) = (&self.oidc_admin, admission) {
                manager.publish(identity, self, || ())?;
            }
            let gateway = self.gateway.endpoint(&active, &profile, &actions);
            let mut response = ProfileSessionCreatedResponse {
                session: ipc::SessionCreatedResponse {
                    session_id,
                    principal_id: profile.principal_id,
                    capability_token: token.to_string(),
                    expires_at_ms,
                    max_uses,
                },
                profile,
                policy_sha256: data_encoding::HEXLOWER.encode(&active.snapshot().digest()),
                gateway,
            };
            let serialized = serde_json::to_vec(&response)
                .map(Zeroizing::new)
                .map_err(|_| BrokerError::Frame(ipc::FrameError::InvalidField));
            response.session.capability_token.zeroize();
            serialized
        })();
        match prepared {
            Ok(serialized) => Ok((serialized, guard)),
            Err(error) => {
                // Revoke before the audit await, including after the mint deadline.
                drop(guard);
                if let Err(audit_error) = self
                    .authority
                    .commit_audit(session_audit(
                        rekey_vault::model::event_type::SESSION_REVOKED,
                        session_id,
                    ))
                    .await
                {
                    self.request_fault();
                    return Err(audit_error.into());
                }
                Err(error)
            }
        }
    }
}

fn check_live(
    ctx: &BrokerCtx,
    active: &ActivePolicy,
    deadline: Instant,
) -> Result<(), BrokerError> {
    ctx.lifecycle.reject_if_not_running()?;
    if Instant::now() >= deadline {
        return Err(AuthorityError::AuthorityBusy.into());
    }
    if active.is_expired(crate::now_ts()?) {
        return Err(PolicyError::Expired.into());
    }
    Ok(())
}

async fn authority_until<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T, AuthorityError>>,
) -> Result<T, BrokerError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| AuthorityError::AuthorityBusy)?
        .map_err(Into::into)
}

pub(crate) fn session_audit(
    event_type: &'static str,
    session_id: SessionId,
) -> rekey_vault::command::AuditDraft {
    rekey_vault::command::AuditDraft {
        request_id: None,
        session_id: Some(session_id),
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        approval: None,
        request_context: None,
        usage: None,
        event_type,
        outcome: rekey_vault::model::outcome::SUCCESS,
        reason_code: "profile".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

#[cfg(all(test, feature = "lab"))]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId, RequestId};
    use rekey_vault::secret::SecretInput;
    use serde_json::json;
    use std::time::Duration;

    fn proof() -> UnlockProof {
        UnlockProof::Password(SecretInput::from_slice(b"fixture-proof"))
    }
    async fn fixture() -> (
        tempfile::TempDir,
        Arc<BrokerCtx>,
        std::thread::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (dir, ctx, join, terminals) = crate::runtime::tests::oidc_test_ctx().await;
        let credential = ctx
            .authority
            .credential_add(
                rekey_domain::credential::CredentialLabel::new("profile").unwrap(),
                rekey_domain::credential::CredentialKind::OpaqueToken,
                SecretInput::from_slice(b"SYNTHETIC-PROFILE-TEST"),
                proof(),
            )
            .await
            .unwrap();
        let install:ipc::TemplateInstallMeta=serde_json::from_value(json!({"source":{"kind":"generic-bearer","origin":"https://api.example.com","actions":[{"method":"POST","path":"/run"}]},"credential_id":credential.id,"bindings":[{}],"capabilities":["fixed-actions"],"name_prefix":"test","timeout_ms":1000,"request_max_bytes":1024,"allowed_extra_headers":[],"response_max_bytes":1024,"allowed_response_headers":[]})).unwrap();
        let action = ctx
            .authority
            .template_install_before(install, vec![], proof(), RequestId::new_random(), None)
            .await
            .unwrap()
            .actions
            .remove(0)
            .action;
        let principal = PrincipalId::new_random();
        let rule = PolicyRuleId::new_random();
        let signer = PolicySignerId::new_random();
        let snapshot = json!({"format_version":8,"version":1,"expires_at_ms":4_102_444_800_000_i64,"approvers":[],"workload_identities":[],"connections":[], "ssh_keys":[], "profiles":[{"name":"test","principal_id":principal,"grants":[{"instance":"one","capabilities":[{"rule":"template-default","capability":"fixed-actions","actions":[{"action_id":action.id,"version":action.version}]}]}],"session":{"ttl_ms":60000,"max_uses":4},"confirm_each_run":false,"isolation":"none","egress":"allow","llm_limits":[]}],"bindings":[{"action_id":action.id,"version":action.version,"resource":{"type":"test","id":"one"},"parameter_schema_id":"any/v1","parameter_schema":{}}],"rules":[{"id":rule,"effect":"permit","principal_id":principal,"action_id":action.id,"version":action.version,"resource":{"type":"test","id":"one"},"parameters":{"kind":"any_validated"}}]});
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let trust = rekey_policy::ValidatedPolicyTrust::from_parts(
            signer,
            rekey_policy::PolicyVerificationKey::from_bytes(
                rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519,
                key.public_key().as_ref(),
            )
            .unwrap(),
        );
        let mut envelope = json!({"format_version":1,"signer_id":signer,"snapshot":snapshot});
        let mut message = b"RKPOLICY\0\x01".to_vec();
        message.extend(serde_jcs::to_vec(&envelope).unwrap());
        envelope["signature"] = data_encoding::BASE64URL_NOPAD
            .encode(key.sign(&message).as_ref())
            .into();
        let verified = rekey_policy::parse_and_verify_policy_bundle(
            &serde_json::to_vec(&envelope).unwrap(),
            &trust,
            crate::now_ts().unwrap(),
        )
        .unwrap();
        *ctx.policy.write().await = Some(Arc::new(
            ActivePolicy::activate_bundle(verified, crate::now_ts().unwrap()).unwrap(),
        ));
        (dir, ctx, join, terminals)
    }
    async fn finish(
        ctx: Arc<BrokerCtx>,
        join: std::thread::JoinHandle<()>,
        terminals: tokio::task::JoinHandle<()>,
    ) {
        ctx.authority.shutdown(Some(proof())).await.unwrap();
        drop(ctx);
        terminals.await.unwrap();
        join.join().unwrap();
    }

    #[tokio::test]
    async fn profile_cancel_during_real_sqlite_audit_revokes_before_database_unblocks() {
        let (dir, ctx, join, terminals) = fixture().await;
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let worker = ctx.clone();
        let mint = tokio::spawn(async move {
            worker
                .profile_create_until(
                    "test",
                    &[],
                    #[cfg(feature = "lab")]
                    None,
                    Instant::now() + Duration::from_secs(3),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while ctx.sessions.active_count(crate::now_ts().unwrap()) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        mint.abort();
        assert!(matches!(mint.await,Err(error) if error.is_cancelled()));
        assert_eq!(
            ctx.sessions.active_count(crate::now_ts().unwrap()),
            0,
            "RAII revoke must precede the blocked audit"
        );
        db.execute_batch("COMMIT").unwrap();
        ctx.authority.status().await.unwrap();
        assert_eq!(ctx.sessions.active_count(crate::now_ts().unwrap()), 0);
        finish(ctx, join, terminals).await;
    }

    #[tokio::test]
    async fn profile_expiry_after_created_audit_commits_revocation() {
        for fail_revocation in [false, true] {
            let (dir, ctx, join, terminals) = fixture().await;
            let db =
                rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                    .unwrap();
            if fail_revocation {
                db.execute_batch("CREATE TRIGGER fail_profile_revoke BEFORE INSERT ON audit_events WHEN NEW.event_type='session.revoked' BEGIN SELECT RAISE(ABORT,'synthetic'); END").unwrap();
            }
            db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let worker = ctx.clone();
            let mint = tokio::spawn(async move {
                worker
                    .profile_create_until(
                        "test",
                        &[],
                        #[cfg(feature = "lab")]
                        None,
                        Instant::now() + Duration::from_secs(3),
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while ctx.sessions.active_count(crate::now_ts().unwrap()) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            // Latch expiry while creation is blocked, without a timing race.
            assert!(
                ctx.policy
                    .read()
                    .await
                    .as_ref()
                    .unwrap()
                    .is_expired(rekey_domain::Timestamp::from_unix_ms(4_102_444_800_000))
            );
            db.execute_batch("COMMIT").unwrap();
            let result = mint.await.unwrap();
            assert_eq!(ctx.sessions.active_count(crate::now_ts().unwrap()), 0);
            let events: Vec<String> = db
                .prepare("SELECT event_type FROM audit_events WHERE event_type IN ('session.created','session.revoked') ORDER BY rowid")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            if fail_revocation {
                assert!(matches!(
                    result,
                    Err(BrokerError::Authority(AuthorityError::AuditCommitFailed))
                ));
                assert_eq!(events, ["session.created"]);
                ctx.authority.shutdown(None).await.unwrap();
                drop(ctx);
                terminals.await.unwrap();
                join.join().unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(BrokerError::Policy(PolicyError::Expired))
                ));
                assert_eq!(events, ["session.created", "session.revoked"]);
                finish(ctx, join, terminals).await;
            }
        }
    }

    #[tokio::test]
    async fn profile_audit_failure_never_leaves_a_live_session() {
        let (dir, ctx, join, terminals) = fixture().await;
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&dir.path().join("state")))
                .unwrap();
        db.execute_batch("CREATE TRIGGER fail_profile_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='session.created' BEGIN SELECT RAISE(ABORT,'synthetic'); END").unwrap();
        let result = ctx
            .profile_create_until(
                "test",
                &[],
                #[cfg(feature = "lab")]
                None,
                Instant::now() + Duration::from_secs(2),
            )
            .await;
        assert!(matches!(
            result,
            Err(BrokerError::Authority(AuthorityError::AuditCommitFailed))
        ));
        assert_eq!(ctx.sessions.active_count(crate::now_ts().unwrap()), 0);
        ctx.authority.shutdown(None).await.unwrap();
        drop(ctx);
        terminals.await.unwrap();
        join.join().unwrap();
    }

    #[tokio::test]
    async fn profile_mapping_identity_is_scoped_to_principal() {
        let (_dir, ctx, join, terminals) = fixture().await;
        let mut actions = ctx.authority.action_list().await.unwrap();
        let (_, original) = ctx.active_profile("test").await.unwrap();
        let mut action = actions[0].clone();
        action.id = rekey_domain::ids::ActionId::new_random();
        action.credential_id = rekey_domain::ids::CredentialId::new_random();
        let mut other = original.clone();
        other.name = "other".into();
        other.principal_id = PrincipalId::new_random();
        other.grants[0].capabilities[0].actions =
            vec![rekey_domain::capability::ActionVersionRef {
                action_id: action.id,
                version: action.version,
            }];
        actions.push(action);
        validate_profiles(&[original.clone(), other.clone()], &actions).unwrap();
        other.principal_id = original.principal_id;
        assert!(validate_profiles(&[original, other], &actions).is_err());
        finish(ctx, join, terminals).await;
    }

    #[tokio::test]
    async fn profile_builtin_name_is_insufficient_without_digest_and_request_match() {
        let (_dir, ctx, join, terminals) = fixture().await;
        let actions = ctx.authority.action_list().await.unwrap();
        let (_, profile) = ctx.active_profile("test").await.unwrap();
        require_supported_profile(&profile, &actions).unwrap();
        for field in ["digest", "header", "target", "unknown"] {
            let mut altered = actions.clone();
            let ActionTarget::Template { source, target, .. } = &mut altered[0].target else {
                panic!()
            };
            match field {
                "digest" => source.digest = [9; 32],
                "header" => {
                    altered[0].auth.prefix =
                        rekey_domain::action::HeaderPrefix::new("Token ").unwrap()
                }
                "target" => {
                    *target =
                        serde_json::from_value(json!({"path":"/changed","params":{},"query":{}}))
                            .unwrap()
                }
                "unknown" => source.template = "team@1".into(),
                _ => unreachable!(),
            }
            assert!(
                require_supported_profile(&profile, &altered).is_err(),
                "{field}"
            );
        }
        finish(ctx, join, terminals).await;
    }
}
