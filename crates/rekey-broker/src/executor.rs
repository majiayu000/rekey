//! Fixed HTTP action execution pipeline. Step order is a contract
//! (spec §14) and must not be rearranged: capability, pinning, validation,
//! started-audit, credential, upstream, sealing, filtering, finished-audit,
//! accounting, cleanup.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use rekey_connector::{BuiltInConnector, resolve_builtin};
use rekey_domain::DomainError;
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_domain::authorization::Decision;
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::PolicySignerId;
use rekey_domain::ids::RequestId;
use rekey_domain::template::{RenderedTarget, TemplateValues};
use rekey_vault::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::active_policy::ActivePolicy;
use crate::audit::{
    ExecutionAuditContext, StartedAuditGuard, TerminalAuditTracker, connector_event,
    execution_blocked,
};
use crate::error::BrokerError;
use crate::github_app::{GitHubAppCredential, GitHubEffect, GitHubError};
use crate::lifecycle::{BrokerPhase, Lifecycle};
use crate::session::{ExecutionPermit, SessionRegistry};
use crate::upstream::{UpstreamRequest, UpstreamTransport, outbound_headers_are_valid};

mod approval;
#[cfg(feature = "lab")]
pub(crate) mod aws_source;
#[cfg(feature = "lab")]
pub(crate) mod azure_source;
mod deadline;
#[cfg(feature = "lab")]
pub(crate) mod gcp_source;
mod github_run;
#[cfg(feature = "lab")]
pub(crate) mod onepassword_source;
#[cfg(test)]
use github_run::{github_post_effect_error, github_without_token_error};
mod http;
#[cfg(feature = "lab")]
pub(crate) mod keycloak;
mod llm;
mod local;
pub(crate) use local::LocalExecuteRequest;
mod llm_stream;
mod sealing;
pub(crate) mod text_stream;
#[cfg(feature = "lab")]
pub(crate) mod vault_dynamic;
#[cfg(feature = "lab")]
mod vault_dynamic_run;
#[cfg(feature = "lab")]
pub(crate) mod vault_source;
#[cfg(any(feature = "lab", test))]
use http::build_upstream;
pub(crate) use http::upstream_failure_is_indeterminate;
use http::{filter_response_headers, reason_static, response_metadata_fits, validate_request};
pub(crate) use sealing::contains_secret;
#[cfg(test)]
use sealing::percent_encode;
pub(crate) use sealing::sealing_needles;
use sealing::{fixed_header_sealing_needles, headers_contain_secret};
#[cfg(feature = "lab")]
use vault_dynamic::{VaultDynamicError, VaultDynamicPrepared, VaultDynamicProfile};
#[cfg(feature = "lab")]
use vault_source::{VaultKvError, VaultKvProfile, VaultPrepared};

/// Exercises the production response-sealing implementation from the external
/// fuzz package without exposing its secret-derived needles.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_response_sealing(
    secret: &[u8],
    auth_value: &[u8],
    response: &[u8],
    as_header: bool,
) -> bool {
    let needles = sealing_needles(secret, auth_value);
    if as_header {
        headers_contain_secret(
            &vec![(
                "x-fuzz".to_owned(),
                String::from_utf8_lossy(response).into(),
            )]
            .into(),
            &needles,
        )
    } else {
        contains_secret(response, &needles)
    }
}

/// Exercises the response-header-name branch independently from header values.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_response_header_name_sealing(
    secret: &[u8],
    auth_value: &[u8],
    response_name: &[u8],
) -> bool {
    let needles = sealing_needles(secret, auth_value);
    headers_contain_secret(
        &vec![(
            String::from_utf8_lossy(response_name).into(),
            "unrelated-header-value".to_owned(),
        )]
        .into(),
        &needles,
    )
}

pub struct ExecuteRequest {
    pub request_id: RequestId,
    pub capability_token: String,
    pub action: ActionVersionRef,
    pub content_type: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub params: TemplateValues,
    pub query: TemplateValues,
    pub body: Vec<u8>,
    pub approval_grants: Vec<String>,
    pub local_approval_request_id: Option<rekey_domain::ids::ApprovalRequestId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PolicyIdentity {
    signer_id: Option<PolicySignerId>,
    version: u64,
    policy_digest: [u8; 32],
    bundle_digest: Option<[u8; 32]>,
}

impl PolicyIdentity {
    fn of(policy: &ActivePolicy) -> Self {
        Self {
            signer_id: policy.signer_id(),
            version: policy.snapshot().version().get(),
            policy_digest: policy.snapshot().digest(),
            bundle_digest: policy.bundle_digest(),
        }
    }
}

pub struct ExecuteOutcome {
    pub stream_status: Option<rekey_domain::ipc::TextStreamStatus>,
    pub upstream_status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Runtime-owned after `execution.started` commits. Dropping a client response
/// receiver cannot drop this object; the ExecutionSupervisor owns `run`.
pub struct AdmittedExecution {
    executor: Arc<ActionExecutor>,
    request: ExecuteRequest,
    action: FixedHttpAction,
    target: RenderedTarget,
    llm: Option<llm::LlmExecution>,
    effect_deadline: Instant,
    started: StartedAuditGuard,
    _permit: Option<ExecutionPermit>,
}

pub struct ActionExecutor {
    pub(crate) local_calls: Arc<crate::runtime::local_calls::LocalCalls>,
    pub(crate) oauth: Arc<crate::oauth::Manager>,
    authority: AuthorityHandle,
    sessions: Arc<SessionRegistry>,
    pub(crate) transport: Arc<dyn UpstreamTransport>,
    lifecycle: Arc<Lifecycle>,
    terminals: Arc<TerminalAuditTracker>,
    policy: Arc<RwLock<Option<Arc<ActivePolicy>>>>,
}

const EFFECT_NOT_STARTED: u8 = 0;
pub(crate) const EFFECT_ORDINARY_HTTP: u8 = 1;
const EFFECT_REVOCABLE_CONNECTOR: u8 = 2;
#[cfg(feature = "lab")]
const EFFECT_READ_ONLY_HTTP: u8 = 3;

impl ActionExecutor {
    pub(crate) fn new(
        authority: AuthorityHandle,
        sessions: Arc<SessionRegistry>,
        transport: Arc<dyn UpstreamTransport>,
        lifecycle: Arc<Lifecycle>,
        terminals: Arc<TerminalAuditTracker>,
        policy: Arc<RwLock<Option<Arc<ActivePolicy>>>>,
    ) -> Self {
        Self {
            local_calls: Arc::new(crate::runtime::local_calls::LocalCalls::default()),
            oauth: Arc::new(crate::oauth::Manager::default()),
            authority,
            sessions,
            transport,
            lifecycle,
            terminals,
            policy,
        }
    }

    fn refuse_unless_running(&self) -> Result<(), BrokerError> {
        match self.lifecycle.phase() {
            BrokerPhase::Running => Ok(()),
            BrokerPhase::Locked => Err(BrokerError::Authority(AuthorityError::Locked)),
            BrokerPhase::Draining | BrokerPhase::ShuttingDown => {
                Err(BrokerError::Authority(AuthorityError::Draining))
            }
        }
    }

    pub async fn admit(
        self: &Arc<Self>,
        request: ExecuteRequest,
    ) -> Result<AdmittedExecution, BrokerError> {
        self.admit_for_response(request, Some(false)).await
    }

    pub(crate) async fn admit_stream(
        self: &Arc<Self>,
        request: ExecuteRequest,
    ) -> Result<AdmittedExecution, BrokerError> {
        self.admit_for_response(request, Some(true)).await
    }

    /// HTTP delegates body shape selection to the same canonicalization as IPC.
    pub(crate) async fn admit_http(
        self: &Arc<Self>,
        request: ExecuteRequest,
    ) -> Result<AdmittedExecution, BrokerError> {
        self.admit_for_response(request, None).await
    }

    async fn admit_for_response(
        self: &Arc<Self>,
        mut request: ExecuteRequest,
        stream: Option<bool>,
    ) -> Result<AdmittedExecution, BrokerError> {
        let admission_started = Instant::now();
        self.refuse_unless_running()?;
        // Step 3: capability authentication reserves one use and one
        // concurrency slot; the permit releases the slot on every path.
        let mut permit =
            self.sessions
                .acquire(&request.capability_token, request.action, crate::now_ts()?)?;
        let effect_deadline = admission_started + Duration::from_millis(permit.timeout_ms as u64);
        self.refuse_unless_running()?;
        let mut evaluated = self
            .evaluate_request(&request, &permit, effect_deadline)
            .await?;
        let expected_stream = evaluated.action.text_stream.is_some()
            || evaluated.llm.as_ref().is_some_and(|llm| llm.streaming);
        if stream.is_none() && evaluated.llm.is_none() {
            return Err(BrokerError::Denied("gateway-profile-required"));
        }
        if stream.is_some_and(|stream| stream != expected_stream) {
            self.audit_denial(effect_deadline, &evaluated.ctx, "stream-operation-mismatch")
                .await?;
            return Err(BrokerError::Denied("stream-operation-mismatch"));
        }
        if let Some(mut body) = evaluated.effective_body.take() {
            zeroize::Zeroize::zeroize(&mut request.body);
            request.body = std::mem::take(&mut *body);
        }
        if request.local_approval_request_id.is_some() && !request.approval_grants.is_empty() {
            return Err(BrokerError::Denied("approval-kinds-conflict"));
        }
        let is_local = matches!(
            evaluated.approval_context.as_ref().map(|c| &c.approver),
            Some(rekey_domain::authorization::ApproverSpec::LocalPresence {})
        );
        if request.local_approval_request_id.is_some() && !is_local {
            return Err(BrokerError::Denied("approval-local-not-required"));
        }
        if is_local {
            if !request.approval_grants.is_empty() {
                return Err(BrokerError::Denied("approval-kinds-conflict"));
            }
            let local = self
                .ensure_local_approval(
                    &evaluated,
                    &mut permit,
                    request.local_approval_request_id,
                    false,
                    effect_deadline,
                )
                .await?;
            if request.local_approval_request_id.is_none()
                || local.state == rekey_domain::ipc::LocalApprovalState::Pending
            {
                return Err(BrokerError::ApprovalRequired(
                    rekey_domain::ipc::ApprovalRequired {
                        challenge_id: local.challenge.approval_request_id,
                        expires_at_ms: local.challenge.max_expires_at_ms,
                    },
                ));
            }
            let started = self
                .commit_local_started(
                    &evaluated,
                    &permit,
                    local.challenge.approval_request_id,
                    effect_deadline,
                )
                .await?;
            return Ok(AdmittedExecution {
                executor: Arc::clone(self),
                request,
                action: evaluated.action,
                target: evaluated.target,
                llm: evaluated.llm,
                effect_deadline,
                started,
                _permit: Some(permit),
            });
        }
        let (accepted, mut approval_deadline) = match &evaluated.decision {
            Decision::Allow { .. } if request.approval_grants.is_empty() => (Vec::new(), None),
            Decision::Allow { .. } => {
                deadline::await_authority(
                    effect_deadline,
                    self.authority
                        .append_audit(execution_blocked(&evaluated.ctx, "approval-not-required")),
                )
                .await?;
                return Err(BrokerError::Denied("approval-not-required"));
            }
            Decision::RequireApproval { .. } => {
                let (accepted, deadline, wall_deadline_ms) = self
                    .verify_and_reserve_approvals(
                        &evaluated,
                        &request.approval_grants,
                        effect_deadline,
                    )
                    .await?;
                (accepted, Some((deadline, wall_deadline_ms)))
            }
            Decision::Deny { .. } => return Err(BrokerError::Denied("policy-evaluation-failed")),
        };

        let policy_cap = evaluated.snapshot.monotonic_deadline().into_std();
        let wall_cap = evaluated.snapshot.snapshot().expires_at_ms();
        approval_deadline = Some(
            approval_deadline.map_or((policy_cap, wall_cap), |(mono, wall)| {
                (mono.min(policy_cap), wall.min(wall_cap))
            }),
        );

        // Step 6: this final point linearizes with drain. Earlier Running
        // checks are advisory; no drain may transition between this re-check
        // and transfer of durable started/terminal ownership.
        let admission_deadline = approval_deadline
            .map(|(approval_deadline, _)| effect_deadline.min(approval_deadline))
            .unwrap_or(effect_deadline);
        let started = tokio::time::timeout_at(
            tokio::time::Instant::from_std(admission_deadline),
            commit_started_with_usage(
                &self.lifecycle,
                &self.terminals,
                &self.policy,
                Some(PolicyIdentity::of(&evaluated.snapshot)),
                evaluated.ctx,
                accepted,
                approval_deadline,
                evaluated.llm.as_ref().map(|llm| llm.usage.clone()),
                Some(admission_deadline),
            ),
        )
        .await
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))??;
        Ok(AdmittedExecution {
            executor: Arc::clone(self),
            request,
            effect_deadline,
            action: evaluated.action,
            target: evaluated.target,
            llm: evaluated.llm,
            started,
            _permit: Some(permit),
        })
    }

    async fn lifecycle_policy(
        &self,
        effect_deadline: Instant,
    ) -> Result<Option<Arc<ActivePolicy>>, BrokerError> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(effect_deadline),
            self.policy.read(),
        )
        .await
        .map(|guard| guard.clone())
        .map_err(|_| BrokerError::Upstream("upstream-timeout"))
    }

    #[cfg(test)]
    async fn run_started(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
        stream: Option<&text_stream::TextStreamSender>,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let target = match &action.target {
            ActionTarget::Fixed { path } => RenderedTarget {
                path: path.clone(),
                params: Default::default(),
                query: Default::default(),
            },
            ActionTarget::Template { target, .. } => {
                target.render(&request.params, &request.query)?
            }
        };
        self.run_started_owned(
            started,
            request,
            action,
            &target,
            effect_deadline,
            effect_kind,
            &AtomicBool::new(false),
            stream,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_started_owned(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        target: &RenderedTarget,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
        cleanup_owned: &AtomicBool,
        stream: Option<&text_stream::TextStreamSender>,
        llm: Option<&llm::LlmExecution>,
        permit: Option<&ExecutionPermit>,
    ) -> Result<ExecuteOutcome, BrokerError> {
        if (action.text_stream.is_some() || llm.is_some_and(|llm| llm.streaming))
            != stream.is_some()
        {
            started
                .blocked_until(effect_deadline, "stream-operation-mismatch")
                .await?;
            return Err(BrokerError::Denied("stream-operation-mismatch"));
        }
        let oauth_connection =
            if let Some(rekey_domain::audit::RequestAuditContext::Connection(context)) =
                &started.context().request_context
            {
                let policy = self.policy.read().await;
                policy.as_ref().and_then(|p| {
                    p.snapshot()
                        .connections()
                        .iter()
                        .find(|c| c.name == context.connection && c.oauth.is_some())
                        .map(|c| (c.clone(), Arc::clone(p)))
                })
            } else {
                None
            };
        let bearer = if let Some((connection, active)) = oauth_connection {
            if connection.credential_id != action.credential_id
                || started
                    .context()
                    .authorization
                    .as_ref()
                    .is_none_or(|a| a.policy_digest != active.snapshot().digest())
            {
                return Err(BrokerError::Denied("policy-changed"));
            }
            match tokio::time::timeout_at(
                effect_deadline.into(),
                self.oauth.bearer(
                    &connection,
                    &active,
                    &self.authority,
                    self.transport.as_ref(),
                    effect_deadline,
                    &self.lifecycle,
                    started,
                    effect_kind,
                ),
            )
            .await
            {
                Ok(Ok(bearer)) => Some(bearer),
                result => {
                    if !started.is_completed() {
                        if effect_kind.load(Ordering::SeqCst) == EFFECT_ORDINARY_HTTP {
                            started
                                .indeterminate_until(effect_deadline, "oauth-refresh-unavailable")
                                .await?;
                        } else {
                            started
                                .blocked_until(effect_deadline, "oauth-unavailable")
                                .await?;
                        }
                    }
                    return Err(match result {
                        Ok(Err(BrokerError::Upstream(reason)))
                            if started.remote_effect_started() =>
                        {
                            BrokerError::UpstreamUnconfirmed(reason)
                        }
                        // A definitive provider rejection asks for fresh
                        // authorization, never replay of the consumed grant.
                        // Authority persistence failures have a different
                        // variant and must still use the unconfirmed arm.
                        Ok(Err(error @ BrokerError::LocalCall("NEEDS_REAUTH", _, _))) => error,
                        Ok(Err(_)) if started.remote_effect_started() => {
                            BrokerError::UpstreamUnconfirmed("oauth-refresh-unavailable")
                        }
                        Ok(Err(error)) => error,
                        _ if started.remote_effect_started() => {
                            BrokerError::UpstreamUnconfirmed("oauth-refresh-timeout")
                        }
                        _ => BrokerError::Upstream("oauth-refresh-timeout"),
                    });
                }
            }
        } else {
            None
        };
        // Steps 7-8: credential eligibility and preparation (single owner).
        let prepared = if bearer.is_some() {
            None
        } else {
            Some(
                match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(effect_deadline),
                    self.authority.prepare_execution_credential(
                        action.credential_id,
                        request.request_id,
                        action.id,
                        action.version,
                        effect_deadline,
                    ),
                )
                .await
                {
                    Ok(Ok(prepared)) => prepared,
                    Ok(Err(err)) => {
                        started
                            .blocked_until(effect_deadline, prepare_block_reason(&err))
                            .await?;
                        return Err(BrokerError::Authority(err));
                    }
                    Err(_) => {
                        started.submit_blocked("upstream-timeout");
                        return Err(BrokerError::Upstream("upstream-timeout"));
                    }
                },
            )
        };
        let credential_version = bearer
            .as_ref()
            .map(|b| b.version)
            .unwrap_or_else(|| prepared.as_ref().expect("prepared credential").version());
        let credential_kind = prepared
            .as_ref()
            .map(|p| p.kind())
            .unwrap_or(rekey_domain::credential::CredentialKind::OpaqueToken);
        if stream.is_some()
            && credential_kind != rekey_domain::credential::CredentialKind::OpaqueToken
        {
            drop(prepared);
            started
                .blocked_until(effect_deadline, "stream-credential-kind")
                .await?;
            return Err(BrokerError::Denied("stream-credential-kind"));
        }
        // A signed Connection explicitly authorizes this fixed HTTP request,
        // including PAT-backed GitHub writes formerly reserved for App Actions.
        let local_http = matches!(
            started.context().request_context,
            Some(rekey_domain::audit::RequestAuditContext::Connection(_))
        );
        let selection = if local_http
            && credential_kind == rekey_domain::credential::CredentialKind::OpaqueToken
        {
            Ok(BuiltInConnector::FixedHttpHeaderV1)
        } else if matches!(action.target, ActionTarget::Template { .. }) {
            if credential_kind != rekey_domain::credential::CredentialKind::OpaqueToken {
                drop(prepared);
                started
                    .blocked_until(effect_deadline, "template-credential-kind")
                    .await?;
                return Err(BrokerError::Denied("template-credential-kind"));
            }
            Ok(BuiltInConnector::FixedHttpHeaderV1)
        } else {
            resolve_builtin(credential_kind, action)
        };
        let connector = match selection {
            Ok(connector) => connector,
            Err(_) => {
                drop(prepared);
                let reason = match credential_kind {
                    #[cfg(feature = "lab")]
                    rekey_domain::credential::CredentialKind::GcpSecretManagerSource => {
                        gcp_source::GcpSourceError::InvalidCredential.reason()
                    }
                    #[cfg(feature = "lab")]
                    rekey_domain::credential::CredentialKind::AzureKeyVaultSource => {
                        azure_source::AzureSourceError::InvalidCredential.reason()
                    }
                    #[cfg(feature = "lab")]
                    rekey_domain::credential::CredentialKind::OnePasswordConnectSource => {
                        onepassword_source::OnePasswordSourceError::InvalidCredential.reason()
                    }
                    #[cfg(feature = "lab")]
                    rekey_domain::credential::CredentialKind::AwsSecretsManagerSource => {
                        aws_source::AwsSourceError::InvalidCredential.reason()
                    }
                    #[cfg(feature = "lab")]
                    rekey_domain::credential::CredentialKind::VaultKvV2Source => {
                        VaultKvError::InvalidCredential.reason()
                    }
                    #[cfg(feature = "lab")]
                    rekey_domain::credential::CredentialKind::VaultDynamicSource => {
                        VaultDynamicError::InvalidCredential.reason()
                    }
                    _ => GitHubError::InvalidCredential.reason(),
                };
                started.blocked_until(effect_deadline, reason).await?;
                return Err(BrokerError::Denied(reason));
            }
        };

        #[cfg(not(feature = "lab"))]
        let _ = cleanup_owned;
        // Step 9: execute the selected compile-time connector. Registry
        // selection performs no IO and never receives credential bytes.
        let prepared = if let Some(bearer) = bearer {
            prepare_fixed_header(action, request, target, &bearer.token).map(|mut prepared| {
                if let PreparedExecution::Opaque { needles, .. } = &mut prepared {
                    needles.extend(bearer.needles);
                }
                prepared
            })
        } else {
            prepared
                .expect("prepared credential")
                .consume(|secret| match connector {
                    BuiltInConnector::FixedHttpHeaderV1 => {
                        prepare_fixed_header(action, request, target, secret)
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::MacosKeychainSourceV1 => {
                        prepare_fixed_header(action, request, target, secret)
                    }
                    BuiltInConnector::GitHubAppInstallationV1 => {
                        let profile = GitHubAppCredential::parse_profile(secret);
                        Ok(PreparedExecution::GitHub(GitHubPrepared {
                            credential_version,
                            needles: profile
                                .as_ref()
                                .map(|profile| sealing_needles(secret, profile.private_key_bytes()))
                                .unwrap_or_default(),
                            profile,
                        }))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::KeycloakTokenExchangeV1 => {
                        let profile = keycloak::KeycloakProfile::parse_profile(secret);
                        Ok(PreparedExecution::Keycloak(keycloak::KeycloakPrepared {
                            credential_version,
                            profile,
                        }))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::GcpSecretManagerSourceV1 => {
                        let profile = gcp_source::GcpSourceProfile::parse_profile(secret);
                        Ok(PreparedExecution::Gcp(gcp_source::GcpPrepared {
                            credential_version,
                            needles: profile
                                .as_ref()
                                .map(|profile| profile.bootstrap_needles(secret))
                                .unwrap_or_default(),
                            profile,
                        }))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::AzureKeyVaultSourceV1 => {
                        let profile = azure_source::AzureSourceProfile::parse_profile(secret);
                        Ok(PreparedExecution::Azure(azure_source::AzurePrepared {
                            credential_version,
                            needles: profile
                                .as_ref()
                                .map(|profile| profile.bootstrap_needles(secret))
                                .unwrap_or_default(),
                            profile,
                        }))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::OnePasswordConnectSourceV1 => {
                        let profile =
                            onepassword_source::OnePasswordSourceProfile::parse_profile(secret);
                        Ok(PreparedExecution::OnePassword(
                            onepassword_source::OnePasswordPrepared {
                                credential_version,
                                needles: profile
                                    .as_ref()
                                    .map(|profile| profile.bootstrap_needles(secret))
                                    .unwrap_or_default(),
                                profile,
                            },
                        ))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::AwsSecretsManagerSourceV1 => {
                        let profile = aws_source::AwsSourceProfile::parse_profile(secret);
                        Ok(PreparedExecution::Aws(aws_source::AwsPrepared {
                            credential_version,
                            needles: profile
                                .as_ref()
                                .map(|profile| profile.bootstrap_needles(secret))
                                .unwrap_or_default(),
                            profile,
                        }))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::VaultKvV2SourceV1 => {
                        let profile = VaultKvProfile::parse_profile(secret);
                        Ok(PreparedExecution::Vault(VaultPrepared {
                            credential_version,
                            needles: profile
                                .as_ref()
                                .map(|profile| profile.bootstrap_needles(secret))
                                .unwrap_or_default(),
                            profile,
                        }))
                    }
                    #[cfg(feature = "lab")]
                    BuiltInConnector::VaultDynamicSourceV1 => {
                        let profile = VaultDynamicProfile::parse_profile(secret);
                        Ok(PreparedExecution::VaultDynamic(VaultDynamicPrepared {
                            credential_version,
                            needles: profile
                                .as_ref()
                                .map(|profile| sealing_needles(secret, profile.token()))
                                .unwrap_or_default(),
                            profile,
                        }))
                    }
                })
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                if effect_kind.load(Ordering::SeqCst) == EFFECT_ORDINARY_HTTP {
                    started.indeterminate_until(effect_deadline, reason).await?;
                } else {
                    started.blocked_until(effect_deadline, reason).await?;
                }
                return Err(BrokerError::Denied(reason));
            }
        };

        #[cfg(feature = "lab")]
        if let PreparedExecution::Keycloak(prepared) = prepared {
            return self
                .run_keycloak(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await;
        }
        if let PreparedExecution::GitHub(prepared) = prepared {
            return self
                .run_github(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await;
        }
        #[cfg(feature = "lab")]
        if let PreparedExecution::VaultDynamic(prepared) = prepared {
            return self
                .run_vault_dynamic(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await;
        }
        #[cfg(feature = "lab")]
        if matches!(&prepared, PreparedExecution::Vault(vault) if vault.profile.as_ref().is_ok_and(|profile| profile.is_approle()))
        {
            let PreparedExecution::Vault(prepared) = prepared else {
                unreachable!()
            };
            return self
                .run_vault_approle(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                    cleanup_owned,
                )
                .await;
        }
        #[cfg(feature = "lab")]
        let prepared = match prepared {
            PreparedExecution::Gcp(prepared) => {
                self.resolve_gcp_source(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await?
            }
            PreparedExecution::Azure(prepared) => {
                self.resolve_azure_source(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await?
            }
            PreparedExecution::OnePassword(prepared) => {
                self.resolve_onepassword_source(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await?
            }
            PreparedExecution::Aws(prepared) => {
                self.resolve_aws_source(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await?
            }
            PreparedExecution::Vault(prepared) => {
                self.resolve_vault_source(
                    started,
                    request,
                    action,
                    prepared,
                    effect_deadline,
                    effect_kind,
                )
                .await?
            }
            other => other,
        };
        let PreparedExecution::Opaque {
            upstream: mut upstream_request,
            needles,
        } = prepared
        else {
            unreachable!("credential execution variant was matched above")
        };

        if stream.is_some() && action.text_stream.is_some() {
            #[cfg(feature = "lab")]
            let plugin_messages =
                match anthropic_plugin_messages(action, &request.body, effect_deadline).await {
                    Ok(body) => body,
                    Err(err) => {
                        started
                            .blocked_until(effect_deadline, "native-plugin-rejected")
                            .await?;
                        return Err(err);
                    }
                };
            #[cfg(feature = "lab")]
            let messages = plugin_messages
                .as_deref()
                .unwrap_or(request.body.as_slice());
            #[cfg(not(feature = "lab"))]
            let messages = request.body.as_slice();
            text_stream::configure(action, messages, &mut upstream_request)?;
        }
        if llm.is_some_and(|llm| llm.streaming) {
            upstream_request
                .headers
                .push(("accept-encoding".to_owned(), "identity".to_owned()));
        }
        // Steps 10-11: fixed HTTPS send with bounded response. Credential
        // preparation consumes the same action deadline as DNS and HTTP.
        upstream_request.timeout = effect_deadline.saturating_duration_since(Instant::now());
        if upstream_request.timeout.is_zero() {
            if started.remote_effect_started() {
                started.submit_indeterminate("upstream-timeout");
                return Err(BrokerError::UpstreamUnconfirmed("upstream-timeout"));
            }
            started.submit_blocked("upstream-timeout");
            return Err(BrokerError::Upstream("upstream-timeout"));
        }
        if !outbound_headers_are_valid(&upstream_request) {
            if effect_kind.load(Ordering::SeqCst) == EFFECT_ORDINARY_HTTP {
                started
                    .indeterminate_until(effect_deadline, "invalid-upstream-header")
                    .await?;
            } else {
                started
                    .blocked_until(effect_deadline, "invalid-upstream-header")
                    .await?;
            }
            return Err(BrokerError::Denied("invalid-upstream-header"));
        }
        // A successful OAuth refresh already contacted its provider. Preserve
        // that effect if the target transport rejects before sending anything.
        let prior_remote_effect = started.remote_effect_started();
        let send_started = Instant::now();
        if let Some(sender) = stream {
            let run = async {
                let response = poll_http_while_live(
                    &self.lifecycle,
                    permit,
                    started,
                    effect_kind,
                    effect_deadline,
                    "text-stream-failed",
                    || self.transport.open_stream(upstream_request),
                )
                .await?;
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        if !upstream_failure_is_indeterminate(&error) {
                            started.record_target_no_effect(prior_remote_effect);
                            if !prior_remote_effect {
                                effect_kind.store(EFFECT_NOT_STARTED, Ordering::SeqCst);
                                started
                                    .blocked_until(effect_deadline, "stream-transport")
                                    .await?;
                            }
                        }
                        return Err(BrokerError::Upstream("stream-transport"));
                    }
                };
                if let Some(llm) = llm.filter(|llm| llm.streaming) {
                    if response.status != 200 {
                        let mut response = response;
                        let mut body = Zeroizing::new(Vec::new());
                        let limit = action.response_policy.max_body_bytes as usize;
                        while let Some(chunk) = response
                            .body
                            .next_chunk()
                            .await
                            .map_err(|_| BrokerError::Upstream("stream-transport"))?
                        {
                            if chunk.len() > limit.saturating_sub(body.len()) {
                                return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
                            }
                            body.extend_from_slice(&chunk);
                        }
                        return finish_buffered_response(
                            started,
                            action,
                            crate::upstream::UpstreamResponse {
                                status: response.status,
                                headers: response.headers,
                                body,
                            },
                            &needles,
                            effect_deadline,
                            credential_version,
                            Some(llm),
                            send_started.elapsed().as_millis() as i64,
                        )
                        .await;
                    }
                    let mut complete = llm_stream::run(
                        response,
                        needles,
                        action.response_policy.max_body_bytes as usize,
                        sender,
                        llm.protocol,
                    )
                    .await?;
                    started.record_profile_output(complete.output_tokens());
                    started
                        .finished_until(
                            effect_deadline,
                            credential_version,
                            200,
                            send_started.elapsed().as_millis() as i64,
                        )
                        .await?;
                    complete.release(sender).await?;
                    return Ok(ExecuteOutcome {
                        stream_status: Some(complete.status()),
                        upstream_status: 200,
                        headers: Vec::new(),
                        body: Vec::new(),
                    });
                }
                let status = text_stream::run(
                    response,
                    needles,
                    action.response_policy.max_body_bytes as usize,
                    sender,
                )
                .await?;
                if status == rekey_domain::ipc::TextStreamStatus::Completed {
                    started
                        .finished_until(
                            effect_deadline,
                            credential_version,
                            200,
                            send_started.elapsed().as_millis() as i64,
                        )
                        .await?;
                } else {
                    started
                        .indeterminate_until(effect_deadline, "incomplete-stream")
                        .await?;
                }
                Ok(ExecuteOutcome {
                    stream_status: Some(status),
                    upstream_status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            };
            let result =
                tokio::time::timeout_at(tokio::time::Instant::from_std(effect_deadline), run)
                    .await
                    .unwrap_or(Err(BrokerError::Upstream("upstream-timeout")));
            let result = match result {
                Err(BrokerError::Upstream(reason)) if started.remote_effect_started() => {
                    Err(BrokerError::UpstreamUnconfirmed(reason))
                }
                other => other,
            };
            if result.is_err() && !started.is_completed() {
                // Terminal tracker owns this audit even if the effect deadline
                // expired or the socket disappeared.
                started.submit_indeterminate("text-stream-failed");
            }
            return result;
        }
        let response = poll_http_while_live(
            &self.lifecycle,
            permit,
            started,
            effect_kind,
            effect_deadline,
            "upstream-timeout",
            || self.transport.send(upstream_request),
        )
        .await?;
        let latency_ms = send_started.elapsed().as_millis() as i64;
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                let reason = match &err {
                    crate::upstream::UpstreamError::Blocked(r) => r,
                    crate::upstream::UpstreamError::ResponseTooLarge => "response-too-large",
                    crate::upstream::UpstreamError::Timeout => "upstream-timeout",
                    crate::upstream::UpstreamError::Transport => "upstream-transport",
                };
                let indeterminate = prior_remote_effect || upstream_failure_is_indeterminate(&err);
                if indeterminate {
                    started.indeterminate_until(effect_deadline, reason).await?;
                } else {
                    started.record_target_no_effect(prior_remote_effect);
                    effect_kind.store(EFFECT_NOT_STARTED, Ordering::SeqCst);
                    started.blocked_until(effect_deadline, reason).await?;
                }
                return Err(match err {
                    crate::upstream::UpstreamError::ResponseTooLarge => {
                        BrokerError::Domain(DomainError::ResponseTooLarge)
                    }
                    _ if indeterminate => BrokerError::UpstreamUnconfirmed(reason_static(reason)),
                    _ => BrokerError::Upstream(reason_static(reason)),
                });
            }
        };

        finish_buffered_response(
            started,
            action,
            response,
            &needles,
            effect_deadline,
            credential_version,
            llm,
            latency_ms,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_buffered_response(
    started: &mut StartedAuditGuard,
    action: &FixedHttpAction,
    mut response: crate::upstream::UpstreamResponse,
    needles: &[Zeroizing<Vec<u8>>],
    effect_deadline: Instant,
    credential_version: u64,
    llm: Option<&llm::LlmExecution>,
    latency_ms: i64,
) -> Result<ExecuteOutcome, BrokerError> {
    // Step 12: secret sealing over the buffered body and every header
    // the upstream sent (name and value), before any allowlist copy.
    if contains_secret(&response.body, needles)
        || headers_contain_secret(&response.headers, needles)
    {
        started
            .indeterminate_until(effect_deadline, "reflected-secret")
            .await?;
        return Err(BrokerError::ResponseSecurityViolation);
    }

    // Step 13: response header filtering (allowlist only).
    let headers = filter_response_headers(action, &response.headers);
    if !response_metadata_fits(response.status, &headers, response.body.len()) {
        started
            .indeterminate_until(effect_deadline, "response-metadata-too-large")
            .await?;
        return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
    }

    if let Some(llm) = llm {
        let measured = if (200..300).contains(&response.status) {
            rekey_policy::profile_llm_output_tokens(llm.protocol, &response.body)
        } else {
            None
        };
        started.record_profile_output(measured);
    }

    // Step 14: ExecutionFinished must commit; upstream success without
    // evidence is not success.
    started
        .finished_until(
            effect_deadline,
            credential_version,
            response.status,
            latency_ms,
        )
        .await?;
    let body = std::mem::take(&mut *response.body);

    // Steps 15-16 (accounting + cleanup) happen in Drop of permit and secrets.
    Ok(ExecuteOutcome {
        stream_status: None,
        upstream_status: response.status,
        headers,
        body,
    })
}

fn prepare_fixed_header(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    target: &RenderedTarget,
    secret: &[u8],
) -> Result<PreparedExecution, &'static str> {
    let mut auth_value = Zeroizing::new(Vec::with_capacity(
        action.auth.prefix.as_str().len() + secret.len(),
    ));
    auth_value.extend_from_slice(action.auth.prefix.as_str().as_bytes());
    if action.auth.prefix.as_str() == "Basic " && action.origin.as_str() == "https://github.com" {
        let mut basic = Zeroizing::new(b"x-access-token:".to_vec());
        basic.extend_from_slice(secret);
        let encoded = Zeroizing::new(data_encoding::BASE64.encode(&basic));
        auth_value.extend_from_slice(encoded.as_bytes());
    } else {
        auth_value.extend_from_slice(secret);
    }
    let needles =
        fixed_header_sealing_needles(secret, &auth_value, action.auth.prefix.as_str().as_bytes());
    Ok(PreparedExecution::Opaque {
        upstream: http::build_rendered_upstream(action, request, target, auth_value),
        needles,
    })
}

enum PreparedExecution {
    Opaque {
        upstream: UpstreamRequest,
        needles: Vec<Zeroizing<Vec<u8>>>,
    },
    GitHub(GitHubPrepared),
    #[cfg(feature = "lab")]
    Vault(VaultPrepared),
    #[cfg(feature = "lab")]
    Gcp(gcp_source::GcpPrepared),
    #[cfg(feature = "lab")]
    Aws(aws_source::AwsPrepared),
    #[cfg(feature = "lab")]
    Azure(azure_source::AzurePrepared),
    #[cfg(feature = "lab")]
    OnePassword(onepassword_source::OnePasswordPrepared),
    #[cfg(feature = "lab")]
    VaultDynamic(VaultDynamicPrepared),
    #[cfg(feature = "lab")]
    Keycloak(keycloak::KeycloakPrepared),
}

struct GitHubPrepared {
    credential_version: u64,
    profile: Result<GitHubAppCredential, GitHubError>,
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl AdmittedExecution {
    pub(crate) fn raw_stream(&self) -> bool {
        self.llm.as_ref().is_some_and(|llm| llm.streaming)
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.effect_deadline
    }

    pub async fn run(self) -> Result<ExecuteOutcome, BrokerError> {
        self.run_inner(None).await
    }

    pub(crate) async fn run_stream(
        self,
        sender: &text_stream::TextStreamSender,
    ) -> Result<ExecuteOutcome, BrokerError> {
        self.run_inner(Some(sender)).await
    }

    async fn run_inner(
        mut self,
        stream: Option<&text_stream::TextStreamSender>,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let cancel = self.executor.lifecycle.subscribe_cancel();
        if *cancel.borrow() {
            self.started.submit_blocked("abandoned");
            return Err(BrokerError::Authority(AuthorityError::Draining));
        }

        let executor = Arc::clone(&self.executor);
        let effect_kind = AtomicU8::new(EFFECT_NOT_STARTED);
        let cleanup_owned = AtomicBool::new(false);
        let mut cancelled_after_ordinary_effect = false;
        {
            let run = executor.run_started_owned(
                &mut self.started,
                &self.request,
                &self.action,
                &self.target,
                self.effect_deadline,
                &effect_kind,
                &cleanup_owned,
                stream,
                self.llm.as_ref(),
                self._permit.as_ref(),
            );
            tokio::pin!(run);
            tokio::select! {
                biased;
                _ = wait_for_cancel(cancel) => {
                    if cleanup_owned.load(Ordering::SeqCst) { return run.await; }
                    match effect_kind.load(Ordering::SeqCst) {
                        EFFECT_REVOCABLE_CONNECTOR => return run.await,
                        EFFECT_ORDINARY_HTTP => cancelled_after_ordinary_effect = true,
                        _ => {}
                    }
                }
                result = &mut run => return result,
            }
        }
        if !self.started.is_completed() {
            if cancelled_after_ordinary_effect {
                self.started
                    .submit_indeterminate("cancelled-after-remote-effect");
            } else {
                self.started.submit_blocked("abandoned");
            }
        }
        Err(BrokerError::Authority(AuthorityError::Draining))
    }
}

/// Transfer ordinary HTTP work once under its live permit. Already handed-off
/// work retains the existing natural-drain grace; private-key runners need a
/// separate per-poll and owned-backend cancellation contract.
async fn poll_http_while_live<T, F: Future<Output = T>>(
    lifecycle: &Lifecycle,
    permit: Option<&ExecutionPermit>,
    started: &mut StartedAuditGuard,
    effect_kind: &AtomicU8,
    effect_deadline: Instant,
    timeout_reason: &'static str,
    make_future: impl FnOnce() -> F,
) -> Result<T, BrokerError> {
    let run = async {
        let owner = match permit {
            Some(permit) => tokio::select! {
                biased;
                _ = permit.wait_revoked() => return Err(DomainError::InvalidCapability.into()),
                owner = lifecycle.coordinate_until(effect_deadline.into()) => owner?,
            },
            None => {
                // A drain owns the coordinator while waiting for Connection
                // terminals. Reject an already closed gate before joining that
                // wait; the protected handoff below still rechecks admission.
                if !lifecycle.try_begin_remote_effect() {
                    return Err(BrokerError::Authority(AuthorityError::Draining));
                }
                lifecycle.coordinate_until(effect_deadline.into()).await?
            }
        };
        let mut make_future = Some(make_future);
        let mut future: Option<Pin<Box<F>>> = None;
        // Return the backend's first Poll as a value so no lock survives
        // Pending. The future is constructed and first-polled in one live gate.
        let first = poll_fn(|cx| {
            let mut handoff = || {
                if !lifecycle.try_begin_remote_effect() {
                    return Err(BrokerError::Authority(AuthorityError::Draining));
                }
                lifecycle.reject_if_not_running()?;
                started.mark_remote_effect_started();
                effect_kind.store(EFFECT_ORDINARY_HTTP, Ordering::SeqCst);
                future = Some(Box::pin(make_future.take().expect("single HTTP handoff")()));
                Ok(future
                    .as_mut()
                    .expect("constructed HTTP future")
                    .as_mut()
                    .poll(cx))
            };
            Poll::Ready(match permit {
                Some(permit) => match crate::now_ts() {
                    Ok(now) => permit.with_live_handoff(now, effect_deadline, handoff)?,
                    Err(error) => Err(error),
                },
                None => handoff(), // signed Connections and direct executor unit harnesses
            })
        })
        .await;
        drop(owner);
        match first? {
            Poll::Ready(value) => Ok(value),
            Poll::Pending => Ok(future.expect("HTTP ownership transferred").await),
        }
    };
    // Keep the original action deadline independent of a concrete transport's
    // relative timeout, which may start only after coordinator queueing.
    let result = tokio::select! {
        biased;
        _ = tokio::time::sleep_until(effect_deadline.into()) => {
            Err(BrokerError::Upstream("upstream-timeout"))
        }
        result = run => result,
    };
    let result = match result {
        Err(BrokerError::Upstream(reason)) if started.remote_effect_started() => {
            Err(BrokerError::UpstreamUnconfirmed(reason))
        }
        other => other,
    };
    if result.is_err() && !started.is_completed() {
        let timed_out = matches!(
            &result,
            Err(BrokerError::Upstream("upstream-timeout")
                | BrokerError::UpstreamUnconfirmed("upstream-timeout"))
        );
        // The guard also remembers a completed OAuth refresh before this
        // target's handoff. A rejected handoff cannot erase that prior effect.
        if started.remote_effect_started() {
            started.submit_indeterminate(if timed_out {
                timeout_reason
            } else {
                "cancelled-after-remote-effect"
            });
        } else {
            started.submit_blocked(if timed_out {
                "upstream-timeout"
            } else {
                "remote-effect-admission-closed"
            });
        }
    }
    result
}

pub(crate) async fn wait_for_cancel(mut cancel: tokio::sync::watch::Receiver<bool>) {
    while !*cancel.borrow_and_update() {
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(feature = "lab")]
async fn anthropic_plugin_messages(
    action: &FixedHttpAction,
    body: &[u8],
    deadline: Instant,
) -> Result<Option<Vec<u8>>, BrokerError> {
    let Some(plugin) = action.native_plugin.as_ref() else {
        return Ok(None);
    };
    if plugin.protocol != rekey_domain::action::ANTHROPIC_MESSAGES_PROTOCOL {
        return Ok(None);
    }
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        crate::github_issue_plugin::normalize_anthropic(plugin, body, deadline)
            .await
            .map(Some)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (plugin, body, deadline);
        Err(BrokerError::Denied("github-plugin-platform-unsupported"))
    }
}

pub(crate) async fn try_begin_remote_effect(
    lifecycle: &Lifecycle,
    started: &mut StartedAuditGuard,
    effect_deadline: Instant,
) -> Result<(), BrokerError> {
    if lifecycle.try_begin_remote_effect() {
        return Ok(());
    }
    if started.remote_effect_started() {
        started
            .indeterminate_until(effect_deadline, "remote-effect-admission-closed")
            .await?;
    } else {
        started
            .blocked_until(effect_deadline, "remote-effect-admission-closed")
            .await?;
    }
    Err(BrokerError::Authority(AuthorityError::Draining))
}

#[cfg(test)]
async fn commit_started_while_running(
    lifecycle: &Lifecycle,
    terminals: &TerminalAuditTracker,
    policy: &RwLock<Option<Arc<ActivePolicy>>>,
    expected_policy: Option<PolicyIdentity>,
    ctx: ExecutionAuditContext,
    preceding: Vec<rekey_vault::command::AuditDraft>,
    approval_deadline: Option<(Instant, i64)>,
) -> Result<StartedAuditGuard, BrokerError> {
    commit_started_with_usage(
        lifecycle,
        terminals,
        policy,
        expected_policy,
        ctx,
        preceding,
        approval_deadline,
        None,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn commit_started_with_usage(
    lifecycle: &Lifecycle,
    terminals: &TerminalAuditTracker,
    policy: &RwLock<Option<Arc<ActivePolicy>>>,
    expected_policy: Option<PolicyIdentity>,
    ctx: ExecutionAuditContext,
    preceding: Vec<rekey_vault::command::AuditDraft>,
    approval_deadline: Option<(Instant, i64)>,
    usage: Option<rekey_vault::command::ProfileUsageStart>,
    request_deadline: Option<Instant>,
) -> Result<StartedAuditGuard, BrokerError> {
    let _coordinator = match lifecycle.try_coordinate() {
        Ok(owner) => owner,
        Err(_) if lifecycle.phase() == BrokerPhase::Running => {
            // Production admission wraps this wait in its absolute deadline.
            // Another valid request's durable started commit is temporary
            // contention, not evidence that the Authority queue is full.
            lifecycle.coordinate().await
        }
        Err(_) => return Err(BrokerError::Authority(AuthorityError::Draining)),
    };
    lifecycle.reject_if_not_running()?;
    check_started_policy(policy, expected_policy, terminals, &ctx).await?;
    let (approval_not_after, mut wall_not_after_ms) = approval_deadline.unzip();
    let mut not_after = match (request_deadline, approval_not_after) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    if expected_policy.is_some() {
        let active = policy.read().await;
        let active = active
            .as_ref()
            .ok_or(BrokerError::Denied("policy-changed"))?;
        if active.is_expired(crate::now_ts()?) {
            return Err(BrokerError::Denied("policy-expired"));
        }
        let cap = active.monotonic_deadline().into_std();
        not_after = Some(not_after.map_or(cap, |deadline| deadline.min(cap)));
        let expires = active.snapshot().expires_at_ms();
        wall_not_after_ms = Some(wall_not_after_ms.map_or(expires, |wall| wall.min(expires)));
    }
    commit_evaluated_started(
        terminals,
        ctx,
        preceding,
        not_after,
        wall_not_after_ms,
        usage,
    )
    .await
}

async fn commit_evaluated_started(
    terminals: &TerminalAuditTracker,
    ctx: ExecutionAuditContext,
    preceding: Vec<rekey_vault::command::AuditDraft>,
    not_after: Option<Instant>,
    wall_not_after_ms: Option<i64>,
    usage: Option<rekey_vault::command::ProfileUsageStart>,
) -> Result<StartedAuditGuard, BrokerError> {
    if let Some(usage) = usage {
        terminals
            .commit_profile_started(
                ctx,
                preceding,
                usage,
                not_after.ok_or(BrokerError::Denied("profile-deadline-missing"))?,
                wall_not_after_ms,
            )
            .await?
            .ok_or(BrokerError::Denied("profile-budget-exceeded"))
    } else {
        terminals
            .commit_started(ctx, preceding, not_after, wall_not_after_ms)
            .await
            .map_err(BrokerError::Authority)
    }
}

async fn check_started_policy(
    policy: &RwLock<Option<Arc<ActivePolicy>>>,
    expected_policy: Option<PolicyIdentity>,
    terminals: &TerminalAuditTracker,
    ctx: &ExecutionAuditContext,
) -> Result<(), BrokerError> {
    let current_policy = policy.read().await;
    if current_policy.as_deref().map(PolicyIdentity::of) != expected_policy {
        drop(current_policy);
        terminals
            .commit(execution_blocked(ctx, "policy-changed"))
            .await
            .map_err(BrokerError::Authority)?;
        return Err(BrokerError::Denied("policy-changed"));
    }
    drop(current_policy);
    Ok(())
}

fn prepare_block_reason(err: &AuthorityError) -> &'static str {
    match err {
        AuthorityError::Locked => "locked",
        AuthorityError::Draining => "draining",
        AuthorityError::Faulted => "faulted",
        AuthorityError::CredentialRevoked => "credential-revoked",
        AuthorityError::CryptoFailure => "crypto-failure",
        _ => "credential-unavailable",
    }
}

#[cfg(test)]
mod tests;

#[cfg(not(feature = "lab"))]
impl ActionExecutor {
    pub(crate) async fn lease_journal_status(
        &self,
    ) -> Result<rekey_domain::ipc::LeaseJournalStatus, BrokerError> {
        let counts = self.authority.lease_recovery_batch().await?.counts;
        Ok(rekey_domain::ipc::LeaseJournalStatus {
            verified: counts.verified,
            pending: counts.pending,
            unknown: counts.unknown,
            complete: counts.complete,
        })
    }
    pub(crate) async fn recover_vault_leases(
        &self,
        _perform: bool,
    ) -> Result<rekey_domain::ipc::LeaseRecoverySummary, BrokerError> {
        let batch = deadline::await_authority(
            Instant::now() + Duration::from_secs(8),
            self.authority.lease_recovery_batch(),
        )
        .await?;
        if let Some(error) = batch.unavailable {
            return Err(error.into());
        }
        let counts = batch.counts;
        Ok(rekey_domain::ipc::LeaseRecoverySummary {
            performed: false,
            journal: rekey_domain::ipc::LeaseJournalStatus {
                verified: counts.verified,
                pending: counts.pending,
                unknown: counts.unknown,
                complete: counts.complete,
            },
            deferred: counts.pending,
            leases: Vec::new(),
        })
    }
}
