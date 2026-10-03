//! Profile-only provider classification. No caller-selected endpoint or budget.
use rekey_domain::action::{ActionTarget, FixedHttpAction};
use rekey_policy::ProfileLlmProtocol;
use rekey_policy::templates::{BuiltinTemplate, builtin_template};
use rekey_vault::command::ProfileUsageStart;

use crate::error::BrokerError;
use crate::session::ProfileActionScope;

pub(super) struct LlmExecution {
    pub protocol: ProfileLlmProtocol,
    pub streaming: bool,
    pub usage: ProfileUsageStart,
}

pub(super) fn protocol(
    action: &FixedHttpAction,
    scope: &ProfileActionScope,
) -> Result<Option<ProfileLlmProtocol>, BrokerError> {
    let ActionTarget::Template {
        target,
        fixed_headers,
        body_schema,
        source,
        ..
    } = &action.target
    else {
        return Err(BrokerError::Denied("profile-template-required"));
    };
    if source.capability != scope.capability {
        return Err(BrokerError::Denied("profile-action-mismatch"));
    }
    if source.signer_id.is_some() {
        return if scope.llm_limits.is_some() {
            Err(BrokerError::Denied("profile-llm-source-unsupported"))
        } else {
            Ok(None)
        };
    }
    let builtin = match source.template.as_str() {
        "anthropic@1" => BuiltinTemplate::Anthropic,
        "glm@1" => BuiltinTemplate::Glm,
        "openai@1" => BuiltinTemplate::OpenAi,
        other => {
            if scope.llm_limits.is_some()
                || other.starts_with("anthropic@")
                || other.starts_with("glm@")
                || other.starts_with("openai@")
            {
                return Err(BrokerError::Denied("profile-llm-source-unsupported"));
            }
            return Ok(None);
        }
    };
    let package = builtin_template(builtin)
        .map_err(|_| BrokerError::Denied("profile-llm-source-unsupported"))?;
    let definition = package.template().definition();
    let declared = definition
        .capabilities
        .iter()
        .find(|capability| capability.id == source.capability)
        .and_then(|capability| capability.actions.get(source.action_index))
        .ok_or(BrokerError::Denied("profile-llm-source-unsupported"))?;
    if source.digest != package.digest()
        || scope
            .llm_limits
            .as_ref()
            .is_none_or(|limit| limit.instance != scope.instance_slug)
        || action.origin != definition.origin
        || action.method != declared.method
        || action.auth.header_name != definition.credential.inject.header
        || action.auth.prefix != definition.credential.inject.prefix
        || target.path_pattern() != declared.path
        || !target.params().is_empty()
        || target.query() != &declared.query
        || fixed_headers != &definition.fixed_headers
        || body_schema.is_some()
        || action.text_stream.is_some()
        || action.native_plugin.is_some()
    {
        return Err(BrokerError::Denied("profile-llm-source-unsupported"));
    }
    use ProfileLlmProtocol::*;
    let protocol = match (source.template.as_str(), source.capability.as_str()) {
        ("anthropic@1" | "glm@1", "messages") => AnthropicMessages,
        ("anthropic@1", "count-tokens") => CountTokens,
        ("openai@1", "chat-completions") => OpenAiChat,
        ("openai@1", "responses") => OpenAiResponses,
        ("openai@1", "embeddings") => Embeddings,
        ("anthropic@1" | "openai@1", "models") => Models,
        _ => return Err(BrokerError::Denied("profile-llm-source-unsupported")),
    };
    Ok(Some(protocol))
}

#[cfg(test)]
mod tests {
    use super::super::{ActionExecutor, ExecuteRequest};
    use super::*;
    use crate::{
        active_policy::ActivePolicy,
        runtime::BrokerCtx,
        session::{ProfileSessionGuard, ProfileSessionScope},
        testing::FakeUpstreamTransport,
        upstream::UpstreamResponse,
    };
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
    use rekey_domain::{
        action::{ActionName, HeaderCredentialUse, RequestPolicy, ResponsePolicy},
        authorization::Principal,
        capability::{ActionVersionRef, SessionGrant},
        credential::{CredentialKind, CredentialLabel},
        ids::{ApprovalId, ApproverId, PolicyRuleId, PrincipalId, RequestId, SessionId, TenantId},
        ipc::LocalApprovalReview,
        profile::AgentProfile,
    };
    use rekey_vault::{
        command::{ActionDefinition, UnlockProof},
        model::UsageTotals,
        secret::SecretInput,
    };
    use serde_json::{Value, json};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    struct Fixture {
        dir: tempfile::TempDir,
        ctx: Arc<BrokerCtx>,
        executor: Arc<ActionExecutor>,
        fake: Arc<FakeUpstreamTransport>,
        worker: std::thread::JoinHandle<()>,
        terminal: tokio::task::JoinHandle<()>,
        profile: AgentProfile,
        action: FixedHttpAction,
        digest: [u8; 32],
        key: Ed25519KeyPair,
        approver: ApproverId,
        unsigned_snapshot: Value,
    }
    fn proof() -> UnlockProof {
        UnlockProof::Password(SecretInput::from_slice(b"fixture-proof"))
    }
    impl Fixture {
        async fn new(provider: BuiltinTemplate, capability: &str, mode: &str, daily: u64) -> Self {
            let (dir, ctx, worker, terminal) = crate::runtime::tests::oidc_test_ctx().await;
            let fake = Arc::new(FakeUpstreamTransport::new());
            let executor = Arc::new(ActionExecutor::new(
                ctx.authority.clone(),
                ctx.sessions.clone(),
                fake.clone(),
                ctx.lifecycle.clone(),
                ctx.executor.terminals.clone(),
                ctx.executor.policy.clone(),
            ));
            let credential = ctx
                .authority
                .credential_add(
                    CredentialLabel::new("synthetic-llm").unwrap(),
                    CredentialKind::OpaqueToken,
                    SecretInput::from_slice(b"synthetic-private-upstream-value"),
                    proof(),
                )
                .await
                .unwrap();
            let package = builtin_template(provider).unwrap();
            let material = package
                .template()
                .bind(&Default::default())
                .unwrap()
                .materialize(capability, 0)
                .unwrap();
            let m = material.definition();
            let target=serde_json::from_value(json!({"kind":"template","target":m.target,"fixed_headers":m.fixed_headers,"body_schema":null,
                "source":{"template":m.template,"capability":m.capability,"action_index":0,"digest":package.digest(),"signer_id":null},"default_policy":{"rule":"allow"}})).unwrap();
            let registered = ctx
                .authority
                .action_upsert(
                    None,
                    ActionDefinition {
                        native_plugin: None,
                        text_stream: None,
                        name: ActionName::new("synthetic-llm").unwrap(),
                        credential_id: credential.id,
                        origin: m.origin.clone(),
                        method: m.method,
                        target,
                        auth: HeaderCredentialUse::new(
                            m.credential.inject.header.clone(),
                            m.credential.inject.prefix.clone(),
                        )
                        .unwrap(),
                        timeout_ms: 5000,
                        request_policy: RequestPolicy {
                            max_body_bytes: 4096,
                            allowed_extra_headers: Default::default(),
                        },
                        response_policy: ResponsePolicy {
                            max_body_bytes: 4096,
                            allowed_headers: Default::default(),
                        },
                    },
                    proof(),
                )
                .await
                .unwrap();
            let action = ctx
                .authority
                .action_get(registered.id, registered.version)
                .await
                .unwrap()
                .action;
            let principal = PrincipalId::new_random();
            let llm_limits = if m.template == "generic-bearer@1" {
                json!([])
            } else {
                json!([{"instance":"provider","models":["allowed"],"max_output_tokens_per_request":20,"max_requests_per_day":10,"max_output_tokens_per_day":daily}])
            };
            let profile:AgentProfile=serde_json::from_value(json!({"name":"synthetic-profile","principal_id":principal,
                "grants":[{"instance":"provider","capabilities":[{"rule":"template-default","capability":capability,"actions":[{"action_id":action.id,"version":action.version}]}]}],
                "session":{"ttl_ms":60000,"max_uses":100},"confirm_each_run":false,"isolation":"none","egress":"allow",
                "llm_limits":llm_limits})).unwrap();
            let key = Ed25519KeyPair::from_pkcs8(
                Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
            let approver = ApproverId::new_random();
            let public = HEXLOWER.encode(key.public_key().as_ref());
            let mut rule = json!({"id":PolicyRuleId::new_random(),"effect":"permit","principal_id":principal,"action_id":action.id,"version":action.version,
                "resource":{"type":"llm","id":action.id},"parameters":{"kind":"any_validated"}});
            let approvers = if mode == "external" {
                json!([{"approver_id":approver,"algorithm":"ed25519","public_key":public}])
            } else {
                json!([])
            };
            if mode != "permit" {
                rule["effect"] = "require-approval".into();
                rule["approval"] = json!({"mode":"one-time","max_uses":1});
                rule["approver"] = if mode == "local" {
                    json!({"kind":"local-presence"})
                } else {
                    json!({"kind":"ed25519","keys":[public],"threshold":1})
                };
            }
            let now = crate::now_ts().unwrap();
            let unsigned_snapshot = json!({
                "format_version":6,"version":1,"expires_at_ms":now.as_unix_ms()+60000,"approvers":approvers,"profiles":[profile],"workload_identities":[],
                "bindings":[{"action_id":action.id,"version":action.version,"resource":{"type":"llm","id":action.id},"parameter_schema_id":"llm/v1","parameter_schema":{}}],"rules":[rule]
            });
            let snapshot = rekey_policy::parse_and_validate_snapshot(
                &serde_json::to_vec(&unsigned_snapshot).unwrap(),
                now,
            )
            .unwrap();
            let digest = snapshot.digest();
            *ctx.executor.policy.write().await =
                Some(Arc::new(ActivePolicy::activate(snapshot, now).unwrap()));
            Self {
                dir,
                ctx,
                executor,
                fake,
                worker,
                terminal,
                profile,
                action,
                digest,
                key,
                approver,
                unsigned_snapshot,
            }
        }
        fn session(&self, max_uses: u32) -> (zeroize::Zeroizing<String>, ProfileSessionGuard) {
            self.session_with_timeout(max_uses, 5000)
        }
        fn session_with_timeout(
            &self,
            max_uses: u32,
            timeout_ms: u32,
        ) -> (zeroize::Zeroizing<String>, ProfileSessionGuard) {
            let id = SessionId::new_random();
            let now = crate::now_ts().unwrap();
            let principal = Principal {
                tenant_id: TenantId::new_random(),
                principal_id: self.profile.principal_id,
                session_id: id,
            };
            let reference = ActionVersionRef {
                action_id: self.action.id,
                version: self.action.version,
            };
            let grant =
                SessionGrant::new(id, principal, vec![reference], now, 60000, max_uses).unwrap();
            // Low-level synthetic scope fixture; production LLM Profile mint remains closed.
            self.ctx
                .sessions
                .admit_profile(
                    grant,
                    vec![(reference, timeout_ms)],
                    ProfileSessionScope::new(self.profile.clone(), self.digest),
                    Instant::now() + Duration::from_secs(60),
                )
                .unwrap()
        }
        fn request(&self, token: &str, body: &[u8]) -> ExecuteRequest {
            ExecuteRequest {
                request_id: RequestId::new_random(),
                capability_token: token.into(),
                action: ActionVersionRef {
                    action_id: self.action.id,
                    version: self.action.version,
                },
                content_type: if body.is_empty() {
                    None
                } else {
                    Some("application/json".into())
                },
                extra_headers: vec![],
                params: Default::default(),
                query: Default::default(),
                body: body.to_vec(),
                approval_grants: vec![],
                local_approval_request_id: None,
            }
        }
        fn response(&self, body: &[u8]) {
            self.fake.push_response(Ok(UpstreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())].into(),
                body: body.to_vec().into(),
            }));
        }
        async fn totals(&self) -> UsageTotals {
            self.ctx
                .authority
                .profile_usage(
                    self.profile.principal_id,
                    "provider".into(),
                    crate::now_ts().unwrap().as_unix_ms() / 86_400_000,
                )
                .await
                .unwrap()
        }
        fn db(&self) -> rusqlite::Connection {
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.dir.path().join("state")))
                .unwrap()
        }
        fn count(&self, event: &str) -> i64 {
            self.db()
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type=?1",
                    [event],
                    |r| r.get(0),
                )
                .unwrap()
        }
        async fn activity(&self) -> Vec<rekey_domain::audit::AuditRecord> {
            self.ctx
                .authority
                .audit_query(rekey_domain::audit::AuditQuery {
                    request_id: None,
                    session_id: None,
                    action_id: Some(self.action.id),
                    credential_id: None,
                    outcome: None,
                    since_ms: None,
                    until_ms: None,
                    snapshot_max_sequence: None,
                    before_sequence: None,
                    limit: 100,
                })
                .await
                .unwrap()
                .events
                .into_iter()
                .filter(|event| event.request_context.is_some())
                .collect()
        }
        async fn finish(self) {
            self.ctx
                .executor
                .terminals
                .wait_idle(Duration::from_secs(5))
                .await
                .unwrap();
            self.ctx.authority.shutdown(Some(proof())).await.unwrap();
            drop(self.executor);
            drop(self.ctx);
            self.terminal.await.unwrap();
            self.worker.join().unwrap();
        }
    }
    const CHAT: &[u8]=br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7}}"#;
    const BODY: &[u8] =
        br#"{"model":"allowed","tools":[{"name":"tool"}],"thinking":{"type":"enabled"}}"#;

    #[tokio::test]
    async fn buffered_providers_bind_effective_body_and_settle_real_cumulative_usage() {
        for (provider, capability, response, field) in [
            (
                BuiltinTemplate::OpenAi,
                "chat-completions",
                CHAT,
                "max_completion_tokens",
            ),
            (
                BuiltinTemplate::OpenAi,
                "responses",
                br#"{"status":"incomplete","usage":{"output_tokens":7}}"#.as_slice(),
                "max_output_tokens",
            ),
            (
                BuiltinTemplate::Anthropic,
                "messages",
                br#"{"type":"message","stop_reason":"max_tokens","usage":{"output_tokens":7}}"#
                    .as_slice(),
                "max_tokens",
            ),
        ] {
            let f = Fixture::new(provider, capability, "permit", 100).await;
            let (token, owner) = f.session(10);
            f.response(response);
            let request = f.request(&token, BODY);
            let id = request.request_id;
            let admitted = f.executor.admit(request).await.unwrap();
            assert_eq!(
                f.totals().await,
                UsageTotals {
                    requests: 1,
                    output_tokens: 0
                }
            );
            assert!(f.fake.take_requests().is_empty());
            let outcome = admitted.run().await.unwrap();
            assert_eq!(outcome.body, response);
            let sent = f.fake.take_requests();
            let sent_body: Value = serde_json::from_slice(&sent[0].body).unwrap();
            assert_eq!(sent_body[field], 20);
            assert_eq!(sent_body["tools"][0]["name"], "tool");
            let snapshot = f.ctx.executor.policy.read().await.clone().unwrap();
            let (_, parameters, _) = snapshot
                .snapshot()
                .canonicalize(
                    &f.action,
                    rekey_policy::ActionRequest {
                        params: &Default::default(),
                        query: &Default::default(),
                        content_type: Some("application/json"),
                        headers: &[],
                        body: &sent[0].body,
                    },
                )
                .unwrap();
            let hash:Vec<u8>=f.db().query_row("SELECT parameter_hash FROM audit_events WHERE request_id=?1 AND event_type='execution.started'",[id.as_bytes().as_slice()],|r|r.get(0)).unwrap();
            assert_eq!(hash, parameters.canonical_hash);
            assert_eq!(
                f.totals().await,
                UsageTotals {
                    requests: 1,
                    output_tokens: 7
                }
            );
            assert_eq!(f.count("execution.finished"), 1);
            let rows = f.activity().await;
            assert_eq!(rows.len(), 2);
            for row in &rows {
                let context = row.request_context.as_ref().unwrap();
                assert_eq!(context.profile_name, f.profile.name);
                assert_eq!(
                    context.policy_sha256,
                    data_encoding::HEXLOWER.encode(&f.digest)
                );
                assert_eq!(context.instance_slug, "provider");
                assert_eq!(context.capability, capability);
                assert_eq!(context.model.as_deref(), Some("allowed"));
                assert_eq!(row.request_id, Some(id));
            }
            assert_eq!(
                rows.iter()
                    .filter_map(|row| row.usage.as_ref())
                    .map(|usage| usage.output_tokens)
                    .sum::<u64>(),
                7
            );
            let audit = serde_json::to_string(&rows).unwrap();
            for secret in [
                token.as_str(),
                "synthetic-private-upstream-value",
                "\"tools\"",
                "\"thinking\"",
            ] {
                assert!(!audit.contains(secret));
            }
            drop(snapshot);
            drop(owner);
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn invalid_model_max_stream_and_background_precede_started_and_upstream() {
        for (capability, bodies) in [
            (
                "chat-completions",
                vec![
                    br#"{"model":"forbidden"}"#.as_slice(),
                    br#"{"model":"allowed","max_tokens":21}"#,
                    br#"{"model":"allowed","n":2}"#,
                    br#"{"model":"allowed","stream":true}"#,
                    br#"{"model":"allowed","max_tokens":1,"max_completion_tokens":1}"#,
                ],
            ),
            (
                "responses",
                vec![br#"{"model":"allowed","background":true}"#.as_slice()],
            ),
        ] {
            let f = Fixture::new(BuiltinTemplate::OpenAi, capability, "permit", 100).await;
            let (token, owner) = f.session(20);
            for body in bodies {
                assert_eq!(
                    f.executor
                        .admit(f.request(&token, body))
                        .await
                        .err()
                        .unwrap()
                        .code(),
                    "REQUEST_DENIED"
                );
            }
            assert_eq!(f.count("execution.started"), 0);
            let rows = f.activity().await;
            assert!(!rows.is_empty());
            for row in &rows {
                let context = row.request_context.as_ref().unwrap();
                assert_eq!(context.profile_name, f.profile.name);
                assert_ne!(context.model.as_deref(), Some("forbidden"));
                if row.reason_code == "invalid-parameters" {
                    assert!(context.model.is_none());
                }
            }
            assert!(!serde_json::to_string(&rows).unwrap().contains("forbidden"));
            assert_eq!(
                f.totals().await,
                UsageTotals {
                    requests: 0,
                    output_tokens: 0
                }
            );
            assert!(f.fake.take_requests().is_empty());
            drop(owner);
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn missing_usage_uses_actual_smaller_bound_and_budget_denial_is_not_a_fault() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 10).await;
        for _ in 0..2 {
            let (token, owner) = f.session(1);
            f.response(b"{}");
            f.executor
                .admit(f.request(&token, br#"{"model":"allowed","max_tokens":5}"#))
                .await
                .unwrap()
                .run()
                .await
                .unwrap();
            drop(owner);
        }
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 2,
                output_tokens: 10
            }
        );
        let (token, owner) = f.session(1);
        assert!(matches!(
            f.executor.admit(f.request(&token, BODY)).await,
            Err(BrokerError::Denied("profile-budget-exceeded"))
        ));
        assert_eq!(f.count("execution.started"), 2);
        assert_eq!(f.fake.take_requests().len(), 2);
        assert!(!f.ctx.executor.terminals.has_failed());
        assert_eq!(f.ctx.authority.status().await.unwrap().state, "unlocked");
        let sources: i64 = f
            .db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE metadata_json LIKE '%indeterminate%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sources, 2);
        let rows = f.activity().await;
        let refused = rows
            .iter()
            .find(|row| row.reason_code == "profile-daily-budget")
            .unwrap();
        assert_eq!(
            refused.request_context.as_ref().unwrap().model.as_deref(),
            Some("allowed")
        );
        assert!(refused.usage.is_none());
        assert_eq!(
            rows.iter()
                .filter_map(|row| row.usage.as_ref())
                .map(|usage| usage.output_tokens)
                .sum::<u64>(),
            10
        );
        drop(owner);
        f.finish().await;
    }
    #[tokio::test]
    async fn dropped_admission_and_cancelled_upstream_each_settle_once() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        let (token, owner) = f.session(10);
        drop(f.executor.admit(f.request(&token, BODY)).await.unwrap());
        f.ctx
            .executor
            .terminals
            .wait_idle(Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 1,
                output_tokens: 20
            }
        );
        let release = f.fake.push_response_gated(Ok(UpstreamResponse {
            status: 200,
            headers: Vec::new().into(),
            body: CHAT.to_vec().into(),
        }));
        let admitted = f.executor.admit(f.request(&token, BODY)).await.unwrap();
        let task = tokio::spawn(admitted.run());
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !f.fake.requests.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.err().unwrap().is_cancelled());
        release.notify_one();
        f.ctx
            .executor
            .terminals
            .wait_idle(Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 2,
                output_tokens: 40
            }
        );
        assert_eq!(f.count("execution.blocked"), 1);
        assert_eq!(f.count("execution.indeterminate"), 1);
        assert_eq!(f.count("execution.finished"), 0);
        drop(owner);
        f.finish().await;
    }
    #[tokio::test]
    async fn non_generation_requests_count_once_with_zero_output() {
        for (provider, capability, body) in [
            (BuiltinTemplate::OpenAi, "models", b"".as_slice()),
            (BuiltinTemplate::OpenAi, "embeddings", BODY),
            (BuiltinTemplate::Anthropic, "count-tokens", BODY),
        ] {
            let f = Fixture::new(provider, capability, "permit", 100).await;
            let (token, owner) = f.session(1);
            f.response(br#"{"usage":{"output_tokens":99999}}"#);
            f.executor
                .admit(f.request(&token, body))
                .await
                .unwrap()
                .run()
                .await
                .unwrap();
            assert_eq!(
                f.totals().await,
                UsageTotals {
                    requests: 1,
                    output_tokens: 0
                }
            );
            drop(owner);
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn local_review_and_retry_share_default_bound_without_early_usage() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "local", 100).await;
        let (token, owner) = f.session(1);
        let required = match f.executor.admit(f.request(&token, BODY)).await {
            Err(BrokerError::ApprovalRequired(required)) => required,
            _ => panic!("expected approval"),
        };
        let (metadata, raw) = f
            .ctx
            .sessions
            .local_review(required.challenge_id, crate::now_ts().unwrap())
            .unwrap();
        let review: LocalApprovalReview = serde_json::from_slice(&raw).unwrap();
        let canonical: Value = serde_json::from_str(review.canonical_request.get()).unwrap();
        assert_eq!(canonical["body"]["max_completion_tokens"], 20);
        assert_eq!(f.totals().await.requests, 0);
        // Seed only the registry decision here; Presence IPC is a separately tested lane.
        f.ctx
            .sessions
            .decide_local(
                required.challenge_id,
                &metadata.review_sha256,
                Some(ApprovalId::new_random()),
                crate::now_ts().unwrap(),
            )
            .unwrap();
        let mut retry = f.request(&token, BODY);
        retry.local_approval_request_id = Some(required.challenge_id);
        f.response(CHAT);
        f.executor.admit(retry).await.unwrap().run().await.unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 1,
                output_tokens: 7
            }
        );
        assert_eq!(f.count("approval.accepted"), 1);
        let rows = f.activity().await;
        let requested = rows
            .iter()
            .find(|row| row.event_type == "approval.requested")
            .unwrap();
        let accepted = rows
            .iter()
            .find(|row| row.event_type == "approval.accepted")
            .unwrap();
        assert_eq!(requested.request_context, accepted.request_context);
        assert_eq!(accepted.reason_code, "local-presence");
        assert_eq!(
            accepted.request_context.as_ref().unwrap().model.as_deref(),
            Some("allowed")
        );
        drop(owner);
        f.finish().await;
    }
    #[tokio::test]
    async fn anthropic_beta_approval_binds_query_and_rejects_modified_declarations() {
        let f = Fixture::new(BuiltinTemplate::Anthropic, "messages", "local", 100).await;
        let (token, owner) = f.session(10);
        let mut request = f.request(&token, BODY);
        request.query.insert("beta".into(), "true".into());
        let permit = f
            .ctx
            .sessions
            .acquire(&token, request.action, crate::now_ts().unwrap())
            .unwrap();
        let scope = permit.profile_scope().unwrap();
        assert_eq!(
            protocol(&f.action, scope).unwrap(),
            Some(ProfileLlmProtocol::AnthropicMessages)
        );
        for query in [
            json!({}),
            json!({"beta":"enum:true,false"}),
            json!({"beta":"enum:true","other":"slug"}),
        ] {
            let mut modified = serde_json::to_value(&f.action).unwrap();
            modified["target"]["target"]["query"] = query;
            let modified = serde_json::from_value(modified).unwrap();
            assert!(protocol(&modified, scope).is_err());
        }
        drop(permit);
        let required = match f.executor.admit(request).await {
            Err(BrokerError::ApprovalRequired(required)) => required,
            _ => panic!("expected approval"),
        };
        let (metadata, raw) = f
            .ctx
            .sessions
            .local_review(required.challenge_id, crate::now_ts().unwrap())
            .unwrap();
        let review: LocalApprovalReview = serde_json::from_slice(&raw).unwrap();
        let canonical: Value = serde_json::from_str(review.canonical_request.get()).unwrap();
        assert_eq!(canonical["target"]["query"], json!({"beta":"true"}));
        assert_eq!(canonical["body"]["max_tokens"], 20);
        assert_eq!(f.totals().await.requests, 0);
        f.ctx
            .sessions
            .decide_local(
                required.challenge_id,
                &metadata.review_sha256,
                Some(ApprovalId::new_random()),
                crate::now_ts().unwrap(),
            )
            .unwrap();
        // A review for the beta URI does not approve the otherwise identical plain URI.
        let mut plain = f.request(&token, BODY);
        plain.local_approval_request_id = Some(required.challenge_id);
        assert!(matches!(
            f.executor.admit(plain).await,
            Err(BrokerError::Denied("approval-tuple-mismatch"))
        ));
        assert!(f.fake.take_requests().is_empty());
        assert_eq!(f.totals().await.requests, 0);
        let mut retry = f.request(&token, BODY);
        retry.query.insert("beta".into(), "true".into());
        retry.local_approval_request_id = Some(required.challenge_id);
        f.response(br#"{"type":"message","stop_reason":"end_turn","usage":{"output_tokens":7}}"#);
        f.executor.admit(retry).await.unwrap().run().await.unwrap();
        let sent = f.fake.take_requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].path, "/v1/messages?beta=true");
        assert_eq!(f.totals().await.output_tokens, 7);
        assert_eq!(f.count("approval.accepted"), 1);
        drop(owner);
        f.finish().await;
    }

    #[tokio::test]
    async fn external_prepare_hash_matches_effective_body_and_signed_retry() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "external", 100).await;
        let (token, owner) = f.session(10);
        let envelope = f
            .executor
            .prepare_approval(f.request(&token, BODY))
            .await
            .unwrap();
        let c = envelope.challenge;
        assert_eq!(f.totals().await.requests, 0);
        let mut grant = json!({"format_version":1,"approval_id":ApprovalId::new_random(),"approval_request_id":c.approval_request_id,"approver_id":f.approver,
            "tenant_id":c.tenant_id,"principal_id":c.principal_id,"session_id":c.session_id,"action_id":c.action_id,"action_version":c.action_version,
            "resource":c.resource,"schema_id":c.schema_id,"parameter_sha256":c.parameter_sha256,"policy_version":c.policy_version,"policy_sha256":c.policy_sha256,
            "policy_rule_id":c.policy_rule_id,"mode":c.mode,"not_before_ms":c.created_at_ms,"expires_at_ms":c.max_expires_at_ms,"max_uses":1});
        let mut bytes = b"RKAPPROVAL\0\x01".to_vec();
        bytes.extend(serde_jcs::to_vec(&grant).unwrap());
        grant["signature"] = BASE64URL_NOPAD.encode(f.key.sign(&bytes).as_ref()).into();
        let mut retry = f.request(&token, BODY);
        retry
            .approval_grants
            .push(serde_json::to_string(&grant).unwrap());
        f.response(CHAT);
        f.executor.admit(retry).await.unwrap().run().await.unwrap();
        assert_eq!(f.totals().await.output_tokens, 7);
        assert_eq!(f.count("approval.accepted"), 1);
        let sent = f.fake.take_requests();
        let snapshot = f.ctx.executor.policy.read().await.clone().unwrap();
        let (_, p, _) = snapshot
            .snapshot()
            .canonicalize(
                &f.action,
                rekey_policy::ActionRequest {
                    params: &Default::default(),
                    query: &Default::default(),
                    content_type: Some("application/json"),
                    headers: &[],
                    body: &sent[0].body,
                },
            )
            .unwrap();
        assert_eq!(HEXLOWER.encode(&p.canonical_hash), c.parameter_sha256);
        drop(snapshot);
        drop(owner);
        f.finish().await;
    }
    #[tokio::test]
    async fn unrecognized_or_modified_sources_and_old_scope_do_not_downgrade() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        let (token, owner) = f.session(10);
        let permit = f
            .ctx
            .sessions
            .acquire(
                &token,
                ActionVersionRef {
                    action_id: f.action.id,
                    version: f.action.version,
                },
                crate::now_ts().unwrap(),
            )
            .unwrap();
        let scope = permit.profile_scope().unwrap();
        for mutation in ["digest", "signer", "version", "path"] {
            let mut action = f.action.clone();
            if let ActionTarget::Template { source, target, .. } = &mut action.target {
                match mutation {
                    "digest" => source.digest = [0; 32],
                    "signer" => {
                        source.signer_id = Some(rekey_domain::ids::PolicySignerId::new_random())
                    }
                    "version" => source.template = "openai@2".into(),
                    _ => {
                        *target =
                            serde_json::from_value(json!({"path":"/wrong","params":{},"query":{}}))
                                .unwrap()
                    }
                }
            }
            assert!(protocol(&action, scope).is_err());
        }
        drop(permit);
        let stale = ProfileSessionScope::new(f.profile.clone(), [0; 32]);
        let id = SessionId::new_random();
        let action = ActionVersionRef {
            action_id: f.action.id,
            version: f.action.version,
        };
        let grant = SessionGrant::new(
            id,
            Principal {
                tenant_id: TenantId::new_random(),
                principal_id: f.profile.principal_id,
                session_id: id,
            },
            vec![action],
            crate::now_ts().unwrap(),
            60000,
            1,
        )
        .unwrap();
        let (stale_token, stale_owner) = f
            .ctx
            .sessions
            .admit_profile(
                grant,
                vec![(action, 5000)],
                stale,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        assert!(matches!(
            f.executor.admit(f.request(&stale_token, BODY)).await,
            Err(BrokerError::Denied("profile-policy-changed"))
        ));
        assert_eq!(f.totals().await.requests, 0);
        drop(stale_owner);
        drop(owner);
        f.finish().await;
    }
    #[tokio::test]
    async fn queued_begin_timeout_rolls_back_before_any_started_or_usage() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        let (token, owner) = f.session_with_timeout(1, 100);
        let db = f.db();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let admission = f.executor.admit(f.request(&token, BODY));
        let release = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            db.execute_batch("COMMIT").unwrap();
        };
        let (result, ()) = tokio::join!(admission, release);
        assert!(result.is_err());
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 0,
                output_tokens: 0
            }
        );
        assert_eq!(f.count("execution.started"), 0);
        assert!(f.fake.take_requests().is_empty());
        assert!(!f.executor.terminals.has_failed());
        assert_eq!(f.ctx.authority.status().await.unwrap().state, "unlocked");
        drop(db);
        drop(owner);
        f.finish().await;
    }

    #[tokio::test]
    async fn cancelling_the_started_receipt_preserves_terminal_ownership() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        let (token, owner) = f.session(1);
        let db = f.db();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            f.executor.admit(f.request(&token, BODY)),
        )
        .await;
        assert!(result.is_err());
        db.execute_batch("COMMIT").unwrap();
        f.executor
            .terminals
            .wait_idle(Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 1,
                output_tokens: 20
            }
        );
        assert_eq!(f.count("execution.started"), 1);
        assert_eq!(f.count("execution.blocked"), 1);
        assert!(f.fake.take_requests().is_empty());
        drop(db);
        drop(owner);
        f.finish().await;
    }

    #[tokio::test]
    async fn terminal_audit_failure_releases_no_success_and_keeps_pending_atomic() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        let (token, owner) = f.session(1);
        let admitted = f.executor.admit(f.request(&token, BODY)).await.unwrap();
        f.db().execute_batch("CREATE TRIGGER fail_llm_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.finished' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
        f.response(CHAT);
        assert!(admitted.run().await.is_err());
        assert!(
            f.executor
                .terminals
                .wait_idle(Duration::from_secs(3))
                .await
                .is_err()
        );
        assert_eq!(f.count("execution.finished"), 0);
        let pending: i64 = f
            .db()
            .query_row(
                "SELECT count(*) FROM profile_usage WHERE settled_at_ms IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
        assert_eq!(f.ctx.authority.status().await.unwrap().state, "faulted");
        drop(owner);
        f.ctx.authority.shutdown(None).await.unwrap();
        drop(f.executor);
        drop(f.ctx);
        f.terminal.await.unwrap();
        f.worker.join().unwrap();
    }

    #[tokio::test]
    async fn malformed_usage_falls_back_and_plain_template_http_is_unchanged() {
        let f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        let (token, owner) = f.session(5);
        for raw in [br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":-1}}"#.as_slice(),br#"{"object":"chat.completion","choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":7,"completion_tokens":0}}"#] {
            f.response(raw);assert_eq!(f.executor.admit(f.request(&token,br#"{"model":"allowed","max_tokens":3}"#)).await.unwrap().run().await.unwrap().body,raw);
        }
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 2,
                output_tokens: 6
            }
        );
        let id = SessionId::new_random();
        let action = ActionVersionRef {
            action_id: f.action.id,
            version: f.action.version,
        };
        let grant = SessionGrant::new(
            id,
            Principal {
                tenant_id: TenantId::new_random(),
                principal_id: f.profile.principal_id,
                session_id: id,
            },
            vec![action],
            crate::now_ts().unwrap(),
            60000,
            1,
        )
        .unwrap();
        let plain = f.ctx.sessions.admit(grant, vec![(action, 5000)]).unwrap();
        f.response(CHAT);
        let raw = br#"{"model":"ordinary-unrestricted","stream":true}"#;
        f.executor
            .admit(f.request(&plain, raw))
            .await
            .unwrap()
            .run()
            .await
            .unwrap();
        let sent = f.fake.take_requests();
        assert_eq!(sent.last().unwrap().body, raw);
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 2,
                output_tokens: 6
            }
        );
        drop(owner);
        f.finish().await;
    }
    #[tokio::test]
    async fn non_llm_profile_retains_plain_http_and_still_checks_scope_policy_hash() {
        let f = Fixture::new(
            BuiltinTemplate::GenericBearer {
                origin: rekey_domain::action::HttpsOrigin::parse("https://api.example.com")
                    .unwrap(),
                actions: vec![(
                    rekey_domain::action::FixedMethod::Post,
                    rekey_domain::action::ExactPath::parse("/fixed").unwrap(),
                )],
            },
            "fixed-actions",
            "permit",
            100,
        )
        .await;
        assert!(f.profile.llm_limits.is_empty());
        let (token, owner) = f.session(10);
        f.response(b"{}");
        let raw = br#"{"unrestricted":"ordinary template"}"#;
        f.executor
            .admit(f.request(&token, raw))
            .await
            .unwrap()
            .run()
            .await
            .unwrap();
        assert_eq!(f.fake.take_requests()[0].body, raw);
        let rows = f.activity().await;
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().all(
                |row| row
                    .request_context
                    .as_ref()
                    .is_some_and(|context| context.profile_name == f.profile.name
                        && context.capability == "fixed-actions"
                        && context.model.is_none())
            )
        );
        assert!(
            !serde_json::to_string(&rows)
                .unwrap()
                .contains("unrestricted")
        );
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 0,
                output_tokens: 0
            }
        );
        let id = SessionId::new_random();
        let reference = ActionVersionRef {
            action_id: f.action.id,
            version: f.action.version,
        };
        let grant = SessionGrant::new(
            id,
            Principal {
                tenant_id: TenantId::new_random(),
                principal_id: f.profile.principal_id,
                session_id: id,
            },
            vec![reference],
            crate::now_ts().unwrap(),
            60000,
            1,
        )
        .unwrap();
        let (stale, stale_owner) = f
            .ctx
            .sessions
            .admit_profile(
                grant,
                vec![(reference, 5000)],
                ProfileSessionScope::new(f.profile.clone(), [0; 32]),
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        assert!(matches!(
            f.executor.admit(f.request(&stale, raw)).await,
            Err(BrokerError::Denied("profile-policy-changed"))
        ));
        assert_eq!(f.count("execution.started"), 1);
        drop(stale_owner);
        drop(owner);
        f.finish().await;
    }

    struct StreamReply {
        chunks: std::collections::VecDeque<Vec<u8>>,
        eof: Option<Arc<tokio::sync::Notify>>,
        error: bool,
    }
    impl crate::upstream::UpstreamBody for StreamReply {
        fn next_chunk(&mut self) -> crate::upstream::UpstreamChunkFuture<'_> {
            Box::pin(async {
                if let Some(bytes) = self.chunks.pop_front() {
                    return Ok(Some(bytes.into()));
                }
                if let Some(gate) = self.eof.take() {
                    gate.notified().await;
                }
                if self.error {
                    Err(crate::upstream::UpstreamError::Transport)
                } else {
                    Ok(None)
                }
            })
        }
    }
    type SentStreamRequest = (Vec<u8>, Vec<(String, String)>);
    #[derive(Default)]
    struct StreamTransport {
        queued: std::sync::Mutex<std::collections::VecDeque<StreamReply>>,
        sent: std::sync::Mutex<Vec<SentStreamRequest>>,
        opened: tokio::sync::Notify,
    }
    impl crate::upstream::UpstreamTransport for StreamTransport {
        fn send(
            &self,
            _request: crate::upstream::UpstreamRequest,
        ) -> crate::upstream::UpstreamFuture<'_> {
            Box::pin(async {
                Err(crate::upstream::UpstreamError::Blocked(
                    "fixture-stream-only",
                ))
            })
        }
        fn open_stream(
            &self,
            request: crate::upstream::UpstreamRequest,
        ) -> crate::upstream::UpstreamStreamFuture<'_> {
            Box::pin(async move {
                self.sent
                    .lock()
                    .unwrap()
                    .push((request.body.to_vec(), request.headers.clone()));
                self.opened.notify_one();
                let body = self.queued.lock().unwrap().pop_front().unwrap();
                Ok(crate::upstream::UpstreamStreamResponse {
                    status: 200,
                    headers: vec![("content-type".into(), "text/event-stream".into())].into(),
                    body: Box::new(body),
                })
            })
        }
    }
    impl StreamTransport {
        fn push(&self, raw: &[u8], eof: Option<Arc<tokio::sync::Notify>>, error: bool) {
            self.queued.lock().unwrap().push_back(StreamReply {
                chunks: raw.chunks(7).map(<[u8]>::to_vec).collect(),
                eof,
                error,
            });
        }
    }
    const RAW_BODY: &[u8]=br#"{"model":"allowed","stream":true,"tools":[{"name":"tool"}],"thinking":{"type":"enabled"}}"#;
    const RAW_CHAT: &str = "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"safe\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"completion_tokens\":7}}\n\ndata: [DONE]\n\n";

    async fn activate_signed(f: &mut Fixture, max_uses: u32) {
        let signer = rekey_domain::ids::PolicySignerId::new_random();
        let key = rekey_policy::PolicyVerificationKey::from_bytes(
            rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519,
            f.key.public_key().as_ref(),
        )
        .unwrap();
        let trust = rekey_policy::ValidatedPolicyTrust::from_parts(signer, key);
        f.ctx
            .install_policy_trust_until(
                trust.clone(),
                proof(),
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        f.unsigned_snapshot["profiles"][0]["session"]["max_uses"] = max_uses.into();
        let mut envelope =
            json!({"format_version":1,"signer_id":signer,"snapshot":f.unsigned_snapshot});
        let mut sign = b"RKPOLICY\0\x01".to_vec();
        sign.extend(serde_jcs::to_vec(&envelope).unwrap());
        envelope["signature"] = BASE64URL_NOPAD.encode(f.key.sign(&sign).as_ref()).into();
        let vault = f.ctx.authority.status().await.unwrap().vault_id;
        let metadata = rekey_domain::ipc::PolicyActivateMeta {
            expected_vault_id: vault,
            expected_trust_sha256: HEXLOWER
                .encode(&rekey_policy::policy_trust_sha256(signer, trust.key()).unwrap()),
            bundle_json: serde_json::value::RawValue::from_string(
                serde_json::to_string(&envelope).unwrap(),
            )
            .unwrap(),
        };
        f.ctx
            .activate_policy_until(
                metadata,
                proof(),
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
    }
    fn install_stream_transport(
        f: &mut Fixture,
    ) -> (
        Arc<StreamTransport>,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), BrokerError>>,
    ) {
        let transport = Arc::new(StreamTransport::default());
        f.executor = Arc::new(ActionExecutor::new(
            f.ctx.authority.clone(),
            f.ctx.sessions.clone(),
            transport.clone(),
            f.ctx.lifecycle.clone(),
            f.ctx.executor.terminals.clone(),
            f.ctx.executor.policy.clone(),
        ));
        let (executions, supervisor) = crate::execution_supervisor::new(f.executor.clone());
        // No production admission shortcut: the replaced test context now uses the real supervisor.
        let ctx = Arc::get_mut(&mut f.ctx).unwrap();
        ctx.executor = f.executor.clone();
        ctx.executions = executions;
        let (tx, rx) = tokio::sync::watch::channel(false);
        (transport, tx, tokio::spawn(supervisor.run(rx)))
    }
    async fn send_wire(
        stream: &mut tokio::net::UnixStream,
        channel: rekey_domain::ipc::Channel,
        opcode: u16,
        meta: &Value,
        body: &[u8],
    ) {
        use tokio::io::AsyncWriteExt;
        let meta = serde_json::to_vec(meta).unwrap();
        let h = rekey_domain::ipc::FrameHeader {
            channel,
            flags: 0,
            message_type: opcode,
            request_id: RequestId::new_random(),
            metadata_len: meta.len() as u32,
            body_len: body.len() as u32,
        };
        stream.write_all(&h.encode()).await.unwrap();
        stream.write_all(&meta).await.unwrap();
        stream.write_all(body).await.unwrap();
    }
    async fn receive_wire(stream: &mut tokio::net::UnixStream) -> (u16, Value, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut h = [0; rekey_domain::ipc::FRAME_HEADER_LEN];
        stream.read_exact(&mut h).await.unwrap();
        let h = rekey_domain::ipc::FrameHeader::decode(&h).unwrap();
        let mut meta = vec![0; h.metadata_len as usize];
        let mut body = vec![0; h.body_len as usize];
        stream.read_exact(&mut meta).await.unwrap();
        stream.read_exact(&mut body).await.unwrap();
        (h.message_type, serde_json::from_slice(&meta).unwrap(), body)
    }
    async fn admin_connection(
        f: &Fixture,
    ) -> (tokio::net::UnixStream, tokio::task::JoinHandle<()>) {
        use std::os::unix::fs::PermissionsExt;
        // A real connect/accept gives the OS peer identity used by the Profile owner guard.
        let path = f
            .dir
            .path()
            .join(format!("{}.sock", RequestId::new_random()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        std::fs::remove_file(path).unwrap();
        let (keep, rx) = tokio::sync::watch::channel(false);
        let ctx = f.ctx.clone();
        (
            client,
            tokio::spawn(async move {
                let _keep = keep;
                crate::ipc::admin::handle_admin_conn(server, ctx, rx).await
            }),
        )
    }
    async fn mint_wire(
        f: &Fixture,
    ) -> (tokio::net::UnixStream, tokio::task::JoinHandle<()>, String) {
        let (mut client, task) = admin_connection(f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Admin,
            rekey_domain::ipc::admin_msg::PROFILE_SESSION_CREATE,
            &json!({"profile":"synthetic-profile"}),
            &[],
        )
        .await;
        let (kind, meta, body) = receive_wire(&mut client).await;
        assert_eq!(kind, rekey_domain::ipc::resp_msg::OK, "{meta}");
        assert_eq!(meta, json!({}));
        let response: rekey_domain::ipc::ProfileSessionCreatedResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(response.session.principal_id, f.profile.principal_id);
        (client, task, response.session.capability_token)
    }
    fn wire_meta(f: &Fixture, token: &str) -> Value {
        json!({"capability_token":token,"action_id":f.action.id,"action_version":f.action.version,"content_type":"application/json","extra_headers":[],"params":{},"query":{},"approval_grants":[]})
    }
    async fn agent_connection(
        f: &Fixture,
    ) -> (tokio::net::UnixStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (keep, rx) = tokio::sync::watch::channel(false);
        let ctx = f.ctx.clone();
        (
            client,
            tokio::spawn(async move {
                let _keep = keep;
                crate::ipc::agent::handle_agent_conn(server, ctx, rx).await
            }),
        )
    }
    async fn read_stream(client: &mut tokio::net::UnixStream) -> (Vec<u8>, Value) {
        let mut out = Vec::new();
        let mut sequence = 0;
        loop {
            let (kind, meta, body) = receive_wire(client).await;
            assert_eq!(meta["sequence"], sequence);
            if kind == rekey_domain::ipc::resp_msg::STREAM_TERMINAL {
                assert!(body.is_empty());
                return (out, meta);
            }
            assert_eq!(kind, rekey_domain::ipc::resp_msg::STREAM_CHUNK);
            assert!(!body.is_empty());
            assert!(std::str::from_utf8(&body).is_ok());
            out.extend(body);
            sequence += 1;
        }
    }
    async fn stop_supervisor(
        f: &Fixture,
        tx: tokio::sync::watch::Sender<bool>,
        task: tokio::task::JoinHandle<Result<(), BrokerError>>,
    ) {
        tx.send(true).unwrap();
        task.await.unwrap().unwrap();
        f.ctx
            .executor
            .terminals
            .wait_idle(Duration::from_secs(5))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn signed_profile_real_control_and_agent_sse_share_budget_and_preserve_effective_body() {
        let mut f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 14).await;
        activate_signed(&mut f, 3).await;
        let (t, stop, supervisor) = install_stream_transport(&mut f);
        let (owner, owner_task, token) = mint_wire(&f).await;
        let (owner2, owner_task2, token2) = mint_wire(&f).await;
        for token in [&token, &token2] {
            t.push(RAW_CHAT.as_bytes(), None, false);
            let (mut client, task) = agent_connection(&f).await;
            send_wire(
                &mut client,
                rekey_domain::ipc::Channel::Agent,
                rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
                &wire_meta(&f, token),
                RAW_BODY,
            )
            .await;
            let (out, terminal) = read_stream(&mut client).await;
            assert_eq!(out, RAW_CHAT.as_bytes());
            assert_eq!(terminal["status"], "completed");
            drop(client);
            task.await.unwrap();
        }
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 2,
                output_tokens: 14
            }
        );
        assert_eq!(f.count("execution.finished"), 2);
        let rows = f.activity().await;
        assert_eq!(
            rows.iter()
                .filter(|row| row.event_type == "execution.started")
                .count(),
            2
        );
        assert_eq!(
            rows.iter()
                .filter_map(|row| row.usage.as_ref())
                .map(|usage| usage.output_tokens)
                .sum::<u64>(),
            14
        );
        assert!(
            rows.iter().all(
                |row| row.request_context.as_ref().unwrap().model.as_deref() == Some("allowed")
            )
        );
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &wire_meta(&f, &token),
            RAW_BODY,
        )
        .await;
        let (kind, meta, _) = receive_wire(&mut client).await;
        assert_eq!(kind, rekey_domain::ipc::resp_msg::ERROR);
        assert_eq!(meta["code"], "REQUEST_DENIED");
        drop(client);
        task.await.unwrap();
        assert_eq!(t.sent.lock().unwrap().len(), 2);
        assert!(!f.ctx.executor.terminals.has_failed());
        for (body, headers) in t.sent.lock().unwrap().iter() {
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap()["max_completion_tokens"],
                20
            );
            assert!(
                headers
                    .iter()
                    .any(|(k, v)| k == "accept-encoding" && v == "identity")
            );
            assert!(String::from_utf8_lossy(body).contains("\"thinking\":{\"type\":\"enabled\"}"));
        }
        drop(owner);
        owner_task.await.unwrap();
        assert!(
            f.ctx
                .sessions
                .acquire(
                    &token,
                    f.request(&token, RAW_BODY).action,
                    crate::now_ts().unwrap()
                )
                .is_err()
        );
        drop(owner2);
        owner_task2.await.unwrap();
        stop_supervisor(&f, stop, supervisor).await;
        f.finish().await;
    }

    #[tokio::test]
    async fn actual_local_presence_approval_and_last_use_retry_reach_raw_stream_once() {
        let mut f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "local", 100).await;
        activate_signed(&mut f, 1).await;
        let (t, stop, supervisor) = install_stream_transport(&mut f);
        let (owner, owner_task, token) = mint_wire(&f).await;
        let (mut client, task) = agent_connection(&f).await;
        let mut meta = wire_meta(&f, &token);
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &meta,
            RAW_BODY,
        )
        .await;
        let (kind, error, _) = receive_wire(&mut client).await;
        assert_eq!(kind, rekey_domain::ipc::resp_msg::ERROR);
        assert_eq!(error["code"], "APPROVAL_REQUIRED");
        drop(client);
        task.await.unwrap();
        assert_eq!(f.totals().await.requests, 0);
        let id = error["approval"]["challenge_id"].clone();
        let (mut admin, admin_task) = admin_connection(&f).await;
        send_wire(
            &mut admin,
            rekey_domain::ipc::Channel::Admin,
            rekey_domain::ipc::admin_msg::APPROVAL_LOCAL_REVIEW,
            &json!({"approval_request_id":id}),
            &[],
        )
        .await;
        let (kind, review, body) = receive_wire(&mut admin).await;
        assert_eq!(kind, rekey_domain::ipc::resp_msg::OK);
        assert!(String::from_utf8_lossy(&body).contains("max_completion_tokens"));
        let (key, _) = f
            .ctx
            .authority
            .desktop_remember(proof(), None)
            .await
            .unwrap();
        let mut proof_body = Vec::new();
        rekey_domain::ipc::encode_proof_body(
            rekey_domain::ipc::ProofKind::Presence,
            &key,
            &mut proof_body,
        );
        send_wire(
            &mut admin,
            rekey_domain::ipc::Channel::Admin,
            rekey_domain::ipc::admin_msg::APPROVAL_LOCAL_APPROVE,
            &json!({"approval_request_id":id,"expected_review_sha256":review["review_sha256"]}),
            &proof_body,
        )
        .await;
        let (kind, result, _) = receive_wire(&mut admin).await;
        assert_eq!(kind, rekey_domain::ipc::resp_msg::OK, "{result}");
        drop(admin);
        admin_task.await.unwrap();
        meta["local_approval_request_id"] = id;
        t.push(RAW_CHAT.as_bytes(), None, false);
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &meta,
            RAW_BODY,
        )
        .await;
        let (out, terminal) = read_stream(&mut client).await;
        assert_eq!(out, RAW_CHAT.as_bytes());
        assert_eq!(terminal["status"], "completed");
        drop(client);
        task.await.unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 1,
                output_tokens: 7
            }
        );
        assert_eq!(f.count("approval.accepted"), 1);
        let rows = f.activity().await;
        let requested = rows
            .iter()
            .find(|row| row.event_type == "approval.requested")
            .unwrap();
        let approved = rows
            .iter()
            .find(|row| row.event_type == "approval.approved")
            .unwrap();
        let accepted = rows
            .iter()
            .find(|row| row.event_type == "approval.accepted")
            .unwrap();
        assert_eq!(requested.request_context, approved.request_context);
        assert_eq!(approved.request_context, accepted.request_context);
        assert_eq!(
            approved.request_context.as_ref().unwrap().model.as_deref(),
            Some("allowed")
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.event_type == "execution.started")
                .count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.event_type == "execution.blocked")
                .count(),
            0
        );
        assert_eq!(
            rows.iter()
                .filter_map(|row| row.usage.as_ref())
                .map(|usage| usage.output_tokens)
                .sum::<u64>(),
            7
        );
        assert!(
            f.ctx
                .sessions
                .acquire(
                    &token,
                    f.request(&token, RAW_BODY).action,
                    crate::now_ts().unwrap()
                )
                .is_err()
        );
        drop(owner);
        owner_task.await.unwrap();
        stop_supervisor(&f, stop, supervisor).await;
        f.finish().await;
    }

    #[tokio::test]
    async fn raw_terminal_is_withheld_at_eof_and_audit_failure_keeps_pending_atomic() {
        let mut f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        activate_signed(&mut f, 2).await;
        let (t, stop, supervisor) = install_stream_transport(&mut f);
        let (owner, owner_task, token) = mint_wire(&f).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        t.push(RAW_CHAT.as_bytes(), Some(gate.clone()), false);
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &wire_meta(&f, &token),
            RAW_BODY,
        )
        .await;
        t.opened.notified().await;
        assert_eq!(f.count("execution.started"), 1);
        assert_eq!(f.count("execution.finished"), 0);
        // Withholding remains until EOF; this trigger is installed after real started.
        f.db().execute_batch("CREATE TRIGGER fail_sse_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.finished' BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
        gate.notify_one();
        let (out, terminal) = read_stream(&mut client).await;
        assert!(!String::from_utf8_lossy(&out).contains("[DONE]"));
        assert_eq!(terminal["status"], "failed");
        drop(client);
        task.await.unwrap();
        assert_eq!(f.count("execution.finished"), 0);
        assert_eq!(f.ctx.authority.status().await.unwrap().state, "faulted");
        let pending: i64 = f
            .db()
            .query_row(
                "SELECT count(*) FROM profile_usage WHERE settled_at_ms IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
        drop(owner);
        owner_task.await.unwrap();
        stop.send(true).unwrap();
        supervisor.await.unwrap().unwrap();
        assert!(
            f.ctx
                .executor
                .terminals
                .wait_idle(Duration::from_secs(5))
                .await
                .is_err()
        );
        f.ctx.authority.shutdown(None).await.unwrap();
        drop(f.executor);
        drop(f.ctx);
        f.terminal.await.unwrap();
        f.worker.join().unwrap();
    }

    #[tokio::test]
    async fn raw_disconnect_finishes_usage_but_transport_cut_settles_saved_max_once() {
        let mut f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        activate_signed(&mut f, 4).await;
        let (t, stop, supervisor) = install_stream_transport(&mut f);
        let (owner, owner_task, token) = mint_wire(&f).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        t.push(RAW_CHAT.as_bytes(), Some(gate.clone()), false);
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &wire_meta(&f, &token),
            RAW_BODY,
        )
        .await;
        t.opened.notified().await;
        drop(client);
        gate.notify_one();
        task.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if f.totals().await.output_tokens == 7 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        t.push(
            RAW_CHAT.trim_end_matches("data: [DONE]\n\n").as_bytes(),
            None,
            true,
        );
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &wire_meta(&f, &token),
            br#"{"model":"allowed","stream":true,"max_tokens":3}"#,
        )
        .await;
        let (_, terminal) = read_stream(&mut client).await;
        assert_eq!(terminal["status"], "failed");
        drop(client);
        task.await.unwrap();
        f.ctx
            .executor
            .terminals
            .wait_idle(Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 2,
                output_tokens: 10
            }
        );
        assert_eq!(f.count("execution.indeterminate"), 1);
        drop(owner);
        owner_task.await.unwrap();
        stop_supervisor(&f, stop, supervisor).await;
        f.finish().await;
    }

    #[tokio::test]
    async fn external_wire_prepare_binds_raw_max_and_real_signed_retry() {
        let mut f =
            Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "external", 100).await;
        activate_signed(&mut f, 4).await;
        let (t, stop, supervisor) = install_stream_transport(&mut f);
        let (owner, owner_task, token) = mint_wire(&f).await;
        let (mut client, task) = agent_connection(&f).await;
        let mut meta = wire_meta(&f, &token);
        meta.as_object_mut().unwrap().remove("approval_grants");
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::PREPARE_APPROVAL,
            &meta,
            RAW_BODY,
        )
        .await;
        let (kind, envelope, _) = receive_wire(&mut client).await;
        assert_eq!(kind, rekey_domain::ipc::resp_msg::OK);
        let envelope: rekey_domain::ipc::SignedApprovalChallenge =
            serde_json::from_value(envelope).unwrap();
        drop(client);
        task.await.unwrap();
        assert_eq!(f.totals().await.requests, 0);
        let c = envelope.challenge;
        let mut grant = json!({"format_version":1,"approval_id":ApprovalId::new_random(),"approval_request_id":c.approval_request_id,"approver_id":f.approver,
            "tenant_id":c.tenant_id,"principal_id":c.principal_id,"session_id":c.session_id,"action_id":c.action_id,"action_version":c.action_version,
            "resource":c.resource,"schema_id":c.schema_id,"parameter_sha256":c.parameter_sha256,"policy_version":c.policy_version,"policy_sha256":c.policy_sha256,
            "policy_rule_id":c.policy_rule_id,"mode":c.mode,"not_before_ms":c.created_at_ms,"expires_at_ms":c.max_expires_at_ms,"max_uses":1});
        let mut bytes = b"RKAPPROVAL\0\x01".to_vec();
        bytes.extend(serde_jcs::to_vec(&grant).unwrap());
        grant["signature"] = BASE64URL_NOPAD.encode(f.key.sign(&bytes).as_ref()).into();
        let mut meta = wire_meta(&f, &token);
        meta["approval_grants"] = json!([serde_json::to_string(&grant).unwrap()]);
        t.push(RAW_CHAT.as_bytes(), None, false);
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &meta,
            RAW_BODY,
        )
        .await;
        let (out, terminal) = read_stream(&mut client).await;
        assert_eq!(out, RAW_CHAT.as_bytes());
        assert_eq!(terminal["status"], "completed");
        drop(client);
        task.await.unwrap();
        let sent = t.sent.lock().unwrap()[0].0.clone();
        let active = f.ctx.executor.policy.read().await.clone().unwrap();
        let (_, canonical, _) = active
            .snapshot()
            .canonicalize(
                &f.action,
                rekey_policy::ActionRequest {
                    params: &Default::default(),
                    query: &Default::default(),
                    content_type: Some("application/json"),
                    headers: &[],
                    body: &sent,
                },
            )
            .unwrap();
        assert_eq!(
            HEXLOWER.encode(&canonical.canonical_hash),
            c.parameter_sha256
        );
        assert_eq!(f.totals().await.output_tokens, 7);
        assert_eq!(f.count("approval.accepted"), 1);
        drop(active);
        drop(owner);
        owner_task.await.unwrap();
        stop_supervisor(&f, stop, supervisor).await;
        f.finish().await;
    }

    #[tokio::test]
    async fn signed_anthropic_and_responses_raw_routes_and_wrong_sinks_use_real_scope() {
        for (provider, capability, raw) in [
            (
                BuiltinTemplate::Anthropic,
                "messages",
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"content\":[]}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{\"output_tokens\":4}}\n\ndata: {\"type\":\"message_stop\"}\n\n",
            ),
            (
                BuiltinTemplate::OpenAi,
                "responses",
                "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"output\":[]}}\n\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r\",\"status\":\"incomplete\",\"usage\":{\"output_tokens\":4}}}\n\n",
            ),
        ] {
            let mut f = Fixture::new(provider, capability, "permit", 100).await;
            activate_signed(&mut f, 4).await;
            let (t, stop, supervisor) = install_stream_transport(&mut f);
            let (owner, owner_task, token) = mint_wire(&f).await;
            for (opcode, body) in [
                (
                    rekey_domain::ipc::agent_msg::EXECUTE_FIXED_HTTP_ACTION,
                    RAW_BODY,
                ),
                (rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM, BODY),
            ] {
                let (mut client, task) = agent_connection(&f).await;
                send_wire(
                    &mut client,
                    rekey_domain::ipc::Channel::Agent,
                    opcode,
                    &wire_meta(&f, &token),
                    body,
                )
                .await;
                let (kind, meta, _) = receive_wire(&mut client).await;
                assert_eq!(kind, rekey_domain::ipc::resp_msg::ERROR);
                assert_eq!(meta["code"], "REQUEST_DENIED");
                drop(client);
                task.await.unwrap();
            }
            assert_eq!(f.totals().await.requests, 0);
            assert_eq!(f.count("execution.started"), 0);
            assert!(t.sent.lock().unwrap().is_empty());
            t.push(raw.as_bytes(), None, false);
            let (mut client, task) = agent_connection(&f).await;
            send_wire(
                &mut client,
                rekey_domain::ipc::Channel::Agent,
                rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
                &wire_meta(&f, &token),
                RAW_BODY,
            )
            .await;
            let (out, terminal) = read_stream(&mut client).await;
            assert_eq!(out, raw.as_bytes());
            assert_eq!(terminal["status"], "incomplete");
            drop(client);
            task.await.unwrap();
            assert_eq!(f.totals().await.output_tokens, 4);
            assert_eq!(f.count("execution.finished"), 1);
            drop(owner);
            owner_task.await.unwrap();
            stop_supervisor(&f, stop, supervisor).await;
            f.finish().await;
        }
    }
    #[tokio::test]
    async fn raw_lifecycle_cancel_after_remote_effect_has_one_conservative_terminal() {
        let mut f = Fixture::new(BuiltinTemplate::OpenAi, "chat-completions", "permit", 100).await;
        activate_signed(&mut f, 2).await;
        let (t, stop, supervisor) = install_stream_transport(&mut f);
        let (owner, owner_task, token) = mint_wire(&f).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        t.push(RAW_CHAT.as_bytes(), Some(gate), false);
        let (mut client, task) = agent_connection(&f).await;
        send_wire(
            &mut client,
            rekey_domain::ipc::Channel::Agent,
            rekey_domain::ipc::agent_msg::EXECUTE_TEXT_STREAM,
            &wire_meta(&f, &token),
            RAW_BODY,
        )
        .await;
        t.opened.notified().await;
        f.ctx.lifecycle.signal_cancel();
        let (out, terminal) = read_stream(&mut client).await;
        assert_eq!(terminal["status"], "failed");
        assert!(!String::from_utf8_lossy(&out).contains("[DONE]"));
        drop(client);
        task.await.unwrap();
        f.ctx
            .executor
            .terminals
            .wait_idle(Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            f.totals().await,
            UsageTotals {
                requests: 1,
                output_tokens: 20
            }
        );
        assert_eq!(f.count("execution.indeterminate"), 1);
        drop(owner);
        owner_task.await.unwrap();
        stop_supervisor(&f, stop, supervisor).await;
        f.finish().await;
    }
}
