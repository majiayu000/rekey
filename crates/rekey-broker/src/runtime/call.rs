//! One local call contract shared by CLI, MCP, and the HTTP adapter.
use rekey_domain::connection::MethodClass;
use rekey_domain::ipc;
use rekey_policy::connections::{decide, evaluate_connection};
use rekey_vault::AuthorityError;

use super::BrokerCtx;
use crate::error::BrokerError;

impl BrokerCtx {
    pub(crate) fn service_url(&self) -> Option<String> {
        self.gateway.service_url()
    }
    pub(crate) async fn list_capabilities(
        &self,
        caller: &str,
    ) -> Result<ipc::ListCapabilitiesResponse, BrokerError> {
        self.lifecycle.reject_if_not_running()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some())
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        if active.is_expired(crate::now_ts()?) {
            return Err(rekey_policy::PolicyError::Expired.into());
        }
        let connections = active
            .snapshot()
            .connections()
            .iter()
            .filter(|c| c.enabled)
            .map(|connection| {
                let (read, _, _) = decide(
                    connection,
                    rekey_domain::action::FixedMethod::Get,
                    MethodClass::Read,
                    "/",
                    caller,
                );
                let (write, _, _) = decide(
                    connection,
                    rekey_domain::action::FixedMethod::Post,
                    MethodClass::Write,
                    "/",
                    caller,
                );
                ipc::ConnectionCapability {
                    connection: connection.name.clone(),
                    preset: connection.preset.clone(),
                    origin: connection.origin.clone(),
                    grade: connection.grade,
                    read,
                    write,
                    operations: described_operations(connection),
                    llm: connection.llm.clone(),
                }
            })
            .collect();
        Ok(ipc::ListCapabilitiesResponse {
            connections,
            derived_credentials: active
                .snapshot()
                .derived_credentials()
                .iter()
                .map(|grant| ipc::DerivedCredentialCapability {
                    connection: grant.name.clone(),
                    kind: match grant.target {
                        rekey_domain::connection::DerivedCredentialTarget::AwsAssumeRole {
                            ..
                        } => "aws-assume-role",
                        rekey_domain::connection::DerivedCredentialTarget::KubernetesEks {
                            ..
                        } => "kubernetes-eks",
                        rekey_domain::connection::DerivedCredentialTarget::GitHubApp { .. } => {
                            "github-app"
                        }
                    }
                    .into(),
                    target: grant.target.clone(),
                    max_ttl_seconds: grant.max_ttl_seconds,
                    effect: grant.effect,
                    grade: rekey_domain::connection::CredentialGrade::T1,
                })
                .collect(),
            service_url: self.gateway.service_url(),
            policy_expires_at_ms: Some(active.snapshot().expires_at_ms()),
        })
    }
    pub(crate) async fn describe_operation(
        &self,
        operation: &str,
        caller: &str,
    ) -> Result<ipc::DescribeResponse, BrokerError> {
        self.lifecycle.reject_if_not_running()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some())
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        if active.is_expired(crate::now_ts()?) {
            return Err(rekey_policy::PolicyError::Expired.into());
        }
        let mut matches = active
            .snapshot()
            .connections()
            .iter()
            .filter(|c| c.enabled)
            .flat_map(|c| {
                c.operations
                    .iter()
                    .filter(move |o| o.name == operation)
                    .map(move |o| (c, o))
            });
        let (connection, operation) = matches
            .next()
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        if matches.next().is_some() {
            return Err(rekey_policy::PolicyError::InvalidParameters.into());
        }
        Ok(ipc::DescribeResponse {
            connection: connection.name.clone(),
            operation: with_model_enum(operation.clone(), connection),
            rules: connection.rules.clone(),
            caller_rules: connection
                .caller_overrides
                .get(caller)
                .cloned()
                .unwrap_or_default(),
            limits: connection.limits.clone(),
            llm: connection.llm.clone(),
            policy_expires_at_ms: Some(active.snapshot().expires_at_ms()),
        })
    }
    pub(crate) async fn dry_run_call(
        &self,
        meta: &ipc::CallMeta,
        body: &[u8],
        caller: &str,
    ) -> Result<ipc::DryRunResponse, BrokerError> {
        self.lifecycle.reject_if_not_running()?;
        let active = self
            .policy
            .read()
            .await
            .clone()
            .filter(|p| p.signer_id().is_some())
            .ok_or(rekey_policy::PolicyError::NotConfigured)?;
        if active.is_expired(crate::now_ts()?) {
            return Err(rekey_policy::PolicyError::Expired.into());
        }
        let request = evaluate_connection(active.snapshot(), meta, body, caller, crate::now_ts()?)?;
        let mut audit = super::call_audit("call.dry_run", &request.connection.name, caller)?;
        audit.action_id = Some(request.action.id);
        audit.action_version = Some(request.action.version);
        audit.outcome = rekey_vault::model::outcome::SUCCESS;
        audit.authorization = Some(Box::new(rekey_vault::model::AuthorizationEvidence {
            principal_id: rekey_domain::ids::PrincipalId::from_random_bytes(
                *audit.request_id.unwrap().as_bytes(),
            ),
            policy_version: active.snapshot().version().get(),
            policy_digest: active.snapshot().digest(),
            policy_rule_id: request.rule_id,
            resource_type: "connection".into(),
            resource_id: request.connection.name.clone(),
            parameter_hash: request.parameters.canonical_hash,
        }));
        audit.request_context = Some(rekey_domain::audit::RequestAuditContext::Connection(
            rekey_domain::connection::ConnectionRequestAuditContext {
                connection: request.connection.name.clone(),
                caller: caller.to_owned(),
                method_class: request.method_class,
                normalized_path: request.normalized_path.clone(),
                rule_id: request.rule_id,
            },
        ));
        self.authority.append_audit(audit).await?;
        Ok(ipc::DryRunResponse {
            connection: request.connection.name.clone(),
            method: request.action.method,
            path: request.target.path.as_str().to_owned(),
            query: request.target.query,
            headers: request.headers,
            credential_placeholder: format!("«rekey:{}»", request.connection.name),
            effect: request.effect,
            rule_id: request.rule_id,
            grade: request.connection.grade,
            origin: request.connection.origin.clone(),
            body: if std::str::from_utf8(&request.request_body).is_ok() {
                String::from_utf8_lossy(&request.request_body).into_owned()
            } else {
                data_encoding::BASE64.encode(&request.request_body)
            },
            body_encoding: if std::str::from_utf8(&request.request_body).is_ok() {
                "text".into()
            } else {
                "base64".into()
            },
        })
    }
    pub(crate) async fn await_unlock(
        &self,
        timeout_s: u16,
    ) -> Result<ipc::AwaitUnlockResponse, BrokerError> {
        if timeout_s > 120 {
            return Err(ipc::FrameError::InvalidField.into());
        }
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_s as u64);
        let mut changed = self.lifecycle.subscribe_cancel();
        loop {
            if self.lifecycle.is_running() {
                return Ok(ipc::AwaitUnlockResponse { unlocked: true });
            }
            if self.shutdown_requested() {
                return Err(AuthorityError::Draining.into());
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(ipc::AwaitUnlockResponse { unlocked: false });
            }
            if tokio::time::timeout_at(deadline, changed.changed())
                .await
                .is_err()
            {
                return Ok(ipc::AwaitUnlockResponse { unlocked: false });
            }
        }
    }
}

fn described_operations(
    connection: &rekey_domain::connection::Connection,
) -> Vec<rekey_domain::connection::PresetOperation> {
    connection
        .operations
        .iter()
        .map(|operation| with_model_enum(operation.clone(), connection))
        .collect()
}

/// Agents must not guess model names: publish the signed allow-list as the
/// schema enum of a named operation's `model` parameter.
fn with_model_enum(
    mut operation: rekey_domain::connection::PresetOperation,
    connection: &rekey_domain::connection::Connection,
) -> rekey_domain::connection::PresetOperation {
    if let Some(llm) = &connection.llm
        && let Some(model) = operation
            .parameters
            .get_mut("properties")
            .and_then(|properties| properties.get_mut("model"))
            .and_then(serde_json::Value::as_object_mut)
    {
        model.insert(
            "enum".into(),
            llm.models
                .iter()
                .cloned()
                .map(serde_json::Value::from)
                .collect(),
        );
    }
    operation
}
