use super::*;

impl ActionExecutor {
    pub(super) async fn run_github(
        &self,
        started: &mut StartedAuditGuard,
        request: &ExecuteRequest,
        action: &FixedHttpAction,
        prepared: GitHubPrepared,
        effect_deadline: Instant,
        effect_kind: &AtomicU8,
    ) -> Result<ExecuteOutcome, BrokerError> {
        let profile = match prepared.profile {
            Ok(profile) => profile,
            Err(err) => {
                started.blocked_until(effect_deadline, err.reason()).await?;
                return Err(BrokerError::Denied(err.reason()));
            }
        };
        let github_action = match profile.action(action, request) {
            Ok(action) => action,
            Err(err) => {
                started.blocked_until(effect_deadline, err.reason()).await?;
                return Err(BrokerError::Denied(err.reason()));
            }
        };
        let request_body = match github_action {
            crate::github_profile::GitHubAction::ListRepositories => Vec::new(),
            crate::github_profile::GitHubAction::CreateIssue { .. } => {
                match GitHubAppCredential::issue_body(request) {
                    Ok(body) => body,
                    Err(err) => {
                        started.blocked_until(effect_deadline, err.reason()).await?;
                        return Err(BrokerError::Denied(err.reason()));
                    }
                }
            }
        };
        if let Err(err) = self
            .terminals
            .commit_until(
                effect_deadline,
                connector_event(
                    started.context(),
                    rekey_vault::model::event_type::GITHUB_CONNECTOR_AUTHORIZED,
                    rekey_vault::model::outcome::SUCCESS,
                    profile.commitment(),
                ),
            )
            .await
        {
            if matches!(err, BrokerError::Upstream("upstream-timeout")) {
                started.submit_blocked("upstream-timeout");
            }
            return Err(err);
        }

        try_begin_remote_effect(&self.lifecycle, started, effect_deadline).await?;
        started.mark_remote_effect_started();
        effect_kind.store(EFFECT_REVOCABLE_CONNECTOR, Ordering::SeqCst);

        let send_started = Instant::now();
        let effect = profile
            .execute_effect(
                self.transport.as_ref(),
                github_action,
                request_body,
                effect_deadline,
                action.response_policy.max_body_bytes,
            )
            .await;
        let latency_ms = send_started.elapsed().as_millis() as i64;
        let GitHubEffect::WithToken {
            resource,
            revoke,
            sealing_sources,
        } = effect
        else {
            let GitHubEffect::WithoutToken {
                error,
                remote_effect_possible,
            } = effect
            else {
                unreachable!("GitHub effect variant was matched above")
            };
            if remote_effect_possible {
                started
                    .indeterminate_until(effect_deadline, error.reason())
                    .await?;
            } else {
                started
                    .blocked_until(effect_deadline, error.reason())
                    .await?;
            }
            return Err(BrokerError::Upstream(error.reason()));
        };
        let mut needles = prepared.needles;
        for source in sealing_sources {
            needles.extend(sealing_needles(&source, &source));
        }
        let (revoke_outcome, revoke_reason) = match revoke {
            Ok(()) => (
                rekey_vault::model::outcome::SUCCESS,
                format!("success;{}", profile.commitment()),
            ),
            Err(err) => (
                rekey_vault::model::outcome::FAILURE,
                format!("{};{}", err.reason(), profile.commitment()),
            ),
        };
        if let Err(err) = self
            .terminals
            .commit_until(
                effect_deadline,
                connector_event(
                    started.context(),
                    rekey_vault::model::event_type::GITHUB_TOKEN_REVOKED,
                    revoke_outcome,
                    revoke_reason,
                ),
            )
            .await
        {
            let reason = if matches!(err, BrokerError::Upstream("upstream-timeout")) {
                "upstream-timeout"
            } else {
                "connector-audit-failed"
            };
            started.submit_indeterminate(reason);
            return Err(err);
        }
        if let Err(err) = revoke {
            started
                .indeterminate_until(effect_deadline, err.reason())
                .await?;
            return Err(github_post_effect_error(github_action, err.reason()));
        }

        let mut response = match resource {
            Ok(response) => response,
            Err(err) => {
                started
                    .indeterminate_until(effect_deadline, err.reason())
                    .await?;
                return Err(github_post_effect_error(github_action, err.reason()));
            }
        };
        if contains_secret(&response.body, &needles)
            || headers_contain_secret(&response.headers, &needles)
        {
            started
                .indeterminate_until(effect_deadline, "reflected-secret")
                .await?;
            return Err(BrokerError::ResponseSecurityViolation);
        }
        let headers = filter_response_headers(action, &response.headers);
        if !response_metadata_fits(response.status, &headers, response.body.len()) {
            started
                .indeterminate_until(effect_deadline, "response-metadata-too-large")
                .await?;
            return Err(BrokerError::Domain(DomainError::ResponseTooLarge));
        }
        started
            .finished_until(
                effect_deadline,
                prepared.credential_version,
                response.status,
                latency_ms,
            )
            .await?;
        let body = std::mem::take(&mut *response.body);
        Ok(ExecuteOutcome {
            upstream_status: response.status,
            headers,
            body,
        })
    }
}

pub(super) fn github_post_effect_error(
    action: crate::github_profile::GitHubAction,
    reason: &'static str,
) -> BrokerError {
    if matches!(
        action,
        crate::github_profile::GitHubAction::CreateIssue { .. }
    ) {
        BrokerError::Indeterminate(reason)
    } else {
        BrokerError::Upstream(reason)
    }
}
