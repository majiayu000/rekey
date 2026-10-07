use std::sync::Arc;

use rekey_domain::authorization::{PolicyMode, PolicyTrustAlgorithm};
use rekey_domain::ipc::{
    PersonalPolicyDraftMeta, PersonalPolicyDraftResponse, PersonalPolicyFieldChange,
    PolicyStatusResponse,
};
use rekey_policy::{
    ValidatedPolicyBundle, ValidatedPolicyTrust, parse_and_verify_policy_bundle_for_load,
};
use rekey_vault::AuthorityError;
use rekey_vault::command::UnlockProof;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::BrokerCtx;
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;

const POLICY_RECONCILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn ensure_activation_metadata_fits(
    vault_id: rekey_domain::ids::VaultId,
    trust_sha256: &str,
    sign_bytes_len: usize,
) -> Result<(), BrokerError> {
    let empty = rekey_domain::ipc::PolicyActivateMeta {
        expected_vault_id: vault_id,
        expected_trust_sha256: trust_sha256.to_owned(),
        bundle_json: serde_json::value::RawValue::from_string("{}".to_owned())
            .map_err(|_| rekey_policy::PolicyError::Malformed)?,
    };
    let outer_len = serde_json::to_vec(&empty)
        .map_err(|_| rekey_policy::PolicyError::Malformed)?
        .len()
        - 2;
    let unsigned_len = sign_bytes_len
        .checked_sub(b"RKPOLICY\0\x01".len())
        .ok_or(rekey_policy::PolicyError::Invalid)?;
    // The exact outer metadata plus the largest P-256 DER signature (72B,
    // 96 unpadded base64url characters) must fit before asking the user to sign.
    let maximum_len = outer_len + unsigned_len + b",\"signature\":\"\"".len() + 96;
    if maximum_len > rekey_domain::ipc::METADATA_MAX_BYTES as usize {
        return Err(rekey_policy::PolicyError::TooLarge.into());
    }
    Ok(())
}

fn verified_stored_bundle(
    record: &rekey_vault::model::PolicyBundleRecord,
    trust: &ValidatedPolicyTrust,
) -> Result<ValidatedPolicyBundle, AuthorityError> {
    match parse_and_verify_policy_bundle_for_load(&record.bundle_json, trust) {
        Ok(verified)
            if verified.signer_id() == record.signer_id
                && verified.snapshot().version().get() == record.version
                && verified.snapshot().expires_at_ms() == record.expires_at_ms
                && verified.policy_digest() == record.policy_digest
                && verified.bundle_digest() == record.bundle_digest =>
        {
            Ok(verified)
        }
        _ => Err(AuthorityError::StorageIntegrityFailed),
    }
}

impl BrokerCtx {
    pub(crate) async fn check_local_approval_policy(
        &self,
        challenge: &rekey_domain::ipc::ApprovalChallenge,
    ) -> Result<(), BrokerError> {
        let now = crate::now_ts()?;
        let policy = self.policy.read().await;
        let current = policy
            .as_ref()
            .filter(|p| !p.is_expired(now))
            .ok_or(BrokerError::Denied("policy-changed"))?;
        if current.snapshot().version().get() != challenge.policy_version
            || data_encoding::HEXLOWER.encode(&current.snapshot().digest())
                != challenge.policy_sha256
        {
            return Err(BrokerError::Denied("policy-changed"));
        }
        Ok(())
    }

    pub async fn personal_policy_draft_until(
        &self,
        request: PersonalPolicyDraftMeta,
        deadline: tokio::time::Instant,
    ) -> Result<(PersonalPolicyDraftResponse, Zeroizing<Vec<u8>>), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        tokio::time::timeout_at(deadline, async {
            let material = self.authority.policy_material().await?;
            if material.state.mode != PolicyMode::Personal {
                return Err(BrokerError::Authority(AuthorityError::PolicyTrustConflict));
            }
            let record = material.trust.ok_or(AuthorityError::PolicyUnavailable)?;
            let trust = ValidatedPolicyTrust::from_parts(record.signer_id, record.key);
            let previous = match material.bundle {
                Some(record) => match verified_stored_bundle(&record, &trust) {
                    Ok(verified) => Some(verified),
                    Err(error) => {
                        drop(self.authority.fault_integrity().await);
                        return Err(error.into());
                    }
                },
                None => None,
            };
            let current_digest = previous
                .as_ref()
                .map(|bundle| data_encoding::HEXLOWER.encode(&bundle.snapshot().digest()));
            if request.expected_policy_sha256 != current_digest {
                return Err(AuthorityError::PolicyVersionConflict.into());
            }
            let available=self.authority.credential_list().await?;
            for connection in &request.connections {
                connection.validate()?;
                let required = if connection.oauth.is_some() { rekey_domain::credential::CredentialKind::OAuthGrant } else { rekey_domain::credential::CredentialKind::OpaqueToken };
                if !available.iter().any(|c| c.id == connection.credential_id && c.state == rekey_domain::credential::CredentialState::Active && c.kind == required) { return Err(AuthorityError::CredentialNotFound.into()); }
            }
            if let Some(grants) = &request.derived_credentials {
                for grant in grants {
                    grant.validate()?;
                    let required = match grant.target {
                        rekey_domain::connection::DerivedCredentialTarget::GitHubApp { .. } => rekey_domain::credential::CredentialKind::GitHubAppInstallation,
                        _ => rekey_domain::credential::CredentialKind::AwsStatic,
                    };
                    if !available.iter().any(|c| c.id == grant.credential_id && c.state == rekey_domain::credential::CredentialState::Active && c.kind == required) { return Err(AuthorityError::CredentialNotFound.into()); }
                }
            }
            if let Some(keys)=&request.ssh_keys {
                for key in keys {
                    if !available.iter().any(|c|c.id==key.credential_id && c.state==rekey_domain::credential::CredentialState::Active && matches!(c.kind,rekey_domain::credential::CredentialKind::SshEd25519|rekey_domain::credential::CredentialKind::SshP256|rekey_domain::credential::CredentialKind::SshSecureEnclaveP256)){return Err(AuthorityError::CredentialNotFound.into());}
                }
            }
            let draft = rekey_policy::personal::generate_connection_draft_with_grants(
                &trust,previous.as_ref(),&request.connections,request.ssh_keys.as_deref(),request.derived_credentials.as_deref(),request.expires_at_ms,crate::now_ts()?,
            )?;
            let base_version = previous
                .as_ref()
                .map(|bundle| bundle.snapshot().version().get());
            let response = PersonalPolicyDraftResponse {
                vault_id: self.authority.admin_status().await?.vault_id,
                trust_sha256: data_encoding::HEXLOWER.encode(&rekey_policy::policy_trust_sha256(
                    trust.signer_id(),
                    trust.key(),
                )?),
                public_key: data_encoding::HEXLOWER.encode(trust.public_key()),
                base_version,
                next_version: base_version
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(rekey_policy::PolicyError::Invalid)?,
                policy_sha256: data_encoding::HEXLOWER
                    .encode(&Sha256::digest(draft.canonical_snapshot())),
                changes: draft
                    .diff()
                    .iter()
                    .map(|change| PersonalPolicyFieldChange {
                        field: change.field.to_owned(),
                        before: change.before.clone(),
                        after: change.after.clone(),
                    })
                    .collect(),
                actions: Vec::new(),
                connections: request.connections,
            };
            if draft.sign_bytes().len() > rekey_policy::SNAPSHOT_MAX_BYTES {
                return Err(rekey_policy::PolicyError::TooLarge.into());
            }
            ensure_activation_metadata_fits(
                response.vault_id,
                &response.trust_sha256,
                draft.sign_bytes().len(),
            )?;
            if tokio::time::Instant::now() >= deadline {
                return Err(AuthorityError::AuthorityBusy.into());
            }
            Ok((response, Zeroizing::new(draft.sign_bytes().to_vec())))
        })
        .await
        .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?
    }

    pub(crate) async fn profile_list_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<rekey_domain::ipc::ConnectionListResponse, BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        tokio::time::timeout_at(deadline, async {
            let material = self.authority.policy_material().await?;
            let Some(record) = material.bundle else {
                return Ok(rekey_domain::ipc::ConnectionListResponse {
                    connections: Vec::new(),
                    ssh_keys: Vec::new(),
                    derived_credentials: Vec::new(),
                    policy_sha256: None,
                    expires_at_ms: None,
                });
            };
            let trust = material.trust.ok_or(AuthorityError::PolicyUnavailable)?;
            let trust = ValidatedPolicyTrust::from_parts(trust.signer_id, trust.key);
            let bundle = match verified_stored_bundle(&record, &trust) {
                Ok(bundle) => bundle,
                Err(error) => {
                    drop(self.authority.fault_integrity().await);
                    return Err(error.into());
                }
            };
            Ok(rekey_domain::ipc::ConnectionListResponse {
                connections: bundle.snapshot().connections().to_vec(),
                ssh_keys: bundle.snapshot().ssh_keys().to_vec(),
                derived_credentials: bundle.snapshot().derived_credentials().to_vec(),
                policy_sha256: Some(data_encoding::HEXLOWER.encode(&bundle.snapshot().digest())),
                expires_at_ms: Some(bundle.snapshot().expires_at_ms()),
            })
        })
        .await
        .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))?
    }

    pub async fn policy_status(&self) -> Result<PolicyStatusResponse, BrokerError> {
        let authority = self.authority.admin_status().await?;
        let tenant_id = rekey_domain::ids::TenantId::from_bytes(*authority.vault_id.as_bytes())?;
        let material = if authority.state == "unlocked" {
            Some(self.authority.policy_material().await?)
        } else {
            None
        };
        let trust_sha256 = material
            .as_ref()
            .and_then(|value| value.trust.as_ref())
            .map(|trust| rekey_policy::policy_trust_sha256(trust.signer_id, &trust.key))
            .transpose()?
            .map(|digest| data_encoding::HEXLOWER.encode(&digest));
        let mut response = PolicyStatusResponse {
            vault_id: authority.vault_id,
            tenant_id,
            mode: material.as_ref().map(|value| value.state.mode),
            algorithm: material
                .as_ref()
                .and_then(|value| value.trust.as_ref())
                .map(|trust| trust.key.algorithm()),
            trust_sha256,
            activated_at_ms: None,
            trust_installed: authority.policy_trust_installed,
            bundle_persisted: authority.policy_bundle_persisted,
            status: "unavailable".to_owned(),
            signer_id: None,
            version: None,
            expires_at_ms: None,
            policy_sha256: None,
            bundle_sha256: None,
        };
        let guard = self.policy.read().await;
        if let (Some(active), Some(material)) = (guard.as_ref(), material.as_ref())
            && let (Some(trust), Some(record)) = (material.trust.as_ref(), material.bundle.as_ref())
            && active.signer_id() == Some(trust.signer_id)
            && active.signer_id() == Some(record.signer_id)
            && active.snapshot().version().get() == record.version
            && active.snapshot().expires_at_ms() == record.expires_at_ms
            && active.snapshot().digest() == record.policy_digest
            && active.bundle_digest() == Some(record.bundle_digest)
        {
            response.status = if active.is_expired(crate::now_ts()?) {
                "expired"
            } else {
                "active"
            }
            .to_owned();
            response.signer_id = Some(record.signer_id);
            response.version = Some(record.version);
            response.expires_at_ms = Some(record.expires_at_ms);
            response.policy_sha256 = Some(data_encoding::HEXLOWER.encode(&record.policy_digest));
            response.bundle_sha256 = Some(data_encoding::HEXLOWER.encode(&record.bundle_digest));
            response.activated_at_ms = Some(record.activated_at_ms);
        }
        Ok(response)
    }

    pub(crate) async fn reload_policy_after_unlock(&self) -> Result<(), BrokerError> {
        let material = self.authority.policy_material().await?;
        let trust = material
            .trust
            .map(|record| ValidatedPolicyTrust::from_parts(record.signer_id, record.key));
        let active = match (trust.as_ref(), material.bundle) {
            (_, None) => None,
            (Some(trust), Some(record)) => {
                let verified = match verified_stored_bundle(&record, trust) {
                    Ok(verified) => verified,
                    Err(error) => {
                        drop(self.authority.fault_integrity().await);
                        return Err(BrokerError::Authority(error));
                    }
                };
                Some(Arc::new(ActivePolicy::load_bundle(
                    verified,
                    crate::now_ts()?,
                )))
            }
            (None, Some(_)) => {
                drop(self.authority.fault_integrity().await);
                return Err(BrokerError::Authority(
                    AuthorityError::StorageIntegrityFailed,
                ));
            }
        };
        *self.policy_trust.write().await = trust;
        let mut guard = self.policy.write().await;
        let preserve_expiry_latch = match (guard.as_ref(), active.as_ref()) {
            (Some(current), Some(loaded)) => {
                current.signer_id() == loaded.signer_id()
                    && current.snapshot().version() == loaded.snapshot().version()
                    && current.bundle_digest() == loaded.bundle_digest()
            }
            _ => false,
        };
        if !preserve_expiry_latch {
            *guard = active;
        }
        Ok(())
    }

    pub async fn install_policy_trust_until(
        &self,
        trust: ValidatedPolicyTrust,
        proof: UnlockProof,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        let installation = tokio::time::timeout_at(
            deadline,
            self.authority.policy_trust_install_before(
                rekey_vault::command::PolicyTrustInput {
                    signer_id: trust.signer_id(),
                    key: trust.key().clone(),
                },
                proof,
                Some(deadline.into_std()),
            ),
        )
        .await;
        match installation {
            Ok(result) => {
                result.map_err(BrokerError::Authority)?;
            }
            Err(_) => {
                let reconciled = tokio::time::timeout(
                    POLICY_RECONCILE_TIMEOUT,
                    self.reload_policy_after_unlock(),
                )
                .await;
                if matches!(reconciled, Ok(Ok(()))) {
                    return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
                }
                self.sessions.close_and_revoke_all();
                self.local_calls.clear();
                self.executor.oauth.clear();
                *self.policy.write().await = None;
                *self.policy_trust.write().await = None;
                self.lifecycle.enter_locked();
                self.request_fault();
                return Err(BrokerError::Authority(AuthorityError::Faulted));
            }
        }
        *self.policy_trust.write().await = Some(trust);
        Ok(())
    }

    pub async fn activate_policy_until(
        &self,
        metadata: rekey_domain::ipc::PolicyActivateMeta,
        proof: UnlockProof,
        deadline: tokio::time::Instant,
    ) -> Result<(), BrokerError> {
        let _owner = self.lifecycle.coordinate_until(deadline).await?;
        self.lifecycle.reject_if_not_running()?;
        let trust = self
            .policy_trust
            .read()
            .await
            .clone()
            .ok_or(BrokerError::Authority(AuthorityError::PolicyUnavailable))?;
        let expected_trust_sha256 =
            rekey_policy::decode_lower_hex_32(&metadata.expected_trust_sha256)?;
        let verified = rekey_policy::parse_and_verify_policy_bundle(
            metadata.bundle_json.get().as_bytes(),
            &trust,
            crate::now_ts()?,
        )?;
        if trust.key().algorithm() == PolicyTrustAlgorithm::SecureEnclaveP256
            || !verified.snapshot().profiles().is_empty()
        {
            // The immutable mode/key contract makes P-256 personal-only. Check
            // the authenticated current Action view even for exact retries;
            // action_list excludes retired versions and includes disabled ones.
            let actions = tokio::time::timeout_at(deadline, self.authority.action_list())
                .await
                .map_err(|_| BrokerError::Authority(AuthorityError::AuthorityBusy))??;
            super::profile::validate_profile_actions(verified.snapshot(), &actions)?;
            if trust.key().algorithm() == PolicyTrustAlgorithm::SecureEnclaveP256
                && verified.snapshot().action_refs().any(|wanted| {
                    !actions.iter().any(|action| {
                        action.enabled
                            && action.id == wanted.action_id
                            && action.version == wanted.version
                    })
                })
            {
                return Err(BrokerError::Authority(
                    AuthorityError::PolicyVersionConflict,
                ));
            }
        }
        let input = rekey_vault::command::PolicyBundleInput {
            expected_vault_id: metadata.expected_vault_id,
            expected_trust_sha256,
            signer_id: verified.signer_id(),
            version: verified.snapshot().version().get(),
            expires_at_ms: verified.snapshot().expires_at_ms(),
            policy_digest: verified.policy_digest(),
            bundle_digest: verified.bundle_digest(),
            bundle_json: verified.canonical_bytes().to_vec(),
        };
        let active = ActivePolicy::activate_bundle(verified, crate::now_ts()?)?;
        let activated_identity = (input.signer_id, input.version, input.bundle_digest);
        let (had_active_policy, was_target_active) = {
            let guard = self.policy.read().await;
            (
                guard.is_some(),
                guard.as_ref().is_some_and(|current| {
                    current.signer_id() == Some(activated_identity.0)
                        && current.snapshot().version().get() == activated_identity.1
                        && current.bundle_digest() == Some(activated_identity.2)
                }),
            )
        };
        let activation = tokio::time::timeout_at(
            deadline,
            self.authority
                .policy_bundle_activate_before(input, proof, Some(deadline.into_std())),
        )
        .await;
        match activation {
            Ok(result) => {
                result.map_err(BrokerError::Authority)?;
            }
            Err(_) => {
                let reconciled = tokio::time::timeout(
                    POLICY_RECONCILE_TIMEOUT,
                    self.reload_policy_after_unlock(),
                )
                .await;
                if matches!(reconciled, Ok(Ok(()))) {
                    let target_is_active =
                        self.policy.read().await.as_ref().is_some_and(|current| {
                            current.signer_id() == Some(activated_identity.0)
                                && current.snapshot().version().get() == activated_identity.1
                                && current.bundle_digest() == Some(activated_identity.2)
                        });
                    if !was_target_active && target_is_active {
                        if had_active_policy {
                            self.sessions.revoke_all();
                        } else {
                            self.sessions.revoke_workload();
                        }
                    }
                    self.reconcile_gateway().await;
                    return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
                }
                self.sessions.close_and_revoke_all();
                self.local_calls.clear();
                self.executor.oauth.clear();
                *self.policy.write().await = None;
                *self.policy_trust.write().await = None;
                self.lifecycle.enter_locked();
                self.request_fault();
                return Err(BrokerError::Authority(AuthorityError::Faulted));
            }
        }
        if !was_target_active {
            if had_active_policy {
                self.sessions.revoke_all();
            } else {
                self.sessions.revoke_workload();
            }
            let mut guard = self.policy.write().await;
            *guard = Some(Arc::new(active));
        }
        self.reconcile_gateway().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use rekey_vault::bootstrap::{confirm_vault_init, init_vault};
    use rekey_vault::crypto::kdf::Argon2Params;
    use rekey_vault::secret::SecretInput;

    #[test]
    fn personal_draft_activation_size_includes_exact_outer_metadata() {
        let vault_id = rekey_domain::ids::VaultId::new_random();
        let trust = "a".repeat(64);
        // A synthetic object isolates wire size from policy schema validation.
        let mut unsigned = serde_json::json!({"payload":""});
        let encode = |unsigned: &serde_json::Value| {
            let mut signed = unsigned.clone();
            signed["signature"] = "A".repeat(96).into();
            serde_json::to_vec(&rekey_domain::ipc::PolicyActivateMeta {
                expected_vault_id: vault_id,
                expected_trust_sha256: trust.clone(),
                bundle_json: serde_json::value::RawValue::from_string(
                    serde_json::to_string(&signed).unwrap(),
                )
                .unwrap(),
            })
            .unwrap()
        };
        let padding = rekey_domain::ipc::METADATA_MAX_BYTES as usize - encode(&unsigned).len();
        for extra in [0, 1] {
            unsigned["payload"] = "x".repeat(padding + extra).into();
            assert_eq!(
                encode(&unsigned).len(),
                rekey_domain::ipc::METADATA_MAX_BYTES as usize + extra
            );
            let sign_len = b"RKPOLICY\0\x01".len() + serde_jcs::to_vec(&unsigned).unwrap().len();
            let result = super::ensure_activation_metadata_fits(vault_id, &trust, sign_len);
            assert_eq!(result.is_ok(), extra == 0);
            if let Err(error) = result {
                assert!(matches!(
                    error,
                    BrokerError::Policy(rekey_policy::PolicyError::TooLarge)
                ));
            }
        }
    }

    #[tokio::test]
    async fn personal_draft_coordinator_timeout_does_not_mutate_or_lock() {
        let fixture = PolicyFixture::new().await;
        let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&fixture.state)).unwrap();
        let count = || {
            db.query_row("SELECT count(*) FROM audit_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        };
        let before = count();
        let owner = fixture.ctx.lifecycle.coordinate().await;
        let error = fixture
            .ctx
            .personal_policy_draft_until(
                rekey_domain::ipc::PersonalPolicyDraftMeta {
                    connections: vec![],
                    ssh_keys: None,
                    derived_credentials: None,
                    expected_policy_sha256: None,
                    expires_at_ms: fixture.expires,
                },
                tokio::time::Instant::now() + Duration::from_millis(20),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BrokerError::Admission(AuthorityError::AuthorityBusy)
        ));
        assert!(fixture.ctx.lifecycle.is_running());
        assert_eq!(count(), before);
        drop(owner);
        drop(db);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn policy_status_uses_actual_material_and_preserves_expiry_latch() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let proof = || UnlockProof::Password(SecretInput::from_slice(b"fixture-proof"));
        let initialized = init_vault(
            &state,
            &SecretInput::from_slice(b"fixture-proof"),
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
            rekey_domain::authorization::PolicyMode::Team,
        )
        .unwrap();
        confirm_vault_init(&state).unwrap();
        let (authority, join) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone())).unwrap();
        let sessions = Arc::new(SessionRegistry::new());
        let transport: Arc<dyn UpstreamTransport> = Arc::new(ReqwestUpstreamTransport);
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter_running().unwrap();
        let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
        let policy = Arc::new(RwLock::new(None));
        let executor = Arc::new(ActionExecutor::new(
            authority.clone(),
            sessions.clone(),
            transport.clone(),
            lifecycle.clone(),
            terminals.clone(),
            policy.clone(),
        ));
        let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
        drop(supervisor);
        let (shutdown_tx, _) = watch::channel(false);
        let (stop_tx, _) = mpsc::unbounded_channel();
        let ctx = BrokerCtx {
            state_dir: state.clone(),
            #[cfg(feature = "lab")]
            oidc_admin: None,
            #[cfg(feature = "lab")]
            metrics: crate::metrics::Metrics::default(),
            authority: authority.clone(),
            sessions,
            executions,
            local_calls: Arc::clone(&executor.local_calls),
            executor,
            #[cfg(feature = "lab")]
            workload_transport: transport,
            #[cfg(feature = "lab")]
            online_jwks_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            lifecycle,
            policy,
            policy_trust: Arc::new(RwLock::new(None)),
            terminals,
            drain_timeout: Duration::from_secs(1),
            gateway: gateway::Gateway::default(),
            shutdown_flag: AtomicBool::new(false),
            shutdown_tx,
            stop_tx,
            allowed_agent_uids: vec![unsafe { libc::geteuid() }].into(),
        };
        let locked = ctx.policy_status().await.unwrap();
        locked.validate().unwrap();
        assert_eq!(locked.vault_id, initialized.vault_id);
        assert_eq!(locked.tenant_id.as_bytes(), initialized.vault_id.as_bytes());
        assert!(locked.trust_sha256.is_none());
        assert!(locked.activated_at_ms.is_none());
        assert!(locked.mode.is_none());
        assert!(locked.algorithm.is_none());
        authority.unlock(proof()).await.unwrap();
        let initialized_status = ctx.policy_status().await.unwrap();
        initialized_status.validate().unwrap();
        assert!(initialized_status.trust_sha256.is_none());
        assert_eq!(
            initialized_status.mode,
            Some(rekey_domain::authorization::PolicyMode::Team)
        );
        assert!(initialized_status.algorithm.is_none());
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let signer_id = rekey_domain::ids::PolicySignerId::new_random();
        let trust = rekey_policy::parse_policy_trust(&serde_json::to_vec(&serde_json::json!({
            "format_version":1,"signer_id":signer_id,"algorithm":"ed25519","public_key":data_encoding::HEXLOWER.encode(signer.public_key().as_ref())
        })).unwrap()).unwrap();
        let deadline = || tokio::time::Instant::now() + Duration::from_secs(5);
        ctx.install_policy_trust_until(trust.clone(), proof(), deadline())
            .await
            .unwrap();
        let before = ctx.policy_status().await.unwrap();
        before.validate().unwrap();
        assert_eq!(before.status, "unavailable");
        assert!(before.trust_sha256.is_some());
        assert!(before.activated_at_ms.is_none());
        assert_eq!(
            before.algorithm,
            Some(rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519)
        );
        let expires = crate::now_ts().unwrap().as_unix_ms() + 60_000;
        let bundle = |version| {
            let mut unsigned = serde_json::json!({"format_version":1,"signer_id":signer_id,"snapshot":{
                "format_version":7,"version":version,"expires_at_ms":expires,"approvers":[],"connections":[], "ssh_keys":[], "derived_credentials":[], "profiles": [], "workload_identities":[],"bindings":[],"rules":[]
            }});
            let mut message = b"RKPOLICY\0\x01".to_vec();
            message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
            unsigned.as_object_mut().unwrap().insert(
                "signature".into(),
                data_encoding::BASE64URL_NOPAD
                    .encode(signer.sign(&message).as_ref())
                    .into(),
            );
            serde_jcs::to_vec(&unsigned).unwrap()
        };
        let metadata = |bytes: &[u8]| rekey_domain::ipc::PolicyActivateMeta {
            expected_vault_id: initialized.vault_id,
            expected_trust_sha256: before.trust_sha256.clone().unwrap(),
            bundle_json: serde_json::from_slice(bytes).unwrap(),
        };
        let first = bundle(1);
        ctx.activate_policy_until(metadata(&first), proof(), deadline())
            .await
            .unwrap();
        let active = ctx.policy_status().await.unwrap();
        active.validate().unwrap();
        assert_eq!(active.status, "active");
        assert_eq!(active.version, Some(1));
        assert_eq!(
            active.activated_at_ms,
            Some(
                authority
                    .policy_material()
                    .await
                    .unwrap()
                    .bundle
                    .unwrap()
                    .activated_at_ms
            )
        );
        ctx.activate_policy_until(metadata(&first), proof(), deadline())
            .await
            .unwrap();
        assert_eq!(
            ctx.policy_status().await.unwrap().activated_at_ms,
            active.activated_at_ms
        );
        let current = ctx.policy.read().await.clone().unwrap();
        assert!(current.is_expired(rekey_domain::Timestamp::from_unix_ms(expires)));
        assert_eq!(ctx.policy_status().await.unwrap().status, "expired");
        ctx.reload_policy_after_unlock().await.unwrap();
        assert_eq!(ctx.policy_status().await.unwrap().status, "expired");
        let different =
            rekey_policy::parse_and_verify_policy_bundle_for_load(&bundle(2), &trust).unwrap();
        *ctx.policy.write().await = Some(Arc::new(ActivePolicy::load_bundle(
            different,
            crate::now_ts().unwrap(),
        )));
        let mismatched = ctx.policy_status().await.unwrap();
        assert_eq!(mismatched.status, "unavailable");
        assert!(mismatched.activated_at_ms.is_none());
        assert!(mismatched.version.is_none());
        *ctx.policy.write().await = Some(current);
        authority.lock("test").await.unwrap();
        let locked = ctx.policy_status().await.unwrap();
        locked.validate().unwrap();
        assert_eq!(locked.vault_id, initialized.vault_id);
        assert!(locked.trust_sha256.is_none());
        assert!(locked.activated_at_ms.is_none());
        assert!(locked.mode.is_none());
        assert!(locked.algorithm.is_none());
        authority.unlock(proof()).await.unwrap();
        ctx.reload_policy_after_unlock().await.unwrap();
        assert_eq!(ctx.policy_status().await.unwrap().status, "expired");
        let connection = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_policy_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='policy.activated' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        let error = ctx
            .activate_policy_until(metadata(&bundle(2)), proof(), deadline())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BrokerError::Authority(AuthorityError::AuditCommitFailed)
        ));
        let faulted = ctx.policy_status().await.unwrap();
        faulted.validate().unwrap();
        assert_eq!(faulted.vault_id, initialized.vault_id);
        assert_eq!(faulted.status, "unavailable");
        assert!(faulted.trust_sha256.is_none());
        assert!(faulted.activated_at_ms.is_none());
        authority.shutdown(None).await.unwrap();
        join.join().unwrap();
        terminal_task.abort();
    }

    struct PolicyFixture {
        _dir: tempfile::TempDir,
        state: std::path::PathBuf,
        ctx: BrokerCtx,
        join: std::thread::JoinHandle<()>,
        terminal_task: tokio::task::JoinHandle<()>,
        signer: Ed25519KeyPair,
        trust: rekey_policy::ValidatedPolicyTrust,
        vault_id: rekey_domain::ids::VaultId,
        approver_id: rekey_domain::ids::ApproverId,
        expires: i64,
    }

    fn proof() -> UnlockProof {
        UnlockProof::Password(SecretInput::from_slice(b"fixture-proof"))
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(5)
    }

    impl PolicyFixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let state = dir.path().join("state");
            let initialized = init_vault(
                &state,
                &SecretInput::from_slice(b"fixture-proof"),
                Argon2Params {
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1,
                },
                rekey_domain::authorization::PolicyMode::Team,
            )
            .unwrap();
            confirm_vault_init(&state).unwrap();
            let (authority, join) =
                rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.clone()))
                    .unwrap();
            let sessions = Arc::new(SessionRegistry::new());
            let transport: Arc<dyn UpstreamTransport> = Arc::new(ReqwestUpstreamTransport);
            let lifecycle = Arc::new(Lifecycle::new());
            lifecycle.enter_running().unwrap();
            let (terminals, terminal_task) = spawn_terminal_worker(authority.clone());
            let policy = Arc::new(RwLock::new(None));
            let executor = Arc::new(ActionExecutor::new(
                authority.clone(),
                sessions.clone(),
                transport.clone(),
                lifecycle.clone(),
                terminals.clone(),
                policy.clone(),
            ));
            let (executions, supervisor) = crate::execution_supervisor::new(executor.clone());
            drop(supervisor);
            let (shutdown_tx, _) = watch::channel(false);
            let (stop_tx, _) = mpsc::unbounded_channel();
            let ctx = BrokerCtx {
                state_dir: state.clone(),
                #[cfg(feature = "lab")]
                oidc_admin: None,
                #[cfg(feature = "lab")]
                metrics: crate::metrics::Metrics::default(),
                authority: authority.clone(),
                sessions,
                executions,
                local_calls: Arc::clone(&executor.local_calls),
                executor,
                #[cfg(feature = "lab")]
                workload_transport: transport,
                #[cfg(feature = "lab")]
                online_jwks_slots: Arc::new(tokio::sync::Semaphore::new(2)),
                lifecycle,
                policy,
                policy_trust: Arc::new(RwLock::new(None)),
                terminals,
                drain_timeout: Duration::from_secs(1),
                gateway: gateway::Gateway::default(),
                shutdown_flag: AtomicBool::new(false),
                shutdown_tx,
                stop_tx,
                allowed_agent_uids: vec![unsafe { libc::geteuid() }].into(),
            };

            authority.unlock(proof()).await.unwrap();
            ctx.sessions.open_for_admission();
            let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let signer = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
            let trust = rekey_policy::ValidatedPolicyTrust::from_parts(
                rekey_domain::ids::PolicySignerId::new_random(),
                rekey_policy::PolicyVerificationKey::from_bytes(
                    rekey_domain::authorization::PolicyTrustAlgorithm::Ed25519,
                    signer.public_key().as_ref(),
                )
                .unwrap(),
            );
            ctx.install_policy_trust_until(trust.clone(), proof(), deadline())
                .await
                .unwrap();
            Self {
                _dir: dir,
                state,
                ctx,
                join,
                terminal_task,
                signer,
                trust,
                vault_id: initialized.vault_id,
                approver_id: rekey_domain::ids::ApproverId::new_random(),
                expires: crate::now_ts().unwrap().as_unix_ms() + 60_000,
            }
        }

        fn bundle(&self, version: u64) -> Vec<u8> {
            let unsigned = serde_json::json!({
                "format_version": 1, "signer_id": self.trust.signer_id(),
                "snapshot": {
                    "format_version": 7, "version": version, "expires_at_ms": self.expires,
                    "approvers": [{"approver_id": self.approver_id, "algorithm": "ed25519",
                        "public_key": data_encoding::HEXLOWER.encode(self.signer.public_key().as_ref())}],
                    "connections":[], "ssh_keys":[], "derived_credentials":[], "profiles": [], "workload_identities": [], "bindings": [], "rules": []
                }
            });
            self.sign(unsigned, b"RKPOLICY\0\x01")
        }

        fn sign(&self, mut unsigned: serde_json::Value, prefix: &[u8]) -> Vec<u8> {
            let mut message = prefix.to_vec();
            message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
            unsigned.as_object_mut().unwrap().insert(
                "signature".into(),
                data_encoding::BASE64URL_NOPAD
                    .encode(self.signer.sign(&message).as_ref())
                    .into(),
            );
            serde_jcs::to_vec(&unsigned).unwrap()
        }

        fn metadata(&self, bytes: &[u8]) -> rekey_domain::ipc::PolicyActivateMeta {
            rekey_domain::ipc::PolicyActivateMeta {
                expected_vault_id: self.vault_id,
                expected_trust_sha256: data_encoding::HEXLOWER.encode(
                    &rekey_policy::policy_trust_sha256(self.trust.signer_id(), self.trust.key())
                        .unwrap(),
                ),
                bundle_json: serde_json::from_slice(bytes).unwrap(),
            }
        }

        async fn activate(&self, version: u64) {
            self.ctx
                .activate_policy_until(self.metadata(&self.bundle(version)), proof(), deadline())
                .await
                .unwrap();
        }

        fn session(
            &self,
            provenance: rekey_domain::capability::SessionProvenance,
        ) -> (
            String,
            rekey_domain::capability::SessionGrant,
            rekey_domain::capability::ActionVersionRef,
        ) {
            use rekey_domain::ids::{ActionId, PrincipalId, SessionId, TenantId};
            let action = rekey_domain::capability::ActionVersionRef {
                action_id: ActionId::new_random(),
                version: 1,
            };
            let session_id = SessionId::new_random();
            let grant = rekey_domain::capability::SessionGrant::new(
                session_id,
                rekey_domain::authorization::Principal {
                    tenant_id: TenantId::from_bytes(*self.vault_id.as_bytes()).unwrap(),
                    principal_id: PrincipalId::new_random(),
                    session_id,
                },
                vec![action],
                crate::now_ts().unwrap(),
                60_000,
                100,
            )
            .unwrap();
            let token = self
                .ctx
                .sessions
                .admit_with_provenance(grant.clone(), vec![(action, 1000)], provenance)
                .unwrap();
            (token, grant, action)
        }

        fn assert_live(&self, token: &str, action: rekey_domain::capability::ActionVersionRef) {
            drop(
                self.ctx
                    .sessions
                    .acquire(token, action, crate::now_ts().unwrap())
                    .unwrap(),
            );
        }

        fn assert_revoked(&self, token: &str, action: rekey_domain::capability::ActionVersionRef) {
            assert!(matches!(
                self.ctx
                    .sessions
                    .begin(token, action, crate::now_ts().unwrap()),
                Err(BrokerError::Domain(
                    rekey_domain::DomainError::InvalidCapability
                ))
            ));
        }

        async fn finish(self) {
            self.ctx.authority.shutdown(Some(proof())).await.unwrap();
            self.join.join().unwrap();
            self.terminal_task.abort();
        }
    }

    #[tokio::test]
    async fn policy_roll_forward_revokes_mixed_sessions_and_pending_grants() {
        use rekey_domain::authorization::{
            ApprovalMode, ApprovalRequirement, ResourceRef, SchemaId,
        };
        use rekey_domain::capability::SessionProvenance::{Admin, Workload};
        use rekey_domain::ids::{ApprovalId, ApprovalRequestId, PolicyRuleId};
        let f = PolicyFixture::new().await;
        let (admin, _, action) = f.session(Admin);
        let (workload, _, workload_action) = f.session(Workload);
        f.activate(1).await;
        f.assert_live(&admin, action);
        f.assert_revoked(&workload, workload_action);
        let active = f.ctx.policy.read().await.clone().unwrap();
        let before = f
            .ctx
            .authority
            .policy_material()
            .await
            .unwrap()
            .bundle
            .unwrap();
        let (workload, _, workload_action) = f.session(Workload);
        let (pending_token, pending_session, pending_action) = f.session(Admin);
        let permit = f
            .ctx
            .sessions
            .acquire(&pending_token, pending_action, crate::now_ts().unwrap())
            .unwrap();
        let now = crate::now_ts().unwrap();
        let challenge = rekey_domain::ipc::ApprovalChallenge {
            record_type: "rekey.approval.challenge.v2".to_owned(),
            approval_request_id: ApprovalRequestId::new_random(),
            tenant_id: pending_session.principal.tenant_id,
            principal_id: pending_session.principal.principal_id,
            session_id: pending_session.id,
            action_id: pending_action.action_id,
            action_version: 1,
            resource: ResourceRef::new("test.resource".into(), "one".into()).unwrap(),
            schema_id: SchemaId::new("test/v1".into()).unwrap(),
            parameter_sha256: "00".repeat(32),
            policy_version: 1,
            policy_sha256: data_encoding::HEXLOWER.encode(&active.snapshot().digest()),
            policy_rule_id: PolicyRuleId::new_random(),
            mode: ApprovalMode::OneTime,
            approver: rekey_domain::authorization::ApproverSpec::Ed25519 {
                keys: vec![data_encoding::HEXLOWER.encode(f.signer.public_key().as_ref())],
                threshold: 1,
            },
            max_uses: 1,
            created_at_ms: now.as_unix_ms(),
            max_expires_at_ms: now.as_unix_ms() + 30_000,
        };
        challenge.validate().unwrap();
        f.ctx
            .sessions
            .store_approval_challenge(
                challenge.clone(),
                std::time::Instant::now(),
                std::time::Instant::now() + Duration::from_secs(30),
                now,
            )
            .unwrap();
        let signed = f.sign(serde_json::json!({
            "format_version": 1, "approval_id": ApprovalId::new_random(),
            "approval_request_id": challenge.approval_request_id, "approver_id": f.approver_id,
            "tenant_id": challenge.tenant_id, "principal_id": challenge.principal_id,
            "session_id": challenge.session_id, "action_id": challenge.action_id,
            "action_version": challenge.action_version, "resource": challenge.resource,
            "schema_id": challenge.schema_id, "parameter_sha256": challenge.parameter_sha256,
            "policy_version": challenge.policy_version, "policy_sha256": challenge.policy_sha256,
            "policy_rule_id": challenge.policy_rule_id, "mode": challenge.mode,
            "not_before_ms": challenge.created_at_ms, "expires_at_ms": challenge.max_expires_at_ms,
            "max_uses": 1,
        }), b"RKAPPROVAL\0\x01");
        let grant =
            rekey_policy::parse_and_verify_approval_grant(&signed, active.snapshot()).unwrap();
        let context = crate::session::ApprovalContext {
            principal: pending_session.principal,
            action: pending_action,
            resource: challenge.resource.clone(),
            schema_id: challenge.schema_id.clone(),
            parameter_hash: [0; 32],
            policy_version: 1,
            policy_digest: active.snapshot().digest(),
            policy_rule_id: challenge.policy_rule_id,
            approver: challenge.approver.clone(),
            allowed_approver_ids: vec![f.approver_id],
            requirement: ApprovalRequirement {
                mode: ApprovalMode::OneTime,
                max_uses: 1,
                max_window_ms: None,
            },
        };
        f.activate(1).await;
        f.assert_live(&admin, action);
        f.assert_live(&workload, workload_action);
        f.assert_live(&pending_token, pending_action);
        assert_eq!(
            f.ctx
                .sessions
                .pending_approval_challenges(crate::now_ts().unwrap())
                .unwrap()
                .len(),
            1
        );
        assert!(Arc::ptr_eq(
            &active,
            f.ctx.policy.read().await.as_ref().unwrap()
        ));
        assert_eq!(
            before.activated_at_ms,
            f.ctx
                .authority
                .policy_material()
                .await
                .unwrap()
                .bundle
                .unwrap()
                .activated_at_ms
        );
        f.activate(2).await;
        f.assert_revoked(&admin, action);
        f.assert_revoked(&workload, workload_action);
        f.assert_revoked(&pending_token, pending_action);
        assert_eq!(f.ctx.sessions.in_flight_total(), 1);
        assert!(
            f.ctx
                .sessions
                .pending_approval_challenges(crate::now_ts().unwrap())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            f.ctx
                .sessions
                .approval_challenge(challenge.approval_request_id, crate::now_ts().unwrap())
                .unwrap_err()
                .code(),
            "approval-challenge-unknown"
        );
        assert_eq!(
            f.ctx
                .sessions
                .reserve_approvals(&context, &[grant], crate::now_ts().unwrap())
                .err()
                .unwrap()
                .code(),
            "approval-session-unavailable"
        );
        drop(permit);
        let (replacement, _, replacement_action) = f.session(Admin);
        f.assert_live(&replacement, replacement_action);
        let connection =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type='policy.activated'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        f.finish().await;
    }

    #[tokio::test]
    async fn policy_activation_failures_preserve_healthy_sessions() {
        use rekey_domain::capability::SessionProvenance::{Admin, Workload};
        let f = PolicyFixture::new().await;
        f.activate(1).await;
        let (admin, _, action) = f.session(Admin);
        let (workload, _, workload_action) = f.session(Workload);
        let before = f
            .ctx
            .authority
            .policy_material()
            .await
            .unwrap()
            .bundle
            .unwrap();
        let mut wrong_vault = f.metadata(&f.bundle(2));
        wrong_vault.expected_vault_id = rekey_domain::ids::VaultId::new_random();
        let mut wrong_trust = f.metadata(&f.bundle(2));
        wrong_trust.expected_trust_sha256 = "00".repeat(32);
        let mut invalid_signature: serde_json::Value =
            serde_json::from_slice(&f.bundle(2)).unwrap();
        invalid_signature["signature"] = data_encoding::BASE64URL_NOPAD.encode(&[0; 64]).into();
        for (metadata, unlock_proof, expected_code) in [
            (wrong_vault, proof(), "POLICY_VERSION_CONFLICT"),
            (wrong_trust, proof(), "POLICY_VERSION_CONFLICT"),
            (f.metadata(&f.bundle(3)), proof(), "POLICY_VERSION_CONFLICT"),
            (
                f.metadata(&serde_json::to_vec(&invalid_signature).unwrap()),
                proof(),
                "POLICY_INVALID",
            ),
            (
                f.metadata(&f.bundle(2)),
                UnlockProof::Password(SecretInput::from_slice(b"wrong-fixture-proof")),
                "INVALID_UNLOCK_CREDENTIAL",
            ),
        ] {
            let error = f
                .ctx
                .activate_policy_until(metadata, unlock_proof, deadline())
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected_code);
            f.assert_live(&admin, action);
            f.assert_live(&workload, workload_action);
            assert_eq!(f.ctx.policy_status().await.unwrap().version, Some(1));
            assert_eq!(
                before.activated_at_ms,
                f.ctx
                    .authority
                    .policy_material()
                    .await
                    .unwrap()
                    .bundle
                    .unwrap()
                    .activated_at_ms
            );
        }
        let connection =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_policy_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='policy.activated' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(matches!(
            f.ctx
                .activate_policy_until(f.metadata(&f.bundle(2)), proof(), deadline())
                .await,
            Err(BrokerError::Authority(AuthorityError::AuditCommitFailed))
        ));
        f.assert_live(&admin, action);
        f.assert_live(&workload, workload_action);
        assert_eq!(
            connection
                .query_row("SELECT version FROM policy_bundle", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        f.finish().await;
    }

    // Block a real SQLite write beyond the Broker deadline. The Authority
    // generation commit checks the deadline again before reserving anchors;
    // reconciliation must observe the actual rollback or fault.
    fn hold_policy_store(f: &PolicyFixture, fail_audit: bool) -> std::thread::JoinHandle<()> {
        let connection =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
        if fail_audit {
            connection.execute_batch("CREATE TRIGGER fail_policy_audit BEFORE INSERT ON audit_events WHEN NEW.event_type='policy.activated' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        }
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            connection.execute_batch("COMMIT").unwrap();
        })
    }

    #[tokio::test]
    async fn policy_timeout_before_generation_reservation_preserves_state() {
        use rekey_domain::capability::SessionProvenance::{Admin, Workload};
        for version in [1, 2] {
            let f = PolicyFixture::new().await;
            if version == 2 {
                f.activate(1).await;
            }
            let (admin, _, action) = f.session(Admin);
            let (workload, _, workload_action) = f.session(Workload);
            let database_state = || {
                let db =
                    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state)).unwrap();
                [
                    "vault_header",
                    "policy_state",
                    "policy_trust",
                    "policy_bundle",
                    "audit_events",
                ]
                .map(|table| {
                    let mut query = db
                        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                        .unwrap();
                    let columns = query.column_count();
                    query
                        .query_map([], |row| {
                            (0..columns)
                                .map(|column| row.get::<_, rusqlite::types::Value>(column))
                                .collect::<rusqlite::Result<Vec<_>>>()
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap()
                })
            };
            let before = database_state();
            let anchor = std::fs::read(f.state.join("generation")).unwrap();
            let lock = hold_policy_store(&f, false);
            let error = f
                .ctx
                .activate_policy_until(
                    f.metadata(&f.bundle(version)),
                    proof(),
                    tokio::time::Instant::now() + Duration::from_millis(100),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                BrokerError::Authority(AuthorityError::AuthorityBusy)
            ));
            lock.join().unwrap();
            assert_eq!(
                f.ctx.policy_status().await.unwrap().version,
                (version == 2).then_some(1)
            );
            assert_eq!(database_state(), before);
            assert_eq!(std::fs::read(f.state.join("generation")).unwrap(), anchor);
            f.assert_live(&admin, action);
            f.assert_live(&workload, workload_action);
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn policy_timeout_retry_and_unapplied_target_preserve_sessions_and_expiry_latch() {
        use rekey_domain::capability::SessionProvenance::{Admin, Workload};
        for version in [1, 2] {
            let f = PolicyFixture::new().await;
            f.activate(1).await;
            let current = f.ctx.policy.read().await.clone().unwrap();
            assert!(current.is_expired(rekey_domain::Timestamp::from_unix_ms(f.expires)));
            let before = f
                .ctx
                .authority
                .policy_material()
                .await
                .unwrap()
                .bundle
                .unwrap();
            let (admin, _, action) = f.session(Admin);
            let (workload, _, workload_action) = f.session(Workload);
            let lock = hold_policy_store(&f, false);
            let mut blocked = Box::pin(f.ctx.authority.append_audit(
                rekey_vault::command::AuditDraft {
                    request_id: None,
                    session_id: None,
                    action_id: None,
                    action_version: None,
                    credential_id: None,
                    credential_version: None,
                    authorization: None,
                    approval: None,
                    request_context: None,
                    usage: None,
                    event_type: rekey_vault::model::event_type::SESSION_REVOKED,
                    outcome: rekey_vault::model::outcome::SUCCESS,
                    reason_code: "fixture-queued".into(),
                    upstream_status: None,
                    latency_ms: None,
                },
            ));
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(blocked.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            let error = f
                .ctx
                .activate_policy_until(
                    f.metadata(&f.bundle(version)),
                    proof(),
                    tokio::time::Instant::now() + Duration::from_millis(100),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                BrokerError::Authority(AuthorityError::AuthorityBusy)
            ));
            blocked.await.unwrap();
            lock.join().unwrap();
            f.assert_live(&admin, action);
            f.assert_live(&workload, workload_action);
            assert!(Arc::ptr_eq(
                &current,
                f.ctx.policy.read().await.as_ref().unwrap()
            ));
            assert_eq!(f.ctx.policy_status().await.unwrap().status, "expired");
            let after = f
                .ctx
                .authority
                .policy_material()
                .await
                .unwrap()
                .bundle
                .unwrap();
            assert_eq!(before.activated_at_ms, after.activated_at_ms);
            assert_eq!(after.version, 1);
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn policy_timeout_failed_reconciliation_faults_and_closes_sessions() {
        use rekey_domain::capability::SessionProvenance::{Admin, Workload};
        let f = PolicyFixture::new().await;
        f.activate(1).await;
        let (admin, _, action) = f.session(Admin);
        let (workload, _, workload_action) = f.session(Workload);
        let lock = hold_policy_store(&f, true);
        let error = f
            .ctx
            .activate_policy_until(
                f.metadata(&f.bundle(2)),
                proof(),
                tokio::time::Instant::now() + Duration::from_millis(100),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BrokerError::Authority(AuthorityError::Faulted)
        ));
        lock.join().unwrap();
        f.assert_revoked(&admin, action);
        f.assert_revoked(&workload, workload_action);
        assert!(f.ctx.policy.read().await.is_none());
        assert!(f.ctx.policy_trust.read().await.is_none());
        assert_ne!(
            f.ctx.lifecycle.phase(),
            crate::lifecycle::BrokerPhase::Running
        );
        #[cfg(feature = "lab")]
        assert_eq!(f.ctx.metrics.fault_signals.load(Ordering::Relaxed), 1);
        f.finish().await;
    }
}
