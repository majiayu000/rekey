use std::sync::Arc;

use rekey_domain::ipc::PolicyStatusResponse;
use rekey_policy::{ValidatedPolicyTrust, parse_and_verify_policy_bundle_for_load};
use rekey_vault::AuthorityError;
use rekey_vault::command::UnlockProof;

use super::BrokerCtx;
use crate::active_policy::ActivePolicy;
use crate::error::BrokerError;

const POLICY_RECONCILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl BrokerCtx {
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
            .map(|trust| rekey_policy::policy_trust_sha256(trust.signer_id, &trust.public_key))
            .transpose()?
            .map(|digest| data_encoding::HEXLOWER.encode(&digest));
        let mut response = PolicyStatusResponse {
            vault_id: authority.vault_id,
            tenant_id,
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
            .map(|record| ValidatedPolicyTrust::from_parts(record.signer_id, record.public_key));
        let active = match (trust.as_ref(), material.bundle) {
            (_, None) => None,
            (Some(trust), Some(record)) => {
                let verified =
                    match parse_and_verify_policy_bundle_for_load(&record.bundle_json, trust) {
                        Ok(verified)
                            if verified.signer_id() == record.signer_id
                                && verified.snapshot().version().get() == record.version
                                && verified.snapshot().expires_at_ms() == record.expires_at_ms
                                && verified.policy_digest() == record.policy_digest
                                && verified.bundle_digest() == record.bundle_digest =>
                        {
                            verified
                        }
                        _ => {
                            drop(self.authority.fault_integrity().await);
                            return Err(BrokerError::Authority(
                                AuthorityError::StorageIntegrityFailed,
                            ));
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
                    public_key: *trust.public_key(),
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
                    return Err(BrokerError::Authority(AuthorityError::AuthorityBusy));
                }
                self.sessions.close_and_revoke_all();
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
            #[cfg(feature = "lab")]
            oidc_admin: None,
            #[cfg(feature = "lab")]
            metrics: crate::metrics::Metrics::default(),
            authority: authority.clone(),
            sessions,
            executions,
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
        authority.unlock(proof()).await.unwrap();
        assert!(ctx.policy_status().await.unwrap().trust_sha256.is_none());
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
        let expires = crate::now_ts().unwrap().as_unix_ms() + 60_000;
        let bundle = |version| {
            let mut unsigned = serde_json::json!({"format_version":1,"signer_id":signer_id,"snapshot":{
                "format_version":3,"version":version,"expires_at_ms":expires,"approvers":[],"workload_identities":[],"bindings":[],"rules":[]
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
                #[cfg(feature = "lab")]
                oidc_admin: None,
                #[cfg(feature = "lab")]
                metrics: crate::metrics::Metrics::default(),
                authority: authority.clone(),
                sessions,
                executions,
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
                signer.public_key().as_ref().try_into().unwrap(),
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
                    "format_version": 3, "version": version, "expires_at_ms": self.expires,
                    "approvers": [{"approver_id": self.approver_id, "algorithm": "ed25519",
                        "public_key": data_encoding::HEXLOWER.encode(self.signer.public_key().as_ref())}],
                    "workload_identities": [], "bindings": [], "rules": []
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
                    &rekey_policy::policy_trust_sha256(
                        self.trust.signer_id(),
                        self.trust.public_key(),
                    )
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
                Err(rekey_domain::DomainError::InvalidCapability)
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
            record_type: "rekey.approval.challenge.v1".to_owned(),
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
            quorum: 1,
            approver_ids: vec![f.approver_id],
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
            requirement: ApprovalRequirement {
                approver_ids: challenge.approver_ids.clone(),
                quorum: 1,
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

    // Block a real SQLite write beyond the Broker deadline. The Authority has
    // already checked that deadline when it reaches the blocked transaction;
    // reconciliation must observe the actual eventual commit or fault.
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
    async fn policy_timeout_reconciles_first_activation_and_roll_forward() {
        use rekey_domain::capability::SessionProvenance::{Admin, Workload};
        for version in [1, 2] {
            let f = PolicyFixture::new().await;
            if version == 2 {
                f.activate(1).await;
            }
            let (admin, _, action) = f.session(Admin);
            let (workload, _, workload_action) = f.session(Workload);
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
            assert_eq!(f.ctx.policy_status().await.unwrap().version, Some(version));
            if version == 1 {
                f.assert_live(&admin, action);
            } else {
                f.assert_revoked(&admin, action);
            }
            f.assert_revoked(&workload, workload_action);
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
