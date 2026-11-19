//! Default-build admin IPC contracts over the real Unix sockets: lab-only
//! entrypoints are refused before any effect, and A2 SHUTDOWN needs a current
//! proof in both lifecycle states. Synthetic vaults only.
mod common;

use std::time::Duration;

#[cfg(not(feature = "lab"))]
use rekey_domain::ipc::agent_msg;
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};

#[cfg(not(feature = "lab"))]
#[tokio::test(flavor = "multi_thread")]
async fn default_broker_rejects_lab_wire_entrypoints_and_source_registration() {
    let broker = common::start_broker().await;
    common::unlock(&broker).await;
    for operation in [
        admin_msg::METRICS,
        admin_msg::OIDC_LOGIN_BEGIN,
        admin_msg::CREDENTIAL_ROTATE_VAULT_KV,
    ] {
        let reply = common::call(&broker.admin_sock(), Channel::Admin, operation, b"{}", &[]).await;
        assert_eq!(reply.err_code(), "INVALID_FRAME");
    }
    let reply = common::call(
        &broker.agent_sock(),
        Channel::Agent,
        agent_msg::WORKLOAD_SESSION_CREATE,
        b"{}",
        b"synthetic.jwt",
    )
    .await;
    assert_eq!(reply.err_code(), "INVALID_FRAME");
    for kind in [
        "vault-kv-v2-source",
        "vault-dynamic-source",
        "keycloak-token-exchange",
        "gcp-secret-manager-source",
        "aws-secrets-manager-source",
        "azure-key-vault-source",
        "onepassword-connect-source",
        "macos-keychain-source",
    ] {
        let metadata = serde_json::json!({"label":"lab-source", "kind":kind}).to_string();
        let reply = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::CREDENTIAL_ADD,
            metadata.as_bytes(),
            &common::proof_and_secret_body(common::PASSWORD, b"synthetic-profile"),
        )
        .await;
        assert_eq!(reply.err_code(), "INVALID_INPUT", "{kind}");
    }
    let reply = common::call(
        &broker.admin_sock(),
        Channel::Admin,
        admin_msg::CREDENTIAL_LIST,
        b"{}",
        &[],
    )
    .await;
    assert!(reply.ok()["credentials"].as_array().unwrap().is_empty());
    broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_shutdown_requires_current_proof_in_locked_and_unlocked_states() {
    for locked in [false, true] {
        for recovery_factor in [false, true] {
            let broker = common::start_broker().await;
            let admin = broker.admin_sock();
            common::unlock(&broker).await;
            let recovery = common::call(
                &admin,
                Channel::Admin,
                admin_msg::RECOVERY_ROTATE,
                b"{}",
                &common::proof_body(common::PASSWORD),
            )
            .await
            .body;
            if locked {
                common::call(&admin, Channel::Admin, admin_msg::LOCK, b"{}", &[])
                    .await
                    .ok();
            }
            let mut wrong_recovery = Vec::new();
            ipc::encode_proof_body(
                ProofKind::Recovery,
                b"invalid-recovery",
                &mut wrong_recovery,
            );
            for (body, code) in [
                (Vec::new(), "AUTHENTICATION_FAILED"),
                (
                    common::proof_body(b"incorrect"),
                    "INVALID_UNLOCK_CREDENTIAL",
                ),
                (wrong_recovery, "INVALID_UNLOCK_CREDENTIAL"),
            ] {
                let reply =
                    common::call(&admin, Channel::Admin, admin_msg::SHUTDOWN, b"{}", &body).await;
                assert_eq!(reply.err_code(), code);
                assert!(!broker.serve_task.is_finished());
                let status =
                    common::call(&admin, Channel::Admin, admin_msg::STATUS, b"{}", &[]).await;
                assert_eq!(
                    status.ok()["state"],
                    if locked { "locked" } else { "unlocked" }
                );
            }
            let mut body = Vec::new();
            let (kind, proof) = if recovery_factor {
                (ProofKind::Recovery, recovery.as_slice())
            } else {
                (ProofKind::Password, common::PASSWORD)
            };
            ipc::encode_proof_body(kind, proof, &mut body);
            let reply =
                common::call(&admin, Channel::Admin, admin_msg::SHUTDOWN, b"{}", &body).await;
            assert_eq!(reply.ok()["shutdown"], true);
            tokio::time::timeout(Duration::from_secs(5), broker.serve_task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}

/// Profile lookup/issuance (58/59) and capability sessions (12/13) are lab
/// only. A signed policy8 snapshot may still carry a valid Profile; the default
/// daemon must refuse before taking the coordinator, touching the Authority or
/// writing audit. Opcode 60 is the default Connection list and stays available.
#[cfg(not(feature = "lab"))]
mod profile_gating {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use rekey_broker::runtime::{BrokerConfig, serve};
    use rekey_broker::testing::FakeUpstreamTransport;
    use rekey_domain::action::FixedHttpAction;
    use rekey_domain::credential::{CredentialKind, CredentialLabel};
    use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId, RequestId, SessionId};
    use rekey_domain::ipc::{Channel, admin_msg, agent_msg};
    use rekey_vault::command::UnlockProof;
    use rekey_vault::handle::AuthorityConfig;
    use rekey_vault::secret::SecretInput;
    use serde_json::{Value, json};
    use tokio::net::UnixStream;

    use super::common;

    fn password() -> UnlockProof {
        UnlockProof::Password(SecretInput::from_slice(common::PASSWORD))
    }

    /// TEMPLATE_INSTALL is lab-only on the wire, so a standalone Authority
    /// seeds the template-source Action a Profile must reference.
    async fn seed_template_action(state: &Path) -> FixedHttpAction {
        let (handle, join) =
            rekey_vault::authority::spawn_authority(AuthorityConfig::new(state.to_owned()))
                .unwrap();
        handle.unlock(password()).await.unwrap();
        let credential = handle
            .credential_add(
                CredentialLabel::new("profile-gating").unwrap(),
                CredentialKind::OpaqueToken,
                SecretInput::from_slice(b"SYNTHETIC-PROFILE-GATING"),
                password(),
            )
            .await
            .unwrap();
        let install = serde_json::from_value(json!({
            "source":{"kind":"generic-bearer","origin":"https://api.example.com",
                "actions":[{"method":"POST","path":"/run"}]},
            "credential_id":credential.id,"bindings":[{}],"capabilities":["fixed-actions"],
            "name_prefix":"gating","timeout_ms":1000,"request_max_bytes":1024,
            "allowed_extra_headers":[],"response_max_bytes":1024,"allowed_response_headers":[]
        }))
        .unwrap();
        let action = handle
            .template_install_before(install, vec![], password(), RequestId::new_random(), None)
            .await
            .unwrap()
            .actions
            .remove(0)
            .action;
        handle.shutdown(Some(password())).await.unwrap();
        join.join().unwrap();
        action
    }

    struct Seeded {
        _dir: tempfile::TempDir,
        state: PathBuf,
        task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    }

    impl Seeded {
        fn admin_sock(&self) -> PathBuf {
            self.state.join("runtime/admin.sock")
        }

        async fn call(&self, opcode: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
            common::call(
                &self.admin_sock(),
                Channel::Admin,
                opcode,
                &serde_json::to_vec(&metadata).unwrap(),
                body,
            )
            .await
        }

        fn audit_count(&self, event: Option<&str>) -> i64 {
            let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.state)).unwrap();
            match event {
                Some(event) => db.query_row(
                    "SELECT count(*) FROM audit_events WHERE event_type=?1",
                    [event],
                    |row| row.get(0),
                ),
                None => db.query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0)),
            }
            .unwrap()
        }

        /// Serves a vault whose active signed policy8 snapshot holds a valid Profile.
        async fn start() -> (Self, FixedHttpAction, PrincipalId) {
            let dir = tempfile::tempdir().unwrap();
            let state = dir.path().join("state");
            rekey_vault::bootstrap::init_vault(
                &state,
                &SecretInput::from_slice(common::PASSWORD),
                common::TEST_PARAMS,
                rekey_domain::authorization::PolicyMode::Team,
            )
            .unwrap();
            rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
            let action = seed_template_action(&state).await;
            let mut config = BrokerConfig::new(state.clone());
            config.transport = Some(Arc::new(FakeUpstreamTransport::new()));
            config.unlock_backoff_base = Duration::from_millis(20);
            let seeded = Self {
                _dir: dir,
                task: tokio::spawn(serve(config)),
                state,
            };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            while UnixStream::connect(seeded.admin_sock()).await.is_err()
                || UnixStream::connect(seeded.state.join("runtime/agent.sock"))
                    .await
                    .is_err()
            {
                assert!(!seeded.task.is_finished(), "broker exited during startup");
                assert!(tokio::time::Instant::now() < deadline, "broker startup");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            common::call(
                &seeded.admin_sock(),
                Channel::Admin,
                admin_msg::UNLOCK_PASSWORD,
                b"{}",
                common::PASSWORD,
            )
            .await
            .ok();
            let principal = PrincipalId::new_random();
            seeded.activate_profile_policy(&action, principal).await;
            (seeded, action, principal)
        }

        async fn activate_profile_policy(&self, action: &FixedHttpAction, principal: PrincipalId) {
            let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let key = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
            let signer = PolicySignerId::new_random();
            let proof = common::proof_body(common::PASSWORD);
            self.call(
                admin_msg::POLICY_TRUST_INSTALL,
                json!({"format_version":1,"signer_id":signer,"algorithm":"ed25519",
                    "public_key":data_encoding::HEXLOWER.encode(key.public_key().as_ref())}),
                &proof,
            )
            .await
            .ok();
            let reference = json!({"action_id":action.id,"version":action.version});
            let resource = json!({"type":"test","id":"one"});
            let snapshot = json!({
                "format_version":8,"version":1,"expires_at_ms":4_102_444_800_000_i64,
                "approvers":[],"workload_identities":[],"connections":[],"ssh_keys":[],
                "derived_credentials":[],
                "profiles":[{"name":"test","principal_id":principal,"grants":[{"instance":"one",
                    "capabilities":[{"rule":"template-default","capability":"fixed-actions",
                        "actions":[reference]}]}],
                    "session":{"ttl_ms":60000,"max_uses":4},"confirm_each_run":false,
                    "isolation":"none","egress":"allow","llm_limits":[]}],
                "bindings":[{"action_id":action.id,"version":action.version,"resource":resource,
                    "parameter_schema_id":"any/v1","parameter_schema":{}}],
                "rules":[{"id":PolicyRuleId::new_random(),"effect":"permit",
                    "principal_id":principal,"action_id":action.id,"version":action.version,
                    "resource":resource,"parameters":{"kind":"any_validated"}}],
            });
            let mut envelope = json!({"format_version":1,"signer_id":signer,"snapshot":snapshot});
            let mut message = b"RKPOLICY\0\x01".to_vec();
            message.extend(serde_jcs::to_vec(&envelope).unwrap());
            envelope["signature"] = data_encoding::BASE64URL_NOPAD
                .encode(key.sign(&message).as_ref())
                .into();
            let status = self.call(admin_msg::POLICY_STATUS, json!({}), &[]).await;
            let status = status.ok();
            self.call(
                admin_msg::POLICY_ACTIVATE,
                json!({"expected_vault_id":status["vault_id"],
                    "expected_trust_sha256":status["trust_sha256"],"bundle_json":envelope}),
                &proof,
            )
            .await
            .ok();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn default_broker_refuses_profile_and_session_issuance_before_effects() {
        let (seeded, action, principal) = Seeded::start().await;
        let proof = common::proof_body(common::PASSWORD);
        let profile = json!({"profile":"test"});
        let session = json!({"actions":[{"action_id":action.id,"version":action.version}],
            "ttl_ms":60000,"max_uses":1,"principal_id":principal});
        let requests = [
            (admin_msg::PROFILE_GET, profile.clone(), Vec::new()),
            (
                admin_msg::PROFILE_SESSION_CREATE,
                profile.clone(),
                Vec::new(),
            ),
            (admin_msg::PROFILE_SESSION_CREATE, profile, proof.clone()),
            (admin_msg::SESSION_CREATE, session, proof.clone()),
            (
                admin_msg::SESSION_REVOKE,
                json!({"session_id":SessionId::new_random()}),
                proof.clone(),
            ),
        ];
        let (before, locks) = (
            seeded.audit_count(None),
            seeded.audit_count(Some("vault.locked")),
        );
        for locked in [false, true] {
            if locked {
                seeded.call(admin_msg::LOCK, json!({}), &[]).await.ok();
            }
            for (opcode, metadata, body) in &requests {
                let reply = seeded.call(*opcode, metadata.clone(), body).await;
                assert_eq!(reply.err_code(), "INVALID_FRAME", "opcode {opcode}");
                assert_eq!(reply.metadata["retryable"], false, "opcode {opcode}");
            }
            let inventory = common::call(
                &seeded.state.join("runtime/agent.sock"),
                Channel::Agent,
                agent_msg::PROFILE_INVENTORY,
                br#"{"capability_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &[],
            )
            .await;
            assert_eq!(inventory.err_code(), "INVALID_FRAME");
        }
        // Only the explicit LOCK is audited; no refusal reached the Authority.
        assert_eq!(seeded.audit_count(Some("vault.locked")), locks + 1);
        assert_eq!(seeded.audit_count(None), before + 1, "refusals wrote audit");
        assert_eq!(seeded.audit_count(Some("session.created")), 0);
        assert_eq!(seeded.audit_count(Some("session.revoked")), 0);
        common::call(
            &seeded.admin_sock(),
            Channel::Admin,
            admin_msg::UNLOCK_PASSWORD,
            b"{}",
            common::PASSWORD,
        )
        .await
        .ok();
        let status = seeded.call(admin_msg::STATUS, json!({}), &[]).await;
        assert_eq!(status.ok()["sessions_active"], 0);
        // Opcode 60 is the default Connection list, not a Profile view.
        let listed = seeded
            .call(admin_msg::CONNECTION_LIST, json!({}), &[])
            .await;
        assert_eq!(listed.ok(), &json!({}));
        let listed: Value = serde_json::from_slice(&listed.body).unwrap();
        assert_eq!(listed["connections"], json!([]));
        assert!(listed["policy_sha256"].is_string());
        assert!(listed.get("profiles").is_none());
        seeded
            .call(admin_msg::SHUTDOWN, json!({}), &proof)
            .await
            .ok();
        tokio::time::timeout(Duration::from_secs(5), seeded.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
