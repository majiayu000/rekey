//! Synthetic software P-256 fixtures; these tests make no hardware-trust claim.
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::testing::FakeUpstreamTransport;
use rekey_domain::action::FixedHttpAction;
use rekey_domain::authorization::PolicyMode;
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::{ActionId, PolicySignerId, PrincipalId, RequestId, VaultId};
use rekey_domain::ipc::{
    self, Channel, FrameHeader, PersonalPolicyDraftMeta, PersonalPolicyDraftResponse, admin_msg,
};
use rekey_vault::secret::SecretInput;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const PREFIX: &[u8] = b"RKPOLICY\0\x01";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn action_ref(action: &FixedHttpAction) -> ActionVersionRef {
    ActionVersionRef {
        action_id: action.id,
        version: action.version,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: PathBuf,
    task: tokio::task::JoinHandle<Result<(), rekey_broker::error::BrokerError>>,
    signer: EcdsaKeyPair,
    signer_id: PolicySignerId,
    vault_id: VaultId,
    principal: PrincipalId,
}

impl Fixture {
    async fn new(mode: PolicyMode, install: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let initialized = rekey_vault::bootstrap::init_vault(
            &state,
            &SecretInput::from_slice(common::PASSWORD),
            common::TEST_PARAMS,
            mode,
        )
        .unwrap();
        rekey_vault::bootstrap::confirm_vault_init(&state).unwrap();
        let mut config = BrokerConfig::new(state.clone());
        config.transport = Some(Arc::new(FakeUpstreamTransport::new()));
        config.unlock_backoff_base = Duration::from_millis(20);
        let task = tokio::spawn(serve(config));
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let fixture = Self {
            _dir: dir,
            state,
            task,
            signer: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref())
                .unwrap(),
            signer_id: PolicySignerId::new_random(),
            vault_id: initialized.vault_id,
            principal: PrincipalId::new_random(),
        };
        let mut ready = false;
        for _ in 0..200 {
            if UnixStream::connect(fixture.socket()).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready, "synthetic broker startup");
        if install {
            fixture.unlock().await;
            fixture.install_trust().await;
        }
        fixture
    }

    fn socket(&self) -> PathBuf {
        self.state.join("runtime/admin.sock")
    }

    async fn call(&self, message: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        common::call(
            &self.socket(),
            Channel::Admin,
            message,
            &serde_json::to_vec(&metadata).unwrap(),
            body,
        )
        .await
    }

    async fn unlock(&self) {
        self.call(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
            .await
            .ok();
    }

    async fn install_trust(&self) {
        self.call(admin_msg::POLICY_TRUST_INSTALL, json!({
            "format_version": 1, "signer_id": self.signer_id, "algorithm": "secure-enclave-p256",
            "public_key": data_encoding::HEXLOWER.encode(self.signer.public_key().as_ref()),
        }), &common::proof_body(common::PASSWORD)).await.ok();
    }

    async fn seed(
        &self,
        capabilities: &[&str],
        bindings: usize,
        label: &str,
    ) -> Vec<FixedHttpAction> {
        let credential = self
            .call(
                admin_msg::CREDENTIAL_ADD,
                json!({"label": label, "kind":"opaque-token"}),
                &common::proof_and_secret_body(common::PASSWORD, b"synthetic-draft-token"),
            )
            .await;
        let response = self.call(admin_msg::TEMPLATE_INSTALL, json!({
            "source":{"kind":"github-pat"}, "credential_id":credential.ok()["id"],
            "bindings": (0..bindings).map(|n| json!({"owner":"acme","repo":format!("repo-{n}")})).collect::<Vec<_>>(),
            "capabilities":capabilities,"name_prefix":label,"timeout_ms":1000,"request_max_bytes":4096,
            "allowed_extra_headers":[],"response_max_bytes":4096,"allowed_response_headers":[],
        }), &common::proof_and_secret_body(common::PASSWORD, &[])).await;
        serde_json::from_value::<ipc::TemplateInstallResponse>(response.ok().clone())
            .unwrap()
            .actions
            .into_iter()
            .map(|item| item.action)
            .collect()
    }

    async fn draft(&self, actions: Vec<ActionVersionRef>, expiry: i64) -> common::WireResponse {
        self.call(
            admin_msg::PERSONAL_POLICY_DRAFT,
            serde_json::to_value(PersonalPolicyDraftMeta {
                principal_id: self.principal,
                actions,
                expires_at_ms: expiry,
            })
            .unwrap(),
            &[],
        )
        .await
    }

    fn decoded(response: &common::WireResponse) -> PersonalPolicyDraftResponse {
        let metadata: PersonalPolicyDraftResponse =
            serde_json::from_value(response.ok().clone()).unwrap();
        metadata.validate().unwrap();
        assert!(response.body.starts_with(PREFIX));
        let unsigned: Value = serde_json::from_slice(&response.body[PREFIX.len()..]).unwrap();
        assert_eq!(
            serde_jcs::to_vec(&unsigned).unwrap(),
            response.body[PREFIX.len()..]
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(
                serde_jcs::to_vec(&unsigned["snapshot"]).unwrap()
            )),
            metadata.policy_sha256
        );
        metadata
    }

    fn signed(&self, response: &common::WireResponse) -> Value {
        Self::decoded(response);
        let mut unsigned: Value = serde_json::from_slice(&response.body[PREFIX.len()..]).unwrap();
        unsigned["signature"] = data_encoding::BASE64URL_NOPAD
            .encode(
                self.signer
                    .sign(&SystemRandom::new(), &response.body)
                    .unwrap()
                    .as_ref(),
            )
            .into();
        unsigned
    }

    async fn activate(
        &self,
        response: &common::WireResponse,
        bundle: &Value,
    ) -> common::WireResponse {
        self.call(admin_msg::POLICY_ACTIVATE, json!({"expected_vault_id": self.vault_id,"expected_trust_sha256": response.metadata["trust_sha256"],"bundle_json": bundle}), &common::proof_body(common::PASSWORD)).await
    }

    fn counts(&self) -> (i64, i64) {
        let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.state)).unwrap();
        db.query_row(
            "SELECT (SELECT count(*) FROM audit_events),(SELECT count(*) FROM policy_bundle)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    async fn finish(self) {
        self.call(
            admin_msg::SHUTDOWN,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await
        .ok();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn exact_sign_bytes_full_diff_empty_revoke_and_stale_version_contract() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let actions = f.seed(&["read-repo"], 1, "read").await;
    let expiry = now() + 60_000;
    let before = f.counts();
    let mut refs: Vec<_> = actions.iter().map(action_ref).collect();
    refs.reverse();
    let first = f.draft(refs.clone(), expiry).await;
    let first_meta = Fixture::decoded(&first);
    assert_eq!(first_meta.vault_id, f.vault_id);
    assert_eq!(
        first_meta.public_key,
        data_encoding::HEXLOWER.encode(f.signer.public_key().as_ref())
    );
    assert_eq!(first_meta.base_version, None);
    assert_eq!(first_meta.next_version, 1);
    assert_eq!(first_meta.actions.len(), actions.len());
    assert_eq!(f.counts(), before, "draft is read-only, including audit");
    let same = f
        .draft(actions.iter().map(action_ref).collect(), expiry)
        .await;
    assert_eq!(first.body, same.body);
    assert_eq!(first.metadata, same.metadata);
    let stale = f.draft(vec![], expiry).await;
    let signed = f.signed(&first);
    f.activate(&first, &signed).await.ok();
    let activated = f.counts();
    f.activate(&first, &signed).await.ok();
    assert_eq!(f.counts(), activated, "exact retry remains idempotent");
    assert_eq!(
        f.activate(&stale, &f.signed(&stale)).await.err_code(),
        "POLICY_VERSION_CONFLICT"
    );
    let empty = f.draft(vec![], expiry).await;
    let empty_meta = Fixture::decoded(&empty);
    assert_eq!(empty_meta.base_version, Some(1));
    assert_eq!(empty_meta.next_version, 2);
    assert!(empty_meta.actions.is_empty());
    for field in ["bindings", "rules"] {
        let change = empty_meta
            .changes
            .iter()
            .find(|change| change.field == field)
            .unwrap();
        assert!(!change.before.as_array().unwrap().is_empty());
        assert_eq!(change.after, json!([]));
    }
    f.activate(&empty, &f.signed(&empty)).await.ok();
    f.finish().await;
}

#[tokio::test]
async fn locked_team_untrusted_and_invalid_selection_are_rejected_without_mutation() {
    for mode in [PolicyMode::Personal, PolicyMode::Team] {
        let f = Fixture::new(mode, false).await;
        assert_eq!(f.draft(vec![], now() + 60_000).await.err_code(), "LOCKED");
        f.unlock().await;
        let before = f.counts();
        assert_eq!(
            f.draft(vec![], now() + 60_000).await.err_code(),
            match mode {
                PolicyMode::Personal => "POLICY_UNAVAILABLE",
                PolicyMode::Team => "POLICY_TRUST_CONFLICT",
            }
        );
        assert_eq!(f.counts(), before);
        f.finish().await;
    }
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let actions = f.seed(&["read-repo", "merge-pr"], 1, "mixed").await;
    let first = action_ref(&actions[0]);
    let before = f.counts();
    for refs in [
        vec![first, first],
        vec![ActionVersionRef {
            action_id: ActionId::new_random(),
            version: 1,
        }],
        vec![ActionVersionRef {
            version: 0,
            ..first
        }],
    ] {
        assert_eq!(
            f.draft(refs, now() + 60_000).await.err_code(),
            "POLICY_INVALID"
        );
    }
    for expiry in [0, -1, now() - 1, 9_007_199_254_740_993] {
        assert_eq!(f.draft(vec![], expiry).await.err_code(), "POLICY_INVALID");
    }
    assert_eq!(f.counts(), before);
    f.finish().await;
}

#[tokio::test]
async fn signed_personal_high_risk_draft_requires_local_presence_before_execution() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let action = f
        .seed(&["merge-pr"], 1, "personal-high-risk")
        .await
        .remove(0);
    let draft = f.draft(vec![action_ref(&action)], now() + 60_000).await;
    let signed = f.signed(&draft);
    assert_eq!(signed["snapshot"]["rules"][0]["effect"], "require-approval");
    assert_eq!(
        signed["snapshot"]["rules"][0]["approver"],
        json!({"kind":"local-presence"})
    );
    f.activate(&draft, &signed).await.ok();
    let session = f.call(admin_msg::SESSION_CREATE, json!({"actions":[action_ref(&action)],"principal_id":f.principal,"ttl_ms":60_000,"max_uses":1}), &common::proof_body(common::PASSWORD)).await;
    let mut request = json!({"capability_token":session.ok()["capability_token"],"action_id":action.id,"action_version":action.version,"content_type":"application/json","extra_headers":[],"params":{"number":"1"},"query":{},"approval_grants":[]});
    let agent_socket = f.state.join("runtime/agent.sock");
    let pending = common::call(
        &agent_socket,
        Channel::Agent,
        ipc::agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        request.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(pending.err_code(), "APPROVAL_REQUIRED");
    let challenge = pending.metadata["approval"]["challenge_id"].clone();
    let review = f
        .call(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":challenge}),
            &[],
        )
        .await;
    review.ok();
    let remembered = f
        .call(
            admin_msg::DESKTOP_REMEMBER,
            json!({}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    remembered.ok();
    let mut presence = Vec::new();
    ipc::encode_proof_body(ipc::ProofKind::Presence, &remembered.body, &mut presence);
    f.call(admin_msg::APPROVAL_LOCAL_APPROVE, json!({"approval_request_id":challenge,"expected_review_sha256":review.metadata["review_sha256"]}), &presence).await.ok();
    request["local_approval_request_id"] = challenge;
    common::call(
        &agent_socket,
        Channel::Agent,
        ipc::agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        request.to_string().as_bytes(),
        b"{}",
    )
    .await
    .ok();
    let replay = common::call(
        &agent_socket,
        Channel::Agent,
        ipc::agent_msg::EXECUTE_FIXED_HTTP_ACTION,
        request.to_string().as_bytes(),
        b"{}",
    )
    .await;
    assert_eq!(replay.err_code(), "CAPABILITY_EXHAUSTED");
    f.finish().await;
}

#[tokio::test]
async fn disabled_and_retired_actions_block_drafts_and_even_exact_activation_retries() {
    for retire in [false, true] {
        let f = Fixture::new(PolicyMode::Personal, true).await;
        let action = f.seed(&["read-repo"], 1, "current").await.remove(0);
        let refs = vec![action_ref(&action)];
        let draft = f.draft(refs.clone(), now() + 60_000).await;
        let signed = f.signed(&draft);
        f.activate(&draft, &signed).await.ok();
        if retire {
            f.call(admin_msg::ACTION_UPDATE, json!({"action_id":action.id,"definition":{
                "name":action.name.as_str(),"credential_id":action.credential_id,"origin":action.origin.as_str(),"method":"GET","exact_path":"/replacement",
                "auth_header":"authorization","auth_prefix":"Bearer ","timeout_ms":1000,"request_max_bytes":4096,"allowed_extra_headers":[],"response_max_bytes":4096,"allowed_response_headers":[],
            }}), &common::proof_body(common::PASSWORD)).await.ok();
        } else {
            f.call(
                admin_msg::ACTION_DISABLE,
                json!({"action_id":action.id}),
                &common::proof_body(common::PASSWORD),
            )
            .await
            .ok();
        }
        let before = f.counts();
        assert_eq!(
            f.draft(refs, now() + 60_000).await.err_code(),
            "POLICY_INVALID"
        );
        assert_eq!(
            f.activate(&draft, &signed).await.err_code(),
            "POLICY_VERSION_CONFLICT"
        );
        assert_eq!(f.counts(), before);
        f.finish().await;
    }
}

#[tokio::test]
async fn expired_previous_bundle_still_supplies_the_authenticated_diff() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let action = f.seed(&["read-repo"], 1, "expires").await.remove(0);
    let expiry = now() + 500;
    let draft = f.draft(vec![action_ref(&action)], expiry).await;
    let signed = f.signed(&draft);
    f.activate(&draft, &signed).await.ok();
    tokio::time::sleep(Duration::from_millis((expiry - now()).max(0) as u64 + 20)).await;
    assert_eq!(
        f.activate(&draft, &signed).await.err_code(),
        "POLICY_INVALID"
    );
    let replacement = f.draft(vec![], now() + 60_000).await;
    let metadata = Fixture::decoded(&replacement);
    assert_eq!(metadata.base_version, Some(1));
    assert!(metadata.changes.iter().any(|change| change.field == "rules"
        && change.before.as_array().is_some_and(|v| v.len() == 1)
        && change.after == json!([])));
    f.activate(&replacement, &f.signed(&replacement)).await.ok();
    f.finish().await;
}

#[tokio::test]
async fn draft_frame_limits_reject_body_and_oversized_metadata_before_reading_them() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let before = f.counts();
    for (metadata_len, body_len) in [(2, 1), (ipc::METADATA_MAX_BYTES + 1, 0)] {
        let header = FrameHeader {
            channel: Channel::Admin,
            flags: 0,
            message_type: admin_msg::PERSONAL_POLICY_DRAFT,
            request_id: RequestId::new_random(),
            metadata_len,
            body_len,
        };
        let mut stream = UnixStream::connect(f.socket()).await.unwrap();
        stream.write_all(&header.encode()).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), stream.read_u8())
            .await
            .expect("invalid frame must close without waiting for its claimed body")
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        ));
    }
    let mut metadata = serde_json::to_value(PersonalPolicyDraftMeta {
        principal_id: f.principal,
        actions: vec![],
        expires_at_ms: now() + 60_000,
    })
    .unwrap();
    metadata["unknown"] = true.into();
    assert_eq!(
        f.call(admin_msg::PERSONAL_POLICY_DRAFT, metadata, &[])
            .await
            .err_code(),
        "INVALID_FRAME"
    );
    assert_eq!(f.counts(), before);
    f.finish().await;
}

#[tokio::test]
async fn complete_review_metadata_overflow_rejects_instead_of_truncating() {
    let f = Fixture::new(PolicyMode::Personal, true).await;
    let actions = f.seed(&["read-repo"], 8, "large").await;
    let before = f.counts();
    let response = f
        .draft(actions.iter().map(action_ref).collect(), now() + 60_000)
        .await;
    assert_eq!(response.err_code(), "INVALID_FRAME");
    assert!(response.body.is_empty());
    assert_eq!(f.counts(), before);
    f.finish().await;
}
