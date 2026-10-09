//! Synthetic keys and temp sockets only; no user's SSH files are opened.
mod common;

use aws_lc_rs::signature::{self, KeyPair};
use data_encoding::BASE64;
use rekey_domain::{
    connection::RuleEffect,
    ids::PolicyRuleId,
    ipc::{self, Channel, ProofKind, admin_msg},
};
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

fn string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}
fn host() -> (signature::Ed25519KeyPair, Vec<u8>) {
    let key = signature::Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap();
    let mut public = Vec::new();
    string(&mut public, b"ssh-ed25519");
    string(&mut public, key.public_key().as_ref());
    (key, public)
}
fn bind(host: &signature::Ed25519KeyPair, public: &[u8], sid: &[u8]) -> Vec<u8> {
    let mut signature = Vec::new();
    string(&mut signature, b"ssh-ed25519");
    string(&mut signature, host.try_sign(sid).unwrap().as_ref());
    let mut out = vec![27];
    string(&mut out, b"session-bind@openssh.com");
    string(&mut out, public);
    string(&mut out, sid);
    string(&mut out, &signature);
    out.push(0);
    out
}
fn userauth(public: &[u8], sid: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    string(&mut out, sid);
    out.push(50);
    string(&mut out, b"git");
    string(&mut out, b"ssh-connection");
    string(&mut out, b"publickey");
    out.push(1);
    string(&mut out, b"ssh-ed25519");
    string(&mut out, public);
    out
}
fn request(public: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = vec![13];
    string(&mut out, public);
    string(&mut out, data);
    out.extend_from_slice(&0_u32.to_be_bytes());
    out
}
async fn exchange(stream: &mut UnixStream, packet: &[u8]) -> Vec<u8> {
    stream.write_u32(packet.len() as u32).await.unwrap();
    stream.write_all(packet).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let len = stream.read_u32().await.unwrap() as usize;
        assert!(len < 256 * 1024);
        let mut out = vec![0; len];
        stream.read_exact(&mut out).await.unwrap();
        out
    })
    .await
    .expect("SSH response deadline")
}
struct Fixture {
    broker: common::TestBroker,
    public: Vec<u8>,
    presence: Vec<u8>,
}
impl Fixture {
    async fn new(effect: RuleEffect) -> Self {
        Self::configured(
            effect,
            json!({"kind":"local-presence"}),
            json!({"max_signatures":100,"max_seconds":600}),
            vec![],
        )
        .await
    }
    async fn configured(
        effect: RuleEffect,
        approver: serde_json::Value,
        budget: serde_json::Value,
        approvers: Vec<serde_json::Value>,
    ) -> Self {
        let broker = common::start_broker().await;
        common::unlock(&broker).await;
        let generated = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            63,
            &serde_json::to_vec(
                &json!({"action":"generate","label":"synthetic-ssh","mode":"ed25519_software"}),
            )
            .unwrap(),
            &common::proof_body(common::PASSWORD),
        )
        .await;
        generated.ok();
        let identity: serde_json::Value = serde_json::from_slice(&generated.body).unwrap();
        let public = BASE64
            .decode(identity["public_key"].as_str().unwrap().as_bytes())
            .unwrap();
        let (_, host_public) = host();
        common::policy::activate_snapshot(&broker,json!({"format_version":8,"version":1,"expires_at_ms":4102444800000_i64,"approvers":approvers,"connections":[],"derived_credentials":[],"profiles":[],"workload_identities":[],"bindings":[],"rules":[],
            "ssh_keys":[{"name":"synthetic-ssh","credential_id":identity["credential"]["id"],"user_public_key":BASE64.encode(&public),"hosts":[{"host":"synthetic.example","host_key":BASE64.encode(&host_public),"rule_id":PolicyRuleId::new_random(),"effect":effect}],"git_signing":"allow","approver":approver,"session_budget":budget}]})).await;
        let remembered = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::DESKTOP_REMEMBER,
            b"{}",
            &common::proof_body(common::PASSWORD),
        )
        .await;
        remembered.ok();
        Self {
            broker,
            public,
            presence: remembered.body,
        }
    }
    async fn socket(&self) -> UnixStream {
        UnixStream::connect(self.broker.state_dir.join("ssh-agent.sock"))
            .await
            .unwrap()
    }
    async fn pending(&self) -> String {
        for _ in 0..100 {
            let reply = common::call(
                &self.broker.admin_sock(),
                Channel::Admin,
                admin_msg::APPROVAL_PENDING,
                b"{}",
                &[],
            )
            .await;
            if let Some(id) = reply.ok()["challenges"]
                .as_array()
                .unwrap()
                .first()
                .and_then(|v| v["approval_request_id"].as_str())
            {
                return id.into();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("synthetic SSH approval never appeared");
    }
    async fn approve(&self, id: &str, hash: &str, window: Option<u32>) -> common::WireResponse {
        let mut body = Vec::new();
        ipc::encode_proof_body(ProofKind::Presence, &self.presence, &mut body);
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_LOCAL_APPROVE,
            &serde_json::to_vec(
                &json!({"approval_request_id":id,"expected_review_sha256":hash,"window_seconds":window}),
            )
            .unwrap(),
            &body,
        )
        .await
    }
    fn started(&self) -> i64 {
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.broker.state_dir))
            .unwrap()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.started'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }
    async fn verify_audit_page(&self, signatures: usize) {
        let query = rekey_domain::audit::AuditQuery {
            request_id: None,
            session_id: None,
            action_id: None,
            credential_id: None,
            outcome: None,
            since_ms: None,
            until_ms: None,
            snapshot_max_sequence: None,
            before_sequence: None,
            limit: 100,
        };
        let reply = common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::AUDIT_QUERY,
            &serde_json::to_vec(&query).unwrap(),
            &[],
        )
        .await;
        reply.ok();
        let page: rekey_domain::audit::AuditPage = serde_json::from_slice(&reply.body).unwrap();
        page.validate_for(&query).unwrap();
        let started: Vec<_> = page
            .events
            .iter()
            .filter(|event| event.event_type == "execution.started")
            .collect();
        assert_eq!(started.len(), signatures);
        assert!(
            started
                .iter()
                .all(|event| event.action_id.is_some() && event.action_version == Some(1))
        );
        let signing_history: Vec<_> = page
            .events
            .iter()
            .filter(|event| {
                matches!(
                    &event.request_context,
                    Some(rekey_domain::audit::RequestAuditContext::Connection(context))
                        if context.caller == "ssh-agent"
                )
            })
            .collect();
        for event in &signing_history {
            assert_eq!(
                event.session_id.map(|id| *id.as_bytes()),
                event.request_id.map(|id| *id.as_bytes()),
                "SSH signing records share their request correlation"
            );
            assert!(event.request_id.is_some());
            assert!(event.action_id.is_some());
            assert_eq!(event.action_version, Some(1));
        }
        for event in &started {
            assert!(signing_history.iter().any(|terminal| {
                terminal.event_type == "execution.finished"
                    && terminal.request_id == event.request_id
                    && terminal.session_id == event.session_id
                    && terminal.action_id == event.action_id
            }));
        }
    }
}

#[tokio::test]
async fn standard_wire_identities_valid_bind_allow_and_explicit_deny() {
    for effect in [RuleEffect::Allow, RuleEffect::Deny] {
        let f = Fixture::new(effect).await;
        let mut stream = f.socket().await;
        let identities = exchange(&mut stream, &[11]).await;
        assert_eq!(identities[0], 12);
        assert_eq!(u32::from_be_bytes(identities[1..5].try_into().unwrap()), 1);
        assert_eq!(f.started(), 0);
        assert_eq!(exchange(&mut stream, &[17]).await, vec![5]);
        let (host, host_public) = host();
        let sid = [31; 32];
        assert_eq!(
            exchange(&mut stream, &bind(&host, &host_public, &sid)).await,
            vec![6]
        );
        assert_eq!(
            exchange(
                &mut stream,
                &request(&f.public, &userauth(&f.public, &[32; 32]))
            )
            .await,
            vec![5]
        );
        assert_eq!(f.started(), 0);
        let response = exchange(&mut stream, &request(&f.public, &userauth(&f.public, &sid))).await;
        assert_eq!(
            response[0],
            if effect == RuleEffect::Allow { 14 } else { 5 }
        );
        assert_eq!(f.started(), if effect == RuleEffect::Allow { 1 } else { 0 });
        f.verify_audit_page(if effect == RuleEffect::Allow { 1 } else { 0 })
            .await;
        drop(stream);
        f.broker.shutdown().await;
    }
}

#[tokio::test]
async fn unbound_target_requires_review_bound_presence_and_does_not_grant_window() {
    let f = Fixture::new(RuleEffect::Allow).await;
    let mut stream = f.socket().await;
    let packet = request(&f.public, &userauth(&f.public, &[31; 32]));
    let task = tokio::spawn(async move { exchange(&mut stream, &packet).await });
    let id = f.pending().await;
    assert_eq!(f.started(), 0);
    let review = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        &serde_json::to_vec(&json!({"approval_request_id":id})).unwrap(),
        &[],
    )
    .await;
    let body: serde_json::Value = serde_json::from_slice(&review.body).unwrap();
    assert_eq!(body["ssh"]["host"], "unknown-host");
    assert_eq!(body["ssh"]["use"]["username"], "git");
    assert_eq!(body["ssh"]["window_allowed"], false);
    let hash = review.ok()["review_sha256"].as_str().unwrap();
    assert_eq!(
        f.approve(&id, &"00".repeat(32), None).await.message_type,
        ipc::resp_msg::ERROR
    );
    assert_eq!(f.started(), 0);
    assert_eq!(
        f.approve(&id, hash, Some(60)).await.message_type,
        ipc::resp_msg::ERROR
    );
    assert_eq!(f.started(), 0);
    f.approve(&id, hash, None).await.ok();
    assert_eq!(task.await.unwrap()[0], 14);
    assert_eq!(f.started(), 1);
    f.verify_audit_page(1).await;
    f.broker.shutdown().await;
}

#[tokio::test]
async fn registered_host_approval_window_reuses_only_the_signed_host_rule() {
    let f = Fixture::new(RuleEffect::Approve).await;
    let mut stream = f.socket().await;
    let (host, host_public) = host();
    let sid = [31; 32];
    assert_eq!(
        exchange(&mut stream, &bind(&host, &host_public, &sid)).await,
        vec![6]
    );
    let packet = request(&f.public, &userauth(&f.public, &sid));
    let pending = tokio::spawn(async move {
        let response = exchange(&mut stream, &packet).await;
        (stream, response)
    });
    let id = f.pending().await;
    let review = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        &serde_json::to_vec(&json!({"approval_request_id":id})).unwrap(),
        &[],
    )
    .await;
    let body: serde_json::Value = serde_json::from_slice(&review.body).unwrap();
    assert_eq!(body["ssh"]["host"], "synthetic.example");
    assert_eq!(body["ssh"]["window_allowed"], true);
    f.approve(
        &id,
        review.ok()["review_sha256"].as_str().unwrap(),
        Some(60),
    )
    .await
    .ok();
    let (mut stream, response) = pending.await.unwrap();
    assert_eq!(response[0], 14);
    assert_eq!(
        exchange(&mut stream, &request(&f.public, &userauth(&f.public, &sid))).await[0],
        14
    );
    assert_eq!(f.started(), 2);
    let listed = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_PENDING,
        b"{}",
        &[],
    )
    .await;
    assert!(listed.ok()["challenges"].as_array().unwrap().is_empty());
    f.verify_audit_page(2).await;
    drop(stream);
    f.broker.shutdown().await;
}

#[tokio::test]
async fn git_namespace_is_separate_and_real_openssh_can_sign_without_export() {
    let f = Fixture::new(RuleEffect::Deny).await;
    let public_path = f.broker.dir.path().join("synthetic.pub");
    std::fs::write(
        &public_path,
        format!("ssh-ed25519 {} synthetic-only\n", BASE64.encode(&f.public)),
    )
    .unwrap();
    // The public file contains the full wire blob, as OpenSSH expects.
    let input = f.broker.dir.path().join("synthetic-message");
    std::fs::write(&input, b"synthetic git message").unwrap();
    let output = tokio::process::Command::new("ssh-keygen")
        .args(["-Y", "sign", "-q", "-n", "git", "-f"])
        .arg(&public_path)
        .arg(&input)
        .env("SSH_AUTH_SOCK", f.broker.state_dir.join("ssh-agent.sock"))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic OpenSSH sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(input.with_extension("sig").exists());
    assert_eq!(f.started(), 1);
    f.verify_audit_page(1).await;
    f.broker.shutdown().await;
}

#[tokio::test]
async fn pending_peer_disconnect_and_pipelining_cancel_without_signing() {
    for extra_byte in [false, true] {
        let f = Fixture::new(RuleEffect::Approve).await;
        let mut stream = f.socket().await;
        let packet = request(&f.public, &userauth(&f.public, &[31; 32]));
        stream.write_u32(packet.len() as u32).await.unwrap();
        stream.write_all(&packet).await.unwrap();
        let id = f.pending().await;
        if extra_byte {
            stream.write_all(&[11]).await.unwrap();
        } else {
            drop(stream);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let listed = common::call(
                    &f.broker.admin_sock(),
                    Channel::Admin,
                    admin_msg::APPROVAL_PENDING,
                    b"{}",
                    &[],
                )
                .await;
                if listed.ok()["challenges"].as_array().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(f.started(), 0);
        let review = common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_LOCAL_REVIEW,
            &serde_json::to_vec(&json!({"approval_request_id":id})).unwrap(),
            &[],
        )
        .await;
        assert_eq!(review.ok()["state"], "cancelled");
        f.broker.shutdown().await;
    }
}

#[tokio::test]
async fn signed_session_budget_counts_signatures_and_expires_on_the_same_socket() {
    for ttl in [false, true] {
        let budget = if ttl {
            json!({"max_signatures":5,"max_seconds":1})
        } else {
            json!({"max_signatures":1,"max_seconds":600})
        };
        let f = Fixture::configured(
            RuleEffect::Allow,
            json!({"kind":"local-presence"}),
            budget,
            vec![],
        )
        .await;
        let mut stream = f.socket().await;
        let (host, public) = host();
        let sid = [31; 32];
        assert_eq!(
            exchange(&mut stream, &bind(&host, &public, &sid)).await,
            vec![6]
        );
        let packet = request(&f.public, &userauth(&f.public, &sid));
        assert_eq!(exchange(&mut stream, &packet).await[0], 14);
        if ttl {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        assert_eq!(exchange(&mut stream, &packet).await, vec![5]);
        assert_eq!(f.started(), 1);
        drop(stream);
        f.broker.shutdown().await;
    }
}

fn signed_grant(
    challenge: &serde_json::Value,
    id: rekey_domain::ids::ApproverId,
    key: &signature::Ed25519KeyPair,
) -> serde_json::Value {
    let mut grant = json!({"format_version":1,"approval_id":rekey_domain::ids::ApprovalId::new_random(),"approval_request_id":challenge["approval_request_id"],"approver_id":id,"tenant_id":challenge["tenant_id"],"principal_id":challenge["principal_id"],"session_id":challenge["session_id"],"action_id":challenge["action_id"],"action_version":challenge["action_version"],"resource":challenge["resource"],"schema_id":challenge["schema_id"],"parameter_sha256":challenge["parameter_sha256"],"policy_version":challenge["policy_version"],"policy_sha256":challenge["policy_sha256"],"policy_rule_id":challenge["policy_rule_id"],"mode":"one-time","not_before_ms":challenge["created_at_ms"],"expires_at_ms":challenge["max_expires_at_ms"],"max_uses":1});
    let mut bytes = b"RKAPPROVAL\0\x01".to_vec();
    bytes.extend(serde_jcs::to_vec(&grant).unwrap());
    grant["signature"] = data_encoding::BASE64URL_NOPAD
        .encode(key.try_sign(&bytes).unwrap().as_ref())
        .into();
    grant
}

#[tokio::test]
async fn external_ssh_quorum_binds_challenge_and_cannot_be_replaced_by_presence() {
    for threshold in [1, 2] {
        let keys: Vec<_> = (0..2)
            .map(|n| signature::Ed25519KeyPair::from_seed_unchecked(&[71 + n; 32]).unwrap())
            .collect();
        let ids: Vec<_> = (0..2)
            .map(|_| rekey_domain::ids::ApproverId::new_random())
            .collect();
        let mut public: Vec<_> = keys
            .iter()
            .map(|k| data_encoding::HEXLOWER.encode(k.public_key().as_ref()))
            .collect();
        let approvers: Vec<_> = ids
            .iter()
            .zip(&public)
            .map(|(id, key)| json!({"approver_id":id,"algorithm":"ed25519","public_key":key}))
            .collect();
        public.sort();
        let f = Fixture::configured(
            RuleEffect::Approve,
            json!({"kind":"ed25519","keys":public,"threshold":threshold}),
            json!({"max_signatures":2,"max_seconds":600}),
            approvers,
        )
        .await;
        let mut stream = f.socket().await;
        let packet = request(&f.public, &userauth(&f.public, &[31; 32]));
        let task = tokio::spawn(async move { exchange(&mut stream, &packet).await });
        let id = f.pending().await;
        let metadata = serde_json::to_vec(&json!({"approval_request_id":id})).unwrap();
        let review = common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_LOCAL_REVIEW,
            &metadata,
            &[],
        )
        .await;
        assert_eq!(
            f.approve(&id, review.ok()["review_sha256"].as_str().unwrap(), None)
                .await
                .message_type,
            ipc::resp_msg::ERROR
        );
        let envelope = common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_GET,
            &metadata,
            &[],
        )
        .await;
        let challenge = &envelope.ok()["challenge"];
        let grants: Vec<_> = (0..threshold as usize)
            .map(|n| signed_grant(challenge, ids[n], &keys[n]))
            .collect();
        let bad = if threshold == 2 {
            vec![grants[0].clone(), grants[0].clone()]
        } else {
            vec![]
        };
        let rejected = common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_EXTERNAL_SUBMIT,
            &metadata,
            &serde_json::to_vec(&bad).unwrap(),
        )
        .await;
        assert_eq!(rejected.message_type, ipc::resp_msg::ERROR);
        assert_eq!(f.started(), 0);
        common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_EXTERNAL_SUBMIT,
            &metadata,
            &serde_json::to_vec(&grants).unwrap(),
        )
        .await
        .ok();
        assert_eq!(task.await.unwrap()[0], 14);
        assert_eq!(f.started(), 1);
        let replay = common::call(
            &f.broker.admin_sock(),
            Channel::Admin,
            admin_msg::APPROVAL_EXTERNAL_SUBMIT,
            &metadata,
            &serde_json::to_vec(&grants).unwrap(),
        )
        .await;
        assert_eq!(replay.message_type, ipc::resp_msg::ERROR);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.broker.state_dir)).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='approval.accepted'",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
            threshold
        );
        f.verify_audit_page(1).await;
        f.broker.shutdown().await;
    }
}

#[tokio::test]
async fn accepted_approval_and_started_roll_back_together_on_audit_failure() {
    let f = Fixture::new(RuleEffect::Approve).await;
    let mut stream = f.socket().await;
    let packet = request(&f.public, &userauth(&f.public, &[31; 32]));
    let task = tokio::spawn(async move {
        stream.write_u32(packet.len() as u32).await.unwrap();
        stream.write_all(&packet).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), stream.read_u32())
            .await
            .unwrap()
        {
            Ok(length) => {
                assert_eq!(length, 1);
                assert_eq!(stream.read_u8().await.unwrap(), 5);
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof),
        }
    });
    let id = f.pending().await;
    let review = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::APPROVAL_LOCAL_REVIEW,
        &serde_json::to_vec(&json!({"approval_request_id":id})).unwrap(),
        &[],
    )
    .await;
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.broker.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_ssh_started BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.started' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    f.approve(&id, review.ok()["review_sha256"].as_str().unwrap(), None)
        .await
        .ok();
    task.await.unwrap();
    let accepted: u32 = db
        .query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='approval.accepted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(accepted, 0);
    assert_eq!(f.started(), 0);
    f.broker.shutdown().await;
}

/// Manual local comparison; all keys/files/sockets are disposable synthetic state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual OpenSSH concurrency/latency comparison; requires ssh-agent, ssh-add and ssh-keygen"]
async fn real_openssh_concurrency_comparison_counts_every_failure() {
    use std::process::Stdio;
    use std::time::Instant;
    let f = Fixture::new(RuleEffect::Deny).await;
    let root = f.broker.dir.path();
    let rekey_public = root.join("rekey-public");
    std::fs::write(
        &rekey_public,
        format!("ssh-ed25519 {} synthetic-only\n", BASE64.encode(&f.public)),
    )
    .unwrap();
    let baseline_key = root.join("baseline-key");
    assert!(
        tokio::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&baseline_key)
            .status()
            .await
            .unwrap()
            .success()
    );
    let baseline_socket = root.join("baseline.sock");
    let mut baseline = tokio::process::Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&baseline_socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !baseline_socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::process::Command::new("ssh-add")
            .arg(&baseline_key)
            .env("SSH_AUTH_SOCK", &baseline_socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap()
            .success()
    );
    let mut results = Vec::new();
    for (name, public, socket) in [
        (
            "openssh-agent",
            baseline_key.with_extension("pub"),
            baseline_socket,
        ),
        (
            "rekey",
            rekey_public,
            f.broker.state_dir.join("ssh-agent.sock"),
        ),
    ] {
        for concurrency in [1, 4, 16] {
            let mut durations = Vec::new();
            let mut failures = 0;
            for start in (0..16).step_by(concurrency) {
                let mut jobs = tokio::task::JoinSet::new();
                for n in start..start + concurrency {
                    let input = root.join(format!("{name}-{concurrency}-{n}"));
                    std::fs::write(&input, b"synthetic concurrency comparison").unwrap();
                    let public = public.clone();
                    let socket = socket.clone();
                    jobs.spawn(async move {
                        let started = Instant::now();
                        let output = tokio::time::timeout(
                            Duration::from_secs(20),
                            tokio::process::Command::new("ssh-keygen")
                                .args(["-Y", "sign", "-q", "-n", "git", "-f"])
                                .arg(public)
                                .arg(input)
                                .env("SSH_AUTH_SOCK", socket)
                                .kill_on_drop(true)
                                .output(),
                        )
                        .await;
                        (
                            started.elapsed().as_micros() as u64,
                            output.is_ok_and(|r| r.is_ok_and(|o| o.status.success())),
                        )
                    });
                }
                while let Some(result) = jobs.join_next().await {
                    let (duration, ok) = result.unwrap();
                    durations.push(duration);
                    failures += usize::from(!ok);
                }
            }
            durations.sort_unstable();
            results.push(json!({"backend":name,"concurrency":concurrency,"attempts":durations.len(),"failures":failures,
                "mean_us":durations.iter().sum::<u64>() / durations.len() as u64,"p95_us":durations[15]}));
        }
    }
    baseline.kill().await.unwrap();
    baseline.wait().await.unwrap();
    println!(
        "{}",
        json!({"scope":"local Ed25519 git-namespace signing; unequal security contracts; all attempts counted", "results":results})
    );
    assert!(
        results.iter().all(|r| r["failures"] == 0),
        "concurrency errors must not be excluded from acceptance"
    );
    assert_eq!(f.started(), 48);
    f.broker.shutdown().await;
}
