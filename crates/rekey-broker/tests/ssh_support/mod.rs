//! Native SSH agent fixture shared by the lifecycle and capacity suites.
//! Synthetic keys and temp sockets only; no user's SSH files are opened.
#![allow(dead_code)]

use std::time::Duration;

use aws_lc_rs::signature::{self, KeyPair};
use data_encoding::BASE64;
use rekey_domain::connection::RuleEffect;
use rekey_domain::ids::PolicyRuleId;
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::common;

pub const FAILURE: u8 = 5;
pub const SIGNATURE: u8 = 14;

pub fn string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}
/// The registered synthetic host key and its public wire blob.
pub fn host() -> (signature::Ed25519KeyPair, Vec<u8>) {
    let key = signature::Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap();
    let mut public = Vec::new();
    string(&mut public, b"ssh-ed25519");
    string(&mut public, key.public_key().as_ref());
    (key, public)
}
pub fn bind(host: &signature::Ed25519KeyPair, public: &[u8], sid: &[u8]) -> Vec<u8> {
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
pub fn userauth(public: &[u8], sid: &[u8]) -> Vec<u8> {
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
/// The `ssh-keygen -Y sign` signed-data blob for one namespace.
pub fn sshsig(namespace: &[u8]) -> Vec<u8> {
    let mut out = b"SSHSIG".to_vec();
    string(&mut out, namespace);
    string(&mut out, b"");
    string(&mut out, b"sha512");
    string(&mut out, &[7; 64]);
    out
}
pub fn request(public: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = vec![13];
    string(&mut out, public);
    string(&mut out, data);
    out.extend_from_slice(&0_u32.to_be_bytes());
    out
}
pub async fn send(stream: &mut UnixStream, packet: &[u8]) {
    stream.write_u32(packet.len() as u32).await.unwrap();
    stream.write_all(packet).await.unwrap();
}
/// One framed reply, or `None` when the agent closed the socket instead.
pub async fn response(stream: &mut UnixStream, within: Duration) -> Option<Vec<u8>> {
    tokio::time::timeout(within, async {
        let len = match stream.read_u32().await {
            Ok(len) => len as usize,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(error) => panic!("SSH response: {error}"),
        };
        assert!(len < 256 * 1024);
        let mut out = vec![0; len];
        stream.read_exact(&mut out).await.unwrap();
        Some(out)
    })
    .await
    .expect("SSH response deadline")
}
pub async fn exchange(stream: &mut UnixStream, packet: &[u8]) -> Vec<u8> {
    send(stream, packet).await;
    response(stream, Duration::from_secs(5))
        .await
        .expect("SSH agent closed the socket")
}

pub struct Fixture {
    pub broker: common::TestBroker,
    pub public: Vec<u8>,
    presence: Vec<u8>,
}
impl Fixture {
    pub async fn new(effect: RuleEffect) -> Self {
        Self::configured(
            effect,
            json!({"max_signatures":100,"max_seconds":600}),
            Duration::from_secs(2),
        )
        .await
    }
    pub async fn configured(effect: RuleEffect, budget: Value, drain: Duration) -> Self {
        let broker = common::start_broker_with(Duration::from_secs(300), drain).await;
        common::unlock(&broker).await;
        let generated = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::SSH_KEY,
            &serde_json::to_vec(
                &json!({"action":"generate","label":"synthetic-ssh","mode":"ed25519_software"}),
            )
            .unwrap(),
            &common::proof_body(common::PASSWORD),
        )
        .await;
        generated.ok();
        let identity: Value = serde_json::from_slice(&generated.body).unwrap();
        let public = BASE64
            .decode(identity["public_key"].as_str().unwrap().as_bytes())
            .unwrap();
        let (_, host_public) = host();
        common::policy::activate_snapshot(&broker,json!({"format_version":8,"version":1,"expires_at_ms":4102444800000_i64,"approvers":[],"connections":[],"derived_credentials":[],"profiles":[],"workload_identities":[],"bindings":[],"rules":[],
            "ssh_keys":[{"name":"synthetic-ssh","credential_id":identity["credential"]["id"],"user_public_key":BASE64.encode(&public),"hosts":[{"host":"synthetic.example","host_key":BASE64.encode(&host_public),"rule_id":PolicyRuleId::new_random(),"effect":effect}],"git_signing":"allow","approver":{"kind":"local-presence"},"session_budget":budget}]})).await;
        let remembered = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::DESKTOP_REMEMBER,
            br#"{"lifetime_ms":604800000}"#,
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
    pub async fn socket(&self) -> UnixStream {
        UnixStream::connect(self.broker.state_dir.join("ssh-agent.sock"))
            .await
            .unwrap()
    }
    async fn admin(&self, message: u16, metadata: Value, body: &[u8]) -> common::WireResponse {
        let metadata = serde_json::to_vec(&metadata).unwrap();
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            message,
            &metadata,
            body,
        )
        .await
    }
    /// The first pending challenge, as listed in the approval inbox.
    pub async fn pending(&self) -> String {
        for _ in 0..250 {
            let reply = self
                .admin(admin_msg::APPROVAL_PENDING, json!({}), &[])
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
    /// The review state and the hash an approver must bind.
    pub async fn review(&self, id: &str) -> (String, String) {
        let review = self
            .admin(
                admin_msg::APPROVAL_LOCAL_REVIEW,
                json!({"approval_request_id":id}),
                &[],
            )
            .await;
        let state = review.ok()["state"].as_str().unwrap().to_owned();
        (state, review.ok()["review_sha256"].as_str().unwrap().into())
    }
    pub async fn approve(&self, id: &str, hash: &str) -> common::WireResponse {
        let mut body = Vec::new();
        ipc::encode_proof_body(ProofKind::Presence, &self.presence, &mut body);
        let decision = json!({"approval_request_id":id,"expected_review_sha256":hash});
        self.admin(admin_msg::APPROVAL_LOCAL_APPROVE, decision, &body)
            .await
    }
    pub fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(rekey_vault::paths::vault_db(&self.broker.state_dir)).unwrap()
    }
    pub fn count(&self, event_type: &str) -> i64 {
        self.db()
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type=?1",
                [event_type],
                |row| row.get(0),
            )
            .unwrap()
    }
    /// reason_code values of one event type, oldest first.
    pub fn reasons(&self, event_type: &str) -> Vec<String> {
        let db = self.db();
        let mut statement = db
            .prepare("SELECT reason_code FROM audit_events WHERE event_type=?1 ORDER BY sequence")
            .unwrap();
        statement
            .query_map([event_type], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
}
