//! Synthetic signed Profiles over the real Authority and Unix control sockets.
mod common;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rekey_domain::action::FixedHttpAction;
use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId, RequestId};
use rekey_domain::ipc::{self, Channel, FrameHeader, admin_msg, agent_msg};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

struct Fixture {
    broker: common::TestBroker,
    actions: Vec<FixedHttpAction>,
    snapshot: Value,
    key: Ed25519KeyPair,
    signer: PolicySignerId,
}
impl Fixture {
    async fn new(confirm: bool, source: Value, capability: &str, bindings: Value) -> Self {
        Self::with_signed_template(confirm, source, capability, bindings, None).await
    }
    async fn custom(name: &str) -> Self {
        Self::with_signed_template(
            false,
            json!({"kind":"signed-package"}),
            "read",
            json!([{"owner":"fixture"}]),
            Some(name),
        )
        .await
    }
    async fn with_signed_template(
        confirm: bool,
        source: Value,
        capability: &str,
        bindings: Value,
        name: Option<&str>,
    ) -> Self {
        let broker = common::start_broker().await;
        common::unlock(&broker).await;
        let credential =
            common::add_credential(&broker, "profile-fixture", b"SYNTHETIC-PROFILE-CREDENTIAL")
                .await;
        let key_doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(key_doc.as_ref()).unwrap();
        let signer = PolicySignerId::new_random();
        let trust = json!({"format_version":1,"signer_id":signer,"algorithm":"ed25519","public_key":data_encoding::HEXLOWER.encode(key.public_key().as_ref())});
        common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::POLICY_TRUST_INSTALL,
            &serde_json::to_vec(&trust).unwrap(),
            &common::proof_body(common::PASSWORD),
        )
        .await
        .ok();
        let package = name.map(|name| {
            let mut package = json!({"format_version":1,"signer_id":signer,"template":{
                "template":name,"display":"Signed custom fixture","origin":"https://api.example.com",
                "credential":{"kind":"opaque-token","inject":{"header":"authorization","prefix":"Bearer "}},
                "bindings":{"owner":{"type":"slug"}},"capabilities":[{"id":"read","risk":"low","actions":[{
                    "method":"GET","path":"/custom/{owner}/{item}","params":{"item":"slug"},"query":{"page":"int:1..10"}
                }]}]},"schemas":{}});
            let mut bytes = rekey_policy::templates::TEMPLATE_SIGN_PREFIX.to_vec();
            bytes.extend(serde_jcs::to_vec(&package).unwrap());
            package["signature"] = data_encoding::BASE64URL_NOPAD.encode(key.sign(&bytes).as_ref()).into();
            serde_json::to_vec(&package).unwrap()
        }).unwrap_or_default();
        let install = json!({"source":source,"credential_id":credential,"bindings":bindings,"capabilities":[capability],"name_prefix":"profile","timeout_ms":2000,"request_max_bytes":4096,"allowed_extra_headers":[],"response_max_bytes":4096,"allowed_response_headers":[]});
        if !package.is_empty() {
            let mut tampered: Value = serde_json::from_slice(&package).unwrap();
            tampered["template"]["origin"] = "https://other.example.com".into();
            let rejected = common::call(
                &broker.admin_sock(),
                Channel::Admin,
                admin_msg::TEMPLATE_INSTALL,
                &serde_json::to_vec(&install).unwrap(),
                &common::proof_and_secret_body(
                    common::PASSWORD,
                    &serde_json::to_vec(&tampered).unwrap(),
                ),
            )
            .await;
            assert_eq!(rejected.err_code(), "AUTHENTICATION_FAILED");
            let listed = common::call(
                &broker.admin_sock(),
                Channel::Admin,
                admin_msg::ACTION_LIST,
                b"{}",
                &[],
            )
            .await;
            assert!(listed.ok()["actions"].as_array().unwrap().is_empty());
        }
        let response = common::call(
            &broker.admin_sock(),
            Channel::Admin,
            admin_msg::TEMPLATE_INSTALL,
            &serde_json::to_vec(&install).unwrap(),
            &common::proof_and_secret_body(common::PASSWORD, &package),
        )
        .await;
        let actions = response.ok()["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| serde_json::from_value(a["action"].clone()).unwrap())
            .collect::<Vec<FixedHttpAction>>();
        let principal = PrincipalId::new_random();
        let refs: Vec<_> = actions
            .iter()
            .map(|a| json!({"action_id":a.id,"version":a.version}))
            .collect();
        let snapshot = json!({"format_version":6,"version":1,"expires_at_ms":4_102_444_800_000_i64,"approvers":[],"workload_identities":[],
            "profiles":[{"name":"test-run","principal_id":principal,"grants":[{"instance":"work","capabilities":[{"rule":"template-default","capability":capability,"actions":refs}]}],"session":{"ttl_ms":60000,"max_uses":100},"confirm_each_run":confirm,"isolation":"none","egress":"allow","llm_limits":[]}],
            "bindings":actions.iter().map(|a|json!({"action_id":a.id,"version":a.version,"resource":{"type":"fixture","id":a.id},"parameter_schema_id":"any/v1","parameter_schema":{}})).collect::<Vec<_>>(),
            "rules":actions.iter().map(|a|json!({"id":PolicyRuleId::new_random(),"effect":"permit","principal_id":principal,"action_id":a.id,"version":a.version,"resource":{"type":"fixture","id":a.id},"parameters":{"kind":"any_validated"}})).collect::<Vec<_>>()});
        let fixture = Self {
            broker,
            actions,
            snapshot,
            key,
            signer,
        };
        fixture.activate(&fixture.snapshot).await.ok();
        fixture
    }
    async fn generic(confirm: bool) -> Self {
        Self::new(confirm,json!({"kind":"generic-bearer","origin":"https://api.example.com","actions":[{"method":"POST","path":"/profile"}]}),"fixed-actions",json!([{}])).await
    }
    async fn activate(&self, snapshot: &Value) -> common::WireResponse {
        let mut envelope = json!({"format_version":1,"signer_id":self.signer,"snapshot":snapshot});
        let mut message = b"RKPOLICY\0\x01".to_vec();
        message.extend(serde_jcs::to_vec(&envelope).unwrap());
        envelope["signature"] = data_encoding::BASE64URL_NOPAD
            .encode(self.key.sign(&message).as_ref())
            .into();
        let metadata = common::policy::activation_metadata(
            &self.broker,
            &serde_jcs::to_vec(&envelope).unwrap(),
        )
        .await;
        common::call(
            &self.broker.admin_sock(),
            Channel::Admin,
            admin_msg::POLICY_ACTIVATE,
            &metadata,
            &common::proof_body(common::PASSWORD),
        )
        .await
    }
    async fn mint(&self, proof: &[u8]) -> (UnixStream, common::WireResponse) {
        let mut stream = UnixStream::connect(self.broker.admin_sock()).await.unwrap();
        send(
            &mut stream,
            admin_msg::PROFILE_SESSION_CREATE,
            br#"{"profile":"test-run"}"#,
            proof,
        )
        .await;
        let response = receive(&mut stream).await;
        (stream, response)
    }
    async fn execute(&self, token: &str) -> common::WireResponse {
        self.broker
            .fake
            .push_response(Ok(rekey_broker::upstream::UpstreamResponse {
                status: 200,
                headers: vec![].into(),
                body: b"{}".to_vec().into(),
            }));
        let meta = common::execute_meta(
            token,
            &self.actions[0].id.to_string(),
            self.actions[0].version,
        );
        common::call(
            &self.broker.agent_sock(),
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            &serde_json::to_vec(&meta).unwrap(),
            b"{}",
        )
        .await
    }
}
async fn send(stream: &mut UnixStream, opcode: u16, meta: &[u8], body: &[u8]) {
    let h = FrameHeader {
        channel: Channel::Admin,
        flags: 0,
        message_type: opcode,
        request_id: RequestId::new_random(),
        metadata_len: meta.len() as u32,
        body_len: body.len() as u32,
    };
    stream.write_all(&h.encode()).await.unwrap();
    stream.write_all(meta).await.unwrap();
    stream.write_all(body).await.unwrap();
}
async fn receive(stream: &mut UnixStream) -> common::WireResponse {
    let mut h = [0; ipc::FRAME_HEADER_LEN];
    stream.read_exact(&mut h).await.unwrap();
    let h = FrameHeader::decode(&h).unwrap();
    let mut m = vec![0; h.metadata_len as usize];
    let mut b = vec![0; h.body_len as usize];
    stream.read_exact(&mut m).await.unwrap();
    stream.read_exact(&mut b).await.unwrap();
    common::WireResponse {
        message_type: h.message_type,
        metadata: serde_json::from_slice(&m).unwrap(),
        body: b,
    }
}
fn session(response: &common::WireResponse) -> ipc::ProfileSessionCreatedResponse {
    assert_eq!(response.ok(), &json!({}));
    serde_json::from_slice(&response.body).unwrap()
}
async fn closed(stream: &mut UnixStream) {
    let mut b = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut b))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_a1_exact_scope_and_control_eof_or_byte_revoke_only_its_session() {
    let f = Fixture::generic(false).await;
    let get = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::PROFILE_GET,
        br#"{"profile":"test-run"}"#,
        &[],
    )
    .await;
    assert_eq!(get.ok(), &json!({}));
    let got: ipc::ProfileGetResponse = serde_json::from_slice(&get.body).unwrap();
    assert_eq!(got.profile.name, "test-run");
    let (mut first, response) = f.mint(&[]).await;
    let first_session = session(&response);
    assert_eq!(first_session.policy_sha256, got.policy_sha256);
    assert_eq!(first_session.profile, got.profile);
    assert_eq!(first_session.session.principal_id, got.profile.principal_id);
    let (second, response) = f.mint(&[]).await;
    let second_session = session(&response);
    f.execute(&first_session.session.capability_token)
        .await
        .ok();
    first.write_all(b"x").await.unwrap();
    closed(&mut first).await;
    assert_eq!(
        f.execute(&first_session.session.capability_token)
            .await
            .err_code(),
        "INVALID_CAPABILITY"
    );
    f.execute(&second_session.session.capability_token)
        .await
        .ok();
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        f.execute(&second_session.session.capability_token)
            .await
            .err_code(),
        "INVALID_CAPABILITY"
    );
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_confirmation_uses_current_signed_flag_and_never_accepts_extra_proof() {
    let mut f = Fixture::generic(false).await;
    assert_eq!(
        f.mint(&common::proof_body(common::PASSWORD))
            .await
            .1
            .err_code(),
        "INVALID_FRAME"
    );
    f.snapshot["version"] = 2.into();
    f.snapshot["profiles"][0]["confirm_each_run"] = true.into();
    f.activate(&f.snapshot).await.ok();
    assert_eq!(f.mint(&[]).await.1.err_code(), "INVALID_FRAME");
    assert_eq!(
        f.mint(&common::proof_body(b"wrong")).await.1.err_code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    let (control, response) = f.mint(&common::proof_body(common::PASSWORD)).await;
    session(&response);
    drop(control);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_policy_change_lock_and_ttl_close_live_controls() {
    let mut f = Fixture::generic(false).await;
    let (mut control, response) = f.mint(&[]).await;
    let token = session(&response).session.capability_token;
    f.snapshot["version"] = 2.into();
    f.activate(&f.snapshot).await.ok();
    closed(&mut control).await;
    assert_eq!(f.execute(&token).await.err_code(), "INVALID_CAPABILITY");
    let (mut control, _) = f.mint(&[]).await;
    common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::LOCK,
        b"{}",
        &[],
    )
    .await
    .ok();
    closed(&mut control).await;
    assert_eq!(f.mint(&[]).await.1.err_code(), "LOCKED");
    common::unlock(&f.broker).await;
    f.snapshot["version"] = 3.into();
    f.snapshot["profiles"][0]["session"]["ttl_ms"] = 150.into();
    f.activate(&f.snapshot).await.ok();
    let (mut control, _) = f.mint(&[]).await;
    closed(&mut control).await;
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_disabled_current_action_and_bad_capability_fail_closed() {
    let f = Fixture::generic(false).await;
    let mut bad = f.snapshot.clone();
    bad["version"] = 2.into();
    bad["profiles"][0]["grants"][0]["capabilities"][0]["capability"] = "other".into();
    assert_eq!(f.activate(&bad).await.err_code(), "POLICY_INVALID");
    common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::ACTION_DISABLE,
        &serde_json::to_vec(&json!({"action_id":f.actions[0].id})).unwrap(),
        &common::proof_body(common::PASSWORD),
    )
    .await
    .ok();
    assert_eq!(f.mint(&[]).await.1.err_code(), "POLICY_VERSION_CONFLICT");
    assert_eq!(
        f.activate(&f.snapshot).await.err_code(),
        "POLICY_VERSION_CONFLICT"
    );
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_llm_is_not_minted_before_shared_executor_enforcement() {
    let f = Fixture::new(false, json!({"kind":"anthropic"}), "messages", json!([{}])).await;
    assert_eq!(f.mint(&[]).await.1.err_code(), "REQUEST_DENIED");
    f.broker.shutdown().await;
    let mut f = Fixture::generic(false).await;
    f.snapshot["version"] = 2.into();
    f.snapshot["profiles"][0]["llm_limits"] = json!([{"instance":"work","models":["synthetic-model"],"max_output_tokens_per_request":1,"max_requests_per_day":2,"max_output_tokens_per_day":3}]);
    f.activate(&f.snapshot).await.ok();
    assert_eq!(f.mint(&[]).await.1.err_code(), "REQUEST_DENIED");
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_control_survives_thirty_seconds_without_heartbeat() {
    let f = Fixture::generic(false).await;
    let (control, response) = f.mint(&[]).await;
    let token = session(&response).session.capability_token;
    tokio::time::sleep(Duration::from_secs(31)).await;
    f.execute(&token).await.ok();
    drop(control);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_github_uses_verified_bound_builtin_materialization() {
    let f = Fixture::new(
        false,
        json!({"kind":"github-pat"}),
        "create-issue",
        json!([{"owner":"acme","repo":"issues"}]),
    )
    .await;
    let (control, response) = f.mint(&[]).await;
    session(&response);
    drop(control);
    f.broker.shutdown().await;
}

// No real credentials. The child keeps the control socket; a forked descendant
// retains it without writing, so killing the owner cannot be mistaken for EOF.
const OWNER_PROCESS: &str = r#"
import json, os, socket, struct, sys, time, uuid
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1])
m=b'{"profile":"test-run"}'
s.sendall(struct.pack('>4sHBBH2x16sII',b'RKIP',1,1,0,59,uuid.uuid4().bytes,len(m),0)+m)
def read(n):
 out=b''
 while len(out)<n:
  b=s.recv(n-len(out))
  if not b: raise RuntimeError('unexpected EOF')
  out+=b
 return out
h=read(36);ml,bl=struct.unpack('>II',h[28:36]);metadata=json.loads(read(ml));body=json.loads(read(bl))
helper=0
if sys.argv[2]=='retain':
 r,w=os.pipe();helper=os.fork()
 if helper==0:
  os.close(r);os.write(w,b'R');os.close(w);os.close(1)
  try:s.recv(1)
  finally:os._exit(0)
 os.close(w);assert os.read(r,1)==b'R';os.close(r)
print(json.dumps({'body':body,'helper':helper}),flush=True)
while True: time.sleep(60)
"#;

async fn process_owner(
    f: &Fixture,
    retain: bool,
) -> (
    tokio::process::Child,
    ipc::ProfileSessionCreatedResponse,
    i32,
) {
    use tokio::io::AsyncBufReadExt;
    let mut child = tokio::process::Command::new("python3")
        .args(["-c", OWNER_PROCESS])
        .arg(f.broker.admin_sock())
        .arg(if retain { "retain" } else { "owner" })
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let value: Value = serde_json::from_str(&line).expect("owner returned a private response");
    let response = serde_json::from_value(value["body"].clone()).unwrap();
    (child, response, value["helper"].as_i64().unwrap() as i32)
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_owner_sigkill_revokes_with_inherited_socket_and_preserves_other_owner() {
    let f = Fixture::generic(false).await;
    let (mut owner, first, helper) = process_owner(&f, true).await;
    let (mut other, second, _) = process_owner(&f, false).await;
    assert!(helper > 0);
    assert_eq!(
        unsafe { libc::kill(helper, 0) },
        0,
        "descendant is alive and retains the socket"
    );
    f.execute(&first.session.capability_token).await.ok();
    f.execute(&second.session.capability_token).await.ok();
    owner.kill().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = f.execute(&first.session.capability_token).await;
            if response.message_type == ipc::resp_msg::ERROR {
                assert_eq!(response.err_code(), "INVALID_CAPABILITY");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("OS owner death must revoke despite inherited socket");
    f.execute(&second.session.capability_token).await.ok();
    other.kill().await.unwrap();
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_unsupported_isolation_remains_queryable_but_cannot_mint() {
    let mut f = Fixture::generic(false).await;
    f.snapshot["version"] = 2.into();
    f.snapshot["profiles"][0]["isolation"] = "seatbelt".into();
    f.activate(&f.snapshot).await.ok();
    common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::PROFILE_GET,
        br#"{"profile":"test-run"}"#,
        &[],
    )
    .await
    .ok();
    assert_eq!(f.mint(&[]).await.1.err_code(), "UNSUPPORTED_PLATFORM");
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_deny_other_mints_only_for_supported_os_isolation() {
    let mut f = Fixture::generic(false).await;
    for (version, isolation) in [(2, "seatbelt"), (3, "netns"), (4, "none")] {
        f.snapshot["version"] = version.into();
        f.snapshot["profiles"][0]["isolation"] = isolation.into();
        f.snapshot["profiles"][0]["egress"] = "deny-other".into();
        f.activate(&f.snapshot).await.ok();
        let (owner, response) = f.mint(&[]).await;
        if cfg!(target_os = "macos") && isolation == "seatbelt" {
            let created = session(&response);
            // Issuance records the signed launch requirements, not OS attestation.
            assert_eq!(
                created.profile.isolation,
                rekey_domain::profile::ProfileIsolation::Seatbelt
            );
            f.execute(&created.session.capability_token).await.ok();
        } else {
            assert_eq!(response.err_code(), "UNSUPPORTED_PLATFORM");
        }
        drop(owner);
    }
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_custom_template_mints_and_executes_authenticated_target() {
    for name in [
        "team-custom@1",
        "github-pat@1",
        "anthropic@1",
        "glm@1",
        "openai@1",
    ] {
        let f = Fixture::custom(name).await;
        let (control, response) = f.mint(&[]).await;
        let created = session(&response);
        assert!(created.gateway.is_none());
        let meta = json!({"capability_token":created.session.capability_token,"action_id":f.actions[0].id,
        "action_version":1,"params":{"item":"record"},"query":{"page":"2"},"extra_headers":[],"approval_grants":[]});
        common::call(
            &f.broker.agent_sock(),
            Channel::Agent,
            agent_msg::EXECUTE_FIXED_HTTP_ACTION,
            &serde_json::to_vec(&meta).unwrap(),
            b"",
        )
        .await
        .ok();
        let requests = f.broker.fake.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/custom/fixture/record?page=2");
        assert_eq!(requests[0].method, "GET");
        assert!(requests[0].body.is_empty());
        assert!(requests[0].auth_value == b"Bearer SYNTHETIC-PROFILE-CREDENTIAL");
        drop(control);
        f.broker.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_custom_template_rejects_bad_grant_old_version_and_llm_limits() {
    let f = Fixture::custom("team-custom@1").await;
    let mut bad = f.snapshot.clone();
    bad["version"] = 2.into();
    bad["profiles"][0]["grants"][0]["capabilities"][0]["capability"] = "other".into();
    assert_eq!(f.activate(&bad).await.err_code(), "POLICY_INVALID");
    let mut stale = f.snapshot.clone();
    stale["version"] = 2.into();
    stale["profiles"][0]["grants"][0]["capabilities"][0]["actions"][0]["version"] = 2.into();
    stale["bindings"][0]["version"] = 2.into();
    stale["rules"][0]["version"] = 2.into();
    assert_eq!(
        f.activate(&stale).await.err_code(),
        "POLICY_VERSION_CONFLICT"
    );
    let mut llm = f.snapshot.clone();
    llm["version"] = 2.into();
    llm["profiles"][0]["llm_limits"] = json!([{"instance":"work","models":["fixture"],"max_output_tokens_per_request":10,"max_requests_per_day":10,"max_output_tokens_per_day":100}]);
    f.activate(&llm).await.ok();
    assert_eq!(f.mint(&[]).await.1.err_code(), "REQUEST_DENIED");
    assert!(f.broker.fake.take_requests().is_empty());
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_custom_template_source_rewrite_fails_seal_before_mint() {
    let f = Fixture::custom("team-custom@1").await;
    let mut target = serde_json::to_value(&f.actions[0].target).unwrap();
    target["source"]["signer_id"] = json!(PolicySignerId::new_random());
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.broker.state_dir)).unwrap();
    db.execute(
        "UPDATE actions SET target_json=?1",
        [serde_json::to_string(&target).unwrap()],
    )
    .unwrap();
    assert_eq!(f.mint(&[]).await.1.err_code(), "STORAGE_INTEGRITY_FAILED");
    assert!(f.broker.fake.take_requests().is_empty());
    drop(db);
    f.broker.shutdown().await;
}
