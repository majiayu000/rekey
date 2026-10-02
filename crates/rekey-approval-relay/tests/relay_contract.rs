use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const APPROVER: &str = "22222222-2222-4222-8222-222222222222";
const REQUEST: &str = "33333333-3333-4333-8333-333333333333";
const OTHER: &str = "44444444-4444-4444-8444-444444444444";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap()
}
fn challenge(id: &str, expiry: i64) -> Vec<u8> {
    challenge_for(id, expiry, APPROVER)
}
fn challenge_for(id: &str, expiry: i64, approver: &str) -> Vec<u8> {
    let c: rekey_domain::ipc::ApprovalChallenge=serde_json::from_value(json!({
        "record_type":"rekey.approval.challenge.v1","approval_request_id":id,"tenant_id":TENANT,
        "principal_id":OTHER,"session_id":OTHER,"action_id":OTHER,"action_version":1,
        "resource":{"type":"test.resource","id":"one"},"schema_id":"test/v1","parameter_sha256":"01".repeat(32),
        "policy_version":1,"policy_sha256":"02".repeat(32),"policy_rule_id":OTHER,"mode":"one-time","quorum":1,
        "approver_ids":[approver],"max_uses":1,"created_at_ms":now()-1000,"max_expires_at_ms":expiry})).unwrap();
    let message = rekey_policy::approval_challenge_sign_payload(&c).unwrap();
    serde_json::to_vec(
        &json!({"record_type":"rekey.approval.challenge.envelope.v1","challenge":c,
        "signature":BASE64URL_NOPAD.encode(key().sign(&message).as_ref())}),
    )
    .unwrap()
}
fn fake_grant(id: &str, expiry: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({
    "format_version":1,"approval_id":OTHER,"approval_request_id":id,"approver_id":APPROVER,"tenant_id":TENANT,
    "principal_id":OTHER,"session_id":OTHER,"action_id":OTHER,"action_version":1,
    "resource":{"type":"test.resource","id":"one"},"schema_id":"test/v1","parameter_sha256":"01".repeat(32),
    "policy_version":1,"policy_sha256":"02".repeat(32),"policy_rule_id":OTHER,"mode":"one-time","max_uses":1,
    "not_before_ms":now()-500,"expires_at_ms":expiry,"signature":"deliberately-invalid-signature"})).unwrap()
}
const IDP: &str = r#"
import http.server,socketserver,ssl,json,pathlib,sys,time,urllib.parse,base64
root=pathlib.Path(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def do_GET(self):
  assert self.path.startswith('/scim/v2/Users/')
  assert self.headers['Authorization']=='Bearer DIRECTORY-TOKEN-CANARY'
  with (root/'scim-hits').open('a') as f: f.write(self.path+'\n')
  config=json.loads((root/'config.json').read_text())
  ident=self.path.rsplit('/',1)[1]
  link=next(l for l in config['directory']['links'] if l['sourceUserId']==ident)
  c=json.loads((root/'control.json').read_text()).get('scim',{}).get(ident,{})
  time.sleep(c.get('delay',0))
  result={'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],'id':ident,'externalId':link['externalId'],'active':True}
  result.update(c.get('claims',{}))
  for name in c.get('remove',[]): result.pop(name,None)
  body=c.get('raw',json.dumps(result)).encode()
  self.send_response(c.get('status',200));self.send_header('Content-Type','application/scim+json')
  if c.get('redirect'): self.send_header('Location',c['redirect'])
  self.send_header('Content-Length',str(len(body)));self.end_headers()
  try: self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass
 def do_POST(self):
  data=urllib.parse.parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
  assert self.path=='/introspect'
  assert self.headers['Authorization']=='Basic '+base64.b64encode(b'client:IDP-SECRET-CANARY').decode()
  assert data.get('token_type_hint')==['access_token']
  with (root/'idp-hits').open('a') as f: f.write('request\n')
  c=json.loads((root/'control.json').read_text())
  time.sleep(c.get('delay',0))
  token=data.get('token',[''])[0]
  sub={'UPLOADER-TOKEN-CANARY':'operator','APPROVER-TOKEN-CANARY':'reviewer'}.get(token,'unlisted-same-email')
  result={'active':True,'iss':c['issuer'],'aud':'relay','client_id':'personnel','token_type':'Bearer',
   'sub':sub,'iat':int(time.time())-1,'exp':int(time.time())+120}
  result.update(c.get('claims',{}))
  for name in c.get('remove',[]): result.pop(name,None)
  body=c.get('raw',json.dumps(result)).encode()
  self.send_response(c.get('status',200));self.send_header('Content-Type','application/json')
  if c.get('redirect'): self.send_header('Location',c['redirect'])
  self.send_header('Content-Length',str(len(body)));self.end_headers()
  try: self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass
class LocalServer(http.server.ThreadingHTTPServer):
 def server_bind(self):
  socketserver.TCPServer.server_bind(self)
  self.server_name='localhost';self.server_port=self.server_address[1]
server=LocalServer(('127.0.0.1',0),H)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'tls.pem',root/'key.pem')
server.socket=context.wrap_socket(server.socket,server_side=True)
(root/'idp-ready').write_text(str(server.server_port));server.serve_forever()
"#;
struct Fixture {
    root: TempDir,
    relay: Option<Child>,
    idp: Child,
    client: reqwest::Client,
    config: Value,
    base: String,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_approvers(vec![json!({"subject":"reviewer","approverId":APPROVER})]).await
    }
    async fn with_approvers(approvers: Vec<Value>) -> Self {
        Self::with_configuration(approvers, |_, _| {}).await
    }
    async fn with_configuration<F: FnOnce(&mut Value, &Path)>(
        approvers: Vec<Value>,
        configure: F,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        write(&root.path().join("tls.pem"), cert.cert.pem());
        write(&root.path().join("key.pem"), cert.key_pair.serialize_pem());
        write(&root.path().join("secret"), b"IDP-SECRET-CANARY");
        write(
            &root.path().join("directory-token.json"),
            json!({"accessToken":"DIRECTORY-TOKEN-CANARY","expiresAtMs":now()+3600000}).to_string(),
        );
        write(&root.path().join("idp.py"), IDP);
        write(&root.path().join("control.json"), b"{}");
        let log = fs::File::create(root.path().join("idp.log")).unwrap();
        let mut idp = Command::new("python3")
            .arg(root.path().join("idp.py"))
            .arg(root.path())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let ready = root.path().join("idp-ready");
        for _ in 0..100 {
            if ready.exists() {
                break;
            }
            assert!(
                idp.try_wait().unwrap().is_none(),
                "IdP fixture exited: {}",
                fs::read_to_string(root.path().join("idp.log")).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let port = fs::read_to_string(ready).unwrap_or_else(|error| {
            panic!(
                "IdP readiness failed: {error}; {}",
                fs::read_to_string(root.path().join("idp.log")).unwrap()
            )
        });
        let issuer = format!("https://localhost:{port}");
        write(
            &root.path().join("control.json"),
            json!({"issuer":issuer}).to_string(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let base = format!("https://localhost:{port}/v1/requests/{REQUEST}");
        let mut config = json!({"formatVersion":2,"instanceId":OTHER,"endpoint":format!("https://localhost:{port}/v1"),
            "listenAddress":format!("127.0.0.1:{port}"),"stateDir":state,"tlsCertificateFile":root.path().join("tls.pem"),
            "tlsKeyFile":root.path().join("key.pem"),"idpIssuer":issuer,"introspectionUrl":format!("{issuer}/introspect"),
            "idpCaCertificateFile":root.path().join("tls.pem"),"introspectionClientId":"client","introspectionClientSecretFile":root.path().join("secret"),
            "personnelClientId":"personnel","audience":"relay","tenantId":TENANT,"originPublicKey":HEXLOWER.encode(key().public_key().as_ref()),
            "uploaderSubject":"operator","approvers":approvers});
        let mut links = vec![
            json!({"sourceUserId":"member-0","externalId":"external-0","issuer":issuer,"subject":"operator",
            "principalId":TENANT,"adminAllowed":true,"confirmedBy":"fixture-registrar","confirmedAtMs":1}),
        ];
        for (i, a) in config["approvers"].as_array().unwrap().iter().enumerate() {
            if a["subject"] == "operator" {
                links[0]["approverId"] = a["approverId"].clone();
                links[0]["publicKeySha256"] = json!("02".repeat(32));
            } else {
                links.push(json!({"sourceUserId":format!("member-{}",i+1),"externalId":format!("external-{}",i+1),"issuer":issuer,
                    "subject":a["subject"],"principalId":format!("50000000-0000-4000-8000-{:012x}",i+1),"approverId":a["approverId"],
                    "publicKeySha256":"02".repeat(32),"adminAllowed":true,"confirmedBy":"fixture-registrar","confirmedAtMs":1}));
            }
        }
        config["directory"] = json!({"baseUrl":format!("{issuer}/scim/v2"),"caCertificateFile":root.path().join("tls.pem"),
            "accessTokenFile":root.path().join("directory-token.json"),"mappingVersion":1,"links":links,
            "nodes":[{"nodeId":TENANT,"vaultId":APPROVER},{"nodeId":REQUEST,"vaultId":OTHER}]});
        configure(&mut config, root.path());
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(12))
            .build()
            .unwrap();
        let mut f = Self {
            root,
            relay: None,
            idp,
            client,
            config,
            base,
        };
        f.start().await;
        f
    }
    fn path(&self, s: &str) -> PathBuf {
        self.root.path().join(s)
    }
    async fn start(&mut self) {
        write(&self.path("config.json"), self.config.to_string());
        let log = fs::File::create(self.path("relay.log")).unwrap();
        self.relay = Some(
            Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
                .args(["serve", "--config"])
                .arg(self.path("config.json"))
                .env("HTTPS_PROXY", "http://127.0.0.1:1")
                .env("HTTP_PROXY", "http://127.0.0.1:1")
                .env("ALL_PROXY", "http://127.0.0.1:1")
                .env("NO_PROXY", "")
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        for _ in 0..700 {
            if self
                .client
                .get(format!("{}/unknown", self.base))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            assert!(
                self.relay.as_mut().unwrap().try_wait().unwrap().is_none(),
                "relay startup failed: {}",
                fs::read_to_string(self.path("relay.log")).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("relay startup timeout");
    }
    fn stop(&mut self) {
        if let Some(mut p) = self.relay.take() {
            p.kill().ok();
            p.wait().unwrap();
        }
    }
    fn control(&self, extra: Value) {
        let mut c = json!({"issuer":self.config["idpIssuer"]});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        write(&self.path("control.json"), c.to_string());
    }
    async fn inbox(&self, token: &str, query: &str) -> reqwest::Response {
        self.client
            .get(format!(
                "{}/inbox{}",
                self.config["endpoint"].as_str().unwrap(),
                query
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }
    async fn inbox_value(&self, token: &str, query: &str) -> Value {
        let response = self.inbox(token, query).await;
        assert_eq!(response.status(), 200);
        let bytes = response.bytes().await.unwrap();
        assert!(bytes.len() <= 16 * 1024);
        assert!(!String::from_utf8_lossy(&bytes).contains("CANARY"));
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn get(&self, kind: &str, token: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/{kind}", self.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }
    async fn put(&self, kind: &str, bytes: &[u8], token: &str) -> reqwest::Response {
        let mut b = self
            .client
            .put(format!("{}/{kind}", self.base))
            .bearer_auth(token)
            .body(bytes.to_vec());
        if kind == "challenge" {
            b = b.header("x-rekey-approver-id", APPROVER);
        }
        b.send().await.unwrap()
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.path("state/relay.sqlite")).unwrap()
    }
    fn no_canary(&self) {
        for name in ["relay.log", "idp.log"] {
            let s = fs::read_to_string(self.path(name)).unwrap();
            assert!(!s.contains("TOKEN-CANARY") && !s.contains("SECRET-CANARY"));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        self.idp.kill().ok();
        self.idp.wait().ok();
    }
}
const UP: &str = "UPLOADER-TOKEN-CANARY";
const AP: &str = "APPROVER-TOKEN-CANARY";

#[tokio::test]
async fn immutable_bytes_receipts_retry_acl_and_restart() {
    let mut f = Fixture::new().await;
    let expiry = now() + 60000;
    let bytes = challenge(REQUEST, expiry);
    let r = f.put("challenge", &bytes, UP).await;
    assert_eq!(r.status(), 201);
    let receipt = r.bytes().await.unwrap();
    let value: Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(value["actor"]["sub"], "operator");
    assert!(!String::from_utf8_lossy(&receipt).contains("CANARY"));
    assert_eq!(
        f.put("challenge", &bytes, UP).await.bytes().await.unwrap(),
        receipt
    );
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert_eq!(f.put("challenge", &changed, UP).await.status(), 409);
    assert_eq!(
        f.get("challenge", AP).await.bytes().await.unwrap().as_ref(),
        bytes.as_slice()
    );
    assert_eq!(f.get("challenge", "unlisted").await.status(), 404);
    assert_eq!(f.put("challenge", &bytes, AP).await.status(), 404);
    let grant = fake_grant(REQUEST, expiry - 1000);
    assert_eq!(f.put("grant", &grant, UP).await.status(), 404);
    let receipt2 = f.put("grant", &grant, AP).await;
    assert_eq!(receipt2.status(), 201);
    let receipt2 = receipt2.bytes().await.unwrap();
    assert_eq!(
        f.get("grant", UP).await.bytes().await.unwrap().as_ref(),
        grant.as_slice()
    );
    assert_eq!(
        f.put("grant", &grant, AP).await.bytes().await.unwrap(),
        receipt2
    );
    f.stop();
    f.start().await;
    assert_eq!(
        f.put("challenge", &bytes, UP).await.bytes().await.unwrap(),
        receipt
    );
    let saved: Value =
        serde_json::from_slice(&f.get("receipt", UP).await.bytes().await.unwrap()).unwrap();
    assert_eq!(saved["challenge"], value);
    assert!(saved["snapshot"].as_str().unwrap().contains("Broker"));
    f.stop();
    f.config["approvers"][0]["subject"] = json!("new-reviewer");
    f.config["directory"]["links"][1]["subject"] = json!("new-reviewer");
    write(&f.path("config.json"), f.config.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
        .args(["serve", "--config"])
        .arg(f.path("config.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("store-identity-mismatch"));
    f.no_canary();
}
#[tokio::test]
async fn fresh_claims_revoke_uncertainty_no_redirect_no_cache() {
    let f = Fixture::new().await;
    let bytes = challenge(REQUEST, now() + 60000);
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 201);
    assert_eq!(f.get("challenge", AP).await.status(), 200);
    for claims in [
        json!({"active":false}),
        json!({"iss":"https://wrong.invalid"}),
        json!({"aud":"wrong"}),
        json!({"client_id":"service-account"}),
        json!({"nbf":now()/1000+60}),
        json!({"exp":now()/1000-1}),
        json!({"iat":now()/1000-400}),
    ] {
        f.control(json!({"claims":claims}));
        assert_eq!(f.get("challenge", AP).await.status(), 401);
    }
    for extra in [
        json!({"remove":["client_id"]}),
        json!({"claims":{"exp":"wrong"}}),
        json!({"raw":"{\"active\":true,\"active\":true}"}),
        json!({"raw":"x".repeat(65537)}),
        json!({"status":503}),
        json!({"status":302,"redirect":"https://localhost:1/stolen"}),
    ] {
        f.control(extra);
        assert_eq!(f.get("challenge", AP).await.status(), 503);
    }
    f.control(json!({}));
    assert_eq!(f.get("challenge", AP).await.status(), 200);
    let hits = fs::read_to_string(f.path("idp-hits"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(hits, 16);
    f.no_canary();
}
#[tokio::test]
async fn origin_route_expiry_limits_and_sql_audit_fail_closed() {
    let mut f = Fixture::new().await;
    let expiry = now() + 60000;
    let bytes = challenge(REQUEST, expiry);
    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["challenge"]["tenant_id"] = json!(OTHER);
    assert_eq!(
        f.put("challenge", tampered.to_string().as_bytes(), UP)
            .await
            .status(),
        400
    );
    assert_eq!(
        f.put("challenge", &vec![b'x'; 65537], UP).await.status(),
        413
    );
    assert_eq!(
        f.put("challenge", &challenge(OTHER, expiry), UP)
            .await
            .status(),
        400
    );
    assert_eq!(
        f.put("challenge", &challenge(REQUEST, now() - 1), UP)
            .await
            .status(),
        410
    );
    assert_eq!(f.get("receipt?token=forbidden", UP).await.status(), 400);
    assert_eq!(
        f.client
            .get(format!("{}/challenge", f.base))
            .header("Authorization", format!("Bearer {UP}"))
            .header("Authorization", format!("Bearer {AP}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 201);
    assert_eq!(
        f.put("grant", &fake_grant(REQUEST, expiry + 1), AP)
            .await
            .status(),
        400
    );
    let db = f.db();
    db.execute_batch("CREATE TRIGGER deny_audit BEFORE INSERT ON transport_events BEGIN SELECT RAISE(FAIL,'synthetic'); END;").unwrap();
    let r = f.get("challenge", AP).await;
    assert_eq!(r.status(), 503);
    assert!(!r.text().await.unwrap().contains("signature"));
    for _ in 0..100 {
        if f.relay.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !f.relay
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .unwrap()
            .success()
    );
    f.no_canary();
}
#[tokio::test]
async fn upload_audit_rollback_capacity_retention_and_state_identity() {
    let mut f = Fixture::new().await;
    let db = f.db();
    db.execute_batch("CREATE TRIGGER deny_audit BEFORE INSERT ON transport_events BEGIN SELECT RAISE(FAIL,'synthetic'); END;").unwrap();
    assert_eq!(
        f.put("challenge", &challenge(REQUEST, now() + 60000), UP)
            .await
            .status(),
        503
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    f.stop();
    db.execute_batch("DROP TRIGGER deny_audit").unwrap();
    f.start().await;
    let bytes = challenge(REQUEST, now() + 60000);
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 201);
    db.execute("UPDATE requests SET challenge_expires=?1", [now() - 1])
        .unwrap();
    assert_eq!(f.get("challenge", AP).await.status(), 410);
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 200);
    let receipt: Value =
        serde_json::from_slice(&f.get("receipt", UP).await.bytes().await.unwrap()).unwrap();
    assert_eq!(receipt["challengeExpired"], true);
    // A full retained audit log cannot be silently pruned to deliver bytes.
    db.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<32768) INSERT INTO transport_events(issuer,subject,request_id,kind,sha256,created,result) SELECT 'i','s','','','',9223372036854775807,'held' FROM n;").unwrap();
    assert_eq!(f.get("receipt", UP).await.status(), 503);
    f.stop();
    db.execute_batch("DELETE FROM transport_events WHERE result='held'")
        .unwrap();
    db.execute(
        "UPDATE requests SET challenge_accepted=?1",
        [now() - 86400001],
    )
    .unwrap();
    f.start().await;
    assert_eq!(f.get("receipt", UP).await.status(), 404);
    f.stop();
    f.config["tenantId"] = json!(OTHER);
    write(&f.path("config.json"), f.config.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
        .args(["serve", "--config"])
        .arg(f.path("config.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("store-identity-mismatch"));
    f.no_canary();
}
#[tokio::test]
async fn bounded_idp_timeout_exclusive_private_files_and_directory_replacement() {
    let mut f = Fixture::new().await;
    f.control(json!({"delay":4}));
    let start = std::time::Instant::now();
    assert_eq!(f.get("receipt", UP).await.status(), 503);
    assert!(start.elapsed() < Duration::from_secs(4));
    assert_eq!(
        f.db()
            .query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
        .args(["serve", "--config"])
        .arg(f.path("config.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("state-in-use"));
    f.control(json!({}));
    fs::rename(f.path("state"), f.path("old-state")).unwrap();
    fs::create_dir(f.path("state")).unwrap();
    fs::set_permissions(f.path("state"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.get("receipt", UP).await.status(), 503);
    f.stop();
    fs::set_permissions(f.path("config.json"), fs::Permissions::from_mode(0o644)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
        .args(["serve", "--config"])
        .arg(f.path("config.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("private-file"));
    f.no_canary();
}

async fn raw_tls(f: &Fixture) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&fs::read(f.path("tls.pem")).unwrap()).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let address = f.config["listenAddress"].as_str().unwrap();
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}
#[tokio::test]
async fn lost_ack_recovers_exact_receipt_without_overwrite() {
    use tokio::io::AsyncWriteExt;
    let mut f = Fixture::new().await;
    let bytes = challenge(REQUEST, now() + 60000);
    let mut stream = raw_tls(&f).await;
    let headers = format!(
        "PUT /v1/requests/{REQUEST}/challenge HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {UP}\r\nX-Rekey-Approver-Id: {APPROVER}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
    // Caller deliberately never reads an ACK. Commit is proven independently by the DB.
    let db = f.db();
    let mut saved = None;
    for _ in 0..100 {
        saved = db
            .query_row(
                "SELECT challenge_receipt FROM requests WHERE id=?1",
                [REQUEST],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .ok();
        if saved.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(stream);
    let saved = saved.expect("PUT did not commit");
    f.stop();
    f.start().await;
    let response = f.put("challenge", &bytes, UP).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), saved.as_slice());
    assert_eq!(
        db.query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    f.no_canary();
}
#[tokio::test]
async fn authentication_expiry_is_rechecked_after_body_before_commit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new().await;
    let bytes = challenge(REQUEST, now() + 60000);
    f.control(json!({"claims":{"exp":now()/1000+2}}));
    let mut stream = raw_tls(&f).await;
    let headers = format!(
        "PUT /v1/requests/{REQUEST}/challenge HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {UP}\r\nX-Rekey-Approver-Id: {APPROVER}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
    stream.flush().await.unwrap();
    for _ in 0..100 {
        if f.path("idp-hits").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(2200)).await;
    stream.write_all(&bytes[bytes.len() - 1..]).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 401"));
    assert_eq!(
        f.db()
            .query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    f.no_canary();
}
#[tokio::test]
async fn explicit_idp_ca_header_limits_and_nonhttps_configuration() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = Fixture::new().await;
    let mut stream = raw_tls(&f).await;
    let mut headers = format!("GET /v1/requests/{REQUEST}/receipt HTTP/1.1\r\nHost: localhost\r\n");
    for n in 0..33 {
        headers.push_str(&format!("X-{n}: a\r\n"));
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.ok();
    assert!(!String::from_utf8_lossy(&bytes).contains("200 OK"));
    assert!(!f.path("idp-hits").exists(), "invalid headers reached IdP");
    f.stop();
    let wrong = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    write(&f.path("wrong-ca.pem"), wrong.cert.pem());
    f.config["idpCaCertificateFile"] = json!(f.path("wrong-ca.pem"));
    f.start().await;
    assert_eq!(f.get("receipt", UP).await.status(), 503);
    assert!(
        !f.path("idp-hits").exists(),
        "wrong CA reached authenticated IdP request"
    );
    f.stop();
    f.config["endpoint"] = json!("http://localhost/v1");
    write(&f.path("config.json"), f.config.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
        .args(["serve", "--config"])
        .arg(f.path("config.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid-config"));
    f.no_canary();
}

#[tokio::test]
async fn request_count_blob_capacity_and_late_grant_retention() {
    let mut f = Fixture::new().await;
    let expiry = now() + 60000;
    assert_eq!(
        f.put("challenge", &challenge(REQUEST, expiry), UP)
            .await
            .status(),
        201
    );
    assert_eq!(
        f.put("grant", &fake_grant(REQUEST, expiry - 1000), AP)
            .await
            .status(),
        201
    );
    let db = f.db();
    f.stop();
    db.execute(
        "UPDATE requests SET challenge_accepted=?1",
        [now() - 86400001],
    )
    .unwrap();
    f.start().await;
    // Late grant's own 24h retention protects both immutable receipts.
    assert_eq!(f.get("receipt", UP).await.status(), 200);
    f.stop();
    db.execute("UPDATE requests SET grant_accepted=?1", [now() - 86400001])
        .unwrap();
    f.start().await;
    assert_eq!(f.get("receipt", UP).await.status(), 404);
    assert_eq!(
        f.put("challenge", &challenge(REQUEST, expiry), UP)
            .await
            .status(),
        201
    );
    db.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4095) INSERT INTO requests(id,tenant,issuer,uploader,recipient,approver,challenge,challenge_sha,challenge_accepted,challenge_expires,challenge_receipt) SELECT printf('50000000-0000-4000-8000-%012x',x),tenant,issuer,uploader,recipient,approver,challenge,challenge_sha,challenge_accepted,challenge_expires,challenge_receipt FROM requests,n WHERE requests.id='33333333-3333-4333-8333-333333333333';").unwrap();
    let bytes = challenge(OTHER, expiry);
    let response = f
        .client
        .put(f.base.replace(REQUEST, OTHER) + "/challenge")
        .bearer_auth(UP)
        .header("x-rekey-approver-id", APPROVER)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        db.query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4096
    );
    db.execute("DELETE FROM requests WHERE id != ?1", [REQUEST])
        .unwrap();
    db.execute(
        "UPDATE requests SET grant=zeroblob(67108864) WHERE id=?1",
        [REQUEST],
    )
    .unwrap();
    let response = f
        .client
        .put(f.base.replace(REQUEST, OTHER) + "/challenge")
        .bearer_auth(UP)
        .header("x-rekey-approver-id", APPROVER)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        db.query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    f.no_canary();
}
#[tokio::test]
async fn absolute_connection_deadline_cancels_incomplete_body_without_late_store() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new().await;
    let bytes = challenge(REQUEST, now() + 60000);
    let started = std::time::Instant::now();
    let mut stream = raw_tls(&f).await;
    let headers = format!(
        "PUT /v1/requests/{REQUEST}/challenge HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {UP}\r\nX-Rekey-Approver-Id: {APPROVER}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(12), stream.read_to_end(&mut response))
        .await
        .expect("server did not close within fixed deadline")
        .ok();
    assert!(
        started.elapsed() >= Duration::from_secs(9) && started.elapsed() < Duration::from_secs(12)
    );
    assert!(!String::from_utf8_lossy(&response).contains("201"));
    stream.write_all(&bytes[bytes.len() - 1..]).await.ok();
    drop(stream);
    assert_eq!(
        f.db()
            .query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(f.get("receipt", UP).await.status(), 404);
    f.no_canary();
}
#[tokio::test]
async fn private_symlink_hardlink_fifo_and_short_header_timeout_are_rejected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = Fixture::new().await;
    let mut stream = raw_tls(&f).await;
    stream.write_all(b"GET /v1/").await.unwrap();
    stream.flush().await.unwrap();
    let start = std::time::Instant::now();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("header timeout absent")
        .ok();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(!f.path("idp-hits").exists());
    f.stop();
    let private = f.path("config.json");
    let linked = f.path("linked-config.json");
    std::os::unix::fs::symlink(&private, &linked).unwrap();
    let run = |path: &Path| {
        Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
            .args(["serve", "--config"])
            .arg(path)
            .output()
            .unwrap()
    };
    assert!(!run(&linked).status.success());
    fs::remove_file(&linked).unwrap();
    fs::hard_link(&private, &linked).unwrap();
    assert!(!run(&linked).status.success());
    fs::remove_file(&linked).unwrap();
    let fifo = f.path("fifo-config");
    let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(!run(&fifo).status.success());
    f.no_canary();
}

#[tokio::test]
async fn inbox_stable_pagination_acl_cursor_and_public_metadata() {
    let f = Fixture::with_approvers(vec![
        json!({"subject":"reviewer","approverId":APPROVER}),
        json!({"subject":"unlisted-same-email","approverId":OTHER}),
    ])
    .await;
    let mut own = Vec::new();
    let expiry = now() + 60000;
    for n in 1..=30 {
        let id = format!("70000000-0000-4000-8000-{n:012x}");
        let r = f
            .client
            .put(f.base.replace(REQUEST, &id) + "/challenge")
            .bearer_auth(UP)
            .header("x-rekey-approver-id", APPROVER)
            .body(challenge(&id, expiry))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201);
        own.push(id);
    }
    let foreign = "70000000-0000-4000-8000-000000000000";
    assert_eq!(
        f.client
            .put(f.base.replace(REQUEST, foreign) + "/challenge")
            .bearer_auth(UP)
            .header("x-rekey-approver-id", OTHER)
            .body(challenge_for(foreign, expiry, OTHER))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let same_created = now();
    f.db()
        .execute("UPDATE requests SET challenge_accepted=?1", [same_created])
        .unwrap();
    let first = f.inbox_value(AP, "").await;
    let items = first["items"].as_array().unwrap();
    assert_eq!(items.len(), 25);
    assert_eq!(first["recordType"], "rekey.approval.inbox.v1");
    assert!(
        first["snapshot"]
            .as_str()
            .unwrap()
            .contains("Broker revalidates at execute")
    );
    for (item, id) in items.iter().zip(&own) {
        assert_eq!(item["requestId"], *id);
        assert_eq!(item["createdAtMs"], same_created);
        assert_eq!(
            item["sourceLabel"],
            format!("ed25519:{}", f.config["originPublicKey"].as_str().unwrap())
        );
        assert_eq!(item["transportStatus"], "awaiting-review");
        assert_eq!(item["detailPath"], format!("/v1/requests/{id}/challenge"));
        let keys: std::collections::BTreeSet<_> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "requestId",
                "sourceLabel",
                "createdAtMs",
                "expiresAtMs",
                "transportStatus",
                "detailPath",
                "receiptPath"
            ])
        );
    }
    let cursor = first["nextCursor"].as_str().unwrap();
    let second = f.inbox_value(AP, &format!("?cursor={cursor}")).await;
    assert_eq!(second["items"].as_array().unwrap().len(), 5);
    assert!(second["nextCursor"].is_null());
    for (item, id) in second["items"].as_array().unwrap().iter().zip(&own[25..]) {
        assert_eq!(item["requestId"], *id);
    }
    let forged = f
        .inbox_value(AP, &format!("?cursor={same_created}:{foreign}"))
        .await;
    assert!(
        forged["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["requestId"] != foreign)
    );
    let other = f.inbox_value("OTHER-APPROVER-TOKEN-CANARY", "").await;
    assert_eq!(other["items"].as_array().unwrap().len(), 1);
    assert_eq!(other["items"][0]["requestId"], foreign);
    assert_eq!(
        f.inbox_value(UP, "").await["items"]
            .as_array()
            .unwrap()
            .len(),
        25
    );
    assert_eq!(
        f.get("challenge", "OTHER-APPROVER-TOKEN-CANARY")
            .await
            .status(),
        404
    );
    for query in [
        "?subject=operator",
        "?cursor=bad",
        "?cursor=-1:33333333-3333-4333-8333-333333333333",
        "?cursor=00:33333333-3333-4333-8333-333333333333",
        "?cursor=0:33333333-3333-4333-8333-333333333333&cursor=0:33333333-3333-4333-8333-333333333333",
        "?includeExpired=1",
        "?includeExpired=true&includeExpired=false",
    ] {
        assert_eq!(f.inbox(AP, query).await.status(), 400);
    }
    assert_eq!(
        f.inbox(AP, &format!("?cursor={}", "x".repeat(257)))
            .await
            .status(),
        400
    );
    assert_eq!(
        f.client
            .post(format!("{}/inbox", f.config["endpoint"].as_str().unwrap()))
            .bearer_auth(AP)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    let endpoint = f.config["endpoint"].as_str().unwrap();
    assert_eq!(
        f.client
            .get(format!("{endpoint}/inbox"))
            .bearer_auth(AP)
            .header("cookie", "forbidden")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        f.client
            .get(format!("{endpoint}/inbox"))
            .bearer_auth(AP)
            .body("body forbidden")
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    f.no_canary();
}
#[tokio::test]
async fn inbox_transport_states_expiry_retry_late_grant_and_restart() {
    let mut f = Fixture::new().await;
    let expiry = now() + 60000;
    let bytes = challenge(REQUEST, expiry);
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 201);
    let original = f.inbox_value(AP, "").await;
    let created = original["items"][0]["createdAtMs"].clone();
    assert_eq!(f.put("grant", b"{}", AP).await.status(), 400);
    assert_eq!(
        f.inbox_value(AP, "").await["items"][0]["transportStatus"],
        "transport-failed"
    );
    f.stop();
    f.start().await;
    assert_eq!(
        f.inbox_value(AP, "").await["items"][0]["transportStatus"],
        "transport-failed"
    );
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 200);
    assert_eq!(
        f.inbox_value(AP, "").await["items"][0]["transportStatus"],
        "awaiting-review"
    );
    let grant_expires = now() + 800;
    let grant = fake_grant(REQUEST, grant_expires);
    assert_eq!(f.put("grant", &grant, AP).await.status(), 201);
    let posted = f.inbox_value(UP, "").await;
    assert_eq!(posted["items"].as_array().unwrap().len(), 1);
    assert_eq!(posted["items"][0]["createdAtMs"], created);
    assert_eq!(posted["items"][0]["expiresAtMs"], grant_expires);
    assert_eq!(posted["items"][0]["transportStatus"], "grant-stored");
    assert_eq!(f.put("grant", &grant, AP).await.status(), 200);
    assert_eq!(
        f.inbox_value(AP, "").await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    tokio::time::sleep(Duration::from_millis(850)).await;
    assert!(
        f.inbox_value(UP, "").await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let expired = f.inbox_value(AP, "?includeExpired=true").await;
    assert_eq!(expired["items"][0]["transportStatus"], "grant-expired");
    assert_eq!(expired["items"][0]["createdAtMs"], created);
    assert_eq!(f.put("grant", &grant, AP).await.status(), 200);
    assert!(
        f.inbox_value(AP, "").await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.client
            .put(f.base.replace(REQUEST, OTHER) + "/challenge")
            .bearer_auth(UP)
            .header("x-rekey-approver-id", APPROVER)
            .body(challenge(OTHER, now() + 300))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    let all = f.inbox_value(AP, "?includeExpired=true").await;
    assert_eq!(all["items"].as_array().unwrap().len(), 2);
    assert!(
        all["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["requestId"] == OTHER && i["transportStatus"] == "expired")
    );
    f.stop();
    f.start().await;
    assert!(
        f.inbox_value(AP, "").await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.no_canary();
}
#[tokio::test]
async fn inbox_dual_role_dedup_fresh_revocation_and_acl_removal() {
    let mut f =
        Fixture::with_approvers(vec![json!({"subject":"operator","approverId":APPROVER})]).await;
    assert_eq!(
        f.put("challenge", &challenge(REQUEST, now() + 60000), UP)
            .await
            .status(),
        201
    );
    assert_eq!(
        f.inbox_value(UP, "").await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(f.inbox(AP, "").await.status(), 404);
    f.control(json!({"claims":{"active":false}}));
    assert_eq!(f.inbox(UP, "").await.status(), 401);
    f.control(json!({"status":503}));
    assert_eq!(f.inbox(UP, "").await.status(), 503);
    f.control(json!({}));
    assert_eq!(
        f.inbox_value(UP, "").await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.stop();
    f.config["uploaderSubject"] = json!("replacement-operator");
    f.config["approvers"][0]["subject"] = json!("reviewer");
    f.config["directory"]["links"][0]["subject"] = json!("reviewer");
    let issuer = f.config["idpIssuer"].clone();
    f.config["directory"]["links"].as_array_mut().unwrap().push(json!({"sourceUserId":"member-new","externalId":"external-new",
        "issuer":issuer,"subject":"replacement-operator","principalId":OTHER,"adminAllowed":true,"confirmedBy":"fixture-registrar","confirmedAtMs":1}));
    write(&f.path("config.json"), f.config.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
        .args(["serve", "--config"])
        .arg(f.path("config.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("store-identity-mismatch"));
    f.no_canary();
}
#[tokio::test]
async fn inbox_audit_commit_before_data_and_failure_returns_no_entries() {
    let mut f = Fixture::new().await;
    assert_eq!(
        f.put("challenge", &challenge(REQUEST, now() + 60000), UP)
            .await
            .status(),
        201
    );
    assert_eq!(
        f.inbox_value(AP, "").await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let db = f.db();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM transport_events WHERE kind='inbox' AND result='downloaded'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    db.execute_batch("CREATE TRIGGER deny_inbox_audit BEFORE INSERT ON transport_events WHEN NEW.kind='inbox' BEGIN SELECT RAISE(FAIL,'synthetic'); END;").unwrap();
    let response = f.inbox(AP, "").await;
    assert_eq!(response.status(), 503);
    let body = response.text().await.unwrap();
    assert!(!body.contains(REQUEST) && !body.contains("items") && !body.contains("sourceLabel"));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM transport_events WHERE kind='inbox' AND result='downloaded'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    f.stop();
    db.execute_batch("DROP TRIGGER deny_inbox_audit").unwrap();
    f.start().await;
    assert_eq!(
        f.inbox_value(AP, "").await["items"][0]["requestId"],
        REQUEST
    );
    f.no_canary();
}

#[tokio::test]
async fn directory_tombstones_fixed_tls_source_and_pending_receipts_survive_restart() {
    let mut f = Fixture::new().await;
    let bytes = challenge(REQUEST, now() + 120000);
    assert_eq!(f.put("challenge", &bytes, UP).await.status(), 201);
    assert_eq!(
        fs::read_to_string(f.path("scim-hits"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    f.stop();
    f.control(json!({"scim":{"member-1":{"claims":{"active":false}}}}));
    f.start().await;
    assert_eq!(f.get("challenge", UP).await.status(), 503);
    assert_eq!(
        f.put("grant", &fake_grant(REQUEST, now() + 60000), AP)
            .await
            .status(),
        503
    );
    let endpoint = format!(
        "{}/directory/revocations",
        f.config["endpoint"].as_str().unwrap()
    );
    assert_eq!(
        f.client
            .get(&endpoint)
            .bearer_auth(AP)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = f
        .client
        .get(&endpoint)
        .bearer_auth(UP)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let receipt: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(receipt["items"][0]["subject"], "reviewer");
    assert_eq!(receipt["items"][0]["affectedRequestIds"], json!([REQUEST]));
    assert_eq!(receipt["items"][0]["nodes"].as_array().unwrap().len(), 2);
    assert!(
        receipt["items"][0]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["status"] == "pending")
    );
    assert!(!receipt.to_string().contains("CANARY"));
    f.stop();
    f.control(json!({}));
    f.start().await;
    assert_eq!(f.get("challenge", AP).await.status(), 503);
    let again: Value = serde_json::from_slice(
        &f.client
            .get(&endpoint)
            .bearer_auth(UP)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt, again);
    f.no_canary();
}
#[tokio::test]
async fn directory_uncertainty_identity_json_status_and_redirect_fail_closed_per_member() {
    let mut f = Fixture::new().await;
    for uncertain in [
        json!({"status":401}),
        json!({"status":403}),
        json!({"status":503}),
        json!({"claims":{"id":"other"}}),
        json!({"claims":{"externalId":"wrong"}}),
        json!({"remove":["active"]}),
        json!({"claims":{"schemas":[]}}),
        json!({"raw":"{\"active\":true,\"active\":false}"}),
        json!({"raw":"x".repeat(65537)}),
        json!({"status":302,"redirect":format!("{}/scim/v2/Users/unregistered",f.config["idpIssuer"].as_str().unwrap())}),
    ] {
        f.stop();
        f.control(json!({"scim":{"member-1":uncertain}}));
        f.start().await;
        assert_eq!(f.inbox(AP, "").await.status(), 503);
        let response = f
            .client
            .get(format!(
                "{}/directory/revocations",
                f.config["endpoint"].as_str().unwrap()
            ))
            .bearer_auth(UP)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let v: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(v["items"], json!([]));
    }
    assert!(
        !fs::read_to_string(f.path("scim-hits"))
            .unwrap()
            .contains("unregistered")
    );
    f.no_canary();
}
#[tokio::test]
async fn directory_timeout_token_expiry_and_authenticated_absence_are_distinct() {
    let mut f = Fixture::new().await;
    f.stop();
    f.control(json!({"scim":{"member-1":{"delay":4}}}));
    let start = std::time::Instant::now();
    f.start().await;
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(f.inbox(AP, "").await.status(), 503);
    assert_eq!(
        f.db()
            .query_row::<i64, _, _>("SELECT count(*) FROM directory_revocations", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    f.stop();
    f.control(json!({}));
    write(
        &f.path("directory-token.json"),
        json!({"accessToken":"DIRECTORY-TOKEN-CANARY","expiresAtMs":now()-1}).to_string(),
    );
    let hits = fs::read_to_string(f.path("scim-hits")).unwrap();
    f.start().await;
    assert_eq!(f.inbox(UP, "").await.status(), 503);
    assert_eq!(fs::read_to_string(f.path("scim-hits")).unwrap(), hits);
    f.stop();
    write(
        &f.path("directory-token.json"),
        json!({"accessToken":"DIRECTORY-TOKEN-CANARY","expiresAtMs":now()+1500}).to_string(),
    );
    f.control(json!({"scim":{"member-1":{"delay":2}}}));
    f.start().await;
    assert_eq!(f.inbox(AP, "").await.status(), 503);
    assert_eq!(
        f.db()
            .query_row::<i64, _, _>("SELECT count(*) FROM directory_revocations", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    f.stop();
    write(
        &f.path("directory-token.json"),
        json!({"accessToken":"DIRECTORY-TOKEN-CANARY","expiresAtMs":now()+120000}).to_string(),
    );
    f.control(json!({"scim":{"member-1":{"status":404}}}));
    f.start().await;
    assert_eq!(
        f.db()
            .query_row::<i64, _, _>("SELECT count(*) FROM directory_revocations", [], |r| r
                .get(0))
            .unwrap(),
        1
    );
    f.no_canary();
}

#[tokio::test]
async fn directory_uses_only_explicit_private_ca_and_never_ambient_trust() {
    let f = Fixture::with_configuration(
        vec![json!({"subject":"reviewer","approverId":APPROVER})],
        |config, root| {
            let wrong = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            write(&root.join("wrong-directory-ca.pem"), wrong.cert.pem());
            config["directory"]["caCertificateFile"] = json!(root.join("wrong-directory-ca.pem"));
        },
    )
    .await;
    assert_eq!(f.inbox(UP, "").await.status(), 503);
    assert_eq!(f.inbox(AP, "").await.status(), 503);
    assert_eq!(
        f.db()
            .query_row::<i64, _, _>("SELECT count(*) FROM directory_revocations", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    assert!(!f.path("scim-hits").exists());
    f.no_canary();
}

#[test]
fn offline_directory_registration_reads_only_protected_profile_and_has_public_closed_shape() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("must-not-be-read");
    let mut config = json!({"formatVersion":2,"instanceId":OTHER,"endpoint":"https://localhost:443/v1",
        "listenAddress":"127.0.0.1:443","stateDir":missing,"tlsCertificateFile":missing,
        "tlsKeyFile":missing,"idpIssuer":"https://issuer.test","introspectionUrl":"https://issuer.test/introspect",
        "idpCaCertificateFile":missing,"introspectionClientId":"client","introspectionClientSecretFile":missing,
        "personnelClientId":"personnel","audience":"relay","tenantId":TENANT,"originPublicKey":HEXLOWER.encode(key().public_key().as_ref()),
        "uploaderSubject":"operator","approvers":[{"subject":"reviewer","approverId":APPROVER}],
        "directory":{"baseUrl":"https://directory.test/scim/v2","caCertificateFile":missing,"accessTokenFile":missing,
        "mappingVersion":1,"nodes":[{"nodeId":TENANT,"vaultId":APPROVER},{"nodeId":REQUEST,"vaultId":OTHER}],
        "links":[{"sourceUserId":"operator","externalId":"operator","issuer":"https://issuer.test","subject":"operator",
        "principalId":TENANT,"adminAllowed":true,"confirmedBy":"registrar","confirmedAtMs":1},
        {"sourceUserId":"reviewer","externalId":"reviewer","issuer":"https://issuer.test","subject":"reviewer",
        "principalId":OTHER,"approverId":APPROVER,"publicKeySha256":"02".repeat(32),"adminAllowed":false,"confirmedBy":"registrar","confirmedAtMs":1}]}});
    let path = root.path().join("config.json");
    write(&path, config.to_string());
    let run = |path: &Path| {
        Command::new(env!("CARGO_BIN_EXE_rekey-approval-relay"))
            .args(["directory-registration", "--config"])
            .arg(path)
            .output()
            .unwrap()
    };
    let output = run(&path);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 4096);
    assert!(!missing.exists());
    let proof: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        proof
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "formatVersion",
            "mappingVersion",
            "mappingSha256",
            "nodes"
        ])
    );
    assert_eq!(proof["formatVersion"], 1);
    assert_eq!(proof["nodes"], config["directory"]["nodes"]);
    assert_eq!(proof["mappingSha256"].as_str().unwrap().len(), 64);
    config["directory"]["links"][1]["adminAllowed"] = json!(true);
    write(&path, config.to_string());
    let changed: Value = serde_json::from_slice(&run(&path).stdout).unwrap();
    assert_ne!(changed["mappingSha256"], proof["mappingSha256"]);
    config["directory"]["links"][0]
        .as_object_mut()
        .unwrap()
        .remove("adminAllowed");
    write(&path, config.to_string());
    assert!(!run(&path).status.success());
    write(&path, b"{}");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let failed = run(&path);
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    let link = root.path().join("symlink.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(!run(&link).status.success());
}

#[tokio::test]
async fn admin_identity_fresh_self_only_fixed_route_and_transport_acl() {
    let f = Fixture::with_configuration(
        vec![json!({"subject":"reviewer","approverId":APPROVER})],
        |config, _| {
            config["directory"]["links"][1]["adminAllowed"] = json!(false);
            let mut admin = config["directory"]["links"][0].clone();
            admin["sourceUserId"] = json!("admin-user");
            admin["externalId"] = json!("admin-person");
            admin["subject"] = json!("administrator");
            admin["principalId"] = json!("55555555-5555-4555-8555-555555555555");
            config["directory"]["links"]
                .as_array_mut()
                .unwrap()
                .push(admin);
        },
    )
    .await;
    let url = format!(
        "{}/directory/admin-identity",
        f.config["endpoint"].as_str().unwrap()
    );
    let before = fs::read_to_string(f.path("idp-hits"))
        .unwrap_or_default()
        .lines()
        .count();
    for _ in 0..2 {
        let reply = f
            .client
            .get(&url)
            .bearer_auth("UPLOADER-TOKEN-CANARY")
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), 200);
        let body = reply.bytes().await.unwrap();
        assert!(body.len() <= 4096);
        let proof: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(proof.as_object().unwrap().len(), 8);
        assert_eq!(proof["subject"], "operator");
        assert_eq!(proof["principalId"], TENANT);
        assert_eq!(proof["nodes"], f.config["directory"]["nodes"]);
        assert!(proof["observedAtMs"].as_i64().unwrap() <= now());
    }
    assert_eq!(
        fs::read_to_string(f.path("idp-hits"))
            .unwrap()
            .lines()
            .count(),
        before + 2
    );
    assert_eq!(f.db().query_row::<i64, _, _>("SELECT count(*) FROM transport_events WHERE kind='directory-admin-identity' AND result='observed'", [], |r| r.get(0)).unwrap(), 2);
    assert_eq!(
        f.client
            .get(&url)
            .bearer_auth("APPROVER-TOKEN-CANARY")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    f.control(json!({"claims":{"sub":"administrator"}}));
    let bytes = f
        .client
        .get(&url)
        .bearer_auth("ADMIN-TOKEN-CANARY")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let proof: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(proof["subject"], "administrator");
    assert_eq!(f.inbox("ADMIN-TOKEN-CANARY", "").await.status(), 404);
    assert_eq!(
        f.put(
            "challenge",
            &challenge(REQUEST, now() + 60000),
            "ADMIN-TOKEN-CANARY"
        )
        .await
        .status(),
        404
    );
    for builder in [
        f.client
            .get(format!("{url}?subject=operator"))
            .bearer_auth("ADMIN-TOKEN-CANARY"),
        f.client
            .get(&url)
            .bearer_auth("ADMIN-TOKEN-CANARY")
            .header("x-rekey-approver-id", APPROVER),
    ] {
        assert_eq!(builder.send().await.unwrap().status(), 400);
    }
    assert_eq!(
        f.client
            .get(&url)
            .bearer_auth("ADMIN-TOKEN-CANARY")
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        f.client
            .put(&url)
            .bearer_auth("ADMIN-TOKEN-CANARY")
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    f.control(json!({"claims":{"sub":"unlisted"}}));
    assert_eq!(
        f.client
            .get(&url)
            .bearer_auth("UNKNOWN-TOKEN-CANARY")
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    f.control(json!({"claims":{"active":false}}));
    assert_eq!(
        f.client
            .get(&url)
            .bearer_auth("ADMIN-TOKEN-CANARY")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    f.no_canary();
}

#[tokio::test]
async fn admin_identity_audit_failure_returns_no_identity_and_faults_service() {
    let f = Fixture::new().await;
    f.db().execute_batch("CREATE TRIGGER fail_admin_audit BEFORE INSERT ON transport_events WHEN NEW.kind='directory-admin-identity' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    let url = format!(
        "{}/directory/admin-identity",
        f.config["endpoint"].as_str().unwrap()
    );
    let reply = f
        .client
        .get(url)
        .bearer_auth("UPLOADER-TOKEN-CANARY")
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 503);
    let body: Value = serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
    assert!(body.get("subject").is_none());
    assert_eq!(
        f.db()
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM transport_events WHERE kind='directory-admin-identity'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        0
    );
    f.no_canary();
}
