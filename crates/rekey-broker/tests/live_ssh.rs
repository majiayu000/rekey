//! Explicit, manual C10 acceptance against the user-authorized Rekey repository.
//! Registers only a generated public deploy key; cleanup removes the key and test ref.
mod common;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use data_encoding::BASE64;
use rekey_domain::ids::PolicyRuleId;
use rekey_domain::ipc::{self, Channel, ProofKind, admin_msg};
use rekey_vault::crypto::kdf::Argon2Params;
use serde_json::{Value, json};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const REPO: &str = "majiayu000/rekey";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn api(method: &str, endpoint: &str, input: Option<Value>) -> Result<Value> {
    use std::io::Write;
    let mut cmd = Command::new("gh");
    cmd.args(["api", "--method", method, endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if input.is_some() {
        cmd.args(["--input", "-"]).stdin(Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or("missing API input")?
            .write_all(&serde_json::to_vec(&input)?)?;
    }
    let result = child.wait_with_output()?;
    if !result.status.success() {
        let not_found = serde_json::from_slice::<Value>(&result.stdout)
            .ok()
            .is_some_and(|v| v["status"] == "404");
        return Err(std::io::Error::new(
            if not_found {
                std::io::ErrorKind::NotFound
            } else {
                std::io::ErrorKind::Other
            },
            format!("GitHub {method} {endpoint} failed"),
        )
        .into());
    }
    if result.stdout.is_empty() {
        Ok(json!({}))
    } else {
        Ok(serde_json::from_slice(&result.stdout)?)
    }
}

struct RemoteCleanup {
    key: Option<u64>,
    branch: String,
}
impl RemoteCleanup {
    fn clean(&mut self) -> Result<()> {
        // A failed push can still have committed its remote ref. Query before cleanup.
        let endpoint = format!("repos/{REPO}/git/refs/heads/{}", self.branch);
        match api("GET", &endpoint, None) {
            Ok(_) => {
                api("DELETE", &endpoint, None)?;
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        if let Some(key) = self.key {
            api("DELETE", &format!("repos/{REPO}/keys/{key}"), None)?;
            self.key = None;
        }
        Ok(())
    }
}
impl Drop for RemoteCleanup {
    fn drop(&mut self) {
        if let Err(error) = self.clean() {
            eprintln!("C10 cleanup requires attention: {error}");
        }
    }
}

fn git(dir: &std::path::Path, args: &[&str]) -> Result<()> {
    let result = Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if result.success() {
        Ok(())
    } else {
        Err("local Git fixture failed".into())
    }
}

async fn admin(
    broker: &common::TestBroker,
    opcode: u16,
    meta: Value,
    body: &[u8],
) -> common::WireResponse {
    common::call(
        &broker.admin_sock(),
        Channel::Admin,
        opcode,
        &serde_json::to_vec(&meta).unwrap(),
        body,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires authenticated gh and explicitly authorized live GitHub writes"]
async fn openssh_git_push_uses_rekey_generated_key_and_cleans_remote_resources() -> Result<()> {
    let broker = common::start_broker_with_kdf(
        Duration::from_secs(600),
        Duration::from_secs(2),
        Argon2Params::RFC9106_LOW_MEMORY,
    )
    .await;
    common::unlock(&broker).await;
    let generated = admin(
        &broker,
        admin_msg::SSH_KEY,
        json!({"action":"generate","label":"C10 temporary deploy key","mode":"ed25519_software"}),
        &common::proof_body(common::PASSWORD),
    )
    .await;
    generated.ok();
    let identity: Value = serde_json::from_slice(&generated.body)?;
    let public = identity["public_key"]
        .as_str()
        .ok_or("missing SSH public key")?
        .to_owned();
    let keys = api("GET", "meta", None)?;
    let host = keys["ssh_keys"]
        .as_array()
        .ok_or("missing official SSH host keys")?
        .iter()
        .filter_map(Value::as_str)
        .find(|k| k.starts_with("ssh-ed25519 "))
        .ok_or("missing GitHub Ed25519 host key")?;
    let host_blob = host
        .split_whitespace()
        .nth(1)
        .ok_or("invalid public host key")?;
    BASE64
        .decode(host_blob.as_bytes())
        .map_err(|_| "invalid public host key")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    common::policy::activate_snapshot(&broker,json!({"format_version":8,"version":1,"expires_at_ms":now+600000,"approvers":[],"connections":[],"derived_credentials":[],"profiles":[],"workload_identities":[],"bindings":[],"rules":[],
        "ssh_keys":[{"name":"live-github-ssh","credential_id":identity["credential"]["id"],"user_public_key":public,"hosts":[{"host":"ssh.github.com","host_key":host_blob,"rule_id":PolicyRuleId::new_random(),"effect":"allow"}],"git_signing":"deny","approver":{"kind":"local-presence"},"session_budget":{"max_signatures":100,"max_seconds":600}}]})).await;

    // Replace the synthetic fixture password before the public key gains live permissions.
    let mut random = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(&mut *random)
        .map_err(|_| "random proof generation failed")?;
    let password = Zeroizing::new(BASE64.encode(&*random).into_bytes());
    let mut change = Zeroizing::new(Vec::new());
    ipc::encode_proof_and_secret_body(
        ProofKind::Password,
        common::PASSWORD,
        &password,
        &mut change,
    );
    admin(&broker, admin_msg::PASSWORD_CHANGE, json!({}), &change)
        .await
        .ok();
    let mut proof = Zeroizing::new(Vec::new());
    ipc::encode_proof_body(ProofKind::Password, &password, &mut proof);
    let remembered = admin(
        &broker,
        admin_msg::DESKTOP_REMEMBER,
        json!({"lifetime_ms":604800000}),
        &proof,
    )
    .await;
    remembered.ok();
    let presence = Zeroizing::new(remembered.body);
    let branch = format!("rekey-c10-acceptance-{now}");
    let mut cleanup = RemoteCleanup {
        key: None,
        branch: branch.clone(),
    };
    let result:Result<()>=async {
        let key=api("POST",&format!("repos/{REPO}/keys"),Some(json!({"title":format!("Rekey C10 acceptance {now}"),"key":format!("ssh-ed25519 {public}"),"read_only":false})))?;
        cleanup.key=Some(key["id"].as_u64().ok_or("missing deploy key receipt")?);
        let work=broker.dir.path().join("git-fixture");std::fs::create_dir(&work)?;
        std::fs::write(work.join("README.md"),"Temporary Rekey 0.4 C10 acceptance branch.\n")?;
        git(&work,&["init","-b",&branch])?;git(&work,&["add","README.md"])?;
        git(&work,&["-c","user.name=Rekey acceptance","-c","user.email=rekey-acceptance@users.noreply.github.com","-c","commit.gpgsign=false","commit","-m","test: verify Rekey SSH agent"])?;
        let public_file=broker.dir.path().join("identity.pub");std::fs::write(&public_file,format!("ssh-ed25519 {public}\n"))?;
        let known=broker.dir.path().join("known_hosts");std::fs::write(&known,format!("[ssh.github.com]:443 {host}\n"))?;
        let ssh=broker.dir.path().join("ssh-command.sh");
        std::fs::write(&ssh,format!("#!/bin/sh\nexec /usr/bin/ssh -F /dev/null -p 443 -o BatchMode=yes -o ConnectTimeout=10 -o ConnectionAttempts=1 -o HostKeyAlgorithms=ssh-ed25519 -o StrictHostKeyChecking=yes -o UserKnownHostsFile='{}' -o IdentityAgent='{}' -o IdentitiesOnly=yes -i '{}' \"$@\"\n",known.display(),broker.state_dir.join("ssh-agent.sock").display(),public_file.display()))?;
        use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&ssh,std::fs::Permissions::from_mode(0o700))?;
        let mut child=tokio::process::Command::new("git").current_dir(&work).args(["-c",&format!("core.sshCommand={}",ssh.display()),"push",&format!("ssh://git@ssh.github.com:443/{REPO}.git"),&format!("HEAD:refs/heads/{branch}")]).kill_on_drop(true).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(45);
        let status=loop {
            if let Some(status)=child.try_wait()? {break status;}
            if tokio::time::Instant::now()>=deadline {child.kill().await?;return Err("OpenSSH push timed out".into());}
            let pending=admin(&broker,admin_msg::APPROVAL_PENDING,json!({}),&[]).await;
            for item in pending.ok()["challenges"].as_array().ok_or("invalid pending response")? {
                let id=item["approval_request_id"].clone();
                let review=admin(&broker,admin_msg::APPROVAL_LOCAL_REVIEW,json!({"approval_request_id":id}),&[]).await;review.ok();
                let mut body=Zeroizing::new(Vec::new());ipc::encode_proof_body(ProofKind::Presence,&presence,&mut body);
                admin(&broker,admin_msg::APPROVAL_LOCAL_APPROVE,json!({"approval_request_id":id,"expected_review_sha256":review.metadata["review_sha256"]}),&body).await.ok();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        if !status.success() {
            use tokio::io::AsyncReadExt;
            let mut diagnostic=String::new();if let Some(mut err)=child.stderr.take(){err.read_to_string(&mut diagnostic).await?;}
            return Err(format!("OpenSSH push failed: {diagnostic}").into());
        }
        let remote=api("GET",&format!("repos/{REPO}/git/refs/heads/{branch}"),None)?;
        if remote["ref"]!=format!("refs/heads/{branch}"){return Err("remote test ref was not created".into());}
        let audit=admin(&broker,admin_msg::AUDIT_QUERY,json!({"limit":50}),&[]).await;audit.ok();
        let audit:Value=serde_json::from_slice(&audit.body)?;
        if !audit["events"].as_array().ok_or("missing audit rows")?.iter().any(|row|row["event_type"]=="ssh.sign"){return Err("OpenSSH signature audit is missing".into());}
        println!("C10 actual OpenSSH push verified: {REPO}, transient branch {branch}");
        Ok(())
    }.await;
    let cleaned = cleanup.clean();
    admin(&broker, admin_msg::SHUTDOWN, json!({}), &proof)
        .await
        .ok();
    let task = tokio::time::timeout(Duration::from_secs(5), broker.serve_task).await?;
    task??;
    cleaned?;
    result
}
