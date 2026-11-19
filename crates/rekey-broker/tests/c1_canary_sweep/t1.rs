//! T1 derived credentials through `rekey aws-credentials`,
//! `kubectl-credentials`, `github-token` and the agent socket. The Agent
//! receives a temporary credential by design; only root material is refused,
//! including when the issuer echoes it back as the "temporary" value.
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::connection::{DerivedCredentialConnection, DerivedCredentialTarget, RuleEffect};
use rekey_domain::ipc::{admin_msg, agent_msg};
use serde_json::{Value, json};

use super::cli::Cli;
use super::paths::{approve, reply};
use super::{Fixture, Sweep};

const AWS_ID: &str = "AKIAC1SWEEPROOT00001";
const AWS_SECRET: &str = "c1/aws+root-secret=4b7e9d2a";
/// EKS tokens are presigned locally and carry the access key ID by design,
/// so the EKS credential has its own key ID and only its secret is refused.
const EKS_ID: &str = "AKIAC1SWEEPEKS000001";
const EKS_SECRET: &str = "c1/eks+root-secret=7a1f3c9e";
#[cfg(not(feature = "lab"))]
const INSTALLATION_TOKEN: &str = "c1-installation-token";

pub(super) struct T1 {
    pub(super) grants: Vec<Value>,
    pub(super) roots: Vec<(&'static str, Vec<u8>)>,
    /// PKCS#1 DER of the GitHub App key; empty in the lab build.
    github_key: Vec<u8>,
}

/// Adds the AWS, EKS and (default build) GitHub App root credentials and
/// returns their signed grants plus the root material to refuse.
pub(super) async fn setup(f: &Fixture) -> T1 {
    let aws = f
        .add_credential("c1-aws", "aws-static", &aws_payload(AWS_ID, AWS_SECRET))
        .await;
    let eks = f
        .add_credential("c1-eks", "aws-static", &aws_payload(EKS_ID, EKS_SECRET))
        .await;
    let mut grants = grants(
        &aws,
        "aws",
        900,
        DerivedCredentialTarget::AwsAssumeRole {
            role_arn: "arn:aws:iam::123456789012:role/synthetic".into(),
            region: "us-east-1".into(),
            session_policy: json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::synthetic/*"}]}),
        },
    );
    grants.extend(self::grants(
        &eks,
        "eks",
        900,
        DerivedCredentialTarget::KubernetesEks {
            cluster_id: "synthetic-cluster".into(),
            region: "us-west-2".into(),
        },
    ));
    #[cfg_attr(feature = "lab", allow(unused_mut))]
    let mut roots = vec![
        ("AWS root access key ID", AWS_ID.as_bytes().to_vec()),
        ("AWS root secret", AWS_SECRET.as_bytes().to_vec()),
        ("EKS root secret", EKS_SECRET.as_bytes().to_vec()),
    ];
    #[cfg(feature = "lab")]
    let github_key = Vec::new();
    #[cfg(not(feature = "lab"))]
    let github_key = {
        let private = github_app_key();
        let payload = serde_json::to_vec(
            &json!({"credential_type":"github-app-root-v1","client_id":"Iv1.synthetic",
            "installation_id":42,"private_key_pkcs1_der_base64":BASE64.encode(&private)}),
        )
        .unwrap();
        let app = f
            .add_credential("c1-github-app", "github-app-installation", &payload)
            .await;
        grants.extend(self::grants(&app, "github", 3600, github_target()));
        roots.push(("GitHub App private key", private.clone()));
        private
    };
    T1 {
        grants,
        roots,
        github_key,
    }
}

pub(super) async fn sweep(f: &Fixture, sweep: &mut Sweep, cli: &Cli<'_>, presence: &[u8], t1: &T1) {
    aws(f, sweep, cli, presence).await;
    eks(f, sweep, cli);
    #[cfg(not(feature = "lab"))]
    github(f, sweep, cli, &t1.github_key);
    #[cfg(feature = "lab")]
    let _ = &t1.github_key;
}

fn aws_payload(access_key_id: &str, secret: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"credential_type":"aws-static-v1",
        "access_key_id":access_key_id,"secret_access_key":secret}))
    .unwrap()
}

/// One signed T1 grant per effect, named `<prefix>-allow|approve|deny`.
fn grants(
    credential: &Value,
    prefix: &str,
    ttl: u32,
    target: DerivedCredentialTarget,
) -> Vec<Value> {
    [
        ("allow", RuleEffect::Allow),
        ("approve", RuleEffect::Approve),
        ("deny", RuleEffect::Deny),
    ]
    .into_iter()
    .map(|(suffix, effect)| {
        serde_json::to_value(DerivedCredentialConnection {
            name: format!("{prefix}-{suffix}"),
            credential_id: serde_json::from_value(credential.clone()).unwrap(),
            effect,
            max_ttl_seconds: ttl,
            target: target.clone(),
        })
        .unwrap()
    })
    .collect()
}

fn rfc3339_in(seconds: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    time::OffsetDateTime::from_unix_timestamp(now + seconds)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn sts_success(access_key: &str, secret: &str, session: &str) -> UpstreamResponse {
    let expires = rfc3339_in(600);
    reply(
        200,
        "text/xml",
        format!(
            "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>{access_key}</AccessKeyId>\
             <SecretAccessKey>{secret}</SecretAccessKey><SessionToken>{session}</SessionToken>\
             <Expiration>{expires}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"
        ),
    )
}

fn temporary() -> UpstreamResponse {
    sts_success(
        "ASIAC1SWEEPTEMP00001",
        "c1-temporary-secret",
        "c1-temporary-session",
    )
}

async fn aws(f: &Fixture, sweep: &mut Sweep, cli: &Cli<'_>, presence: &[u8]) {
    // Issuance returns only the temporary credential.
    f.fake.push_response(Ok(temporary()));
    let issued = cli.ok(sweep, &["aws-credentials", "aws-allow"]);
    assert_eq!(issued["Version"], 1);
    assert_eq!(issued["AccessKeyId"], "ASIAC1SWEEPTEMP00001");
    assert_eq!(f.upstream_requests(), 1);
    // Refusals reach no STS.
    assert_eq!(
        cli.error(sweep, &["aws-credentials", "aws-deny"], false),
        "DENIED"
    );
    let pending = ["aws-credentials", "aws-approve", "--no-wait"];
    assert_eq!(cli.error(sweep, &pending, false), "APPROVAL_REQUIRED");
    cli.error(sweep, &["aws-credentials", "aws-deny"], true);
    assert_eq!(f.upstream_requests(), 0);
    // An STS answer that echoes root material is never handed to the Agent.
    let root = AWS_SECRET;
    let echoes = [
        (
            "STS error echoing the root key",
            reply(
                403,
                "text/xml",
                format!(
                    "<ErrorResponse><Error><Message>bad signature for {AWS_ID} {root}</Message></Error></ErrorResponse>"
                ),
            ),
        ),
        (
            "root secret returned as the temporary secret",
            sts_success("ASIAC1SWEEPTEMP00002", root, "c1-temporary-session"),
        ),
        (
            "base64 root secret in the session token",
            sts_success(
                "ASIAC1SWEEPTEMP00003",
                "c1-temporary-secret",
                &BASE64.encode(root.as_bytes()),
            ),
        ),
        (
            "root key ID returned as the temporary key ID",
            sts_success(AWS_ID, "c1-temporary-secret", "c1-temporary-session"),
        ),
    ];
    for (name, response) in echoes {
        f.fake.push_response(Ok(response));
        let output = cli.run(sweep, &["aws-credentials", "aws-allow"], None, false);
        assert!(!output.status.success(), "{name} was issued");
        assert_eq!(f.upstream_requests(), 1, "{name}");
    }
    // The approval path: agent request, local review and decision, CLI retry.
    let requested = f
        .agent(
            agent_msg::DERIVE_CREDENTIAL,
            json!({"connection":"aws-approve"}),
        )
        .await;
    sweep.check(
        "agent",
        "derive pending metadata",
        requested.metadata.to_string().as_bytes(),
    );
    sweep.check("agent", "derive pending body", &requested.body);
    assert_eq!(requested.err_code(), "APPROVAL_REQUIRED");
    let id = requested.metadata["approval"]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned();
    approve(f, sweep, &id, presence, admin_msg::APPROVAL_LOCAL_APPROVE).await;
    assert_eq!(f.upstream_requests(), 0);
    f.fake.push_response(Ok(temporary()));
    let issued = cli.ok(
        sweep,
        &["aws-credentials", "aws-approve", "--approval", &id],
    );
    assert_eq!(issued["AccessKeyId"], "ASIAC1SWEEPTEMP00001");
    assert_eq!(f.upstream_requests(), 1);
}

fn eks(f: &Fixture, sweep: &mut Sweep, cli: &Cli<'_>) {
    // The token is presigned locally: no upstream, no root secret.
    let issued = cli.ok(sweep, &["kubectl-credentials", "eks-allow"]);
    assert_eq!(issued["kind"], "ExecCredential");
    let token = issued["status"]["token"].as_str().unwrap();
    assert!(token.starts_with("k8s-aws-v1."));
    assert_eq!(
        cli.error(sweep, &["kubectl-credentials", "eks-deny"], false),
        "DENIED"
    );
    let pending = ["kubectl-credentials", "eks-approve", "--no-wait"];
    assert_eq!(cli.error(sweep, &pending, false), "APPROVAL_REQUIRED");
    cli.error(sweep, &pending, true);
    assert_eq!(f.upstream_requests(), 0);
}

#[cfg(not(feature = "lab"))]
fn github_target() -> DerivedCredentialTarget {
    DerivedCredentialTarget::GitHubApp {
        installation_id: 42,
        repository_ids: vec![7],
        permissions: [
            ("issues".into(), "write".into()),
            ("metadata".into(), "read".into()),
        ]
        .into_iter()
        .collect(),
    }
}

/// A synthetic 2048-bit RSA App key as PKCS#1 DER, made with the system OpenSSL.
#[cfg(not(feature = "lab"))]
fn github_app_key() -> Vec<u8> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let generated = Command::new("/usr/bin/openssl")
        .args(["genrsa", "2048"])
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(generated.status.success(), "synthetic RSA generation");
    let mut converter = Command::new("/usr/bin/openssl");
    converter.arg("rsa");
    #[cfg(target_os = "linux")]
    converter.arg("-traditional");
    let mut convert = converter
        .args(["-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    convert
        .stdin
        .take()
        .unwrap()
        .write_all(&generated.stdout)
        .unwrap();
    let private = convert.wait_with_output().unwrap();
    assert!(private.status.success(), "synthetic RSA conversion");
    private.stdout
}

#[cfg(not(feature = "lab"))]
fn installation(token: &str) -> UpstreamResponse {
    reply(
        201,
        "application/json",
        serde_json::to_vec(&json!({"token":token,"expires_at":rfc3339_in(1800),
            "repositories":[{"id":7}],"permissions":{"issues":"write","metadata":"read"}}))
        .unwrap(),
    )
}

#[cfg(not(feature = "lab"))]
fn github(f: &Fixture, sweep: &mut Sweep, cli: &Cli<'_>, private_key: &[u8]) {
    f.fake.push_response(Ok(installation(INSTALLATION_TOKEN)));
    let issued = cli.run(sweep, &["github-token", "github-allow"], None, false);
    assert!(
        issued.status.success(),
        "github-token: {}",
        String::from_utf8_lossy(&issued.stderr)
    );
    assert!(String::from_utf8_lossy(&issued.stdout).contains(INSTALLATION_TOKEN));
    // The App JWT can mint tokens for the whole installation: it is root
    // material for every later output.
    let requests = f.fake.take_requests();
    assert_eq!(requests.len(), 1);
    let jwt = requests[0]
        .auth_value
        .strip_prefix(b"Bearer ")
        .unwrap()
        .to_vec();
    sweep.refuse("GitHub App JWT", &jwt);
    assert_eq!(
        cli.error(sweep, &["github-token", "github-deny"], false),
        "DENIED"
    );
    let pending = ["github-token", "github-approve", "--no-wait"];
    assert_eq!(cli.error(sweep, &pending, false), "APPROVAL_REQUIRED");
    assert_eq!(f.upstream_requests(), 0);
    let jwt = String::from_utf8(jwt).unwrap();
    let key = BASE64.encode(private_key);
    let echoes = [
        (
            "error echoing the App JWT",
            reply(401, "application/json", json!({"message":jwt}).to_string()),
        ),
        (
            "App JWT returned as the installation token",
            installation(&jwt),
        ),
        ("private key returned as the token", installation(&key)),
        (
            "error echoing the private key",
            reply(422, "application/json", json!({"message":key}).to_string()),
        ),
    ];
    for (name, response) in echoes {
        f.fake.push_response(Ok(response));
        let output = cli.run(sweep, &["github-token", "github-allow"], None, false);
        assert!(!output.status.success(), "{name} was issued");
        assert_eq!(f.upstream_requests(), 1, "{name}");
    }
}
