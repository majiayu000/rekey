//! C1 / I1 for the paths the base sweep leaves out: LLM streaming (see
//! `stream.rs`), T1
//! derived credentials, approval-gated SSH signing and OAuth Connections.
//! Each path holds its own synthetic root material, and every caller surface
//! that reaches the path must refuse every form of all of it. T1 hands the
//! Agent a temporary credential by design; only its root material is refused.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::connection::{
    ConnectionLlmLimits, DerivedCredentialConnection, DerivedCredentialTarget, OAuthBinding,
    OAuthProvider, RuleEffect,
};
use rekey_domain::ipc::{ProofKind, admin_msg, agent_msg, encode_proof_body};
use serde_json::{Value, json};
use tokio::net::UnixStream;

use super::cli::Cli;
use super::mcp::Mcp;
use super::stream::{LLM_KEY, llm_stream_sweep};
use super::{Extra, Fixture, Sweep, common, percent_encode, ssh_blob, ssh_support};

/// Synthetic root material; `/`, `+` and `=` make the encoded forms differ
/// from the raw bytes, as in the base sweep.
const OAUTH_CLIENT_SECRET: &str = "c1-oauth-client/8c+Qz=secret";
const OAUTH_REFRESH: &str = "c1-oauth-refresh/3b+Wk=token";
const OAUTH_ACCESS: &str = "c1-oauth-access/6f+Pj=bearer";
const AWS_ID: &str = "AKIAC1SWEEPROOT00001";
const AWS_SECRET: &str = "c1/aws+root-secret=4b7e9d2a";
const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
const DRIVE_PATH: &str = "/drive/v3/files";
/// Host key registered by the base fixture for `synthetic.example`.
const HOST_SEED: [u8; 32] = [29; 32];

pub(super) async fn sweep() {
    let mut f = Fixture::boot().await;
    let messages_key = f
        .add_credential("c1-llm-messages", "opaque-token", LLM_KEY)
        .await;
    let chat_key = f
        .add_credential("c1-llm-chat", "opaque-token", LLM_KEY)
        .await;
    let oauth = f
        .add_credential("c1-oauth", "oauth-grant", &oauth_payload())
        .await;
    let aws = f
        .add_credential("c1-aws", "aws-static", &aws_payload())
        .await;
    let identity = f
        .activate(Extra {
            connections: vec![
                llm_connection("anthropic", "llm-messages", messages_key),
                llm_connection("openai", "llm-chat", chat_key),
                drive_connection(oauth),
            ],
            derived_credentials: [
                ("aws-allow", RuleEffect::Allow),
                ("aws-approve", RuleEffect::Approve),
                ("aws-deny", RuleEffect::Deny),
            ]
            .into_iter()
            .map(|(name, effect)| aws_grant(&aws, name, effect))
            .collect(),
        })
        .await;
    let mut sweep = Sweep::new();
    sweep.refuse("LLM key", LLM_KEY);
    for (label, secret) in [
        ("OAuth client secret", OAUTH_CLIENT_SECRET),
        ("OAuth refresh token", OAUTH_REFRESH),
        ("OAuth access token", OAUTH_ACCESS),
        ("AWS root access key ID", AWS_ID),
        ("AWS root secret", AWS_SECRET),
    ] {
        sweep.refuse(label, secret.as_bytes());
    }
    // The presence ticket is root material too.
    let remembered = f
        .admin(
            admin_msg::DESKTOP_REMEMBER,
            json!({"lifetime_ms":600_000}),
            &common::proof_body(common::PASSWORD),
        )
        .await;
    remembered.ok();
    sweep.refuse("presence ticket", &remembered.body);
    let presence = remembered.body.clone();

    let cli = Cli::new(&f, "paths-cli-home");
    let listed = cli.ok(&mut sweep, &["list", "--json"]);
    assert_eq!(listed["connections"].as_array().unwrap().len(), 4);
    llm_stream_sweep(&f, &mut sweep).await;
    t1_sweep(&f, &mut sweep, &cli, &presence).await;
    ssh_approval_sweep(&f, &mut sweep, &identity, &presence).await;
    let mut mcp = Mcp::initialized(&f, &mut sweep);
    oauth_sweep(&f, &mut sweep, &cli, &mut mcp).await;
    mcp.finish(&mut sweep);
    // Every path really ran: a skipped step must not pass as clean.
    for (surface, minimum) in [
        ("stream", 2 * 2 * 8),
        ("cli", 2 * 12),
        ("agent", 2),
        ("admin", 4),
        ("ssh", 4),
        ("http", 7),
        ("mcp", 7),
    ] {
        let seen = sweep.outputs.get(surface).copied().unwrap_or(0);
        assert!(seen >= minimum, "{surface}: {seen} outputs checked");
    }
    f.finish().await;
}

fn llm_connection(preset: &str, name: &str, credential: Value) -> Value {
    let mut connection = rekey_policy::presets::builtin_preset(preset)
        .unwrap()
        .connection(name.into(), serde_json::from_value(credential).unwrap());
    connection.llm = Some(ConnectionLlmLimits {
        models: ["synthetic-model".into()].into_iter().collect(),
        max_tokens: 32,
        max_requests_per_day: 100,
        max_output_tokens_per_day: 100_000,
    });
    serde_json::to_value(connection).unwrap()
}

fn oauth_payload() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"credential_type":"oauth-grant-v1","provider":"google",
        "client_id":"synthetic-client","client_secret":OAUTH_CLIENT_SECRET,
        "refresh_token":OAUTH_REFRESH,"scopes":[DRIVE_SCOPE],"expires_at_ms":null}),
    )
    .unwrap()
}

fn drive_connection(credential: Value) -> Value {
    let mut connection = rekey_policy::presets::builtin_preset("google-drive")
        .unwrap()
        .connection("drive".into(), serde_json::from_value(credential).unwrap());
    connection.oauth = Some(OAuthBinding {
        provider: OAuthProvider::Google,
        client_id: "synthetic-client".into(),
        scopes: [DRIVE_SCOPE.into()].into_iter().collect(),
    });
    serde_json::to_value(connection).unwrap()
}

fn aws_payload() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"credential_type":"aws-static-v1","access_key_id":AWS_ID,
        "secret_access_key":AWS_SECRET}),
    )
    .unwrap()
}

fn aws_grant(credential: &Value, name: &str, effect: RuleEffect) -> Value {
    serde_json::to_value(DerivedCredentialConnection {
        name: name.into(),
        credential_id: serde_json::from_value(credential.clone()).unwrap(),
        effect,
        max_ttl_seconds: 900,
        target: DerivedCredentialTarget::AwsAssumeRole {
            role_arn: "arn:aws:iam::123456789012:role/synthetic".into(),
            region: "us-east-1".into(),
            session_policy: json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::synthetic/*"}]}),
        },
    })
    .unwrap()
}

fn reply(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".to_owned(), content_type.to_owned())].into(),
        body: body.into().into(),
    }
}

// ---- T1 derived credentials (CLI credential_process and the agent socket) ----

fn sts_success(access_key: &str, secret: &str, session: &str) -> UpstreamResponse {
    let expires = time::OffsetDateTime::from_unix_timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 600,
    )
    .unwrap()
    .format(&time::format_description::well_known::Rfc3339)
    .unwrap();
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

async fn t1_sweep(f: &Fixture, sweep: &mut Sweep, cli: &Cli<'_>, presence: &[u8]) {
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

/// Reviews one pending request and decides it with the presence ticket.
async fn approve(f: &Fixture, sweep: &mut Sweep, id: &str, presence: &[u8], decision: u16) {
    let review = f
        .admin(
            admin_msg::APPROVAL_LOCAL_REVIEW,
            json!({"approval_request_id":id}),
            &[],
        )
        .await;
    sweep.check(
        "admin",
        "approval review metadata",
        review.metadata.to_string().as_bytes(),
    );
    sweep.check("admin", "approval review body", &review.body);
    let hash = review.ok()["review_sha256"].clone();
    let mut proof = Vec::new();
    encode_proof_body(ProofKind::Presence, presence, &mut proof);
    let decided = f
        .admin(
            decision,
            json!({"approval_request_id":id,"expected_review_sha256":hash}),
            &proof,
        )
        .await;
    sweep.check(
        "admin",
        "approval decision",
        decided.metadata.to_string().as_bytes(),
    );
    decided.ok();
}

// ---- Approval-gated SSH signing (the SSH agent socket) ----

async fn pending_approval(f: &Fixture) -> String {
    for _ in 0..250 {
        let reply = f.admin(admin_msg::APPROVAL_PENDING, json!({}), &[]).await;
        if let Some(id) = reply.ok()["challenges"]
            .as_array()
            .unwrap()
            .first()
            .and_then(|challenge| challenge["approval_request_id"].as_str())
        {
            return id.to_owned();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the SSH signing approval never appeared");
}

async fn ssh_approval_sweep(f: &Fixture, sweep: &mut Sweep, identity: &Value, presence: &[u8]) {
    let public = BASE64
        .decode(identity["public_key"].as_str().unwrap().as_bytes())
        .unwrap();
    let host = Ed25519KeyPair::from_seed_unchecked(&HOST_SEED).unwrap();
    let host_public = ssh_blob(b"ssh-ed25519", &[host.public_key().as_ref()]);
    let within = common::test_timeout(Duration::from_secs(30));
    for (round, decision, expected) in [
        (
            1_u8,
            admin_msg::APPROVAL_LOCAL_APPROVE,
            ssh_support::SIGNATURE,
        ),
        (2, admin_msg::APPROVAL_LOCAL_REJECT, ssh_support::FAILURE),
    ] {
        let mut agent = UnixStream::connect(f.state.join("ssh-agent.sock"))
            .await
            .unwrap();
        let session = [round; 32];
        ssh_support::send(
            &mut agent,
            &ssh_support::bind(&host, &host_public, &session),
        )
        .await;
        let bound = ssh_support::response(&mut agent, within).await.unwrap();
        sweep.check("ssh", "session bind", &bound);
        assert_eq!(bound, [6], "registered host bind");
        let sign = ssh_support::request(&public, &ssh_support::userauth(&public, &session));
        let waiting = tokio::spawn(async move {
            ssh_support::send(&mut agent, &sign).await;
            ssh_support::response(&mut agent, within).await
        });
        let id = pending_approval(f).await;
        approve(f, sweep, &id, presence, decision).await;
        let answer = waiting.await.unwrap().expect("SSH agent answered");
        sweep.check("ssh", "approval-gated sign", &answer);
        assert_eq!(answer[0], expected, "round {round}");
    }
    assert_eq!(f.upstream_requests(), 0);
}

// ---- OAuth Connections (local HTTP, CLI and MCP) ----

fn token_response() -> UpstreamResponse {
    reply(
        200,
        "application/json",
        serde_json::to_vec(
            &json!({"access_token":OAUTH_ACCESS,"refresh_token":OAUTH_REFRESH,
            "token_type":"Bearer","expires_in":3600,"scope":DRIVE_SCOPE}),
        )
        .unwrap(),
    )
}

/// Upstream answers that echo one OAuth secret.
fn oauth_reflections(secret: &str) -> Vec<(String, UpstreamResponse)> {
    let bearer = format!("Bearer {secret}");
    vec![
        ("raw body".into(), reply(200, "text/plain", secret)),
        (
            "base64 body".into(),
            reply(200, "text/plain", BASE64.encode(secret.as_bytes())),
        ),
        (
            "JSON-escaped body".into(),
            reply(
                200,
                "application/json",
                json!({ "echo": secret }).to_string(),
            ),
        ),
        (
            "percent body".into(),
            reply(
                200,
                "text/plain",
                percent_encode(secret.as_bytes(), true, true),
            ),
        ),
        (
            "authorization echo".into(),
            reply(200, "text/plain", BASE64.encode(bearer.as_bytes())),
        ),
        (
            "error status echo".into(),
            reply(401, "text/plain", format!("invalid token {secret}")),
        ),
        (
            "header echo".into(),
            reply(
                200,
                &format!(
                    "text/plain; charset={}",
                    BASE64URL_NOPAD.encode(secret.as_bytes())
                ),
                "{}",
            ),
        ),
    ]
}

/// One local HTTP GET whose status line, headers and body are checked.
async fn http_get(sweep: &mut Sweep, client: &reqwest::Client, url: &str, what: &str) -> u16 {
    let response = client.get(url).bearer_auth("rekey").send().await.unwrap();
    let status = response.status().as_u16();
    let mut output = format!("HTTP {status}\n").into_bytes();
    for (name, value) in response.headers() {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.push(b'\n');
    }
    output.extend_from_slice(&response.bytes().await.unwrap());
    sweep.check("http", what, &output);
    status
}

async fn oauth_sweep(f: &Fixture, sweep: &mut Sweep, cli: &Cli<'_>, mcp: &mut Mcp) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("{}/c/drive{DRIVE_PATH}", f.service_url);
    let mcp_get = json!({"connection":"drive","method":"GET","path":DRIVE_PATH});
    // The first call refreshes once and caches the access token.
    f.fake.push_response(Ok(token_response()));
    f.fake
        .push_response(Ok(reply(200, "application/json", r#"{"files":[]}"#)));
    assert_eq!(http_get(sweep, &client, &url, "OAuth GET").await, 200);
    assert_eq!(f.upstream_requests(), 2);
    // Reflected access, refresh and client secrets are sealed on every surface.
    let mut index = 0;
    for secret in [OAUTH_ACCESS, OAUTH_REFRESH, OAUTH_CLIENT_SECRET] {
        for (name, response) in oauth_reflections(secret) {
            f.fake.push_response(Ok(response));
            let what = format!("OAuth {name}");
            match index % 3 {
                0 => {
                    assert_eq!(http_get(sweep, &client, &url, &what).await, 502, "{what}");
                }
                1 => {
                    let args = ["http", "drive", "GET", DRIVE_PATH];
                    assert_eq!(cli.error(sweep, &args, false), "RESPONSE_BLOCKED", "{what}");
                }
                _ => {
                    let error = mcp.error(sweep, "http", mcp_get.clone());
                    assert_eq!(error["code"], "RESPONSE_BLOCKED", "{what}");
                }
            }
            assert_eq!(f.upstream_requests(), 1, "{what}");
            index += 1;
        }
    }
    // A refresh refusal that echoes the refresh token and client secret
    // surfaces only as NEEDS_REAUTH. Locking drops the cached access token.
    f.admin(admin_msg::LOCK, json!({}), &[]).await.ok();
    f.admin(admin_msg::UNLOCK_PASSWORD, json!({}), common::PASSWORD)
        .await
        .ok();
    let refusal = || {
        reply(
            400,
            "application/json",
            json!({"error":"invalid_grant",
                "error_description":format!("refresh {OAUTH_REFRESH} for client {OAUTH_CLIENT_SECRET}")})
            .to_string(),
        )
    };
    // The refusal is not remembered: every call asks the token endpoint again.
    let args = ["http", "drive", "GET", DRIVE_PATH];
    f.fake.push_response(Ok(refusal()));
    assert_eq!(cli.error(sweep, &args, false), "NEEDS_REAUTH");
    assert_eq!(f.upstream_requests(), 1);
    f.fake.push_response(Ok(refusal()));
    cli.error(sweep, &args, true);
    assert_eq!(f.upstream_requests(), 1);
    f.fake.push_response(Ok(refusal()));
    let error = mcp.error(sweep, "http", mcp_get);
    assert_eq!(error["code"], "NEEDS_REAUTH");
    assert_eq!(f.upstream_requests(), 1);
    f.fake.push_response(Ok(refusal()));
    let what = "OAuth after refresh refusal";
    assert_ne!(http_get(sweep, &client, &url, what).await, 200);
    assert_eq!(f.upstream_requests(), 1);
}
