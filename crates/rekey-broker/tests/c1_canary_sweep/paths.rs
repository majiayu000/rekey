//! C1 / I1 for the paths the base sweep leaves out: LLM streaming
//! (`stream.rs`), T1 derived credentials (`t1.rs`), approval-gated SSH
//! signing and OAuth Connections. Each path holds its own synthetic root
//! material, and every caller surface that reaches the path must refuse
//! every form of all of it.
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use rekey_broker::upstream::UpstreamResponse;
use rekey_domain::connection::{ConnectionLlmLimits, OAuthBinding, OAuthProvider};
use rekey_domain::ipc::{ProofKind, admin_msg, encode_proof_body};
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
    let t1 = super::t1::setup(&f).await;
    let identity = f
        .activate(Extra {
            connections: vec![
                llm_connection("anthropic", "llm-messages", messages_key),
                llm_connection("openai", "llm-chat", chat_key),
                drive_connection(oauth),
            ],
            derived_credentials: t1.grants.clone(),
        })
        .await;
    let mut sweep = Sweep::new();
    sweep.refuse("LLM key", LLM_KEY);
    for (label, secret) in [
        ("OAuth client secret", OAUTH_CLIENT_SECRET),
        ("OAuth refresh token", OAUTH_REFRESH),
        ("OAuth access token", OAUTH_ACCESS),
    ] {
        sweep.refuse(label, secret.as_bytes());
    }
    for (label, secret) in &t1.roots {
        sweep.refuse(label, secret);
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
    super::t1::sweep(&f, &mut sweep, &cli, &presence, &t1).await;
    ssh_approval_sweep(&f, &mut sweep, &identity, &presence).await;
    let mut mcp = Mcp::initialized(&f, &mut sweep);
    oauth_sweep(&f, &mut sweep, &cli, &mut mcp).await;
    mcp.finish(&mut sweep);
    // Every path really ran: a skipped step must not pass as clean.
    for (surface, minimum) in [
        ("stream", 2 * 2 * 8),
        ("cli", 2 * 18),
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

pub(super) fn reply(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers: vec![("content-type".to_owned(), content_type.to_owned())].into(),
        body: body.into().into(),
    }
}

/// Reviews one pending request and decides it with the presence ticket.
pub(super) async fn approve(
    f: &Fixture,
    sweep: &mut Sweep,
    id: &str,
    presence: &[u8],
    decision: u16,
) {
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

async fn pending_ids(f: &Fixture) -> Vec<String> {
    let reply = f.admin(admin_msg::APPROVAL_PENDING, json!({}), &[]).await;
    reply.ok()["challenges"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|challenge| challenge["approval_request_id"].as_str())
        .map(str::to_owned)
        .collect()
}

/// The first pending approval not in `before`. Earlier `--no-wait` T1
/// requests stay pending, so the SSH step must not take theirs.
async fn new_approval(f: &Fixture, before: &[String]) -> String {
    for _ in 0..250 {
        if let Some(id) = pending_ids(f)
            .await
            .into_iter()
            .find(|id| !before.contains(id))
        {
            return id;
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
        let before = pending_ids(f).await;
        let waiting = tokio::spawn(async move {
            ssh_support::send(&mut agent, &sign).await;
            ssh_support::response(&mut agent, within).await
        });
        let id = new_approval(f, &before).await;
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
    // The token endpoint is asked once; the refused grant is remembered, so
    // later calls on every surface return NEEDS_REAUTH without resending it.
    let args = ["http", "drive", "GET", DRIVE_PATH];
    f.fake.push_response(Ok(refusal()));
    assert_eq!(cli.error(sweep, &args, false), "NEEDS_REAUTH");
    assert_eq!(f.upstream_requests(), 1);
    cli.error(sweep, &args, true);
    assert_eq!(f.upstream_requests(), 0);
    let error = mcp.error(sweep, "http", mcp_get);
    assert_eq!(error["code"], "NEEDS_REAUTH");
    assert_eq!(f.upstream_requests(), 0);
    let what = "OAuth after refresh refusal";
    assert_ne!(http_get(sweep, &client, &url, what).await, 200);
    assert_eq!(f.upstream_requests(), 0);
}
