//! The real git client (smart HTTP, protocol v2) through the default local
//! service. The upstream is `git http-backend` behind the injected transport:
//! no GitHub, network or user git configuration is involved.
use super::*;
use rekey_broker::upstream::{
    UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamTransport,
};
use rekey_domain::ids::CredentialId;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;

const BRANCHES: usize = 40;

struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    auth: (String, Vec<u8>),
    body_len: usize,
}

/// Runs each upstream request through CGI `git http-backend` over `root`.
struct GitBackend {
    root: PathBuf,
    seen: Mutex<Vec<Seen>>,
}

impl UpstreamTransport for GitBackend {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(Seen {
                method: request.method.as_str().to_owned(),
                target: request.path.clone(),
                headers: request.headers.clone(),
                auth: (
                    request.auth_header.0.clone(),
                    request.auth_header.1.to_vec(),
                ),
                body_len: request.body.len(),
            });
            let (path, query) = request
                .path
                .split_once('?')
                .unwrap_or((request.path.as_str(), ""));
            let header = |name: &str| {
                request
                    .headers
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, v)| v.clone())
            };
            let mut command = hermetic(&self.root);
            command
                .arg("http-backend")
                .env("GIT_PROJECT_ROOT", &self.root)
                .env("GIT_HTTP_EXPORT_ALL", "1")
                // An authenticated web-server user is what enables receive-pack.
                .env("REMOTE_USER", "rekey-test")
                .env("REQUEST_METHOD", request.method.as_str())
                .env("PATH_INFO", path)
                .env("QUERY_STRING", query)
                .env("CONTENT_TYPE", header("content-type").unwrap_or_default())
                .env("CONTENT_LENGTH", request.body.len().to_string());
            if let Some(protocol) = header("git-protocol") {
                command.env("HTTP_GIT_PROTOCOL", protocol);
            }
            let output = run(command, Some(request.body.to_vec())).await;
            if !output.status.success() {
                return Err(UpstreamError::Transport);
            }
            cgi_response(&output.stdout)
        })
    }
}

fn cgi_response(stdout: &[u8]) -> Result<UpstreamResponse, UpstreamError> {
    let end = stdout
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(UpstreamError::Transport)?;
    let head = std::str::from_utf8(&stdout[..end]).map_err(|_| UpstreamError::Transport)?;
    let (mut status, mut headers) = (200, Vec::new());
    for line in head.split("\r\n") {
        let (name, value) = line.split_once(':').ok_or(UpstreamError::Transport)?;
        if name.eq_ignore_ascii_case("status") {
            status = value.trim()[..3]
                .parse()
                .map_err(|_| UpstreamError::Transport)?;
        } else {
            headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    Ok(UpstreamResponse {
        status,
        headers: headers.into(),
        body: stdout[end + 4..].to_vec().into(),
    })
}

/// git with no system or user configuration and no prompts or proxies.
fn hermetic(home: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("git");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true);
    command
}

/// The client configured as the user guide documents: `https://github.com/`
/// for this repository is rewritten to `service` (`.../c/<connection>/`).
fn client(home: &Path, service: &str) -> tokio::process::Command {
    let mut command = hermetic(home);
    command
        .env("GIT_TRACE_CURL", home.join("curl-trace.txt"))
        .env("GIT_TRACE_CURL_NO_DATA", "1")
        // A rewrite that failed to apply must not reach the real GitHub.
        .env("GIT_ALLOW_PROTOCOL", "http")
        // git turns this into an Accept-Language header the service must strip.
        .env("LANGUAGE", "en_US:zh_CN")
        .arg("-c")
        .arg(format!(
            "url.{service}owner/repo.git.insteadOf=https://github.com/owner/repo.git"
        ))
        .arg("-c")
        .arg(format!(
            "http.{service}.extraHeader=Authorization: Bearer rekey"
        ))
        .args([
            "-c",
            "protocol.version=2",
            "-c",
            "user.name=Rekey Test",
            "-c",
            "user.email=test@rekey.invalid",
        ]);
    command
}

async fn run(mut command: tokio::process::Command, stdin: Option<Vec<u8>>) -> Output {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .expect("this contract needs the git client and git http-backend");
    let mut pipe = child.stdin.take().unwrap();
    let writer = tokio::spawn(async move {
        if let Some(bytes) = stdin {
            let _ = pipe.write_all(&bytes).await;
        }
    });
    let output = tokio::time::timeout(Duration::from_secs(120), child.wait_with_output())
        .await
        .expect("git must finish")
        .unwrap();
    writer.await.unwrap();
    output
}

fn ok(output: &Output, step: &str) -> String {
    assert!(
        output.status.success(),
        "{step}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// One commit per `(ref, content, extend existing ref)`, each with its own tree.
fn fast_import(commits: &[(String, String, bool)]) -> Vec<u8> {
    let mut stream = String::new();
    for (refname, content, extend) in commits {
        let from = if *extend {
            format!("from {refname}^0\n")
        } else {
            String::new()
        };
        stream.push_str(&format!(
            "commit {refname}\ncommitter Rekey Test <test@rekey.invalid> 1700000000 +0000\ndata {}\n{content}\n{from}M 644 inline file\ndata {}\n{content}\n\n",
            content.len() + 1,
            content.len() + 1,
        ));
    }
    stream.into_bytes()
}

async fn rev(home: &Path, git_dir: &Path, name: &str) -> String {
    let mut command = hermetic(home);
    command
        .arg("--git-dir")
        .arg(git_dir)
        .args(["rev-parse", name]);
    ok(&run(command, None).await, name)
}

/// Signs the `git` Connection. `git_protocol: false` reproduces a Connection
/// signed before the preset allowed that header.
async fn sign_git(
    f: &Fixture,
    credential: CredentialId,
    receive_pack: RuleEffect,
    git_protocol: bool,
) -> String {
    let mut connection = rekey_policy::presets::builtin_preset("github-git")
        .unwrap()
        .connection("git".into(), credential);
    if !git_protocol {
        connection
            .allowed_headers
            .retain(|name| name.as_str() != "git-protocol");
    }
    connection
        .bindings
        .insert("owner".into(), vec!["owner".into()]);
    connection
        .bindings
        .insert("repo".into(), vec!["repo.git".into()]);
    for rule in &mut connection.rules {
        if rule.path.ends_with("/git-receive-pack") {
            rule.effect = receive_pack;
        }
    }
    let draft = f.draft(vec![connection]).await;
    f.activate(&draft, &f.signed(&draft)).await.ok();
    let listed = f
        .agent(ipc::agent_msg::LIST_CAPABILITIES, json!({}), &[])
        .await;
    let list: ipc::ListCapabilitiesResponse = serde_json::from_slice(&listed.body).unwrap();
    format!("{}/c/git/", list.service_url.unwrap())
}

fn executions(f: &Fixture) -> (i64, i64) {
    rusqlite::Connection::open(rekey_vault::paths::vault_db(&f.state))
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM audit_events WHERE event_type='execution.started'), \
             (SELECT count(*) FROM audit_events WHERE event_type='execution.finished')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// A bare `owner/repo.git` under `home/upstream` with `main` and BRANCHES
/// distinct root commits, so a clone sends one want per branch.
async fn seeded_upstream(home: &Path) -> (PathBuf, PathBuf) {
    let root = home.join("upstream");
    let bare = root.join("owner/repo.git");
    std::fs::create_dir_all(&bare).unwrap();
    let mut init = hermetic(home);
    init.args(["init", "--bare", "--quiet"]).arg(&bare);
    ok(&run(init, None).await, "init");
    let mut refs = vec![("refs/heads/main".to_owned(), "main".to_owned(), false)];
    refs.extend((0..BRANCHES).map(|i| {
        (
            format!("refs/heads/b{i:02}"),
            format!("branch {i:02}"),
            false,
        )
    }));
    let mut seed = hermetic(home);
    seed.arg("--git-dir")
        .arg(&bare)
        .args(["fast-import", "--quiet"]);
    ok(&run(seed, Some(fast_import(&refs))).await, "seed");
    let mut head = hermetic(home);
    head.arg("--git-dir")
        .arg(&bare)
        .args(["symbolic-ref", "HEAD", "refs/heads/main"]);
    ok(&run(head, None).await, "HEAD");
    (root, bare)
}

#[tokio::test]
async fn real_git_clones_pushes_and_fetches_through_the_local_service() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let (root, bare) = seeded_upstream(home).await;
    let backend = Arc::new(GitBackend {
        root: root.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let f = Fixture::with_transport(PolicyMode::Personal, true, Some(backend.clone())).await;
    let credential = f.seed().await.credential_id;
    let service = sign_git(&f, credential, RuleEffect::Approve, true).await;

    // Clone: forty-one wants make git gzip its upload-pack request.
    let checkout = home.join("clone");
    let mut clone = client(home, &service);
    clone
        .args(["clone", "--quiet", "https://github.com/owner/repo.git"])
        .arg(&checkout);
    ok(&run(clone, None).await, "clone");
    let local = checkout.join(".git");
    for branch in ["main", "b00", "b39"] {
        assert_eq!(
            rev(home, &local, &format!("refs/remotes/origin/{branch}")).await,
            rev(home, &bare, &format!("refs/heads/{branch}")).await
        );
    }
    let trace = std::fs::read_to_string(home.join("curl-trace.txt")).unwrap();
    for header in [
        "Content-Encoding: gzip",
        "Pragma: no-cache",
        "Git-Protocol: version=2",
        "Accept-Language: ",
    ] {
        assert!(
            trace.contains(&format!("Send header: {header}")),
            "git did not send {header}"
        );
    }

    // receive-pack is a write: without a signed allow it never reaches upstream.
    let mut commit = client(home, &service);
    commit
        .arg("-C")
        .arg(&checkout)
        .args(["commit", "--allow-empty", "--quiet", "-m", "pushed"]);
    ok(&run(commit, None).await, "commit");
    let push = || {
        let mut push = client(home, &service);
        push.arg("-C")
            .arg(&checkout)
            .args(["push", "--quiet", "origin", "HEAD:main"]);
        push
    };
    assert!(!run(push(), None).await.status.success());
    let receive = |seen: &[Seen]| {
        seen.iter()
            .filter(|r| r.method == "POST" && r.target.ends_with("/git-receive-pack"))
            .count()
    };
    assert_eq!(receive(&backend.seen.lock().unwrap()), 0);
    sign_git(&f, credential, RuleEffect::Allow, true).await;
    ok(&run(push(), None).await, "push");
    assert_eq!(
        rev(home, &bare, "refs/heads/main").await,
        rev(home, &local, "HEAD").await
    );

    // Fetch negotiates against the clone's history and gets an upstream update.
    let mut update = hermetic(home);
    update
        .arg("--git-dir")
        .arg(&bare)
        .args(["fast-import", "--quiet"]);
    let changed = [("refs/heads/b07".to_owned(), "updated".to_owned(), true)];
    ok(&run(update, Some(fast_import(&changed))).await, "update");
    let mut fetch = client(home, &service);
    fetch
        .arg("-C")
        .arg(&checkout)
        .args(["fetch", "--quiet", "origin"]);
    ok(&run(fetch, None).await, "fetch");
    assert_eq!(
        rev(home, &local, "refs/remotes/origin/b07").await,
        rev(home, &bare, "refs/heads/b07").await
    );

    let seen = std::mem::take(&mut *backend.seen.lock().unwrap());
    let basic = format!(
        "Basic {}",
        data_encoding::BASE64.encode(b"x-access-token:synthetic-connection-token")
    );
    for request in seen.iter() {
        assert_eq!(
            request.auth,
            ("authorization".into(), basic.clone().into_bytes())
        );
        let names: Vec<_> = request.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|(n, v)| n == "accept-encoding" && v == "identity")
                .count(),
            1,
            "{names:?}"
        );
        for stripped in [
            "authorization",
            "pragma",
            "accept",
            "accept-language",
            "user-agent",
            "content-encoding",
            "content-length",
        ] {
            assert!(!names.contains(&stripped), "{stripped} reached upstream");
        }
    }
    // Every upload-pack exchange rode protocol v2 on the signed header;
    // push falls back to v0 and sends none.
    for request in seen.iter() {
        let v2 = request
            .headers
            .contains(&("git-protocol".into(), "version=2".into()));
        assert_eq!(
            v2,
            request.target.contains("git-upload-pack"),
            "{}",
            request.target
        );
    }
    // The gzip request reached upstream decoded, above git's 1 KiB threshold.
    assert!(
        seen.iter()
            .any(|r| r.target.ends_with("/git-upload-pack") && r.body_len > 1024)
    );
    assert_eq!(receive(&seen), 1);
    let calls = seen.len() as i64;
    assert_eq!(executions(&f), (calls, calls));
    f.finish().await;
}

#[tokio::test]
async fn malformed_or_oversized_gzip_never_reaches_the_git_upstream() {
    let backend = Arc::new(GitBackend {
        root: PathBuf::from("/nonexistent"),
        seen: Mutex::new(Vec::new()),
    });
    let f = Fixture::with_transport(PolicyMode::Personal, true, Some(backend.clone())).await;
    let credential = f.seed().await.credential_id;
    let service = sign_git(&f, credential, RuleEffect::Approve, true).await;
    // A few KiB that inflate past the signed 1 MiB request bound.
    let mut bomb = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut bomb, &vec![0; 2 * 1024 * 1024]).unwrap();
    let bomb = bomb.finish().unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (body, code) in [
        (b"0009done\n0000".to_vec(), "INVALID_INPUT"),
        (bomb, "REQUEST_TOO_LARGE"),
    ] {
        let out = client
            .post(format!("{service}owner/repo.git/git-upload-pack"))
            .bearer_auth("rekey")
            .header("content-type", "application/x-git-upload-pack-request")
            .header("content-encoding", "gzip")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 400);
        let error: Value = serde_json::from_slice(&out.bytes().await.unwrap()).unwrap();
        assert_eq!(error["code"], code, "{error}");
    }
    assert!(backend.seen.lock().unwrap().is_empty());
    assert_eq!(executions(&f), (0, 0));
    f.finish().await;
}

#[tokio::test]
async fn connection_signed_without_git_protocol_refuses_v2_and_serves_v0() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let (root, bare) = seeded_upstream(home).await;
    let backend = Arc::new(GitBackend {
        root,
        seen: Mutex::new(Vec::new()),
    });
    let f = Fixture::with_transport(PolicyMode::Personal, true, Some(backend.clone())).await;
    let credential = f.seed().await.credential_id;
    let service = sign_git(&f, credential, RuleEffect::Approve, false).await;
    let clone = |protocol: &str, target: &str| {
        let mut clone = client(home, &service);
        clone
            .args(["-c", &format!("protocol.version={protocol}")])
            .args(["clone", "--quiet", "https://github.com/owner/repo.git"])
            .arg(home.join(target));
        clone
    };
    // The unsigned Git-Protocol header is refused before anything is sent.
    assert!(!run(clone("2", "v2"), None).await.status.success());
    assert!(backend.seen.lock().unwrap().is_empty());
    ok(&run(clone("0", "v0"), None).await, "v0 clone");
    assert_eq!(
        rev(home, &home.join("v0/.git"), "refs/remotes/origin/b39").await,
        rev(home, &bare, "refs/heads/b39").await
    );
    assert!(
        backend
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.headers.iter().all(|(name, _)| name != "git-protocol"))
    );
    f.finish().await;
}
