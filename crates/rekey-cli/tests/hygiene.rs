//! Synthetic files and IPC peers; dotenv values never cross the CLI output boundary.
use rekey_domain::ipc::{Channel, FRAME_HEADER_LEN, FrameHeader, admin_msg, agent_msg, resp_msg};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        let runtime = root.join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _dir: dir,
            root,
            project,
        }
    }
    fn git(&self, args: &[&str]) {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(&self.project)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "true")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
    fn exchange(
        &self,
        channel: Channel,
        args: &[&str],
        input: Option<&[u8]>,
        handler: impl FnOnce(FrameHeader, Value, Vec<u8>) -> (Value, Vec<u8>, bool) + Send + 'static,
    ) -> Output {
        let socket = self
            .root
            .join("runtime")
            .join(if channel == Channel::Admin {
                "admin.sock"
            } else {
                "agent.sock"
            });
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut bytes = [0; FRAME_HEADER_LEN];
            stream.read_exact(&mut bytes).unwrap();
            let header = FrameHeader::decode(&bytes).unwrap();
            let mut metadata = vec![0; header.metadata_len as usize];
            let mut body = vec![0; header.body_len as usize];
            stream.read_exact(&mut metadata).unwrap();
            stream.read_exact(&mut body).unwrap();
            let (metadata, body, error) =
                handler(header, serde_json::from_slice(&metadata).unwrap(), body);
            let metadata = metadata.to_string();
            stream
                .write_all(
                    &FrameHeader {
                        channel,
                        flags: 0,
                        message_type: if error { resp_msg::ERROR } else { resp_msg::OK },
                        request_id: header.request_id,
                        metadata_len: metadata.len() as u32,
                        body_len: body.len() as u32,
                    }
                    .encode(),
                )
                .unwrap();
            stream.write_all(metadata.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_rekey"));
        command
            .arg("--state-dir")
            .arg(&self.root)
            .args(args)
            .current_dir(&self.project)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "true");
        let output = if let Some(input) = input {
            let mut child = command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            child.wait_with_output().unwrap()
        } else {
            command.output().unwrap()
        };
        worker.join().unwrap();
        std::fs::remove_file(socket).unwrap();
        output
    }
}
#[test]
fn staged_scan_reads_the_index_instead_of_the_working_copy_and_never_echoes_the_match() {
    let f = Fixture::new();
    f.git(&["init"]);
    std::fs::write(
        f.project.join("source.txt"),
        b"synthetic-full-secret-in-index\n",
    )
    .unwrap();
    f.git(&["add", "source.txt"]);
    std::fs::write(f.project.join("source.txt"), b"clean-working-copy\n").unwrap();
    let output=f.exchange(Channel::Agent,&["scan","--staged"],None,|header,metadata,body| {
        assert_eq!(header.message_type,agent_msg::SCAN);assert_eq!(metadata,json!({"path":"source.txt"}));assert_eq!(body,b"synthetic-full-secret-in-index\n");
        (json!({}),json!({"findings":[{"path":"source.txt","line":1,"column":1,"connection":"github"}]}).to_string().into_bytes(),false)
    });
    assert_eq!(output.status.code(), Some(4));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("synthetic-full-secret"));
    assert!(text.contains("source.txt"));
}
#[test]
fn staged_locked_scan_warns_and_passes_unless_strict() {
    let f = Fixture::new();
    f.git(&["init"]);
    std::fs::write(f.project.join("source.txt"), b"text").unwrap();
    f.git(&["add", "source.txt"]);
    for strict in [false, true] {
        let args = if strict {
            vec!["scan", "--staged", "--strict"]
        } else {
            vec!["scan", "--staged"]
        };
        let output=f.exchange(Channel::Agent,&args,None,|header,_,_|(json!({"request_id":header.request_id,"code":"LOCKED","message":"vault locked","retryable":false,"next":"Call await_unlock"}),Vec::new(),true));
        assert_eq!(output.status.success(), !strict);
        assert!(String::from_utf8_lossy(&output.stderr).contains(if strict {
            "LOCKED"
        } else {
            "Warning"
        }));
    }
}
#[test]
fn stdin_scan_supports_a_whole_file_above_the_normal_action_body_limit() {
    let f = Fixture::new();
    let input = vec![b'x'; 2 * 1024 * 1024];
    let output = f.exchange(
        Channel::Agent,
        &["scan", "--stdin"],
        Some(&input),
        |header, metadata, body| {
            assert_eq!(header.message_type, agent_msg::SCAN);
            assert_eq!(metadata["path"], "<stdin>");
            assert_eq!(body.len(), 2 * 1024 * 1024);
            (json!({}), br#"{"findings":[]}"#.to_vec(), false)
        },
    );
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
}
#[test]
fn import_preview_sends_only_an_absolute_path_and_rejects_any_value_field() {
    let f = Fixture::new();
    let expected = f.project.join(".env").to_str().unwrap().to_owned();
    for extra in [false, true] {
        let expected = expected.clone();
        let output=f.exchange(Channel::Admin,&["import",".env","--dry-run"],None,move|header,metadata,body| {
            assert_eq!(header.message_type,admin_msg::IMPORT_ENV);assert_eq!(metadata,json!({"path":expected,"dry_run":true}));assert!(body.is_empty());
            let mut preview=json!({"entries":[{"key":"OPENAI_API_KEY","preset_hint":"openai"}],"unsupported":[]});if extra{preview["entries"][0]["value"]=json!("synthetic-secret-must-not-print");}
            (json!({}),preview.to_string().into_bytes(),false)
        });
        assert_eq!(output.status.success(), !extra);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-secret"));
        assert!(!f.project.join(".env").exists());
    }
}
#[test]
fn connection_and_access_lists_are_public_admin_projections() {
    for (args, opcode, body) in [
        (
            vec!["connection", "list"],
            admin_msg::PROFILE_LIST,
            json!({"connections":[],"ssh_keys":[],"derived_credentials":[],"policy_sha256":null,"expires_at_ms":null}),
        ),
        (
            vec!["access", "list"],
            admin_msg::ACCESS_RESOLVE,
            json!({"requests":[],"blocked_callers":[]}),
        ),
    ] {
        let f = Fixture::new();
        let expected = body.clone();
        let output = f.exchange(Channel::Admin, &args, None, move |header, _, proof| {
            assert_eq!(header.message_type, opcode);
            assert!(proof.is_empty());
            (json!({}), body.to_string().into_bytes(), false)
        });
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            expected
        );
    }
}
#[test]
fn access_decisions_read_step_up_only_from_the_verified_ipc_body() {
    let f = Fixture::new();
    let proof = b"synthetic-management-proof\n";
    let output=f.exchange(Channel::Admin,&["access","resolve","00112233-4455-4677-8899-aabbccddeeff","--granted","true","--password-stdin"],Some(proof),|header,metadata,body| {
        assert_eq!(header.message_type,admin_msg::ACCESS_RESOLVE);assert_eq!(metadata,json!({"action":"resolve","request_id":"00112233-4455-4677-8899-aabbccddeeff","granted":true,"block_caller":false}));
        let (kind,value)=rekey_domain::ipc::parse_proof_body(&body).unwrap();assert_eq!(kind,rekey_domain::ipc::ProofKind::Password);assert_eq!(value,b"synthetic-management-proof");
        (json!({}),br#"{"status":"GRANTED"}"#.to_vec(),false)
    });
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-management-proof"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-management-proof"));
}

#[test]
fn app_import_and_rewrite_send_only_public_selections_and_explicit_proof() {
    for rewrite in [false, true] {
        let f = Fixture::new();
        let expected = f.project.join(".env");
        let payload = if rewrite {
            json!([{"key":"OPENAI_API_KEY","connection":"openai","base_url_variable":"OPENAI_BASE_URL"}])
        } else {
            json!([{"key":"OPENAI_API_KEY","label":"openai"}])
        };
        let input = format!("synthetic-app-presence\n{payload}\n");
        let flag = if rewrite {
            "--rewrite-stdin"
        } else {
            "--selections-stdin"
        };
        let output = f.exchange(
            Channel::Admin,
            &["import", ".env", flag, "--presence", "--password-stdin"],
            Some(input.as_bytes()),
            move |header, metadata, body| {
                assert_eq!(header.message_type, admin_msg::IMPORT_ENV);
                assert_eq!(metadata["path"], expected.to_str().unwrap());
                assert_eq!(ipc_proof(&body), b"synthetic-app-presence");
                if rewrite {
                    assert_eq!(metadata["action"], "rewrite");
                    assert_eq!(metadata["replacements"], payload);
                    (
                        json!({}),
                        json!({"backup":expected.with_extension("env.rekey-backup")})
                            .to_string()
                            .into_bytes(),
                        false,
                    )
                } else {
                    assert!(metadata.get("action").is_none());
                    assert_eq!(metadata["selections"], payload);
                    (
                        json!({}),
                        br#"{"entries":[],"unsupported":[]}"#.to_vec(),
                        false,
                    )
                }
            },
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-app-presence"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-app-presence"));
        assert!(!f.project.join(".env").exists());
    }
}
fn ipc_proof(body: &[u8]) -> &[u8] {
    let (kind, proof) = rekey_domain::ipc::parse_proof_body(body).unwrap();
    assert_eq!(kind, rekey_domain::ipc::ProofKind::Presence);
    proof
}

#[test]
fn app_policy_draft_preserves_explicit_public_editing_scopes_without_a_proof() {
    let f = Fixture::new();
    let request = json!({"connections":[],"ssh_keys":[],"derived_credentials":[],"expected_policy_sha256":null,"expires_at_ms":1234567});
    let input = request.to_string();
    let output = f.exchange(
        Channel::Admin,
        &["policy", "draft", "--request-stdin"],
        Some(input.as_bytes()),
        move |header, metadata, body| {
            assert_eq!(header.message_type, admin_msg::PERSONAL_POLICY_DRAFT);
            assert_eq!(metadata, request);
            assert!(body.is_empty());
            (
                json!({"vault_id":rekey_domain::ids::VaultId::new_random(),"trust_sha256":"1".repeat(64),"public_key":format!("04{}","2".repeat(128)),"base_version":null,"next_version":1,"policy_sha256":"3".repeat(64),"changes":[],"connections":[]}),
                b"RKPOLICY\0\x01{}".to_vec(),
                false,
            )
        },
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["sign_bytes"].as_str().unwrap().as_bytes(),
        b"RKPOLICY\0\x01{}"
    );
}

#[test]
fn t1_adapters_preserve_temporary_stdout_without_exposing_root_values_or_metadata() {
    for (command, kind, issued) in [
        ("aws-credentials", "aws-assume-role", br#"{"Version":1,"AccessKeyId":"synthetic-temporary-id","SecretAccessKey":"synthetic-temporary-key","SessionToken":"synthetic-session","Expiration":"2026-10-05T12:00:00Z"}"#.as_slice()),
        ("kubectl-credentials", "kubernetes-eks", br#"{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"synthetic-temporary-token","expirationTimestamp":"2026-10-05T12:00:00Z"}}"#.as_slice()),
        ("github-token", "github-app", b"synthetic-temporary-installation-token".as_slice()),
    ] {
        let f = Fixture::new();
        let approval = rekey_domain::ids::ApprovalRequestId::new_random();
        let approval_text = approval.to_string();
        let output = f.exchange(Channel::Agent, &[command, "fixture", "--approval", &approval_text], None, move |header, metadata, body| {
            assert_eq!(header.message_type, agent_msg::DERIVE_CREDENTIAL);
            assert_eq!(metadata, json!({"connection":"fixture","approval_request_id":approval}));
            assert!(body.is_empty());
            (json!({"connection":"fixture","kind":kind,"expires_at_ms":1234567}), issued.to_vec(), false)
        });
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.stdout, issued);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("T1"));
        assert!(!stderr.contains("synthetic-temporary"));
        assert!(!stderr.contains("synthetic-session"));
    }
}

#[test]
fn t1_wrong_kind_and_approval_errors_never_release_values_or_replay_issuance() {
    for requires_approval in [false, true] {
        let f = Fixture::new();
        let output = f.exchange(Channel::Agent, &["aws-credentials", "fixture"], None, move |header, metadata, body| {
            assert_eq!(header.message_type, agent_msg::DERIVE_CREDENTIAL);
            assert_eq!(metadata, json!({"connection":"fixture"}));
            assert!(body.is_empty());
            if requires_approval {
                (json!({"request_id":header.request_id,"code":"APPROVAL_REQUIRED","message":"local approval required","retryable":false,"next":"Call await_approval, then repeat with --approval","approval":{"challenge_id":rekey_domain::ids::ApprovalRequestId::new_random(),"expires_at_ms":1234567}}), vec![], true)
            } else {
                (json!({"connection":"fixture","kind":"github-app","expires_at_ms":1234567}), b"synthetic-value-must-not-release".to_vec(), false)
            }
        });
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error["code"],
            if requires_approval {
                "APPROVAL_REQUIRED"
            } else {
                "INVALID_FRAME"
            }
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-value"));
        if requires_approval {
            assert_eq!(
                error["next"],
                "Call await_approval, then repeat with --approval"
            );
        }
    }
}

#[test]
fn oauth_app_begin_sends_only_explicit_proof_and_returns_public_receipt() {
    for malformed in [false, true] {
        let f = Fixture::new();
        let output = f.exchange(Channel::Admin, &["oauth", "login", "google", "--proof-stdin", "--presence", "--redirect-uri", "http://127.0.0.1:12345/callback"], Some(b"synthetic-oauth-presence\n"), move |header, metadata, body| {
            assert_eq!(header.message_type, admin_msg::OAUTH_LOGIN);
            assert_eq!(metadata, json!({"connection":"google","redirect_uri":"http://127.0.0.1:12345/callback"}));
            assert_eq!(ipc_proof(&body), b"synthetic-oauth-presence");
            let receipt = json!({"authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?state=synthetic-state","request_id":rekey_domain::ids::RequestId::new_random(),"expires_at_ms":1234567});
            (receipt, if malformed { b"synthetic-token-must-not-release".to_vec() } else { vec![] }, false)
        });
        assert_eq!(output.status.success(), !malformed);
        if malformed {
            assert!(output.stdout.is_empty());
        } else {
            let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(
                receipt["authorization_url"]
                    .as_str()
                    .unwrap()
                    .starts_with("https://accounts.google.com/")
            );
        }
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("synthetic-oauth-presence"));
            assert!(!text.contains("synthetic-token-must-not-release"));
        }
    }
}

#[test]
fn typed_root_sources_accept_only_explicit_secret_stdin_and_return_public_metadata() {
    for kind in ["oauth-grant", "aws-static", "github-app-installation"] {
        let f = Fixture::new();
        let source = json!({"client_secret":"synthetic-private-root-json"}).to_string();
        let input = format!("synthetic-root-presence\n{source}\n");
        let output = f.exchange(Channel::Admin, &["credential", "add", "fixture", "--kind", kind, "--stdin-secrets", "--presence"], Some(input.as_bytes()), move |header, metadata, body| {
            assert_eq!(header.message_type, admin_msg::CREDENTIAL_ADD);
            assert_eq!(metadata, json!({"label":"fixture","kind":kind}));
            let (proof_kind, proof, secret) = rekey_domain::ipc::parse_proof_and_secret_body(&body).unwrap();
            assert_eq!(proof_kind, rekey_domain::ipc::ProofKind::Presence);
            assert_eq!(proof, b"synthetic-root-presence");
            assert_eq!(secret, source.as_bytes());
            (json!({"id":"00112233-4455-4677-8899-aabbccddeeff","label":"fixture","kind":kind,"state":"active","current_version":1,"created_at":123,"updated_at":123}), vec![], false)
        });
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("synthetic-private-root-json"));
            assert!(!text.contains("synthetic-root-presence"));
        }
        let rejected = Command::new(env!("CARGO_BIN_EXE_rekey"))
            .args(["credential", "add", "fixture", "--kind", kind])
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
    }
}

fn ssh_receipt() -> Value {
    json!({"credential":{"id":"00112233-4455-4677-8899-aabbccddeeff","label":"fixture","kind":"ssh-ed25519","state":"active","current_version":1,"created_at":123,"updated_at":123},"public_key":"AAAAC3NzaC1lZDI1NTE5"})
}
#[test]
fn ssh_status_and_generation_project_public_data_without_software_fallback() {
    let f = Fixture::new();
    let socket = f.root.join("ssh-agent.sock");
    let output = f.exchange(
        Channel::Admin,
        &["ssh-agent", "status"],
        None,
        move |header, metadata, body| {
            assert_eq!(header.message_type, admin_msg::SSH_KEY);
            assert_eq!(metadata, json!({"action":"status"}));
            assert!(body.is_empty());
            (
                json!({}),
                json!({"socket":socket,"ssh_keys":[]})
                    .to_string()
                    .into_bytes(),
                false,
            )
        },
    );
    assert!(output.status.success());
    let output = f.exchange(
        Channel::Admin,
        &["ssh-agent", "generate", "fixture", "--password-stdin"],
        Some(b"synthetic-management-proof\n"),
        |header, metadata, body| {
            assert_eq!(header.message_type, admin_msg::SSH_KEY);
            assert_eq!(
                metadata,
                json!({"action":"generate","label":"fixture","mode":"default"})
            );
            let (kind, proof) = rekey_domain::ipc::parse_proof_body(&body).unwrap();
            assert_eq!(kind, rekey_domain::ipc::ProofKind::Password);
            assert_eq!(proof, b"synthetic-management-proof");
            (json!({}), ssh_receipt().to_string().into_bytes(), false)
        },
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        ssh_receipt()
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-management-proof"));
}
#[test]
fn ssh_import_preserves_multiline_private_bytes_only_in_the_secret_body() {
    let f = Fixture::new();
    let private = b"-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-private-key-canary\n-----END OPENSSH PRIVATE KEY-----\n";
    let mut input = b"synthetic-app-presence\n".to_vec();
    input.extend_from_slice(private);
    let output = f.exchange(
        Channel::Admin,
        &[
            "ssh-agent",
            "import",
            "fixture",
            "--stdin-secrets",
            "--presence",
        ],
        Some(&input),
        move |header, metadata, body| {
            assert_eq!(header.message_type, admin_msg::SSH_KEY);
            assert_eq!(metadata, json!({"action":"import","label":"fixture"}));
            let (kind, proof, key) = rekey_domain::ipc::parse_proof_and_secret_body(&body).unwrap();
            assert_eq!(kind, rekey_domain::ipc::ProofKind::Presence);
            assert_eq!(proof, b"synthetic-app-presence");
            assert_eq!(key, private);
            (json!({}), ssh_receipt().to_string().into_bytes(), false)
        },
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("PRIVATE KEY"));
        assert!(!text.contains("synthetic-private-key-canary"));
        assert!(!text.contains("synthetic-app-presence"));
    }
}
