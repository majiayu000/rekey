use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::ids::{PolicyRuleId, PolicySignerId, PrincipalId};
use serde_json::{Value, json};

const PASSWORD: &str = "workload blackbox battery staple";

fn rekey_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rekey"))
}

fn rekeyd_bin() -> PathBuf {
    let binary = rekey_bin().parent().unwrap().join("rekeyd");
    assert!(binary.exists(), "rekeyd binary must be built beside rekey");
    binary
}

struct Output {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(rekey_bin())
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child.stdin.as_mut().unwrap().write_all(input).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    Output {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

struct ServeGuard(Option<Child>);

impl Drop for ServeGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn key_pair() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
}

fn token(key: &Ed25519KeyPair, subject: &str, jti: &str, expires_delta: i64) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let header = BASE64URL_NOPAD.encode(
        &serde_json::to_vec(&json!({"alg":"EdDSA","kid":"workload-key","typ":"JWT"})).unwrap(),
    );
    let claims = BASE64URL_NOPAD.encode(
        &serde_json::to_vec(&json!({
            "iss":"https://issuer.example",
            "sub":subject,
            "aud":"rekey://blackbox",
            "jti":jti,
            "iat":now - 1,
            "nbf":now - 1,
            "exp":now + expires_delta
        }))
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    format!(
        "{input}.{}\n",
        BASE64URL_NOPAD.encode(key.sign(input.as_bytes()).as_ref())
    )
    .into_bytes()
}

fn policy_bundle(
    signer_id: PolicySignerId,
    signer: &Ed25519KeyPair,
    workload_key: &Ed25519KeyPair,
    action_id: &str,
    version: u64,
) -> Value {
    let profiles = [
        (
            json!({"kind":"oidc","subject":"service:build"}),
            "service:build",
        ),
        (
            json!({"kind":"spiffe-jwt-svid","spiffe_id":"spiffe://issuer.example/workload/api"}),
            "spiffe://issuer.example/workload/api",
        ),
        (
            json!({"kind":"kubernetes-service-account","namespace":"prod","service_account":"api"}),
            "system:serviceaccount:prod:api",
        ),
        (
            json!({"kind":"ci-cloud","subject":"repo:owner/name:ref:refs/heads/main"}),
            "repo:owner/name:ref:refs/heads/main",
        ),
    ];
    let entries = profiles
        .iter()
        .map(|(profile, _)| {
            json!({
                "principal_id": PrincipalId::new_random(),
                "issuer":"https://issuer.example",
                "audiences":["rekey://blackbox"],
                "max_token_age_ms":900_000,
                "profile":profile,
                "keys":[{
                    "algorithm":"ed25519",
                    "kid":"workload-key",
                    "x":BASE64URL_NOPAD.encode(workload_key.public_key().as_ref())
                }]
            })
        })
        .collect::<Vec<_>>();
    let resource = json!({"type":"blackbox-action","id":action_id});
    let rules = entries
        .iter()
        .map(|entry| {
            json!({
                "id":PolicyRuleId::new_random(),
                "effect":"permit",
                "principal_id":entry["principal_id"],
                "action_id":action_id,
                "version":1,
                "resource":resource,
                "parameters":{"kind":"any_validated"}
            })
        })
        .collect::<Vec<_>>();
    let unsigned = json!({
        "format_version":1,
        "signer_id":signer_id,
        "snapshot":{
            "format_version":3,
            "version":version,
            "expires_at_ms":4_102_444_800_000_i64,
            "approvers":[],
            "workload_identities":entries,
            "bindings":[{
                "action_id":action_id,
                "version":1,
                "resource":resource,
                "parameter_schema_id":"blackbox/v1",
                "parameter_schema":{}
            }],
            "rules":rules
        }
    });
    let mut message = b"RKPOLICY\0\x01".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
    let mut bundle = unsigned;
    bundle.as_object_mut().unwrap().insert(
        "signature".to_owned(),
        Value::String(BASE64URL_NOPAD.encode(signer.sign(&message).as_ref())),
    );
    bundle
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
}

#[test]
fn workload_stdin_flag_conflicts_with_admin_proof_flags() {
    let action = "00000000-0000-4000-8000-000000000001@1";
    for conflicting in ["--recovery", "--password-stdin"] {
        let output = run(
            &[
                "session",
                "create",
                "--action",
                action,
                "--workload-token-stdin",
                conflicting,
            ],
            Some(b"a.b.c\n"),
        );
        assert_eq!(output.status, 2);
    }
}

#[test]
fn workload_stdin_is_bounded_before_socket_access() {
    let action = "00000000-0000-4000-8000-000000000001@1";
    let oversized = vec![b'a'; rekey_domain::ipc::WORKLOAD_TOKEN_MAX_BYTES as usize + 1];
    let output = run(
        &[
            "session",
            "create",
            "--action",
            action,
            "--workload-token-stdin",
        ],
        Some(&oversized),
    );
    assert_eq!(output.status, 2);
    assert!(output.stderr.contains("INVALID_FRAME"));
}

#[test]
fn real_rekeyd_and_rekey_accept_all_profiles_and_reject_replay_and_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let state = state_dir.to_str().unwrap();
    let init = Command::new(rekeyd_bin())
        .args(["init", "--state-dir", state, "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(format!("{PASSWORD}\n").as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let daemon = Command::new(rekeyd_bin())
        .args(["serve", "--state-dir", state, "--idle-lock", "15m"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = ServeGuard(Some(daemon));
    let admin_socket = state_dir.join("runtime/admin.sock");
    for _ in 0..300 {
        if admin_socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(admin_socket.exists());
    let base = ["--state-dir", state];
    let unlocked = run(
        &[&base[..], &["unlock", "--password-stdin"]].concat(),
        Some(format!("{PASSWORD}\n").as_bytes()),
    );
    assert_eq!(unlocked.status, 0, "{}", unlocked.stderr);

    let added = run(
        &[
            &base[..],
            &["credential", "add", "workload", "--stdin-secrets"],
        ]
        .concat(),
        Some(format!("{PASSWORD}\nblackbox-secret\n").as_bytes()),
    );
    assert_eq!(added.status, 0, "{}", added.stderr);
    let credential_id = serde_json::from_str::<Value>(&added.stdout).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let action_path = dir.path().join("action.json");
    write_json(
        &action_path,
        &json!({
            "name":"workload-action",
            "credential_id":credential_id,
            "origin":"https://example.com",
            "method":"GET",
            "exact_path":"/",
            "auth_header":"authorization",
            "auth_prefix":"Bearer ",
            "timeout_ms":10_000,
            "request_max_bytes":1024,
            "allowed_extra_headers":[],
            "response_max_bytes":4096,
            "allowed_response_headers":["content-type"]
        }),
    );
    let action = run(
        &[
            &base[..],
            &[
                "action",
                "create",
                "--file",
                action_path.to_str().unwrap(),
                "--password-stdin",
            ],
        ]
        .concat(),
        Some(format!("{PASSWORD}\n").as_bytes()),
    );
    assert_eq!(action.status, 0, "{}", action.stderr);
    let action_id = serde_json::from_str::<Value>(&action.stdout).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let action_ref = format!("{action_id}@1");

    let signer = key_pair();
    let workload_key = key_pair();
    let signer_id = PolicySignerId::new_random();
    let trust_path = dir.path().join("trust.json");
    write_json(
        &trust_path,
        &json!({
            "format_version":1,
            "signer_id":signer_id,
            "algorithm":"ed25519",
            "public_key":HEXLOWER.encode(signer.public_key().as_ref())
        }),
    );
    let installed = run(
        &[
            &base[..],
            &[
                "policy",
                "trust",
                "install",
                "--file",
                trust_path.to_str().unwrap(),
                "--step-up-stdin",
            ],
        ]
        .concat(),
        Some(format!("{PASSWORD}\n").as_bytes()),
    );
    assert_eq!(installed.status, 0, "{}", installed.stderr);
    let policy_path = dir.path().join("policy.json");
    write_json(
        &policy_path,
        &policy_bundle(signer_id, &signer, &workload_key, &action_id, 1),
    );
    let activated = run(
        &[
            &base[..],
            &[
                "policy",
                "activate",
                "--file",
                policy_path.to_str().unwrap(),
                "--step-up-stdin",
            ],
        ]
        .concat(),
        Some(format!("{PASSWORD}\n").as_bytes()),
    );
    assert_eq!(activated.status, 0, "{}", activated.stderr);

    let subjects = [
        "service:build",
        "spiffe://issuer.example/workload/api",
        "system:serviceaccount:prod:api",
        "repo:owner/name:ref:refs/heads/main",
    ];
    let mut first_capability = None;
    for (index, subject) in subjects.iter().enumerate() {
        let jwt = token(
            &workload_key,
            subject,
            &format!("blackbox-jti-{index}"),
            600,
        );
        let created = run(
            &[
                &base[..],
                &[
                    "session",
                    "create",
                    "--action",
                    &action_ref,
                    "--ttl",
                    "15m",
                    "--max-uses",
                    "2",
                    "--workload-token-stdin",
                ],
            ]
            .concat(),
            Some(&jwt),
        );
        assert_eq!(created.status, 0, "{}", created.stderr);
        let response = serde_json::from_str::<Value>(&created.stdout).unwrap();
        if index == 0 {
            first_capability = Some(response["capability_token"].as_str().unwrap().to_owned());
            let replay = run(
                &[
                    &base[..],
                    &[
                        "session",
                        "create",
                        "--action",
                        &action_ref,
                        "--workload-token-stdin",
                    ],
                ]
                .concat(),
                Some(&jwt),
            );
            assert_eq!(replay.status, 4, "{}", replay.stderr);
            assert!(replay.stderr.contains("WORKLOAD_IDENTITY_INVALID"));
        }
    }

    let mut tampered = token(&workload_key, subjects[0], "tampered", 600);
    let signature = tampered.iter().rposition(|byte| *byte != b'\n').unwrap();
    tampered[signature] = if tampered[signature] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let denied = run(
        &[
            &base[..],
            &[
                "session",
                "create",
                "--action",
                &action_ref,
                "--workload-token-stdin",
            ],
        ]
        .concat(),
        Some(&tampered),
    );
    assert_eq!(denied.status, 4, "{}", denied.stderr);
    let expired = run(
        &[
            &base[..],
            &[
                "session",
                "create",
                "--action",
                &action_ref,
                "--workload-token-stdin",
            ],
        ]
        .concat(),
        Some(&token(&workload_key, subjects[0], "expired", -1)),
    );
    assert_eq!(expired.status, 4, "{}", expired.stderr);

    write_json(
        &policy_path,
        &policy_bundle(signer_id, &signer, &workload_key, &action_id, 2),
    );
    let rotated = run(
        &[
            &base[..],
            &[
                "policy",
                "activate",
                "--file",
                policy_path.to_str().unwrap(),
                "--step-up-stdin",
            ],
        ]
        .concat(),
        Some(format!("{PASSWORD}\n").as_bytes()),
    );
    assert_eq!(rotated.status, 0, "{}", rotated.stderr);
    let revoked = run(
        &[
            &base[..],
            &[
                "execute",
                &action_ref,
                "--capability",
                first_capability.as_deref().unwrap(),
            ],
        ]
        .concat(),
        None,
    );
    assert_eq!(revoked.status, 4, "{}", revoked.stderr);
    assert!(revoked.stderr.contains("INVALID_CAPABILITY"));

    let audit = run(
        &[&base[..], &["audit", "list", "--limit", "100"]].concat(),
        None,
    );
    assert_eq!(audit.status, 0, "{}", audit.stderr);
    assert!(audit.stdout.contains("workload-attested"));
    for canary in ["blackbox-jti-0", "service:build", "blackbox-secret"] {
        assert!(!audit.stdout.contains(canary), "audit leaked {canary}");
    }

    let shutdown = run(
        &[&base[..], &["shutdown", "--password-stdin"]].concat(),
        Some(format!("{PASSWORD}\n").as_bytes()),
    );
    assert_eq!(shutdown.status, 0, "{}", shutdown.stderr);
    let output = guard.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
