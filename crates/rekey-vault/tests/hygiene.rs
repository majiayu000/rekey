mod common;

use std::os::unix::fs::PermissionsExt;

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_vault::AuthorityError;
use rekey_vault::hygiene::{
    EnvImportRequest, EnvImportSelection, EnvReplacement, ScanCredential, ScanInput,
    matching_positions, preview_env, rewrite_env,
};

const CANARY: &[u8] = b"synthetic-scan-canary-1234";

#[test]
fn full_secret_variants_and_source_offsets() {
    for encoding in [
        &BASE64,
        &BASE64_NOPAD,
        &BASE64URL,
        &BASE64URL_NOPAD,
        &HEXLOWER,
        &HEXUPPER,
    ] {
        let input = format!("first\n  {}", encoding.encode(CANARY));
        assert_eq!(
            matching_positions(input.as_bytes(), CANARY).unwrap(),
            vec![8]
        );
    }
    assert_eq!(
        matching_positions(b"--synthetic-scan-canary-1234--", CANARY).unwrap(),
        vec![2]
    );
    let percent = CANARY
        .iter()
        .map(|byte| format!("%{byte:02X}"))
        .collect::<String>();
    let escaped = CANARY
        .iter()
        .map(|byte| format!("\\u{byte:04x}"))
        .collect::<String>();
    for encoded in [percent, escaped] {
        let input = format!("  {encoded}");
        assert_eq!(
            matching_positions(input.as_bytes(), CANARY).unwrap(),
            vec![2]
        );
    }
    assert!(
        matching_positions(&CANARY[..CANARY.len() - 1], CANARY)
            .unwrap()
            .is_empty()
    );
    assert!(
        matching_positions(br"synthetic-\uZZZZcanary", CANARY)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        matching_positions(br"z\uD83D\uDE00y", "😀".as_bytes()).unwrap(),
        vec![1]
    );
    assert!(matching_positions(b"safe", b"").unwrap().is_empty());
    assert!(matching_positions(&vec![b'x'; 5000], b"x").is_err());
}

#[tokio::test]
async fn scan_is_locked_until_unlock_and_returns_only_locations() {
    let fixture = common::init_test_vault();
    let (authority, join) = common::spawn(&fixture.state_dir);
    assert!(matches!(
        authority.scan_credentials(Vec::new(), Vec::new()).await,
        Err(AuthorityError::Locked)
    ));
    authority.unlock(common::password_proof()).await.unwrap();
    let credential = authority
        .credential_add(
            CredentialLabel::new("synthetic-connection").unwrap(),
            CredentialKind::OpaqueToken,
            rekey_vault::secret::SecretInput::from_slice(CANARY),
            common::password_proof(),
        )
        .await
        .unwrap();
    let findings = authority
        .scan_credentials(
            vec![ScanInput::new(
                "src/fixture.txt",
                [b"safe\n  ".as_slice(), CANARY].concat(),
            )],
            vec![ScanCredential {
                connection: "synthetic-connection".to_owned(),
                credential_id: credential.id,
            }],
        )
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!((findings[0].line, findings[0].column), (2, 3));
    let result = serde_json::to_string(&findings).unwrap();
    assert!(!result.contains(std::str::from_utf8(CANARY).unwrap()));
    let audit = rekey_vault::store::SqliteRecordStore::open(&rekey_vault::paths::vault_db(
        &fixture.state_dir,
    ))
    .unwrap();
    assert!(
        audit
            .audit_event_types()
            .unwrap()
            .iter()
            .any(|event| event == "scan.performed")
    );
    authority
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn scan_checks_byte_limits_before_decryption_and_audit_failure_is_closed() {
    let fixture = common::init_test_vault();
    let (authority, join) = common::spawn(&fixture.state_dir);
    authority.unlock(common::password_proof()).await.unwrap();
    assert!(
        authority
            .scan_credentials(
                vec![ScanInput::new("large", vec![0; 10 * 1024 * 1024 + 1])],
                Vec::new()
            )
            .await
            .is_err()
    );
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&fixture.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER deny_scan BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    let failed = authority.scan_credentials(Vec::new(), Vec::new()).await;
    assert!(matches!(
        failed,
        Err(AuthorityError::StorageUnavailable(_) | AuthorityError::AuditCommitFailed)
    ));
    assert_eq!(authority.status().await.unwrap().state, "faulted");
    authority
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[test]
fn dotenv_preview_retains_unsupported_syntax_and_redacts_values() {
    let input = b"# fixture\nexport OPENAI_API_KEY='sk-synthetic-fixture'\nDB_PASSWORD=synthetic-database-password\nEXPANDED=$OTHER\nDUP=first\nDUP=second\nQUOTED=\"line\\nsecret\"\nBROKEN=\"unterminated\n";
    let preview = rekey_vault::hygiene::env::preview_bytes(input);
    assert_eq!(
        preview
            .entries
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        vec!["OPENAI_API_KEY", "DB_PASSWORD", "QUOTED"]
    );
    assert_eq!(preview.unsupported.len(), 3);
    let json = serde_json::to_string(&preview).unwrap();
    assert!(!json.contains("sk-synthetic-fixture"));
    assert!(!json.contains("synthetic-database-password"));
}

#[tokio::test]
async fn daemon_imports_once_without_changing_project_file() {
    let fixture = common::init_test_vault();
    let path = fixture
        .dir
        .path()
        .canonicalize()
        .unwrap()
        .join("fixture.env");
    let original = b"OPENAI_API_KEY=sk-synthetic-only\nDB_PASSWORD=keep-me\n";
    std::fs::write(&path, original).unwrap();
    let (authority, join) = common::spawn(&fixture.state_dir);
    authority.unlock(common::password_proof()).await.unwrap();
    let imported = authority
        .import_env(
            EnvImportRequest {
                path: path.clone(),
                selections: vec![EnvImportSelection {
                    key: "OPENAI_API_KEY".to_owned(),
                    label: CredentialLabel::new("synthetic-openai").unwrap(),
                }],
            },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(imported.entries.len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(
        !serde_json::to_string(&imported)
            .unwrap()
            .contains("sk-synthetic-only")
    );
    let failure = authority
        .import_env(
            EnvImportRequest {
                path: path.clone(),
                selections: vec![EnvImportSelection {
                    key: "DB_PASSWORD".to_owned(),
                    label: CredentialLabel::new("never-created").unwrap(),
                }],
            },
            rekey_vault::command::UnlockProof::Password(
                rekey_vault::secret::SecretInput::from_slice(b"bad-password"),
            ),
            None,
        )
        .await;
    assert!(matches!(
        failure,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    assert_eq!(authority.credential_list().await.unwrap().len(), 1);
    authority
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[test]
fn atomic_dotenv_rewrite_preserves_unsupported_values_and_creates_private_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("fixture.env");
    let original =
        b"# keep\nOPENAI_API_KEY=sk-synthetic-only\nOPENAI_BASE_URL=https://synthetic.invalid/v1\nDB_PASSWORD=keep-me\nEXPANDED=$OTHER\n";
    std::fs::write(&path, original).unwrap();
    let replacements = vec![EnvReplacement {
        key: "OPENAI_API_KEY".to_owned(),
        base_url_variable: "OPENAI_BASE_URL".to_owned(),
        base_url: "http://127.0.0.1:7787/c/synthetic-openai/v1".to_owned(),
    }];
    let backup = rewrite_env(&path, &replacements).unwrap();
    assert_eq!(std::fs::read(&backup).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let rewritten = std::fs::read_to_string(&path).unwrap();
    assert!(rewritten.contains("OPENAI_API_KEY=rekey"));
    assert!(rewritten.contains("OPENAI_BASE_URL=\"http://127.0.0.1:7787/c/synthetic-openai/v1\""));
    assert_eq!(rewritten.matches("OPENAI_BASE_URL=").count(), 1);
    assert!(!rewritten.contains("synthetic.invalid"));
    assert!(rewritten.contains("DB_PASSWORD=keep-me\nEXPANDED=$OTHER"));
    assert!(!rewritten.contains("sk-synthetic-only"));
    assert!(rewrite_env(&path, &replacements).is_err());
    assert_eq!(std::fs::read(&backup).unwrap(), original);
}

#[test]
fn dotenv_refuses_file_directory_and_backup_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let target = root.join("actual.env");
    std::fs::write(&target, b"KEY=synthetic\n").unwrap();
    let link = root.join("link.env");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(preview_env(&link).is_err());
    let directory_link = root.join("link-dir");
    std::os::unix::fs::symlink(&root, &directory_link).unwrap();
    assert!(preview_env(&directory_link.join("actual.env")).is_err());
    std::os::unix::fs::symlink(&target, root.join("actual.env.rekey-backup")).unwrap();
    assert!(
        rewrite_env(
            &target,
            &[EnvReplacement {
                key: "KEY".to_owned(),
                base_url_variable: "BASE_URL".to_owned(),
                base_url: "http://127.0.0.1:7787/c/test".to_owned()
            }]
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"KEY=synthetic\n");
}

#[tokio::test]
async fn connection_audit_keeps_context_and_rejects_mismatched_rule_binding() {
    use rekey_domain::connection::{ConnectionRequestAuditContext, MethodClass};
    use rekey_domain::ids::{PolicyRuleId, PrincipalId, RequestId};
    use rekey_vault::command::AuditDraft;
    use rekey_vault::model::AuthorizationEvidence;

    let fixture = common::init_test_vault();
    let (authority, join) = common::spawn(&fixture.state_dir);
    authority.unlock(common::password_proof()).await.unwrap();
    let rule = PolicyRuleId::new_random();
    let request = RequestId::new_random();
    let draft = AuditDraft {
        request_id: Some(request),
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: Some(Box::new(AuthorizationEvidence {
            principal_id: PrincipalId::new_random(),
            policy_version: 1,
            policy_digest: [3; 32],
            policy_rule_id: Some(rule),
            resource_type: "connection".to_owned(),
            resource_id: "synthetic-service".to_owned(),
            parameter_hash: [0; 32],
        })),
        approval: None,
        usage: None,
        request_context: Some(
            ConnectionRequestAuditContext {
                connection: "synthetic-service".to_owned(),
                caller: "codex".to_owned(),
                method_class: MethodClass::Read,
                normalized_path: "/items".to_owned(),
                rule_id: Some(rule),
            }
            .into(),
        ),
        event_type: "execution.blocked",
        outcome: "denied",
        reason_code: "synthetic-policy".to_owned(),
        upstream_status: None,
        latency_ms: None,
    };
    authority.append_audit(draft.clone()).await.unwrap();
    let mut wrong = draft.clone();
    wrong.authorization.as_mut().unwrap().policy_rule_id = Some(PolicyRuleId::new_random());
    assert!(authority.append_audit(wrong).await.is_err());
    let mut missing = draft;
    missing.request_id = None;
    assert!(authority.append_audit(missing).await.is_err());
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&fixture.state_dir)).unwrap();
    let metadata: String = db
        .query_row(
            "SELECT metadata_json FROM audit_events WHERE request_id=?1",
            [request.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(metadata.contains("synthetic-service"));
    assert!(metadata.contains("\"normalized_path\":\"/items\""));
    authority
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
