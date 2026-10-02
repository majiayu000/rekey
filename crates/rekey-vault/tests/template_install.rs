//! Atomic, authenticated template installation using synthetic vaults only.
mod common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use rekey_domain::action::{ActionTarget, ExactPath, FixedMethod, HttpsOrigin};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{CredentialId, PolicySignerId, RequestId};
use rekey_domain::ipc::{TemplateFixedAction, TemplateInstallMeta, TemplateSource};
use rekey_vault::command::{PolicyTrustInput, UnlockProof};
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rusqlite::Connection;
use serde_json::json;

fn input(credential_id: CredentialId) -> TemplateInstallMeta {
    TemplateInstallMeta {
        source: TemplateSource::GitHubPat {},
        credential_id,
        bindings: vec![BTreeMap::from([
            ("owner".into(), "acme".into()),
            ("repo".into(), "one".into()),
        ])],
        capabilities: vec!["read-repo".into(), "create-issue".into()],
        name_prefix: "work".into(),
        timeout_ms: 1000,
        request_max_bytes: 1024,
        response_max_bytes: 1024,
        allowed_extra_headers: vec![],
        allowed_response_headers: vec![],
    }
}

async fn seed(handle: &AuthorityHandle, kind: CredentialKind) -> CredentialId {
    handle.unlock(common::password_proof()).await.unwrap();
    handle
        .credential_add(
            CredentialLabel::new("synthetic").unwrap(),
            kind,
            SecretInput::from_slice(b"synthetic-install-token"),
            common::password_proof(),
        )
        .await
        .unwrap()
        .id
}

async fn finish(handle: AuthorityHandle, join: std::thread::JoinHandle<()>) {
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

fn counts(connection: &Connection) -> (u64, u64) {
    (
        connection
            .query_row("SELECT count(*) FROM actions", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='action.created'",
                [],
                |row| row.get(0),
            )
            .unwrap(),
    )
}

#[tokio::test]
async fn multiple_bindings_install_all_selected_actions_with_sealed_source_and_audit() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let credential_id = seed(&handle, CredentialKind::OpaqueToken).await;
    let catalog = handle
        .template_catalog_before(TemplateSource::GitHubPat {}, vec![], None)
        .await
        .unwrap();
    let mut request = input(credential_id);
    request.bindings.push(BTreeMap::from([
        ("owner".into(), "other".into()),
        ("repo".into(), "two".into()),
    ]));
    let request_id = RequestId::new_random();
    let response = handle
        .template_install_before(
            request.clone(),
            vec![],
            common::password_proof(),
            request_id,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.actions.len(), 16);
    let mut ids = std::collections::BTreeSet::new();
    for installed in &response.actions {
        let action = &installed.action;
        assert!(ids.insert(action.id.to_string()));
        assert_eq!(action.version, 1);
        assert_eq!(action.origin.as_str(), "https://api.github.com");
        assert_eq!(action.auth.header_name.as_str(), "authorization");
        let ActionTarget::Template {
            target,
            source,
            body_schema,
            fixed_headers,
            ..
        } = &action.target
        else {
            panic!("template required")
        };
        assert_eq!(source.digest, catalog.digest);
        assert_eq!(source.signer_id, None);
        assert_eq!(source.template, "github-pat@1");
        let expected = if installed.binding_index == 0 {
            "/repos/acme/one"
        } else {
            "/repos/other/two"
        };
        assert!(target.path_pattern().starts_with(expected));
        assert!(
            fixed_headers.contains_key(&rekey_domain::action::HeaderName::new("accept").unwrap())
        );
        if source.capability == "create-issue" {
            assert!(body_schema.as_ref().unwrap().is_object());
        }
        // This read verifies the persisted row seal before decoding.
        assert_eq!(
            handle
                .action_get(action.id, 1)
                .await
                .unwrap()
                .action
                .name
                .as_str(),
            action.name.as_str()
        );
    }
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(counts(&db), (16, 16));
    let audited: u64 = db.query_row("SELECT count(*) FROM audit_events WHERE event_type='action.created' AND request_id=?1 AND reason_code='template-install'", [request_id.as_bytes().as_slice()], |row| row.get(0)).unwrap();
    assert_eq!(audited, 16);
    let again = handle
        .template_install_before(
            request,
            vec![],
            common::password_proof(),
            RequestId::new_random(),
            None,
        )
        .await
        .unwrap();
    assert!(
        again
            .actions
            .iter()
            .all(|installed| !ids.contains(&installed.action.id.to_string()))
    );
    finish(handle, join).await;
}

#[tokio::test]
async fn invalid_late_binding_capability_headers_and_capacity_leave_no_rows() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let credential_id = seed(&handle, CredentialKind::OpaqueToken).await;
    let mut bad_binding = input(credential_id);
    bad_binding.bindings.push(BTreeMap::from([
        ("owner".into(), "acme".into()),
        ("repo".into(), "../escape".into()),
    ]));
    let mut bad_capability = input(credential_id);
    bad_capability.capabilities.push("unknown".into());
    let mut duplicate = input(credential_id);
    duplicate.capabilities.push("read-repo".into());
    let mut fixed_header = input(credential_id);
    fixed_header.allowed_extra_headers.push("accept".into());
    let mut capacity = input(credential_id);
    capacity.bindings = vec![capacity.bindings[0].clone(); 100];
    for request in [
        bad_binding,
        bad_capability,
        duplicate,
        fixed_header,
        capacity,
    ] {
        let result = handle
            .template_install_before(
                request,
                vec![],
                common::password_proof(),
                RequestId::new_random(),
                None,
            )
            .await;
        assert_eq!(result.unwrap_err().code(), "INVALID_INPUT");
        assert!(handle.action_list().await.unwrap().is_empty());
    }
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(counts(&db), (0, 0));
    finish(handle, join).await;
}

#[tokio::test]
async fn proof_kind_revocation_and_deadline_fail_before_any_creation() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let id = seed(&handle, CredentialKind::GitHubAppInstallation).await;
    let error = handle
        .template_install_before(
            input(id),
            vec![],
            common::password_proof(),
            RequestId::new_random(),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "INVALID_INPUT");
    let id = handle
        .credential_add(
            CredentialLabel::new("opaque").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic-other"),
            common::password_proof(),
        )
        .await
        .unwrap()
        .id;
    let wrong = UnlockProof::Password(SecretInput::from_slice(b"wrong-proof"));
    assert_eq!(
        handle
            .template_install_before(input(id), vec![], wrong, RequestId::new_random(), None)
            .await
            .unwrap_err()
            .code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    assert_eq!(
        handle
            .template_install_before(
                input(id),
                vec![],
                common::password_proof(),
                RequestId::new_random(),
                Some(Instant::now())
            )
            .await
            .unwrap_err()
            .code(),
        "AUTHORITY_BUSY"
    );
    handle
        .credential_revoke(id, common::password_proof())
        .await
        .unwrap();
    assert_eq!(
        handle
            .template_install_before(
                input(id),
                vec![],
                common::password_proof(),
                RequestId::new_random(),
                None
            )
            .await
            .unwrap_err()
            .code(),
        "CREDENTIAL_UNAVAILABLE"
    );
    assert!(handle.action_list().await.unwrap().is_empty());
    finish(handle, join).await;
}

fn signed_package(signer: &Ed25519KeyPair, signer_id: PolicySignerId) -> Vec<u8> {
    let mut template = serde_json::to_value(rekey_domain::template::github_pat().unwrap()).unwrap();
    template["template"] = json!("team@1");
    let mut envelope =
        json!({"format_version":1,"signer_id":signer_id,"template":template,"schemas":{}});
    // These test fixtures contain only ASCII strings and integers. serde_json's
    // sorted map encoding is the JCS representation for this restricted input.
    let mut message = rekey_policy::templates::TEMPLATE_SIGN_PREFIX.to_vec();
    message.extend(serde_json::to_vec(&envelope).unwrap());
    envelope["signature"] =
        json!(data_encoding::BASE64URL_NOPAD.encode(signer.sign(&message).as_ref()));
    serde_json::to_vec(&envelope).unwrap()
}

#[tokio::test]
async fn team_package_uses_installed_trust_without_policy_activation_and_rejects_tampering() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let id = seed(&handle, CredentialKind::OpaqueToken).await;
    let signer = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
    let signer_id = PolicySignerId::new_random();
    let package = signed_package(&signer, signer_id);
    assert_eq!(
        handle
            .template_catalog_before(TemplateSource::SignedPackage {}, package.clone(), None)
            .await
            .unwrap_err()
            .code(),
        "POLICY_UNAVAILABLE"
    );
    handle
        .policy_trust_install_before(
            PolicyTrustInput {
                signer_id,
                public_key: signer.public_key().as_ref().try_into().unwrap(),
            },
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert!(handle.policy_material().await.unwrap().bundle.is_none());
    let catalog = handle
        .template_catalog_before(TemplateSource::SignedPackage {}, package.clone(), None)
        .await
        .unwrap();
    assert_eq!(catalog.signer_id, Some(signer_id));
    let mut request = input(id);
    request.source = TemplateSource::SignedPackage {};
    let mut bad: serde_json::Value = serde_json::from_slice(&package).unwrap();
    bad["template"]["origin"] = json!("https://elsewhere.example.com");
    let duplicate = [b"{\"format_version\":1,".as_slice(), &package[1..]].concat();
    for bytes in [
        serde_json::to_vec(&bad).unwrap(),
        duplicate,
        vec![b'x'; 65537],
    ] {
        assert!(
            handle
                .template_install_before(
                    request.clone(),
                    bytes,
                    common::password_proof(),
                    RequestId::new_random(),
                    None
                )
                .await
                .is_err()
        );
        assert!(handle.action_list().await.unwrap().is_empty());
    }
    let response = handle
        .template_install_before(
            request,
            package.clone(),
            common::password_proof(),
            RequestId::new_random(),
            None,
        )
        .await
        .unwrap();
    for installed in response.actions {
        let ActionTarget::Template { source, .. } = installed.action.target else {
            panic!()
        };
        assert_eq!(source.signer_id, Some(signer_id));
        assert_eq!(source.digest, catalog.digest);
    }
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    let before = counts(&db);
    db.execute("UPDATE policy_trust SET public_key=?1", [vec![19u8; 32]])
        .unwrap();
    let error = handle
        .template_catalog_before(TemplateSource::SignedPackage {}, package, None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "STORAGE_INTEGRITY_FAILED");
    assert_eq!(handle.action_list().await.unwrap_err().code(), "FAULTED");
    assert_eq!(counts(&db), before);
    finish(handle, join).await;
}

#[tokio::test]
async fn late_sql_and_audit_failures_roll_back_the_entire_batch() {
    for audit_failure in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        let id = seed(&handle, CredentialKind::OpaqueToken).await;
        let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
        let sql = if audit_failure {
            "CREATE TRIGGER fail_second BEFORE INSERT ON audit_events WHEN NEW.event_type='action.created' AND (SELECT count(*) FROM audit_events WHERE event_type='action.created')=1 BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END"
        } else {
            "CREATE TRIGGER fail_second BEFORE INSERT ON actions WHEN (SELECT count(*) FROM actions)=1 BEGIN SELECT RAISE(ABORT,'synthetic row failure'); END"
        };
        db.execute_batch(sql).unwrap();
        let error = handle
            .template_install_before(
                input(id),
                vec![],
                common::password_proof(),
                RequestId::new_random(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            if audit_failure {
                "AUDIT_COMMIT_FAILED"
            } else {
                "STORAGE_UNAVAILABLE"
            }
        );
        assert_eq!(counts(&db), (0, 0));
        assert_eq!(
            handle.status().await.unwrap().state,
            if audit_failure { "faulted" } else { "unlocked" }
        );
        db.execute_batch("DROP TRIGGER fail_second").unwrap();
        finish(handle, join).await;
    }
}

#[tokio::test]
async fn generic_bearer_is_closed_and_bounded_to_twenty_actions() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let id = seed(&handle, CredentialKind::OpaqueToken).await;
    let action = TemplateFixedAction {
        method: FixedMethod::Get,
        path: ExactPath::parse("/fixed").unwrap(),
    };
    let source = |count| TemplateSource::GenericBearer {
        origin: HttpsOrigin::parse("https://api.example.com").unwrap(),
        actions: vec![action.clone(); count],
    };
    for count in [0, 21] {
        assert!(
            handle
                .template_catalog_before(source(count), vec![], None)
                .await
                .is_err()
        );
    }
    assert!(
        handle
            .template_catalog_before(source(1), b"not-a-builtin".to_vec(), None)
            .await
            .is_err()
    );
    let mut request = input(id);
    request.source = source(20);
    request.bindings = vec![BTreeMap::new()];
    request.capabilities = vec!["fixed-actions".into()];
    assert_eq!(
        handle
            .template_install_before(
                request,
                vec![],
                common::password_proof(),
                RequestId::new_random(),
                None
            )
            .await
            .unwrap()
            .actions
            .len(),
        20
    );
    finish(handle, join).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_lock_outlasting_deadline_never_commits_a_late_batch() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    let id = seed(&handle, CredentialKind::OpaqueToken).await;
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        db.execute_batch("ROLLBACK").unwrap();
    });
    let error = handle
        .template_install_before(
            input(id),
            vec![],
            common::password_proof(),
            RequestId::new_random(),
            Some(Instant::now() + Duration::from_millis(100)),
        )
        .await
        .unwrap_err();
    release.join().unwrap();
    assert_eq!(error.code(), "AUTHORITY_BUSY");
    let db = Connection::open(paths::vault_db(&vault.state_dir)).unwrap();
    assert_eq!(counts(&db), (0, 0));
    finish(handle, join).await;
}
