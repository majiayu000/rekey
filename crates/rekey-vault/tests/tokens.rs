mod common;

use std::time::{Duration, Instant};

use data_encoding::BASE64;
use rekey_domain::{
    credential::{CredentialKind, CredentialLabel},
    ids::{ActionId, RequestId},
};
use rekey_vault::{
    AuthorityError,
    command::{OAuthGrantUpdateReason, UnlockProof},
    hygiene::{ScanCredential, ScanInput},
    paths,
    secret::SecretInput,
};

const PLACEHOLDER: &[u8] = br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","scopes":["synthetic.read"],"client_secret":"synthetic-client-secret-0123"}"#;
const GRANT: &[u8] = br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","scopes":["synthetic.read"],"client_secret":"synthetic-client-\u0073ecret-0123","refresh_token":"synthetic-refresh-token-0123"}"#;
const REFRESHED: &[u8] = br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","scopes":["synthetic.read"],"refresh_token":"synthetic-rotated-refresh-token-4567"}"#;
const NOTION: &[u8] = br#"{"credential_type":"oauth-grant-v1","provider":"notion","client_id":"synthetic-client","scopes":[],"access_token":"synthetic-notion-access-0123","expires_at_ms":123456789}"#;
const AWS: &[u8] = br#"{"credential_type":"aws-static-v1","access_key_id":"AKIASYNTHETICFIXTURE12","secret_access_key":"synthetic-aws-secret-0123","session_token":"synthetic-aws-session-0123"}"#;

fn label(name: &str) -> CredentialLabel {
    CredentialLabel::new(name).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn db(state: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(paths::vault_db(state)).unwrap()
}

#[tokio::test]
async fn dedicated_grants_accept_pending_authorization_but_never_inject_source_json_into_http() {
    let fixture = common::init_test_vault();
    let (h, join) = common::spawn(&fixture.state_dir);
    assert!(matches!(
        h.oauth_grant_create(
            label("locked"),
            SecretInput::from_slice(PLACEHOLDER),
            common::password_proof(),
            None
        )
        .await,
        Err(AuthorityError::Locked)
    ));
    h.unlock(common::password_proof()).await.unwrap();
    assert!(matches!(
        h.credential_add(
            label("generic-grant"),
            CredentialKind::OAuthGrant,
            SecretInput::from_slice(GRANT),
            common::password_proof()
        )
        .await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    let google = h
        .oauth_grant_create(
            label("pending-google"),
            SecretInput::from_slice(PLACEHOLDER),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let notion = h
        .oauth_grant_create(
            label("persisted-notion"),
            SecretInput::from_slice(NOTION),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let aws = h
        .credential_add(
            label("synthetic-aws"),
            CredentialKind::AwsStatic,
            SecretInput::from_slice(AWS),
            common::password_proof(),
        )
        .await
        .unwrap();
    for credential in [&google, &notion, &aws] {
        assert!(matches!(
            h.prepare_credential(credential.id).await,
            Err(AuthorityError::CredentialSourceUnavailable)
        ));
        assert!(matches!(
            h.prepare_execution_credential(
                credential.id,
                RequestId::new_random(),
                ActionId::new_random(),
                1,
                deadline()
            )
            .await,
            Err(AuthorityError::CredentialSourceUnavailable)
        ));
    }
    assert!(matches!(
        h.prepare_oauth_grant(aws.id).await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    assert!(matches!(
        h.prepare_aws_static(google.id).await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    assert!(matches!(
        h.credential_rotate_typed_before(
            google.id,
            CredentialKind::OAuthGrant,
            Some(1),
            SecretInput::from_slice(GRANT),
            common::password_proof(),
            None
        )
        .await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    let prepared = h.prepare_oauth_grant(google.id).await.unwrap();
    assert_eq!(
        (prepared.kind(), prepared.version()),
        (CredentialKind::OAuthGrant, 1)
    );
    prepared.consume(|payload| assert_eq!(payload, PLACEHOLDER));
    h.prepare_oauth_grant(notion.id)
        .await
        .unwrap()
        .consume(|payload| assert_eq!(payload, NOTION));
    h.prepare_aws_static(aws.id)
        .await
        .unwrap()
        .consume(|payload| assert_eq!(payload, AWS));
    for invalid in [
        br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","scopes":[],"access_token":"synthetic-must-not-persist"}"#.as_slice(),
        br#"{"credential_type":"oauth-grant-v1","provider":"google","client_id":"synthetic-client","scopes":[],"refresh_token":9}"#,
    ] {
        assert!(h.oauth_grant_create(label("invalid"), SecretInput::from_slice(invalid), common::password_proof(), None).await.is_err());
    }
    assert!(h.credential_add(label("invalid-aws"), CredentialKind::AwsStatic, SecretInput::from_slice(br#"{"credential_type":"aws-static-v1","access_key_id":"fixture","secret_access_key":true}"#), common::password_proof()).await.is_err());
    h.oauth_grant_update(notion.id, 1, SecretInput::from_slice(br#"{"credential_type":"oauth-grant-v1","provider":"notion","client_id":"synthetic-client","scopes":[],"access_token":"synthetic-notion-access-0123"}"#), common::password_proof(), None).await.unwrap();
    assert_eq!(h.credential_list().await.unwrap().len(), 3);
    let bad_proof = UnlockProof::Password(SecretInput::from_slice(b"synthetic-wrong-password"));
    assert!(matches!(
        h.oauth_grant_update(
            google.id,
            1,
            SecretInput::from_slice(GRANT),
            bad_proof,
            None
        )
        .await,
        Err(AuthorityError::InvalidUnlockCredential)
    ));
    h.oauth_grant_update(
        google.id,
        1,
        SecretInput::from_slice(GRANT),
        common::password_proof(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(h.prepare_oauth_grant(google.id).await.unwrap().version(), 2);
    let sql = db(&fixture.state_dir);
    let ciphertexts: Vec<Vec<u8>> = sql
        .prepare("SELECT encrypted_payload FROM credential_versions")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(ciphertexts.iter().all(|bytes| {
        !bytes
            .windows(b"synthetic".len())
            .any(|part| part == b"synthetic")
    }));
    h.shutdown(Some(common::password_proof())).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn internal_oauth_rotation_is_active_kind_and_version_bound_with_distinct_audit_events() {
    let fixture = common::init_test_vault();
    let (h, join) = common::spawn(&fixture.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let oauth = h
        .oauth_grant_create(
            label("oauth"),
            SecretInput::from_slice(PLACEHOLDER),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let aws = h
        .credential_add(
            label("aws"),
            CredentialKind::AwsStatic,
            SecretInput::from_slice(AWS),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert_eq!(
        h.rotate_oauth_grant(
            oauth.id,
            1,
            SecretInput::from_slice(GRANT),
            OAuthGrantUpdateReason::Authorized,
            deadline()
        )
        .await
        .unwrap()
        .current_version,
        2
    );
    assert_eq!(
        h.rotate_oauth_grant(
            oauth.id,
            2,
            SecretInput::from_slice(REFRESHED),
            OAuthGrantUpdateReason::Refreshed,
            deadline()
        )
        .await
        .unwrap()
        .current_version,
        3
    );
    for (id, version, until) in [
        (oauth.id, 2, deadline()),
        (aws.id, 1, deadline()),
        (oauth.id, 3, Instant::now() - Duration::from_millis(1)),
    ] {
        assert!(
            h.rotate_oauth_grant(
                id,
                version,
                SecretInput::from_slice(GRANT),
                OAuthGrantUpdateReason::Refreshed,
                until
            )
            .await
            .is_err()
        );
    }
    let preserved = h.prepare_oauth_grant(oauth.id).await.unwrap();
    assert_eq!(preserved.version(), 3);
    preserved.consume(|payload| assert_eq!(payload, REFRESHED));
    let sql = db(&fixture.state_dir);
    let events: Vec<String> = sql
        .prepare(
            "SELECT event_type FROM audit_events WHERE event_type LIKE 'oauth.%' ORDER BY sequence",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(events, vec!["oauth.authorized", "oauth.refreshed"]);
    h.credential_revoke(oauth.id, common::password_proof())
        .await
        .unwrap();
    assert!(matches!(
        h.rotate_oauth_grant(
            oauth.id,
            3,
            SecretInput::from_slice(GRANT),
            OAuthGrantUpdateReason::Refreshed,
            deadline()
        )
        .await,
        Err(AuthorityError::CredentialRevoked)
    ));
    assert!(matches!(
        h.prepare_oauth_grant(oauth.id).await,
        Err(AuthorityError::CredentialRevoked)
    ));
    h.lock("synthetic lock test").await.unwrap();
    assert!(matches!(
        h.rotate_oauth_grant(
            oauth.id,
            3,
            SecretInput::from_slice(GRANT),
            OAuthGrantUpdateReason::Refreshed,
            deadline()
        )
        .await,
        Err(AuthorityError::Locked)
    ));
    h.shutdown(Some(common::password_proof())).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn refresh_audit_and_transaction_commit_failures_leave_old_grant_intact() {
    for mode in ["audit", "commit"] {
        let fixture = common::init_test_vault();
        let (h, join) = common::spawn(&fixture.state_dir);
        h.unlock(common::password_proof()).await.unwrap();
        let oauth = h
            .oauth_grant_create(
                label("oauth"),
                SecretInput::from_slice(GRANT),
                common::password_proof(),
                None,
            )
            .await
            .unwrap();
        let sql = db(&fixture.state_dir);
        let before: (Vec<u8>, Vec<u8>, u64) = sql
            .query_row(
                "SELECT encrypted_payload, wrapped_dek, version FROM credential_versions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        if mode == "audit" {
            sql.execute_batch("CREATE TRIGGER fail_refresh BEFORE INSERT ON audit_events WHEN NEW.event_type='oauth.refreshed' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
        } else {
            sql.execute_batch("CREATE TABLE test_parent(id INTEGER PRIMARY KEY); CREATE TABLE test_child(id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_refresh AFTER INSERT ON audit_events WHEN NEW.event_type='oauth.refreshed' BEGIN INSERT INTO test_child VALUES(1); END;").unwrap();
        }
        assert!(matches!(
            h.rotate_oauth_grant(
                oauth.id,
                1,
                SecretInput::from_slice(REFRESHED),
                OAuthGrantUpdateReason::Refreshed,
                deadline()
            )
            .await,
            Err(AuthorityError::AuditCommitFailed)
        ));
        let after: (Vec<u8>, Vec<u8>, u64) = sql
            .query_row(
                "SELECT encrypted_payload, wrapped_dek, version FROM credential_versions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            sql.query_row("SELECT current_version FROM credentials", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM credential_versions", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='oauth.refreshed'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(h.status().await.unwrap().state, "faulted");
        sql.execute_batch("DROP TRIGGER fail_refresh").unwrap();
        if mode == "commit" {
            sql.execute_batch("DROP TABLE test_child; DROP TABLE test_parent;")
                .unwrap();
        }
        h.shutdown(Some(common::password_proof())).await.unwrap();
        join.join().unwrap();
        let (h, join) = common::spawn(&fixture.state_dir);
        if mode == "commit" {
            // A commit failure after the durable generation reservation keeps
            // the existing rollback confirmation requirement intact.
            assert!(matches!(
                h.unlock(common::password_proof()).await,
                Err(AuthorityError::RollbackSuspected)
            ));
            let context = h.status().await.unwrap().rollback.unwrap();
            h.confirm_rollback(
                context,
                rekey_vault::bootstrap::RestoreProof::Password(common::password_input()),
                deadline(),
            )
            .await
            .unwrap();
        }
        h.unlock(common::password_proof()).await.unwrap();
        h.prepare_oauth_grant(oauth.id)
            .await
            .unwrap()
            .consume(|payload| assert_eq!(payload, GRANT));
        h.shutdown(Some(common::password_proof())).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn scan_matches_decoded_oauth_and_aws_fields_and_only_reports_locations() {
    let fixture = common::init_test_vault();
    let (h, join) = common::spawn(&fixture.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let oauth = h
        .oauth_grant_create(
            label("oauth"),
            SecretInput::from_slice(GRANT),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let notion = h
        .oauth_grant_create(
            label("notion"),
            SecretInput::from_slice(NOTION),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let aws = h
        .credential_add(
            label("aws"),
            CredentialKind::AwsStatic,
            SecretInput::from_slice(AWS),
            common::password_proof(),
        )
        .await
        .unwrap();
    let canaries = [
        "synthetic-client-secret-0123",
        "synthetic-refresh-token-0123",
        "synthetic-notion-access-0123",
        "AKIASYNTHETICFIXTURE12",
        "synthetic-aws-secret-0123",
        "synthetic-aws-session-0123",
    ];
    let text = canaries
        .iter()
        .enumerate()
        .map(|(index, value)| {
            format!(
                "{}\n",
                if index % 2 == 0 {
                    value.to_string()
                } else {
                    BASE64.encode(value.as_bytes())
                }
            )
        })
        .collect::<String>();
    let findings = h
        .scan_credentials(
            vec![ScanInput::new("fixture.txt", text.into_bytes())],
            vec![
                ScanCredential {
                    connection: "oauth".into(),
                    credential_id: oauth.id,
                },
                ScanCredential {
                    connection: "notion".into(),
                    credential_id: notion.id,
                },
                ScanCredential {
                    connection: "aws".into(),
                    credential_id: aws.id,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(findings.len(), 6);
    for (index, expected) in ["oauth", "oauth", "notion", "aws", "aws", "aws"]
        .iter()
        .enumerate()
    {
        assert!(
            findings
                .iter()
                .any(|finding| finding.connection == *expected
                    && finding.line == index as u32 + 1
                    && finding.column == 1)
        );
    }
    let encoded = serde_json::to_string(&findings).unwrap();
    assert!(canaries.iter().all(|value| !encoded.contains(value)));
    h.shutdown(Some(common::password_proof())).await.unwrap();
    join.join().unwrap();
}
