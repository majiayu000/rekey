mod common;

use aws_lc_rs::signature;
use rekey_domain::{
    connection::{ConnectionRequestAuditContext, MethodClass},
    credential::{CredentialKind, CredentialLabel},
    ids::{CredentialId, PrincipalId, RequestId},
};
use rekey_vault::{
    AuthorityError,
    command::{AuditDraft, SshKeyMode, SshSignPurpose, SshSignStart},
    model::{AuthorizationEvidence, event_type, outcome},
};
use std::time::{Duration, Instant};

fn start(draft: AuditDraft) -> SshSignStart {
    SshSignStart {
        draft,
        purpose: SshSignPurpose::Unknown,
        host_key_sha256: None,
    }
}

fn started(credential: CredentialId) -> AuditDraft {
    AuditDraft {
        request_id: Some(RequestId::new_random()),
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: Some(credential),
        credential_version: None,
        authorization: Some(Box::new(AuthorizationEvidence {
            principal_id: PrincipalId::new_random(),
            policy_version: 1,
            policy_digest: [3; 32],
            policy_rule_id: None,
            resource_type: "connection".into(),
            resource_id: "synthetic-ssh".into(),
            parameter_hash: [7; 32],
        })),
        approval: None,
        usage: None,
        request_context: Some(
            ConnectionRequestAuditContext {
                connection: "synthetic-ssh".into(),
                caller: "ssh".into(),
                method_class: MethodClass::Write,
                normalized_path: "/ssh/sign".into(),
                rule_id: None,
            }
            .into(),
        ),
        event_type: event_type::EXECUTION_STARTED,
        outcome: outcome::SUCCESS,
        reason_code: "ssh-sign".into(),
        upstream_status: None,
        latency_ms: None,
    }
}
fn string<'a>(bytes: &mut &'a [u8]) -> &'a [u8] {
    let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let (head, tail) = bytes[4..].split_at(len);
    *bytes = tail;
    head
}
fn verify(public: &[u8], blob: &[u8], data: &[u8]) {
    let mut public = public;
    let alg = string(&mut public);
    let mut blob = blob;
    assert_eq!(string(&mut blob), alg);
    let signature = string(&mut blob);
    assert!(blob.is_empty());
    if alg == b"ssh-ed25519" {
        signature::UnparsedPublicKey::new(&signature::ED25519, string(&mut public))
            .verify(data, signature)
            .unwrap();
    } else {
        assert_eq!(string(&mut public), b"nistp256");
        let point = string(&mut public);
        let mut parts = signature;
        let mut fixed = [0; 64];
        for half in fixed.chunks_mut(32) {
            let part = string(&mut parts);
            let part = if part.len() == 33 {
                assert_eq!(part[0], 0);
                &part[1..]
            } else {
                part
            };
            half[32 - part.len()..].copy_from_slice(part);
        }
        assert!(parts.is_empty());
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(data, &fixed)
            .unwrap();
    }
    assert!(public.is_empty());
}

#[tokio::test]
async fn software_keys_sign_inside_authority_and_never_prepare_as_http_credentials() {
    let fixture = common::init_test_vault();
    let (h, join) = common::spawn(&fixture.state_dir);
    assert!(matches!(
        h.ssh_generate(
            CredentialLabel::new("locked").unwrap(),
            SshKeyMode::Ed25519Software,
            common::password_proof(),
            None
        )
        .await,
        Err(AuthorityError::Locked)
    ));
    h.unlock(common::password_proof()).await.unwrap();
    for kind in [
        CredentialKind::SshEd25519,
        CredentialKind::SshP256,
        CredentialKind::SshSecureEnclaveP256,
    ] {
        assert!(matches!(
            h.credential_add(
                CredentialLabel::new("forged-type").unwrap(),
                kind,
                rekey_vault::secret::SecretInput::from_slice(b"synthetic forged SSH payload"),
                common::password_proof()
            )
            .await,
            Err(AuthorityError::CredentialSourceUnavailable)
        ));
    }
    assert!(h.credential_list().await.unwrap().is_empty());
    // The verified host digest and use reach only ssh.sign, in a fixed grammar.
    for (label, mode, kind, purpose, host, reason) in [
        (
            "synthetic-ed",
            SshKeyMode::Ed25519Software,
            CredentialKind::SshEd25519,
            SshSignPurpose::Auth,
            Some([5; 32]),
            "ssh-sign;use=auth;host_key=SHA256:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
        ),
        (
            "synthetic-p256",
            SshKeyMode::P256Software,
            CredentialKind::SshP256,
            SshSignPurpose::Git,
            None,
            "ssh-sign;use=git;host_key=none",
        ),
    ] {
        let identity = h
            .ssh_generate(
                CredentialLabel::new(label).unwrap(),
                mode,
                common::password_proof(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(identity.credential.kind, kind);
        assert!(matches!(
            h.prepare_credential(identity.credential.id).await,
            Err(AuthorityError::CredentialSourceUnavailable)
        ));
        assert!(matches!(
            h.prepare_execution_credential(
                identity.credential.id,
                RequestId::new_random(),
                rekey_domain::ids::ActionId::new_random(),
                1,
                Instant::now() + Duration::from_secs(5)
            )
            .await,
            Err(AuthorityError::CredentialSourceUnavailable)
        ));
        assert!(matches!(
            h.credential_rotate_typed_before(
                identity.credential.id,
                kind,
                Some(1),
                rekey_vault::secret::SecretInput::from_slice(b"synthetic forged replacement"),
                common::password_proof(),
                None
            )
            .await,
            Err(AuthorityError::CredentialSourceUnavailable)
        ));
        let draft = started(identity.credential.id);
        let signature = h
            .ssh_sign(
                identity.credential.id,
                identity.public_key.clone(),
                b"synthetic sign input".to_vec(),
                SshSignStart {
                    draft: draft.clone(),
                    purpose,
                    host_key_sha256: host,
                },
                Vec::new(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        verify(&identity.public_key, &signature, b"synthetic sign input");
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&fixture.state_dir)).unwrap();
        let mut query = db
            .prepare("SELECT event_type, reason_code FROM audit_events WHERE request_id=?1 ORDER BY sequence")
            .unwrap();
        let events: Vec<(String, String)> = query
            .query_map([draft.request_id.unwrap().as_bytes().as_slice()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            events,
            vec![
                ("execution.started".to_owned(), "ssh-sign".to_owned()),
                ("ssh.sign".to_owned(), reason.to_owned()),
                ("execution.finished".to_owned(), "ssh-sign".to_owned()),
            ]
        );
        let wrong = h
            .ssh_sign(
                identity.credential.id,
                b"different public key".to_vec(),
                b"synthetic sign input".to_vec(),
                start(started(identity.credential.id)),
                Vec::new(),
                Instant::now() + Duration::from_secs(5),
            )
            .await;
        assert!(matches!(wrong, Err(AuthorityError::AuthenticationFailed)));
    }
    h.shutdown(Some(common::password_proof())).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn terminal_audit_failure_withholds_signature_and_faults_worker() {
    let fixture = common::init_test_vault();
    let (h, join) = common::spawn(&fixture.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let identity = h
        .ssh_generate(
            CredentialLabel::new("synthetic-ed").unwrap(),
            SshKeyMode::Ed25519Software,
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&fixture.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.finished' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END").unwrap();
    let result = h
        .ssh_sign(
            identity.credential.id,
            identity.public_key,
            b"synthetic input".to_vec(),
            start(started(identity.credential.id)),
            Vec::new(),
            Instant::now() + Duration::from_secs(5),
        )
        .await;
    assert!(matches!(
        result,
        Err(AuthorityError::AuditCommitFailed | AuthorityError::StorageUnavailable(_))
    ));
    assert_eq!(h.status().await.unwrap().state, "faulted");
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='execution.started'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM audit_events WHERE event_type='execution.finished'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    h.shutdown(Some(common::password_proof())).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn expired_or_unproven_generate_creates_no_credential() {
    let fixture = common::init_test_vault();
    let (h, join) = common::spawn(&fixture.state_dir);
    h.unlock(common::password_proof()).await.unwrap();
    let result = h
        .ssh_generate(
            CredentialLabel::new("expired").unwrap(),
            SshKeyMode::Ed25519Software,
            common::password_proof(),
            Some(Instant::now() - Duration::from_secs(1)),
        )
        .await;
    assert!(result.is_err());
    assert!(h.credential_list().await.unwrap().is_empty());
    h.shutdown(Some(common::password_proof())).await.unwrap();
    join.join().unwrap();
}
