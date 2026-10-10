//! Real synthetic CSR possession, leaf-purpose and Worker authorization contracts.
mod common;
use rcgen_signing::PublicKeyData;
use rcgen_signing::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{CredentialId, RequestId};
use rekey_domain::ipc::{
    PkiCertificateResponse, PkiIssueClientCsrMeta, PkiRevocationResponse, PkiRevokeCertificateMeta,
};
use rekey_vault::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::secret::SecretInput;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn root(key: &KeyPair, expires: Option<Duration>) -> Zeroizing<String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(ttl) = expires {
        let now = x509_parser::time::ASN1Time::now().to_datetime();
        params.not_before = now - Duration::from_secs(30);
        params.not_after = now + ttl;
    }
    Zeroizing::new(format!(
        "{}{}",
        key.serialize_pem(),
        params.self_signed(key).unwrap().pem()
    ))
}
fn client() -> CertificateParams {
    let mut params = CertificateParams::new(vec!["client.test".into()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "synthetic-client");
    params
}
async fn add(handle: &AuthorityHandle, label: &str, material: &[u8]) -> CredentialId {
    handle
        .credential_add(
            CredentialLabel::new(label).unwrap(),
            CredentialKind::PkiCaSigner,
            SecretInput::from_slice(material),
            common::password_proof(),
        )
        .await
        .unwrap()
        .id
}
async fn issue(
    handle: &AuthorityHandle,
    id: CredentialId,
    csr: &[u8],
) -> Result<PkiCertificateResponse, AuthorityError> {
    handle
        .pki_issue_client_csr_before(
            PkiIssueClientCsrMeta {
                credential_id: id,
                expected_version: 1,
            },
            SecretInput::from_slice(csr),
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
}
async fn revoke(
    handle: &AuthorityHandle,
    serial: &str,
) -> Result<PkiRevocationResponse, AuthorityError> {
    handle
        .pki_revoke_certificate_before(
            PkiRevokeCertificateMeta {
                serial_hex: serial.into(),
            },
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
}
async fn crl(
    handle: &AuthorityHandle,
    id: CredentialId,
    version: u64,
) -> Result<(rekey_domain::ipc::PkiCrlResponse, Vec<u8>), AuthorityError> {
    handle
        .pki_generate_crl_before(
            rekey_domain::ipc::PkiGenerateCrlMeta {
                credential_id: id,
                version,
            },
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
}
fn persisted_crls(state: &std::path::Path) -> Vec<Vec<rusqlite::types::Value>> {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    let mut query = db
        .prepare("SELECT * FROM pki_crls ORDER BY number")
        .unwrap();
    query
        .query_map([], |r| (0..10).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn generation(state: &std::path::Path) -> u64 {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT generation FROM vault_header", [], |r| r.get(0))
        .unwrap();
    u64::from_be_bytes(bytes.try_into().unwrap())
}

fn audit_count(state: &std::path::Path) -> i64 {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    db.query_row(
        "SELECT count(*) FROM audit_events WHERE event_type LIKE 'pki.certificate.%'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn leaf_preserves_csr_key_and_fixed_purpose_across_ca_algorithms() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let client_key = KeyPair::generate().unwrap();
    let csr = client()
        .serialize_request(&client_key)
        .unwrap()
        .pem()
        .unwrap();
    for (index, algorithm) in [
        &rcgen_signing::PKCS_ECDSA_P256_SHA256,
        &rcgen_signing::PKCS_ECDSA_P384_SHA384,
        &rcgen_signing::PKCS_ED25519,
        &rcgen_signing::PKCS_RSA_SHA256,
    ]
    .iter()
    .enumerate()
    {
        let ca_key = KeyPair::generate_for(algorithm).unwrap();
        let ca = root(&ca_key, None);
        let id = add(&handle, &format!("issuer-{index}"), ca.as_bytes()).await;
        let first = issue(&handle, id, csr.as_bytes()).await.unwrap();
        let second = issue(&handle, id, csr.as_bytes()).await.unwrap();
        assert_ne!(first.serial_hex, second.serial_hex);
        assert_eq!(first.issuer_version, 1);
        let (_, pem) = x509_parser::pem::parse_x509_pem(first.certificate_pem.as_bytes()).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
        let ca_cert = ca.split("-----BEGIN CERTIFICATE-----").nth(1).unwrap();
        let ca_cert = format!("-----BEGIN CERTIFICATE-----{ca_cert}");
        let (_, ca_pem) = x509_parser::pem::parse_x509_pem(ca_cert.as_bytes()).unwrap();
        let (_, issuer) = x509_parser::parse_x509_certificate(&ca_pem.contents).unwrap();
        leaf.verify_signature(Some(issuer.public_key())).unwrap();
        assert_eq!(leaf.public_key().raw, client_key.subject_public_key_info());
        assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
        assert_eq!(leaf.key_usage().unwrap().unwrap().value.flags, 1);
        let eku = leaf.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.client_auth);
        assert!(!eku.value.server_auth);
        assert_eq!(
            leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
            3600
        );
        assert_eq!(
            leaf.subject_alternative_name()
                .unwrap()
                .unwrap()
                .value
                .general_names
                .len(),
            1
        );
    }
    assert_eq!(audit_count(&vault.state_dir), 16);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn bad_possession_ca_escalation_subject_san_and_extensions_never_start_issuance() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let key = KeyPair::generate().unwrap();
    let mut cases = Vec::new();
    let valid = client().serialize_request(&key).unwrap();
    let mut der = valid.der().to_vec();
    *der.last_mut().unwrap() ^= 1;
    // The PEM encoder is only a synthetic fixture; no handwritten CSR ASN.1.
    cases.push(format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        data_encoding::BASE64.encode(&der)
    ));
    cases.push(format!("{}{}", valid.pem().unwrap(), valid.pem().unwrap()));
    cases.push(format!("prefix{}", valid.pem().unwrap()));
    let mut params = client();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cases.push(params.serialize_request(&key).unwrap().pem().unwrap());
    let mut params = client();
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    cases.push(params.serialize_request(&key).unwrap().pem().unwrap());
    let mut params = client();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cases.push(params.serialize_request(&key).unwrap().pem().unwrap());
    let mut params = client();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "unapproved-org");
    cases.push(params.serialize_request(&key).unwrap().pem().unwrap());
    for names in [
        vec!["*.test".into()],
        vec!["same.test".into(), "SAME.test".into()],
        vec!["127.0.0.1".into()],
        vec!["-bad.test".into()],
    ] {
        let mut params = client();
        params.subject_alt_names = CertificateParams::new(names).unwrap().subject_alt_names;
        cases.push(params.serialize_request(&key).unwrap().pem().unwrap());
    }
    let mut params = client();
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]));
    cases.push(params.serialize_request(&key).unwrap().pem().unwrap());
    for csr in cases {
        assert!(matches!(
            issue(&handle, id, csr.as_bytes()).await,
            Err(AuthorityError::Domain(_))
        ));
    }
    assert_eq!(audit_count(&vault.state_dir), 0);
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn proof_version_deadline_revocation_and_ca_lifetime_are_enforced() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(
        &KeyPair::generate().unwrap(),
        Some(Duration::from_secs(1800)),
    );
    let id = add(&handle, "short-lived", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    assert!(matches!(
        issue(&handle, id, csr.as_bytes()).await,
        Err(AuthorityError::Domain(_))
    ));
    assert_eq!(audit_count(&vault.state_dir), 2); // Started + failed; no shorter certificate silently issued.
    let failed = persisted_certificates(&vault.state_dir);
    let rusqlite::types::Value::Blob(serial) = &failed[0][0] else {
        panic!("serial")
    };
    assert_eq!(
        revoke(&handle, &data_encoding::HEXLOWER.encode(serial))
            .await
            .unwrap_err()
            .code(),
        "INVALID_INPUT"
    );
    assert_eq!(persisted_certificates(&vault.state_dir), failed);
    for (version, proof, deadline, code) in [
        (
            1,
            rekey_vault::command::UnlockProof::Password(SecretInput::from_slice(b"wrong")),
            Instant::now() + Duration::from_secs(10),
            "INVALID_UNLOCK_CREDENTIAL",
        ),
        (
            2,
            common::password_proof(),
            Instant::now() + Duration::from_secs(10),
            "INVALID_INPUT",
        ),
        (
            1,
            common::password_proof(),
            Instant::now() - Duration::from_secs(1),
            "AUTHORITY_BUSY",
        ),
    ] {
        let error = handle
            .pki_issue_client_csr_before(
                PkiIssueClientCsrMeta {
                    credential_id: id,
                    expected_version: version,
                },
                SecretInput::from_slice(csr.as_bytes()),
                proof,
                RequestId::new_random(),
                deadline,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), code);
    }
    assert_eq!(audit_count(&vault.state_dir), 2);
    handle
        .credential_revoke(id, common::password_proof())
        .await
        .unwrap();
    assert!(matches!(
        issue(&handle, id, csr.as_bytes()).await,
        Err(AuthorityError::CredentialRevoked)
    ));
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn audit_failure_before_key_use_or_before_return_faults_the_worker() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for event in ["pki.certificate.started", "pki.certificate.finished"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        let csr = client()
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER deny_pki BEFORE INSERT ON audit_events WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;")).unwrap();
        assert!(matches!(
            issue(&handle, id, csr.as_bytes()).await,
            Err(AuthorityError::AuditCommitFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert_eq!(
            audit_count(&vault.state_dir),
            i64::from(event.ends_with("finished"))
        );
        drop(db);
        drop(handle);
        join.join().unwrap();
    }
}

#[tokio::test]
async fn deadline_during_terminal_audit_suppresses_certificate_return_after_commit() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("CREATE TABLE synthetic_audit_delay(n INTEGER); WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<500) INSERT INTO synthetic_audit_delay SELECT n FROM t;
        CREATE TRIGGER delay_pki_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.finished' BEGIN SELECT count(*) FROM synthetic_audit_delay a, synthetic_audit_delay b, synthetic_audit_delay c; END;").unwrap();
    let result = handle
        .pki_issue_client_csr_before(
            PkiIssueClientCsrMeta {
                credential_id: id,
                expected_version: 1,
            },
            SecretInput::from_slice(csr.as_bytes()),
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_millis(100),
        )
        .await;
    assert!(matches!(result, Err(AuthorityError::AuthorityBusy)));
    assert_eq!(audit_count(&vault.state_dir), 2);
    let finished: String = db
        .query_row(
            "SELECT outcome FROM audit_events WHERE event_type='pki.certificate.finished'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(finished, "success"); // Generated and committed, but no certificate returned past deadline.
    let issued: i64 = db
        .query_row(
            "SELECT count(*) FROM pki_certificates WHERE state=1 AND certificate_der IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(issued, 1); // Persist generation even though delivery is suppressed.
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    drop(db);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn issuance_error_keeps_its_contract_when_terminal_audit_exceeds_deadline() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(
        &KeyPair::generate().unwrap(),
        Some(Duration::from_secs(1800)),
    );
    let id = add(&handle, "short-issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("CREATE TABLE synthetic_audit_delay(n INTEGER); WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<500) INSERT INTO synthetic_audit_delay SELECT n FROM t;
      CREATE TRIGGER delay_pki_error BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.finished' BEGIN SELECT count(*) FROM synthetic_audit_delay a, synthetic_audit_delay b, synthetic_audit_delay c; END;").unwrap();
    let deadline = Instant::now() + Duration::from_millis(100);
    let error = handle
        .pki_issue_client_csr_before(
            PkiIssueClientCsrMeta {
                credential_id: id,
                expected_version: 1,
            },
            SecretInput::from_slice(csr.as_bytes()),
            common::password_proof(),
            RequestId::new_random(),
            deadline,
        )
        .await
        .unwrap_err();
    assert!(Instant::now() > deadline);
    assert_eq!(error.code(), "INVALID_INPUT");
    assert_eq!(audit_count(&vault.state_dir), 2);
    let finished: String = db
        .query_row(
            "SELECT outcome FROM audit_events WHERE event_type='pki.certificate.finished'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(finished, "failure");
    let failed: i64 = db
        .query_row(
            "SELECT count(*) FROM pki_certificates WHERE state=2 AND certificate_der IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(failed, 1);
    drop(db);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

fn persisted_certificates(state: &std::path::Path) -> Vec<Vec<rusqlite::types::Value>> {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    let mut query = db.prepare("SELECT serial,credential_id,credential_version,request_id,request_digest,created_at_ms,state,finished_at_ms,certificate_der,issuer_der,revoked_at_ms FROM pki_certificates ORDER BY serial").unwrap();
    query
        .query_map([], |r| (0..11).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[tokio::test]
async fn issued_records_survive_restart_vrk_rotation_and_backup_restore() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let issued = issue(&handle, id, csr.as_bytes()).await.unwrap();
    let revoked = revoke(&handle, &issued.serial_hex).await.unwrap();
    let (first_crl, _) = crl(&handle, id, 1).await.unwrap();
    let before_crls = persisted_crls(&vault.state_dir);
    let before = persisted_certificates(&vault.state_dir);
    assert_eq!(
        before[0][10],
        rusqlite::types::Value::Integer(revoked.revoked_at_ms)
    );
    assert_eq!(before.len(), 1);
    assert_eq!(
        before[0][0],
        rusqlite::types::Value::Blob(
            data_encoding::HEXLOWER
                .decode(issued.serial_hex.as_bytes())
                .unwrap()
        )
    );
    let (_, pem) = x509_parser::pem::parse_x509_pem(issued.certificate_pem.as_bytes()).unwrap();
    assert_eq!(before[0][8], rusqlite::types::Value::Blob(pem.contents));
    assert_eq!(before[0][6], rusqlite::types::Value::Integer(1));
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    let collision = db
        .execute(
            "INSERT INTO pki_certificates SELECT * FROM pki_certificates",
            [],
        )
        .unwrap_err();
    assert!(
        matches!(collision, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation)
    );
    drop(db);
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert_eq!(persisted_crls(&vault.state_dir), before_crls);
    // A regular credential mutation also increments generation, preserving the set.
    handle
        .credential_add(
            CredentialLabel::new("other").unwrap(),
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"synthetic-token"),
            common::password_proof(),
        )
        .await
        .unwrap();
    assert_eq!(
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap(),
        2
    );
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert_eq!(persisted_crls(&vault.state_dir), before_crls);
    handle.lock("pki-vrk-test").await.unwrap();
    handle
        .rotate_vrk_before(
            common::password_input(),
            SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
            None,
        )
        .await
        .unwrap();
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert_eq!(persisted_crls(&vault.state_dir), before_crls);
    let backup = vault.dir.path().join("certificates.backup");
    let receipt = handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    assert_eq!(receipt.format_version, rekey_vault::model::FORMAT_VERSION);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert_eq!(persisted_crls(&vault.state_dir), before_crls);
    issue(&handle, id, csr.as_bytes()).await.unwrap();
    assert_eq!(persisted_certificates(&vault.state_dir).len(), 2);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let restored = vault.dir.path().join("restored");
    let context = rekey_vault::bootstrap::inspect_restore(
        &backup,
        &restored,
        rekey_vault::bootstrap::RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    rekey_vault::bootstrap::restore_vault(
        &backup,
        &restored,
        rekey_vault::bootstrap::RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
        context,
    )
    .unwrap();
    let (handle, join) = common::spawn(&restored);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(persisted_certificates(&restored), before);
    assert_eq!(persisted_crls(&restored), before_crls);
    assert!(crl(&handle, id, 1).await.unwrap().0.number > first_crl.number);
    issue(&handle, id, csr.as_bytes()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn certificate_deletion_modification_and_old_set_replay_fail_with_current_header() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for attack in ["delete", "modify", "replay"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        let csr = client()
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        issue(&handle, id, csr.as_bytes()).await.unwrap();
        let old = persisted_certificates(&vault.state_dir);
        issue(&handle, id, csr.as_bytes()).await.unwrap();
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        match attack {
            "delete" => {
                db.execute("DELETE FROM pki_certificates", []).unwrap();
            }
            "modify" => {
                db.execute(
                    "UPDATE pki_certificates SET request_digest=zeroblob(32)",
                    [],
                )
                .unwrap();
            }
            "replay" => {
                db.execute("DELETE FROM pki_certificates", []).unwrap();
                for row in old {
                    db.execute("INSERT INTO pki_certificates(serial,credential_id,credential_version,request_id,request_digest,created_at_ms,state,finished_at_ms,certificate_der,issuer_der,revoked_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", rusqlite::params_from_iter(row)).unwrap();
                }
            }
            _ => unreachable!(),
        }
        drop(db);
        let (handle, join) = common::spawn(&vault.state_dir);
        let error = handle.unlock(common::password_proof()).await.unwrap_err();
        assert!(
            matches!(error, AuthorityError::StorageIntegrityFailed),
            "{attack}: {error:?}"
        );
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn cancelled_receiver_keeps_generated_certificate_terminal() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.busy_timeout(Duration::ZERO).unwrap();
    db.execute_batch("CREATE TABLE synthetic_cancel_delay(n INTEGER); WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<500) INSERT INTO synthetic_cancel_delay SELECT n FROM t; CREATE TRIGGER delay_cancel_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.finished' BEGIN SELECT count(*) FROM synthetic_cancel_delay a, synthetic_cancel_delay b, synthetic_cancel_delay c; END;").unwrap();
    let h = handle.clone();
    let task = tokio::spawn(async move { issue(&h, id, csr.as_bytes()).await });
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM pki_certificates WHERE state=0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if count == 1 {
            // Reserved is already committed. A new write lock now belongs to
            // terminal persistence, after the signing closure completed.
            match db.execute_batch("BEGIN IMMEDIATE; ROLLBACK;") {
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::DatabaseBusy =>
                {
                    break;
                }
                Ok(()) => {}
                Err(e) => panic!("unexpected terminal lock probe error: {e:?}"),
            }
        }
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // The Actor completes the ongoing transaction before this queued status.
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    let rows = persisted_certificates(&vault.state_dir);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][6], rusqlite::types::Value::Integer(1));
    assert!(matches!(rows[0][8], rusqlite::types::Value::Blob(_)));
    drop(db);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
#[ignore = "explicit owned crash-child process used by reservation_survives_killed_worker_process"]
async fn pki_reservation_crash_child() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let state = std::path::PathBuf::from(std::env::var_os("REKEY_TEST_PKI_STATE").unwrap());
    let (handle, _join) = common::spawn(&state);
    handle.unlock(common::password_proof()).await.unwrap();
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&state)).unwrap();
    let id: Vec<u8> = db
        .query_row(
            "SELECT credential_id FROM credentials WHERE kind='pki-ca-signer'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let id = CredentialId::from_bytes(id.try_into().unwrap()).unwrap();
    drop(db);
    std::fs::write(state.join("synthetic-child-ready"), b"ready").unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while !state.join("synthetic-child-go").exists() {
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let _ = issue(&handle, id, csr.as_bytes()).await;
    panic!("crash child must be killed and reaped by its parent");
}

struct OwnedCrashChild(std::process::Child);

#[tokio::test]
async fn unauthorized_trigger_changes_are_not_authenticated_or_delivered() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for route in ["audit", "ledger", "header"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        let csr = client()
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        issue(&handle, id, csr.as_bytes()).await.unwrap();
        let original = persisted_certificates(&vault.state_dir);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        // Introduce the attack after open/unlock: startup layout admission is
        // insufficient to protect an already running mutation.
        let attack = match route {
            "audit" => {
                "CREATE TRIGGER erase_prior_certificate BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.started' BEGIN DELETE FROM pki_certificates WHERE state=1; END;"
            }
            "ledger" => {
                "CREATE TRIGGER erase_prior_certificate AFTER INSERT ON pki_certificates BEGIN DELETE FROM pki_certificates WHERE state=1; END;"
            }
            "header" => {
                "CREATE TRIGGER erase_prior_certificate AFTER UPDATE ON vault_header BEGIN DELETE FROM pki_certificates WHERE state=1; END;"
            }
            _ => unreachable!(),
        };
        db.execute_batch(attack).unwrap();
        let result = issue(&handle, id, csr.as_bytes()).await;
        assert!(
            matches!(result, Err(AuthorityError::StorageIntegrityFailed)),
            "route={route}, result={:?}",
            result.as_ref().map(|r| &r.serial_hex)
        );
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert_eq!(persisted_certificates(&vault.state_dir), original);
        db.execute_batch("DROP TRIGGER erase_prior_certificate")
            .unwrap();
        drop(db);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        assert_eq!(persisted_certificates(&vault.state_dir), original);
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

impl Drop for OwnedCrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn older_certificate_database_is_rejected_by_the_newer_external_anchor() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    issue(&handle, id, csr.as_bytes()).await.unwrap();
    let old = vault.dir.path().join("old-certificate-snapshot");
    handle
        .backup(old.clone(), common::password_proof())
        .await
        .unwrap();
    issue(&handle, id, csr.as_bytes()).await.unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    // Replace only the synthetic DB, retaining the newer generation anchor.
    let db = rekey_vault::paths::vault_db(&vault.state_dir);
    for suffix in ["-wal", "-shm"] {
        let path = std::path::PathBuf::from(format!("{}{suffix}", db.display()));
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("synthetic sqlite sidecar cleanup: {e}"),
        }
    }
    std::fs::copy(old, db).unwrap();
    let (handle, join) = common::spawn(&vault.state_dir);
    assert!(matches!(
        handle.unlock(common::password_proof()).await,
        Err(AuthorityError::RollbackSuspected)
    ));
    drop(handle);
    join.join().unwrap();
}

#[tokio::test]
async fn reservation_survives_killed_worker_process() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let mut child = OwnedCrashChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pki_reservation_crash_child",
                "--nocapture",
            ])
            .env("REKEY_TEST_PKI_STATE", &vault.state_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(10);
    while !vault.state_dir.join("synthetic-child-ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before ready"
        );
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER delay_crash_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.finished' BEGIN WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<1500) SELECT count(*) FROM t a,t b,t c; END;").unwrap();
    std::fs::write(vault.state_dir.join("synthetic-child-go"), b"go").unwrap();
    loop {
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM pki_certificates WHERE state=0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if count == 1 {
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before reservation"
        );
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    child.0.kill().unwrap();
    let result = child.0.wait().unwrap();
    assert!(!result.success());
    db.execute_batch("DROP TRIGGER delay_crash_terminal")
        .unwrap();
    drop(db);
    for n in ["synthetic-child-ready", "synthetic-child-go"] {
        std::fs::remove_file(vault.state_dir.join(n)).unwrap();
    }
    let pending = persisted_certificates(&vault.state_dir);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0][6], rusqlite::types::Value::Integer(0));
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(persisted_certificates(&vault.state_dir), pending);
    let rusqlite::types::Value::Blob(serial) = &pending[0][0] else {
        panic!("serial")
    };
    assert_eq!(
        revoke(&handle, &data_encoding::HEXLOWER.encode(serial))
            .await
            .unwrap_err()
            .code(),
        "INVALID_INPUT"
    );
    assert_eq!(persisted_certificates(&vault.state_dir), pending);
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let issued = issue(&handle, id, csr.as_bytes()).await.unwrap();
    assert_ne!(
        pending[0][0],
        rusqlite::types::Value::Blob(
            data_encoding::HEXLOWER
                .decode(issued.serial_hex.as_bytes())
                .unwrap()
        )
    );
    assert_eq!(persisted_certificates(&vault.state_dir).len(), 2);
    assert_eq!(
        crl(&handle, id, 1).await.unwrap_err().code(),
        "INVALID_INPUT"
    );
    assert!(persisted_crls(&vault.state_dir).is_empty());
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn certificate_revocation_is_targeted_repeatable_and_independent_of_current_ca() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let first = issue(&handle, id, csr.as_bytes()).await.unwrap();
    let second = issue(&handle, id, csr.as_bytes()).await.unwrap();
    let before = persisted_certificates(&vault.state_dir);
    let ca2 = root(&KeyPair::generate().unwrap(), None);
    handle
        .credential_rotate_typed_before(
            id,
            CredentialKind::PkiCaSigner,
            Some(1),
            SecretInput::from_slice(ca2.as_bytes()),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    handle
        .credential_revoke(id, common::password_proof())
        .await
        .unwrap();
    let old_generation = generation(&vault.state_dir);
    let old_audit = audit_count(&vault.state_dir);
    let revoked = revoke(&handle, &first.serial_hex).await.unwrap();
    assert_eq!(revoked.serial_hex, first.serial_hex);
    assert!(revoked.revoked_at_ms >= 0);
    assert_eq!(generation(&vault.state_dir), old_generation + 1);
    assert_eq!(audit_count(&vault.state_dir), old_audit + 1);
    let after = persisted_certificates(&vault.state_dir);
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(&old[..10], &new[..10]);
        let rusqlite::types::Value::Blob(serial) = &new[0] else {
            panic!("serial")
        };
        assert_eq!(
            new[10],
            if data_encoding::HEXLOWER.encode(serial) == first.serial_hex {
                rusqlite::types::Value::Integer(revoked.revoked_at_ms)
            } else {
                rusqlite::types::Value::Null
            }
        );
    }
    assert_ne!(first.serial_hex, second.serial_hex);
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    // A repeated success must not rewrite any certificate row.
    db.execute_batch("CREATE TRIGGER deny_certificate_rewrite BEFORE UPDATE ON pki_certificates BEGIN SELECT RAISE(ABORT,'unexpected rewrite'); END;").unwrap();
    let repeated = revoke(&handle, &first.serial_hex).await.unwrap();
    assert_eq!(repeated.revoked_at_ms, revoked.revoked_at_ms);
    assert_eq!(persisted_certificates(&vault.state_dir), after);
    assert_eq!(generation(&vault.state_dir), old_generation + 2);
    assert_eq!(audit_count(&vault.state_dir), old_audit + 2);
    db.execute_batch("DROP TRIGGER deny_certificate_rewrite")
        .unwrap();
    drop(db);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn certificate_revocation_rejects_invalid_proof_serial_and_expired_requests() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let issued = issue(&handle, id, csr.as_bytes()).await.unwrap();
    let before = persisted_certificates(&vault.state_dir);
    let old_gen = generation(&vault.state_dir);
    let old_audit = audit_count(&vault.state_dir);
    for serial in [
        "invalid",
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "00000000000000000000000000000001",
    ] {
        assert_eq!(
            revoke(&handle, serial).await.unwrap_err().code(),
            "INVALID_INPUT"
        );
    }
    let expired = handle
        .pki_revoke_certificate_before(
            PkiRevokeCertificateMeta {
                serial_hex: issued.serial_hex.clone(),
            },
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() - Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert_eq!(expired.code(), "AUTHORITY_BUSY");
    let wrong = handle
        .pki_revoke_certificate_before(
            PkiRevokeCertificateMeta {
                serial_hex: issued.serial_hex,
            },
            rekey_vault::command::UnlockProof::Password(SecretInput::from_slice(b"wrong")),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), "INVALID_UNLOCK_CREDENTIAL");
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert_eq!(generation(&vault.state_dir), old_gen);
    assert_eq!(audit_count(&vault.state_dir), old_audit);
    tokio::time::sleep(Duration::from_millis(25)).await;
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn certificate_revocation_rejects_audit_ledger_and_header_trigger_changes() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for route in [
        "audit-deny",
        "audit-extra",
        "ledger-extra",
        "header-extra",
        "repeat-extra",
    ] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        let csr = client()
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        let issued = issue(&handle, id, csr.as_bytes()).await.unwrap();
        issue(&handle, id, csr.as_bytes()).await.unwrap();
        if route == "repeat-extra" {
            revoke(&handle, &issued.serial_hex).await.unwrap();
        }
        let before = persisted_certificates(&vault.state_dir);
        let old_gen = generation(&vault.state_dir);
        let old_audit = audit_count(&vault.state_dir);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        let attack = match route {
            "audit-deny" => {
                "CREATE TRIGGER attack BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.revoked' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;"
            }
            "audit-extra" | "repeat-extra" => {
                "CREATE TRIGGER attack BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.revoked' BEGIN UPDATE pki_certificates SET certificate_der=x'01'; END;"
            }
            "ledger-extra" => {
                "CREATE TRIGGER attack AFTER UPDATE OF revoked_at_ms ON pki_certificates BEGIN UPDATE pki_certificates SET certificate_der=x'01' WHERE serial!=NEW.serial; END;"
            }
            "header-extra" => {
                "CREATE TRIGGER attack AFTER UPDATE ON vault_header BEGIN UPDATE pki_certificates SET revoked_at_ms=NULL; END;"
            }
            _ => unreachable!(),
        };
        db.execute_batch(attack).unwrap();
        let error = revoke(&handle, &issued.serial_hex).await.unwrap_err();
        assert_eq!(
            error.code(),
            if route == "audit-deny" {
                "AUDIT_COMMIT_FAILED"
            } else {
                "STORAGE_INTEGRITY_FAILED"
            },
            "{route}"
        );
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert_eq!(persisted_certificates(&vault.state_dir), before);
        assert_eq!(generation(&vault.state_dir), old_gen);
        assert_eq!(audit_count(&vault.state_dir), old_audit);
        db.execute_batch("DROP TRIGGER attack").unwrap();
        drop(db);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        assert_eq!(persisted_certificates(&vault.state_dir), before);
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn certificate_revocation_deadline_during_transaction_rolls_back() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let issued = issue(&handle, id, csr.as_bytes()).await.unwrap();
    let before = persisted_certificates(&vault.state_dir);
    let old_gen = generation(&vault.state_dir);
    let old_audit = audit_count(&vault.state_dir);
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("CREATE TABLE synthetic_revoke_delay(n INTEGER); WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<250) INSERT INTO synthetic_revoke_delay SELECT n FROM t; CREATE TRIGGER delay_revoke BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.revoked' BEGIN SELECT count(*) FROM synthetic_revoke_delay a, synthetic_revoke_delay b, synthetic_revoke_delay c; END;").unwrap();
    let deadline = Instant::now() + Duration::from_millis(100);
    let error = handle
        .pki_revoke_certificate_before(
            PkiRevokeCertificateMeta {
                serial_hex: issued.serial_hex,
            },
            common::password_proof(),
            RequestId::new_random(),
            deadline,
        )
        .await
        .unwrap_err();
    assert!(Instant::now() >= deadline);
    assert_eq!(error.code(), "AUTHORITY_BUSY");
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert_eq!(generation(&vault.state_dir), old_gen);
    assert_eq!(audit_count(&vault.state_dir), old_audit);
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
    db.execute_batch("DROP TRIGGER delay_revoke").unwrap();
    drop(db);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

fn root_with_ski(key: &KeyPair, ski: u8, crl_sign: bool) -> Zeroizing<String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_identifier_method = rcgen_signing::KeyIdMethod::PreSpecified(vec![ski; 20]);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    if crl_sign {
        params.key_usages.push(KeyUsagePurpose::CrlSign);
    }
    Zeroizing::new(format!(
        "{}{}",
        key.serialize_pem(),
        params.self_signed(key).unwrap().pem()
    ))
}

#[tokio::test]
async fn crl_aggregates_equivalent_issuers_and_matches_selected_ski_after_ca_stop() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let key = KeyPair::generate().unwrap();
    let ca1 = root_with_ski(&key, 1, true);
    let ca2 = root_with_ski(&key, 2, true);
    let ca3 = root_with_ski(&KeyPair::generate().unwrap(), 3, true);
    let id1 = add(&handle, "ca-one", ca1.as_bytes()).await;
    let id2 = add(&handle, "ca-two", ca2.as_bytes()).await;
    let id3 = add(&handle, "ca-three", ca3.as_bytes()).await;
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let target = issue(&handle, id1, csr.as_bytes()).await.unwrap();
    let good = issue(&handle, id1, csr.as_bytes()).await.unwrap();
    let equivalent = issue(&handle, id2, csr.as_bytes()).await.unwrap();
    let other = issue(&handle, id3, csr.as_bytes()).await.unwrap();
    for serial in [
        &target.serial_hex,
        &equivalent.serial_hex,
        &other.serial_hex,
    ] {
        revoke(&handle, serial).await.unwrap();
    }
    let (first, _) = crl(&handle, id1, 1).await.unwrap();
    let replacement = root(&KeyPair::generate().unwrap(), None);
    handle
        .credential_rotate_typed_before(
            id1,
            CredentialKind::PkiCaSigner,
            Some(1),
            SecretInput::from_slice(replacement.as_bytes()),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    handle
        .credential_revoke(id1, common::password_proof())
        .await
        .unwrap();
    let before = persisted_certificates(&vault.state_dir);
    for (id, ski) in [(id1, 1), (id2, 2)] {
        let (info, pem) = crl(&handle, id, 1).await.unwrap();
        assert!(info.number > first.number);
        let (_, pem) = x509_parser::pem::parse_x509_pem(&pem).unwrap();
        let (rest, parsed) = x509_parser::parse_x509_crl(&pem.contents).unwrap();
        assert!(rest.is_empty());
        let ca_pem = ca1.split("-----BEGIN CERTIFICATE-----").nth(1).unwrap();
        let (_, ca_pem) = x509_parser::pem::parse_x509_pem(
            format!("-----BEGIN CERTIFICATE-----{ca_pem}").as_bytes(),
        )
        .unwrap();
        let (_, ca) = x509_parser::parse_x509_certificate(&ca_pem.contents).unwrap();
        parsed.verify_signature(ca.public_key()).unwrap();
        assert_eq!(parsed.issuer().as_raw(), ca.subject().as_raw());
        let serials: Vec<_> = parsed
            .iter_revoked_certificates()
            .map(|r| {
                format!(
                    "{:0>32}",
                    data_encoding::HEXLOWER
                        .encode(&r.raw_serial()[r.raw_serial().len().saturating_sub(16)..])
                )
            })
            .collect();
        assert!(serials.contains(&target.serial_hex));
        assert!(serials.contains(&equivalent.serial_hex));
        assert!(!serials.contains(&good.serial_hex));
        assert!(!serials.contains(&other.serial_hex));
        assert_eq!(serials.len(), 2);
        assert_eq!(
            parsed.next_update().unwrap().timestamp() - parsed.last_update().timestamp(),
            3600
        );
        let aki = parsed
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(aki, vec![ski; 20]);
    }
    assert_eq!(persisted_certificates(&vault.state_dir), before);
    assert!(issue(&handle, id1, csr.as_bytes()).await.is_err());
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    assert!(crl(&handle, id2, 1).await.unwrap().0.number > first.number);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn crl_rejects_invalid_proof_deadline_and_ca_without_crl_sign() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root_with_ski(&KeyPair::generate().unwrap(), 4, false);
    let id = add(&handle, "ca", ca.as_bytes()).await;
    let request = rekey_domain::ipc::PkiGenerateCrlMeta {
        credential_id: id,
        version: 1,
    };
    let before = generation(&vault.state_dir);
    assert_eq!(
        handle
            .pki_generate_crl_before(
                request.clone(),
                rekey_vault::command::UnlockProof::Password(SecretInput::from_slice(b"wrong")),
                RequestId::new_random(),
                Instant::now() + Duration::from_secs(10)
            )
            .await
            .unwrap_err()
            .code(),
        "INVALID_UNLOCK_CREDENTIAL"
    );
    assert_eq!(
        handle
            .pki_generate_crl_before(
                request,
                common::password_proof(),
                RequestId::new_random(),
                Instant::now() - Duration::from_secs(1)
            )
            .await
            .unwrap_err()
            .code(),
        "AUTHORITY_BUSY"
    );
    assert_eq!(generation(&vault.state_dir), before);
    assert!(persisted_crls(&vault.state_dir).is_empty());
    assert_eq!(
        crl(&handle, id, 1).await.unwrap_err().code(),
        "INVALID_INPUT"
    );
    assert_eq!(generation(&vault.state_dir), before + 2);
    let rows = persisted_crls(&vault.state_dir);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][6], rusqlite::types::Value::Integer(2));
    assert_eq!(rows[0][8], rusqlite::types::Value::Null);
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn crl_transactions_refuse_cross_table_and_header_trigger_changes() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for (trigger, expected) in [
        (
            "CREATE TRIGGER attack BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.crl.started' BEGIN UPDATE pki_certificates SET certificate_der=x'01'; END;",
            "STORAGE_INTEGRITY_FAILED",
        ),
        (
            "CREATE TRIGGER attack AFTER INSERT ON pki_crls BEGIN UPDATE pki_crls SET snapshot_digest=zeroblob(32); END;",
            "STORAGE_INTEGRITY_FAILED",
        ),
        (
            "CREATE TRIGGER attack AFTER UPDATE ON vault_header BEGIN DELETE FROM pki_crls; END;",
            "STORAGE_INTEGRITY_FAILED",
        ),
        (
            "CREATE TRIGGER attack BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.crl.started' BEGIN SELECT RAISE(ABORT,'denied'); END;",
            "AUDIT_COMMIT_FAILED",
        ),
    ] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        let csr = client()
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        issue(&handle, id, csr.as_bytes()).await.unwrap();
        let before = persisted_certificates(&vault.state_dir);
        let old_gen = generation(&vault.state_dir);
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        db.execute_batch(trigger).unwrap();
        assert_eq!(crl(&handle, id, 1).await.unwrap_err().code(), expected);
        assert_eq!(generation(&vault.state_dir), old_gen);
        assert_eq!(persisted_certificates(&vault.state_dir), before);
        assert!(persisted_crls(&vault.state_dir).is_empty());
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        db.execute_batch("DROP TRIGGER attack").unwrap();
        drop(db);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        crl(&handle, id, 1).await.unwrap();
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn crl_deadline_and_cancel_preserve_generated_terminal_der() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for cancel in [false, true] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        db.busy_timeout(Duration::ZERO).unwrap();
        db.execute_batch("CREATE TABLE synthetic_crl_delay(n INTEGER); WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<500) INSERT INTO synthetic_crl_delay SELECT n FROM t; CREATE TRIGGER delay_crl_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.crl.finished' BEGIN SELECT count(*) FROM synthetic_crl_delay a, synthetic_crl_delay b, synthetic_crl_delay c; END;").unwrap();
        let before = generation(&vault.state_dir);
        if cancel {
            let h = handle.clone();
            let task = tokio::spawn(async move { crl(&h, id, 1).await });
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let reserved: i64 = db
                    .query_row("SELECT count(*) FROM pki_crls WHERE state=0", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                if reserved == 1 {
                    match db.execute_batch("BEGIN IMMEDIATE; ROLLBACK;") {
                        Err(rusqlite::Error::SqliteFailure(e, _))
                            if e.code == rusqlite::ErrorCode::DatabaseBusy =>
                        {
                            break;
                        }
                        Ok(()) => {}
                        Err(e) => panic!("terminal lock probe: {e:?}"),
                    }
                }
                assert!(Instant::now() < end);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(matches!(
                handle
                    .pki_generate_crl_before(
                        rekey_domain::ipc::PkiGenerateCrlMeta {
                            credential_id: id,
                            version: 1
                        },
                        common::password_proof(),
                        RequestId::new_random(),
                        Instant::now() + Duration::from_millis(100)
                    )
                    .await,
                Err(AuthorityError::AuthorityBusy)
            ));
        }
        assert_eq!(handle.status().await.unwrap().state, "unlocked");
        let records = persisted_crls(&vault.state_dir);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][6], rusqlite::types::Value::Integer(1));
        assert!(matches!(records[0][8], rusqlite::types::Value::Blob(_)));
        assert_eq!(generation(&vault.state_dir), before + 2);
        let outcome: String = db
            .query_row(
                "SELECT outcome FROM audit_events WHERE event_type='pki.crl.finished'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "success");
        db.execute_batch("DROP TRIGGER delay_crl_terminal").unwrap();
        drop(db);
        assert!(crl(&handle, id, 1).await.unwrap().0.number > before + 1);
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn crl_deletion_modification_and_old_set_replay_are_rejected_on_unlock() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for attack in ["delete", "modify", "replay"] {
        let vault = common::init_test_vault();
        let (handle, join) = common::spawn(&vault.state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
        let ca = root(&KeyPair::generate().unwrap(), None);
        let id = add(&handle, "issuer", ca.as_bytes()).await;
        crl(&handle, id, 1).await.unwrap();
        let old = persisted_crls(&vault.state_dir);
        crl(&handle, id, 1).await.unwrap();
        handle
            .shutdown(Some(common::password_proof()))
            .await
            .unwrap();
        join.join().unwrap();
        let db =
            rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
        match attack {
            "delete" => {
                db.execute("DELETE FROM pki_crls", []).unwrap();
            }
            "modify" => {
                db.execute("UPDATE pki_crls SET crl_der=x'01'", []).unwrap();
            }
            "replay" => {
                db.execute("DELETE FROM pki_crls", []).unwrap();
                for row in old {
                    db.execute("INSERT INTO pki_crls(number,credential_id,credential_version,request_id,snapshot_digest,created_at_ms,state,finished_at_ms,crl_der,issuer_der) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",rusqlite::params_from_iter(row)).unwrap();
                }
            }
            _ => unreachable!(),
        };
        drop(db);
        let (handle, join) = common::spawn(&vault.state_dir);
        assert!(matches!(
            handle.unlock(common::password_proof()).await,
            Err(AuthorityError::StorageIntegrityFailed)
        ));
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
    }
}

#[tokio::test]
async fn certificate_mutation_cannot_authenticate_trigger_changes_to_existing_crls() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let ca = root(&KeyPair::generate().unwrap(), None);
    let id = add(&handle, "issuer", ca.as_bytes()).await;
    crl(&handle, id, 1).await.unwrap();
    let before = persisted_crls(&vault.state_dir);
    let old_gen = generation(&vault.state_dir);
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(&vault.state_dir)).unwrap();
    db.execute_batch("CREATE TRIGGER attack BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.started' BEGIN DELETE FROM pki_crls; END;").unwrap();
    let csr = client()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    assert!(matches!(
        issue(&handle, id, csr.as_bytes()).await,
        Err(AuthorityError::StorageIntegrityFailed)
    ));
    assert_eq!(handle.status().await.unwrap().state, "faulted");
    assert_eq!(persisted_crls(&vault.state_dir), before);
    assert_eq!(generation(&vault.state_dir), old_gen);
    assert!(persisted_certificates(&vault.state_dir).is_empty());
    db.execute_batch("DROP TRIGGER attack").unwrap();
    drop(db);
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

static PKI_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
