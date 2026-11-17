//! Unowned PKI reservations: a crash-left reservation was never delivered, so
//! the next unlock from Locked finalizes it inside the generation contract.
mod common;
use std::path::Path;
use std::time::{Duration, Instant};

use rcgen_signing::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{CredentialId, RequestId};
use rekey_domain::ipc::{
    PkiCertificateResponse, PkiCrlResponse, PkiGenerateCrlMeta, PkiIssueClientCsrMeta,
    PkiRevocationResponse, PkiRevokeCertificateMeta,
};
use rekey_vault::AuthorityError;
use rekey_vault::handle::AuthorityHandle;
use rekey_vault::secret::SecretInput;
use rusqlite::types::Value;

static PKI_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const ABANDONED: &str = "abandoned-on-unlock";

fn root() -> zeroize::Zeroizing<String> {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    zeroize::Zeroizing::new(format!(
        "{}{}",
        key.serialize_pem(),
        params.self_signed(&key).unwrap().pem()
    ))
}
fn csr() -> String {
    let mut params = CertificateParams::new(vec!["client.test".into()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "synthetic-client");
    params
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap()
}
async fn add(handle: &AuthorityHandle) -> CredentialId {
    handle
        .credential_add(
            CredentialLabel::new("issuer").unwrap(),
            CredentialKind::PkiCaSigner,
            SecretInput::from_slice(root().as_bytes()),
            common::password_proof(),
        )
        .await
        .unwrap()
        .id
}
async fn issue(
    handle: &AuthorityHandle,
    id: CredentialId,
) -> Result<PkiCertificateResponse, AuthorityError> {
    handle
        .pki_issue_client_csr_before(
            PkiIssueClientCsrMeta {
                credential_id: id,
                expected_version: 1,
            },
            SecretInput::from_slice(csr().as_bytes()),
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(30),
        )
        .await
}
async fn revoke(
    handle: &AuthorityHandle,
    serial_hex: &str,
) -> Result<PkiRevocationResponse, AuthorityError> {
    handle
        .pki_revoke_certificate_before(
            PkiRevokeCertificateMeta {
                serial_hex: serial_hex.into(),
            },
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(30),
        )
        .await
}
async fn crl(
    handle: &AuthorityHandle,
    id: CredentialId,
) -> Result<(PkiCrlResponse, Vec<u8>), AuthorityError> {
    handle
        .pki_generate_crl_before(
            PkiGenerateCrlMeta {
                credential_id: id,
                version: 1,
            },
            common::password_proof(),
            RequestId::new_random(),
            Instant::now() + Duration::from_secs(30),
        )
        .await
}
fn rows(state: &Path, sql: &str, columns: usize) -> Vec<Vec<Value>> {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    let mut query = db.prepare(sql).unwrap();
    query
        .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}
fn certificates(state: &Path) -> Vec<Vec<Value>> {
    rows(
        state,
        "SELECT serial,credential_id,credential_version,request_id,request_digest,created_at_ms,state,finished_at_ms,certificate_der,issuer_der,revoked_at_ms FROM pki_certificates ORDER BY serial",
        11,
    )
}
fn crls(state: &Path) -> Vec<Vec<Value>> {
    rows(state, "SELECT * FROM pki_crls ORDER BY number", 10)
}
/// request_id, credential_id, credential_version, outcome, reason_code.
fn audits(state: &Path, event_type: &str) -> Vec<Vec<Value>> {
    rows(
        state,
        &format!(
            "SELECT request_id,credential_id,credential_version,outcome,reason_code FROM audit_events WHERE event_type='{event_type}' ORDER BY sequence"
        ),
        5,
    )
}
fn generation(state: &Path) -> u64 {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT generation FROM vault_header", [], |r| r.get(0))
        .unwrap();
    u64::from_be_bytes(bytes.try_into().unwrap())
}
fn hex(value: &Value) -> String {
    let Value::Blob(bytes) = value else {
        panic!("blob column")
    };
    data_encoding::HEXLOWER.encode(bytes)
}
fn crl_serials(pem: &[u8]) -> Vec<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem).unwrap();
    let (rest, parsed) = x509_parser::parse_x509_crl(&pem.contents).unwrap();
    assert!(rest.is_empty());
    parsed
        .iter_revoked_certificates()
        .map(|r| {
            let raw = r.raw_serial();
            format!(
                "{:0>32}",
                data_encoding::HEXLOWER.encode(&raw[raw.len().saturating_sub(16)..])
            )
        })
        .collect()
}
/// The finalized row keeps its reservation identity and gains only the
/// existing Failed terminal facts; one failure audit pairs with its started row.
fn assert_finalized(state: &Path, reserved: &[Value], finalized: &[Value], kind: &str) {
    assert_eq!(&finalized[..6], &reserved[..6]);
    assert_eq!(reserved[6], Value::Integer(0));
    assert_eq!(reserved[7], Value::Null);
    assert_eq!(finalized[6], Value::Integer(2));
    assert!(matches!(finalized[7], Value::Integer(t) if t >= 0));
    assert!(finalized[8..].iter().all(|v| *v == Value::Null));
    let started = audits(state, &format!("pki.{kind}.started"));
    assert!(started.iter().any(|row| row[0] == reserved[3]));
    let finished: Vec<_> = audits(state, &format!("pki.{kind}.finished"))
        .into_iter()
        .filter(|row| row[0] == reserved[3])
        .collect();
    assert_eq!(
        finished,
        vec![vec![
            reserved[3].clone(),
            reserved[1].clone(),
            reserved[2].clone(),
            Value::Text("failure".into()),
            Value::Text(ABANDONED.into()),
        ]]
    );
}
async fn finish(handle: AuthorityHandle, join: std::thread::JoinHandle<()>) {
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

/// A terminal UPDATE that fails without faulting leaves a committed reservation
/// that the still-unlocked Worker no longer owns, as a crash would.
async fn abandon_terminal(handle: &AuthorityHandle, state: &Path, table: &str, id: CredentialId) {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    db.execute_batch(&format!("CREATE TRIGGER fail_terminal BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'synthetic terminal failure'); END;")).unwrap();
    let error = if table == "pki_crls" {
        crl(handle, id).await.map(|_| ()).unwrap_err()
    } else {
        issue(handle, id).await.map(|_| ()).unwrap_err()
    };
    assert_eq!(error.code(), "STORAGE_UNAVAILABLE");
    db.execute_batch("DROP TRIGGER fail_terminal").unwrap();
    assert_eq!(handle.status().await.unwrap().state, "unlocked");
}

#[tokio::test]
#[ignore = "explicit owned crash-child process used by killed_issuance_owner_reservation_is_finalized_on_unlock"]
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
    let end = Instant::now() + Duration::from_secs(60);
    while !state.join("synthetic-child-go").exists() {
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let _ = issue(&handle, id).await;
    panic!("crash child must be killed and reaped by its parent");
}

struct OwnedCrashChild(std::process::Child);

impl Drop for OwnedCrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Kills the owning Worker process after its reservation committed and while
/// its terminal commit is held open, then reaps it.
async fn kill_owner_after_reservation(state: &Path) {
    let mut child = OwnedCrashChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pki_reservation_crash_child",
                "--nocapture",
            ])
            .env("REKEY_TEST_PKI_STATE", state)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(60);
    while !state.join("synthetic-child-ready").exists() {
        assert!(child.0.try_wait().unwrap().is_none(), "child exited early");
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    db.execute_batch("CREATE TRIGGER delay_crash_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='pki.certificate.finished' BEGIN WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<1500) SELECT count(*) FROM t a,t b,t c; END;").unwrap();
    std::fs::write(state.join("synthetic-child-go"), b"go").unwrap();
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
        assert!(child.0.try_wait().unwrap().is_none(), "child exited early");
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    db.execute_batch("DROP TRIGGER delay_crash_terminal")
        .unwrap();
    drop(db);
    for name in ["synthetic-child-ready", "synthetic-child-go"] {
        std::fs::remove_file(state.join(name)).unwrap();
    }
}

#[tokio::test]
async fn killed_issuance_owner_reservation_is_finalized_on_unlock() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let state = vault.state_dir.as_path();
    let (handle, join) = common::spawn(state);
    handle.unlock(common::password_proof()).await.unwrap();
    let id = add(&handle).await;
    finish(handle, join).await;
    kill_owner_after_reservation(state).await;
    let pending = certificates(state);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0][6], Value::Integer(0));
    assert!(audits(state, "pki.certificate.finished").is_empty());
    let before = generation(state);

    let (handle, join) = common::spawn(state);
    handle.unlock(common::password_proof()).await.unwrap();
    let finalized = certificates(state);
    assert_eq!(finalized.len(), 1);
    assert_finalized(state, &pending[0], &finalized[0], "certificate");
    // One generation commit binds the finalized set; the anchor agrees.
    assert_eq!(generation(state), before + 1);
    assert_eq!(
        common::fixture_anchors(state).read().unwrap().file,
        Some(before + 1)
    );
    // Nothing was issued under the finalized serial: there is nothing to revoke,
    // and the serial is never reused.
    let lost = hex(&pending[0][0]);
    assert_eq!(
        revoke(&handle, &lost).await.unwrap_err().code(),
        "INVALID_INPUT"
    );
    let issued = issue(&handle, id).await.unwrap();
    assert_ne!(issued.serial_hex, lost);
    let revoked = revoke(&handle, &issued.serial_hex).await.unwrap();
    assert!(revoked.revoked_at_ms >= 0);
    let (first, pem) = crl(&handle, id).await.unwrap();
    assert_eq!(crl_serials(&pem), vec![issued.serial_hex.clone()]);
    let settled = certificates(state);
    assert_eq!(settled.len(), 2);
    assert!(settled.contains(&finalized[0]));

    // DEK rotation and backup carry the finalized set.
    assert_eq!(
        handle
            .rotate_dek_before(common::password_proof(), None)
            .await
            .unwrap(),
        1
    );
    assert_eq!(certificates(state), settled);
    let backup = vault.dir.path().join("recovered.backup");
    let receipt = handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    finish(handle, join).await;

    // Restart verification finds nothing left to finalize; VRK rotation then
    // re-binds the same set (last, because later proofs use production KDF cost).
    let at_restart = generation(state);
    let (handle, join) = common::spawn(state);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(generation(state), at_restart);
    assert_eq!(certificates(state), settled);
    assert_finalized(state, &pending[0], &finalized[0], "certificate");
    handle.lock("pki-recovery-test").await.unwrap();
    handle
        .rotate_vrk_before(
            common::password_input(),
            SecretInput::from_slice(vault.outcome.recovery_key_display.as_bytes()),
            None,
        )
        .await
        .unwrap();
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(certificates(state), settled);
    assert_finalized(state, &pending[0], &finalized[0], "certificate");
    handle.lock("pki-recovery-test").await.unwrap();
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();

    let restored = vault.dir.path().join("restored");
    let proof = || rekey_vault::bootstrap::RestoreProof::Password(common::password_input());
    let context =
        rekey_vault::bootstrap::inspect_restore(&backup, &restored, proof(), &receipt.sha256_hex)
            .unwrap();
    rekey_vault::bootstrap::restore_vault(
        &backup,
        &restored,
        proof(),
        &receipt.sha256_hex,
        context,
    )
    .unwrap();
    let (handle, join) = common::spawn(&restored);
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(certificates(&restored), settled);
    let (again, pem) = crl(&handle, id).await.unwrap();
    assert!(again.number > first.number);
    assert_eq!(crl_serials(&pem), vec![issued.serial_hex]);
    issue(&handle, id).await.unwrap();
    finish(handle, join).await;
}

#[tokio::test]
async fn running_worker_keeps_crl_protection_until_unlock_from_locked() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let state = vault.state_dir.as_path();
    let (handle, join) = common::spawn(state);
    handle.unlock(common::password_proof()).await.unwrap();
    let id = add(&handle).await;
    abandon_terminal(&handle, state, "pki_certificates", id).await;
    let pending = certificates(state);
    assert_eq!(pending.len(), 1);
    let before = generation(state);
    // While Unlocked the reservation keeps today's conservative refusal, and
    // re-authentication is not recovery.
    assert_eq!(crl(&handle, id).await.unwrap_err().code(), "INVALID_INPUT");
    handle.unlock(common::password_proof()).await.unwrap();
    assert_eq!(crl(&handle, id).await.unwrap_err().code(), "INVALID_INPUT");
    assert_eq!(certificates(state), pending);
    assert_eq!(generation(state), before);
    assert!(crls(state).is_empty());

    // Remembered-unlock resume from Locked recovers like password unlock.
    let (key, _) = handle
        .desktop_remember(common::password_proof(), None, 604_800_000)
        .await
        .unwrap();
    handle.lock_for_restart("pki-recovery-test").await.unwrap();
    handle
        .desktop_resume(SecretInput::from_slice(&key), None)
        .await
        .unwrap();
    let finalized = certificates(state);
    assert_finalized(state, &pending[0], &finalized[0], "certificate");
    assert_eq!(generation(state), before + 1);
    let (_, pem) = crl(&handle, id).await.unwrap();
    assert!(crl_serials(&pem).is_empty());
    finish(handle, join).await;
}

#[tokio::test]
async fn crl_reservation_without_owner_is_finalized_on_unlock() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    let vault = common::init_test_vault();
    let state = vault.state_dir.as_path();
    let (handle, join) = common::spawn(state);
    handle.unlock(common::password_proof()).await.unwrap();
    let id = add(&handle).await;
    abandon_terminal(&handle, state, "pki_crls", id).await;
    let pending = crls(state);
    assert_eq!(pending.len(), 1);
    assert!(audits(state, "pki.crl.finished").is_empty());
    finish(handle, join).await;
    let before = generation(state);
    let (handle, join) = common::spawn(state);
    handle.unlock(common::password_proof()).await.unwrap();
    let finalized = crls(state);
    assert_eq!(finalized.len(), 1);
    assert_finalized(state, &pending[0], &finalized[0], "crl");
    assert_eq!(generation(state), before + 1);
    // CRL numbers stay unique: a new CRL takes a later number.
    let Value::Blob(number) = &pending[0][0] else {
        panic!("number")
    };
    let number = u64::from_be_bytes(number.as_slice().try_into().unwrap());
    assert!(crl(&handle, id).await.unwrap().0.number > number);
    assert_eq!(crls(state)[0], finalized[0]);
    finish(handle, join).await;
}

#[tokio::test]
async fn unlock_finalization_refuses_trigger_changes_and_audit_failure() {
    let _serial = PKI_TEST_SERIAL.lock().await;
    for (route, attack, expected) in [
        (
            "audit",
            "CREATE TRIGGER attack BEFORE INSERT ON audit_events WHEN NEW.reason_code='abandoned-on-unlock' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;",
            "AUDIT_COMMIT_FAILED",
        ),
        (
            "ledger",
            "CREATE TRIGGER attack AFTER UPDATE ON pki_certificates BEGIN DELETE FROM pki_certificates WHERE state=1; END;",
            "STORAGE_INTEGRITY_FAILED",
        ),
        (
            "header",
            "CREATE TRIGGER attack AFTER UPDATE ON vault_header BEGIN UPDATE pki_certificates SET finished_at_ms=0 WHERE state=2; END;",
            "STORAGE_INTEGRITY_FAILED",
        ),
    ] {
        let vault = common::init_test_vault();
        let state = vault.state_dir.as_path();
        let (handle, join) = common::spawn(state);
        handle.unlock(common::password_proof()).await.unwrap();
        let id = add(&handle).await;
        issue(&handle, id).await.unwrap();
        abandon_terminal(&handle, state, "pki_certificates", id).await;
        finish(handle, join).await;
        let pending = certificates(state);
        let before = generation(state);
        let (handle, join) = common::spawn(state);
        // Installed after startup layout admission, before the recovery commit.
        let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
        db.execute_batch(attack).unwrap();
        let error = handle.unlock(common::password_proof()).await.unwrap_err();
        assert_eq!(error.code(), expected, "route={route}");
        assert_eq!(handle.status().await.unwrap().state, "faulted");
        assert_eq!(certificates(state), pending, "route={route}");
        assert_eq!(generation(state), before, "route={route}");
        assert!(
            audits(state, "pki.certificate.finished")
                .iter()
                .all(|row| row[4] != Value::Text(ABANDONED.into()))
        );
        db.execute_batch("DROP TRIGGER attack").unwrap();
        drop(db);
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
        let (handle, join) = common::spawn(state);
        handle.unlock(common::password_proof()).await.unwrap();
        let finalized = certificates(state);
        let reserved = pending.iter().position(|row| row[6] == Value::Integer(0));
        let reserved = reserved.unwrap();
        assert_finalized(
            state,
            &pending[reserved],
            &finalized[reserved],
            "certificate",
        );
        crl(&handle, id).await.unwrap();
        finish(handle, join).await;
    }
}
