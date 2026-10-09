//! Synthetic CA material only. Import is not a certificate issuance permission.
mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rekey_domain::action::{
    ActionName, ActionTarget, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_domain::ids::{ActionId, RequestId};
use rekey_vault::bootstrap::{RestoreProof, inspect_restore, restore_vault};
use rekey_vault::command::{ActionDefinition, UnlockProof};
use rekey_vault::crypto::aad::{AadPurpose, AadV1};
use rekey_vault::crypto::aead;
use rekey_vault::error::AuthorityError;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use zeroize::Zeroizing;

fn parameters() -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn root(params: CertificateParams, key: &KeyPair) -> Zeroizing<String> {
    let cert = params.self_signed(key).unwrap();
    Zeroizing::new(format!("{}{}", key.serialize_pem(), cert.pem()))
}

fn snapshot(state: &std::path::Path) -> (u64, u64, Vec<u8>) {
    let db = rusqlite::Connection::open(rekey_vault::paths::vault_db(state)).unwrap();
    (
        db.query_row("SELECT count(*) FROM credentials", [], |row| row.get(0))
            .unwrap(),
        db.query_row("SELECT count(*) FROM credential_versions", [], |row| {
            row.get(0)
        })
        .unwrap(),
        db.query_row("SELECT generation FROM vault_header", [], |row| row.get(0))
            .unwrap(),
    )
}

fn http(credential_id: rekey_domain::ids::CredentialId, mtls: bool) -> ActionDefinition {
    ActionDefinition {
        native_plugin: None,
        text_stream: None,
        name: ActionName::new("ca-http-rejected").unwrap(),
        credential_id,
        origin: HttpsOrigin::parse("https://api.example.test").unwrap(),
        method: FixedMethod::Post,
        target: ActionTarget::Fixed {
            path: ExactPath::parse("/resource").unwrap(),
        },
        auth: HeaderCredentialUse::new(
            HeaderName::new("authorization").unwrap(),
            HeaderPrefix::new(if mtls { "" } else { "Bearer " }).unwrap(),
        )
        .unwrap(),
        timeout_ms: 30_000,
        request_policy: RequestPolicy {
            max_body_bytes: 1024,
            allowed_extra_headers: BTreeSet::new(),
        },
        response_policy: ResponsePolicy {
            max_body_bytes: 1024,
            allowed_headers: BTreeSet::new(),
        },
    }
}

#[tokio::test]
async fn ca_import_rejects_non_ca_invalid_signature_constraints_and_key_mismatch_without_mutation()
{
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = parameters().self_signed(&key).unwrap();
    let mut cases = Vec::new();
    let leaf = CertificateParams::new(vec!["leaf.test".into()]).unwrap();
    cases.push(root(leaf, &key));
    let mut no_usage = parameters();
    no_usage.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cases.push(root(no_usage, &key));
    let now = x509_parser::time::ASN1Time::now().to_datetime();
    let mut expired = parameters();
    expired.not_before = now - Duration::from_secs(7200);
    expired.not_after = now - Duration::from_secs(3600);
    cases.push(root(expired, &key));
    let mut future = parameters();
    future.not_before = now + Duration::from_secs(3600);
    future.not_after = now + Duration::from_secs(7200);
    cases.push(root(future, &key));
    let wrong = KeyPair::generate().unwrap();
    cases.push(Zeroizing::new(format!(
        "{}{}",
        wrong.serialize_pem(),
        cert.pem()
    )));
    cases.push(Zeroizing::new(format!(
        "{}{}{}",
        key.serialize_pem(),
        cert.pem(),
        cert.pem()
    )));
    cases.push(Zeroizing::new(format!(
        "{}{}{}",
        key.serialize_pem(),
        key.serialize_pem(),
        cert.pem()
    )));
    let mut bad_signature = cert.der().to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    let encoded = data_encoding::BASE64.encode(&bad_signature);
    cases.push(Zeroizing::new(format!(
        "{}-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        key.serialize_pem(),
        encoded
    )));
    let mut critical = parameters();
    let mut unknown = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], Vec::new());
    unknown.set_criticality(true);
    critical.custom_extensions.push(unknown);
    cases.push(root(critical, &key));
    let mut constrained = parameters();
    constrained.name_constraints = Some(rcgen::NameConstraints {
        permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("only.test".into())],
        excluded_subtrees: vec![],
    });
    cases.push(root(constrained, &key));
    let mut duplicate = parameters();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.der()).unwrap();
    let basic = parsed
        .extensions()
        .iter()
        .find(|ext| {
            matches!(
                ext.parsed_extension(),
                x509_parser::extensions::ParsedExtension::BasicConstraints(_)
            )
        })
        .unwrap();
    duplicate
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 19],
            basic.value.to_vec(),
        ));
    cases.push(root(duplicate, &key));
    let parent_key = KeyPair::generate().unwrap();
    let mut parent_params = parameters();
    parent_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "synthetic-parent");
    let parent = parent_params.self_signed(&parent_key).unwrap();
    let intermediate = parameters().signed_by(&key, &parent, &parent_key).unwrap();
    cases.push(Zeroizing::new(format!(
        "{}{}",
        key.serialize_pem(),
        intermediate.pem()
    )));
    cases.push(Zeroizing::new(format!(
        "{}trailing text",
        root(parameters(), &key).as_str()
    )));
    let before = snapshot(&vault.state_dir);
    for (index, value) in cases.into_iter().enumerate() {
        let error = common::expect_err(
            handle
                .credential_add(
                    CredentialLabel::new(&format!("bad-ca-{index}")).unwrap(),
                    CredentialKind::PkiCaSigner,
                    SecretInput::from_slice(value.as_bytes()),
                    common::password_proof(),
                )
                .await,
        );
        assert!(
            matches!(error, AuthorityError::Domain(rekey_domain::DomainError::InvalidActionDefinition(ref message)) if message == "invalid private credential material"),
            "case {index}"
        );
        assert_eq!(snapshot(&vault.state_dir), before, "case {index}");
    }
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn ca_history_is_encrypted_typed_rotatable_restorable_and_never_business_or_plaintext_material()
 {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let first = root(parameters(), &KeyPair::generate().unwrap());
    let second = root(
        parameters(),
        &KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
    );
    let meta = handle
        .credential_add(
            CredentialLabel::new("synthetic-ca").unwrap(),
            CredentialKind::PkiCaSigner,
            SecretInput::from_slice(first.as_bytes()),
            common::password_proof(),
        )
        .await
        .unwrap();
    let id = meta.id;
    assert_eq!(meta.kind, CredentialKind::PkiCaSigner);
    assert!(matches!(
        handle.prepare_credential(id).await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    assert!(matches!(
        handle
            .prepare_execution_credential(
                id,
                RequestId::new_random(),
                ActionId::new_random(),
                1,
                Instant::now() + Duration::from_secs(30)
            )
            .await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    assert!(matches!(
        handle
            .desktop_reveal(common::password_proof(), id, None)
            .await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    for mtls in [false, true] {
        assert!(matches!(
            handle
                .action_upsert(None, http(id, mtls), common::password_proof())
                .await,
            Err(AuthorityError::Domain(
                rekey_domain::DomainError::InvalidActionDefinition(_)
            ))
        ));
    }
    let before = snapshot(&vault.state_dir);
    for expected in [None, Some(0), Some(2)] {
        assert!(
            handle
                .credential_rotate_typed_before(
                    id,
                    CredentialKind::PkiCaSigner,
                    expected,
                    SecretInput::from_slice(second.as_bytes()),
                    common::password_proof(),
                    None
                )
                .await
                .is_err()
        );
        assert_eq!(snapshot(&vault.state_dir), before);
    }
    assert!(
        handle
            .credential_rotate_typed_before(
                id,
                CredentialKind::MtlsIdentity,
                Some(1),
                SecretInput::from_slice(second.as_bytes()),
                common::password_proof(),
                None
            )
            .await
            .is_err()
    );
    assert_eq!(snapshot(&vault.state_dir), before);
    assert!(
        handle
            .credential_rotate_typed_before(
                id,
                CredentialKind::PkiCaSigner,
                Some(1),
                SecretInput::from_slice(second.as_bytes()),
                UnlockProof::Password(SecretInput::from_slice(b"synthetic-wrong-proof")),
                None
            )
            .await
            .is_err()
    );
    assert_eq!(snapshot(&vault.state_dir), before);
    let rotated = handle
        .credential_rotate_typed_before(
            id,
            CredentialKind::PkiCaSigner,
            Some(1),
            SecretInput::from_slice(second.as_bytes()),
            common::password_proof(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(rotated.current_version, 2);
    let backup = vault.dir.path().join("ca.rkbackup");
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
    let store = SqliteRecordStore::open(&backup).unwrap();
    let header = store.load_header().unwrap();
    let vrk = common::fixture_root(&vault.state_dir);
    for (index, value) in [first.as_bytes(), second.as_bytes()]
        .into_iter()
        .enumerate()
    {
        let version = store.get_version(id, index as u64 + 1).unwrap();
        let mut aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id: header.vault_id,
            object_id: *id.as_bytes(),
            object_version: version.version,
            credential_kind: 0,
            constraints_hash: [0; 32],
        };
        let opened = aead::open(
            &vrk,
            &aad.encode(),
            &version.dek_nonce,
            &version.wrapped_dek,
        )
        .unwrap();
        let dek = Zeroizing::new(<[u8; 32]>::try_from(opened.as_slice()).unwrap());
        aad.purpose = AadPurpose::CredentialPayload;
        aad.credential_kind = CredentialKind::PkiCaSigner.aad_code();
        let payload = aead::open(
            &dek,
            &aad.encode(),
            &version.payload_nonce,
            &version.encrypted_payload,
        )
        .unwrap();
        assert!(payload.as_slice() == value);
        aad.credential_kind = CredentialKind::MtlsIdentity.aad_code();
        assert!(
            aead::open(
                &dek,
                &aad.encode(),
                &version.payload_nonce,
                &version.encrypted_payload
            )
            .is_err()
        );
    }
    let restored = vault.dir.path().join("restored");
    let context = inspect_restore(
        &backup,
        &restored,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap();
    restore_vault(
        &backup,
        &restored,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
        context,
    )
    .unwrap();
    let (handle, join) = common::spawn(&restored);
    handle.unlock(common::password_proof()).await.unwrap();
    let listed = handle.credential_list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, CredentialKind::PkiCaSigner);
    assert_eq!(listed[0].current_version, 2);
    assert!(matches!(
        handle.prepare_credential(id).await,
        Err(AuthorityError::CredentialSourceUnavailable)
    ));
    handle
        .credential_revoke(id, common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}
