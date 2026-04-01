use rekey_ca::authority::CertificateAuthority;
use rekey_ca::leaf::LeafCertCache;
use rekey_vault::{audit, crypto, db, rules, secrets};
use tempfile::TempDir;

#[test]
fn full_vault_lifecycle() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("vault.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    db::init_db(&conn).unwrap();

    // Derive key
    let salt = [42u8; 16];
    let key = crypto::derive_master_key("test-password", &salt).unwrap();

    // Add secrets
    secrets::add_secret(
        &conn,
        &key,
        "anthropic",
        "anthropic",
        "sk-ant-test-123",
        "api.anthropic.com",
    )
    .unwrap();
    secrets::add_secret(
        &conn,
        &key,
        "openai",
        "openai",
        "sk-proj-test-456",
        "api.openai.com",
    )
    .unwrap();

    // List
    let list = secrets::list_secrets(&conn).unwrap();
    assert_eq!(list.len(), 2);

    // Retrieve value
    let val = secrets::get_secret_value(&conn, &key, "anthropic").unwrap();
    assert_eq!(val, "sk-ant-test-123");

    // Rules auto-created by provider
    let anthropic_rules = rules::find_rules_for_host(&conn, "api.anthropic.com").unwrap();
    assert_eq!(anthropic_rules.len(), 1);
    assert_eq!(anthropic_rules[0].0.header_name, "x-api-key");

    let openai_rules = rules::find_rules_for_host(&conn, "api.openai.com").unwrap();
    assert_eq!(openai_rules.len(), 1);
    assert_eq!(openai_rules[0].0.header_name, "authorization");
    assert_eq!(openai_rules[0].0.value_format, "Bearer {value}");

    // No rules for unknown host
    let no_rules = rules::find_rules_for_host(&conn, "api.unknown.com").unwrap();
    assert!(no_rules.is_empty());

    // Rotate
    secrets::rotate_secret(&conn, &key, "anthropic", "sk-ant-new-789").unwrap();
    let val = secrets::get_secret_value(&conn, &key, "anthropic").unwrap();
    assert_eq!(val, "sk-ant-new-789");

    // Audit
    audit::log_access(
        &conn,
        "anthropic",
        "api.anthropic.com",
        "/v1/messages",
        Some(200),
        Some(100),
        "proxy",
    )
    .unwrap();
    let logs = audit::query_audit(&conn, None, None, 10).unwrap();
    assert_eq!(logs.len(), 1);

    // Remove
    secrets::remove_secret(&conn, "anthropic").unwrap();
    let list = secrets::list_secrets(&conn).unwrap();
    assert_eq!(list.len(), 1);
}

#[test]
fn ca_and_leaf_cert_lifecycle() {
    let dir = TempDir::new().unwrap();
    let ca = CertificateAuthority::generate(dir.path()).unwrap();
    let cache = LeafCertCache::new();

    // Generate leaf certs
    let leaf1 = cache.get_or_create("api.anthropic.com", &ca).unwrap();
    let leaf2 = cache.get_or_create("api.openai.com", &ca).unwrap();

    assert!(!leaf1.cert_der.is_empty());
    assert_ne!(leaf1.cert_der, leaf2.cert_der);

    // Cache hit
    let leaf1_again = cache.get_or_create("api.anthropic.com", &ca).unwrap();
    assert_eq!(leaf1.cert_der, leaf1_again.cert_der);

    // Reload CA from disk
    let ca2 = CertificateAuthority::load(dir.path()).unwrap();
    assert_eq!(ca.ca_cert_pem(), ca2.ca_cert_pem());
}
