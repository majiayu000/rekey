use super::*;

#[tokio::test]
async fn restore_rejects_format_twelve_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v12.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    // Downgrade only this test snapshot header and its CHECK, keeping valid crypto.
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 12') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=12", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v12");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
    let db = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        db.query_row("SELECT format_version FROM vault_header", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        12
    );
}

#[tokio::test]
async fn restore_rejects_format_thirteen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v13.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 13') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=13", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v13");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
    let db = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        db.query_row("SELECT format_version FROM vault_header", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        13
    );
}

#[tokio::test]
async fn restore_rejects_format_fourteen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v14.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 14') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=14", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v14");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn restore_rejects_format_fifteen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v15.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 15') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=15", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v15");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}
#[tokio::test]
async fn restore_rejects_format_sixteen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v16.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 16') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=16", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v16");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn restore_rejects_format_seventeen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v17.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 17') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=17", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v17");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn restore_rejects_format_eighteen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v18.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 18') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=18", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v18");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}

#[tokio::test]
async fn restore_rejects_format_nineteen_without_installing_or_migrating() {
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("v19.rkbackup");
    handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute_batch(&format!("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'format_version = {}','format_version = 19') WHERE name='vault_header'; PRAGMA writable_schema=OFF;", rekey_vault::model::FORMAT_VERSION)).unwrap();
    drop(db);
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute("UPDATE vault_header SET format_version=19", [])
        .unwrap();
    drop(db);
    let target = vault.dir.path().join("restored-v19");
    assert!(matches!(
        restore_vault(
            &backup,
            &target,
            RestoreProof::Password(common::password_input()),
            &file_sha256(&backup),
            common::unconfirmed_restore_context()
        ),
        Err(AuthorityError::UnsupportedFormatVersion)
    ));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
}
