//! Real Linux tmpfs exhaustion coverage. The dedicated CI step supplies a
//! small owner-only mount through `REKEY_ENOSPC_DIR`; ordinary test runs skip.

mod common;

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rekey_domain::credential::{CredentialKind, CredentialLabel};
use rekey_vault::bootstrap::{RestoreProof, confirm_vault_init, init_vault, restore_vault};
use rekey_vault::command::AuditDraft;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::error::AuthorityError;
use rekey_vault::model::{event_type, outcome};
use rekey_vault::secret::SecretInput;

const RESERVE_BYTES: usize = 16 * 1024;

fn mounted_case(prefix: &str) -> Option<tempfile::TempDir> {
    let configured = std::env::var_os("REKEY_ENOSPC_DIR").map(PathBuf::from)?;
    let root = fs::canonicalize(configured).expect("canonicalize REKEY_ENOSPC_DIR");
    validate_bounded_mount(&root).expect("REKEY_ENOSPC_DIR must be a bounded dedicated mount");
    Some(
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(root)
            .expect("create ENOSPC case directory"),
    )
}

fn validate_bounded_mount(root: &Path) -> Result<(), String> {
    let parent = root
        .parent()
        .ok_or_else(|| "mount has no parent".to_owned())?;
    let root_device = fs::metadata(root).map_err(|error| error.to_string())?.dev();
    let parent_device = fs::metadata(parent)
        .map_err(|error| error.to_string())?
        .dev();
    if root_device == parent_device {
        return Err("path is not a distinct filesystem mount".to_owned());
    }

    let output = Command::new("df")
        .args(["-kP"])
        .arg(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("df failed for configured mount".to_owned());
    }
    let stdout = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let blocks = stdout
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "df did not report mount capacity".to_owned())?;
    if !(8 * 1024..=128 * 1024).contains(&blocks) {
        return Err(format!(
            "mount capacity must be 8..=128 MiB, got {blocks} KiB"
        ));
    }
    Ok(())
}

#[test]
fn enospc_root_must_be_a_bounded_dedicated_mount() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("ordinary-directory");
    fs::create_dir(&nested).unwrap();
    assert!(validate_bounded_mount(&nested).is_err());
}

fn init_at(state_dir: &Path) {
    init_vault(
        state_dir,
        &common::password_input(),
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        },
    )
    .expect("initialize test vault");
    confirm_vault_init(state_dir).expect("confirm test vault");
}

struct ExhaustedSpace {
    filler: PathBuf,
}

impl ExhaustedSpace {
    fn release(self) {
        fs::remove_file(self.filler).expect("release exhausted tmpfs space");
    }
}

fn exhaust_space(dir: &Path, reserve_bytes: usize) -> ExhaustedSpace {
    let reserve = dir.join("reserve.bin");
    if reserve_bytes > 0 {
        let mut file = File::create(&reserve).expect("create ENOSPC reserve");
        write_exact_bytes(&mut file, reserve_bytes).expect("allocate ENOSPC reserve");
        file.sync_all().expect("sync ENOSPC reserve");
    }

    let filler = dir.join("filler.bin");
    let mut file = File::create(&filler).expect("create ENOSPC filler");
    let chunk = [0xa5; 64 * 1024];
    let error = loop {
        match file.write(&chunk) {
            Ok(0) => panic!("tmpfs filler made no progress"),
            Ok(_) => {}
            Err(error) => break error,
        }
    };
    assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    drop(file);

    if reserve_bytes > 0 {
        fs::remove_file(reserve).expect("release ENOSPC reserve");
    }
    ExhaustedSpace { filler }
}

fn write_exact_bytes(file: &mut File, mut remaining: usize) -> std::io::Result<()> {
    let chunk = [0x5a; 4096];
    while remaining > 0 {
        let count = remaining.min(chunk.len());
        file.write_all(&chunk[..count])?;
        remaining -= count;
    }
    Ok(())
}

fn audit_draft() -> AuditDraft {
    AuditDraft {
        request_id: None,
        session_id: None,
        action_id: None,
        action_version: None,
        credential_id: None,
        credential_version: None,
        authorization: None,
        event_type: event_type::POLICY_ACTIVATED,
        outcome: outcome::SUCCESS,
        reason_code: "enospc-probe".to_owned(),
        upstream_status: None,
        latency_ms: None,
    }
}

#[tokio::test]
async fn audit_enospc_faults_the_worker() {
    let Some(case) = mounted_case("audit-") else {
        return;
    };
    let state_dir = case.path().join("state");
    init_at(&state_dir);
    let (handle, join) = common::spawn(&state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let exhausted = exhaust_space(case.path(), 0);

    let mut failure = None;
    for _ in 0..64 {
        if let Err(error) = handle.append_audit(audit_draft()).await {
            failure = Some(error);
            break;
        }
    }
    assert!(matches!(failure, Some(AuthorityError::AuditCommitFailed)));
    assert_eq!(handle.status().await.unwrap().state, "faulted");

    exhausted.release();
    handle.shutdown(None).await.unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn credential_mutation_enospc_is_atomic_and_retryable() {
    let Some(case) = mounted_case("mutation-") else {
        return;
    };
    let state_dir = case.path().join("state");
    init_at(&state_dir);
    let (mut handle, mut join) = common::spawn(&state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let exhausted = exhaust_space(case.path(), 0);

    let label = CredentialLabel::new("enospc mutation").unwrap();
    let error = common::expect_err(
        handle
            .credential_add(
                label.clone(),
                CredentialKind::OpaqueToken,
                SecretInput::from_slice(&vec![0x6b; 64 * 1024]),
                common::password_proof(),
            )
            .await,
    );
    assert!(matches!(
        error,
        AuthorityError::StorageUnavailable(_) | AuthorityError::AuditCommitFailed
    ));
    let faulted = handle.status().await.unwrap().state == "faulted";
    exhausted.release();

    if faulted {
        handle.shutdown(None).await.unwrap();
        join.join().unwrap();
        (handle, join) = common::spawn(&state_dir);
        handle.unlock(common::password_proof()).await.unwrap();
    }
    handle
        .credential_add(
            label,
            CredentialKind::OpaqueToken,
            SecretInput::from_slice(b"retry-value"),
            common::password_proof(),
        )
        .await
        .expect("failed mutation must leave no partial credential");
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn backup_enospc_returns_no_receipt_and_requires_a_new_path() {
    let Some(case) = mounted_case("backup-") else {
        return;
    };
    let vault = common::init_test_vault();
    let source_len = fs::metadata(rekey_vault::paths::vault_db(&vault.state_dir))
        .unwrap()
        .len();
    assert!(source_len > RESERVE_BYTES as u64);
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let exhausted = exhaust_space(case.path(), RESERVE_BYTES);
    let output = case.path().join("partial.rkbackup");

    let error = common::expect_err(
        handle
            .backup(output.clone(), common::password_proof())
            .await,
    );
    assert!(matches!(error, AuthorityError::BackupFailed));
    assert!(
        output.exists(),
        "authorized partial backup must be retained"
    );
    assert!(fs::metadata(&output).unwrap().len() < source_len);

    exhausted.release();
    assert!(matches!(
        common::expect_err(
            handle
                .backup(output.clone(), common::password_proof())
                .await
        ),
        AuthorityError::BackupFailed
    ));
    handle
        .backup(case.path().join("retry.rkbackup"), common::password_proof())
        .await
        .expect("retry at a new path must succeed after space is restored");
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
}

#[tokio::test]
async fn restore_enospc_cleans_internal_artifacts_and_retries() {
    let Some(case) = mounted_case("restore-") else {
        return;
    };
    let vault = common::init_test_vault();
    let (handle, join) = common::spawn(&vault.state_dir);
    handle.unlock(common::password_proof()).await.unwrap();
    let backup = vault.dir.path().join("source.rkbackup");
    let receipt = handle
        .backup(backup.clone(), common::password_proof())
        .await
        .unwrap();
    handle
        .shutdown(Some(common::password_proof()))
        .await
        .unwrap();
    join.join().unwrap();
    assert!(fs::metadata(&backup).unwrap().len() > RESERVE_BYTES as u64);

    let target = case.path().join("target");
    fs::create_dir(&target).unwrap();
    let exhausted = exhaust_space(case.path(), RESERVE_BYTES);
    let error = restore_vault(
        &backup,
        &target,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .unwrap_err();
    assert!(matches!(error, AuthorityError::RestoreFailed));
    assert!(!rekey_vault::paths::vault_db(&target).exists());
    assert!(!target.join(".incoming-vault.sqlite3").exists());
    assert!(!rekey_vault::paths::restore_incomplete(&target).exists());

    exhausted.release();
    restore_vault(
        &backup,
        &target,
        RestoreProof::Password(common::password_input()),
        &receipt.sha256_hex,
    )
    .expect("restore retry must succeed after space is restored");
}
