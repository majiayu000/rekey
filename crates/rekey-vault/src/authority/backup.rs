use std::path::{Path, PathBuf};

use crate::command::{BackupInfo, UnlockProof};
use crate::error::AuthorityError;
use crate::model::{event_type, outcome};
use crate::now_ms;

use super::{Worker, unlock_audit};

impl Worker {
    pub(super) fn backup(
        &mut self,
        output: PathBuf,
        proof: UnlockProof,
    ) -> Result<BackupInfo, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        let created_at_ms = now_ms()?;
        if !output.is_absolute() {
            return Err(AuthorityError::BackupFailed);
        }
        crate::durable::ensure_outside_tree(&output, &self.config.state_dir)
            .map_err(|_| AuthorityError::BackupFailed)?;
        let output = crate::durable::resolve_destination(&output)
            .map_err(|_| AuthorityError::BackupFailed)?;
        match std::fs::symlink_metadata(&output) {
            Ok(_) => return Err(AuthorityError::BackupFailed),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AuthorityError::BackupFailed),
        }

        let snapshot_path = crate::durable::resolve_destination(&crate::paths::backup_snapshot(
            &self.config.state_dir,
        ))
        .map_err(|_| AuthorityError::BackupFailed)?;
        self.cleanup_reserved_snapshot(&snapshot_path)?;
        let mut snapshot = match crate::durable::create_new_file(&snapshot_path) {
            Ok(file) => file,
            Err(_) => {
                self.cleanup_reserved_snapshot(&snapshot_path)?;
                return Err(AuthorityError::BackupFailed);
            }
        };
        if let Err(err) = self.store.backup_to(&snapshot_path, &snapshot) {
            self.cleanup_reserved_snapshot(&snapshot_path)?;
            return Err(err);
        }
        if snapshot.sync_all().is_err() {
            self.cleanup_reserved_snapshot(&snapshot_path)?;
            return Err(AuthorityError::BackupFailed);
        }
        if let Err(err) = self.append_audit(unlock_audit(
            event_type::BACKUP_RELEASE_AUTHORIZED,
            outcome::SUCCESS,
            "backup-release",
        )) {
            self.cleanup_reserved_snapshot(&snapshot_path)?;
            return Err(err);
        }

        let mut output_file = match crate::durable::create_new_file(&output) {
            Ok(file) => file,
            Err(_) => {
                self.cleanup_reserved_snapshot(&snapshot_path)?;
                return Err(AuthorityError::BackupFailed);
            }
        };
        let sha256_hex =
            match crate::durable::copy_files_and_sha256(&mut snapshot, &mut output_file) {
                Ok(hash) => hash,
                Err(_) => {
                    self.cleanup_reserved_snapshot(&snapshot_path)?;
                    return Err(AuthorityError::BackupFailed);
                }
            };
        let output_is_owned = match crate::durable::same_file(&output_file, &output) {
            Ok(owned) => owned,
            Err(_) => {
                self.fault("backup-output-ownership-lost");
                self.cleanup_reserved_snapshot(&snapshot_path)?;
                return Err(AuthorityError::BackupFailed);
            }
        };
        if !output_is_owned {
            self.fault("backup-output-ownership-lost");
            self.cleanup_reserved_snapshot(&snapshot_path)?;
            return Err(AuthorityError::BackupFailed);
        }
        if crate::durable::fsync_parent(&output).is_err() {
            self.cleanup_reserved_snapshot(&snapshot_path)?;
            return Err(AuthorityError::BackupFailed);
        }
        self.cleanup_reserved_snapshot(&snapshot_path)?;

        let info = BackupInfo {
            vault_id: self.header.vault_id,
            format_version: self.header.format_version,
            created_at_ms,
            sha256_hex,
            output_path: output,
        };
        self.append_audit(unlock_audit(
            event_type::BACKUP_CREATED,
            outcome::SUCCESS,
            "backup",
        ))?;
        Ok(info)
    }

    fn cleanup_reserved_snapshot(&mut self, path: &Path) -> Result<(), AuthorityError> {
        if crate::durable::remove_file_and_sync(path).is_err() {
            self.fault("backup-snapshot-cleanup-failed");
            return Err(AuthorityError::BackupFailed);
        }
        Ok(())
    }
}
