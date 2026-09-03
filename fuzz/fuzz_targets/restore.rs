#![no_main]

use std::fs::{self, OpenOptions};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rekey_vault::bootstrap::{RestoreProof, confirm_vault_init, init_vault, restore_vault};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let mut candidate = fixture.backup.clone();
    let mutations = data
        .iter()
        .skip(2)
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if !mutations.is_empty() {
        match data.get(1).copied().unwrap_or_default() % 3 {
            0 => {
                for (position, byte) in mutations.iter().copied().enumerate() {
                    let index = (position.saturating_mul(257) + byte as usize) % candidate.len();
                    candidate[index] ^= byte;
                }
            }
            1 => {
                let new_len = mutations[0] as usize * candidate.len() / u8::MAX as usize;
                candidate.truncate(new_len);
            }
            _ => candidate.extend_from_slice(&mutations),
        }
    }

    let Ok(work) = tempfile::tempdir() else {
        return;
    };
    let backup = work.path().join("candidate.rkbackup");
    let target = work.path().join("restore");
    if fs::write(&backup, &candidate).is_err() {
        return;
    }
    let digest = format!("{:x}", Sha256::digest(&candidate));
    let result = restore_vault(&backup, &target, proof(data, fixture), &digest);
    if mutations.is_empty() {
        assert!(result.is_ok());
    } else if result.is_err() {
        assert_restore_cleanup(&target);
        if data.get(2).is_some_and(|byte| byte & 0x0f == 1) {
            fs::write(&backup, &fixture.backup).expect("rewrite fixed restore fixture");
            let fixture_digest = format!("{:x}", Sha256::digest(&fixture.backup));
            assert!(
                restore_vault(&backup, &target, proof(data, fixture), &fixture_digest).is_ok()
            );
        }
    }
});

const PASSWORD: &[u8] = b"fuzz-fixture-password";

struct RestoreFixture {
    backup: Vec<u8>,
    recovery_key: Zeroizing<Vec<u8>>,
}

fn proof(data: &[u8], fixture: &RestoreFixture) -> RestoreProof {
    if data.first() == Some(&b'R') {
        RestoreProof::RecoveryKey(SecretInput::from_slice(&fixture.recovery_key))
    } else {
        RestoreProof::Password(SecretInput::from_slice(PASSWORD))
    }
}

fn assert_restore_cleanup(target: &std::path::Path) {
    let installed = rekey_vault::paths::vault_db(target);
    for path in [
        installed.clone(),
        target.join(".incoming-vault.sqlite3"),
        target.join("vault.sqlite3-wal"),
        target.join("vault.sqlite3-shm"),
        target.join(".incoming-vault.sqlite3-wal"),
        target.join(".incoming-vault.sqlite3-shm"),
        rekey_vault::paths::restore_incomplete(target),
    ] {
        assert!(!path.exists(), "failed restore left {}", path.display());
    }
}

fn fixture() -> &'static RestoreFixture {
    static FIXTURE: OnceLock<RestoreFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let work = tempfile::tempdir().expect("create fixture directory");
        let state = work.path().join("state");
        let password = SecretInput::from_slice(PASSWORD);
        let outcome = init_vault(
            &state,
            &password,
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        )
        .expect("initialize current-format restore fixture");
        confirm_vault_init(&state).expect("confirm restore fixture");
        let store = SqliteRecordStore::open(&rekey_vault::paths::vault_db(&state))
            .expect("open restore fixture");
        let backup_path = work.path().join("fixture.rkbackup");
        let backup_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&backup_path)
            .expect("create restore fixture snapshot");
        store
            .backup_to(&backup_path, &backup_file)
            .expect("snapshot restore fixture");
        RestoreFixture {
            backup: fs::read(backup_path).expect("read restore fixture snapshot"),
            recovery_key: Zeroizing::new(outcome.recovery_key_display.as_bytes().to_vec()),
        }
    })
}
