#![no_main]

use std::fs;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rekey_vault::bootstrap::{RestoreProof, confirm_vault_init, init_vault, restore_vault};
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::durable;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;
use rekey_vault::store::SqliteRecordStore;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let mut candidate = fixture.backup.clone();
    let mutations = data
        .iter()
        .skip(1)
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    for (position, byte) in mutations.iter().copied().enumerate() {
        let index = (position.saturating_mul(257) + byte as usize) % candidate.len();
        candidate[index] ^= byte;
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
    let proof = if data.first() == Some(&b'R') {
        RestoreProof::RecoveryKey(SecretInput::from_slice(&fixture.recovery_key))
    } else {
        RestoreProof::Password(SecretInput::from_slice(PASSWORD))
    };
    let result = restore_vault(&backup, &target, proof, &digest);
    if mutations.is_empty() {
        assert!(result.is_ok());
    }
});

const PASSWORD: &[u8] = b"fuzz-fixture-password";
const TEST_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};

struct Fixture {
    backup: Vec<u8>,
    recovery_key: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let work = tempfile::tempdir().expect("create fuzz fixture directory");
        let state = work.path().join("state");
        let outcome = init_vault(&state, &SecretInput::from_slice(PASSWORD), TEST_PARAMS)
            .expect("initialize fuzz fixture vault");
        confirm_vault_init(&state).expect("confirm fuzz fixture vault");

        let source =
            SqliteRecordStore::open(&paths::vault_db(&state)).expect("open fuzz fixture vault");
        let backup_path = work.path().join("fixture.rkbackup");
        let backup_file =
            durable::create_new_file(&backup_path).expect("create fuzz fixture backup");
        source
            .backup_to(&backup_path, &backup_file)
            .expect("snapshot fuzz fixture vault");
        backup_file.sync_all().expect("sync fuzz fixture backup");
        drop(backup_file);
        drop(source);

        Fixture {
            backup: fs::read(backup_path).expect("read fuzz fixture backup"),
            recovery_key: outcome.recovery_key_display.as_bytes().to_vec(),
        }
    })
}
