#![no_main]

use std::fs;
use std::sync::OnceLock;

use data_encoding::BASE64;
use libfuzzer_sys::fuzz_target;
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::secret::SecretInput;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let mut candidate = fixture().to_vec();
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
    let result = restore_vault(&backup, &target, proof(data), &digest);
    if mutations.is_empty() {
        assert!(result.is_ok());
    } else if result.is_err() {
        assert_restore_cleanup(&target);
        if data.get(2).is_some_and(|byte| byte & 0x0f == 1) {
            fs::write(&backup, fixture()).expect("rewrite fixed restore fixture");
            let fixture_digest = format!("{:x}", Sha256::digest(fixture()));
            assert!(restore_vault(&backup, &target, proof(data), &fixture_digest).is_ok());
        }
    }
});

const PASSWORD: &[u8] = b"fuzz-fixture-password";
const RECOVERY_KEY: &[u8] =
    b"RKREC1-EVVJDV-IKDIP7-2KSCPN-N5D26G-Y6MJS2-AYI7HZ-4JZP6Z-TZ5MGK-WKTOLR-GVVQ";
const FIXTURE_BASE64: &str = include_str!("../fixtures/restore.rkbackup.base64");

fn proof(data: &[u8]) -> RestoreProof {
    if data.first() == Some(&b'R') {
        RestoreProof::RecoveryKey(SecretInput::from_slice(RECOVERY_KEY))
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

fn fixture() -> &'static [u8] {
    static FIXTURE: OnceLock<Vec<u8>> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let encoded = FIXTURE_BASE64
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        BASE64
            .decode(&encoded)
            .expect("decode fixed restore fixture")
    })
}
