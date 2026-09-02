#![no_main]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use libfuzzer_sys::fuzz_target;
use rekey_vault::bootstrap::{RestoreProof, restore_vault};
use rekey_vault::secret::SecretInput;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let Ok(work) = tempfile::tempdir() else {
        return;
    };
    let backup = work.path().join("candidate.rkbackup");
    let target = work.path().join("restore");
    if fs::write(&backup, data).is_err() || fs::create_dir(&target).is_err() {
        return;
    }
    if fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).is_err() {
        return;
    }
    let digest = format!("{:x}", Sha256::digest(data));
    let proof = RestoreProof::Password(SecretInput::from_slice(b"fuzz-only-proof"));
    let _ = restore_vault(&backup, &target, proof, &digest);
});
