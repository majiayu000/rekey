//! Process-level gate: a real rekeyd must fail before binding either UDS when
//! persisted crypto discriminators are not implemented by this binary.

use std::process::Command;

use rekey_vault::bootstrap::init_vault;
use rekey_vault::crypto::kdf::Argon2Params;
use rekey_vault::paths;
use rekey_vault::secret::SecretInput;

const PASSWORD: &[u8] = b"format rejection test password";
const TEST_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};

#[test]
fn real_rekeyd_rejects_unknown_crypto_format_before_binding_uds() {
    for update in [
        "UPDATE vault_header SET crypto_suite = 'future-suite'",
        "UPDATE key_wrappers SET state = 'disabled', kdf_algorithm = 'future-kdf' WHERE wrapper_kind = 'recovery'",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        init_vault(&state_dir, &SecretInput::from_slice(PASSWORD), TEST_PARAMS).unwrap();

        let connection = rusqlite::Connection::open(paths::vault_db(&state_dir)).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection.execute(update, []).unwrap();
        drop(connection);

        let output = Command::new(env!("CARGO_BIN_EXE_rekeyd"))
            .args([
                "serve",
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--idle-lock",
                "15m",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(5));
        assert!(!state_dir.join("runtime/admin.sock").exists());
        assert!(!state_dir.join("runtime/agent.sock").exists());
    }
}
