//! Process-level gate: a real rekeyd must fail before binding either UDS when
//! persisted crypto discriminators are not implemented by this binary.

use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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

fn run_rekeyd_bounded(state_dir: &std::path::Path, case_name: &str) -> ExitStatus {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rekeyd"))
        .args([
            "serve",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--idle-lock",
            "15m",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("rekeyd did not reject {case_name} within 5 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_rekeyd_rejects_unknown_crypto_format_before_binding_uds() {
    for (case_name, schema_edit, update) in [
        (
            "unknown crypto suite",
            None,
            "UPDATE vault_header SET crypto_suite = 'future-suite'",
        ),
        (
            "unknown KDF algorithm",
            None,
            "UPDATE key_wrappers SET state = 'disabled', kdf_algorithm = 'future-kdf' WHERE wrapper_kind = 'recovery'",
        ),
        (
            "NULL crypto suite",
            Some((
                "vault_header",
                "crypto_suite       TEXT NOT NULL",
                "crypto_suite       TEXT",
            )),
            "UPDATE vault_header SET crypto_suite = NULL",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        init_vault(&state_dir, &SecretInput::from_slice(PASSWORD), TEST_PARAMS).unwrap();

        let connection = rusqlite::Connection::open(paths::vault_db(&state_dir)).unwrap();
        if let Some((table, declaration, nullable)) = schema_edit {
            connection
                .execute_batch("PRAGMA writable_schema = ON;")
                .unwrap();
            connection
                .execute(
                    "UPDATE sqlite_schema SET sql = replace(sql, ?2, ?3)
                     WHERE type = 'table' AND name = ?1",
                    [table, declaration, nullable],
                )
                .unwrap();
            drop(connection);
            let connection = rusqlite::Connection::open(paths::vault_db(&state_dir)).unwrap();
            connection.execute(update, []).unwrap();
            drop(connection);
        } else {
            connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            connection.execute(update, []).unwrap();
            drop(connection);
        }

        assert_eq!(run_rekeyd_bounded(&state_dir, case_name).code(), Some(5));
        assert!(!state_dir.join("runtime/admin.sock").exists());
        assert!(!state_dir.join("runtime/agent.sock").exists());
    }
}
