use std::path::{Path, PathBuf};

pub const VAULT_DB_FILE: &str = "vault.sqlite3";
pub const BROKER_LOCK_FILE: &str = "broker.lock";
pub const RUNTIME_DIR: &str = "runtime";
pub const ADMIN_SOCKET_FILE: &str = "admin.sock";
pub const AGENT_SOCKET_FILE: &str = "agent.sock";

pub fn vault_db(state_dir: &Path) -> PathBuf {
    state_dir.join(VAULT_DB_FILE)
}

pub fn broker_lock(state_dir: &Path) -> PathBuf {
    state_dir.join(BROKER_LOCK_FILE)
}

pub fn runtime_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(RUNTIME_DIR)
}

pub fn admin_socket(state_dir: &Path) -> PathBuf {
    runtime_dir(state_dir).join(ADMIN_SOCKET_FILE)
}

pub fn agent_socket(state_dir: &Path) -> PathBuf {
    runtime_dir(state_dir).join(AGENT_SOCKET_FILE)
}
