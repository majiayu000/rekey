use sha2::{Digest, Sha256};

/// Schema v2. This SQL text is the single source of truth; `schema_digest()`
/// hashes its normalized form to detect accidental drift, not tampering.
pub const SCHEMA_SQL: &str = r#"
CREATE TABLE vault_header (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version     INTEGER NOT NULL CHECK (format_version = 2),
    vault_id           BLOB NOT NULL CHECK (length(vault_id) = 16),
    crypto_suite       TEXT NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    schema_digest      BLOB NOT NULL CHECK (length(schema_digest) = 32),
    integrity_nonce    BLOB NOT NULL CHECK (length(integrity_nonce) = 12),
    integrity_ciphertext BLOB NOT NULL
) STRICT;

CREATE TABLE key_wrappers (
    wrapper_id         BLOB PRIMARY KEY CHECK (length(wrapper_id) = 16),
    wrapper_kind       TEXT NOT NULL CHECK (wrapper_kind IN ('password', 'recovery')),
    state              TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    kdf_algorithm      TEXT NOT NULL,
    kdf_params_json    TEXT NOT NULL,
    salt               BLOB NOT NULL,
    nonce              BLOB NOT NULL CHECK (length(nonce) = 12),
    wrapped_vrk        BLOB NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    disabled_at_ms     INTEGER
) STRICT;

CREATE UNIQUE INDEX one_active_password_wrapper
ON key_wrappers(wrapper_kind) WHERE wrapper_kind = 'password' AND state = 'active';

CREATE TABLE credentials (
    credential_id      BLOB PRIMARY KEY CHECK (length(credential_id) = 16),
    label              TEXT NOT NULL UNIQUE,
    kind               TEXT NOT NULL CHECK (kind = 'opaque-token'),
    state              TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    current_version    INTEGER NOT NULL CHECK (current_version >= 1),
    created_at_ms      INTEGER NOT NULL,
    updated_at_ms      INTEGER NOT NULL,
    revoked_at_ms      INTEGER
) STRICT;

CREATE TABLE credential_versions (
    credential_id      BLOB NOT NULL REFERENCES credentials(credential_id),
    version            INTEGER NOT NULL CHECK (version >= 1),
    state              TEXT NOT NULL CHECK (state IN ('active', 'retired', 'revoked')),
    aad_version        INTEGER NOT NULL CHECK (aad_version = 1),
    crypto_suite       TEXT NOT NULL,
    dek_nonce          BLOB NOT NULL CHECK (length(dek_nonce) = 12),
    wrapped_dek        BLOB NOT NULL,
    payload_nonce      BLOB NOT NULL CHECK (length(payload_nonce) = 12),
    encrypted_payload  BLOB NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    retired_at_ms      INTEGER,
    PRIMARY KEY (credential_id, version)
) STRICT;

CREATE UNIQUE INDEX one_active_version_per_credential
ON credential_versions(credential_id) WHERE state = 'active';

CREATE TABLE actions (
    action_id                     BLOB NOT NULL CHECK (length(action_id) = 16),
    version                       INTEGER NOT NULL CHECK (version >= 1),
    name                          TEXT NOT NULL,
    state                         TEXT NOT NULL CHECK (state IN ('active', 'retired', 'disabled')),
    credential_id                 BLOB NOT NULL REFERENCES credentials(credential_id),
    origin                        TEXT NOT NULL,
    method                        TEXT NOT NULL,
    exact_path                    TEXT NOT NULL,
    auth_header                   TEXT NOT NULL,
    auth_prefix                   TEXT NOT NULL,
    request_max_bytes             INTEGER NOT NULL,
    allowed_extra_headers_json    TEXT NOT NULL,
    response_max_bytes            INTEGER NOT NULL,
    allowed_response_headers_json TEXT NOT NULL,
    timeout_ms                    INTEGER NOT NULL,
    created_at_ms                 INTEGER NOT NULL,
    PRIMARY KEY (action_id, version)
) STRICT;

CREATE UNIQUE INDEX one_active_action_version
ON actions(action_id) WHERE state = 'active';

CREATE TABLE audit_events (
    sequence            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
    request_id          BLOB CHECK (request_id IS NULL OR length(request_id) = 16),
    session_id          BLOB CHECK (session_id IS NULL OR length(session_id) = 16),
    action_id           BLOB CHECK (action_id IS NULL OR length(action_id) = 16),
    action_version      INTEGER,
    credential_id       BLOB CHECK (credential_id IS NULL OR length(credential_id) = 16),
    credential_version  INTEGER,
    event_type          TEXT NOT NULL,
    outcome             TEXT NOT NULL,
    reason_code         TEXT NOT NULL,
    upstream_status     INTEGER,
    latency_ms          INTEGER,
    created_at_ms       INTEGER NOT NULL
) STRICT;
"#;

pub fn schema_digest() -> [u8; 32] {
    let normalized: String = SCHEMA_SQL
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let digest = Sha256::digest(normalized.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
