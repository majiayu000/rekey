use sha2::{Digest, Sha256};

/// Schema v25. This SQL text is the single source of truth; `schema_digest()`
/// hashes its normalized form to detect accidental drift, not tampering.
pub const SCHEMA_SQL: &str = r#"
CREATE TABLE vault_header (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version     INTEGER NOT NULL CHECK (format_version = 25),
    vault_id           BLOB NOT NULL CHECK (length(vault_id) = 16),
    generation         BLOB NOT NULL CHECK (length(generation) = 8 AND generation != zeroblob(8)),
    generation_mac     BLOB NOT NULL CHECK (length(generation_mac) = 32),
    crypto_suite       TEXT NOT NULL CHECK (crypto_suite = 'rkca-aes256gcm-argon2id-hkdfsha256-v1'),
    created_at_ms      INTEGER NOT NULL,
    schema_digest      BLOB NOT NULL CHECK (length(schema_digest) = 32),
    integrity_nonce    BLOB NOT NULL CHECK (length(integrity_nonce) = 12),
    integrity_ciphertext BLOB NOT NULL
) STRICT;

CREATE TABLE key_wrappers (
    wrapper_id         BLOB PRIMARY KEY CHECK (length(wrapper_id) = 16),
    wrapper_kind       TEXT NOT NULL CHECK (wrapper_kind IN ('password', 'recovery')),
    state              TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    kdf_algorithm      TEXT NOT NULL CHECK (
        (wrapper_kind = 'password' AND kdf_algorithm = 'argon2id') OR
        (wrapper_kind = 'recovery' AND kdf_algorithm = 'hkdf-sha256')
    ),
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
    kind               TEXT NOT NULL CHECK (kind IN ('opaque-token', 'github-app-installation', 'vault-kv-v2-source', 'vault-dynamic-source', 'keycloak-token-exchange', 'gcp-secret-manager-source', 'aws-secrets-manager-source', 'azure-key-vault-source', 'onepassword-connect-source', 'macos-keychain-source')),
    state              TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    current_version    INTEGER NOT NULL CHECK (current_version >= 1),
    created_at_ms      INTEGER NOT NULL,
    updated_at_ms      INTEGER NOT NULL,
    revoked_at_ms      INTEGER,
    state_nonce        BLOB NOT NULL CHECK (length(state_nonce) = 12),
    state_ciphertext   BLOB NOT NULL CHECK (length(state_ciphertext) = 16)
) STRICT;

CREATE TABLE credential_versions (
    credential_id      BLOB NOT NULL REFERENCES credentials(credential_id),
    version            INTEGER NOT NULL CHECK (version >= 1),
    state              TEXT NOT NULL CHECK (state IN ('active', 'retired', 'revoked')),
    aad_version        INTEGER NOT NULL CHECK (aad_version = 1),
    crypto_suite       TEXT NOT NULL CHECK (crypto_suite = 'rkca-aes256gcm-argon2id-hkdfsha256-v1'),
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
    native_plugin_json             TEXT,
    text_stream_json              TEXT,
    action_id                     BLOB NOT NULL CHECK (length(action_id) = 16),
    version                       INTEGER NOT NULL CHECK (version >= 1),
    name                          TEXT NOT NULL,
    state                         TEXT NOT NULL CHECK (state IN ('active', 'retired', 'disabled')),
    credential_id                 BLOB NOT NULL REFERENCES credentials(credential_id),
    origin                        TEXT NOT NULL,
    method                        TEXT NOT NULL,
    target_json                   TEXT NOT NULL,
    auth_header                   TEXT NOT NULL,
    auth_prefix                   TEXT NOT NULL,
    request_max_bytes             INTEGER NOT NULL,
    allowed_extra_headers_json    TEXT NOT NULL,
    response_max_bytes            INTEGER NOT NULL,
    allowed_response_headers_json TEXT NOT NULL,
    timeout_ms                    INTEGER NOT NULL,
    created_at_ms                 INTEGER NOT NULL,
    seal_nonce                    BLOB NOT NULL CHECK (length(seal_nonce) = 12),
    seal_ciphertext               BLOB NOT NULL CHECK (length(seal_ciphertext) = 16),
    PRIMARY KEY (action_id, version)
) STRICT;

CREATE UNIQUE INDEX one_active_action_version
ON actions(action_id) WHERE state = 'active';

CREATE TABLE audit_retention (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    days INTEGER CHECK (days IS NULL OR days > 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    seal_nonce BLOB NOT NULL CHECK (length(seal_nonce) = 12),
    seal_ciphertext BLOB NOT NULL CHECK (length(seal_ciphertext) = 16)
) STRICT;

CREATE TABLE policy_state (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    mode               TEXT NOT NULL CHECK (mode IN ('personal', 'team')),
    trust_installed    INTEGER NOT NULL CHECK (trust_installed IN (0, 1)),
    bundle_activated   INTEGER NOT NULL CHECK (bundle_activated IN (0, 1)),
    signer_id          BLOB CHECK (signer_id IS NULL OR length(signer_id) = 16),
    highest_version    INTEGER,
    policy_digest      BLOB CHECK (policy_digest IS NULL OR length(policy_digest) = 32),
    bundle_digest      BLOB CHECK (bundle_digest IS NULL OR length(bundle_digest) = 32),
    updated_at_ms      INTEGER NOT NULL,
    seal_nonce         BLOB NOT NULL CHECK (length(seal_nonce) = 12),
    seal_ciphertext    BLOB NOT NULL CHECK (length(seal_ciphertext) = 16),
    CHECK (
        (trust_installed = 0 AND signer_id IS NULL) OR
        (trust_installed = 1 AND signer_id IS NOT NULL)
    ),
    CHECK (
        (bundle_activated = 0 AND highest_version IS NULL
            AND policy_digest IS NULL AND bundle_digest IS NULL) OR
        (bundle_activated = 1 AND trust_installed = 1 AND highest_version >= 1
            AND policy_digest IS NOT NULL AND bundle_digest IS NOT NULL)
    )
) STRICT;

CREATE TABLE policy_trust (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    signer_id          BLOB NOT NULL UNIQUE CHECK (length(signer_id) = 16),
    algorithm          TEXT NOT NULL CHECK (algorithm IN ('ed25519', 'secure-enclave-p256')),
    public_key         BLOB NOT NULL CHECK ((algorithm = 'ed25519' AND length(public_key) = 32)
        OR (algorithm = 'secure-enclave-p256' AND length(public_key) = 65)),
    installed_at_ms    INTEGER NOT NULL,
    seal_nonce         BLOB NOT NULL CHECK (length(seal_nonce) = 12),
    seal_ciphertext    BLOB NOT NULL CHECK (length(seal_ciphertext) = 16)
) STRICT;

CREATE TABLE policy_bundle (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    signer_id          BLOB NOT NULL CHECK (length(signer_id) = 16),
    version            INTEGER NOT NULL CHECK (version >= 1),
    expires_at_ms      INTEGER NOT NULL,
    policy_digest      BLOB NOT NULL CHECK (length(policy_digest) = 32),
    bundle_digest      BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    bundle_json        BLOB NOT NULL CHECK (length(bundle_json) <= 65536),
    activated_at_ms    INTEGER NOT NULL,
    seal_nonce         BLOB NOT NULL CHECK (length(seal_nonce) = 12),
    seal_ciphertext    BLOB NOT NULL CHECK (length(seal_ciphertext) = 16)
) STRICT;

CREATE TABLE workload_token_uses (
    replay_digest      BLOB PRIMARY KEY CHECK (length(replay_digest) = 32),
    expires_at_ms      INTEGER NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    CHECK (created_at_ms >= 0 AND expires_at_ms > created_at_ms)
) STRICT;

CREATE TABLE profile_usage (
 request_id BLOB PRIMARY KEY CHECK(length(request_id)=16),
 principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
 instance_slug TEXT NOT NULL,
 utc_day INTEGER NOT NULL CHECK(utc_day>=0),
 started_at_ms INTEGER NOT NULL CHECK(started_at_ms>=0),
 context_json TEXT NOT NULL,
 generation_max_output INTEGER CHECK(generation_max_output>0),
 output_tokens INTEGER CHECK(output_tokens>=0),
 source TEXT CHECK(source IN ('measured','indeterminate','not-applicable')),
 terminal_json TEXT,
 settled_at_ms INTEGER CHECK(settled_at_ms>=0),
 CHECK ((output_tokens IS NULL AND source IS NULL AND terminal_json IS NULL AND settled_at_ms IS NULL)
     OR (output_tokens IS NOT NULL AND source IS NOT NULL AND terminal_json IS NOT NULL AND settled_at_ms IS NOT NULL))
) STRICT;
CREATE INDEX profile_usage_bucket ON profile_usage(principal_id,instance_slug,utc_day);
CREATE TABLE profile_usage_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 revision INTEGER NOT NULL CHECK(revision>=0), record_count INTEGER NOT NULL CHECK(record_count>=0),
 records_digest BLOB NOT NULL CHECK(length(records_digest)=32),
 seal_nonce BLOB NOT NULL CHECK(length(seal_nonce)=12), seal_ciphertext BLOB NOT NULL CHECK(length(seal_ciphertext)=16)
) STRICT;

CREATE TABLE audit_events (
    sequence            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
    request_id          BLOB CHECK (request_id IS NULL OR length(request_id) = 16),
    session_id          BLOB CHECK (session_id IS NULL OR length(session_id) = 16),
    action_id           BLOB CHECK (action_id IS NULL OR length(action_id) = 16),
    action_version      INTEGER,
    credential_id       BLOB CHECK (credential_id IS NULL OR length(credential_id) = 16),
    credential_version  INTEGER,
    principal_id        BLOB CHECK (principal_id IS NULL OR length(principal_id) = 16),
    policy_version      INTEGER,
    policy_digest       BLOB CHECK (policy_digest IS NULL OR length(policy_digest) = 32),
    policy_rule_id      BLOB CHECK (policy_rule_id IS NULL OR length(policy_rule_id) = 16),
    approval_request_id BLOB CHECK (approval_request_id IS NULL OR length(approval_request_id) = 16),
    approval_id         BLOB CHECK (approval_id IS NULL OR length(approval_id) = 16),
    approver_id         BLOB CHECK (approver_id IS NULL OR length(approver_id) = 16),
    resource_type       TEXT,
    resource_id         TEXT,
    parameter_hash      BLOB CHECK (parameter_hash IS NULL OR length(parameter_hash) = 32),
    event_type          TEXT NOT NULL,
    outcome             TEXT NOT NULL,
    reason_code         TEXT NOT NULL,
    upstream_status     INTEGER,
    latency_ms          INTEGER,
    metadata_json          TEXT,
    created_at_ms       INTEGER NOT NULL,
    CHECK (
        (principal_id IS NULL AND policy_version IS NULL AND policy_digest IS NULL
            AND policy_rule_id IS NULL AND resource_type IS NULL
            AND resource_id IS NULL AND parameter_hash IS NULL)
        OR
        (principal_id IS NOT NULL AND policy_version >= 1 AND policy_digest IS NOT NULL
            AND resource_type IS NOT NULL AND resource_id IS NOT NULL
            AND parameter_hash IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_execution_started_per_request
ON audit_events(request_id) WHERE event_type = 'execution.started';

CREATE UNIQUE INDEX one_execution_terminal_per_request
ON audit_events(request_id)
WHERE event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate');

CREATE TABLE vault_lease_journal (
 registration_id BLOB PRIMARY KEY CHECK(length(registration_id)=16),
 execution_request_id BLOB NOT NULL CHECK(length(execution_request_id)=16),
 session_id BLOB NOT NULL CHECK(length(session_id)=16),
 action_id BLOB NOT NULL CHECK(length(action_id)=16), action_version INTEGER NOT NULL CHECK(action_version>=1),
 credential_id BLOB NOT NULL CHECK(length(credential_id)=16), credential_version INTEGER NOT NULL CHECK(credential_version>=1),
 source_ref_hash BLOB NOT NULL CHECK(length(source_ref_hash)=32), revision INTEGER NOT NULL CHECK(revision>=1),
 phase TEXT NOT NULL CHECK(phase IN ('acquire_intent','issued','renewing','cleanup_started','complete')),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=created_at_ms),
 issued_at_ms INTEGER, last_confirmed_expires_at_ms INTEGER, renewable INTEGER CHECK(renewable IN(0,1)),
 cleanup_outcome TEXT NOT NULL CHECK(cleanup_outcome IN('none','unconfirmed','confirmed')), completed_at_ms INTEGER,
 last_audit_event_id BLOB NOT NULL CHECK(length(last_audit_event_id)=16) REFERENCES audit_events(event_id) ON DELETE RESTRICT,
 aad_version INTEGER NOT NULL CHECK(aad_version=1), crypto_suite TEXT NOT NULL CHECK(crypto_suite='rkca-aes256gcm-argon2id-hkdfsha256-v1'),
 dek_nonce BLOB NOT NULL CHECK(length(dek_nonce)=12), wrapped_dek BLOB NOT NULL CHECK(length(wrapped_dek)=48),
 payload_nonce BLOB NOT NULL CHECK(length(payload_nonce)=12), encrypted_payload BLOB NOT NULL CHECK(length(encrypted_payload) BETWEEN 16 AND 8192),
 FOREIGN KEY(credential_id,credential_version) REFERENCES credential_versions(credential_id,version) ON DELETE RESTRICT
) STRICT;
CREATE INDEX lease_source_phase ON vault_lease_journal(source_ref_hash,phase);
CREATE INDEX lease_recovery_order ON vault_lease_journal(phase,updated_at_ms,registration_id);
CREATE TABLE vault_lease_journal_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL CHECK(revision>=0), record_count INTEGER NOT NULL CHECK(record_count>=0),
 last_audit_event_id BLOB CHECK(last_audit_event_id IS NULL OR length(last_audit_event_id)=16) REFERENCES audit_events(event_id) ON DELETE RESTRICT,
 records_digest BLOB NOT NULL CHECK(length(records_digest)=32), seal_nonce BLOB NOT NULL CHECK(length(seal_nonce)=12),
 seal_ciphertext BLOB NOT NULL CHECK(length(seal_ciphertext)=16)
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
