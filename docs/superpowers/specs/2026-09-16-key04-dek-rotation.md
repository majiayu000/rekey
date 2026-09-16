# KEY-04 bounded DEK rotation

Status: implemented and locally verified, 2026-09-16. This is the per-version DEK slice only, not
full KEY-04 or Vault Root Key (VRK) rotation.

## Admin and worker contract

`rekey key rotate-dek [--recovery] [--password-stdin]` is an Admin-only mutation
on the existing Unix socket. Message 38 (`KEY_ROTATE_DEK`) accepts empty JSON
metadata and the existing proof-only secret body. The reply is typed numeric
metadata `{ "rotated_versions": N }` and an empty body. Proof comes from hidden
TTY or explicit stdin, never argv/environment/metadata. Agent calls are rejected.
No new dependency, listener, configuration, schema or migration is introduced.

The AuthorityWorker remains the sole credential/VRK owner. It requires unlocked
state, verifies password or recovery step-up on every call, verifies credential
state seals and version invariants, and processes **all** credential versions,
including retired versions and versions belonging to revoked credentials.

For each version, retain the existing IDs, version, kind, state, AAD version,
crypto suite, timestamps and exact AAD fields. Unwrap the old DEK and decrypt
its payload into Zeroizing buffers. Generate a fresh random DEK and fresh AEAD
nonces; reseal the same payload and wrap the new DEK under the unchanged VRK.
Only `dek_nonce`, `wrapped_dek`, `payload_nonce`, and `encrypted_payload` change.
The existing new-version insertion helper must not be used: it would reset state.
At most one version's plaintext is processed at a time. The existing encrypted
version list may hold the replacement ciphertexts; no whole-vault plaintext
collection, temporary plaintext file, credential value output or audit is allowed.

## Transaction, expiry and failures

Cryptographic preparation occurs before the write transaction; preparation
failure therefore changes no credential row. One SQLite transaction replaces all
four ciphertext fields for every version and inserts `vault.dek_rotated` success
audit. Each UPDATE must affect exactly one row. Any SQL or audit failure rolls
back the complete batch. Audit commit failure faults the worker under the existing
fail-closed contract. Corrupt ciphertext/state faults the worker; unsupported
formats and entropy failures return explicit errors without committing replacements.

Use the existing 25-second Admin mutation deadline and serialized lifecycle
coordination. The worker checks expiry at admission and during preparation. The
store checks again after all updates and success-audit insertion, immediately
before commit. Expired operations return `AUTHORITY_BUSY`, rolling back all updates
and the success audit. Once commit starts, its definitive result is awaited;
there is no cancellable timeout wrapper that can report failure for a successful
commit. SQLite commit duration itself is not interrupted. Client connection loss
cannot undo an accepted operation, as with other admitted Admin mutations.

An empty vault still requires step-up, commits one success audit and returns zero.
Repeating rotation reseals every stored version again with fresh keys/nonces.
Failure audit/fault records may be appended independently under existing worker
behavior, but a failure never retains credential replacements or success audit.

## Unchanged state and limits

The VRK, password/recovery wrappers, credential state seals, policy/approval state,
action versions, capability bindings and desktop authentication state remain
unchanged. Existing capabilities continue to resolve the same credential version.
Neither credential payload values nor provider credentials are rotated.

Backups made before and after the operation remain independently restorable with
their existing unlock factors. This does not revoke old backups, sanitize old
SQLite pages/WAL, erase historical key copies, or remediate a compromised VRK.
VRK rotation and other KEY-04 key lifecycle work remain out of scope.

## Required evidence

Cover multiple credential kinds and active/retired/revoked versions, unchanged
metadata and authenticated plaintext, changed ciphertexts, repeat/empty rotation,
locked/wrong-proof rejection, expiry, a later corrupt version, later SQL failure,
audit failure and expiry immediately before commit with no partial replacement.
Restore backups from both generations. Exercise Admin/Agent boundaries and CLI
secret-canary output. The integration owner runs the full workspace gate.

Local evidence on 2026-09-16: `cargo check --workspace`; four
`rekey-vault --test dek_rotation` tests; the store's targeted precommit-expiry
unit test; one `rekey-broker --test admin_ipc dek_rotation` test; and the
`rekey-cli --test cli_blackbox cli_end_to_end` process test all pass.
The store test directly bypasses admission gates with an expired deadline,
uses a test-only audit trigger to verify all four replacement fields are
already visible inside the transaction, and then proves rollback and absence
of success audit. The integration SQL-wait test separately proves an admitted
operation expires without partial persistence; status blocking by itself is
not treated as a precise SQL execution probe.
