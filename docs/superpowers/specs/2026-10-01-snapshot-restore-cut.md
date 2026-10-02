# H2: actual backup snapshot cut and offline restore receipt

Frozen 2026-10-01 before implementation. Accepted scope is manual primary/standby
DR in external-capabilities.md, using completed encrypted artifacts and receipts.
Minimal change: seven existing production files, existing tests, one spec; no new
source module, schema/opcode/dependency, service, config or fencing mechanism.

## Public contract

Extend the existing BackupInfo and deny-unknown-fields BackupReceipt with required
`snapshot_cut`: { "audit_sequence": unsigned64, "policy": null |
{ "version": unsigned64, "bundle_sha256": stored lowercase64hex } }.
Share these pure DTOs in existing domain IPC models. No legacy JSON alias or shim.
`audit_sequence` is MAX(sequence) actually in the completed snapshot, zero only
when no rows exist. Reject invalid/negative/overflow columns using existing typed
storage/integrity error paths. `policy` is the persisted bundle version/digest,
not a claim that its trust, time or directory authorization is currently valid.

SQLite online Backup API must complete before reading this cut from the actual
destination connection, under the existing sole Worker operation. Retain held
file identity and durable export gates. Backup release/created audits commit
later in the source; they are not part of this cut. created_at_ms remains the
existing export-start wall instant and must not substitute for commit sequence.

Use exact existing audit_events.sequence and policy_bundle singleton
version/bundle_digest columns, checked typed conversions and existing digest
encoding. Do not read credential payloads or add a secret-reading/SQL Admin API.
Whole snapshot sha256 already binds replay, lease journal, trust and all other
bytes; do not add per-table hashes/counts or a second audit serialization digest.

Offline restore retains original proof, expected input SHA, empty-target, file,
crypto, policy, journal and installation checks. Read the input-derived cut after
those checks and before appending RESTORE_COMPLETED. Do not recompute the input
SHA from the modified restored database. Success returns a pure fixed JSON
RestoreReceipt: vault_id, format_version, input_sha256_hex, output_path (actual
state directory), snapshot_cut. Input digest is the actual copied-and-hashed
artifact digest; identifiers are actual recovered identities. No partial success
JSON on failure; preserve error codes/cleanup and hidden TTY/explicit stdin.
CLI restore remains a pure rekeyd delegate; it links no DB, crypto or HTTP.

Operator compares computed restore cut and input SHA against the original backup
receipt. H2 does not accept/claim to have validated an arbitrary supplied node or
fencing receipt. H1 transports the complete public receipt unchanged and already
rejects conflicting completed objects; no extra sync bookkeeping is required.

## Verification and boundaries

Use socketless real Worker/SQLite backups and offline restore: known committed
audit/policy then backup, later source changes, recover selected older artifact
and compare its original cut before the new restore audit. Inspect actual
archive/installed records; preserve replay rejection and journal consistency.
Cover no-policy, typed corrupt data, expected-hash/wrong-proof/failure cleanup,
cross-vault actual identity, nonempty target and real local bootstrap lock.
Update only direct breaking restore-return/BackupReceipt test callers. Do not
claim old generated fixtures or empty test filters as passing behavior.

This identifies the selected artifact's actual recovery point. It does not prove
latest state, no missing revocation/replay history, external effects, old-primary
isolation, automatic promotion, continuous replication, HA or RPO/RTO. Two
copies of one vault retain historical VRK and can be dangerous concurrently.
External fencing, traffic switching and actual two-node drills remain deferred.
Fresh focused/check/Clippy/fmt/mechanical contracts and independent review at
exact source SHA required. Full sockets/TTY workspace gate remains unpassed;
no commit/publication. H2 writer starts only after C2 stable integration review.
## Review clarification: exact restore path (2026-10-01)

The JSON output path must represent the actual canonical target exactly. Native
Unix paths containing invalid UTF8 cannot be represented by this receipt. Reject
such a canonical target with the existing RestoreFailed error before copying,
proof/decryption or database installation. Do not emit lossy display text or add
a second byte-path encoding. Resolve and check once at the trusted bootstrap
boundary; carry a checked String in RestoreInfo into the pure JSON receipt.
Retain empty-target/file cleanup and valid UTF8 paths including non-ASCII names.
Test the invalid native path conversion and, where the filesystem accepts that
name, real offline restore refusal with no installed database. Preserve a
positive canonical UTF8 restore and exact JSON serialization.
