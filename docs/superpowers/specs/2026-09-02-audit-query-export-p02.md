# Rekey v2 P-02 Audit Query and Export

**Date:** 2026-09-02
**Status:** Implemented and verified
**Depends on:** Credential Authority v2 Foundation, P-01
**Scope:** local Admin audit queries, stable pagination, redacted JSON, and secure local export

## 1. Goal

P-02 lets the local operator inspect Rekey's durable audit trail without opening
SQLite directly. Queries stay inside the AuthorityWorker that owns the database
connection, and only the owner-checked Admin socket exposes them. The Agent
socket gains no audit or Secret-reading operation.

This specification adds no schema migration, background service, remote audit
sink, SIEM protocol, WORM store, legal hold, or automatic deletion policy.

## 2. User-visible commands

```text
rekey audit list [--request ID] [--session ID] [--action ID]
                 [--credential ID] [--outcome VALUE]
                 [--since-ms EPOCH_MS] [--until-ms EPOCH_MS]
                 [--snapshot-max-sequence N] [--before-sequence N] [--limit N]

rekey audit export --output FILE [--request ID] [--session ID]
                   [--action ID] [--credential ID] [--outcome VALUE]
                   [--since-ms EPOCH_MS] [--until-ms EPOCH_MS]
```

`audit list` prints one JSON page to stdout. Its default limit is 50 and its
hard maximum is 100. A continuation passes both `snapshot_max_sequence` and the
exclusive `next_before_sequence` returned by the previous page; callers do not
construct or reinterpret either value as a time.

All supplied filters are intersected. `since_ms` and `until_ms` are inclusive,
must be non-negative, and are rejected when `since_ms > until_ms`. IDs and
outcomes are exact matches. Unknown flags, malformed IDs, zero/oversized limits,
and invalid time bounds fail as `USAGE` before IPC.

`audit export` captures one stable high-water mark, fetches bounded pages, and
writes a JSON Lines snapshot to a new local file. It does not accept a cursor or
page limit because a successful export covers the complete matching snapshot.

## 3. Query and pagination semantics

Audit rows are ordered by `sequence DESC`. The first query captures the maximum
audit sequence visible at query start as `snapshot_max_sequence`. Every later
page applies both of these bounds:

```text
sequence <= snapshot_max_sequence
sequence < before_sequence
```

New audit commits therefore never duplicate, reorder, or enter an in-progress
pagination snapshot. Deletions are not part of P-02. Each Authority request
reads at most 1,000 consecutive rows in sequence order plus one lookahead row,
then applies the requested filters inside that bounded window. A page returns at
most the requested number of matching records plus a nullable
`next_before_sequence`.

The cursor is the exclusive sequence bound after the last scanned row. It can
therefore be present on an empty or underfilled page when more rows remain to be
scanned. Clients must continue until the cursor is null; `audit export` does so
automatically. This scan bound prevents a selective or no-match filter from
occupying the single AuthorityWorker for an unbounded table scan.

The query executes as one bounded read inside AuthorityWorker and does not keep
a SQLite transaction or lock alive while the response is written. A malformed
persisted row, negative stored version, invalid identifier length, or storage
read failure returns the existing integrity/storage error; rows are never
silently skipped or partially decoded.

The Authority may serve audit queries while locked because audit rows contain no
credential plaintext and incident inspection must not require decrypting the
vault. A faulted Authority preserves the existing fail-stop boundary and rejects
the query. Queries are not themselves appended to the same audit stream: doing
so once per pagination request would recursively change and amplify the dataset.

## 4. IPC contract

One Admin message type, `AuditQuery`, is added. Its JSON metadata contains the
optional filters, `snapshot_max_sequence`, exclusive `before_sequence`, and the
bounded limit. Its request body is empty.

The successful response metadata is `{}`. The response body contains the
self-describing UTF-8 JSON page so the existing 64-KiB metadata ceiling does not
become the page-size contract and the frame header remains the sole body-length
source; the normal 4-MiB response-body ceiling still applies. The Broker
serializes the complete page and checks that ceiling before writing any success
frame.

The Agent channel rejects the new Admin message exactly like every other Admin
type. The CLI remains an IPC-only client and does not link SQLite, crypto,
`rekey-vault`, or `rekey-broker`.

## 5. Public audit record

The P-02 JSON schema is `rekey.audit.v1`. Each record contains only:

- sequence, event ID, event type, outcome, reason code, and creation time;
- nullable request, session, action, credential, principal, and policy-rule IDs;
- nullable action, credential, and policy versions;
- nullable policy digest, upstream status, and latency.

Typed identifiers use their canonical UUID text form; the 16-byte event ID and
policy digest use lowercase hexadecimal. Numbers stay JSON numbers and absent
values stay `null`.

`authorization.resource_id` and `authorization.parameter_hash` are deliberately
omitted from list and export output. They can enable correlation or offline
guessing of low-entropy parameters and are not needed for the P-02 filters.
Secret values, request/response bodies, headers, raw errors, salts, nonces,
ciphertexts, capability tokens, and recovery material were never valid audit
fields and cannot appear in the public record.

The schema is explicit rather than a generic SQLite-row serializer. Adding a
field requires a later spec and disclosure review; unknown response fields are
rejected by the CLI.

## 6. Export format and filesystem safety

The export file is UTF-8 JSON Lines in newest-first order:

1. one `rekey.audit.export.v1` header with creation time, filters, schema, and
   `snapshot_max_sequence`;
2. zero or more `rekey.audit.v1` event records;
3. one `rekey.audit.export.complete.v1` trailer with the exact row count.

The CLI opens the requested path with create-new and mode `0600`, refuses an
existing path or symlink, writes only records returned by the Admin endpoint,
flushes and `fsync`s the file, then `fsync`s its parent directory before printing
a success receipt. It re-checks the opened file is a regular file owned by the
current effective UID with mode `0600` before writing audit data.

If IPC, decoding, output, flush, file sync, or parent sync fails, the command
returns a non-zero error and no success receipt. A partial create-new file may
remain as explicit failure evidence and is never resumed or overwritten; the
operator chooses a new path or deliberately removes it after inspection.

Export content is redacted operational metadata, not a Credential backup and
not encrypted by Rekey. Operators must still protect it as sensitive metadata.

## 7. Retention and backup boundary

P-02 retains audit rows for the lifetime of the local vault. There is no TTL,
size-triggered pruning, `audit clear`, or retention setting. Existing encrypted
backups capture the audit rows present at their snapshot time, and restore keeps
that historical snapshot exactly; export neither deletes nor marks rows.

Configurable retention, deletion, legal hold, remote durability, transactional
outbox, WORM, and customer SIEM delivery remain E-04 work. P-02's stable local
JSON schema is an input to that future design, not a claim that enterprise audit
delivery exists.

## 8. Required verification

P-02 is complete only when all of the following are fresh and passing:

1. Store contracts cover each filter, filter intersection, inclusive time
   bounds, newest-first ordering, empty results, the 1,000-row scan bound,
   continuation after an empty scan window, hard page bounds, and stable
   high-water pagination while new rows are committed.
2. Persisted negative versions, malformed identifier lengths, oversized output,
   and storage failures fail clearly without returning partial rows.
3. Authority and Admin IPC tests prove locked reads work, faulted reads fail,
   bodies are rejected, limits are enforced, and response/body binding holds.
4. Agent IPC adversarial tests reject `AuditQuery` and retain the no-secret-read
   mechanical contract.
5. Real `rekeyd` + `rekey` black-box tests exercise every filter, pagination,
   empty output, JSON decoding, and a snapshot that excludes later audit rows.
6. Export tests prove header/event/trailer counts, `0600`, owner and regular-file
   checks, create-new behavior, symlink/existing-file rejection, parent-fsync
   failure, partial-file failure semantics, and no success receipt on failure.
7. Canary scans prove credentials, passwords, recovery keys, capability tokens,
   request/response bodies, resource IDs, and parameter hashes do not enter list
   or export output.
8. `cargo check --workspace`, `cargo test --workspace`, `cargo fmt --all --check`,
   repository mechanical contracts, and exact-head CI pass.
9. README, user guide, operations runbook, threat model, closeout plan, and
   Feature Truth Matrix describe P-02 without raising G1/G2, Connector, SIEM,
   enterprise, or release maturity.

## 9. Non-goals

- Audit deletion, pruning, compaction, configurable retention, or legal hold.
- Tail/follow, subscriptions, streaming IPC, dashboards, metrics, or tracing.
- Remote collectors, syslog, OpenTelemetry logs, SIEM, WORM, or signed exports.
- Agent-visible audit APIs or direct CLI access to the vault database.
- Full forensic erasure, tamper-evident external anchoring, or rollback detection.
- Export encryption, upload, rotation, scheduling, or background jobs.
- Querying by fields deliberately omitted from the public P-02 record.
