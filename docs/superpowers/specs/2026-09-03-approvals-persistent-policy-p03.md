# Rekey v2 P-03 Approvals and Persistent Policy

**Date:** 2026-09-03
**Status:** Implemented and verified
**Depends on:** Credential Authority v2 Foundation, P-01, P-02
**Scope:** signed local policy bundles, durable activation, and signed one-time or time-window approvals

## 1. Goal

P-03 makes authorization policy survive broker restarts and lets a policy require
one or two named human approvals before a fixed HTTP action can execute. Policy
and approval signatures bind the exact typed authorization inputs; neither an
Agent nor a compromised policy-delivery path can substitute an action, resource,
parameters, principal, session, policy version, or expiry after approval.

Rekey is a verifier and enforcement point in P-03. It does not generate or store
policy-signing or approver private keys, run a remote approval service, provide a
dashboard, or claim enterprise identity. External signers consume the canonical
payloads specified below and return signed JSON artifacts.

## 2. User-visible commands

```text
rekey policy trust install --file TRUST.json --step-up-stdin
rekey policy activate --file BUNDLE.json --step-up-stdin
rekey policy status
rekey approval prepare ACTION_ID@VERSION --capability - [--body-file FILE]
                       [--content-type TYPE] [--header NAME:VALUE]
rekey execute ACTION_ID@VERSION --capability - [--body-file FILE]
              [--content-type TYPE] [--header NAME:VALUE]
              [--approval FILE]...
```

Trust installation is a one-time operation for a vault. `TRUST.json` contains
one Ed25519 policy signer identifier and one raw 32-byte public key encoded as
exactly 64 lowercase hexadecimal characters. It is public verification
material, but the CLI still requires a regular bounded file and sends it only through the owner-checked
Admin socket. The Authority requires an unlock proof, refuses replacement, and
stores the trust record with a VRK-authenticated lifecycle seal.
Retrying the exact same trust record after a lost response is idempotent;
supplying a different signer ID or public key is replacement and is rejected.

```json
{
  "format_version": 1,
  "signer_id": "UUID",
  "algorithm": "ed25519",
  "public_key": "LOWERCASE_HEX"
}
```

The trust file is parsed once as a closed object with recursive duplicate-key
and unknown-field rejection before any record is committed. Its signer ID,
algorithm, and public key must all be canonical.

`policy activate` now accepts only a signed policy bundle. An unsigned snapshot,
unknown signer, malformed signature, expired snapshot, or invalid policy
version fails without changing the active bundle. The first version is `1` and
every later activation must be exactly the next integer. Operators perform
rollback by reissuing the previously accepted contents as that next version;
downgrades and version gaps are never allowed. Retrying the exact active version
and canonical bundle digest after a lost response is idempotent; the same
version with different canonical content is rejected. `i64::MAX` is reserved
and cannot be activated; version exhaustion fails closed as
`policy-version-exhausted` instead of accepting a terminal expiring bundle.

`policy status` reports whether a trust root is installed and whether a
persisted bundle is loaded, plus the signer ID, policy version, expiry, digest,
and one of `unavailable`, `active`, or `expired`. It exposes no public key,
signature, approval grant, or private material. Before first successful unlock
after restart, a persisted bundle is `unavailable`, not optimistically active;
unverified signer, version, expiry, and digest fields remain null.

No Rekey command creates private keys or signatures. That remains the external
signer's responsibility and avoids turning the IPC-only `rekey` client into a
second credential store.

`approval prepare` prints one challenge JSON document to stdout. It shares the
existing execute request-file, header, content-type, capability-stdin, and size
contracts. `execute --approval` accepts one or two repeated paths to regular
files, each bounded to 4 KiB; the CLI rejects stdin, directories, symlinks,
duplicate paths, and more than two grants before connecting. Grant files are
signed authorization artifacts, never private signing keys.

## 3. Signed policy bundle

The JSON envelope is `rekey.policy.bundle.v1`:

```json
{
  "format_version": 1,
  "signer_id": "UUID",
  "snapshot": {},
  "signature": "BASE64URL_NO_PAD"
}
```

The signature input is the byte prefix `RKPOLICY\0\x01` followed by RFC 8785
JCS encoding of the envelope with `signature` omitted. Parsers reject duplicate
keys, unknown fields, non-canonical UUIDs, non-canonical base64url, signatures
other than 64 bytes, and bundles over 64 KiB before verification. Ed25519 is the
only P-03 algorithm and there is exactly one immutable trust root per vault.

The policy digest is exactly `SHA-256(JCS(snapshot))`. The canonical bundle
digest is exactly `SHA-256(JCS(envelope))`, including the signature. Status,
authorization evidence, challenges, and grants use the policy digest; the
persisted bundle seal and activation idempotency use the canonical bundle
digest. Raw JSON whitespace and member order affect neither digest.

The existing `PolicySnapshot` remains the signed payload. Its format version is
raised from `1` to `2` for the breaking P-03 schema and adds a bounded approver
catalog. Each approver has a canonical `approver_id` UUID and one raw Ed25519 public key. The
snapshot contains at most 32 distinct approvers; duplicate IDs or public keys
are invalid.

Policy rules keep exact principal, action version, resource, and parameter-scope
matching. Their effects are:

- `forbid`;
- `permit`;
- `require-approval`, with an explicit allowlist of approver IDs, quorum `1` or
  `2`, and mode `one-time` or `time-window`.

The snapshot uses `approvers` as an array of
`{"approver_id":"UUID","algorithm":"ed25519","public_key":"LOWERCASE_HEX"}`.
Each policy rule keeps the existing string `effect`; `require-approval` also
requires an `approval` object containing `approver_ids`, `quorum`, `mode`, and
`max_uses`; time-window mode additionally requires `max_window_ms`. One-time
mode requires `max_uses` to equal `1`; time-window mode requires a positive
`max_uses` no greater than 10,000. `permit` and `forbid` rules must not contain
`approval`.

A referenced approver ID must exist in the same snapshot's approver catalog,
and quorum cannot exceed the distinct allowlisted approvers. A time-window rule
also declares `max_window_ms`, which must be positive and at most eight hours.
A one-time rule has no window setting. `forbid` continues to win over both
permit and approval rules. A direct permit wins only when no matching approval
rule exists; policy authors cannot accidentally bypass an approval rule by
adding a broad permit.

Overlapping approval rules for the same principal, action, and resource must
have identical approver allowlists, quorum, mode, `max_uses`, and window.
`any-validated` overlaps every exact parameter hash and equal exact hashes
overlap each other; a snapshot with conflicting requirements is invalid. When
identical rules match, the lowest rule ID remains the deterministic determining
rule.

## 4. Durable policy lifecycle

The vault schema initializes one mandatory sealed policy-state singleton with
every new vault. It records whether trust has ever been installed, whether a
bundle has ever been activated, the immutable signer ID, highest accepted
version, policy digest, bundle digest, and update time, using nullable fields
only in the never-installed or never-activated states. Optional sealed trust and
current-bundle rows must exactly match that singleton. Missing singleton state,
an impossible field combination, a missing row named by the state, or any seal
mismatch faults the Authority; deleting an entire optional row can never look
like a fresh vault.

Trust installation and bundle activation are AuthorityWorker mutations. Each
updates the mandatory state, its corresponding record, and the success audit in
one SQLite transaction; an audit failure rolls back the mutation and faults the
Authority under the existing fail-closed contract. The singleton's initial
authenticated state is created while `init` still holds the VRK. Replaying an
older previously valid singleton together with its matching rows remains within
the explicitly documented authenticated-state replay limitation.

P-03 raises the vault format to schema v6. There is no in-place v5 migration or
compatibility reader; existing v5 vaults remain usable only by the earlier
binary and must be recreated or restored through a separately specified future
upgrade path.

The trust and bundle lifecycle seals bind vault ID, record purpose, signer ID,
public-key or bundle digest, policy version, expiry, and timestamps. Direct row
tampering, cross-vault copying, signer substitution, or changing the persisted
version or digest fails integrity verification. The signed bundle is also
verified against the sealed trust root every time it is loaded.

All three lifecycle seals reuse the existing 84-byte `AadV1` encoding and seal
an empty plaintext, producing a 12-byte stored nonce and a 16-byte
authentication tag. P-03 assigns purpose codes `6` (`PolicyState`), `7`
(`PolicyTrust`), and `8` (`PolicyBundle`). `credential_kind` is zero for all
three. Their remaining AAD fields are exact:

| Purpose | `object_id` | `object_version` | `constraints_hash` |
|---|---|---:|---|
| `PolicyState` | sixteen zero bytes | `1` | SHA-256 of the canonical policy-state record |
| `PolicyTrust` | raw 16-byte signer UUID | `1` | SHA-256 of the canonical trust record |
| `PolicyBundle` | raw 16-byte signer UUID | policy version as `u64` | SHA-256 of the canonical bundle record |

The canonical records use the concatenations below. All integer fields are
big-endian; UUIDs are their raw 16 bytes; digests and public keys are decoded
raw bytes; the algorithm code for Ed25519 is `1`; booleans are exactly `0` or
`1`.

```text
policy-state =
  "RKPS" || u16(1) || vault_id[16] || u8(trust_installed) ||
  u8(bundle_activated) || signer_id_or_zero[16] ||
  u64(highest_version_or_zero) || policy_digest_or_zero[32] ||
  bundle_digest_or_zero[32] || i64(updated_at_ms)

policy-trust =
  "RKPT" || u16(1) || vault_id[16] || signer_id[16] ||
  u16(1) || public_key[32] || i64(installed_at_ms)

policy-bundle =
  "RKPB" || u16(1) || vault_id[16] || signer_id[16] ||
  u64(policy_version) || i64(expires_at_ms) || policy_digest[32] ||
  bundle_digest[32] || i64(activated_at_ms)
```

The zero sentinels in `policy-state` are valid only before the corresponding
trust or bundle exists. Once `trust_installed` is `1`, the signer ID is nonzero
and immutable. Once `bundle_activated` is `1`, the version is positive and both
digests are nonzero. Any other combination is an integrity failure.

On startup the Broker does not publish policy while locked. The first successful
unlock verifies the trust seal, bundle seal, signature, schema, version, and
expiry before publishing an `ActivePolicy`. A malformed persisted record or bad
signature faults the Authority and keeps execution closed. A valid but expired
bundle loads as expired and default-denies until a higher signed version is
activated. Lock clears the in-memory compiled policy; the next unlock reloads
the persisted bundle. Restart never resets the highest accepted policy version.

The existing irreversible monotonic expiry latch remains active for each loaded
bundle. P-03 does not claim protection against replay of an entire previously
valid vault snapshot. G1 rollback freshness remains out of scope; the bounded G2
topology prevents the Agent from accessing the state tree but does not protect
against host root or offline operator rollback.

## 5. Approval challenge

The Agent channel adds `PrepareApproval`. It accepts the same capability token,
action version, content type, allowed headers, and body as execution, but never
decrypts a credential or contacts the upstream. It validates the live session
and action, canonicalizes parameters through the active policy binding, and
evaluates forbid/permit/approval precedence.

For a matching approval rule it returns this exact closed JSON object:

```json
{
  "record_type": "rekey.approval.challenge.v1",
  "approval_request_id": "UUID",
  "tenant_id": "UUID",
  "principal_id": "UUID",
  "session_id": "UUID",
  "action_id": "UUID",
  "action_version": 1,
  "resource": {"type": "TYPE", "id": "ID"},
  "schema_id": "SCHEMA",
  "parameter_sha256": "LOWERCASE_HEX",
  "policy_version": 1,
  "policy_sha256": "LOWERCASE_HEX",
  "policy_rule_id": "UUID",
  "mode": "one-time",
  "quorum": 1,
  "approver_ids": ["UUID"],
  "max_uses": 1,
  "created_at_ms": 0,
  "max_expires_at_ms": 0
}
```

The approval request ID is random. UUIDs are canonical lowercase hyphenated
strings; both SHA-256 values are exactly 64 lowercase hexadecimal characters;
the resource object is itself closed; and `approver_ids` contains distinct
canonical UUIDs sorted by raw UUID bytes. Parsers reject duplicate keys at any
depth, unknown fields, missing fields, non-canonical encodings, and any value
outside the policy bounds. `record_type` is the only discriminator and must
equal the literal shown above.

The challenge is safe for the Agent to see because the Agent supplied the
request and already knows its resource and parameters. It contains no action
credential, request header outside the policy allowlist, request body, or
capability token. Preparing a challenge consumes one session use under the
existing strict accounting rule, even though it performs no upstream effect.
This bounds Agent-driven challenge and audit growth by the Admin-issued
session grant. It also requires a currently valid non-revoked session and is
covered by the normal concurrency, frame-size, and deadline limits.

The maximum expiry is the earliest of policy expiry, session expiry, challenge
creation plus ten minutes for one-time mode, or challenge creation plus the
rule's bounded window for time-window mode. At challenge creation the
SessionRegistry also captures the current monotonic instant and derives an
irreversible monotonic deadline for that maximum expiry. `PrepareApproval`
returns `approval-not-required` instead of a challenge for a direct permit.

The exact challenge and its monotonic time anchor live only in the existing
in-memory SessionRegistry and are bound to that session. They are cleared by
session revocation, lock, or process restart; P-03 adds no durable approval
request or approval-usage table. The Authority commits `approval.requested`
before the challenge is returned. If that audit transaction fails, no challenge
is returned, its consumed session use is not restored, and the Authority
faults. A request matching `forbid` or no authorization rule is denied without
producing an approval challenge.

## 6. Signed approval grant

An external approver signs `rekey.approval.grant.v1`:

```json
{
  "format_version": 1,
  "approval_id": "UUID",
  "approval_request_id": "UUID",
  "approver_id": "UUID",
  "tenant_id": "UUID",
  "principal_id": "UUID",
  "session_id": "UUID",
  "action_id": "UUID",
  "action_version": 1,
  "resource": {"type": "TYPE", "id": "ID"},
  "schema_id": "SCHEMA",
  "parameter_sha256": "HEX",
  "policy_version": 1,
  "policy_sha256": "HEX",
  "policy_rule_id": "UUID",
  "mode": "one-time",
  "not_before_ms": 0,
  "expires_at_ms": 0,
  "max_uses": 1,
  "signature": "BASE64URL_NO_PAD"
}
```

The signature input is `RKAPPROVAL\0\x01` followed by JCS encoding with
`signature` omitted. The complete grant is parsed once with recursive duplicate
key and unknown-field rejection before canonicalization or authorization. The
execution request carries at most two grants. Every field except `approval_id`,
`approver_id`, validity bounds, signed use limit, and signature must exactly
equal the prepared challenge and current execution authorization tuple. This
includes the determining `policy_rule_id`. The approver must exist in the active
signed snapshot and be allowed by that rule.

`approval_request_id` names the session-bound challenge and is distinct from
the new execution request ID assigned to each execute attempt. `policy_sha256`
is the policy digest defined in Section 3, not the bundle digest. The signed
grant digest used for in-memory usage identity is exactly
`SHA-256(JCS(grant))`, including its signature; raw whitespace and member order
do not affect it.

The Broker rejects grants with an invalid signature, future `not_before_ms`,
expired validity, validity beyond the challenge maximum, a wrong mode, duplicate
approval ID, duplicate approver ID, zero or over-limit `max_uses`, or any tuple
mismatch. Two-person approval requires two valid grants from distinct allowed
approvers. Each signed `max_uses` must be no greater than the rule and challenge
ceiling. Invalid or insufficient approval never falls back to permit, never
decrypts the credential, and never reaches the upstream.

A one-time grant may be valid for at most ten minutes and has `max_uses = 1`.
A time-window grant may be reused only within the same bound session and until
both its signed use count and validity window are exhausted. Its effective
expiry is the earlier of signed expiry, the rule's maximum window, session
expiry, or policy expiry. Session revocation, policy change, parameter change,
or action-version change therefore invalidates the grant without a separate
revocation list.

For every presented grant, the Broker derives its monotonic expiry from the
challenge's stored creation wall time and monotonic anchor, capped by the
challenge's stored monotonic deadline. First and later admission require both
the signed wall-clock expiry and this derived monotonic expiry to remain valid.
A wall-clock rollback between challenge creation and first execution therefore
cannot extend either a one-time or time-window grant. Restart does not rebuild
the deadline: it destroys the session and challenge, so every grant bound to
them is invalid.

## 7. Execution and transaction ordering

Approval verification happens after capability, action, and parameter
canonicalization but before credential preparation. Under the SessionRegistry
lock, an approved execution atomically:

1. loads the session-bound challenge and requires an exact current tuple, rule,
   policy, session, and wall-clock plus monotonic expiry match;
2. verifies each grant and rejects an exhausted approval ID or a prior entry
   whose signed grant digest does not match;
3. reserves one use from each grant's in-memory counter without exceeding its
   signed `max_uses`, and verifies distinct approvers satisfy quorum.

After that reservation, the Authority appends one `approval.accepted` event per
grant and the existing `execution.started` event in one SQLite transaction.
Only after that transaction commits may the worker decrypt a credential and the
Broker enter the remote-effect gate. Concurrent reuse can therefore admit at
most the signed use count, and a one-time grant can admit exactly one execution.
Cancellation, upstream failure, or audit failure after the memory reservation
does not restore any approval use; audit failure permits no remote effect and
faults the Authority. The normal terminal execution audit records outcomes
after successful admission.

Approval counters are keyed by approval ID and signed grant digest inside the
owning session. Reusing an approval ID with different signed content is denied.
Because the capability session, challenge, and counters share one volatile
lifetime, deletion or rollback of SQLite rows cannot restore approval capacity;
restart or lock instead invalidates the entire authorization context.

Rejected signatures, tuple mismatches, insufficient quorum, expired grants, and
exhausted-use attempts append `approval.rejected` with a bounded reason code
before returning denial. Audit failure itself fails closed. Time-window reuse
appends fresh `approval.accepted` evidence for every admitted execution.

## 8. Evaluator and unavailable behavior

The evaluator remains deterministic and default-deny:

- missing, unavailable, invalid, or expired persisted policy denies;
- schema/canonicalization failure denies;
- explicit forbid denies;
- a matching approval rule without sufficient valid grants denies;
- signature-verification or typed evaluator error denies;
- inconsistent or unavailable session approval state denies, and poisoned
  session state follows the existing Broker fail-stop behavior;
- only an explicit permit or a fully satisfied approval rule can allow.

P-03 has no network approval dependency. If an external approver or signing
service is unavailable, the Agent cannot obtain enough valid grants and the
action is denied. Cached time-window grants continue only within their exact
signed tuple and expiry. There is no emergency allow, stale-policy fallback, or
offline approval bypass.

## 9. Audit and public export

The durable audit schema adds nullable approval request, approval, and approver
IDs. Approval events use the existing authorization evidence fields for the
principal, action, resource, parameter hash, policy version, digest, and
determining rule. Signatures, public keys, grant JSON, request bodies, headers,
and capability tokens are never audit fields.

P-03 uses `rekey.audit.v2` for both the paginated page's `schema` field and each
event's `record_type`. Export uses `rekey.audit.export.v2` for the header,
`rekey.audit.v2` for every event, and `rekey.audit.export.complete.v2` for the
trailer. These objects add only the three nullable approval IDs. The P-02
pagination, scan bound, redaction, create-new output, inode check, fsync,
partial-file, and retention contracts stay unchanged. The CLI requires this
exact version combination, rejects unknown response fields, and never silently
reads a v1 object as v2.

Required approval event types are `approval.requested`, `approval.accepted`, and
`approval.rejected`. Each admission transaction keeps its accepted events and
`execution.started` together; there is no separate durable approval state that
can drift from execution admission. Challenge and usage state is intentionally
absent from backup and restore because it is part of the volatile capability
session and becomes invalid on lock or restart.

## 10. Bounds and error contract

- Trust file: at most 4 KiB.
- Policy bundle: at most 64 KiB.
- Approver catalog: at most 32 entries.
- Rule approval allowlist: at most 32 entries; quorum only 1 or 2.
- Execution grants: at most 2, each at most 4 KiB encoded.
- One-time validity: at most 10 minutes.
- Time-window validity: positive and at most the rule limit and eight hours.
- Grant uses: exactly 1 for one-time; 1 through 10,000 for time-window and no
  greater than the signed policy-rule ceiling.
- Signature algorithms, format versions, and encodings are closed sets.

Malformed or oversized input returns invalid input before expensive signature
or schema work. A bad policy artifact leaves the current bundle active. A bad
approval artifact denies only that request unless the audit commit fails, in
which case the existing Authority fail-stop rules apply.

## 11. Required verification

P-03 is complete only when all of the following are fresh and passing:

1. Policy tests cover canonical signing bytes, duplicate keys, malformed keys
   and signatures, unknown signer, tampering of every bound field, approver
   catalog membership and limits, overlap conflicts including `max_uses`, forbid
   precedence, approval precedence, consecutive versions, the reserved terminal
   value, and default deny.
2. Store tests cover one-time trust installation, sealed trust and bundle row
   tampering and deletion, mandatory policy-state absence and mismatch, all
   three seal golden vectors and every bound-field mutation, atomic
   activation/audit rollback, consecutive versions, roll-forward of old
   contents, restart reload, expiry, and backup/restore.
3. Approval tests cover exact tuple and determining-rule binding, one-time replay
   including a concurrent race, reusable time windows, two distinct approvers,
   duplicate and unknown challenge or grant fields at every depth, duplicate
   grants, signed use exhaustion including a concurrent race,
   policy/session/action/parameter changes, wall-clock rollback before first
   execution and after observed expiry, and all expiry boundaries. Restart and
   lock tests prove the session, challenge, and all grants become invalid rather
   than restoring approval use. Challenge tests also prove one session use per
   request and no challenge or audit amplification after capability exhaustion.
4. Fault injection proves in-memory approval use is reserved before the atomic
   `approval.accepted` plus `execution.started` audit transaction, audit failure
   prevents the remote effect without restoring use, and post-admission failure
   does not restore use.
5. Admin and Agent IPC adversarial tests enforce channel separation, empty or
   bounded bodies, response binding, unknown-field rejection, and deadlines.
6. Real `rekeyd` plus `rekey` black-box tests install a trust root, activate a
   signed bundle, reload it after restart, produce a challenge, admit one-person
   and two-person grants, reject replay/tampering/expiry, and show approval audit
   records through list and export.
7. Canary scans prove private signing keys, signatures, grants, capability
   tokens, credentials, passwords, and recovery keys do not enter argv,
   environment, logs, audit output, or state files outside the defined sealed
   records.
8. `cargo fmt --all --check`, `cargo check --workspace --all-targets`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, repository mechanical contracts, and exact-head CI
   pass.
9. README, user guide, operations runbook, threat model, closeout plan, and
   Feature Truth Matrix describe the verifier-only boundary and do not raise
   G1/G2, remote approval, control-plane, Connector, SIEM, enterprise, or release
   maturity claims.

## 12. Non-goals

- Private-key generation, custody, rotation, escrow, or signing inside Rekey.
- Remote approval workflows, notifications, inboxes, dashboards, webhooks, or
  human directory integration.
- OIDC, SAML, SCIM, RBAC administration, organizational roles, or break-glass.
- More than two approvals, weighted quorum, delegation, groups, or policy code.
- Cedar/Rego, remote policy fetch, policy compilation services, or hot polling.
- Trust-root replacement or multiple concurrent policy signers in one vault.
- Approval revocation lists beyond exact session, policy, action, tuple, and
  expiry binding.
- Approval survival across session revocation, lock, or process restart.
- Full-vault replay detection, external monotonic counters, transparency logs,
  WORM audit, or enterprise SIEM delivery.
- Inclusion in `v2.0.0-alpha.1` or any increase to the current G1 and bounded
  Linux G2 claims.
