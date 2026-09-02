# Rekey v2 P-03 Approvals and Persistent Policy

**Date:** 2026-09-03
**Status:** Proposed
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

`policy activate` now accepts only a signed policy bundle. An unsigned snapshot,
unknown signer, malformed signature, expired snapshot, or non-increasing policy
version fails without changing the active bundle. Operators perform rollback by
reissuing the previously accepted policy contents under a strictly higher
version; downgrade activation is never allowed.
Retrying the exact active version and digest after a lost response is
idempotent; the same version with different bytes is rejected.

`policy status` reports whether a trust root is installed and whether a
persisted bundle is loaded, plus the signer ID, policy version, expiry, digest,
and one of `unavailable`, `active`, or `expired`. It exposes no public key,
signature, approval grant, or private material. Before first successful unlock
after restart, a persisted bundle is `unavailable`, not optimistically active;
unverified signer, version, expiry, and digest fields remain null.

No Rekey command creates private keys or signatures. That remains the external
signer's responsibility and avoids turning the IPC-only `rekey` client into a
second credential store.

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
`max_window_ms` only for time-window mode. `permit` and `forbid` rules must not
contain `approval`.

A required quorum cannot exceed the distinct allowlisted approvers. A
time-window rule also declares `max_window_ms`, which must be positive and at
most eight hours. A one-time rule has no window setting. `forbid` continues to
win over both permit and approval rules. A direct permit wins only when no
matching approval rule exists; policy authors cannot accidentally bypass an
approval rule by adding a broad permit.

Overlapping approval rules for the same principal, action, and resource must
have identical approver allowlists, quorum, mode, and window. `any-validated`
overlaps every exact parameter hash and equal exact hashes overlap each other;
a snapshot with conflicting requirements is invalid. When identical rules
match, the lowest rule ID remains the deterministic determining rule.

## 4. Durable policy lifecycle

The vault schema stores one sealed trust record and one current signed bundle.
Trust installation and bundle activation are AuthorityWorker mutations. Each
commits its durable record and success audit in one SQLite transaction; an audit
failure rolls back the mutation and faults the Authority under the existing
fail-closed contract.

P-03 raises the vault format to schema v6. There is no in-place v5 migration or
compatibility reader; existing v5 vaults remain usable only by the earlier
binary and must be recreated or restored through a separately specified future
upgrade path.

The trust and bundle lifecycle seals bind vault ID, record purpose, signer ID,
public-key or bundle digest, policy version, expiry, and timestamps. Direct row
tampering, cross-vault copying, signer substitution, or changing the persisted
version or digest fails integrity verification. The signed bundle is also
verified against the sealed trust root every time it is loaded.

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

For a matching approval rule it returns `rekey.approval.challenge.v1` containing:

- a random approval request ID;
- tenant, principal, and session IDs;
- action ID and version;
- resource type and ID;
- schema ID and canonical parameter SHA-256;
- policy version and digest;
- approval mode, quorum, allowed approver IDs, and maximum expiry.

The challenge is safe for the Agent to see because the Agent supplied the
request and already knows its resource and parameters. It contains no action
credential, request header outside the policy allowlist, request body, or
capability token. Preparing a challenge does not consume session use count, but
it does require a currently valid non-revoked session and is covered by the
normal connection, frame-size, and deadline limits.

The maximum expiry is the earliest of policy expiry, session expiry, challenge
creation plus ten minutes for one-time mode, or challenge creation plus the
rule's bounded window for time-window mode. `PrepareApproval` returns
`approval-not-required` instead of a challenge for a direct permit.

Every successful challenge creation inserts a durable approval-request record
and commits `approval.requested` in one Authority transaction before the
response is returned. The record stores the request ID, exact authorization
tuple, rule, mode, quorum, allowed approvers, creation time, and maximum expiry;
it contains no request body, header, capability, credential, or signature. If
that transaction fails, no challenge is returned and the Authority faults. A
request matching `forbid` or no authorization rule is denied without producing
an approval challenge.

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
  "mode": "one-time",
  "not_before_ms": 0,
  "expires_at_ms": 0,
  "signature": "BASE64URL_NO_PAD"
}
```

The signature input is `RKAPPROVAL\0\x01` followed by JCS encoding with
`signature` omitted. The execution request carries at most two grants. Every
field except `approval_id`, `approver_id`, validity bounds, and signature must
exactly equal the prepared challenge and current execution authorization tuple.
The approver must exist in the active signed snapshot and be allowed by the
determining rule.

`approval_request_id` names the durable challenge and is distinct from the new
execution request ID assigned to each execute attempt. `policy_sha256` is the
digest of the canonical snapshot, not the enclosing bundle or its signature.

The Broker rejects grants with an invalid signature, future `not_before_ms`,
expired validity, validity beyond the challenge maximum, a wrong mode, duplicate
approval ID, duplicate approver ID, or any tuple mismatch. Two-person approval
requires two valid grants from distinct allowed approvers. Invalid or
insufficient approval never falls back to permit, never decrypts the credential,
and never reaches the upstream.

A one-time grant may be valid for at most ten minutes and is consumed by its
`approval_id` exactly once across processes and restarts. A time-window grant may
be reused only within the same bound session and only until the earlier of its
signed expiry, the rule's maximum window, the session expiry, or policy expiry.
Session revocation, policy change, parameter change, or action-version change
therefore invalidates the grant without a separate revocation list.

## 7. Execution and transaction ordering

Approval verification happens after capability, action, and parameter
canonicalization but before credential preparation. For an approved execution,
the Authority commits the following admission atomically:

1. load the durable approval request and require an exact current tuple, rule,
   policy, session, and expiry match;
2. reject any previously consumed one-time approval ID;
3. insert the one-time consumption rows, if any;
4. append one `approval.accepted` event per accepted grant;
5. append the existing `execution.started` event.

Only after that transaction commits may the worker decrypt a credential and the
Broker enter the remote-effect gate. A concurrent replay of a one-time grant can
therefore produce at most one admitted execution. Cancellation or upstream
failure after admission does not restore a one-time grant; the normal terminal
execution audit records the outcome.

Rejected signatures, tuple mismatches, insufficient quorum, expired grants, and
replay attempts append `approval.rejected` with a bounded reason code before
returning denial. Audit failure itself fails closed. Time-window reuse appends
fresh `approval.accepted` evidence for every admitted execution.

## 8. Evaluator and unavailable behavior

The evaluator remains deterministic and default-deny:

- missing, unavailable, invalid, or expired persisted policy denies;
- schema/canonicalization failure denies;
- explicit forbid denies;
- a matching approval rule without sufficient valid grants denies;
- signature-verification or approval-store error denies;
- evaluator panic or internal error faults the request path and never becomes
  permit;
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

P-03 advances the public audit record to `rekey.audit.v2` and the export header
to `rekey.audit.export.v2`; both add only the three nullable approval IDs. The
P-02 pagination, scan bound, redaction, create-new output, inode check, fsync,
partial-file, and retention contracts stay unchanged. The CLI rejects unknown
response fields and never silently reads a v1 record as v2.

Required approval event types are `approval.requested`, `approval.accepted`, and
`approval.rejected`. One-time consumption is represented by the accepted event
and the durable consumption row in the same admission transaction; no separate
success event may drift from execution admission. Approval-request and
consumption rows are retained with the vault in P-03; automatic pruning remains
future retention work.

## 10. Bounds and error contract

- Trust file: at most 4 KiB.
- Policy bundle: at most 64 KiB.
- Approver catalog: at most 32 entries.
- Rule approval allowlist: at most 32 entries; quorum only 1 or 2.
- Execution grants: at most 2, each at most 4 KiB encoded.
- One-time validity: at most 10 minutes.
- Time-window validity: positive and at most the rule limit and eight hours.
- Signature algorithms, format versions, and encodings are closed sets.

Malformed or oversized input returns invalid input before expensive signature
or schema work. A bad policy artifact leaves the current bundle active. A bad
approval artifact denies only that request unless the durable store or audit
commit fails, in which case the existing Authority fail-stop rules apply.

## 11. Required verification

P-03 is complete only when all of the following are fresh and passing:

1. Policy tests cover canonical signing bytes, duplicate keys, malformed keys
   and signatures, unknown signer, tampering of every bound field, approver
   catalog limits, forbid precedence, approval precedence, and default deny.
2. Store tests cover one-time trust installation, sealed trust and bundle row
   tampering, atomic activation/audit rollback, strictly increasing versions,
   roll-forward of old contents, restart reload, expiry, and backup/restore.
3. Approval tests cover exact tuple binding, one-time replay including a
   concurrent race and restart, reusable time windows, two distinct approvers,
   duplicate grants, policy/session/action/parameter changes, and all expiry
   boundaries.
4. Fault injection proves approval consumption and `execution.started` are
   atomic, audit failure prevents the remote effect, and post-admission failure
   does not restore one-time approval.
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
- Full-vault replay detection, external monotonic counters, transparency logs,
  WORM audit, or enterprise SIEM delivery.
- Inclusion in `v2.0.0-alpha.1` or any increase to the current G1 and bounded
  Linux G2 claims.
