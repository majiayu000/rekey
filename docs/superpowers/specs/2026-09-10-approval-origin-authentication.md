# APR-08 remainder: approval challenge origin authentication

This slice authenticates a Broker-issued approval challenge so an operator can
copy it to a second machine they control, review it with the existing
`rekey-approval-sign` tool, and bring the grant back. It is not a hosted remote
approval service, notification inbox, personnel directory, or Agent-callable
approval socket. Rekey remains verifier-only for approver keys.

Topology is G1 same-user personal CLI. “Remote” means the operator relocates a
Broker-signed challenge envelope plus a separately pinned origin public key.
There is no new network listener and no third Unix socket.

## Origin key

While the vault is unlocked, AuthorityWorker derives a stable Ed25519 origin
key from the in-memory VRK. The seed never leaves the worker.

- HKDF-SHA256: salt = `vault_id` (16 bytes), IKM = VRK, info =
  `rekey/approval-origin-ed25519/v1`, output = 32-byte seed
- Ed25519 from that seed (`from_seed_unchecked`); the seed is zeroized after
  keypair construction
- Stable across password and recovery **wrapper** rotation (same VRK)
- Different vaults produce different origin keys
- Vault format stays 10; no persisted origin-key row

Admin `rekey approval origin` (message type 28, empty body, unlocked Running)
returns `{ "algorithm": "ed25519", "public_key": "<64 lowercase hex>" }`.
The CLI prints that object and does not verify signatures. Operators pin the
hex independently of the envelope; envelopes do not embed the public key.

Signing an origin payload also happens only inside the worker. The broker
sends the already-prefixed message bytes; the worker refuses payloads larger
than 64 KiB.

## Envelope

Inner `rekey.approval.challenge.v1` is unchanged and remains what SessionRegistry
stores and what grants bind to.

`PrepareApproval` now returns this closed envelope instead of the bare v1
object:

```json
{
  "record_type": "rekey.approval.challenge.envelope.v1",
  "challenge": { "... inner v1 ..." },
  "signature": "BASE64URL_NO_PAD"
}
```

Signature input is the byte prefix `RKCHALLENGE\0\x01` followed by RFC 8785
JCS of the inner challenge only. Parsers reject duplicate keys, unknown fields,
non-canonical base64url, signatures other than 64 bytes, and envelopes over
64 KiB before verification.

The IPC-only `rekey` client checks envelope **shape** and inner `validate()`
only. It does not perform Ed25519. `rekey-approval-sign` requires
`--origin-key HEX` and rejects unsigned v1, the wrong origin key, and a
tampered inner challenge.

Grant verification on execute is unchanged: existing `SignedApprovalGrant`
plus the in-memory inner challenge.

## Operator flow

1. On the Broker host, pin `rekey approval origin`.
2. `rekey approval prepare` prints the envelope.
3. Copy the envelope, original request body, independently chosen
   policy/trust/Action files, and the pinned origin hex to the signing machine.
4. `rekey-approval-sign review` / `sign` with `--origin-key`.
5. Return the grant and execute the same request within 60 seconds.

The origin signature authenticates Broker challenge bytes. It does not
authenticate Action/policy/trust files, the operator’s intent, or same-user
process isolation. Auto-approve remains forbidden.

## Non-goals

- Public internet approval SaaS, APR-09 inbox/UI, APR-10 directory
- Agent-callable approval socket or auto-approve
- Exporting VRK, origin seed, or origin private key to CLI, argv, env, logs,
  or audit rows
- Vault schema bump or hosted control plane
