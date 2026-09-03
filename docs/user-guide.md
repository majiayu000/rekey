# User guide

This guide assumes the verified Alpha binaries are installed and the broker is
running. Read [the security and platform scope](alpha-scope.md) first. Sections
covering signed persistent policy, approval, and workload identity describe
post-Alpha development head; those commands are not included in the published
`v2.0.0-alpha.1` artifacts.

## Start, unlock, and status

```bash
rekey serve                    # foreground; starts locked
rekey unlock                   # hidden password prompt
rekey status
```

`rekey serve` delegates to `rekeyd serve`; agents and Admin clients never open
the SQLite database. `rekey lock` revokes sessions and clears the active
policy. The default idle lock is 15 minutes. `rekey shutdown` requires a
step-up proof while unlocked.

For deliberate automation, password-only commands accept `--password-stdin`.
Credential add/rotate accepts `--stdin-secrets`, with proof on line 1 and the
credential on line 2. Do not place secrets in argv, environment variables,
JSON metadata, logs, or Action files.

## Replace password or recovery key

Both operations require an unlocked broker and rewrap the existing VRK; they
do not rewrite Credentials or revoke current capability sessions.

```bash
rekey password change              # current password, then new password twice
rekey password change --recovery   # current recovery key, then new password
rekey recovery rotate              # current password; new key is shown once
```

For deliberate automation, password replacement uses `--stdin-secrets` with
the current proof on line 1 and new password on line 2. Recovery rotation uses
`--password-stdin`. Save the newly displayed recovery key before closing the
terminal. If that output is lost, the password remains valid: rotate recovery
again and retain only the latest key.

Rotation does not invalidate historical backups. Each backup remains tied to
the password and recovery wrappers captured in that snapshot.

## Query and export local audit metadata

Audit queries use the owner-checked Admin socket and work while the broker is
locked. A list call returns at most 100 newest-first records:

```bash
rekey audit list --limit 50
rekey audit list --request REQUEST_ID --session SESSION_ID \
  --action ACTION_ID --credential CREDENTIAL_ID --outcome denied \
  --since-ms 1900000000000 --until-ms 1900003600000
```

To continue a page, pass both the returned `snapshot_max_sequence` and
`next_before_sequence` as `--snapshot-max-sequence` and `--before-sequence`.
The high-water mark prevents newly committed rows entering that traversal. A
selective query can return no records and still include a continuation cursor:
each request scans at most 1,000 audit rows, so continue until the cursor is
null.

Export captures the complete matching snapshot in bounded pages:

```bash
rekey audit export --output /secure/new/audit.jsonl --outcome failure
```

The destination must not exist. Rekey creates a regular owner-only mode-0600
JSONL file, refuses symlinks and overwrites, syncs the file and parent directory,
verifies the destination pathname still names that file, and prints a receipt
only after completion. On failure, a partial new file may remain for inspection
and is never resumed. Output omits credentials, recovery material, capability
tokens, bodies, headers, resource IDs, and parameter hashes. Protect it as
sensitive metadata. Rekey keeps local audit rows for the vault lifetime; there
is no delete, pruning, configurable retention, SIEM, WORM, legal hold, or remote
delivery in this capability.

## Create a fixed HTTPS Action

Add an opaque token and retain the returned credential ID:

```bash
rekey credential add github-token
rekey credential list
```

Create `action.json` with the returned ID:

```json
{
  "name": "github-create-issue",
  "credential_id": "00000000-0000-4000-8000-000000000000",
  "origin": "https://api.github.com",
  "method": "POST",
  "exact_path": "/repos/OWNER/REPOSITORY/issues",
  "auth_header": "authorization",
  "auth_prefix": "Bearer ",
  "timeout_ms": 30000,
  "request_max_bytes": 65536,
  "allowed_extra_headers": ["x-request-id"],
  "response_max_bytes": 262144,
  "allowed_response_headers": ["content-type"]
}
```

The origin, method, path, authentication slot, body bound, and response
allowlist are fixed by the Admin. Rekey rejects redirects, proxy environment
variables, private/reserved addresses, and unexpected headers.

```bash
rekey action create --file action.json
rekey action list
```

Record the returned `ACTION_ID@VERSION`.

## Session and policy

Create a capability session and record its `principal_id` and token:

```bash
rekey session create --action ACTION_ID@1 --ttl 1h --max-uses 10
```

Create a policy snapshot, replacing all UUIDs and the Action version with
returned values. `expires_at_ms` must be a future Unix epoch in milliseconds.

```json
{
  "format_version": 3,
  "version": 1,
  "expires_at_ms": 1900000000000,
  "approvers": [],
  "workload_identities": [],
  "bindings": [
    {
      "action_id": "00000000-0000-4000-8000-000000000000",
      "version": 1,
      "resource": {
        "type": "fixed-http-action",
        "id": "00000000-0000-4000-8000-000000000000"
      },
      "parameter_schema_id": "github-issue/v1",
      "parameter_schema": {
        "type": "object",
        "required": ["title"],
        "properties": {"title": {"type": "string"}},
        "additionalProperties": true
      }
    }
  ],
  "rules": [
    {
      "id": "00000000-0000-4000-8000-000000000001",
      "effect": "permit",
      "principal_id": "00000000-0000-4000-8000-000000000002",
      "action_id": "00000000-0000-4000-8000-000000000000",
      "version": 1,
      "resource": {
        "type": "fixed-http-action",
        "id": "00000000-0000-4000-8000-000000000000"
      },
      "parameters": {"kind": "any_validated"}
    }
  ]
}
```

An external Ed25519 policy signer wraps this snapshot in
`rekey.policy.bundle.v1` and signs the canonical bytes defined by the
[P-03 specification](superpowers/specs/2026-09-03-approvals-persistent-policy-p03.md).
Rekey does not create or store that private key. Install its public trust root
once, then activate the signed bundle:

```json
{
  "format_version": 1,
  "signer_id": "00000000-0000-4000-8000-000000000010",
  "algorithm": "ed25519",
  "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
}
```

```bash
printf '%s\n' "$STEP_UP_PROOF" | \
  rekey policy trust install --file trust.json --step-up-stdin
printf '%s\n' "$STEP_UP_PROOF" | \
  rekey policy activate --file bundle.json --step-up-stdin
rekey policy status
```

There is one immutable trust root per vault. Policy version 1 must be first;
later bundles must be exactly consecutive. A malformed, unsigned, expired,
wrong-signer, skipped-version, or rollback bundle is rejected without changing
the active policy. Lock clears the compiled policy and a successful unlock
reverifies the signed, lifecycle-sealed persisted bundle before loading it. Before that unlock,
status is `unavailable`. Capability sessions still disappear on lock or restart.

### Create a workload-attested session

Policy snapshot v3 can map a generic OIDC, SPIFFE JWT-SVID, Kubernetes service
account, or CI/cloud JWT subject to a Rekey `principal_id`. Each mapping pins an
exact HTTPS issuer, exact subject/profile, canonical audience set, maximum token
age, and static Ed25519 or RS256 verification keys. See the
[P-04 specification](superpowers/specs/2026-09-03-workload-identity-p04.md) for
the closed JSON schema.

After activating that signed policy, send the workload JWT only through stdin:

```bash
printf '%s\n' "$WORKLOAD_TOKEN" | rekey session create \
  --action ACTION_ID@1 --ttl 15m --max-uses 20 \
  --workload-token-stdin
```

This uses `agent.sock` and does not require an Admin step-up. Rekey verifies the
signature and exact claims, checks that the mapped principal may request every
Action, and atomically consumes the token replay identity before returning the
capability. Replay remains denied after restart and after restoring a backup
that already contains the consumption record. A valid backup created before
consumption cannot contain that record; restoring it is complete-vault rollback
and is outside the G1 freshness guarantee described below. Activating a new
policy version revokes workload-minted sessions but preserves Admin-minted
sessions. Retrying the exact active bundle preserves both kinds of session.
Lock, restart, expiry, use exhaustion, and explicit revoke still end the
resulting capability.

Rekey does not fetch JWKS, perform OIDC discovery or introspection, contact
SPIRE or Kubernetes APIs, or hold issuer private keys. Rotate a workload
verification key by signing and activating the next consecutive policy bundle;
the old policy activation revokes existing workload sessions.

To require approval, add approvers to the snapshot catalog and use a
`require-approval` rule. The rule names the allowed approvers, quorum 1 or 2,
`one-time` or `time-window` mode, and its use/window ceilings. For example:

```json
{
  "effect": "require-approval",
  "approval": {
    "approver_ids": ["00000000-0000-4000-8000-000000000020"],
    "quorum": 1,
    "mode": "one-time",
    "max_uses": 1
  }
}
```

Prepare the exact request and give the challenge JSON to an external approver:

```bash
printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey approval prepare ACTION_ID@1 --capability - \
    --body-file request.json --content-type application/json >challenge.json
```

After the approver returns a signed grant, execute the same request:

```bash
printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey execute ACTION_ID@1 --capability - \
    --body-file request.json --content-type application/json \
    --approval grant.json
```

Two-person rules require two distinct `--approval` files. Each file must be a
regular non-symlink UTF-8 JSON file no larger than 4 KiB. A grant is bound to
the exact challenge/session/principal/Action/resource/canonical parameters,
determining rule, policy version/digest, expiry, and signed use count. Approval
requests and usage are memory-only and vanish on session revocation, lock, or
restart. Rekey has no remote approval service, notifications, dashboard, human
directory, or private-key custody.

Failed password throttling is also process-local and resets when `rekeyd`
restarts. The G1 public Alpha accepts this limitation; restarting the broker is
not an authentication defense. Rekey also cannot detect replay of a complete,
previously valid vault snapshot. G1 therefore has no monotonic rollback
protection. Restore only a backup and receipt you intentionally selected.

## Execute without exposing the token in argv

Create a request body such as `request.json`, then pipe the capability token:

```bash
printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey execute ACTION_ID@1 --capability - \
    --body-file request.json --content-type application/json
```

Only response headers on the Action allowlist are returned. Secret sealing
detects raw, base64, base64url, percent-encoded, header, and chunk-boundary
reflections. It does not guarantee detection of arbitrary compression,
encryption, hashes, derivations, or application-specific encodings.

## GitHub App closed profile

This is not a general GitHub connector. It supports only one selected
repository, `metadata=read`, and the fixed
`GET https://api.github.com/installation/repositories` Action. The profile is:

```json
{
  "credential_type": "github-app-installation-v1",
  "client_id": "Iv1.REPLACE_ME",
  "app_id": 123456,
  "installation_id": 234567,
  "repository_id": 345678,
  "private_key_pkcs1_der_base64": "REPLACE_WITH_BASE64_PKCS1_DER"
}
```

Add it with `rekey credential add-github-app LABEL --file profile.json`. Keep
the profile owner-readable only and delete the plaintext file after the
encrypted mutation succeeds. The corresponding Action must use origin
`https://api.github.com`, method `GET`, path `/installation/repositories`,
`authorization` with prefix `Bearer `, no request body/extra headers, and an
allowlisted JSON response.

## Backup and restore

```bash
rekey backup --output /secure/path/rekey.backup
# Save the receipt and its SHA-256 separately.
rekey shutdown
mkdir -m 700 /secure/path/restored-state
rekey --state-dir /secure/path/restored-state restore \
  --input /secure/path/rekey.backup --sha256 RECEIPT_SHA256
```

Restore is offline and requires an empty destination. Use `--recovery` to
verify with the recovery key. A successful restore does not reset the password.

## Errors and exit codes

| Exit | Meaning | Typical codes |
| --- | --- | --- |
| 2 | Invalid input, frame, or policy | `USAGE`, `INVALID_INPUT`, `POLICY_INVALID` |
| 3 | Locked or authentication failure | `LOCKED`, `AUTHENTICATION_FAILED`, `UNLOCK_RATE_LIMITED` |
| 4 | Authorization/capability/credential denial | `ACTION_DENIED`, `INVALID_CAPABILITY`, `CREDENTIAL_UNAVAILABLE` |
| 5 | Durable state, crypto, audit, or bootstrap failure | `STORAGE_UNAVAILABLE`, `FAULTED`, `RESTORE_FAILED` |
| 6 | Upstream transport/size failure | `UPSTREAM_FAILED`, `RESPONSE_TOO_LARGE` |
| 7 | Other explicit failure | code shown on stderr |
| 8 | Post-effect security/audit uncertainty | `RESPONSE_SECURITY_VIOLATION`, `AUDIT_COMMIT_FAILED_AFTER_EXECUTION` |

An exit 8 means a remote effect may have occurred; do not blindly retry.

If a domain resolves only into `198.18.0.0/15`, Clash/TUN Fake-IP is being
rejected by design. Configure real DNS for that exact host; never weaken
private-IP screening or set a proxy environment variable as a workaround.
