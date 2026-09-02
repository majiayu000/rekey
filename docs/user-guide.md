# User guide

This guide assumes the verified Alpha binaries are installed and the broker is
running. Read [the security and platform scope](alpha-scope.md) first.

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

Create `policy.json`, replacing all UUIDs and the Action version with returned
values. `expires_at_ms` must be a future Unix epoch in milliseconds.

```json
{
  "format_version": 1,
  "version": 1,
  "expires_at_ms": 1900000000000,
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

```bash
rekey policy activate --file policy.json
rekey policy status
```

Policy and capabilities are in memory and disappear on lock or restart.

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
