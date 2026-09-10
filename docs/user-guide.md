# User guide

This guide assumes verified binaries are installed and the broker is running.
Read [the security and platform scope](alpha-scope.md) first.

This Alpha (`v2.0.0-alpha.2`) is vault schema v9. The historical
`v2.0.0-alpha.1` archive was schema v5. There is no in-place migration. Keep
the old binaries and a verified backup to roll back; initialize v9 in a new
empty directory.

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

Released Alpha uses static keys. In this source tree, the
[WID-09 extension](superpowers/specs/2026-09-10-github-actions-jwks.md) also accepts
the exact GitHub issuer with `keys: []` and
`online_key_source: "github-actions-jwks"` in the signed identity. The Broker
fetches only its fixed public HTTPS JWKS for each mint and denies admission on
outage or invalid keys; no cache, discovery or introspection is used.
Rekey does not contact SPIRE or Kubernetes APIs or hold issuer private keys.
Rotate a static workload verification key by signing and activating the next consecutive policy bundle;
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

Source builds also provide `rekey-approval-sign` for a local operator's
single-person, one-time review. This is not a remote approval service: the
challenge has no source signature, and another process running as your user
can still read the same files. Independently choose policy, trust, Action, and
key files from an operator-owned directory. Do not take them from an Agent
workspace. The signer only handles `one-time` / `quorum=1` / `max_uses=1`.

### Local independent approval endpoint

Keep these files in an operator directory that the Agent cannot write:

- `policy.json` and `trust.json` from `rekey-policy-sign` (or another external
  signer), already installed/activated on this Broker
- `trusted-action.json`: the full `FixedHttpAction` printed by
  `rekey action create` / `rekey action update`, or one object copied from
  `rekey action list` after you confirm origin, method, path, and version
- `approver.der`: PKCS8 Ed25519, owned by the current user, mode `0600`, not a
  symlink. Generate and extract the 32-byte public key as lowercase hex:

```bash
openssl genpkey -algorithm Ed25519 -outform DER -out approver.der
chmod 600 approver.der
openssl pkey -in approver.der -inform DER -pubout -outform DER | tail -c 32 | xxd -p -c 32
```

Put that public key and a stable approver UUID into the signed policy catalog.
The `--approver-id` you pass later must be that UUID, and the key must match it.

1. From a trusted terminal, prepare the **exact** request that will later
   execute. `body` in the approval request must be that same original text.

```bash
printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey approval prepare ACTION_ID@1 --capability - \
    --body-file request.json --content-type application/json >challenge.json
python3 - <<'PY'
import json
from pathlib import Path
challenge = json.loads(Path("challenge.json").read_text())
body = Path("request.json").read_text()
Path("approval-request.json").write_text(json.dumps({
    "challenge": challenge,
    "content_type": "application/json",
    "headers": [],
    "body": body,
}, indent=2) + "\n")
PY
chmod 600 approval-request.json
```

`headers` is an array of `[name, value]` pairs for extra headers that were
also passed to `approval prepare`. Omit them when unused. `content_type` may
be `null` when the original call had none.

2. Review on the operator machine. Read the printed Action, request, approver,
   and `source_assumption`. Copy `reviewed_sha256` only if those fields are the
   operation you intend to allow.

```bash
cargo build -p rekey-policy --bin rekey-approval-sign
rekey-approval-sign review approval-request.json \
  --policy policy.json --trust trust.json \
  --action trusted-action.json --approver-id APPROVER_UUID
```

3. Sign the **same** files and digest. The grant file is created exclusively
   (`0600`) and will not overwrite an existing path. It is valid for at most 60
   seconds and still has to pass the live Broker challenge/session/policy checks.

```bash
rekey-approval-sign sign approval-request.json \
  --policy policy.json --trust trust.json \
  --action trusted-action.json --approver-id APPROVER_UUID \
  --reviewed-sha256 REVIEWED_HEX \
  --key-file approver.der --output grant.json
```

4. Immediately execute the **same** body, content type, headers, capability,
   and Action version:

```bash
printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey execute ACTION_ID@1 --capability - \
    --body-file request.json --content-type application/json \
    --approval grant.json
```

A changed body, a grant from another session, an expired challenge, or a
replay is rejected by the existing Broker verifier. See the
[local approval specification](superpowers/specs/2026-09-10-local-approval-endpoint.md).

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

## Launch an Agent with deny-by-default IP egress (Linux)

This Linux-only command requires bubblewrap. It does not upgrade default G1 or
replace the Docker G2 reference harness. The Agent socket must be disjoint from
the state directory; the default `runtime/agent.sock` is rejected.

```bash
rekeyd serve --state-dir /var/lib/rekey/state \
  --agent-runtime-dir /run/rekey-agent
rekey --state-dir /var/lib/rekey/state \
  --agent-socket /run/rekey-agent/agent.sock \
  agent-run -- /usr/bin/my-agent
```

The Ubuntu black-box harness recorded that the child had no IP/TCP/UDP path,
could not see the vault or Admin socket, and could still connect to
`agent.sock`, including when that socket is under `/tmp` (the launcher
bind-mounts the socket inode back after overlaying `/tmp`). Those facts are
not Adversarially Verified isolation. macOS returns `UNSUPPORTED_PLATFORM`. See
[the P-09 specification](superpowers/specs/2026-09-04-agent-egress-launcher-p09.md).

## GitHub App closed profile

This Alpha uses `github-app-installation-v2` with the bounds below. Live
`api.github.com` evidence does not cover every added Admin path. This is not a
general GitHub connector. One profile binds one installation, 1-16 exact
repositories, `metadata=read`, and optional `issues=write`. It supports only
repository listing and issue creation at a configured repository path. The
profile is:

```json
{
  "credential_type": "github-app-installation-v2",
  "client_id": "Iv1.REPLACE_ME",
  "app_id": 123456,
  "installation_id": 234567,
  "repositories": [
    {"id": 345678, "owner": "OWNER", "name": "REPOSITORY"}
  ],
  "permissions": {"metadata": "read", "issues": "write"},
  "webhook_secret": "REPLACE_WITH_32_OR_MORE_BYTES",
  "private_key_pkcs1_der_base64": "REPLACE_WITH_BASE64_PKCS1_DER"
}
```

Add it with `rekey credential add-github-app LABEL --file profile.json`. Keep
the profile owner-readable only and delete the plaintext file after the
encrypted mutation succeeds. The corresponding Action must use origin
`https://api.github.com`, `authorization` with prefix `Bearer `, and either
`GET /installation/repositories` with no body or
`POST /repos/OWNER/REPOSITORY/issues` with a closed JSON `title`/`body` input.
Provider responses are reduced to the documented non-secret fields.

Rotate the whole typed profile from a regular file:

```bash
rekey credential rotate-github-app CREDENTIAL_ID --file profile.json
```

There is no public webhook listener. Forward a raw GitHub delivery through the
owner-only Admin socket; the signature covers the exact file bytes and the
expected version makes a successful delivery non-repeatable:

```bash
rekey credential apply-github-webhook CREDENTIAL_ID \
  --expected-version 3 --event installation_repositories \
  --delivery DELIVERY_UUID --signature 'sha256=LOWERCASE_HEX' \
  --file payload.json
```

Only a non-empty `added` or `removed` repository delta for the exact
installation is accepted. Exchange, create-issue, revoke, transport failures,
and mutative effects are never retried; repository listing may retry once only
for a bounded canonical `Retry-After` response.

## Vault KV v2 fixed-version source

This fixture-bounded feature is in this Alpha archive. It resolves one exact
string from one exact HashiCorp Vault KV v2 version and uses it only as the
credential for an existing fixed HTTPS Action. Create an owner-readable profile
and delete it after the encrypted Admin mutation succeeds:

```json
{
  "credential_type": "vault-kv-v2-source-v1",
  "origin": "https://vault.example.com",
  "mount": "secret",
  "path": "agents/github",
  "key": "token",
  "version": 7,
  "vault_token": "hvs.REPLACE_ME"
}
```

```bash
rekey credential add-vault-kv LABEL --file profile.json
rekey credential rotate-vault-kv CREDENTIAL_ID --file profile.json
```

The Broker issues only `GET /v1/MOUNT/data/PATH?version=N` with
`X-Vault-Token`, through the existing public-address HTTPS screen. It does not
retry the source request. The selected response field must be the only field in
`data.data`, must be a visible-ASCII string no larger than 8 KiB, and must match
the configured nonzero version. Deleted, destroyed, malformed, reflected, or
wrong-version results stop before the final Action request.

The Agent cannot select the Vault location or read either the Vault token or
resolved value. Private Vault networks, private CA configuration, latest/alias
resolution, Vault authentication flows, namespaces, cloud secret/KMS
providers, 1Password, HSM, keychain, and generic source templates are not
supported.

## Vault one-shot dynamic lease source

This fixture-bounded feature is in this Alpha archive. It acquires one bounded
Vault dynamic lease, uses one selected string as the credential for an existing
fixed HTTPS Action, and synchronously revokes the exact lease before returning
success:

```json
{
  "credential_type": "vault-dynamic-source-v1",
  "origin": "https://vault.example.com",
  "mount": "database",
  "role": "agent-api-token",
  "key": "token",
  "vault_token": "hvs.REPLACE_ME"
}
```

```bash
rekey credential add-vault-dynamic LABEL --file profile.json
rekey credential rotate-vault-dynamic CREDENTIAL_ID --file profile.json
```

The Broker sends one non-retried `GET /v1/MOUNT/creds/ROLE`, accepts only a
5–300 second lease with one exact selected visible-ASCII string, executes the
fixed Action, then sends `POST /v1/sys/leases/revoke` with the exact lease ID
and `sync: true`. A revoke failure hides any Action response and returns a
non-retryable indeterminate result.

Rekey does not renew leases or persist an outstanding-lease registry. A hard
process or host crash may leave the lease active until Vault expires it, so
this feature does not claim crash-time cleanup, general Vault support, or
private-network support.

## Connector SDK contract

The source-only [fixed Keycloak exchange](superpowers/specs/2026-09-10-keycloak-token-exchange-oau02.md)
stores an operator-owned encrypted profile and executes one registered GET for
one audience. Use `rekey credential add-keycloak LABEL --file PROFILE` or
`rekey credential rotate-keycloak ID --file PROFILE`; proof is read through the
existing hidden TTY flow. Keep the profile file owner-only. It contains the
client secret and subject access token and must not go through Agent messages.
The Broker exchanges, executes, seals the response and directly revokes the
issued token before returning success. There is no refresh or automatic retry;
replace an expired or withdrawn subject token through the typed rotate command.
See the spec for exact fields and resource-server revocation limits.

This source uses storage format 10 and rejects older state/backups without
migration. Published alpha.2 and its recorded backup acceptance use format 9.

The development tree contains the IO-free `rekey-connector` library. The library
itself is not an MCP server. The source-only
[MCP-03 stdio executable](superpowers/specs/2026-09-10-local-mcp-stdio.md)
adds an operator-configured Agent IPC adapter; it is not packaged in this Alpha.
Its compile-time registry gives integrators stable versioned descriptors for
the existing opaque-header, closed GitHub App, closed Vault KV v2 source, and
one-shot Vault dynamic source paths. It also provides a pure
MCP tool projection for authorized Actions whose policy input schema explicitly
has an object root, plus a redacted RFC 8693 OAuth exchange descriptor that
contains only fixed public metadata.

This does not add a CLI command, MCP server, OAuth authorization flow, provider
discovery, live generic token exchange, or dynamic connector. The built-in
Vault source is Broker-owned and is not exposed as a generic SDK adapter. An MCP
host must keep the Rekey capability outside tool arguments and
call the existing Agent IPC operation. MCP client tokens must never be reused
as upstream provider tokens. Connector selection does not move credential,
network, audit, deadline, sealing, lease, or revoke ownership out of `rekeyd`.

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

## First Agent shell integration (source checkout)

The source-only `scripts/agent-quickstart.py` provides an explicit shell entry
for a host such as Codex CLI. It prepares one Action and a short session on a
dedicated, unlocked vault. It refuses existing policy/trust so it cannot replace
your other grants. This is a bounded onboarding flow, not an MCP server or an
automatic signing service.

Build with `cargo build --workspace`. In your operator terminal:

```bash
target/debug/rekey --state-dir /tmp/rekey-agent-demo init
target/debug/rekey --state-dir /tmp/rekey-agent-demo serve
# In another operator terminal:
target/debug/rekey --state-dir /tmp/rekey-agent-demo unlock
python3 scripts/agent-quickstart.py prepare \
  --rekey target/debug/rekey --state-dir /tmp/rekey-agent-demo \
  --repo OWNER/DEDICATED-TEST-REPO --output /tmp/rekey-agent-handoff
```

Record the recovery key from init. Enter the dedicated GitHub token only in
the hidden credential prompt, with Issues: Write on that test repository.
The test repository must also have Issues enabled. After an indeterminate
write result, inspect the repository and audit trail before any new attempt.
Every Admin mutation still prompts for its step-up proof. `--credential ID`
reuses an existing credential. To use an existing fixed Action instead of
creating the GitHub Action, pass `--action ID@VERSION --schema schema.json`.

Review `policy-draft.json`: it permits one principal to execute one Action
version, accepts only the indicated request schema, and expires with the
15-minute/10-use session. Have your external signer produce `trust.json` and
`bundle.json`. Then activate them in the operator terminal:

```bash
target/debug/rekey --state-dir /tmp/rekey-agent-demo policy trust install --file trust.json
target/debug/rekey --state-dir /tmp/rekey-agent-demo policy activate --file bundle.json
```

For a disposable local demo only, the repository's external **test signer**
can produce those artifacts; keep the private key outside the Agent workspace:

```bash
python3 scripts/sign-test-policy.py policy --key-dir /tmp/rekey-demo-signer \
  --snapshot /tmp/rekey-agent-handoff/policy-draft.json \
  --trust /tmp/rekey-demo-trust.json --bundle /tmp/rekey-demo-bundle.json
```

Use these two generated paths in the activation commands. The test signer is
not a production key-management workflow. Rekey itself never generates or
stores the signer private key.

Give the host the absolute script and handoff paths plus this instruction:

> To create an issue in the authorized test repository, write a JSON file
> with `title` and optional `body`, then run `python3 /ABS/REKEY/scripts/agent-quickstart.py
> execute --handoff /tmp/rekey-agent-handoff --body-file /ABS/request.json`.
> Report the returned issue URL. On failure, stop and ask the operator to
> repair access. Never ask for a token or vault password in chat and never
> automatically retry a write whose outcome is uncertain.

The wrapper uses only `agent.sock` for execution. Capability input travels
over stdin, not argv or environment. The handoff directory is 0700 and files
are 0600; it contains a short-lived capability, so do not commit or paste it.
The wrapper exits nonzero on upstream HTTP errors. A host shell must be able
to access the script, handoff and Unix socket; this adds no OS isolation.

If the credential becomes unavailable, the operator inspects `credential list`
and uses `credential rotate ID` in a trusted terminal, then explicitly retries
after checking whether an effect already occurred. A revoked credential may
need a new credential and Action version; `rotate` does not undo revocation.
Lock/restart/expiry requires a new session and a newly signed policy naming its
new principal. The bounded helper does not renew sessions or edit existing
policy; use the existing Admin commands for subsequent sessions. To close a
demo immediately, `rekey --state-dir /tmp/rekey-agent-demo lock` revokes its
sessions. Remove the temporary handoff and demo signing key when finished.

## Public Vault Layer B acceptance (operator terminal)

Prepare a public HTTPS Vault test origin, an exact KV version or dynamic role,
and a disposable token. The public source JSON omits `vault_token`, for example:

```json
{"credential_type":"vault-kv-v2-source-v1","origin":"https://YOUR-VAULT-HOST",
 "mount":"secret","path":"agents/test","version":1,"key":"token"}
```

Prepare `action.json` as a fixed HTTPS Action (its credential_id is replaced
by the harness) and `schema.json` for the request. The target should accept
the selected credential and return your expected status only on success.

```bash
cargo build --release -p rekey-cli -p rekey-broker
python3 scripts/dogfood-vault.py --source source-public.json \
  --action action.json --schema schema.json --body-file request.json \
  --expected-status 200 --receipt /tmp/rekey-vault-layer-b.json
```

Use `vault-dynamic-source-v1` with `mount`, `role`, `key` and public `origin`
for the dynamic path. A hidden prompt reads the token. The harness creates and
removes a disposable local vault and test signer, uses production TLS/IP
screening, and writes a new metadata-only receipt only after the expected HTTP
status and audit sequence pass. It does not deploy Vault or configure provider
permissions. Dynamic receipt validation requires `vault.lease.issued` and
`vault.lease.revoked` before `execution.finished`. Provider expiry still bounds
crash-time cleanup. No public run is claimed merely by adding this script.

## Errors and exit codes

| Exit | Meaning | Typical codes |
| --- | --- | --- |
| 2 | Invalid input, frame, or policy | `USAGE`, `INVALID_INPUT`, `POLICY_INVALID` |
| 3 | Locked or authentication failure | `LOCKED`, `AUTHENTICATION_FAILED`, `UNLOCK_RATE_LIMITED` |
| 4 | Authorization/capability/credential denial | `ACTION_DENIED`, `INVALID_CAPABILITY`, `CREDENTIAL_UNAVAILABLE` |
| 5 | Durable state, crypto, audit, or bootstrap failure | `STORAGE_UNAVAILABLE`, `FAULTED`, `RESTORE_FAILED` |
| 6 | Upstream transport/size failure | `UPSTREAM_FAILED`, `RESPONSE_TOO_LARGE` |
| 7 | Other explicit failure | code shown on stderr |
| 8 | Post-effect security/audit uncertainty | `UPSTREAM_INDETERMINATE`, `RESPONSE_SECURITY_VIOLATION`, `AUDIT_COMMIT_FAILED_AFTER_EXECUTION` |

An exit 8 means a remote effect may have occurred; do not blindly retry.

If a domain resolves only into `198.18.0.0/15`, Clash/TUN Fake-IP is being
rejected by design. Configure real DNS for that exact host; never weaken
private-IP screening or set a proxy environment variable as a workaround.
