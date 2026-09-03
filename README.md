# rekey

Local credential authority for AI agents: agents execute fixed, pre-registered
actions through short-lived capability tokens and **never see real
credentials**. Secrets live in an encrypted SQLite vault owned by a single
broker process; the CLI, agents, and everything they spawn talk to it only
over two permission-separated Unix sockets.

> Status: `2.0.0-alpha.1` is the public Alpha. Password lifecycle, local audit
> query/export, signed approvals/policy, workload identity, and the connector
> contract SDK are post-Alpha development changes not included in that tag.
> The default product is G1 and is not G2. Credentials never
> appear in agent-facing APIs, process
> arguments, environment variables, logs, or audit records. Same-user
> `ptrace`, process memory, and filesystem access are out of G1. Canonical
> feature status: `docs/product-foundation/feature-truth-matrix.md`.

The production transport rejects all non-public address ranges, including
`198.18.0.0/15`. On systems where a TUN proxy returns that range as fake DNS
answers, domain-based Actions fail closed until the host supplies real DNS;
Rekey does not silently allow the fake-IP range or honor proxy environment
variables.

To diagnose a blocked domain Action, resolve its exact Action host before
changing Rekey:

```bash
dig +short api.github.com
```

If every answer is inside `198.18.0.0/15`, configure the TUN client to return
real DNS for that exact host (for Clash, add it to `dns.fake-ip-filter`), then
rerun `dig` and the Action. Do not solve this by adding private ranges to
Rekey, disabling endpoint screening, or setting HTTP proxy environment
variables.

## How it works

```
admin (you)                      agent (untrusted)
  │ rekey unlock / credential /     │ rekey execute ACTION@V --capability TOKEN
  │ action / session …              │
  ▼                                 ▼
admin.sock ──────► rekeyd broker ◄────── agent.sock
                     │  AuthorityWorker: SQLite + envelope crypto
                     │  (Argon2id → VRK → per-version DEK → payload)
                     ▼
              fixed HTTPS upstream (origin/method/path/auth pinned by admin)
```

- Credentials are stored envelope-encrypted (AES-256-GCM, binary AAD binding
  vault/credential/version/purpose) and decrypted only after capability,
  action, and audit checks pass — once per request, zeroized after use.
- The agent wire protocol has no secret-read operation and no way to choose
  origin, method, path, auth headers, or redirects.
- Responses are size-bounded, header-filtered, and scanned for reflected
  secrets (raw, base64, base64url, percent-encoded) before the agent sees them.

## Quick start

Download, checksum, and attest the supported GitHub Release archive by following
[`docs/installation.md`](docs/installation.md). Then:

```bash
rekey init                       # create vault; shows recovery key ONCE
rekey serve                      # run broker in foreground (starts locked)

rekey unlock                     # hidden password prompt
rekey credential add github-token
rekey action create --file action.json
rekey session create --action <ACTION_ID>@1 --ttl 1h --max-uses 100
# have an external Ed25519 signer create trust.json and a signed bundle.json:
printf '%s\n' "$STEP_UP_PROOF" | \
  rekey policy trust install --file trust.json --step-up-stdin
printf '%s\n' "$STEP_UP_PROOF" | \
  rekey policy activate --file bundle.json --step-up-stdin
# hand the printed capability token to the agent, then:
rekey execute <ACTION_ID>@1 --capability - --body-file req.json
```

The recovery key can unlock the running broker, satisfy an explicit Admin
step-up with `--recovery`, or verify an offline backup restore. With the broker
unlocked, `rekey password change` atomically replaces the password wrapper;
add `--recovery` when the current password is lost. `rekey recovery rotate`
requires the current password, replaces the recovery wrapper, and displays the
new recovery key once. Neither operation rotates the VRK or Credential data.

Operators can inspect redacted local audit metadata while the broker is locked:

```bash
rekey audit list --limit 50
rekey audit list --request REQUEST_ID --outcome denied
rekey audit export --output /secure/new/audit.jsonl
```

List results use a stable sequence snapshot and bounded pages. Export creates a
new mode-0600 JSONL file and never overwrites or follows a symlink. Audit output
omits secrets, bodies, headers, capability tokens, resource IDs, and parameter
hashes. It is sensitive operational metadata, not an encrypted backup. Local
retention is append-only for the vault lifetime; SIEM, WORM, legal hold, remote
delivery, configurable retention, and audit deletion are not implemented.

For explicit automation, proof-only commands use `--password-stdin`;
`rekey password change --stdin-secrets`, `rekey credential add`, and
`rekey credential rotate` read the step-up proof on line 1 and the new secret
on line 2. Add `--recovery` when that proof is the recovery key. Secrets are
never accepted as argument values or environment variables.

Policy trust installation and signed-bundle activation use the P03-specific
`--step-up-stdin` flag. The one Ed25519 trust root is immutable per vault;
signed bundles have VRK-authenticated lifecycle seals, activate only at
consecutive versions, and are reverified after each unlock. Rekey verifies externally produced
signatures but never creates or stores policy-signing or approver private keys.
Lock and restart revoke capability sessions, challenges, and approval-use state,
while the persisted policy reloads only after a successful unlock.

Policy snapshot v3 may also map exact generic OIDC, SPIFFE JWT-SVID,
Kubernetes service-account, or CI/cloud identities to policy principals using
pinned Ed25519 or RS256 public keys. A workload can then mint a bounded session
through `agent.sock` without an Admin step-up:

```bash
rekey session create --action <ACTION_ID>@1 --ttl 15m --max-uses 20 \
  --workload-token-stdin < workload.jwt
```

The JWT is consumed once and replay denial persists across restart and any
restore whose backup already contains the consumption record. A new-version
policy activation revokes workload-minted sessions; an exact same-bundle retry
preserves them. Rekey does
not fetch JWKS, discover issuers, introspect tokens, or hold issuer private
keys; see [`docs/user-guide.md`](docs/user-guide.md#create-a-workload-attested-session).

For a `require-approval` rule, prepare the exact typed request, send the emitted
challenge to an external approver, and execute with one or two returned grants:

```bash
printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey approval prepare <ACTION_ID>@1 --capability - \
    --body-file req.json --content-type application/json >challenge.json

printf '%s\n' "$CAPABILITY_FROM_SECURE_STORAGE" | \
  rekey execute <ACTION_ID>@1 --capability - \
    --body-file req.json --content-type application/json \
    --approval grant.json
```

The grant is bound to the challenge, session, principal, exact Action/resource,
canonical parameters, determining rule, policy version/digest, validity window,
and use limit. Rekey provides no remote approval service, notification UI,
human directory, private-key custody, or approval survival across lock/restart.

`action.json`:

```json
{
  "name": "github-create-issue",
  "credential_id": "<CREDENTIAL_ID>",
  "origin": "https://api.github.com",
  "method": "POST",
  "exact_path": "/repos/you/repo/issues",
  "auth_header": "authorization",
  "auth_prefix": "Bearer ",
  "timeout_ms": 30000,
  "request_max_bytes": 65536,
  "allowed_extra_headers": ["x-request-id"],
  "response_max_bytes": 262144,
  "allowed_response_headers": ["content-type"]
}
```

## Connector contract SDK

Development head includes the IO-free `rekey-connector` crate. Its versioned,
compile-time registry describes the four existing built-ins:
`fixed-http-header@1` (`inject`) and `github-app-installation@1`
(`sign → exchange → lease → revoke`), plus `vault-kv-v2-source@1`
(`resolve → inject`) and `vault-dynamic-source@1`
(`resolve → lease → inject → revoke`). Broker code still owns every credential, network effect,
deadline, audit event, response-sealing decision, and cleanup.

The SDK can project an object-shaped authorized Action schema into a stable MCP
tool descriptor and can describe the public fields of an RFC 8693 OAuth token
exchange. These are pure library contracts, not an MCP server or a live generic
OAuth connector. They accept no provider token, client secret, capability, or
dynamic plugin. Development head now extends the same closed GitHub connector
through P-06 with 1-16 exact repositories, bounded issue creation, typed
rotation, Admin-forwarded signed repository deltas, and read-only bounded
retry. Those additions are not part of the published `v2.0.0-alpha.1` archive.

Development head also supports one closed HashiCorp Vault KV v2 source for an
existing fixed HTTPS Action. The encrypted profile pins one public HTTPS Vault
origin, mount, path, exact nonzero version, exact string key, and Vault token.
Each execution performs one non-retried versioned KV read, seals the source
token and resolved value, and then injects that value into the already-fixed
Action request. Add or rotate the profile with:

```bash
rekey credential add-vault-kv LABEL --file profile.json
rekey credential rotate-vault-kv CREDENTIAL_ID --file profile.json
```

This is not general Vault support: there is no latest-version lookup, private
Vault network exception, Vault auth flow, cloud secret/KMS,
1Password, HSM, keychain, generic URL/JSONPath adapter, or new Agent secret API.
It is not included in the published `v2.0.0-alpha.1` archive.

Development head also supports one closed one-shot Vault dynamic source. Each
execution performs one `GET /v1/MOUNT/creds/ROLE`, uses one selected string in
the fixed Action, and withholds the Action response until
`POST /v1/sys/leases/revoke` succeeds for the exact lease with `sync: true`:

```bash
rekey credential add-vault-dynamic LABEL --file profile.json
rekey credential rotate-vault-dynamic CREDENTIAL_ID --file profile.json
```

Lease duration is restricted to 5–300 seconds. Rekey does not renew leases or
claim cleanup after process/host crash; provider expiry bounds that residual
exposure. There is no background lease registry, private Vault networking,
generic provider adapter, or inclusion in `v2.0.0-alpha.1`.

## Not compatible with v1

This is a breaking rewrite. There is no MITM proxy, system CA, dashboard,
single port, or TCP passthrough, and v1 vaults are neither read nor migrated —
a non-empty legacy state directory is rejected untouched. History lives in Git.

## Development

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all
```

The repository pins Rust/MSRV `1.95.0`. No crate is published to crates.io in
this Alpha.

Design: `docs/superpowers/specs/2026-08-28-credential-authority-v2-foundation.md`

Feature status: `docs/product-foundation/feature-truth-matrix.md`

Alpha scope and platform matrix: `docs/alpha-scope.md`

Install/service/uninstall: `docs/installation.md`

User guide: `docs/user-guide.md`

Operations and recovery: `docs/operations-runbook.md`

P0 acceptance (release binaries, no FakeTransport): `scripts/p0-acceptance.sh`

Typed-policy release-process acceptance (UDS, SQLite, local TLS):
`scripts/p1-policy-acceptance.sh`

Signed persistent-policy and approval acceptance:
`scripts/p3-approval-acceptance.sh`

The Linux G2 harness proves only the documented container/namespace reference
topology; it does not upgrade the default G1 product claim:
`scripts/p1-linux-g2.sh`

GitHub create-issue dogfood (opt-in, dedicated fine-grained token entered
through a hidden TTY prompt; exits nonzero unless GitHub returns 201):

```bash
scripts/dogfood-github.sh --repo owner/name
```

## License

MIT
