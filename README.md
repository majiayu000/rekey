# rekey

Local credential authority for AI agents: agents execute fixed, pre-registered
actions through short-lived capability tokens and **never see real
credentials**. Secrets live in an encrypted SQLite vault owned by a single
broker process; the CLI, agents, and everything they spawn talk to it only
over two permission-separated Unix sockets.

> Status: `2.0.0-alpha.1` public Alpha candidate with bounded P1 and P2.1
> implementations. The default product is G1 and is not G2. Credentials never
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
# put the returned principal_id and Action version in a typed snapshot:
rekey policy activate --file policy.json
# hand the printed capability token to the agent, then:
rekey execute <ACTION_ID>@1 --capability - --body-file req.json
```

The recovery key can unlock the running broker, satisfy an explicit Admin
step-up with `--recovery`, or verify an offline backup restore. The current
Foundation does not change/reset the vault password or replace key wrappers.

For explicit automation, password/recovery-only commands use
`--password-stdin`; `rekey credential add` and `rekey credential rotate` use
`--stdin-secrets` for the step-up proof and Credential value. Add `--recovery`
when that proof is the recovery key. Secrets are never accepted as argument
values or environment variables.

Policy snapshots are JSON-only, default-deny, in-memory, and exact-principal;
lock or restart clears the active snapshot. The normative snapshot schema is
in the P1.1 section of the implementation spec linked below.

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
