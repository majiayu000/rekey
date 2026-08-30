# rekey

Local credential authority for AI agents: agents execute fixed, pre-registered
actions through short-lived capability tokens and **never see real
credentials**. Secrets live in an encrypted SQLite vault owned by a single
broker process; the CLI, agents, and everything they spawn talk to it only
over two permission-separated Unix sockets.

> Status: v2 foundation (P0) **G1 development candidate**, not a G1 security
> release and not G2. Credentials never appear in agent-facing APIs, process
> arguments, environment variables, logs, or audit records. Same-user
> `ptrace`, process memory, and filesystem access are out of G1. Canonical
> feature status: `docs/product-foundation/feature-truth-matrix.md`.

The production transport rejects all non-public address ranges, including
`198.18.0.0/15`. On systems where a TUN proxy returns that range as fake DNS
answers, domain-based Actions fail closed until the host supplies real DNS;
Rekey does not silently allow the fake-IP range or honor proxy environment
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

```bash
cargo build --release   # produces `rekey` (CLI) and `rekeyd` (broker)

rekey init                       # create vault; shows recovery key ONCE
rekey serve                      # run broker in foreground (starts locked)

rekey unlock                     # hidden password prompt
rekey credential add github-token
rekey action create --file action.json
rekey session create --action <ACTION_ID>@1 --ttl 1h --max-uses 100
# hand the printed capability token to the agent, then:
rekey execute <ACTION_ID>@1 --capability - --body-file req.json
```

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

Design: `docs/superpowers/specs/2026-08-28-credential-authority-v2-foundation.md`

Feature status: `docs/product-foundation/feature-truth-matrix.md`

P0 acceptance (release binaries, no FakeTransport): `scripts/p0-acceptance.sh`

GitHub create-issue dogfood (opt-in, dedicated fine-grained token entered
through a hidden TTY prompt; exits nonzero unless GitHub returns 201):

```bash
scripts/dogfood-github.sh --repo owner/name
```

## License

MIT
