# P-07 Vault OSS protocol interop

> Status: specified; not implemented. Does not change P-07A/P-07B behavior.
>
> Date: 2026-09-07
>
> Tracking: follow-on to [Issue #31](https://github.com/majiayu000/rekey/issues/31)
> after P-09 PR #39. Open a dedicated child issue before the implementation PR.
>
> Depends on: P-07A KV v2 source, P-07B one-shot dynamic lease,
> Feature Truth Matrix Vault rows (currently Black-box Verified, no live Vault)

## Objective

P-07A and P-07B speak Vault's documented HTTP shapes, but today's black-box
evidence is a Rust local-CA fixture (`p2_github_app_fixture`), not HashiCorp
Vault. This slice proves the same closed profiles against a real Vault OSS
binary without adding providers, private-network product support, or a
private-IP exception.

This is not P-07C. Other cloud/KMS/1Password/PKCS#11 sources stay paused.

## Current evidence

| Area | Evidence | Implication |
| --- | --- | --- |
| KV v2 | `vault_source_contract`, `scripts/p7-vault-kv-source.sh` | Exact versioned read and sealing pass against a mock |
| Dynamic lease | `vault_dynamic_contract`, `scripts/p7-vault-dynamic-source.sh` | One-shot `creds` + sync revoke pass against a mock |
| Production transport | public HTTPS, no redirects, private IP refused | A Vault on `127.0.0.1` cannot be a product origin |
| GitHub analog | `scripts/dogfood-github.sh` vs `api.github.com` | Field Validated required a public origin and TTY secrets |

## Chosen shape

Two layers, separate claims:

```text
product/app
  - no new CLI verbs; reuse credential add-vault-kv / add-vault-dynamic

runtime/application
  - BrokerRuntime and screened HTTPS unchanged
  - no private-address allowlist

adapters/backends
  - Layer A: HashiCorp Vault OSS (pinned version) behind the existing
    LocalTlsTransport fixture address injection (same bypass p7 already uses)
  - Layer B (optional, not CI): public HTTPS Vault dogfood, GitHub-style TTY

testing/headless
  - Linux CI script for Layer A
  - opt-in script for Layer B; secrets never from env/argv
```

Layer A may move the Matrix notes from "mock HTTP" to "Vault OSS binary via
the local-CA fixture." It must not say Field Validated, private Vault
networks, or HashiCorp Cloud.

Layer B is the only path to Field Validated, and only for the exact origin,
mount, and operation exercised.

## 1. Layer A — Vault OSS binary, local CA/TLS fixture

### Inputs

- HashiCorp Vault OSS, version pinned in the script (no `latest`).
- A test CA and leaf certificate whose SAN is `vault.test.local`.
- Vault TLS listener on `127.0.0.1`.
- KV v2 mount `secret` with one exact path/version/key used by P-07A.
- For P-07B: one `creds` role that returns a JSON object containing the
  selected string field, plus working `sys/leases/revoke` with `sync: true`.
  Prefer Vault's cubbyhole- or KV-unrelated secrets engine that can issue
  leases without shipping a database. If a database engine is required, the
  script starts an ephemeral local engine and still injects the listen
  address after screening. Document the engine. Do not widen the Rekey
  profile.

### Broker wiring

Reuse the existing fixture pattern: public-address screening still runs;
`LocalTlsTransport` then connects to the Vault listen address with the test
CA. Do not add a production private-IP exception. Do not point unmodified
`rekeyd` at `127.0.0.1`.

CLI remains release `rekey`. The fixture binary may stay an example under
`rekey-broker`; do not link Vault into `rekey-cli`.

### Proofs

1. KV v2: exact `GET /v1/:mount/data/:path?version=:version`, inject the
   resolved value into one fixed HTTPS Action, rotate the source profile,
   sealing canaries absent from Agent output, argv, env, and audit export.
2. Dynamic: one `GET /v1/:mount/creds/:role`, inject selected field, exact
   sync revoke before success, failure path still attempts cleanup.
3. Wrong version / missing key / revoked token fail closed with no Agent
   secret.
4. Workspace fmt/check/clippy/tests, mechanical forbidden APIs, CLI
   `cargo tree` negative dependencies.

Missing `vault` on macOS CI is skip-by-OS, not a silent pass on Ubuntu.
Ubuntu security-gate must install the pinned binary.

## 2. Layer B — public HTTPS dogfood (optional)

Follow `scripts/dogfood-github.sh`:

- Interactive TTY for the vault token; never env, argv, or a file flag.
- Operator supplies a public HTTPS origin that already passes Rekey's IP
  screen.
- One KV v2 read and one fixed Action, or one dynamic lease plus revoke.
- Throwaway vault under `$TMPDIR`; delete on exit.
- Nonzero unless upstream success matches the closed profile.

This layer is not a CI secret. It does not authorize private RFC1918 Vault
origins.

## 3. Explicit non-goals

- Private-network source access or `--insecure` TLS.
- Vault namespaces, AppRole, Kubernetes/OIDC auth, token renewal, KV v1,
  writes, latest/alias, lease renewal, or crash-time revoke (P-07B already
  refuses those product claims).
- OpenBao compatibility as a declared target (incidental OSS protocol match
  is not a support promise).
- Inclusion in `v2.0.0-alpha.1`. Next-Alpha inclusion of the Vault kinds
  remains optional even after Layer A, per the alignment plan.
- Other P-07 providers.

## 4. Completion criteria

Layer A is complete only when Ubuntu CI runs HashiCorp Vault OSS against
both closed profiles through the fixture transport, and the Matrix notes
say so without upgrading topology or calling it Field Validated.

Layer B is complete only after one recorded public-HTTPS run with
disposable credentials, analogous to the GitHub App dogfood row.

## 5. Readiness language

After Layer A: "Rekey's closed Vault KV v2 and one-shot dynamic-lease
sources interoperate with HashiCorp Vault OSS in a local-CA test fixture."

Not claimed: general Vault support, private Vault, HA Vault, enterprise
namespaces, or "live HashiCorp Cloud."
