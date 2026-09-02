# rekey — Project Rules

## What is this

Rekey v2: a local Credential Authority for AI agents. Agents call fixed,
admin-registered actions through a capability token and never see real
credentials. Breaking rewrite — no v1 vault, MITM, system CA, dashboard,
single-port proxy, or TCP passthrough exists anymore.

## Build

- `cargo check --workspace` after every change
- `cargo test --workspace` before commit
- `cargo fmt --all` before commit
- Mechanical contracts (must stay clean):
  - `rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests src` → no matches
  - `rg -n 'get_secret\b|read_secret|export_secret' crates/rekey-domain crates/rekey-broker crates/rekey-cli` → no matches
  - `cargo tree -p rekey-cli -e normal` → no rusqlite / aes-gcm / argon2 / reqwest / rekey-vault / rekey-broker

## Architecture

Cargo workspace, 5 crates + root integration-test host:

- `rekey-domain` — pure models, invariants, typed errors, IPC wire codec (no IO)
- `rekey-policy` — canonical typed policy snapshots, schema validation, and a
  deterministic default-deny evaluator (no credential IO)
- `rekey-vault` — envelope crypto (Argon2id/HKDF → VRK → per-version DEK → payload,
  84-byte binary AAD), SQLite store (WAL + synchronous=FULL, STRICT tables),
  offline bootstrap (init/restore), AuthorityWorker (single owner of the DB
  connection, VRK, and all credential mutations)
- `rekey-broker` — BrokerRuntime: two Unix sockets (admin.sock / agent.sock,
  0600), capability SessionRegistry, fixed-HTTP-action executor with response
  secret sealing; ships the `rekeyd` binary (serve/init/restore)
- `rekey-cli` — `rekey` binary, pure IPC client; delegates init/serve/restore
  to `rekeyd` so the CLI never links crypto or SQLite

## Key Design Decisions

- Agent API has no get/read/export secret operation — only ExecuteFixedHttpAction
  with a short-lived capability token; decrypted payloads exist once as a
  consume-once `PreparedCredential`
- Admin mutations require a step-up unlock proof on every call
- Secrets travel only in frame bodies / hidden TTY / explicit stdin flags —
  never argv, env, JSON metadata, logs, or audit rows
- Audit commit failure fails closed (worker faults); execution.started commits
  before any credential is decrypted
- Upstream: fixed origin/method/path, redirects disabled, proxy env ignored,
  non-public IPs refused, bounded bodies, reflected-secret sealing
- The default topology remains G1 (same-user local). G2 claims are limited to
  the bounded Linux container/namespace reference topology and its attack harness
- No backward compatibility: non-empty legacy state dirs are rejected, never
  migrated or overwritten

## Spec & Baselines

- Implementation spec: `docs/superpowers/specs/2026-08-28-credential-authority-v2-foundation.md`
- Public technical baselines:
  - `docs/product-foundation/feature-truth-matrix.md`
  - `docs/product-foundation/threat-model-v2.md`
- Other product/enterprise research under `docs/product-foundation/` is not a
  repository behavior source unless it is explicitly tracked later
- If code and spec disagree, fix the spec (and baselines) first, then the code
- 2026-04-01 design/plan docs are superseded; never treat them as behavior sources
