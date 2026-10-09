# rekey — Project Rules

## Computer Use

- 打开文件、目录、网页或应用时，只要能通过终端或命令（例如 macOS 的 `open`）完成，就使用命令工具，不使用 Computer Use，也不通过 Computer Use 打开终端。
- 只有命令、API 或专用工具无法完成、确实需要原生界面交互的步骤，才使用 Computer Use。

## What is this

Rekey 0.3 personal-first Credential Authority (v3 design) (`0.3.0-alpha.2`, alpha). Agents call fixed or template,
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
  - `cargo tree -p rekey-cli -e normal` → no rusqlite / aes-gcm / argon2 / reqwest / rekey-vault / rekey-broker / rekey-connector

## Architecture

Cargo workspace, 7 crates + root integration-test host:

- `rekey-domain` — pure models, invariants, typed errors, IPC wire codec (no IO)
- `rekey-connector` — versioned compile-time connector contracts, built-in
  registry, testkit, and pure MCP/OAuth projections (no IO or secrets)
- `rekey-policy` — canonical typed policy snapshots, schema validation, and a
  deterministic default-deny evaluator (library has no credential IO; separate
  operator signer binaries perform protected-file and fixed signing IO)
- `rekey-approval-relay` — independent single-organization HTTPS approval-file
  transport with fixed IdP introspection and its own SQLite transport receipts;
  no credential authority, signing decision, or Broker public listener
- `rekey-vault` — envelope crypto (Argon2id/HKDF → VRK → per-version DEK → payload,
  84-byte binary AAD), SQLite store (WAL + synchronous=FULL, STRICT tables),
  offline bootstrap (init/restore), AuthorityWorker (single owner of the DB
  connection, VRK, and all credential mutations)
- `rekey-broker` — BrokerRuntime: two Unix sockets (admin.sock / agent.sock,
  0600), capability SessionRegistry, shared fixed/template executor with response
  sealing, local approvals, signed Profiles and a bounded loopback SDK gateway; ships the `rekeyd` binary (serve/init/restore)
- `rekey-cli` — `rekey` binary, pure IPC client; delegates init/serve/restore
  to `rekeyd` so the CLI never links crypto or SQLite

## Key Design Decisions

- Agent API has no get/read/export secret operation — only ExecuteFixedHttpAction
  with a short-lived capability token; decrypted payloads exist once as a
  consume-once `PreparedCredential`
- Sensitive A2 operations require a fresh proof, including all-state SHUTDOWN
  and plaintext reveal; A1 desktop tokens cannot replace it. Presence is
  accepted only while unlocked with an active process-local verifier. Offline
  restore and VRK rewrapping still require their original decryption factors.
  Presence cannot issue seven-day grants, change passwords, or rotate recovery keys.
- Secrets travel only in frame bodies / hidden TTY / explicit stdin flags —
  never argv, env, JSON metadata, logs, or audit rows. Profile `run` supplies
  its short-lived capability to the child environment as an explicit exception;
  this is never an upstream credential
- Audit commit failure fails closed (worker faults); execution.started commits
  before any credential is decrypted
- Upstream: fixed origin/method and authenticated fixed or validated template
  target, redirects disabled, proxy env ignored,
  non-public IPs refused, bounded bodies, reflected-secret sealing
- Current confirmed floor is L1-dev. Peer verification alone does not establish
  L1; V1/V2, protected anchors and actual isolation require separate evidence.
  Linux Profile netns and Codex Seatbelt limitations must not be hidden.
- No migration, old-format double reader or backfill, permanently. Vault25 /
  policy6 remain frozen across all 0.3 releases, including prereleases and `lab`.
  The product version is 0.3; v3 names the design stage. Preserve durable layouts
  and canonical signing semantics; incompatible changes require a separately
  planned release line and a prior SPEC revision. Stop feature expansion during
  the seven-day dogfood period; fix only evidenced safety/correctness/release blockers.
- Default features are empty; enterprise execution requires `--features lab`.
- Ordinary unlock is not rollback consent. Explicit confirmation binds current
  context; never delete or lower generation history to make a snapshot unlock.

## Spec & Baselines

- Active v3 specification: `docs/superpowers/specs/2026-10-02-rekey-v3-personal-first.md`
- Implemented versus pending v3 scope: `docs/superpowers/plans/2026-10-03-v3-implementation.md`
- Historical foundation (v3 supersedes conflicting clauses): `docs/superpowers/specs/2026-08-28-credential-authority-v2-foundation.md`
- Public technical baselines:
  - `docs/product-foundation/feature-truth-matrix.md`
  - `docs/product-foundation/threat-model-v2.md`
- Other product/enterprise research under `docs/product-foundation/` is not a
  repository behavior source unless it is explicitly tracked later
- If code and spec disagree, fix the spec (and baselines) first, then the code
- 2026-04-01 design/plan docs are superseded; never treat them as behavior sources

## 0.4 Agent call implementation

- Active contract: `docs/superpowers/specs/2026-10-05-rekey-agent-call-model.md`. This overrides conflicting 0.3 Profile/run/capability and format-freeze clauses for this release line.
- Local callers invoke signed Connection rules without capability tokens; caller labels can only restrict rules. Secrets remain inside the Authority.
- Implement and validate milestone gates before claiming release readiness. Preserve the old vault; initialize a new 0.4 vault with no migration.
- For this implementation's external Agent acceptance, the user requires Codex only. Do not run Claude CLI, account, model or plugin tests, or change Claude login state. Preserve historical results without inferring that a particular account is suspended.

## Unified development line

`docs/superpowers/specs/2026-10-09-unified-experiments.md` is the active integration contract for 0.5 development (vault27/policy8). It supersedes conflicting format freezes for this checkout only. Published 0.4/0.3 vaults are preserved; no migration or dual reader. Integration remains unvalidated until the combined-head gates pass.
