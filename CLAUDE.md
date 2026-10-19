# rekey — Project Rules

## What is this

Rekey personal-first Credential Authority. Source is the unreleased
`0.5.0-alpha.1` development line (vault27 / policy8); the latest published
release is `0.4.0-alpha.1` (vault26 / policy7). Local Agents call signed
Connection rules and never see real credentials. Breaking rewrite — no v1 vault, MITM, system CA, dashboard,
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
- `rekey-connector` — pure compile-time connector contracts and projections
- `rekey-approval-relay` — lab-only external approval transport, not an approver
  decision or credential authority
- `rekey-policy` — canonical typed policy snapshots, schema validation, and a
  deterministic default-deny evaluator (library has no credential IO; separate
  operator signer binaries perform fixed signing IO)
- `rekey-vault` — envelope crypto (Argon2id/HKDF → VRK → per-version DEK → payload,
  84-byte binary AAD), SQLite store (WAL + synchronous=FULL, STRICT tables),
  offline bootstrap (init/restore), AuthorityWorker (single owner of the DB
  connection, VRK, and all credential mutations)
- `rekey-broker` — BrokerRuntime: two Unix sockets (admin.sock / agent.sock,
  0600), tokenless local CALL against signed Connection rules, shared
  executor with response sealing, local and time-window approvals, MCP, a
  bounded loopback HTTP service and SSH agent; ships the `rekeyd` binary
  (serve/init/restore). Capability sessions and signed Profiles remain lab-only
- `rekey-cli` — `rekey` binary, pure IPC client; delegates init/serve/restore
  to `rekeyd` so the CLI never links crypto or SQLite

## Key Design Decisions

- Agent API has no get/read/export secret operation — Agents invoke signed
  Connection rules (no local capability token since 0.4); decrypted payloads
  exist once as a consume-once `PreparedCredential`
- Sensitive A2 operations require a fresh proof, including all-state SHUTDOWN
  and plaintext reveal. A1 desktop sessions cannot replace that proof.
- Secrets travel only in frame bodies / hidden TTY / explicit stdin flags —
  never argv, env, JSON metadata, logs, or audit rows. Lab-only Profile `run`
  supplies its short-lived capability to the child environment as an explicit
  exception; this is never an upstream credential
- Audit commit failure fails closed (worker faults); execution.started commits
  before any credential is decrypted
- Upstream: fixed origin/method and authenticated fixed or validated template
  target, redirects disabled, proxy env ignored,
  non-public IPs refused, bounded bodies, reflected-secret sealing
- Current confirmed floor is L1-dev. Peer verification alone does not establish
  L1; V1/V2, protected anchors and actual isolation require separate evidence.
  Linux Profile netns and Codex Seatbelt limitations must not be hidden.
- No migration, old-format double reader or backfill, permanently. Each release
  line freezes its formats: 0.3 = vault25 / policy6, 0.4 = vault26 / policy7,
  0.5 = vault27 / policy8. Non-current layouts are rejected; a new line needs a
  new vault. Incompatible changes require a separately planned release line and
  a prior SPEC revision. Never touch the user's existing vault or installed App.
- Default features are empty; enterprise execution requires `--features lab`.
- Ordinary unlock is not rollback consent. Explicit confirmation binds current
  context; never delete or lower generation history to make a snapshot unlock.

## Spec & Baselines

- Active contracts (newest overrides older on conflict):
  - 0.5: `docs/superpowers/specs/2026-10-09-unified-experiments.md`,
    `docs/superpowers/specs/2026-10-09-personal-desktop-security.md`,
    `docs/superpowers/specs/2026-10-09-docker-ha-controller.md`
  - 0.4 Agent call model: `docs/superpowers/specs/2026-10-05-rekey-agent-call-model.md`
  - 0.3 / v3 base: `docs/superpowers/specs/2026-10-02-rekey-v3-personal-first.md`
- Implementation/evidence trackers: `docs/superpowers/plans/2026-10-09-experiment-integration.md`,
  `docs/superpowers/plans/2026-10-05-agent-call-implementation.md`, `docs/superpowers/plans/2026-10-03-v3-implementation.md`
- Historical foundation: `docs/superpowers/specs/2026-08-28-credential-authority-v2-foundation.md`
- Public technical baselines:
  - `docs/product-foundation/feature-truth-matrix.md`
  - `docs/product-foundation/threat-model-v2.md`
- Other product/enterprise research under `docs/product-foundation/` is not a
  repository behavior source unless it is explicitly tracked later
- If code and spec disagree, fix the spec (and baselines) first, then the code
- 2026-04-01 design/plan docs are superseded; never treat them as behavior sources

## Release readiness

- Software checks are not release acceptance. Installed App, real Touch ID /
  device events, provider/CA/SSH hardware deployment, Agent PKI admission and
  multi-host HA stay Pending until separately evidenced.
- Releases, tags and version bumps require explicit owner authorization.
