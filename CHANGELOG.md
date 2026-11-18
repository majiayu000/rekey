# Changelog

All notable public changes are recorded here. The current source candidate is
0.5.0-alpha.1 (vault27 / policy8). Actual published downloads are determined by
GitHub Releases. Historical 0.3/v3/v2 entries below remain release history.

## 0.5.0-alpha.1 (prepared, not yet published)

**Requires a new vault.** One-step `rekey add` with basic-mode
software signing, `rekey unlock --remember 7d`, background request alerts,
public DoH fallback behind fake-IP DNS, JSON content-type for named-operation
calls, an in-App update check and an optional Homebrew tap PR job. See the
[release notes](docs/releases/v0.5.0-alpha.1.md). Also integrates native connect-on-open, explicit Connection
mTLS, administrator CA import/CSR/revocation/CRL operations, authenticated complete
PKI/action collections, and SSH cancellation, one/two-person external approvals
and per-socket budgets. Retain main's Worker-owned SSH signing and signed
Connections; no old-format reader or migration. Include the remaining accepted
JSON/SSE allocation changes and the lab child-exit event watcher. See the
[integration contract](docs/superpowers/specs/2026-10-09-unified-experiments.md)
and [integration record](docs/superpowers/plans/2026-10-09-experiment-integration.md).
This is source integration, with device/deployment/release gates separate.

Local HTTP refusals (2026-11-16): a locked vault now answers `LOCKED` with the
`await_unlock` hint instead of `NOT_CONFIGURED`; lifecycle refusals (`LOCKED`,
retryable `AUTHORITY_BUSY`, `DRAINING`, `FAULTED`) return 503 rather than 403,
so SDK clients no longer read a temporary refusal as a permission error. An
occupied service port fails startup with `SERVICE_PORT_IN_USE`, the port and
the `service.json` fix; other startup IO failures log their OS cause, and a
failed start removes the sockets it bound.

Basic-mode approvals (2026-10-22): `rekey approval review` accepts the
Connection review body the daemon actually writes (it always failed with
`INVALID_FRAME`), and `rekey approval approve|reject --password` approves with
the vault password. `rekey unlock --remember` now issues an unlock-only ticket:
the same-user readable file can no longer approve, reveal, stop the daemon or
satisfy any other presence step-up. Files written earlier keep their old
authority until `rekey unlock --remember` or `rekey lock --forget-remembered`
is run again.

Agent discovery (2026-10-23): `describe` returns the Connection's signed rules,
caller overrides, limits, LLM model allow-list and rule expiry; named LLM
operations list the allowed models as a schema `enum`, and `rekey list` shows
models plus a warning within seven days of rule expiry. A target that resolves
to a non-public address (often a proxy's fake-IP DNS) now fails with
`UPSTREAM_ADDRESS_BLOCKED` and an actionable `next`. Approval guidance
everywhere names `approval.challenge_id` as the ID to await and retry with,
and tests check that shipped Agent guidance only names real MCP tools and
`rekey` subcommands.

Dependency advisories (2026-11-16): update `rusqlite` 0.34 to 0.41, which moves
the bundled SQLite from 3.49.1 to 3.54.1 (RUSTSEC-2026-0459), and `quinn-udp`
to 0.5.16 (RUSTSEC-2026-0538). Storage code is unchanged: the `fallible_uint`
feature keeps the previous checked `u64`/`usize` conversions, and the SQLite
file format and vault27 layout are not affected.
Also update Tokio to 1.51.6 and rustix to 1.1.6 to resolve the remaining
unsoundness advisories (RUSTSEC-2026-0386 and RUSTSEC-2026-0486). The peer-process
watch and Linux plugin guardian wait now use Tokio's explicit unsafe registration
API with owned descriptors kept valid until deregistration; registration errors
still preserve their underlying IO cause. Both lockfiles are synchronized.

Design completion (2026-11-17): an audit of the active 0.5 contracts against the
code verified 81 gaps; this round fixes the software ones. See the
[design completion record](docs/evidence/2026-11-17-design-completion.md).
No vault, policy, backup, audit-schema or AAD format changes; the IPC changes
are listed below.

- Caller identification: CLI, MCP and SSH agent requests are labelled from the
  socket peer's process chain, and local HTTP requests from the process that
  holds the client socket (found by TCP four-tuple). Those two paths were fixed
  to `unknown` and `ssh-agent`, so per-caller rules, approvals and time windows
  now apply there. On macOS a path miss falls back to a Team ID and identifier
  check.
- Access requests: the fourth request from one caller within a minute returns
  `RATE_LIMITED` with the reset time (it returned `BUDGET_EXCEEDED`). Provider
  families resolve to their presets, unknown providers return `INVALID_INPUT`,
  and under a signed policy the access-request audit rows carry Connection
  context.
- Scan: SCAN uses a shared 600 MiB per minute byte budget per system user
  instead of 60 frames per minute, so commits with more than 60 staged files
  are no longer blocked. The hook warns and lets the commit through when Rekey
  is not running, is locked, has no current signed policy or has used its
  budget; `--strict` blocks. A staged type change (a symlink replaced by a
  file) is scanned, and a staged submodule pointer no longer fails the hook.
  `ScanResponse` gains the required `unavailable_credentials`, so the CLI and
  daemon must come from the same build; an expired policy returns
  `NOT_CONFIGURED` instead of `DENIED`.
- `rekey connect` writes no `--state-dir` for the default `~/.rekey` and warns
  before writing a non-default vault path. New `rekey hooks install|uninstall`.
  Existing hooks are chained: shell hooks get the scan after the shebang,
  others are renamed to `pre-commit.rekey-chained`. The `--with-ssh` block
  ends with `Match all`.
- T1: `aws-credentials`, `kubectl-credentials` and `github-token` wait up to
  120 s for a local approval and retry once with the same approval ID.
- Upstream: every upstream request sends `accept-encoding: identity`. A
  response with another content coding, or a transfer coding other than
  chunked, is refused before any byte is released (`RESPONSE_BLOCKED`).
  `github-git` signs `git-protocol` (Git protocol v2) and accepts a single gzip
  request body member; Connections signed earlier must be re-signed for v2.
  Adds the `flate2` dependency (pure-Rust backend).
- Audit: a basic-mode password approval or rejection no longer makes
  `AUDIT_QUERY` (`rekey audit list`, the activity view) fail with
  `STORAGE_INTEGRITY_FAILED`. `ssh.sign` reason codes record the purpose and
  the verified host key fingerprint, and a provider refusal during an OAuth
  refresh is recorded as `oauth-needs-reauth`.
- PKI: a certificate reservation left by a crashed Worker becomes `Failed`,
  with one failure audit, at the next unlock from Locked, instead of blocking
  the full CRL forever.
- Default build: `rekeyd` refuses the lab-only session and Profile opcodes
  (admin `SESSION_CREATE`, `SESSION_REVOKE`, `PROFILE_GET`,
  `PROFILE_SESSION_CREATE`; agent `PROFILE_INVENTORY`) with `INVALID_FRAME`. `rekey unlock
  --remember` rejects lifetimes outside 1 s to 30 days before sending the
  password. CALL execution audit IDs come from the daemon, not the frame
  request ID.
- App: a failed background start writes `startup-failure.json` (0600) and the
  App shows its code and next step, the port and `service.json` path for
  `SERVICE_PORT_IN_USE`, and read-only rebuild guidance for unsupported vault
  layouts. `rekey status` gains `protection_level`, and `peer_security` is only
  the identity label. `.env` import writes the `<X>_BASE_URL` name SDKs read
  and marks replaced lines. The signer preflight runs before a key is saved,
  short-credential warnings are shown, desktop tokens that arrive after a lock
  are revoked, and OAuth Connections that need re-authorization are listed.
- Docker HA controller: publishes the ready primary before preparing a spare,
  labels every Docker error and hands over recovery output before the first
  start; the live drill passed on the design-completion head.
- Tests: the P0 acceptance scripts use signed Connections and run in the
  security gate on both platforms; four fuzz targets gained synthetic seed
  corpora; load-sensitive tests wait for events instead of fixed deadlines.

## 0.4.0-alpha.1

**Requires a new vault.** Replace local capability/Profile launching with signed
Connections and ordinary Agent calls through CLI, MCP, local HTTP and SSH agent.
Add read/write/path rules, approval windows, access requests, connect tooling,
exact secret scanning, managed OAuth and explicit T1 temporary credentials.
Archive personal isolation launchers behind lab. The macOS editor signs the
complete Connection, SSH and derivation policy. See [candidate release notes](docs/releases/v0.4.0-alpha.1.md)
and the [acceptance record](docs/evidence/agent-call-acceptance-2026-10-05.md) for
completed checks and remaining device/account/public-release gates.

## 0.3.0-alpha.2

**Requires reinitialization: no for vault25 / policy6.** Fix premature rejection
of bounded large text/tool SSE responses by reclaiming checked stream buffers.
Improve stream scheduling, revoke-before-poll handling and authenticated usage
ledger processing without changing durable formats or authorization boundaries.
Clarify the product positioning, L1-dev threat model and pinned competitor evidence.
See [release notes](docs/releases/v0.3.0-alpha.2.md).

## 0.3.0-alpha.1

**Requires reinitialization: no for vault25 / policy6.** Renumber the product line
from 3.0.0-alpha.4 to reflect its pre-1.0 maturity. Align binaries, macOS bundle
metadata, signed package/cask and Linux archive versions. Keep the alpha status,
existing formats, security boundaries and historical releases. Publication must
pass the existing signed-package and public-download gates again. See
[release notes](docs/releases/v0.3.0-alpha.1.md).

## 3.0.0-alpha.4

Run packaged MCP discovery through the v3 signed Profile and `rekey run`, using
an installed synthetic template. The v2 manifest/session-file interface has been
removed. alpha.3 completed signing, notarization and installed P0, then its stale
MCP harness blocked publication; preserve the immutable tag. Formats remain
vault25 / policy6. See [release notes](docs/releases/v3.0.0-alpha.4.md).

## 3.0.0-alpha.3

**Requires reinitialization: no for vault25 / policy6.** Formats remain frozen.
Keep archive-only Python helper checks in the tar.gz smoke entry point, so the
macOS package can run the same native behavior and service-manager acceptance.
The macOS manager exercises the installed daemon inside its profiled bundle.
Alpha.2 passed signing/notarization but its install gate exposed the misplaced
archive checks; its immutable tag remains unpublished. See [release notes](docs/releases/v3.0.0-alpha.3.md).

## 3.0.0-alpha.2 (unpublished tag)

**Requires reinitialization: no for vault25 / policy6.** Formats remain frozen.
Split the Activity list comparison into explicitly typed expressions so the
macOS release runner can compile it. Sorting and security behavior are unchanged.
Alpha.1's immutable tag remains as the failed, unpublished build; alpha.2 carries
that source plus this release fix. See [release notes](docs/releases/v3.0.0-alpha.2.md).

## 3.0.0-alpha.1 (unpublished tag)

**Requires reinitialization: yes.** Older formats are rejected, never migrated.
Vault25 and policy snapshot6 are frozen from this alpha onward. All v3
prereleases, GA, minor and patch releases must preserve these durable formats.

- Personal/team immutable signing mode; explicit Presence step-up, protected
  desktop reveal, authenticated daemon peer, and all-state shutdown proof.
- Provider templates, canonical parameterized targets, complete personal policy
  drafts and explicit template-default/allow/require-approval selections.
- Local one-time Presence approval plus existing external Ed25519 approval.
- Signed Profiles, managed Agent owner lifecycle, MCP discovery, loopback SDK
  gateway, raw SSE sealing, persistent daily usage and trusted Activity context.
- Authenticated generation and external high-water reservation, rollback-suspected
  state, explicit password/recovery confirmation and two-step offline restore.
- macOS onboarding, opt-in SMAppService, signed pkg/cask generation and Linux
  user-unit generation. Enterprise execution remains opt-in `lab`.

These are source changes, not a complete hardware claim. Publication and download
status are recorded on the GitHub release and its workflow.
Final joint checks and every release/device gate remain separate. See the
[candidate release notes](docs/releases/v3.0.0-alpha.1.md) and
[feature matrix](docs/product-foundation/feature-truth-matrix.md).
The v2 entries below are immutable historical descriptions, not current usage.

## 2.0.0-alpha.2 - 2026-09-08

Schema v9 Alpha archive. Shape A HEAD cut: password/recovery wrapper lifecycle,
local audit list/export, signed persistent policy and approvals, workload
identity, GitHub App v2 bounds, fixture-bounded Vault KV v2 / one-shot
dynamic sources, and Linux `agent-run`.

This is not an in-place upgrade from `2.0.0-alpha.1` (schema v5). Initialize a
new empty directory and recreate Admin state. Old backups restore only with
matching old binaries.

### Added

- `rekey password change` and `rekey recovery rotate` (VRK rewrap only).
- Local audit list and JSONL export.
- Signed persistent policy, one- and two-person approvals (external signatures).
- Workload identity session mint with static public keys.
- GitHub App `github-app-installation-v2` bounds (P-06).
- Vault KV v2 and one-shot dynamic lease sources (Shape A, fixture-only).
- Linux `agent-run` (`linux-netns-v1`) via bubblewrap.

### Changed

- Vault format is v9. Any other format, including v1 and v4–v8, is rejected
  with no reader or migration. Signed persisted policy replaces the alpha.1
  in-memory snapshot.

### Known limitations

See `docs/releases/v2.0.0-alpha.2.md` and `docs/alpha-scope.md`.

## 2.0.0-alpha.1 - 2026-09-02

First public Alpha of the breaking Rekey v2 Credential Authority.

### Added

- Fixed HTTPS Actions and short-lived capability sessions without a secret-read API.
- Encrypted SQLite authority, lock/idle lock, step-up proofs, and backup/restore.
- Typed default-deny policy snapshots and supervised fail-closed execution.
- Response secret sealing, public-endpoint screening, and bounded Linux G2 reference.
- Closed read-only GitHub App Installation profile.
- macOS arm64 and Ubuntu 24.04 x86_64 signed release artifacts.

### Removed

- v1 MITM proxy, system CA, dashboard, single-port proxy, TCP passthrough, and
  legacy vault compatibility.

### Known limitations

See `docs/releases/v2.0.0-alpha.1.md`.
