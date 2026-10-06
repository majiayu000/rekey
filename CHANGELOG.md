# Changelog

All notable public changes are recorded here. Rekey uses semantic versioning
for release identifiers. The current product line is 0.3 (the v3 design stage),
not a 1.0 maturity claim. Vault25 / policy snapshot6 remain frozen across all 0.3
releases, including prereleases; CLI and UI prerelease behavior may still change.
Historical v3/v2 tags and entries below are retained.

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
