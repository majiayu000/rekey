# Changelog

All notable public changes are recorded here. Rekey uses semantic versioning
for release identifiers, but prerelease compatibility is not guaranteed.

## 3.0.0-alpha.1 — Unreleased candidate

**Requires reinitialization: yes.** Older formats are rejected, never migrated.
Vault25 and policy snapshot6 remain pre-GA and are not finally frozen. GA
minor/patch releases within one major must preserve durable formats.

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

These are source changes, not a published release or complete hardware claim.
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
