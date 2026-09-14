# Changelog

All notable public changes are recorded here. Rekey uses semantic versioning
for release identifiers, but prerelease compatibility is not guaranteed.

## Unreleased

### Added

- Pinned Vault OSS KV v2 and dynamic-lease interoperability harness; separate
  bounded public HTTPS receipts cover the recorded KV and dynamic profiles.
- Source-only local MCP stdio server, external policy and approval signers,
  protected Agent onboarding and operator credential repair helpers.
- Fixed GitHub Actions online JWKS opt-in, fixed Keycloak token exchange,
  and GitHub App issue-comment support.
- Origin-authenticated approval envelopes and an Admin CLI pending/get inbox.

### Changed

- Development vault format is v10; older state and backups are rejected
  without migration. Public alpha.2 remains v9.
- GitHub exchange or post-effect uncertainty returns non-retryable
  `UPSTREAM_INDETERMINATE`; write failures must not trigger automatic retries.
- Hardened private profile/handoff files, JWKS admission bounds, MCP input
  handling, and backup publication.

This is an unpublished candidate. Archive scope and remaining release gates:
[alpha.3 candidate](docs/releases/v2.0.0-alpha.3.md).

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
