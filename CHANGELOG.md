# Changelog

All notable public changes are recorded here. Rekey uses semantic versioning
for release identifiers, but prerelease compatibility is not guaranteed.

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

See `docs/releases/v2.0.0-alpha.1.md` and `docs/alpha-scope.md`.
