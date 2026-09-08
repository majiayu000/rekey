# Rekey v2 public Alpha scope

Version: `2.0.0-alpha.2`

This file describes the `v2.0.0-alpha.2` archive (vault schema v9, Shape A).
A version string here is archive membership. The GitHub Release of the same
name exists only after the tagged release workflow's public-URL smoke passes.
Until then, `v2.0.0-alpha.1` remains the last completed public download.

## Distribution and platform matrix

| Platform | Architecture | Status | Artifact |
| --- | --- | --- | --- |
| Ubuntu 24.04 with systemd | x86_64 | This archive | `rekey-v2.0.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz` |
| macOS 14 | Apple silicon arm64 | This archive | `rekey-v2.0.0-alpha.2-aarch64-apple-darwin.tar.gz` |
| Other glibc Linux distributions | x86_64 | Experimental source build only | None |
| Linux arm64 | arm64 | Experimental; bounded G2 development evidence is not release support | None |
| macOS Intel | x86_64 | Unsupported in this Alpha | None |
| Windows | Any | Unsupported | None |

Distribution is limited to signed GitHub Release artifacts. Rekey is not
published to crates.io, Homebrew, or another package registry in this Alpha.

## Included capabilities

| Capability | Handling | Limit that must stay in the notes |
| --- | --- | --- |
| Local credentials, fixed Action, backup/restore | included | G1, one local Authority |
| Password change, recovery rotation | included | no historical-backup invalidation; no VRK/DEK rotation |
| Audit list/export | included | no remote delivery, deletion, or configurable retention |
| Signed policy, one- and two-person approval | included | external signatures only; no approval service or private-key custody |
| Workload identity | included | static public keys; no JWKS/discovery |
| GitHub App closed profile and P-06 bounds | included | one installation; 1–16 exact repositories; `GET /installation/repositories` and `POST /repos/OWNER/REPOSITORY/issues` only; live `api.github.com` evidence does not cover every added Admin path |
| Vault KV v2 and one-shot dynamic lease | included (Shape A) | fixture-only closed protocol; no private-network source |
| Linux `agent-run` | included | bubblewrap; disjoint socket; Ubuntu AppArmor profile; Black-box Verified facts only |
| Connector SDK | ship in source | do not announce an MCP server or generic OAuth connector |

Out of this Alpha: Shape B Vault cut, other cloud secret sources, MCP server,
online JWKS, P-08 metrics, P-10 plugin isolation, macOS sandbox, general G2,
and an enterprise control plane.

## Product identity decision

This Alpha uses the descriptive project name **Rekey Credential Authority**
only within `github.com/majiayu000/rekey`, with binaries named `rekey` and
`rekeyd`. The active `rekey.dev` auth/billing/MCP product is unrelated. This
project does not use that domain, its package scopes, or imply affiliation.
No project domain or registry namespace is claimed for this Alpha. A distinct
commercial name and formal trademark clearance are required before paid or
hosted distribution.

## Security grade

The default product topology is G1: one trusted local user administers Rekey
and runs agents under the same user. Same-user process inspection, `ptrace`,
direct filesystem access, host root, kernel compromise, and direct Agent
egress are outside that boundary.

The Linux container/namespace G2 recipe is a separately tested reference. It
does not make the default deployment, arbitrary Linux hosts, or macOS G2.
Linux `agent-run` does not change that default.

## Compatibility and support

This is a breaking prerelease. There is no v1 import or in-place migration.
`2.0.0-alpha.2` is the current Alpha archive. Support is best effort through the
public issue tracker and private security channel; no SLA, 24x7 coverage, or
guaranteed response time is offered.

`v2.0.0-alpha.2` state is vault schema v9. There is no reader or migration for
any other format, including v1 and v4–v8. Follow [installation.md](installation.md): make and verify
a backup with the old binaries, keep those binaries and the old directory,
initialize the new version in an empty path, and recreate Admin
configuration. The old backup restores only with the matching old binaries; it
is not a v9 import.

## Previous public Alpha

`v2.0.0-alpha.1` is a historical v5 archive. Keep its binaries for rollback. Do
not open v9 state with them. Do not treat alpha.1 backups as a v9 import. Do
not rewrite `docs/releases/v2.0.0-alpha.1.md` to claim compatibility.
