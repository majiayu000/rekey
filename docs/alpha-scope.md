# Rekey v2 public Alpha scope

Version: `2.0.0-alpha.1`

## Distribution and platform matrix

| Platform | Architecture | Status | Artifact |
| --- | --- | --- | --- |
| Ubuntu 24.04 with systemd | x86_64 | Supported and release-tested | `rekey-v2.0.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz` |
| macOS 14 | Apple silicon arm64 | Supported and release-tested | `rekey-v2.0.0-alpha.1-aarch64-apple-darwin.tar.gz` |
| Other glibc Linux distributions | x86_64 | Experimental source build only | None |
| Linux arm64 | arm64 | Experimental; bounded G2 development evidence is not release support | None |
| macOS Intel | x86_64 | Unsupported in this Alpha | None |
| Windows | Any | Unsupported | None |

Distribution is limited to signed GitHub Release artifacts. Rekey is not
published to crates.io, Homebrew, or another package registry in this Alpha.

Post-Alpha development-head capabilities are not retroactively part of these
artifacts. This includes password/recovery wrapper lifecycle, local audit
query/export, signed persistent policy and approvals, workload identity session
minting, durable workload-token replay protection, Vault KV v2 / dynamic lease
sources, and the Linux `agent-run` netns launcher. Their repository test
evidence does not change the scope or support promise of `v2.0.0-alpha.1`.

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

## Compatibility and support

This is a breaking prerelease. There is no v1 import or in-place migration.
Only `2.0.0-alpha.1` is supported until a later Alpha supersedes it. Support is
best effort through the public issue tracker and private security channel; no
SLA, 24x7 coverage, or guaranteed response time is offered.

`v2.0.0-alpha.1` state is vault schema v5. A later v9 Alpha cannot open that
directory, and v5 binaries cannot open v9. Follow
[installation.md](installation.md): make and verify a backup with the old
binaries, keep those binaries and the old directory, initialize the new version
in an empty path, and recreate Admin configuration. The old backup restores
only with the matching old binaries; it is not a v9 import. After a later Alpha
is published, alpha.1 remains a historical archive for that rollback path.

## Next published Alpha

`v2.0.0-alpha.1` remains the only supported public archive. A later Alpha is
not implied by development-head evidence and is not downloadable yet.

The adopted candidate for the next tag is `v2.0.0-alpha.2`: vault schema v9,
Shape A HEAD cut (Vault kinds ship, fixture-only notes), same two platforms.
That freeze lives in
[the next-Alpha alignment plan](https://github.com/majiayu000/rekey/blob/main/docs/superpowers/plans/2026-09-07-next-alpha-and-verification-alignment.md)
and in the candidate table below. It does not change this file's current
support promise, rewrite `docs/releases/v2.0.0-alpha.1.md`, or fill Feature
Truth Matrix `Release` cells.

## Frozen candidate `v2.0.0-alpha.2` (not published)

Cut only after dual-platform attested archives, native service-manager
fresh-install, and public-URL smoke pass on the release commit. No v5–v8
reader, migration, or compile-time Vault strip. After that tag exists, alpha.1
remains a historical v5 archive: keep its binaries for rollback; do not open
v9 state with them; do not treat alpha.1 backups as a v9 import.

| Capability | alpha.2 handling | Limit that must stay in the notes |
| --- | --- | --- |
| Local credentials, fixed Action, backup/restore | keep | G1, one local Authority |
| Password change, recovery rotation | include | no historical-backup invalidation; no VRK/DEK rotation |
| Audit list/export | include | no remote delivery, deletion, or configurable retention |
| Signed policy, one- and two-person approval | include | external signatures only; no approval service or private-key custody |
| Workload identity | include | static public keys; no JWKS/discovery |
| GitHub App closed profile and merged P-06 bounds | include | one installation; 1–16 exact repositories; `GET /installation/repositories` and `POST /repos/OWNER/REPOSITORY/issues` only; live `api.github.com` evidence does not cover every added Admin path |
| Vault KV v2 and one-shot dynamic lease | include (Shape A) | fixture-only closed protocol; no private-network source |
| Linux `agent-run` | include | bubblewrap; disjoint socket; Ubuntu AppArmor profile; Black-box Verified facts only |
| Connector SDK | ship in source | do not announce an MCP server or generic OAuth connector |

Out of this candidate: Shape B Vault cut, other cloud secret sources, MCP
server, online JWKS, P-08 metrics, P-10 plugin isolation, macOS sandbox,
general G2, and an enterprise control plane.
