# Rekey v2 public Alpha scope

Version: `2.0.0-alpha.1`

## Distribution and platform matrix

| Platform | Architecture | Status | Artifact |
| --- | --- | --- | --- |
| Ubuntu 24.04 with systemd | x86_64 | Supported and release-tested | `rekey-v2.0.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz` |
| macOS 14 or newer | Apple silicon arm64 | Supported and release-tested | `rekey-v2.0.0-alpha.1-aarch64-apple-darwin.tar.gz` |
| Other glibc Linux distributions | x86_64 | Experimental source build only | None |
| Linux arm64 | arm64 | Experimental; bounded G2 development evidence is not release support | None |
| macOS Intel | x86_64 | Unsupported in this Alpha | None |
| Windows | Any | Unsupported | None |

Distribution is limited to signed GitHub Release artifacts. Rekey is not
published to crates.io, Homebrew, or another package registry in this Alpha.

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

Before upgrading, stop the broker and create a verified encrypted backup plus
receipt. Rollback means restoring the matching pre-upgrade backup into an empty
state directory with the older binaries. Never open newer incompatible state
with an older binary.
