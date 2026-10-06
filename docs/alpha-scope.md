# Rekey 0.3 candidate scope (v3 design)

Pre-tag candidate snapshot; current publication status is recorded on the
[GitHub release](https://github.com/majiayu000/rekey/releases/tag/v0.3.0-alpha.2) and its complete workflow.

Target: **0.3.0-alpha.2 — unpublished candidate, not GA**.
Current durable formats vault25 and policy snapshot6 remain frozen through
all 0.3 releases, including prereleases. Product version 0.3 reflects current
maturity; v3 still names the design stage, not a GA release. Source implementation,
local validation and Release status are distinct. Every current candidate Release entry remains **Pending**.

## Distribution

| Platform | Candidate artifact / entry | Release |
|---|---|---|
| macOS 14+, Apple Silicon | Signed/notarized pkg; release-local generated cask; Rekey.app + CLI links | Pending |
| Ubuntu 24.04, x86_64 | tar.gz; explicit systemd user unit | Pending |
| Other Linux / arm64 | Source and bounded test environments only | Pending; no distribution support claim |
| macOS Intel / Windows | No candidate artifact | Not supported |

There is no public tap or crates.io package. The historical v3.0.0-alpha.4
[public release workflow](https://github.com/majiayu000/rekey/actions/runs/37262839187)
completed; the new 0.3 candidate must pass its own public-download checks. The cask
uses the actual final pkg hash; it does not bypass signing, notarization or
Installer gates. Current Homebrew local-file opt-in is documented in
[installation](installation.md). No auto-updater or unattended installer is added.

## Default source scope

- Local encrypted vault, password/recovery/Presence lifecycle, per-call sensitive
  proofs, authenticated daemon peer, bounded audit and backup/restore.
- Immutable personal P-256 or team Ed25519 trust; canonical default-deny policy.
- Anthropic/OpenAI/GitHub PAT/generic Bearer templates and exact Action versions.
- Personal template-default/allow/require-approval choices; complete replacement
  diff and exact-byte App signing. Snapshot6/rule UI passed the joined local software checks; device gates remain pending.
- Local Presence one-time approval and external Ed25519 approval; no implemented
  remote approver. Agent calls within allow rules request no human interaction.
- Signed Profile, owner-bound `run`, MCP discovery, SDK loopback gateway, model
  and usage limits, raw SSE reflection blocking and Activity metadata.
- Generation MAC, external high-water reservation, rollback-suspected state and
  authenticated explicit restore. No lowering history or automatic rollback consent.

[The feature matrix](product-foundation/feature-truth-matrix.md) links actual
source and bounded tests. Neither a module nor a local test result is a Release.

## Enterprise reserve

`--features lab` gates workload identity/OIDC, approval relay, external secret
sources, native plugins, metrics, delivery/archive and standby/DR tools. Pure
models/storage support may remain compiled without enabling their execution.
Historical guide examples in those sections require matching lab binaries.
They are not a team product, support commitment or default archive contents.

## Security and remaining acceptance

Current confirmed floor is L1-dev: the Agent interface does not return provider
credentials. Signed peer identity alone does not establish L1. V1 (DPK access),
V2 (memory isolation with positive controls), protected-anchor DPK permissions/CAS
and deletion/recreation behavior, real SE/Touch ID and installed App lifecycle
remain device gates. L2 additionally requires actual verified isolation and
restricted egress; Profile text alone proves neither.

Linux Profile netns remains unavailable. The older `agent-run` reference has a
narrower contract and cannot be substituted for it. Codex strict Seatbelt launch
has the recorded managed-preferences limitation. Installed-client tests using a
synthetic provider prove routing only; real accounts/providers remain unaccepted.

The release workflow requires security gates, signed/notarized artifacts,
installed-package checks and public-download smoke. The user deferred the three
installed-App interaction/lifecycle checks and T12's fresh-account
three-command/under-five-minute path for this alpha; they remain unverified.
External human security review and real-provider dogfood are also unfinished.
Software and distribution checks cannot replace these acceptance results.

## Format and support policy

Migration, old-format double reading and backfill are permanently excluded.
Old directories and backups need their matching old binaries; a new format uses
an empty directory and deliberate re-enrollment. All 0.3 releases, including
prereleases, must preserve durable formats.
An incompatible format requires a separately planned release line and SPEC revision.
This alpha is not a GA compatibility commitment, SLA or general A2/L2 guarantee.

Historical v2 archive facts remain in [v2 alpha.2 notes](releases/v2.0.0-alpha.2.md)
and [v2 alpha.1 notes](releases/v2.0.0-alpha.1.md), not in this 0.3 candidate status.
The unrelated rekey.dev product/domain is not affiliated with this repository;
no commercial-name or registry ownership claim is made here.
