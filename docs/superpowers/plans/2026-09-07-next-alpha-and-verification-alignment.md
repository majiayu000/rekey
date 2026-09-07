# Next public Alpha and verification alignment

> Status: draft planning only; does not change `v2.0.0-alpha.1` support
>
> Date: 2026-09-07
>
> Depends on: Feature Truth Matrix, `docs/alpha-scope.md`, P-09 PR #39

## Why this note exists

Development head already has password lifecycle, local audit export, signed
policy/approvals, workload identity, Vault KV v2 / dynamic lease sources, and
a Linux `agent-run` launcher. The only public archive is still
[`v2.0.0-alpha.1`](https://github.com/majiayu000/rekey/releases/tag/v2.0.0-alpha.1)
(vault schema v5). Users who download that archive cannot use those later
capabilities. This file is the candidate list for a later Alpha so
implementation, verification, and the downloadable version stay aligned.

It is not a release checklist and does not move any Feature Truth Matrix
`Release` cell.

## Hard gates before cutting a later Alpha

1. P-09 (`linux-netns-v1`) is merged with Ubuntu `scripts/p9-linux-agent-run.sh`
   green on the exact head. Overlap rejection must not trip the Bash `ERR`
   trap; a disjoint Agent socket under `/tmp` must remain reachable after the
   HOME overlay.
2. Exact-head security, fuzz, and performance gates pass; signed squash merge
   and post-main CI pass.
3. Dual-platform attested archives, native launchd/systemd fresh-install, and
   public-URL smoke follow the `v2.0.0-alpha.1` release shape.
4. The published `docs/alpha-scope.md` is rewritten for the new tag only at
   release time. This draft must not be copied into user docs as a promise.

The cut is a new breaking tag (for example `v2.0.0-alpha.2`). There is no
reader or migration for v5/v6/v7/v8 state. Operators backup, install into an
empty directory, and restore only with matching binaries.

## Schema and topology that the next archive would actually ship

| Item | `v2.0.0-alpha.1` | Development head | Next Alpha if cut from head |
| --- | --- | --- | --- |
| Vault format | v5 | v9 | v9 only; older state rejected |
| Default topology | G1 | G1 | G1; do not retitle as G2 |
| Linux G2 recipe | not in archive | `scripts/p1-linux-g2.sh` | keep as reference, not default |
| Linux `agent-run` | absent | PR #39 | include only after Ubuntu black-box |
| Windows / macOS isolation | unsupported / unimplemented | unchanged | unchanged |

## Candidate inclusion (already verified on head, not in alpha.1)

Include only rows that remain at least `Black-box Verified` on the release
commit. Security-facing rows still need `Adversarially Verified`.

| Capability | Head maturity | Include? | Limit that must stay in the Alpha notes |
| --- | --- | --- | --- |
| Password / recovery wrapper lifecycle | Adversarially Verified | yes | no VRK/DEK rotation; no historical-backup invalidation |
| Local audit query / JSONL export | Adversarially Verified | yes | no SIEM, deletion, retention, or remote delivery |
| Signed persistent policy and approvals | Adversarially Verified | yes | verifier-only; external signer; no control plane |
| Workload identity session mint | Adversarially Verified | yes | static keys only; no JWKS/discovery |
| Connector SDK / MCP and OAuth projections | Contract Tested | library only | no MCP server, no live generic OAuth |
| GitHub App closed profile | already in alpha.1 | keep | not a general GitHub connector |
| Vault KV v2 source | Black-box Verified | optional | local CA/TLS fixture only until OSS/field interop exists |
| Vault one-shot dynamic lease | Black-box Verified | optional | same; no renewal or crash-time revoke |
| Linux `agent-run` | Implemented until Ubuntu re-run | yes, after gate 1 | not general G2; needs bubblewrap |

GitHub App in alpha.1 shipped on local-fixture evidence, with live
`api.github.com` as a separate Field Validated row that is still not in the
archive. Vault may follow that pattern: include on black-box evidence, or hold
the Vault kinds out of the archive until
[`2026-09-07-vault-oss-interop.md`](../specs/2026-09-07-vault-oss-interop.md)
has protocol evidence. Do not mark Vault `Field Validated` from a mock.

## Explicitly out of the next Alpha

- MCP server, generic OAuth connector, online JWKS, private-network Vault.
- Other P-07 providers (AWS/GCP/Azure, 1Password, PKCS#11, OS keychain).
- P-08 metrics and P-10 connector process/WASM isolation.
- Enterprise control plane, multi-tenant, SSO, HA/DR, remote audit, Windows.
- macOS seatbelt / general G2 / kernel or Docker-daemon resistance.
- Third-party audit: existing review records are Codex review, not an
  independent human audit. Do not say otherwise in release notes.

Same-user process memory, `ptrace`, and filesystem inspection remain outside
G1. Shipping `agent-run` does not change that default.

## Verification still owed after P-09 merges

| Work | Why | Own spec / PR? |
| --- | --- | --- |
| Ubuntu P-09 black-box on the remount/ERR-trap head | current merge blocker | this P-09 PR |
| HashiCorp Vault OSS protocol interop | KV/dynamic are mock-HTTP today | yes, Vault OSS spec |
| Optional public-HTTPS Vault dogfood | Field Validated analog of `scripts/dogfood-github.sh` | same spec; not CI secrets |
| Alpha.2 release engineering | align archive, schema v9, and Matrix `Release` cells | release PR, not this file |

## Honest product claims after a later Alpha

Allowed, if the gates pass:

- "Public Alpha `v2.0.0-alpha.N` is a local G1 Credential Authority on the
  tested macOS arm64 and Ubuntu 24.04 x86_64 archives, with vault schema v9."
- "Linux `agent-run` (`linux-netns-v1`) denies IP egress for one launched argv
  when bubblewrap is installed and the Agent endpoint is disjoint."

Not allowed:

- production-ready G2, enterprise-ready, general Vault, general GitHub
  connector, live IdP, or "users can download everything that exists on main."
