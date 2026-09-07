# Next public Alpha and verification alignment

> Status: adopted candidate scope for `v2.0.0-alpha.2`; does not change
> `v2.0.0-alpha.1` support or fill Matrix `Release` cells
>
> Date: 2026-09-07
>
> Depends on: Feature Truth Matrix, `docs/alpha-scope.md`, P-09 merge
> `9565f9e` / [PR #39](https://github.com/majiayu000/rekey/pull/39)

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

1. `[x]` P-09 (`linux-netns-v1`) merged. Ubuntu `scripts/p9-linux-agent-run.sh`
   printed `PASS` on exact-head `P0 (ubuntu-latest)` in security-gate
   `34082334618`. Squash merge `9565f9e`.
2. Exact-head security, fuzz, and performance gates pass on the *release*
   commit; signed squash merge and post-main CI pass.
3. Dual-platform attested archives, native launchd/systemd fresh-install, and
   public-URL smoke follow the `v2.0.0-alpha.1` release shape.
4. The published `docs/alpha-scope.md` keeps `v2.0.0-alpha.1` as the only
   public archive until tag time. The frozen candidate table in that file is
   not a download or support promise.
5. Vault packaging is decided by the section below *before* the tag. Omitting
   Vault from notes while shipping HEAD binaries is not a decision.

The cut is a new breaking tag (for example `v2.0.0-alpha.2`). There is no
reader or migration for v5/v6/v7/v8 state. Operators backup, install into an
empty directory, and restore only with matching binaries.

## Schema and topology that the next archive would actually ship

| Item | `v2.0.0-alpha.1` | Development head | Next Alpha if cut from head |
| --- | --- | --- | --- |
| Vault format | v5 | v9 | v9 only; older state rejected |
| Default topology | G1 | G1 | G1; do not retitle as G2 |
| Linux G2 recipe | not in archive | `scripts/p1-linux-g2.sh` | keep as reference, not default |
| Linux `agent-run` | absent | `9565f9e` / PR #39 | include; not general G2 |
| Windows / macOS isolation | unsupported / unimplemented | unchanged | unchanged |

## Frozen `v2.0.0-alpha.2` inclusion (verified on head, not in alpha.1)

The next tag is `v2.0.0-alpha.2` if gates pass. Include only rows that remain
at least `Black-box Verified` on the release commit. Security-facing rows still
need `Adversarially Verified`. Release engineering during the cut only fixes
blockers; it does not add providers or product modules.

| Capability | Head maturity | alpha.2 | Limit that must stay in the Alpha notes |
| --- | --- | --- | --- |
| Local credentials, fixed Action, backup/restore | Adversarially Verified | keep | G1, one local Authority |
| Password / recovery wrapper lifecycle | Adversarially Verified | include | no VRK/DEK rotation; no historical-backup invalidation |
| Local audit query / JSONL export | Adversarially Verified | include | no SIEM, deletion, retention, or remote delivery |
| Signed persistent policy and approvals | Adversarially Verified | include | verifier-only; external signer; no control plane or key custody |
| Workload identity session mint | Adversarially Verified | include | static keys only; no JWKS/discovery |
| Connector SDK / MCP and OAuth projections | Contract Tested | source only | no MCP server, no live generic OAuth |
| GitHub App closed profile and P-06 bounds | Black-box Verified (live create-issue is a separate Field Validated row) | include | one installation; 1–16 exact repositories; `GET /installation/repositories` and `POST /repos/OWNER/REPOSITORY/issues` only; Admin webhook-delta and typed rotation are fixture-covered; live `api.github.com` does not cover every added path |
| Vault KV v2 source | Black-box Verified | **Shape A HEAD cut** | local CA/TLS fixture only; closed protocol; no live Vault; no private-network |
| Vault one-shot dynamic lease | Black-box Verified | **Shape A HEAD cut** | same; no renewal or crash-time revoke |
| Linux `agent-run` | Black-box Verified (Ubuntu `34082334618`) | include | bubblewrap; disjoint socket; Ubuntu 24.04 bwrap userns profile; cite black-box facts only |

Platforms stay macOS 14 arm64 and Ubuntu 24.04 x86_64. No new migration,
compat reader, or compile-time cut switch. Do not widen G2, enterprise, or
human-audit claims.

GitHub App in alpha.1 shipped on local-fixture evidence, with live
`api.github.com` as a separate Field Validated row that is still not in the
archive. Vault on a HEAD cut follows that same *binary* pattern: the kinds,
CLI, IPC, schema v9 CHECK, and connector descriptors are in the archive.
Live OSS/field interop stays a separate spec and does not gate inclusion.
Do not mark Vault `Field Validated` from a mock.

## Vault packaging (not a documentation flag)

Rekey has no compile-time feature that strips P-07. A release built from
current head contains all of:

- schema v9 `CHECK (kind IN (… 'vault-kv-v2-source', 'vault-dynamic-source'))`;
- Admin IPC add/rotate for those kinds;
- `rekey credential add-vault-kv` / `rotate-vault-kv` /
  `add-vault-dynamic` / `rotate-vault-dynamic`;
- executor source/lease paths;
- `rekey-connector` descriptors `vault-kv-v2-source@1` and
  `vault-dynamic-source@1`.

Therefore there are only two honest release shapes:

| Shape | What the archive contains | What the notes may say | Extra work |
| --- | --- | --- | --- |
| **A. HEAD cut (default)** | Vault implementation above | Closed KV v2 and one-shot dynamic lease; fixture-only; not general Vault; not private-network; not in alpha.1 | Matrix `Release` cells for those two rows at tag time |
| **B. Product cut** | Named surfaces removed or fail-closed | Vault kinds are not in this Alpha | Own spec + PR *before* the tag |

**Forbidden:** shape “docs omit, binary includes.” Users who download the
archive can still invoke the CLI and IPC. That is not “暂不纳入 Vault.”

Shape B is not “leave the optional box unchecked.” A cut spec must list, for
each surface, remove vs fail-closed, and must say whether schema v9 still
names the kinds in `CHECK`. Keeping the CHECK while hiding CLI is still a
v9 vault that can store those kinds via IPC. Removing the CHECK is a new
format, not a docs edit, and still has no v8 reader.

Until a Shape B spec exists, the next Alpha is Shape A. OSS protocol interop
([`2026-09-07-vault-oss-interop.md`](../specs/2026-09-07-vault-oss-interop.md))
does not change that default; it only upgrades the verification note after
Layer A.

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

## Verification still owed after P-09

| Work | Why | Own spec / PR? |
| --- | --- | --- |
| P-09 Ubuntu black-box | done; merge `9565f9e` | — |
| HashiCorp Vault OSS protocol interop | KV/dynamic are mock-HTTP today; does not hold back Shape A | yes, Vault OSS spec |
| Optional public-HTTPS Vault dogfood | Field Validated analog of `scripts/dogfood-github.sh` | same spec; not CI secrets |
| Shape B Vault cut (only if product refuses Shape A) | must name CLI/IPC/schema/connector surfaces | yes, before the tag |
| Alpha.2 release engineering | align archive, schema v9, Matrix `Release` cells, Shape A notes | release PR |

## Honest product claims after a later Alpha

Allowed, if the gates pass:

- "Public Alpha `v2.0.0-alpha.N` is a local G1 Credential Authority on the
  tested macOS arm64 and Ubuntu 24.04 x86_64 archives, with vault schema v9."
- "Linux `agent-run` (`linux-netns-v1`) is Black-box Verified on Ubuntu: with
  bubblewrap and a disjoint Agent socket, the harnessed child could not open
  public TCP, could not see vault files, and could still use `agent.sock`."

Not allowed:

- production-ready G2, enterprise-ready, general Vault, general GitHub
  connector, live IdP, or "users can download everything that exists on main."
- An Adversarially Verified isolation claim, or unqualified "denies IP
  egress," while the matrix row remains `Black-box Verified`.
