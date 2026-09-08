# Feature Truth Matrix

This is the only table that may call a P0 capability “usable”. Other docs
must link here instead of restating status.

Allowed states (exactly one per row):

`Specified` → `Implemented` → `Contract Tested` → `Black-box Verified` →
`Adversarially Verified` → `Field Validated`

Rules:

- User-facing “可用” requires at least `Black-box Verified`.
- Security claims additionally require `Adversarially Verified`.
- Enterprise / multi-tenant claims require `Field Validated`.
- Release inclusion is orthogonal to verification maturity. A version in the
  `Release` column means the row is present in that named public archive. It does
  not widen the row's documented topology, provider, or maturity limits.
  Later archives also contain unchanged rows unless the notes say otherwise.
  Limits are version-specific: do not apply an older limit to a later archive
  when a later row records the replacement.
- `v2.0.0-alpha.2` in `Release` is archive membership for this tag's packed
  docs. It is not by itself proof that the GitHub Release URL has passed
  public-URL smoke.
- `—` means the row is not in the named public archive (source-only, out of
  scope, or still unpublished as a product binary).

Evidence snapshot: public tag `v2.0.0-alpha.1` at commit `d919e1e`, 2026-09-02.
[Release run 33592538786](https://github.com/majiayu000/rekey/actions/runs/33592538786)
passed the complete security gate, built attested macOS arm64 and Ubuntu 24.04
x86_64 archives, exercised fresh installs with native launchd/systemd, published
the prerelease, and passed both public-URL smoke jobs. A separate live acceptance
used a disposable GitHub App and `majiayu000/rekey-ci-dogfood` against real
`api.github.com`; exchange, resource request, token revocation and the exact
`execution.started → connector.github.authorized → connector.github.token_revoked → execution.finished`
audit chain passed. The temporary App and credentials were deleted after the
run; the test repository was retained. This is one-provider evidence, not a
general connector or enterprise claim.

The `v2.0.0-alpha.1` archives contain a pre-publication snapshot of this file
that still said nothing was Released. That is historical erratum for those
v5 artifacts. This file is the current record. `v2.0.0-alpha.2` archives pack
this file; do not leave those rows as “nothing is released.”

`v2.0.0-alpha.2` archive membership is recorded in the `Release` column below.
The public GitHub Release, attestations, and public-URL smoke for that tag
are not claimed in this snapshot until that workflow succeeds.

Security grade for every P0 row: **G1 public Alpha**. The separate Linux
container recipe has bounded G2 evidence; that does not upgrade the default P0
topology or establish a general G2 release.

A row with `Release` set to `—` is not part of the downloadable product even
when its local state is `Adversarially Verified` (for example the connector SDK
source crate, live `api.github.com` Field Validated evidence, or the Docker
G2 harness).

## P0 local authority

| Feature | User story / entry | State | Release | Implementation | Black-box / contract | Failure paths | Limits | Public docs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Init empty vault | `rekey init` / `rekeyd init` | Black-box Verified | `v2.0.0-alpha.1` (v5); `v2.0.0-alpha.2` (v9) | `crates/rekey-vault/src/bootstrap.rs`, `crates/rekey-broker/src/bin/rekeyd.rs` | `cargo test -p rekey-vault --test bootstrap_contract`; `cargo test -p rekey-cli --test cli_blackbox` | empty password, nonempty dir, legacy/mismatched format, unknown/NULL crypto discriminator, confirm mismatch discards | This archive initializes schema v9 and rejects every other format, including v1 and v4–v8, with no reader or migration. The historical `v2.0.0-alpha.1` artifact initialized v5 | README Quick start |
| Password / recovery proof | `rekey unlock`; Admin mutation `--recovery` | Black-box Verified | `v2.0.0-alpha.1` | `crates/rekey-vault/src/authority.rs`, `crates/rekey-broker/src/ipc/admin.rs`, CLI commands | `cli_blackbox`; `lifecycle_contract` | wrong password exit 3, backoff, recovery mutation proof | G1 unlock/step-up/restore proof. `v2.0.0-alpha.1` had no password change on this surface. Wrapper replacement in `v2.0.0-alpha.2` is the separate Password and recovery wrapper lifecycle row. No rate-limit across process restarts | README |
| lock / idle lock / shutdown | `rekey lock`, idle timer, `rekey shutdown` | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/lifecycle.rs`, `runtime.rs`, `execution_supervisor.rs` | `scripts/p0-acceptance.sh`; `scripts/p1-service-manager.sh`; `lifecycle_drain` (10); required macOS launchd and Ubuntu systemd CI gates | partial frame, disconnected in-flight work, execution panic, terminal-audit fault, Busy→lock→unlock Running epoch | Default topology remains G1; native-manager evidence is bounded to tested macOS/Ubuntu environments | spec §11.2 / P1.2 |
| Credential add/list | `rekey credential add/list` | Black-box Verified | `v2.0.0-alpha.1` | `crates/rekey-vault/src/authority.rs`, CLI commands | `cli_blackbox`; `scripts/p0-acceptance.sh` | duplicate label | Values only via TTY/stdin, never argv/env | README |
| Credential rotate/revoke | `rekey credential rotate/revoke` | Black-box Verified | `v2.0.0-alpha.1` | `crates/rekey-vault/src/authority.rs`, CLI commands | `scripts/p0-acceptance.sh`; `authority_contract` | revoke then execute | One clean-install host; not Field Validated | README |
| Fixed HTTPS Action create/update/list/disable | `rekey action …` | Black-box Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/ipc/admin.rs`, `rekey-domain` action types | `scripts/p0-acceptance.sh`; `session_contract` (retired pin) | invalid origin/method/path; disabled execution; retired not mintable | No parameterized path | README `action.json` |
| Capability session create/revoke | `rekey session create/revoke` | Black-box Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/session.rs` | `scripts/p0-acceptance.sh`; `session_contract`; `cli_blackbox` | revoked token, garbage token, exhaust uses, restart revoke, base64url token beginning with `-` | In-memory only; sessions intentionally vanish on restart | README |
| Agent execute fixed origin/method/path | `rekey execute ACTION@V --capability` | Field Validated | `v2.0.0-alpha.1` | `crates/rekey-broker/src/executor.rs`, `upstream.rs` | `execution_contract`; `fixed_http_action` (FakeTransport); `scripts/p0-acceptance.sh` uses real `ReqwestUpstreamTransport`; GitHub create-issue dogfood returned 201 and created `majiayu000/rekey-dogfood#2` | oversized body, extra headers, locked broker; dogfood rejects non-201 upstream responses | One macOS host and one GitHub fixed Action; not a general connector claim | README |
| Agent IPC has no secret-read | agent.sock message surface | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/ipc/agent.rs`, `tests/broker_ipc.rs` | `cargo test --test broker_ipc` (all non-agent types rejected) | 62 admin/unknown types | G1 API boundary only; not ptrace | spec §12 |
| CLI response binding and limits | real `rekey` process against forged Broker | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-cli/src/client.rs` | `cargo test -p rekey-cli --test malicious_broker` | wrong channel/id, oversize body, malformed error envelope, error body | Same-user G1 attacker can deny service but cannot make a forged response accepted | spec §12.2 |
| Runtime channel availability | release Broker under Agent flood and listener fault | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/runtime.rs` | `scripts/p0-acceptance.sh`; `scripts/p0-runtime-faults.sh` | 128 incomplete Agent connections; EMFILE accept failure | G1 availability only; same-UID attacker can still target Admin directly | spec §11–12 |
| Structured runtime fault events | release `rekeyd` JSONL stderr | Adversarially Verified | `v2.0.0-alpha.1` | `rekeyd.rs`, `runtime.rs` | `scripts/p0-runtime-faults.sh` parses required events and scans password canary | EMFILE listener fault and command failure | P0 event set only; metrics registry/counters are P1 | spec §18.2 |
| Response size, header filter, secret sealing | execute response path | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/executor.rs` | `reflected_secret` (8); `adversarial_http`; `scripts/p1-streaming-sealing.sh` | raw/base64/base64url/percent/content-type header leak across HTTP chunks and TLS writes; oversize and mid-stream close return one empty Agent ERROR frame | Sealing needles are zeroized; bounded full buffering only, no Agent-visible streaming | spec §14–15 |
| Private-IP and redirect block | production transport | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/upstream.rs` | public-IP release acceptance; `production_transport_blocks_*`; `upstream_screened` TLS/3xx/size/truncate | special IPv4/IPv6, embedded NAT64/6to4 private IP, 302, oversize, truncated | Strictly rejects 198.18/15; domain Actions need real DNS, not Clash/TUN fake-IP DNS | spec §15 |
| Encrypted backup | `rekey backup --output` | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-vault/src/authority/backup.rs`, `durable.rs` | `scripts/p0-acceptance.sh`; `scripts/p0-durability.sh`; `backup_restore` | protected internal snapshot before release audit; create-new/no-follow external final; pre/post-authorization SIGKILL; audit failure; streaming 256 MiB copy/hash | Only receipt + matching SHA-256 is success; an authorized partial/complete artifact may remain after failure/SIGKILL; one macOS durability environment | spec §16.1 |
| Offline restore | `rekey restore --input --sha256` | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-vault/src/bootstrap.rs` | `scripts/p0-durability.sh`; `backup_restore`; `cli_blackbox` | durable incomplete marker blocks serve; SIGKILL then safe retry; missing/wrong hash, wrong proof, nonempty target, corrupt later credential | `--sha256` required; 256 MiB bounded-RSS evidence on one macOS host | spec §16.2 |
| started/terminal audit pairing | execute + drain + SIGKILL/restart | Adversarially Verified | `v2.0.0-alpha.1` | `crates/rekey-broker/src/audit.rs`, `executor.rs`, `execution_supervisor.rs`; vault reconcile | `scripts/p0-crash-recovery.sh`; `scripts/p1-service-manager.sh`; `lifecycle_drain`; tracker fault tests | duplicate untrusted frame ID, SIGKILL after durable started, connection drop, execution panic, Drop/cancel/direct commit failure; restart preserves Policy evidence | Real release process and WAL; crash timing is harness-controlled | spec §11.2 / §18 |
| CLI never links crypto/SQLite | `rekey` binary | Adversarially Verified (dep tree) | `v2.0.0-alpha.1` | `crates/rekey-cli` | `cargo tree -p rekey-cli -e normal` | n/a | Delegates init/serve/restore to `rekeyd` | CLAUDE.md |

## P1 slices and explicitly absent capabilities

| Feature | State | Release | Notes |
| --- | --- | --- | --- |
| Linux container/namespace G2 reference | Adversarially Verified | — | `scripts/p1-linux-g2.sh` proved bounded UID/PID/ptrace/state/Admin/Docker-socket/direct-egress boundary plus approved production TLS execution on one LinuxKit arm64 environment; excludes kernel, daemon, runtime, VM host, native Linux and availability isolation |
| Linux `agent-run` netns launcher (`linux-netns-v1`) | Black-box Verified | `v2.0.0-alpha.2` | `rekey agent-run` / `rekeyd agent-run` via system bubblewrap; disjoint `--agent-socket` required; after `--tmpfs /tmp` the canonical socket is bind-mounted back; Docker hide paths are canonicalized. macOS `UNSUPPORTED_PLATFORM`. Ubuntu `P0 (ubuntu-latest)` in security-gate `34082334618` ran `scripts/p9-linux-agent-run.sh` to `PASS` (overlap-reject, public-tcp-denied, state-hidden, parent-env-dropped, unix-agent-socket, approved-execute). Merge `9565f9e` / PR #39. Ubuntu `P0 (ubuntu-latest)` in security-gate `34112035337` (PR #43) also recorded `public-udp-denied`. Ubuntu 24.04 needs a bwrap userns AppArmor profile. Notes may cite those black-box facts only; they must not call this Adversarially Verified isolation or general G2. Not a Docker-harness replacement. |
| P1.1 typed authorization kernel | Black-box Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Default-deny exact principal/action/resource/parameter rules and durable decision evidence; `v2.0.0-alpha.1` used an in-memory v1 snapshot; this archive accepts only signed persisted bundles (policy v3 for workload mapping) |
| Runtime-owned execution and central stop | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Agent disconnect cannot own/cancel admitted effects; supervisor panic fail-stops; stop closes remote-effect admission before Authority waits; one absolute deadline; sticky cancellation is scoped to one Running epoch |
| Password and recovery wrapper lifecycle | Adversarially Verified | `v2.0.0-alpha.2` | `rekey password change` and `rekey recovery rotate`; Authority, Admin IPC, and real CLI tests cover password/recovery step-up, old-factor rejection, response-loss retry, wrapper/audit rollback, backup generations, SIGKILL/reopen atomicity, and argv/env/log/file canaries; no VRK/DEK rotation, historical-backup invalidation, or escrow |
| Local audit query and JSONL export | Adversarially Verified | `v2.0.0-alpha.2` | Owner-checked Admin-only stable sequence snapshots, exact filters, 1,000-row bounded scans with continuation cursors, bounded result pages, locked reads, strict forged-response parsing, create-new mode-0600 export, pathname-inode verification, partial/final-sync failures, response-size rejection and secret/resource canaries; no Agent API, deletion, configurable retention, SIEM, WORM, legal hold, or remote delivery |
| Approvals / signed persistent policy | Adversarially Verified | `v2.0.0-alpha.2` | PR #25 code head `fc86bbe00e09a265b12bcad5740b1fabc1b9d432`; exact-head security `33689478062`, fuzz `33689478037`, performance `33689478030`. Immutable Ed25519 public trust root; sealed durable consecutive bundles; unlock-time reload; one-time/time-window and distinct two-person grants; exact tuple/policy/rule/expiry/use binding; atomic accepted+started audit; `approval_contract`, `policy_lifecycle`, `approval_policy`, and real `scripts/p3-approval-acceptance.sh` cover replay, concurrent exhaustion, parameter/policy/session change, lock/restart, tamper, deletion, expiry, audit rollback, CLI file bounds and list/export evidence. Verifier-only: no private-key custody, remote approval, control plane, or enterprise identity. |
| Workload identity session mint | Adversarially Verified | `v2.0.0-alpha.2` | Signed policy v3 maps exact generic OIDC, SPIFFE JWT-SVID, Kubernetes service-account, and CI/cloud subjects to Rekey principals with static Ed25519/RS256 keys. Agent-only stdin mint, strict compact JWT/claim validation, policy-authorized Actions, bounded capability lifetime, persistent atomic replay consumption, audit rollback faulting, restart and post-consumption-backup restore replay denial, policy-activation revocation, and real `rekeyd` + `rekey` black-box tests pass in `workload_identity`, `workload_blackbox`, storage, backup/restore, ENOSPC, and malicious-broker suites. A pre-consumption backup has no later replay record and remains within the documented G1 complete-vault rollback limit. No JWKS/discovery/introspection, issuer private-key custody, online provider interoperability, or G2/enterprise maturity upgrade. |
| Connector contract SDK / MCP and OAuth projections | Contract Tested | — | IO-free `rekey-connector` format v1 registry describes `fixed-http-header@1`, `github-app-installation@1`, `vault-kv-v2-source@1`, and `vault-dynamic-source@1`; Broker retains credential/network/deadline/audit/sealing/revoke ownership. Public testkit covers registry/effect/lifecycle invariants and routing mismatch; pure MCP object-schema projection rejects `x-mcp-header`, and OAuth projection serializes only fixed public RFC 8693 metadata. Source crate only: no MCP server, live generic OAuth, dynamic plugin/registry, new Agent API, generic provider expansion, announced product binary, or broader G1/G2 claim. |
| Control plane / multi-tenant / SSO / HA / SIEM | Specified | — | Enterprise |
| Windows | Specified unsupported | — | P0 macOS+Linux only |
| Chunk-boundary response sealing | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Real release CLI, dual UDS, SQLite and local CA/TLS; reflected variants split across HTTP chunks and 3-byte TLS writes; transparent Agent UDS capture proves one empty ERROR frame and no trailing/partial bytes. This is bounded full buffering, not Agent-visible streaming. |
| launchd service integration | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Real GUI-user LaunchAgent install/start/locked boot/unlock/disconnect+SIGTERM/audit-fault/restart/Admin shutdown acceptance passed on macOS |
| systemd service integration | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Required `ubuntu-latest` gate in release run 33592538786 passed with PID 1 systemd and a non-root service account, including locked boot, unlock, disconnect/drain, signal stop, audit-fault restart and Admin shutdown paths |
| OS key wrapper | Specified | — | Deferred: no auto-unlock and no external paid dependency; revisit only if platform user-presence can independently satisfy step-up |
| General password manager | Out of scope | — | |
| Transparent MITM / system CA | Deleted in v2 | — | |

## P2 local connector slice and enterprise gaps

| Feature | State | Release | Notes |
| --- | --- | --- | --- |
| GitHub App Installation closed profile | Black-box Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Typed encrypted credential, fixed GitHub action, exact repo/permission scope, revoke-before-success, absolute admission deadline, response sealing, disconnect+SIGTERM cleanup, ordered audit, backup/restore and raw/base64 private-key/JWT/token canary scans passed against local CA/TLS mock GitHub. `v2.0.0-alpha.1` shipped the earlier closed profile; this archive is `github-app-installation-v2` (P-06): one installation, 1–16 exact repositories, `GET /installation/repositories` and `POST /repos/OWNER/REPOSITORY/issues` only. Live `api.github.com` evidence does not cover every added Admin path. |
| Live github.com GitHub App interoperability | Field Validated | — | One disposable GitHub App/installation and `majiayu000/rekey-ci-dogfood` proved real `api.github.com` exchange, resource request, revoke-before-success and exact ordered audit chain. The App and credentials were deleted after verification; this does not generalize beyond the closed GitHub profile |
| Vault KV v2 fixed-version CredentialSource | Black-box Verified | `v2.0.0-alpha.2` | Shape A fixture-only: typed encrypted source profile, exact version/key read, public HTTPS screen, shared absolute deadline, no retry, source/resolved-value sealing, fixed-Action injection, typed rotation, drain gate, restart and backup/restore passed with release `rekeyd` + `rekey`, dual UDS, SQLite and local CA/TLS fixtures in `vault_source_contract` and `scripts/p7-vault-kv-source.sh`. No live Vault interoperability. OSS-binary protocol interop is specified in `docs/superpowers/specs/2026-09-07-vault-oss-interop.md` and is not implemented. |
| Vault one-shot dynamic lease CredentialSource | Black-box Verified | `v2.0.0-alpha.2` | Shape A fixture-only: typed encrypted profile, one exact `creds` acquisition, 5–300 second lease bound, selected-value sealing, fixed-Action injection, exact synchronous revoke-before-success, bounded malformed-response cleanup, non-retryable uncertainty, audit-failure cleanup and lock drain pass in `vault_dynamic_contract`. No renewal, durable lease registry, crash-time cleanup guarantee, live Vault interoperability, or private-network source access. OSS-binary protocol interop is specified in `docs/superpowers/specs/2026-09-07-vault-oss-interop.md` and is not implemented. |
| Other external CredentialSource / operation providers | Specified | — | Other Vault operations, AWS/GCP/Azure secrets or KMS, 1Password, PKCS#11/HSM, OS keychain, private-network source access, generic sign endpoints and dynamic provider adapters are not implemented |
| Enterprise multi-tenant control plane | Specified | — | Not implemented; no tenant-scoped key/query/session/audit model, SSO, SCIM or control-plane service |
| HA/DR | Specified | — | Not implemented; current durable authority is one local SQLite vault and no RPO/RTO or split-brain drill exists |

## How to update this file

After any behavior change: run the row’s verification command in this session,
then move state only as far as that command proves. Do not add a version to
the `Release` column from an ordinary feature PR or a development machine.
Archive membership is recorded in a release-prep PR. Public GitHub Release
URL success belongs in the evidence snapshot after that workflow succeeds.
