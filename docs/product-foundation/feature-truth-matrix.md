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
[Release run 34329532708](https://github.com/majiayu000/rekey/actions/runs/34329532708)
succeeded: both platform builds, native fresh installs, publication and both
public-URL smoke jobs passed. This was checked on 2026-09-14. Development
format v19 and the source-only rows below remain outside that v9 archive.

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
| Local Admin metrics snapshot (P-08 slice) | Black-box Verified (bounded local snapshot) | — | `rekey metrics [--prometheus]` samples fixed numeric process counters and capability gauges through existing Admin IPC, including locked state. Metrics reads do not extend idle lock; Agent access, malformed requests and hostile replies are rejected. Six focused metrics tests and a real Broker/CLI locked-read/self-exclusion/counter/text smoke passed on 2026-09-16. No listener, sensitive labels, OTel, persistent collection or worker queue-depth claim. See `2026-09-16-local-metrics.md` and the remaining-capabilities plan. |
| Local Prometheus textfile publication (P-08 slice) | Black-box Verified (local producer) | Unreleased | `rekey metrics --prometheus --textfile-dir DIR` publishes fixed `rekey.prom` atomically with controlled mode/group, one writer and explicit stale-file invalidation on sampling failure. Six unit cases, two hostile-Broker process cases and real locked-Broker publication/unavailable-Broker cleanup passed locally. POSIX permissions are checked; operator must ensure no additional ACL grants. No scheduler, collector deployment, remote delivery or freshness alert installation. |
| Linux metrics scheduling and freshness consumption (P-08 follow-up) | Source Implemented; deployment verification incomplete | Unreleased | Fixed Admin-UID oneshot/timer output, separate collector read group, and Prometheus freshness/rate/alert files are implemented. Ten real generator subprocess tests and five existing publisher tests passed; independent static review found no remaining actionable finding. The default tool gate fails explicitly here because promtool/systemd-analyze are unavailable: 22 official rule vectors have not run. Fixed-version/checksum Linux CI gate is added but has not executed. No actual Linux timer/cgroup/collector/network/alert installation claim. See `2026-09-30-metrics-deployment.md`. |
| Linux container/namespace G2 reference | Adversarially Verified | — | `scripts/p1-linux-g2.sh` proved bounded UID/PID/ptrace/state/Admin/Docker-socket/direct-egress boundary plus approved production TLS execution on one LinuxKit arm64 environment; excludes kernel, daemon, runtime, VM host, native Linux and availability isolation |
| Linux `agent-run` netns launcher (`linux-netns-v1`) | Black-box Verified | `v2.0.0-alpha.2` | `rekey agent-run` / `rekeyd agent-run` via system bubblewrap; disjoint `--agent-socket` required; after `--tmpfs /tmp` the canonical socket is bind-mounted back; Docker hide paths are canonicalized. Historical macOS unsupported behavior is superseded by the experimental macOS row below. Ubuntu `P0 (ubuntu-latest)` in security-gate `34082334618` ran `scripts/p9-linux-agent-run.sh` to `PASS` (overlap-reject, public-tcp-denied, state-hidden, parent-env-dropped, unix-agent-socket, approved-execute). Merge `9565f9e` / PR #39. Ubuntu `P0 (ubuntu-latest)` in security-gate `34112035337` (PR #43) also recorded `public-udp-denied`. Ubuntu 24.04 needs a bwrap userns AppArmor profile. Notes may cite those black-box facts only; they must not call this Adversarially Verified isolation or general G2. Not a Docker-harness replacement. |
| P1.1 typed authorization kernel | Black-box Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Default-deny exact principal/action/resource/parameter rules and durable decision evidence; `v2.0.0-alpha.1` used an in-memory v1 snapshot; this archive accepts only signed persisted bundles (policy v3 for workload mapping) |
| Runtime-owned execution and central stop | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Agent disconnect cannot own/cancel admitted effects; supervisor panic fail-stops; stop closes remote-effect admission before Authority waits; one absolute deadline; sticky cancellation is scoped to one Running epoch |
| Password and recovery wrapper lifecycle | Adversarially Verified | `v2.0.0-alpha.2` | `rekey password change` and `rekey recovery rotate`; Authority, Admin IPC, and real CLI tests cover password/recovery step-up, old-factor rejection, response-loss retry, wrapper/audit rollback, backup generations, SIGKILL/reopen atomicity, and argv/env/log/file canaries; no VRK/DEK rotation, historical-backup invalidation, or escrow |
| Local audit query and JSONL export | Adversarially Verified | `v2.0.0-alpha.2` | Owner-checked Admin-only stable sequence snapshots, exact filters, 1,000-row bounded scans with continuation cursors, bounded result pages, locked reads, strict forged-response parsing, create-new mode-0600 export, pathname-inode verification, partial/final-sync failures, response-size rejection and secret/resource canaries; no Agent API, deletion, configurable retention, SIEM, WORM, legal hold, or remote delivery |
| Approvals / signed persistent policy | Adversarially Verified | `v2.0.0-alpha.2` | PR #25 code head `fc86bbe00e09a265b12bcad5740b1fabc1b9d432`; exact-head security `33689478062`, fuzz `33689478037`, performance `33689478030`. Immutable Ed25519 public trust root; sealed durable consecutive bundles; unlock-time reload; one-time/time-window and distinct two-person grants; exact tuple/policy/rule/expiry/use binding; atomic accepted+started audit; `approval_contract`, `policy_lifecycle`, `approval_policy`, and real `scripts/p3-approval-acceptance.sh` cover replay, concurrent exhaustion, parameter/policy/session change, lock/restart, tamper, deletion, expiry, audit rollback, CLI file bounds and list/export evidence. Verifier-only: no private-key custody, remote approval, control plane, or enterprise identity. |
| Workload identity session mint | Adversarially Verified | `v2.0.0-alpha.2` | Signed policy v3 maps exact generic OIDC, SPIFFE JWT-SVID, Kubernetes service-account, and CI/cloud subjects to Rekey principals with static Ed25519/RS256 keys. Agent-only stdin mint, strict compact JWT/claim validation, policy-authorized Actions, bounded capability lifetime, persistent atomic replay consumption, audit rollback faulting, restart and post-consumption-backup restore replay denial, policy-activation revocation, and real `rekeyd` + `rekey` black-box tests pass in `workload_identity`, `workload_blackbox`, storage, backup/restore, ENOSPC, and malicious-broker suites. A pre-consumption backup has no later replay record and remains within the documented G1 complete-vault rollback limit. No JWKS/discovery/introspection, issuer private-key custody, online provider interoperability, or G2/enterprise maturity upgrade. |
| Connector contract SDK / MCP and OAuth projections | Contract Tested | — | IO-free `rekey-connector` format v1 registry describes ten built-ins in current unreleased source: `fixed-http-header@1`, `github-app-installation@1`, `keycloak-token-exchange@1`, `vault-kv-v2-source@1`, `vault-dynamic-source@1`, `gcp-secret-manager-source@1`, `aws-secrets-manager-source@1`, `azure-key-vault-source@1`, `onepassword-connect-source@1`, and `macos-keychain-source@1`; Broker retains credential/network/deadline/audit/sealing/revoke ownership. Public testkit covers registry/effect/lifecycle invariants and routing mismatch; pure MCP object-schema projection rejects `x-mcp-header`, and OAuth projection serializes only fixed public RFC 8693 metadata. The SDK crate itself remains projection-only (no IO or secrets). Source-only MCP-03 (`rekey-mcp`) and OAU-02 Keycloak evidence are recorded in the additional P2 slices below; this row still excludes live generic OAuth, dynamic plugin/registry, new Agent API, generic provider expansion, announced product binary, or broader G1/G2 claim. |
| Control plane / multi-tenant / SSO / HA | Specified | — | Enterprise |
| Agent CLI onboarding helper | Contract Tested | — | Source-only `scripts/agent-quickstart.py`; exact GitHub Action or existing Action plus explicit schema; protected session handoff and unsigned policy draft; real local broker and pseudo-terminal tests prove hidden credential entry, per-mutation step-up, denial before policy, signed activation and revoked-session denial. After an operator-authorized exact DNS exception, the current Codex shell host read the public GitHub test repository with HTTP 200, repeated successfully after synthetic-credential rotation, then received exit 4 after revocation (`docs/evidence/agent-cli-public-read-2026-09-10.json`). A subsequent real App run through the same helper proved authenticated repository reads before/after typed key rotation, create-issue 201 and revoked-credential exit 4 (`docs/evidence/github-app-rotation-write-2026-09-10.json`). Host evidence is the current Codex shell session, not a separately spawned Codex CLI process. No MCP server, auto signer, policy replacement or session renewal. |
| Vault public HTTPS Layer B harness | Field Validated (bounded KV and dynamic) | — | `scripts/dogfood-vault.py` passed with production release binaries, Vault OSS 1.20.3 and two public Cloudflare HTTPS origins: exact KV version read, fixed authenticated Action HTTP 200, unauthenticated API HTTP 401, successful started/finished audit ordering. See `docs/evidence/vault-kv-cloudflare-2026-09-10.json` for binary hashes and topology. Cloudflare terminates public TLS; temporary process-only Osaka routing resolved the earlier Tunnel failures. Test services, credentials and temporary DNS/routing changes were removed. A separate GitHub-hosted public run also passed the exact dynamic database role and independent post-revoke role-removal check; see interop specification section 7 and `outputs/rekey-onboarding-acceptance-20260910/public-run.json`. |
| macOS `agent-run` Seatbelt (`macos-seatbelt-v1`) | Black-box Verified | Unreleased | Experimental fixed profile; real kernel probes and capability-authorized execution against a real Broker with a deterministic test upstream pass on macOS 26.5.1 / 25F80 arm64. Read-only launch code directory; private writable scratch; exact canonical Agent UDS; no unsandboxed fallback. Fixture attacks cover state/Admin/other UDS, symlinks and APFS/case aliases, IPv4/IPv6 TCP/UDP, DNS resolver, Mach lookup, cross-process signal, inherited FD, fork/exec, and confinement after rekeyd death. `task_for_pid` control is denied by the host too, so no independent task-port claim. No general G2, host same-UID attacker, all-Agent compatibility, or full descendant termination guarantee. See OS-05 in `2026-09-16-local-isolation-and-streaming.md`. |
| GitHub CreateIssue reference process | Black-box Verified | Unreleased | macOS bundled native sidecar with separate deny-default Seatbelt profile; only canonical operation and public issue/comment input/output, Broker retains secrets/effects/revoke/audit. Eight focused attack cases and real Broker revoke-before-success fixture passed. Sampling RSS is not a hard limit; no general multi-effect SDK-04 or full P-10 claim. See `2026-09-16-github-reference-plugin.md`. |
| Action-bound native plugin registration | Black-box Verified | Unreleased | Optional `native_plugin` stores Admin-approved path/SHA-256 and either `github-issues-v1` or `anthropic-messages-v1` on immutable Action versions using existing step-up CRUD. Nine real Broker fixtures cover GitHub CreateIssue/CreateIssueComment, same-artifact selection, exact operation/body envelope matching, six hostile output cases with zero token exchange, version pin/disable, audit rollback, restart and backup roundtrip. Anthropic `text_stream` binds the same GitHub sidecar artifact; first-chunk-before-upstream-end and hostile zero-upstream cases are in `tests/native_plugin.rs`. Explicit binding never falls back to bundled or in-process code; unregistered Anthropic streaming stays in-process. macOS and the bounded Linux GNU x86_64/aarch64 explicit-registration runtime are implemented. Schema 14 plus Anthropic bind evidence is local workspace tests on this increment; the Linux GitHub runner previously passed native Ubuntu P0/G2 on format 13 (`35139996331`). Schema 14 rejects v13 and older; backups include declarations, not executable files. See `2026-09-16-native-action-plugin.md` and `2026-09-16-action-plugin-registration.md`. This is not a marketplace or a complete P-10 claim. |
| Independent Anthropic text streaming | Black-box Verified | Unreleased | `execute-text-stream`; eight real local TLS/UDS cases prove checked early text before upstream completion, late failure, audit failure, disconnect, deadline and slow consumer. Four parser/sealer cases include all split points; CLI validates terminal/sequence/EOF; MCP rejects projection. Only completed is success; visible checked prefixes cannot be recalled. Opaque-token, one text block, no tools/thinking or live provider validation. Original Execute remains buffered. Current state/backup format 15 rejects earlier versions. See `2026-09-16-anthropic-text-stream.md`. |
| Windows | Specified unsupported | — | P0 macOS+Linux only |
| Chunk-boundary response sealing | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Real release CLI, dual UDS, SQLite and local CA/TLS; reflected variants split across HTTP chunks and 3-byte TLS writes; transparent Agent UDS capture proves one empty ERROR frame and no trailing/partial bytes. This is bounded full buffering, not Agent-visible streaming. |
| launchd service integration | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Real GUI-user LaunchAgent install/start/locked boot/unlock/disconnect+SIGTERM/audit-fault/restart/Admin shutdown acceptance passed on macOS |
| systemd service integration | Adversarially Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Required `ubuntu-latest` gate in release run 33592538786 passed with PID 1 systemd and a non-root service account, including locked boot, unlock, disconnect/drain, signal stop, audit-fault restart and Admin shutdown paths |
| OS key wrapper | Implemented (bounded native macOS) | — | Superseded by the 2026-09-15 native desktop remembered-unlock specification: explicit manual proof issues a fixed seven-day recovery authorization, with its random key stored in the login Keychain; lock/expiry/factor changes revoke it. This is not an OS Keychain upstream credential source or a general platform user-presence guarantee. See the Native macOS Admin UI rows and `apps/macos/README.md`. |
| General password manager | Out of scope | — | |
| Transparent MITM / system CA | Deleted in v2 | — | |

## P2 local connector slice and enterprise gaps

| Feature | State | Release | Notes |
| --- | --- | --- | --- |
| GitHub App Installation closed profile | Black-box Verified | `v2.0.0-alpha.1` / `v2.0.0-alpha.2` | Typed encrypted credential, fixed GitHub action, exact repo/permission scope, revoke-before-success, absolute admission deadline, response sealing, disconnect+SIGTERM cleanup, ordered audit, backup/restore and raw/base64 private-key/JWT/token canary scans passed against local CA/TLS mock GitHub. `v2.0.0-alpha.1` shipped the earlier closed profile; this archive is `github-app-installation-v2` (P-06): one installation, 1–16 exact repositories, `GET /installation/repositories` and `POST /repos/OWNER/REPOSITORY/issues` only. Live `api.github.com` evidence now covers typed App add/rotation/revoke and issue creation on one repository; A separate two-repository field run now validates GitHub-signed added/removed deliveries via the delivery REST API and Admin apply, including same-capability scope changes and pre-IO denial (`docs/evidence/github-app-repository-webhook-2026-09-10.json`). |
| Live github.com GitHub App interoperability | Field Validated | — | One disposable GitHub App/installation and `majiayu000/rekey-ci-dogfood` proved real `api.github.com` exchange, resource request, revoke-before-success and exact ordered audit chain. The 2026-09-10 run additionally proved two real App keys, typed rotation to version 2 with unchanged capability, read 200 before/after rotation, create-issue 201 and revoked-credential exit 4 (`docs/evidence/github-app-rotation-write-2026-09-10.json`). The issue was closed, Issues settings restored, App uninstalled/deleted and local keys removed. A separate A→A+B→A run validated real GitHub delivery signatures, tamper and stale-version rejection, exact scope, and removed-repository pre-IO denial (`docs/evidence/github-app-repository-webhook-2026-09-10.json`). Events were retrieved via the delivery REST API; the HTTP target returned 403, so no public receiver-success claim is made. All temporary App/repository resources were deleted. This does not generalize beyond the closed GitHub profile |
| Vault KV v2 fixed-version CredentialSource | Field Validated (bounded KV read) | `v2.0.0-alpha.2` | Shape A: typed encrypted source profile, exact version/key read, public HTTPS screen, shared absolute deadline, no retry, source/resolved-value sealing, fixed-Action injection, typed rotation, drain gate, restart and backup/restore passed with release `rekeyd` + `rekey`, dual UDS, SQLite and local CA/TLS fixtures in `vault_source_contract` and `scripts/p7-vault-kv-source.sh`. Ubuntu CI also runs pinned HashiCorp Vault OSS `1.20.3` through the same post-screen local-CA injection (`scripts/p7-vault-oss-interop.sh`). One public HTTPS KV v2 run with Vault OSS 1.20.3 through Cloudflare also passed (`docs/evidence/vault-kv-cloudflare-2026-09-10.json`); this validates the exact recorded source/version and Action, not general Vault operations, private-network support or HashiCorp Cloud. |
| Vault one-shot dynamic lease CredentialSource | Field Validated (bounded dynamic role) | `v2.0.0-alpha.2` | Shape A fixture-only: typed encrypted profile, one exact `creds` acquisition, 5–300 second lease bound, selected-value sealing, fixed-Action injection, exact synchronous revoke-before-success, bounded malformed-response cleanup, non-retryable uncertainty, audit-failure cleanup and lock drain pass in `vault_dynamic_contract`. Ubuntu CI also runs the same closed profile against Vault OSS `1.20.3` using the database secrets engine plus ephemeral PostgreSQL (`scripts/p7-vault-oss-interop.sh`). Public run `34447873706` additionally passed the exact `database/agent-test` profile through Cloudflare, real PostgreSQL authentication, ordered successful lease revoke, and independent database-role removal. See interop specification section 7. Published alpha.2 has no renewal; the separate unreleased DYN-05 row records the breaking v2 extension. Published alpha.2 has no durable journal; the separate DYN-06 development row records bounded exact-ID recovery. No crash-time cleanup guarantee or private-network source access. |
| Execution-scoped Vault lease renewal (DYN-05) | Black-box Verified | — | Breaking `vault-dynamic-source-v2` profile requires a 5–300 second renewal increment. One conditional renewal before business IO, actual TTL from request start capped by the original Action deadline, 500ms cleanup reserve, audit-before-renew, exact revoke and nonretryable uncertainty. Six parser/deadline unit tests and 21 real Broker/Authority/UDS contracts passed with independent review. See [renewal specification](../superpowers/specs/2026-09-30-vault-lease-renewal.md). The local macOS post-screen TLS fixture also passed against real Vault OSS 1.20.3 and PostgreSQL: initial TTL 5, requested increment 60, actual TTL assertion 6–60, and exact revoke removed the issued database role. Production maximum TTL and parent revocation remain field-unvalidated; durable registration and recovery are separately tracked in DYN-06, with no crash-time cleanup guarantee. |
| Encrypted Vault lease journal and bounded restart recovery (DYN-06) | Contract Tested | — | Format 15 seals exact-ID records and the set manifest with audit linkage; source acquisition intent commits before IO and issued registration commits before business. Locked startup has no cleanup IO; first explicit unlock cleans at most eight known IDs within eight seconds using exact historical versions, while Running repeat unlock leaves live executions untouched. 151 Vault targeted tests, 27 Broker contracts and five real TLS/CLI/process scenarios passed, including three SIGKILL windows, historical profile rotation/revoke, pending/old backup and unknown source isolation. Broker/process evidence was collected before the sandbox permission change; two subsequent P2 corrections passed four actual Actor/SQLite no-listener regressions in the integrated source and independent static review. Same-snapshot typed unavailability rejects recovery after a late fault; exact cleanup uses the absolute provider deadline. Current all-targets/Clippy/fmt pass, but full integrated runtime verification remains blocked. Unknown acquire IDs are never guessed, and older backups cannot reveal later leases. Field TTL, account removal, historic token validity and old-primary fencing remain unvalidated. See [journal contract](../superpowers/specs/2026-09-30-vault-lease-journal.md). |
| Independent audit delivery (AUD-07) | Black-box Verified | — | `scripts/rekey-audit-delivery.py` reads complete unfiltered CLI exports into a private immutable batch/ACK journal for one fixed public HTTPS receiver. Twenty-seven tests cover real CLI export/local TLS, lost ACK/restart replay, source/vault binding, sequence gaps, pruning of acknowledged history, private files/path replacement, bounded retries, deadline process termination, hidden-input failure, malformed/deep ACKs and receipt capacity. No unlock ability or Broker/SIEM coupling. Production receiver persistence, deduplication, authentication and capacity remain field-unvalidated. See [delivery contract](../superpowers/specs/2026-09-30-audit-delivery.md). |
| Fixed S3 audit archival and Legal Hold (AUD-08) | Contract Tested | — | Independent `rekey-audit-archive.py` uses protected expiring STS profiles, a fixed owner/bucket/key, conditional PUT and exact-version SHA256/SSE/retention/hold readback before durable receipt. Twenty-three tests include the official SigV4 vector, real synthetic TLS, lost upload/hold responses, early recovery version pin, role-purpose separation, private journal/fsync failures, credential reflection and DNS deadline termination. No delete, retention shortening or governance bypass. Actual IAM roles, Object Lock enforcement, permissions and production WORM remain field-unvalidated. See [archive contract](../superpowers/specs/2026-09-30-s3-audit-archive.md). |
| Single-organization HTTPS approval-file relay (APR-08) | Black-box Verified | — | Independent service transports origin-signed challenges and grants with fixed fresh IdP introspection, explicit subject ACL, private SQLite FULL/WAL immutable receipts and audit-before-response. Eleven actual subprocess HTTPS contracts passed and independent review found no remaining blocker; HTTPS→existing signer→real Broker accepted exactly one request and denied false signatures/body/session/replay. No server signing or Broker public listener. Client login, real customer IdP, personnel devices and hosted operations remain field-unvalidated; APR-09 inbox and APR-10 directory are separate capabilities. See [relay contract](../superpowers/specs/2026-09-30-remote-approval-relay.md). |
| Authenticated remote pull inbox (APR-09) | Contract Tested | — | Same-service fixed GET /v1/inbox applies fresh personnel authentication and current owner/recipient ACL before stable 25-item paging; public pins and transport states never authorize execution. Fifteen actual TLS contracts and inbox→signer→real Broker E2E passed; independent defensive review found no remaining blocker. No web review/sign interface, directory or outbound notifications. Native click acceptance remains separate. See [inbox contract](../superpowers/specs/2026-09-30-remote-approval-inbox.md). |
| Fixed Vault Transit approval signing (EXT-07 slice) | Contract Tested | — | Explicit protected profile on the independent `rekey-approval-sign` binds one public HTTPS origin, Transit mount/key, Ed25519 public key and explicit key version into the existing reviewed digest. Eleven binary-private contracts include real TLS, exact RKAPPROVAL bytes, production grant verification, wrong version/key/expiry, bounded response/deadline and secret canaries; six existing software-signing tests also passed. Production uses shared public-IP screening and built-in WebPKI roots, no proxy/redirect/retry or private/CA override. Real Vault ACL, non-derived/exportable settings, revocation and production Broker consumption remain unvalidated. See [Transit signing contract](../superpowers/specs/2026-09-30-vault-transit-approval-signer.md). |
| Other external CredentialSource / operation providers | Specified | — | Other Vault operations, cloud KMS, PKCS#11/HSM, OS keychain, private-network source access, generic sign endpoints and dynamic provider adapters remain unimplemented; fixed GCP/AWS/Azure and 1Password Connect secret-source local implementation and its current verification limits are recorded separately below |
| Enterprise multi-tenant control plane | Contract Tested (local target slice) | — | Actual vault/root activation binding and verified target status/activation audit implemented; fixed two-node file helper in progress. 58 focused Rust tests passed in an isolated worker. No shared tenant service, SSO/SCIM, HA or real node isolation acceptance. |
| HA/DR | Black-box Verified (Docker manual reference) | — | Two distinct container volumes, external Docker-daemon fencing by immutable container deletion, partition promotion refusal, verified restore cut, old-token rejection and fresh-session execution passed locally. One synthetic lost credential write was verified; observed RTO 1.36s and commit-gap RPO bounds 1.42–1.76s apply only to this run. No physical-host HA, automatic failover, continuous replication, independent power domains or production SLA. See [Docker DR contract](../superpowers/specs/2026-10-02-docker-dr-reference.md). |

2026-10-02 integration corrections selected before implementation: audit delivery
accepts the current BackupReceipt including `snapshot_cut`, pins all receipt bytes,
and still advances only from durable ACKs. Policy replacement continues to revoke
all old capabilities; local step-up-protected Admin session issuance gains explicit
principal selection for reissue under the current policy. OIDC identity binding
and the workload Agent metadata remain unchanged. Fresh verification is pending.

## How to update this file

Source regression fixes (2026-09-30; no release-membership change):
`connector_audit_deadline` exercises six real Broker/Authority/Agent IPC paths
with a stalled SQLite writer, proving non-retryable issued/revoked audit
timeouts, successful cleanup and ordered indeterminate terminals. The CLI
process contract verifies exit 8. The shared launcher regression rejects an
exact capability in child argv before spawn; macOS kernel acceptance remains
bounded to the tested host. A delayed-Authority unit regression proves that
ordinary idle polling does not hold execution admission, while existing idle
drain tests retain the stale-activity checks. These fixes do not broaden G1/G2.

After any behavior change: run the row’s verification command in this session,
then move state only as far as that command proves. Do not add a version to
the `Release` column from an ordinary feature PR or a development machine.
Archive membership is recorded in a release-prep PR. Public GitHub Release
URL success belongs in the evidence snapshot after that workflow succeeds.

GHA-12 source extension: fixed issue-comment creation is Black-box Verified locally under P-06 §5.3. Canonical fixed issue path, closed body, exact repository/write exchange, response projection, revoke-before-success, request-linked audit chain and canary scans passed via the extended `scripts/p6-github-app-extension.sh`. Unit tests cover malformed numbers, scope/body rejection, wrong response issue/host/id and no write retry. Existing released and field-validated GitHub claims above do not include comments. See `outputs/rekey-gha12-20260910/`.

WID-10 source interoperability passed in GitHub Actions run `34458227976`: real JWT mint, fixed read 200, replay/wrong-audience rejection and natural expiry rejection. Public evidence is in `outputs/rekey-wid10-20260910/static-receipt/`. Released alpha.2 rejects GitHub Actions JWTs containing standard `x5t`; the tested source permits bounded informational RS256 `x5t` without changing pinned `(issuer,kid,algorithm)` trust. This static-key run does not validate online JWKS or change release claims.


## Additional source-only P2 slices (2026-09-10)

| Slice | Evidence level | Current boundary |
| --- | --- | --- |
| MCP-03 local stdio server | Black-box Verified | `rekey-mcp` reuses connector descriptors and the pure IPC client. Real broker success/denial/expiry/lock/sealing tests passed. Codex 0.151.0 completed actual 2025-06-18 initialization and tool discovery. Only explicitly configured fixed Actions/object schemas; no Admin operations, signing, auto retries or session renewal. Host discovery and direct MCP invocation are separately evidenced in `outputs/rekey-mcp03-20260910/`. Not release-packaged. |
| POL-08 external operator signer | Black-box Verified | `rekey-policy-sign` reviews a typed draft, binds its RFC8785 digest, reads an operator-owned PKCS8 Ed25519 file and writes new-only trust/bundle files. Existing verifier and real Broker accept the signed artifact and reject tampering; signing alone changes no Broker state. No key generation/custody or activation. `outputs/rekey-pol08-20260910/live.log`. |
| UX-03 trusted terminal repair | Black-box Verified | `operator-credential-repair.py` displays registered metadata as escaped data, handles provide/decline, and delegates hidden proof/value input to the CLI. Active opaque-token rotation only; unsupported/missing/disabled/revoked cases fail explicitly. Cancel makes no change; provide rotates without execution; later explicit action returns 200 with the new version. No graphical credential card or automatic write retry. `outputs/rekey-ux03-20260910/live.log`. |
| WID-09 fixed GitHub online JWKS | Field Validated (bounded GitHub issuer) | Explicit signed opt-in with empty static keys; fresh fixed HTTPS fetch per mint, transient keys without policy/replay digest changes. Local tests cover rotation, failures and policy replacement. Real GitHub run `34459644320` passed mint/read200, replay/wrong-audience/natural-expiry rejection and a fresh-token positive control. Temporary repo deleted, API404 confirmed. `outputs/rekey-wid09-20260910/online/`. No Discovery or Introspection; not released. |
| OAU-02 fixed Keycloak exchange | Black-box Verified (real provider, local TLS transport) | Protected typed add/rotate, fixed audience/GET, exchange/use/direct issued-token revoke and request-linked audit. Real root Broker/CLI with Keycloak 26.7.3 passed resource200, revoke-before-expiry, same-subject reuse for that configuration, reflected-token denial/revoke and expired-subject rejection. JSON-escaped profile-secret reflection regression fixed; six focused contract tests and two local unit tests pass. `outputs/rekey-oau02-20260910/live/integrated/`. No generic OAuth, refresh, private-network permission or crash cleanup claim. This slice originally introduced storage format 10; current source uses format 17 and rejects older state/backups without migration. |

These credential-related source changes require human review before merge.

APR-08 origin-authenticated relocated signing (source only):
`rekey approval prepare` returns a Broker-signed
`rekey.approval.challenge.envelope.v1`. `rekey approval origin` pins the
VRK-derived origin public key. `rekey-approval-sign` requires `--origin-key` and
rejects unsigned or tampered challenges. Signer tests, Broker approval
contracts, and the real Broker fixture in `scripts/test-approval-signer-live.py`
cover acceptance, mismatch, replay, and origin verification. Evidence:
`outputs/rekey-apr08-20260910/`. This is not a hosted remote approval service
or personnel directory. Human review is required before merge.

APR-09 local Admin approval inbox (source only):
`rekey approval pending` lists unused in-memory challenge summaries;
`rekey approval get` reprints a freshly origin-signed envelope. The CLI
validates shape only. After the first successful reservation the item leaves
the inbox. Session unit tests and Broker approval contracts cover list, get,
unknown id, expiry, overflow, and post-execute removal. This is not a GUI,
push notification, hosted inbox, or Agent-callable sign socket. Human review
is required before merge.

## Native macOS Admin UI (2026-09-14, source only)

| Feature | State | Release | Limits and evidence |
| --- | --- | --- | --- |
| Chinese SwiftUI Admin client | Black-box Verified | — | Local macOS build and observed native credential list/detail/search, protected forms, Action/policy/approval/audit navigation. `scripts/test-macos-ui.swift` exercises the same CLI bridge against a disposable real vault: init, wrong-proof and locked denial, credential lifecycle, Actions, capability lifecycle, policy/approval reads, backup/restore/audit export, stdin-only proof, filtered environment, new-only 0600 results and malformed responses. UI submit paths are not all individually covered by native automation. No independent human audit, notarization, release packaging, remote service or signing-key custody. See `docs/superpowers/specs/2026-09-14-native-admin-ui.md`. |

Human desktop current-secret reveal and API-key add use a password-authenticated 7-day Admin session (source only). Locked/stale/forged sessions and the Agent channel are denied; plaintext is returned only in Admin response bodies after durable audit commits. Verified by `scripts/test-human-vault.py` and `admin_ipc::desktop_values_use_body_and_agent_channel_cannot_reveal`. Native interaction automation for this extension remains pending.

Remembered native desktop unlock can survive application and broker restart for the original seven-day window using a local Keychain restore key and an authenticated wrapped root key. Manual lock revokes it. Coverage: `authority_contract::remembered_desktop_*`, `scripts/test-human-vault.py`, and the local `scripts/test-macos-keychain.swift` process-restart/expiry contract.

APR-09 native approval binding details (2026-09-16, source only): the native client displays a selected origin-signed challenge envelope, origin public key, and exact-version current Action metadata, and exports the displayed bytes as a new private file. The UI does not verify signatures or display original request parameters, which are absent from the envelope. Native compilation and the extended UIContract passed against disposable Broker and subprocess fixtures; no full native-click or end-to-end signing claim. See `docs/superpowers/specs/2026-09-16-approval-review-ui.md`.

## Local encryption-key rotation (2026-09-16, source only)

| Feature | State | Release | Limits and evidence |
| --- | --- | --- | --- |
| KEY-04 all-version DEK rotation | Black-box Verified (bounded DEK slice) | — | `rekey key rotate-dek` reencrypts active, retired and revoked versions under fresh DEKs with unchanged VRK and metadata. Vault/store fault tests prove SQL, audit, corrupt-later-row and precommit-expiry rollback; Admin/Agent and CLI tests prove step-up, capability continuity and body-only secrets. Both backup generations restore independently. Full VRK rotation and historical-backup revocation are not included. See `docs/superpowers/specs/2026-09-16-key04-dek-rotation.md`. |

## Explicit local audit pruning (2026-09-16, source only)

| Feature | State | Release | Limits and evidence |
| --- | --- | --- | --- |
| AUD-06 completed execution-group pruning | Black-box Verified (bounded explicit deletion) | — | `rekey audit prune --before-ms` requires unlocked Admin step-up and deletes only complete, old execution groups without approval/management associations. Sequence-key deletion, in-loop deadlines, audited rollback, restart reconciliation and global snapshot invalidation have 10 targeted tests. A disposable real CLI/Broker smoke proved locked denial, two-row deletion, stale-snapshot failure and no-op. The export interruption test uses a synthetic Broker. No automatic retention, all-event cleanup, file shrinking, secure erase or backup deletion. See `docs/superpowers/specs/2026-09-16-audit-prune.md`. |

## Locked root-key rotation (2026-09-16, source only)

| Feature | State | Release | Limits and evidence |
| --- | --- | --- | --- |
| KEY-04 VRK and dependent-key rotation | Black-box Verified (bounded local rotation) | — | `rekey key rotate-vrk` requires Locked state and both current factors, generates a new VRK and DEKs, reseals credentials/header/all three policy records, and preserves business metadata and workload replay. One audited SQL transaction replaces all database state; remembered desktop authorization is revoked first and cannot be rolled back. Vault tests cover all kinds/history, both backup generations, proof/backoff, corrupt-state/SQL/audit/deadline rollback and SIGKILL before/after commit; real CLI and Broker tests cover secret input, origin change, old-session/challenge denial and bounded-stop unknown results. No slow-COMMIT, power-loss or directory-fsync fault injection; new CLI hidden TTY was not exercised. No provider-secret or historical-backup revocation. See `docs/superpowers/specs/2026-09-16-key04-vrk-rotation.md`. |

### 2026-09-17 local continuation

The registered GitHub issue protocol now supports two fixed operations (CreateIssue and CreateIssueComment) using a closed operation/body envelope. The subsequent closed native plugin increment renamed the JSON field to `native_plugin`, added `anthropic-messages-v1` on the same runner, and uses schema 14 (rejecting v13). This is not a general multi-credential effect platform, marketplace, or complete P-10. The full run results are recorded in the remaining-capabilities plan.

Linux Agent FD acceptance reproduced a non-CLOEXEC descriptor leak through bwrap (state file FD211; the first failed assertion stopped the later socket case). The fix marks all descriptors >=3 close-on-exec using Linux close_range(CLOSE_RANGE_CLOEXEC), with startup failure on unsupported/denied calls. Final integrated Linux tests pass as root and UID/GID65534 (5 each), including file/socket FD211 and FD500 after lowering NOFILE to128, network controls, state/Admin hiding and real Broker execution. Environment: LinuxKit 6.12.76 arm64, Debian bookworm, dedicated Docker container with seccomp/systempaths unconfined, no extra capability or host mounts. This is not native Ubuntu evidence, a Linux plugin runtime or complete OS-06.


## Linux plugin backend scope (2026-09-17, source only)

Explicit GitHub plugin registration supports Linux GNU x86_64/aarch64, following `2026-09-16-github-reference-plugin.md`. The final runner uses a fixed minimal read-only rootfs, native-ABI default-deny seccomp, CPU1/2s, AS64MiB and NOFILE128. Integrated LinuxKit arm64 tests pass as root and UID/GID65534: 11 runner entries (including a helper fixture) and nine real Broker tests each. Native Ubuntu x86_64 P0 and Linux G2 jobs also passed on source `c21aee4` in [CI 35135342482](https://github.com/majiayu000/rekey/actions/runs/35135342482), including x32/compat-ABI rejection and explicit-plugin P6. The macOS job in that run failed a separate synthetic SQL cleanup fixture; the whole run was not green. Existing Linux in-process defaults remain. AS is per-process virtual memory, not total physical memory; cancellation and READY-based parent-death tests prove stopped descendants, allowing zombies, not atomic all-startup-phase cleanup. No release claim is made.

2026-09-30 fixed GCP Secret Manager source (EXT-02): protected typed registration/rotation, explicit canonical numeric version, one bounded source read, CRC32C/base64/UTF-8 validation, original Action deadline, durable audit and consume-once sealing are implemented in source format 16 (kind 6/rotate opcode 41). The final source/header corrections passed 15 GCP tests (five parser checks and ten real Authority/SQLite/executor tests), two real HeaderMap regressions, and 12 existing sealing/source regressions in the integration tree. Compilation/Clippy/fuzzing/fmt passed. Real TLS/UDS/CLI positive contracts remain blocked by listener EPERM; cloud IAM/expiry/audit acceptance and full current workspace have not passed. This is not cloud-field or full black-box acceptance; independent final static review is tracked separately. See `2026-09-30-gcp-secret-source.md`.

2026-09-30 native policy/approval file flow (UX-04/APR-09): unsigned draft preview/export, original body handoff to the independent signer, and explicit exact-version execute with stdin-only capability and private snapshots are implemented. Three independent review findings were fixed: pretty CLI response parsing, late detail callback admission, and the CLI-aligned 4KiB grant limit. The integration tree passed 80 local file/process/lifecycle assertions and full App/UIContract macOS14 strict compilation. The child response fixture now follows the actual CLI pretty layout; it is not a real Broker execute or native-click result. Original full UIContract remains intact and compiled but cannot run under listener EPERM. No GUI signing/private-key custody or full graphical-flow acceptance is claimed. See `2026-09-30-native-policy-approval-flow.md`.

2026-09-30 fixed AWS Secrets Manager source (EXT-01): kind7/state format17/typed rotate42 are integrated for one full commercial ARN and explicit VersionId, complete SecretString only. Imported temporary key/secret/session credentials remain protected; existing fixed TLS/public-IP screening, one signed read, deadline/audit-before-effect/consume-once and source/business sealing apply. Independent review found and production-corrected a SigV4 canonical-token reflection omission; the normalized-header regression now independently isolates clean bodies and passed fresh tests and final static closure. Current integration passed 293 unique targeted tests (246 domain/connector/Vault,20 AWS parser/signing/Actor,27 existing source/CLI regressions); these do not constitute TLS/UDS/customer AWS acceptance. Current full workspace remains blocked, no commit/release claim. See `2026-09-30-aws-secret-source.md`.

2026-09-30 Azure fixed version source (EXT-03): local implementation and final source-bound static review completed, kind8/format18/typed rotate43; fixed commercial Key Vault GET2025-07-01, complete SecretBundle value and exact ID, explicit token-use deadline and provider metadata admission checks. 234 unique focused tests passed (70 coordinator,164 same-source worker); bootstrap and complete-value HTTP edge-OWS regressions for Azure/GCP passed actual RED-to-GREEN. Current full workspace failed15 IdP fixture startups; independent current TCP/UDS listener probes returnedEPERM. Real Azure/TLS/UDS/GUI acceptance has not passed. Other source HTTP parsed representations remain a separately tracked risk. See `2026-09-30-azure-secret-source.md`.

2026-09-30 fixed HTTP edge-OWS follow-up: actual Opaque/AWS complete-value RED-to-GREEN fixes are integrated in six existing files, retaining exact outbound bytes; Vault KV/Dynamic reject SP/HTAB at their existing intake boundary and two added regressions preserve it. Coordinator executor102 and GitHub10 tests, all-targets/check/Clippy/fmt/mechanical and CLI dependency contracts passed. Final source-bound independent review found no actionable findings; no workspace-wide DLP or listener acceptance claim. See `2026-09-30-http-header-ows-sealing.md`.

2026-09-30 1Password Connect fixed item/field source (EXT-04) is integrated for review, kind9/format19/typedrotate44; complete field value with exact current item version, fixed single publicHTTPS GET and declared local-use deadline. 374 unique focused tests passed (289 coordinator,85 same-source worker); final independent actual25-SHA review closed the eligibility-null and parsed-selected bootstrap P2 findings. Root check/Clippy/fmt/fuzz-feature/mechanical passed. The previous parallel VRK test failure and unchanged macOS native-sidecar failures remain in the evidence; full workspace/TLS/UDS/GUI/customer acceptance is incomplete. Protected CLI spelling RED was fixed explicitly. Strict listener/customer Connect acceptance remains incomplete. This does not prove latest cloud synchronization or private-network connectivity. See `2026-09-30-onepassword-secret-source.md`.

2026-09-30 decoded bootstrap source boundary: Azure/AWS/GCP, Vault KV/Dynamic
and the actual RSA-signed GitHub issued-token encoding bypass are fixed in
13 existing files; 107 unique focused worker tests pass at one frozen SHA.
Parsed values are checked before business effects. Dynamic keeps exact cleanup
and unknown intent; a reflected GitHub bootstrap never acquires revoke ownership.
Keycloak production remains unchanged with prior parse rejection demonstrated.
No generalized transformation/issuer DLP or field acceptance claim follows.

ENT-01/02 Rust target/status/audit slice binds actual vault and canonical trust
document after step-up, before transaction and exact retry. Required CLI target
arguments are wired into 24 existing scripts and the native file activation flow.
Immutable root digest, persistent activation instant and exact audit reason are
covered locally. Fixed private filebox helper is implemented; 66/67 fresh root
tests pass, strict synthetic PTY restoration remains failed under actual setter
EPERM. Three static P2 findings are closed in independent review; real two-node
activation/isolation and field acceptance remain unvalidated.

2026-09-30 ENT-03/APR-10 next contract frozen: fixed registered SCIM consumer,
relay-only breaking config/store2 and durable tombstone/transaction admission;
signed policy roll-forward conservatively revokes existing sessions. Implementation
and strict runtime verification pending; full personnel OIDC/SCIM/node-offboarding
claims remain open. See [bounded contract](../superpowers/specs/2026-09-30-identity-directory.md).

ENT-03 next: [fixed OIDC administrator contract](../superpowers/specs/2026-09-30-oidc-admin.md)
freezes pure signed ID-token validation first, followed by actual code/state/nonce/
PKCE and managed Node IPC/directory gate. Still pending; relay login and Workload
JWT cannot stand in for node administrator identity. No full SSO claim follows.

ENT-03/APR-10 directory A + node prerequisite B implemented locally: fresh
coordinator13 directory units and6 real Authority policy/session units pass.
Independent review closed the directory failure-to-fault mutex race with actual
SQLite concurrent RED/GREEN evidence. Nineteen strict TLS cases compile; actual
source bindEPERM keeps runtime gate unpassed. Existing signer-live caller config2
is wired/AST-checked. Node receipts remain pending; directory-to-signed-policy
application, OIDC administrator login and real two-node field acceptance remain open.

2026-10-01 OIDC C1 pure16 signed tests +10 Workload regressions and C3 explicit admin/self-only proof20 units +1 offline registration passed locally. C3 strict21 TLS contracts compiled only; C2 node PKCE/login/managed dispatch contract frozen before implementation. This is partial ENT-03, no field/whole-suite completion.

2026-10-01 manual standby H1 [receiver durability contract](../superpowers/specs/2026-10-01-standby-backup-durability.md) frozen before implementation. Existing completed backup transport is strengthened, not a failover/fencing claim; snapshot cut/restore/promotion remain pending.


2026-10-01 VEX-04 latest slice selected for local implementation in the explicit
latest spec; exact remains unchanged. This initial selection preceded the integrated ROOT17/independent closure recorded below.
Write/CAS, Namespace/engines and private-source binding are separate scopes.


2026-10-01 node OIDC C2 local source implementation and review closed: fixed PKCE,
management-body/file boundary, fresh directory admission, lifetime and revocation
checks. Root84 unique targeted tests (latest25OIDC) pass; strict TLS/loopback/UDS
remains compiled/listed, not executed. Native16+80 assertions/fullApp compile and
existing operator path propagation have independent closure. No real SSO or
two-node offboarding completion claim. H1 durable receiver root13 and later
caller14 tests pass; H2 snapshot/restore public cut is currently implementing.

2026-10-01 VEX04 integrated: explicit latest single-read/frozen actual-version audit and first-poll absolute deadline guard passed 17 root pure/Actor cases; independent P2 closure confirmed five exact source SHA. Strict TLS/UDS remain compiled/listed only, full workspace unpassed; no latest-state or field acceptance claim.

2026-10-01 VEX01 selected minimal implementation contract: explicit per-profile RFC1918/ULA exact address and fixed CA binding, current Authority credential version, source-only routing, historical cleanup. No global private permission or trusted Admin mis-import prevention; code and strict private TLS/runtime acceptance not yet completed. See 2026-10-01-vault-private-source.md.

2026-10-01 H2 local snapshot cut/restore receipt completed: final18 source SHA independently reviewed including checked canonicalUTF8 path; ROOT36 feature cases/51 unique with IPC regressions and4 actual offline CLI/SQLite cases passed. Explicit input digest and pre-restore audit/policy cut are artifact evidence, not latest-state, fencing, HA or RPO/RTO proof. Invalid-name filesystem case/current full workspace remain unpassed.

2026-10-01 EXT06 selected minimal source contract before code: format20/kind10/rotate49 reserved for exact file-Keychain reference and execution-only Authority native preparation after actual started audit. One official SDK UI-Fail constant binding, native no-UI/query/status behavior still field deferred; no syscall cancellation guarantee. Code not implemented yet. See 2026-10-01-macos-keychain-source.md.

2026-10-01 VEX02 selected: one explicit execution-scoped AppRole login using existing KV kind/format20, finite observed service-token TTL, one read and bounded revoke-self. Login may consume SecretID/create remote identity; unknown login and failed cleanup are not retry-safe or success. Cleanup ownership is separate from ordinary HTTP effect. Partial transport bodies/unknown TTL and crash cleanup are not claimed. Implementation/local tests pending; see `2026-10-01-vault-approle-source.md`.

2026-10-01 current format20 local integration: VEX01 final7 SHA and43 focused tests passed; both confirmed private-source P1 findings independently CLOSED. EXT06 final29 SHA independently reviewed,67 unique worker tests and ROOT18 native-focused/40 Domain/230 full Vault/8 admin IPC/7 connector cases passed. Two stale format test fixtures fixed and independently reviewed; old formats remain rejected without migration. Current all-targets check/Clippy/fmt/mechanical/CLI dependency checks passed. Actual Keychain item API calls0; native item/strictTLS/UDS/TTY/full workspace/customer acceptance remains unpassed. Historical earlier format receipts/packages remain immutable.

2026-10-01 AUD06 explicit age convenience is locally implemented: --older-than-days selects the existing cutoff after per-call hiddenTTY/explicitstdin step-up; checked24h arithmetic and epoch refusal, no changed Authority/Store deletion set or new protocol/schema. Two new CLI cases RED→GREEN; actual CLI27 passed/6UnixListener.bind EPERM failed, existing6 real Actor/SQLite prune passed,3 real CLI local age-refusal paths passed. Independent spec-wording P2 CLOSED and source2SHA bound. Unattended automatic retention policy, archive ACK dependency guarantees, physical secure erase and current CLI→UDS remain unaccepted.

2026-10-01 SDK AppRole supplement selected before code: existing Vault KV descriptor declares static/AppRole capability union (exchange/lease/resolve/inject/revoke), ProviderDefined and cleanup-before-success for acquired temporary tokens. Static token path has no acquired-token obligation; other source contracts unchanged. No new kind/connector/schema/lifetime surface; root owns existing SDK source/contract test separately. Registry actual10; stale count9 fixture requires repair. Root local acceptance pending.

2026-10-01 AppRole local implementation accepted at currentformat20: one login/read/revoke, acquired-token cleanup ownership separated from ordinary business effect, typed fatal audit errors preserved. Independent nine-file source/evidence review found no confirmed P0/P1/P2. Root executor188 and SDK19 passed; broader targeted regression266 passed/one Unix socket bind EPERM failed. No full-workspace, provider ACL/TTL/revoke, strictTLS/UDS/TTY/native Keychain, HA or release acceptance is claimed. Evidence: `approle-integrated-final-acceptance.json`; earlier selection/pending records above are historical.

2026-10-01 remaining P10 implementation selected before code: mandatory delegated Linux cgroup-v2 payload, fixed memory.max/swap.max/oom.group, original-deadline guardian arming and cgroup.kill/drain before success. No weaker fallback or new protocol/config/dependency. Kernel charged-memory is not strict RSS or birth-time accounting; Darwin full guarantees and actual Linux kernel gates remain OPEN. See `2026-10-01-linux-plugin-cgroup.md`.

## Selected PKCS#11 approval signer (2026-10-01)

The fixed independent Ed25519 operator signer contract is recorded in `../superpowers/specs/2026-10-01-pkcs11-approval-signer.md`. Implementation, local contract tests, actual token support and physical HSM acceptance are separate gates. Profile identity is reviewed before PIN/device access; native modules retain operator G1 trust. No Broker/Agent private-key operation is added.

## Authorized automatic audit retention (2026-10-01)

| Feature | State | Release | Limits and evidence |
| --- | --- | --- | --- |
| AUD-06 unlocked automatic execution-group retention | Contract Tested | — | `audit retention set --days D` / `--disable` uses per-call Admin step-up and an independent sealed format21 row. Background maintenance preserves idle locking and faults closed on unknown completion. Independent 2P1+1P2 closed; root Actor/runtime/desktop and CLI parser tests passed. Real IPC/full workspace unpassed; no backup removal, physical erasure, all-event pruning or strict maximum age guarantee. |

The user explicitly authorized a step-up-set/revoked, sealed retention policy. Only the unlocked trusted Worker may automatically prune existing eligible complete execution groups; no stored proof, automatic unlock or Agent deletion operation. The spec `../superpowers/specs/2026-10-01-unlocked-audit-retention.md` freezes format21/Admin50-51 before implementation. Local and field acceptance remain pending; physical erasure, old backup removal and strict real-world maximum retention are not promised.

2026-10-01 selected PKCS#11 signer local closure: exact fixed Ed25519 profile, normal cryptoki0.12.0 registry dependency, 17 focused local contracts, workspace all-targets/Clippy/fmt pass. Independent review closed both original P1 deadline-cleanup and final-cancellation findings, with no confirmed new P1/P2 in the mechanical supplement. At this snapshot, device, nonexportability, driver behavior and operator controlling TTY acceptance were unexecuted; local process/injected cases do not close physical HSM claims. Evidence: `../../../evidence/hsm-selected-local-final.json`.

2026-10-02 dependency follow-up: cryptoki is now pinned to 0.12.1 to close RUSTSEC-2026-0286, without an advisory exception or unrelated dependency updates. Actual SoftHSM/controlling-TTY/Broker acceptance was repeated successfully on the patch. Physical HSM/vendor-driver claims remain open; see [current local evidence](../evidence/local-capabilities-2026-10-02.json).

2026-10-01 authorized automatic retention local closure: format21 sealed policy and Admin50/51 are implemented. Every set/revoke needs step-up; unlocked background maintenance holds the lifecycle owner and preserves the original idle lock. Unknown completion synchronously closes admission and revokes sessions before releasing ownership. Desktop resume verifies the retention seal, and SET uses the original Admin deadline. Independent review closed all original 2P1+1P2 findings; root Broker6/Vault4/Desktop2 targeted sets and CLI5 entry checks passed (sets overlap). Full workspace remains unpassed; physical erasure, backup deletion and maximum real-world retention are not claimed. Evidence: `../../../evidence/retention-exact3-root-local-final.json`.

2026-10-02 current local acceptance: full workspace 1032 passed, 0 failed,
1 performance test ignored; audit delivery28, archive23 and controlplane86 passed.
The previous permission/startup failures are historical, not current results.
Docker manual DR passed with measured recovery and owned-resource cleanup;
required PR CI and physical/customer environments remain separate gates.

2026-10-02 native/PKCS11 acceptance: the isolated native App completed the frozen
file policy/approval flow through a real Broker and test TLS response (HTTP200,
one effect, replay denied). Registered Action limits now decode from the actual
nested wire metadata. SoftHSM2.6 exercised the production PKCS11 signer and real
controlling TTY, including wrong PIN rejection and verified grant execution.
These results close the local software-token and bounded native-click gates;
physical HSM and customer IdP/SCIM/cloud/SIEM/WORM remain unaccepted.

2026-10-02 EXT06 native source acceptance: a disposable file-Keychain item with
an explicit trusted test executable passed actual Broker/TLS use, reflected-value
sealing, locked-Keychain refusal with no dialog or additional upstream effect,
and full Keychain/process/artifact cleanup. `scripts/test-keychain-live.py` is
included in macOS CI. Customer item ACLs and service identities remain separate.
