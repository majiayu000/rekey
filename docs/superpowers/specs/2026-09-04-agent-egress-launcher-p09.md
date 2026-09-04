# P-09 Agent Egress Launcher (`linux-netns-v1`)

> Status: implemented locally; Linux black-box and exact-head CI pending
>
> Date: 2026-09-04
>
> Tracking: [Issue #38](https://github.com/majiayu000/rekey/issues/38)
>
> Depends on: Credential Authority v2 Foundation §12.1 (disjoint Agent
> endpoint), existing `rekeyd serve --agent-runtime-dir`

## Objective

P-09 makes deny-by-default Agent egress a product command, not only a Docker
attack recipe. An operator starts one Agent argv through `rekey agent-run`.
That child has no IP/TCP/UDP/DNS path to the host or public network, cannot
see the vault state directory or Admin socket, and can still use the disjoint
`agent.sock` data plane.

This slice does not change default G1, does not replace
`scripts/p1-linux-g2.sh`, and does not claim kernel, Docker daemon, macOS, or
general G2 isolation.

## Current Evidence

| Area | Evidence | Implication |
| --- | --- | --- |
| Entrypoints | `rekey` delegates `init`/`serve`/`restore` to `rekeyd`; no agent launcher exists | New command must delegate the same way so `rekey-cli` stays IPC-only |
| Core models | Domain crate is IO-free; no launch plan type | Path/argv invariants belong in `rekey-domain` |
| Runtime/lifecycle | `BrokerRuntime` owns sockets, sessions, VRK; G2 is operator-composed Docker | Launcher is a sibling `rekeyd` subcommand, not a new owner of credentials |
| Adapters/backends | `scripts/p1-linux-g2.sh` proves container G2; `serve --agent-runtime-dir` already requires a disjoint Agent endpoint | Reuse that endpoint contract; do not make Docker the daily launcher |
| Generated/config | No launch policy in the vault | P0 is flags-only; no schema bump |
| Errors/diagnostics | Stable IPC codes; CLI never links broker | New codes: `UNSUPPORTED_PLATFORM`, `LAUNCHER_UNAVAILABLE`; plan errors are `INVALID_INPUT` |
| Tests/headless | Linux G2 is a Docker gate; `macos_sandbox` in the threat model is not implemented | P0 tests are plan unit tests + macOS unsupported + Linux bubblewrap black-box |
| Open issues/PRs | [#38](https://github.com/majiayu000/rekey/issues/38); no open PR | One child issue, one squash PR |

## Reference Models Considered

| Reference | Borrow | Do not copy | Source |
| --- | --- | --- | --- |
| bubblewrap | Closed unshare-user/net/pid, die-with-parent, read-only root bind, tmpfs overlays | Flag surface, D-Bus proxy, `--share-net`, file forwarding, operator-supplied argv to bwrap | `bwrap(1)` |
| systemd `PrivateNetwork=` | Deny-by-default network as a property of the launched task | Requiring systemd as the only launcher; shipping a new unit generator in this slice | systemd.exec(5) |
| `scripts/p1-linux-g2.sh` | Attack assertions: no state/Admin/Docker socket, no direct egress, Unix data plane still works | Docker Engine as a runtime dependency for everyday `agent-run` | in-tree harness |
| gVisor / Firecracker | — | MicroVM/runtime stacks, extra attack surface, product-scale isolation claims | — |
| Chromium sandbox | — | Multi-layer zygote, global policy language, macOS seatbelt in P0 | — |

## Chosen Shape

State ownership: `rekeyd agent-run` owns one bubblewrap child and waits for it.
`BrokerRuntime` remains the only owner of sockets, sessions, decrypted
credentials, and remote effects. The child never receives a vault secret.

```text
product/app
  - rekey agent-run → exec rekeyd agent-run
  - rekeyd serve --agent-runtime-dir remains the endpoint owner

core/domain
  - linux-netns-v1 plan: absolute disjoint paths, argv, capability charset

runtime/application
  - rekeyd agent-run: validate, verify Agent peer, spawn, reap, forward exit

adapters/backends
  - Linux: /usr/bin/bwrap or /bin/bwrap with a compile-time flag list
  - macOS/other: UNSUPPORTED_PLATFORM, no spawn

plugins/components
  - none (no connector, WASM, or download path)

testing/headless
  - plan/flag contract tests without bwrap
  - Linux black-box with real rekey/rekeyd and system bwrap
```

## 1. Goal

Add one closed Linux profile `linux-netns-v1`:

```text
rekey --state-dir STATE --agent-socket AGENT_SOCK agent-run [--capability-stdin] -- COMMAND [ARGS...]
```

`COMMAND` must be an absolute, non-symlink executable. The child can use
`AGENT_SOCK`. It cannot open the vault, Admin socket, or a public TCP/UDP/DNS
path.

## 2. Scope and invariants

- No vault schema, Action, policy, or Agent wire change.
- No secret injection into argv, environment of `rekey`/`rekeyd` as flags, logs,
  or audit rows. Optional capability uses `--capability-stdin` and child env
  `REKEY_CAPABILITY` only.
- Default G1 `state/runtime/agent.sock` is rejected: the Agent socket must be
  disjoint from `--state-dir` (same rule as `serve --agent-runtime-dir`).
- CLI does not link `rekey-broker`, rusqlite, aes-gcm, argon2, or reqwest.
- Existing Docker G2 harness stays the adversarial container/namespace proof.
- This slice does not create OS users, cgroups, Landlock, seccomp, or nftables.

## 3. Closed launch profile

Profile name: `linux-netns-v1`.

Required inputs:

- `--state-dir`: existing directory, not a symlink, mode/owner already a
  Broker state tree the operator intends to hide.
- `--agent-socket`: existing Unix socket, not a symlink, not a descendant of
  `state-dir` and not an ancestor overlap after lexical `..` rejection and
  `canonicalize`.
- `COMMAND...`: non-empty; `COMMAND[0]` is an absolute path with no `.` or `..`
  components; remaining args are non-empty.

Forbidden:

- relative `COMMAND[0]`; empty args; exec of the selected `bwrap` binary;
- operator bwrap flags; `--share-net`; extra hide paths; env forwarding;
- `--capability` as an argv value.

Optional `--capability-stdin`: one line, 1..=128 visible ASCII bytes
(`0x21..=0x7e`), no space. Stored only in the child environment as
`REKEY_CAPABILITY`. It must not appear in the bwrap argv vector.

Child environment is exactly:

| Name | Value |
| --- | --- |
| `PATH` | `/usr/bin:/bin` |
| `HOME` | `/tmp` |
| `LANG` | `C` |
| `REKEY_CAPABILITY` | present only with `--capability-stdin` |

Parent env, `REKEY_PASSWORD`, and any other name are dropped.

## 4. Linux adapter (bubblewrap)

`rekeyd` locates `bwrap` only at `/usr/bin/bwrap` then `/bin/bwrap`. No `PATH`
search and no `BWRAP` environment override.

Compile-time argv, in order:

```text
bwrap
  --die-with-parent
  --new-session
  --unshare-user --uid <euid> --gid <egid>
  --unshare-net
  --unshare-pid
  --ro-bind / /
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --tmpfs <canonical-state-dir>
  [--bind /dev/null /var/run/docker.sock]   # only if that path exists as a socket
  [--bind /dev/null /run/docker.sock]       # same, and not the Agent socket
  --chdir /tmp
  --
  COMMAND ARGS...
```

`--unshare-net` gives a network namespace with no veth and no default route.
Loopback is not configured. AF_UNIX is a mount-namespace path and still works
for the disjoint Agent socket.

`--unshare-pid` plus `--proc /proc` hides host PIDs so the child cannot open
host `/proc/<pid>/ns/net` as an egress escape.

`--tmpfs <state-dir>` hides vault DB, Admin socket, and recovery material.
`--bind /dev/null` on well-known Docker sockets is defense in depth, not a
claim that every container runtime socket is covered.

Missing `bwrap` is `LAUNCHER_UNAVAILABLE`. Spawn failure is fail-closed.

The launcher waits, reaps, and forwards the child exit status. A signal death
without a status code maps to exit 5. `PR_SET_PDEATHSIG` is supplied by
`--die-with-parent`.

Before spawn, `rekeyd` connects to `--agent-socket`, checks `SO_PEERCRED` /
`getpeereid`, and requires the peer UID to equal the state-directory owner.
Pathname ownership is not enough.

## 5. Platform behavior

| Platform | Behavior |
| --- | --- |
| Linux with bwrap | `linux-netns-v1` |
| Linux without bwrap | `LAUNCHER_UNAVAILABLE` (exit 5) |
| macOS | `UNSUPPORTED_PLATFORM` (exit 2) after plan validation |
| Windows | out of scope (P0 already unsupported) |

macOS seatbelt remains a later slice. This command must not silently run the
argv on the host.

## 6. Boundary contracts

| Contract | Owner | Allowed dependencies | Forbidden dependencies | Tests |
| --- | --- | --- | --- | --- |
| State ownership | `rekeyd agent-run` owns the child; Broker owns sockets/secrets | domain plan, libc peer, bwrap | vault/crypto in the launcher path; child owning VRK | peer mismatch; CLI `cargo tree` |
| Lifecycle | validate → peer check → spawn → wait → forward exit | std process | running inside `BrokerRuntime`; canceling in-flight Actions | die-with-parent via script kill |
| Events/actions | CLI flags only | clap | Agent IPC launch message; durable launch policy | clap `--` required |
| Effects/IO | sandbox adapter | filesystem metadata, Unix connect, exec bwrap | HTTP, SQLite, env credential | no reqwest in CLI |
| Errors | `INVALID_INPUT`, `UNSUPPORTED_PLATFORM`, `LAUNCHER_UNAVAILABLE`, `IPC_UNAVAILABLE` | BrokerError/CliError | leaking capability or paths in `code()` | unit codes |
| Config | compile-time bwrap list + flags | — | operator bwrap, schema, download | argv snapshot test |
| Observability | none in P0 (P-08) | — | metrics/labels with capability | canary scans in script |
| Compatibility | new command only | — | G1 default socket; v1; MITM | overlap rejection |

## 7. Source of truth and migration debt

| Contract | Current source of truth | Consumers | Duplicates or forks | Action |
| --- | --- | --- | --- | --- |
| Disjoint Agent endpoint | Foundation §12.1 + `validate_agent_endpoint` | serve, this launcher | none intended | reuse the rule; do not add a second overlap definition in CLI |
| G2 container topology | `scripts/p1-linux-g2.sh` | security-gate `g2-linux` | threat-model row still names a missing `rekey-e2e` crate | keep Docker harness; P-09 is a native launcher, not that crate |
| Default topology | G1 in alpha-scope / truth matrix | public docs | none | do not retitle G1 as G2 |
| macOS isolation | threat-model `macos_sandbox` (unimplemented) | — | planned P1+ test name | P0 returns unsupported; do not fake a seatbelt |

No compatibility shim. There is no old launcher to migrate.

## 8. Failure semantics

- Overlap, relative argv, symlink socket/state/command, missing socket, empty
  capability, oversized/non-ASCII capability: `INVALID_INPUT` / usage, no spawn.
- Agent peer UID ≠ state owner: `IPC_UNAVAILABLE`, no spawn.
- Direct TCP/UDP/DNS from the child to a public address must fail.
- Reading `$STATE/vault.sqlite3` or `$STATE/runtime/admin.sock` from the child
  must fail.
- Parent `REKEY_PASSWORD` must be absent from the child environment.
- Launch is not an Authority mutation and writes no audit row in this slice.

## 9. Explicit non-goals

- P-08 metrics/tracing.
- P-10 connector process/WASM isolation.
- Remaining P-07 providers.
- Transparent MITM, system CA, TCP passthrough, agent secret-read.
- Creating a dedicated Agent UID, Landlock, seccomp, nftables, or cgroup limits.
- Hiding `$HOME`, SSH keys, or the rest of the host filesystem.
- Claiming ptrace isolation against a same-UID host attacker (G1). Nested
  `/proc` only blocks the child from seeing host PIDs.
- Replacing or weakening `scripts/p1-linux-g2.sh`.
- Inclusion in `v2.0.0-alpha.1`.

## 10. P0/P1/P2 roadmap

| Priority | Work | Files/modules | Done when | Verification |
| --- | --- | --- | --- | --- |
| P0 | Closed `linux-netns-v1` launcher | `rekey-domain` sandbox plan; `rekey-broker` sandbox; `rekeyd`/`rekey` `agent-run`; `scripts/p9-linux-agent-run.sh`; security-gate Linux step | Child has no public IP path, cannot read state, can execute one fixed Action via disjoint UDS | `cargo test -p rekey-domain sandbox`; `cargo test -p rekey-broker sandbox`; macOS unsupported via `rekeyd agent-run`; `scripts/p9-linux-agent-run.sh` |
| P1 | Stronger hide set / dedicated UID docs / Landlock net if kernel supports it | later spec | Extra sockets hidden; operator runbook for `--agent-uid` | new spec + tests |
| P2 | macOS seatbelt profile | later spec | Explicit profile or still `UNSUPPORTED_PLATFORM` with no silent host exec | `macos_sandbox` when specified |

## 11. Completion criteria

This slice is complete only when:

1. `rekey`/`rekeyd agent-run` exist and CLI still satisfies
   `cargo tree -p rekey-cli -e normal` (no rusqlite/aes-gcm/argon2/reqwest/
   rekey-vault/rekey-broker).
2. Plan tests reject overlap, relative argv, and capability-in-argv.
3. macOS returns `UNSUPPORTED_PLATFORM` without executing `COMMAND` on the host.
4. Linux black-box with system bubblewrap proves: public TCP denied, state
   hidden, parent env canary absent, Unix connect to disjoint `agent.sock`
   works, one capability-authorized `rekey execute` succeeds through that
   socket, credential canary never appears in child output.
5. Public docs say Linux launcher, not general G2.
6. Exact-head CI includes the Linux script on Ubuntu.

## 12. Readiness language

The spec is complete enough to implement P0. After merge, the honest claim is:

- "Linux `agent-run` (`linux-netns-v1`) denies IP egress for one launched
  argv when bubblewrap is installed and the Agent endpoint is disjoint."

Not claimed:

- production-ready G2;
- equivalent to the Docker G2 harness;
- macOS isolation;
- kernel/Docker-daemon/host-root resistance.

## Open questions

None that block P0. P1 should decide whether a missing `bwrap` on a Linux
distribution that already runs `rekeyd serve` is documented as a hard
dependency or gains a native `clone` fallback.
