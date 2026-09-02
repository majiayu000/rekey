# Performance and soak baseline

Rekey's H-07 gate is a repeatable capacity and stability baseline, not a public
throughput SLO. It exercises real IPC, policy evaluation, envelope decryption,
SQLite audit commits, lock/unlock, backup, response sealing, and shutdown. The
upstream HTTP transport is deterministic so external network variance cannot
hide Broker regressions.

## Measured boundaries

The ignored `performance_and_soak_baseline` integration test records:

- Authority queue saturation from 512 simultaneous submissions against the
  production 128-entry queue, including accepted latency and explicit
  `AUTHORITY_BUSY` counts.
- The 128-connection Broker budget: 119 Agent plus 7 Admin request handlers
  held simultaneously, with one overload responder reserved inside each
  channel's 120/8 budget. Concurrent additional connections on both sockets
  must receive retryable `AUTHORITY_BUSY` instead of a silent close.
- Four held execution permits for one session. A fifth permit must return
  `INVALID_CAPABILITY`, and a released slot must be reusable.
- Twelve 4 MiB response-sealing samples with p50/p95/p99/max latency and RSS.
- 500 durable audit commits with p50/p95/p99/max latency and commits per second.
- Repeated fixed-action execution with the production 64 MiB Argon2 profile,
  periodic lock/unlock, periodic backup, current and high-water RSS, error rate,
  and exact durable started/terminal audit counts during soak.
- Backup while one remote effect is in flight, and shutdown while one admitted
  disconnected execution is in flight.

The report embeds the exact Git commit, OS, architecture, CPU, installed memory,
and `rustc -Vv`, plus all fixed data sizes. This keeps results attributable to
one environment instead of extrapolating between machines.

## Pass conditions

The run fails unless every saturated boundary rejects explicitly, every soak
request succeeds, and execution-started and terminal audit counts both match the
known execution total after reopening SQLite. Every terminal must be
`execution.finished`. The final-quarter RSS average may be no more than 64 MiB
above the first-quarter average, and shutdown must drain the admitted execution.
These are correctness and boundedness gates; the
recorded latency and throughput values
are not product guarantees. Values from GitHub-hosted runners are descriptive
unless their full hardware fingerprints match. The H-07 closeout comparison is
anchored to one recorded run on a fixed host.

Pull requests and pushes run a 60-second smoke. The weekly schedule and the H-07
closeout run use 1,800 seconds. GitHub Actions uploads the JSON report, complete
runner description, and `/usr/bin/time -v` output for every exact run.

Run the short baseline locally with:

```bash
REKEY_SOAK_SECONDS=30 \
REKEY_PERF_REPORT=target/performance-report.json \
cargo test --locked -p rekey-broker --test performance_baseline \
  performance_and_soak_baseline -- --ignored --exact --nocapture
```

Set `REKEY_SOAK_SECONDS` from 30 through 3600. Local results are diagnostic;
closeout evidence must identify one fixed host and must not be compared with a
GitHub-hosted run unless the full environment fingerprint matches.

## H-07 closeout result

The fixed-host 1,800-second closeout passed on 2026-09-02 at merge commit
`83da2233f73dbd996d9c23af0e12937840a41c03`: macOS 26.5.1 (Darwin 25.5.0),
Apple M3 Max, 128 GiB memory, Rust 1.95.0, aarch64. The checked-in
evidence is [`evidence/h07-performance-2026-09-02.json`](evidence/h07-performance-2026-09-02.json).
It is a normalized summary rather than a byte-for-byte copy of the raw report:
all benchmark result objects are preserved, the raw `uname -a`, `rustc -Vv`, and
decimal memory strings are replaced with explicit OS, architecture, CPU,
integer-memory, Rust release/host, and LLVM fields, and an `evidence` object adds
capture time plus process timing/RSS metadata. The local hostname, kernel build
string, and full Rust commit metadata are omitted. The raw report SHA-256 is
`ed25a01cdf563a291180796e194ebba2b4701ead3c7d538e453d5fa4ed8a7403`.

The run completed 63,798 soak executions with zero unexpected errors. Durable
audit counts reopened at exactly 63,812 started, terminal, and finished rows.
It exercised 29 lock/unlock cycles and 14 periodic backups; those soak backups
did not overlap executions. The separate backup-interference measurement in the
report covers one backup concurrent with one in-flight execution. Across 181 RSS
samples, the first-window average was 49,513 KiB and the last-window average was
47,308 KiB, with a sampled maximum of 93,536 KiB. Queue overload returned 384
explicit `AUTHORITY_BUSY` responses from 512 attempts; the total IPC boundary
held 128 connections and rejected both extra connections explicitly. Session
concurrency rejected the fifth permit and reused a released slot. Shutdown
drained one admitted execution.

PR [#18](https://github.com/majiayu000/rekey/pull/18) supplied the implementation.
Its exact head `9bddae2fda319bc6ce0b872496298933f5821a59` passed all nine security,
fuzz, and performance jobs before squash merge. The merge commit then passed
[security](https://github.com/majiayu000/rekey/actions/runs/33633015752),
[fuzz](https://github.com/majiayu000/rekey/actions/runs/33633015820), and
[performance](https://github.com/majiayu000/rekey/actions/runs/33633015821) again.
