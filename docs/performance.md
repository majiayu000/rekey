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
- 120 Agent plus 8 Admin IPC connections held simultaneously. One additional
  connection on each socket must close instead of waiting without a bound.
- Four held execution permits for one session. A fifth permit must return
  `INVALID_CAPABILITY`, and a released slot must be reusable.
- Twelve 4 MiB response-sealing samples with p50/p95/p99/max latency and RSS.
- 500 durable audit commits with p50/p95/p99/max latency and commits per second.
- Repeated fixed-action execution, periodic lock/unlock, periodic backup, RSS
  samples, error rate, and durable started/terminal audit counts during soak.
- Backup while one remote effect is in flight, and shutdown while one admitted
  disconnected execution is in flight.

The report embeds the exact Git commit, OS, architecture, CPU, installed memory,
and `rustc -Vv`, plus all fixed data sizes. This keeps results attributable to
one environment instead of extrapolating between machines.

## Pass conditions

The run fails unless every saturated boundary rejects explicitly, every soak
request succeeds, execution-started and terminal audit counts are equal after
reopening SQLite, and the final-quarter RSS average is no more than 64 MiB above
the first-quarter average. Shutdown must drain the admitted execution. These are
correctness and boundedness gates; the recorded latency and throughput values
are baselines for detecting regressions, not product guarantees.

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
closeout evidence comes from the fixed `ubuntu-24.04` workflow runner.
