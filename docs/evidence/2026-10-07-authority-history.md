# Authenticated usage history and Authority queue measurement

This is a diagnostic follow-up for KEY-03 on the 0.4 Connection branch in PR #68.
The production runtime measured is `7085c96d796b695bf61a17380d4ec27a736baa15`.
The benchmark additions do not change admission, storage, signing or settlement
behavior. The 0.3 format freeze and deferred device acceptance remain unchanged.

## Method

Run the two opt-in tests in `crates/rekey-vault/src/store/usage/history_benchmark.rs`:

```sh
cargo test --locked -p rekey-vault --lib history_benchmark -- --ignored --nocapture --test-threads=1
```

Both tests use 1,000, 10,000 and 100,000 authenticated history rows spanning four
instance slugs and 30 UTC days. One row in every 4,096 is initially pending.
Fixture creation is outside timing. The store test calls the exact authenticated
SQLite read, admission and settlement methods. The Authority test opens a real
worker and exercises its command queue, password unlock, usage reads, durable
admission and audit, settlement, duplicate settlement and password-proven backup.
Unlock uses the production Argon2 parameters: 65,536 KiB, three iterations, four
lanes. The Authority test also queues `AuthorityHandle::status()` behind each
admission and measures its idle and contended latency. This diagnostic uses
`refresh_activity = false`; it does not call `admin_status()` or exercise the
authenticated Broker admin IPC operation.

Each operation has five samples. Recovery unlock is a separate single observation.
Assertions verify conservative recovery of every pending row, five newly charged
requests and 35 output tokens, settlement idempotency, a written backup, and
authenticated reopening with all `history + 5` rows settled. These are production
store/Authority paths with synthetic inputs; they exclude Broker IPC and providers.

## Observations

The cloud Linux x86-64 run used Rust 1.97.0 and the debug test profile. Both tests
passed; elapsed time was 474.89 seconds. Medians below are milliseconds.

| History rows | Store authenticated read | Store admission | Store settlement | Authority admission | Authority settlement | Authority status queued with admission |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 49.70 | 50.27 | 50.49 | 32.87 | 25.36 | 32.87 |
| 10,000 | 324.82 | 317.52 | 485.67 | 325.62 | 308.80 | 326.77 |
| 100,000 | 3,062.64 | 4,012.85 | 3,368.46 | 3,583.14 | 3,186.73 | 3,583.43 |

| History rows | Idle Authority status | Authority usage read | Backup | Steady password unlock | Recovery password unlock (one observation) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 0.21 | 25.56 | 4,525.87 | 4,117.74 | 4,778.40 |
| 10,000 | 0.39 | 317.18 | 5,361.01 | 5,039.48 | 6,528.03 |
| 100,000 | 0.33 | 3,198.53 | 12,289.90 | 7,712.22 | 6,450.02 |

The history growth is visible through the actual Authority queue as well as the
store methods: a normally sub-millisecond status request waits behind the
authenticated admission operation. This supports prioritizing the existing
whole-history hot path. An index or unauthenticated totals cache would not replace
the current integrity proof, and this measurement introduces neither.

See [the JSON receipt](2026-10-07-authority-history.json) for each minimum, median,
maximum, RSS observation and the benchmark source fingerprint. End-of-size RSS
in the Authority test was 141,732 / 156,116 / 331,060 KiB; these values include
allocator retention from the preceding store test and earlier sizes. Peak RSS
is cumulative. They are not isolated per-operation memory bounds.

The collected JSON field names `admin_status` and `admin_status_during_admission`
refer to the `status()` diagnostic above. They do not name the distinct
`admin_status()` method; the historical measurement keys are retained unchanged.

Shared cloud host load, debug code generation, and the small sample count limit
absolute performance conclusions. Do not compare these milliseconds with the
historical release-profile measurements as an optimization result. No native
application, macOS device, external Codex, Linux container G2 reference-boundary,
L1 upgrade or release-readiness claim follows from these tests.

## Phase A Stage Attribution (2026-10-14, `9537cf2`, Darwin arm64)

Test-only stage attribution (`#[cfg(test)]`), store-level `profile_usage` timing,
and macOS `proc_pid_rusage` / `getrusage` RSS sampling were added in
`crates/rekey-vault/src/store/usage/history_benchmark.rs` without changing any
production runtime behavior, schema, or cryptographic format. Both `--release`
(36.27s vs 35.27s pre-attribution baseline) and `debug` (238.64s vs 292.33s
pre-attribution baseline) runs completed with 2 passed and 0 failed on Darwin
arm64 (`rustc 1.95.0`). See
[the stage-attributed JSON receipt](2026-10-14-authority-history-attribution.json).

### Release Profile (`--release`, `debug_assertions = false`) Medians (ms)

| History rows | Store read | Store `profile_usage` | Store admission | Store settlement | Authority read | Authority admission | Authority settlement | Contended `status()` |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 2.27 | 2.27 | 2.88 | 2.73 | 1.86 | 2.40 | 2.33 | 2.41 |
| 10,000 | 19.78 | 20.81 | 24.60 | 24.89 | 20.38 | 24.33 | 24.39 | 24.35 |
| 100,000 | 200.72 | 198.37 | 232.60 | 233.70 | 206.90 | 239.84 | 243.51 | 239.87 |

### Stage Breakdown at 100,000 Rows (`authority_started`)

| Stage | `--release` median (ms) | `--release` share | `debug` median (ms) | `debug` share |
| :--- | ---: | ---: | ---: | ---: |
| `context_parse_us` (`100,004` JSON decodes) | 104.47 | 44.56% | 1,359.47 | 80.77% |
| `sql_decode_us` (full-table `SELECT` + `88.0 MiB` alloc) | 54.42 | 23.21% | 171.95 | 10.22% |
| `canonical_digest_us` (read SHA-256 over all rows) | 37.49 | 15.99% | 74.82 | 4.44% |
| `new_digest_us` (write SHA-256 over all rows) | 37.25 | 15.89% | 74.90 | 4.45% |
| `audit_commit_us` (SQLite write + `commit_audited`) | 0.54 | 0.23% | 0.55 | 0.03% |
| `budget_totals_us` (in-memory linear fold) | 0.25 | 0.11% | 1.34 | 0.08% |
| `new_seal_us` + `aead_verify_us` (AES-256-GCM) | 0.02 | 0.01% | 0.12 | 0.01% |
| **Attributed stage sum (`stage_total_us`, sum of per-stage medians)** | **234.43** | **100.00%** | **1,683.15** | **100.00%** |
| **Total `authority_started` wall-clock** | **239.84** | — | **1,696.79** | — |

`stage_total_us` adds each stage's median across the five samples, so it need not equal any single run. The wall-clock total also includes the benchmark's own O(N) metric passes (row widths and retained capacity) that run outside the stage timers; that instrumentation, plus untimed glue, accounts for the gap between the stage sum and the wall-clock row. Instrumented source: `48861ed` on the production base `9537cf2`.

Per-operation structural and allocation metrics at `100,000` rows (`authority_started`):
- `total_rows`: `100,004`
- `rows_scanned`: `500,021` (`5N + 1` across `load`, `verify`, `context_parse`, `totals`, and `next_state`)
- `contexts_parsed`: `100,004` (`60,002,400` bytes of `context_json` parsed per call)
- `retained_total_bytes`: `92,269,357` bytes (`88.00 MiB` of capacity retained by the loaded rows, not total allocation; transient buffers freed during decode are excluded: `25,165,824` bytes `Vec<UsageRecord>` + `67,103,533` bytes heap strings)
- End-of-benchmark `process_rss_kib` / `process_peak_rss_kib`: `906,432 KiB` (`885.19 MiB` in `--release`), `664,544` / `690,608 KiB` (in `debug`).

