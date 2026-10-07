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
