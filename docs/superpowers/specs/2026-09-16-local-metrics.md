# P-08 local monitoring slice

Status: implemented and locally verified, 2026-09-16. This slice extends the v2 foundation without
changing its Admin/Agent or credential boundary.

## Contract

`rekey metrics` reads a typed JSON snapshot; `rekey metrics --prometheus`
prints Prometheus text exposition 0.0.4. Both use the existing owner-only
`admin.sock`, Admin message 37 (`METRICS`), empty JSON metadata and no body.
The reply is numeric JSON metadata and an empty body. No unlock proof is
required for this read. It works while locked and never contacts the Authority
worker, refreshes idle activity, decrypts a credential, or writes an audit row.
The Agent channel cannot obtain it. Malformed metadata/body is rejected using
the existing strict frame boundary. No HTTP listener, remote collector,
dependency, configuration option, or background scraping loop is added.

## Measurement semantics

Counters start at zero on broker startup and reset on restart. For each of the
two fixed channels (`admin`, `agent`), count complete frames entering dispatch,
finished dispatches, dispatch errors, cancelled dispatches, aggregate dispatch
duration in microseconds, and current dispatches in flight. Finished includes
cancellation. A guard records cancellation and duration even if shutdown drops
the dispatch future. Duration uses a monotonic clock and ends before response
write. Errors count all returned dispatch errors, including policy,
capability, validation and infrastructure failures, without error-code labels.
METRICS requests themselves are excluded from dispatch counters, even when
invalid. Partial/invalid frames never count as dispatched requests.

Separately count peer rejections, connection-capacity rejections and failed
frame reads. All EOF is excluded; truncated EOF is also excluded because
the shared codec classifies it as closed, by the same two fixed channels. Capacity
counts an accepted connection denied a request slot, whether or not the bounded
error reply succeeds; it is a saturation signal, not worker queue depth. Count
calls to `request_fault` as fault signals, **not** confirmed transitions to
Faulted. Fault shutdown may make the final snapshot unavailable.

Backup dispatches additionally use the same request/finished/error/cancelled/
duration/in-flight counters as a fixed `backup` operation. These measure IPC
backup results, not retained backup count, bytes, durability or restore health.

Active capabilities and executing capabilities are read directly from
SessionRegistry's existing expiry-aware active count and in-flight count. No
second registry or reconciliation is introduced. Individual atomics and session
locks are sampled separately; the snapshot is approximate under concurrency,
not a globally atomic accounting ledger. A cancelled dispatch may leave an
independently supervised execution running, so executing capability and dispatch
gauges have deliberately different meanings.

## Data and cardinality boundary

The DTO denies unknown fields and contains only unsigned integer values and
fixed nested objects. The CLI parses the typed DTO before rendering. Prometheus
names, HELP text and labels are compile-time strings, only channel=admin/agent
(backup has separate fixed metric names); no user, credential, principal, resource, action, request,
path, token, upstream, error message or arbitrary metadata enters the output.
Dispatch durations render as a Prometheus summary (count and sum, no quantiles).
JSON keeps integer microseconds, Prometheus uses seconds. There are no per-action
or per-credential traces added by this slice.

## Verification and remaining scope

Exercise locked snapshots, success and rejection deltas, session gauges,
Agent denial, malformed frames, backup failure and strict CLI rendering.
Unit tests cover cancelled guard accounting and fixed-label exposition.

P-08 remains partial: OpenTelemetry export, Authority worker queue depth,
persistent/remote metrics collection, latency histograms/quantiles, backup
inventory/size/restore freshness and a broader tracing contract are not provided.

Local evidence (2026-09-16): `cargo check --workspace`; two metrics IPC
integration tests; `cargo test -p rekey-broker -p rekey-cli metrics` covering
cancel accounting, idle-lock behavior, fixed exposition and strict CLI parsing.
The integration owner passed workspace tests and Clippy. A disposable real
`rekeyd`/`rekey` process smoke also proved locked JSON reads, consecutive reads
without self-counting, the expected status-request counter delta and fixed
Prometheus types. Local evidence is recorded under
`.git/codex/threads/rekey-remaining-20260916/metrics-smoke.log`.
