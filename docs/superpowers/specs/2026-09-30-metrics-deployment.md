# P-08 single-host Linux metrics deployment artifacts

Status: frozen minimum implementation contract, 2026-09-30. Extends the accepted
Node Exporter textfile slice and current local publisher. Four new implementation
files plus this specification, one existing generator change; no Rust/CLI/IPC
changes, dependency, wrapper daemon, Rekey listener or external installation.
Root owns docs/CI/package/full-suite gates. Worker owns only the existing service
generator, deployment rules/vectors/scrape example and their subprocess tests.

## Generation and scheduler

Extend scripts/rekey-service-unit.py with stdout-only modes:
`systemd-metrics-service --rekey ABS --state-dir ABS --run-as-user ADMIN` and
`systemd-metrics-timer` (no additional arguments). Reuse installed_path,
systemd_quote and non-root account validation. Preserve original launchd/systemd
daemon modes and 130s stop contract. No shell, output-file installer, real user
creation, enable/start or state mutation. Operators save the two outputs as
rekey-metrics.service and rekey-metrics.timer. Inapplicable options are errors.

Service runs the existing metrics --prometheus --textfile-dir command directly
as the trusted daemon/Admin user, supplementary group rekey-metrics,
UMask=0077, NoNewPrivileges=true, Type=oneshot. TimeoutStartSec=10s and
TimeoutStartFailureMode=kill bound its whole cgroup, with KillMode=control-group,
FinalKillSignal=SIGKILL and SendSIGKILL=yes. No Restart, RemainAfterExit, wrapper
loop or second cleanup. Type=oneshot RuntimeMaxSec is ineffective and is absent.
Require systemd >=246. Scheduling cannot guarantee hard realtime against
uninterruptible kernel IO. Timer uses OnBootSec/OnUnitActiveSec=30s, AccuracySec=1s,
RandomizedDelaySec=0 and the fixed Unit; no Persistent catch-up or concurrent
instance. Existing publication flock remains authoritative.

The deployment configuration uses fixed non-business directory
/var/lib/rekey-metrics and rekey.prom. Operator prepares Admin:rekey-metrics
0750 (or 2750), final file0640 and temporary0600, with no additional ACL grants.
Collector is a separate low-privilege UID in read-only rekey-metrics group; it
has no state/database/admin.sock access. Generator does not create/check groups
or prepare directories. Existing collector receives only its textfile directory
flag. No new collector listener/service is installed by Rekey artifacts.

## Prometheus rules and unknown state

Use fixed job rekey-node, complete-path file label, 15s scrape/evaluation example.
Record fixed-file mtime and age by job/instance; rekey:metrics_fresh has value1
only when up==1, node_textfile_scrape_error==0, mtime exists, 0<=age<=60,
node_timex_sync_status==1 and
abs(node_time_seconds-timestamp(node_time_seconds))<=5. Missing clock/sync or
file data, future mtime, stale file, target failure and parse error are unknown.
Sample timestamp comparison avoids interpreting time between scrapes as clock
drift. Host/Prometheus clock synchronization remains an operational prerequisite;
common erroneous clocks and trusted Admin tampering are not detected guarantees.
File age is successful publication age, not exact Broker sample age.

Request/error rate records use rate of existing counters over5m, and join the
fresh gate on job/instance, retaining channel labels. Unknown removes records;
no zero fill/clamp/fake quantiles or persistent counter guarantee. Fresh true
zeros remain zeros. Counter resets follow Prometheus semantics; missed events
are not fabricated. RekeyMetricsUnavailable alerts use up unless fresh; separate
absent(up{job="rekey-node"}) handles missing targets. No additional for delay;
the15s evaluation cadence still affects notification time. Static labels/messages
contain no credential/action/principal/request/token or user business path.

Provide deploy/prometheus/rekey.rules.yml, rekey.rules.test.yml, and
rekey.scrape.example.yml, plus scripts/test-metrics-deployment.py. Example endpoint
is configuration for an existing same-host collector; TLS/auth/network ACL must
be selected by the operator before deployment. No endpoint security claim comes
from Rekey having no listener. Fixed tool versions: Prometheus3.15.0 and
Node Exporter1.12.1; never float latest. CI downloads job-local official release
assets and validates the exact basename with same-release sha256sums.txt. Missing
checksum or mismatch fails; no global package installation.

## Checks and field boundary

Meaningful generator subprocess tests exercise minimal and inapplicable args,
quoting of installed paths and actual old/new mode contracts. Actual promtool
check rules/test rules/check config covers fresh,60/61s boundary,futuremtime,
stopped publishing while scraped,missing/stale,target down/absent,parseerrors,
clockmissing/unsynced/drift,counterreset,zero and unknown disappearance. Use the
official engine/vectors; no imitation evaluator. Linux systemd-analyze verify
checks generated units without installing or starting them. Missing tools are
explicit unavailable/nonzero, not silent skips or full-pass claims.

Reuse existing publisher tests for partial write/failure/atomic replacement,
permission/link/flock/canary. Full native Linux service timeout/cgroup termination,
scheduling, independent UID isolation, actual exporter parsing and Prometheus
network delivery need an isolated permitted runtime later. This macOS host lacks
promtool/systemd tools and disallows TCP/Unix listeners; compile/static generation
and official protocol review do not close these runtime or deployment claims.

Primary contracts: [systemd service](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml),
[timers](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.timer.xml),
[Node Exporter1.12.1 collector](https://github.com/prometheus/node_exporter/blob/v1.12.1/collector/textfile.go),
[Prometheus rule testing](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/),
[Prometheus3.15.0](https://github.com/prometheus/prometheus/releases/tag/v3.15.0),
[Node Exporter1.12.1](https://github.com/prometheus/node_exporter/releases/tag/v1.12.1).
