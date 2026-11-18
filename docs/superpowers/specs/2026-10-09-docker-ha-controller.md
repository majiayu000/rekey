# Docker replication and automatic container failover

User-selected scope on 2026-10-09: implement Docker HA separately from the personal desktop changes in PR #61. Development base: PR #74 (`fa734a5`), vault27/policy8. This is an isolated operator experiment, not a published release or multi-host guarantee.

Implementation contract frozen before adaptation. Extends BAK-07/ENT-04 beyond the
manual drill. Scope: one trusted Docker daemon/host, two dedicated non-root
containers, separate volumes and one external operator controller. Three new
files: this contract, controller, tests; wire the contracts into existing CI and reuse the existing image with production
rekeyd/rekey and existing encrypted backup/step-up APIs. No consensus service,
public proxy, database/IPC changes, cloud account or physical-host HA claim.

`rekey-docker-ha.py --directory DIR create --image IMAGE --password-stdin`
creates a fresh cluster and vault, starts the primary locked, returns the normal
private initialization output for recovery-key custody, and durably records
owned immutable container IDs/volume names/image digest. That output is written
to stdout as soon as `rekeyd init` succeeds, before the Broker starts; if a later
step fails, the error states that the output was already delivered and that the
operator keeps it, runs `destroy` and creates a new cluster. No existing vault is
overwritten. Nodes run UID10001, read-only root, no capabilities/Docker socket,
no restart policy, unique volumes and network. `run --interval-seconds N
--password-stdin` takes one explicit proof, retains it only in process memory
for that foreground operator session and supplies each existing step-up via
stdin. No password file/environment/argv/log, background login or durable unlock
authority. Controller exit releases its proof; Python memory is not claimed
zeroizable. Operator lock ends supervision rather than automatically unlocking.

Each cycle creates a fresh encrypted online backup through the real Worker,
transfers it to the standby, verifies its SHA and fsyncs before publishing a
receipt/status. It retains the latest completed replica, not an unbounded log.
Replication failure stops supervision; it is not evidence of primary failure.
A successful daemon query plus failure of the bounded primary health call can
trigger failover. Daemon errors fail closed. Host-private directory flock limits
one controller. Only recorded containers bearing the exact cluster label can
be fenced/deleted. Stopped is not fenced: remove the immutable ID and verify
absence with a successful full daemon query before any standby activation.

Asynchronous snapshots can omit recent revocations and approval replay state.
Therefore automatic activation MUST NOT restore an older periodic snapshot.
After fencing, use a short-lived networkless helper to copy the entire quiescent
vault directory (including SQLite WAL; exclude runtime sockets and broker lock)
from the retained old volume read-only into the empty standby state directory.
The destination files and directory must be synced before Broker startup.
The real Authority performs crash recovery, integrity checks and lease-journal
reconciliation at unlock. No manual SQLite edits, replay of business requests,
regeneration of policy, or copying a live database. If source volume is missing,
copy/unlock/integrity fails or recovery is uncertain, stop without publishing a
new active route; snapshots remain available for an explicit operator restore.
SQLite's WAL is part of the committed state, per its [WAL contract](https://www.sqlite.org/wal.html).

Persist phase=fencing before removal. Interrupted/failed promotion is never
blindly resumed or automatically retried. Publish phase=ready with the new primary
in the single atomic cluster.json only after the new Broker is unlocked; that
write carries an empty standby, so no persisted state names the promoted node as
its own standby. Old
sessions remain invalid, fresh desktop management sessions require existing
step-up. Routing means the published immutable active container ID for a local
docker-exec CLI client; it does not silently retry or reroute in-flight effects.
Prepare a fresh spare and continue replication after successful promotion,
allowing repeated failover. A spare failure stops supervision but leaves the
ready primary published; the next `run` prepares the spare before replicating.
A failed primary with no standby is never fenced. Original failed volumes remain quarantined until
explicit destroy; no automatic deletion of the only final committed state.

`status` reads public phase/active/replica data; `destroy` removes only the exact
cluster-labelled containers/network/volumes created by this tool. SIGINT/TERM
stop supervision without deleting persistent nodes/data. Every Docker invocation
carries a fixed operation label; errors disclose only that label and the exit
status or timeout, never raw child stderr, arguments or proof. A second
controller on the same directory is refused with a fixed message. No auto-unlock
on controller restart until the operator supplies the proof again. A detected
locked primary remains locked and the run exits.

Docker-free contracts in the default CI gate cover duplicate controller refusal
while read-only status works, successful/failed replica publication (digest
mismatch never saves or publishes), daemon query failure versus absent/stopped
primary, refused unowned targets, promotion ordering, unlock/status failure after
fencing, ready publication before spare preparation, spare failure, early
recovery output and operation-labelled errors. Docker tests use synthetic
secrets, real Broker/CLI, repeated new recovery points, and revocation AFTER the
last replica then SIGKILL: restored state must retain that revocation. Verify
fresh desktop management sessions, old-session rejection, repeat failover and owned cleanup.

## Software acceptance on the historical `fa734a5` base

Historical record: this drill ran on the PR #74 product base `fa734a5` and has
not been rerun on the current head, so it does not establish current-head behavior.
Image `rekey-ha-acceptance:20261009-fa734a5` was built from PR #74 product code,
image config digest `sha256:b85ebaf46b7b6915a41a7824912fce4b9d20ae1c2118246ca5d174366a43e31c`.
Eight controller contracts and real disposable Docker acceptance pass: encrypted
replicas advance; writes and revocation after the final replica survive two
fenced failovers; the old desktop session is rejected and a fresh one works;
exclusive supervision and read-only status work; termination preserves nodes;
all owned resources are subsequently cleaned. The initial test used an obsolete
CLI flag on desktop-login; the harness was corrected and the complete drill rerun.
This establishes one trusted-host software behavior only. No installed App,
real vault, multi-host consensus, provider/hardware or public release acceptance.
The 2026-11-17 ordering change (ready before spare, labelled errors, early
recovery output) postdates this drill; the live `--image` drill was rerun on the
current head (next section).

<a id="software-acceptance-on-the-current-integration-base"></a>
## Software acceptance on the 2026-11-17 design-completion head

On 2026-11-17 the live drill ran against `5c249ed8` (branch
`design/completion-20261117`, including the ordering change above). The image
was built from `git archive 5c249ed8` with `scripts/Dockerfile.dr`, compiling
release `rekey`, `rekeyd` and the policy fixture from that source (image ID
`sha256:07480effd05a0dc41f8790e56af2c9c0035c0a87f5ec2b43414d15db9e9990c9`,
linux/arm64). `python3 scripts/test-docker-ha.py --image <tag>` exited 0: the 18
controller unit tests passed and all five live checks passed (encrypted replicas
advance; writes and revocation after the last replica survive fenced failover;
second failover and fresh spare; exclusive controller with readable status and
termination preserving nodes; owned resource cleanup). Afterwards no container,
volume or network labelled `rekey.ha.cluster` remained and the image was removed.
The scope limits of the historical record apply unchanged: one trusted host
only; no installed App, real vault, multi-host consensus, provider/hardware or
public release acceptance. Receipt:
[design completion evidence](../../evidence/2026-11-17-design-completion.md).

Reproduce with `docker build -f scripts/Dockerfile.dr -t rekey-ha-acceptance .`
and `python3 scripts/test-docker-ha.py --image rekey-ha-acceptance`.
