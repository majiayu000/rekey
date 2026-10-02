# Docker replication and automatic container failover

Implementation contract frozen before code. Extends BAK-07/ENT-04 beyond the
manual drill. Scope: one trusted Docker daemon/host, two dedicated non-root
containers, separate volumes and one external operator controller. Three new
files: this contract, controller, tests; reuse the existing image with production
rekeyd/rekey and existing encrypted backup/step-up APIs. No consensus service,
public proxy, database/IPC changes, cloud account or physical-host HA claim.

`rekey-docker-ha.py --directory DIR create --image IMAGE --password-stdin`
creates a fresh cluster and vault, starts the primary locked, returns the normal
private initialization output for recovery-key custody, and durably records
owned immutable container IDs/volume names/image digest. No existing vault is
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
in the single atomic cluster.json only after the new Broker is unlocked; old
sessions remain invalid, fresh sessions require existing
step-up. Routing means the published immutable active container ID for a local
docker-exec CLI client; it does not silently retry or reroute in-flight effects.
Prepare a fresh spare and continue replication after successful promotion,
allowing repeated failover. Original failed volumes remain quarantined until
explicit destroy; no automatic deletion of the only final committed state.

`status` reads public phase/active/replica data; `destroy` removes only the exact
cluster-labelled containers/network/volumes created by this tool. SIGINT/TERM
stop supervision without deleting persistent nodes/data. Errors disclose fixed
operation context/exit status, never raw child stderr or proof. No auto-unlock
on controller restart until the operator supplies the proof again. A detected
locked primary remains locked and the run exits.

Tests cover duplicate controller refusal, successful/failed replica publication,
daemon query failure versus absent/stopped primary, refused unowned targets,
promotion ordering and failure before publication. Docker tests use synthetic
secrets, real Broker/CLI, repeated new recovery points, and revocation AFTER the
last replica then SIGKILL: restored state must retain that revocation. Verify
fresh sessions, old-session rejection, repeat failover and owned cleanup.
