# Docker primary/standby recovery reference

Selected for issue #60 after the user authorized a disposable Docker environment.
This is a fixed manual drill, scoped to one trusted external Docker daemon and
two unprivileged Linux containers. It does not establish physical-host HA,
independent power domains, automatic failover, continuous replication or an SLA.

`scripts/rekey-docker-dr-drill.py --image IMAGE --output DIR` owns uniquely named
containers, volumes and one internal network. Nodes have separate vault volumes,
no Docker socket, no host network/PID namespace or host directory mounts, no
capabilities, read-only root filesystems, and no restart policy. Only the host
controller can operate the daemon. The image is built from current sources with
`scripts/Dockerfile.dr`; the real CLI/authority and existing P1 TLS fixture are
used. The fixture's local CA/transport is explicitly test-only.

The primary is initialized with a generated synthetic proof, credential and
signed policy, and executes an action. A completed encrypted backup is retained;
one further acknowledged credential write is deliberately excluded from it.
Disconnecting the primary from the internal network leaves its local authority
alive. Promotion must refuse while the old immutable container ID still exists,
including if merely stopped. Fence through `docker rm --force ID` outside the
nodes, then a successful daemon list must prove the ID absent. Failed daemon
queries never count as absence. Attempting to start the deleted ID must fail.
This exclusion holds only while trusted Docker administrators do not recreate a
node over the old state volume; administrators and daemon/kernel compromise are
outside the reference boundary.

Only after this fence may the backup be copied and restored into the other
empty volume. Compare actual backup digest, vault identity and restore cut.
Unlock the restored authority, confirm retained and lost credential IDs, reject
the old capability, and step-up issue a fresh capability for the signed policy's
principal. The first successful real CLI/UDS/TLS business response is recovery
completion. Agent routing here is the controller selecting the standby's local
socket; there is no new public proxy or shared live database.

One host monotonic clock measures the interval from starting the network fault
through refusal, fence, transfer, restore, unlock, freshness checks, new issuance
and first successful response. RPO records the actual acknowledged source write
missing from the restored cut, its audit sequence, and both the observed ACK gap
and conservative commit-gap bounds between the last retained and lost synthetic
credential writes (each commit falls inside its measured call interval). These
are measured observations for this write workload, not elapsed time inferred
from sequence numbers or `BackupReceipt.created_at_ms`, nor a universal RPO SLA.

Proofs and capabilities use stdin; generated credentials/signing keys stay in
owner-private temporary files or memory. No raw child output/error, proof or
token is published in the report. Command failures preserve a nonzero result;
missing fence/restore evidence, refusal failure, failed execution, and uncertain
cleanup cannot report success. SIGINT/SIGTERM perform owned-resource cleanup.
An exclusive private output directory receives source/image identity, timings,
public IDs and individual outcomes. All owned containers, volumes and network
must be removed before `pass: true` is published. This supplements the existing
artifact-only DR entry; its `--require-field` failure contract is unchanged.

Tests cover daemon failure versus absence, a running/stopped primary refusal,
immutable-ID targeting and failure before restore. Actual Docker execution is
required for the topology, fencing, restoration, measurements and cleanup claims.
