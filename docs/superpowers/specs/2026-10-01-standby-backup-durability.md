# BAK-07/ENT-04 H1 completed standby artifact durability

Frozen before code, 2026-10-01. Accepted manual primary/standby DR, not automatic
HA. This independent smallest first slice strengthens existing backup-sync
receiver publication; snapshot-cut/restore evidence and genuine infrastructure
fencing/promotion remain separate pending work. No new registration/config,
commands/services/dependencies, live SQLite copying, decryption or auto-start.

Only scripts/rekey-backup-sync.py existing REMOTE receiver and
scripts/test-backup-sync.py are writer-owned. Root owns spec/tracker/package and
integration. Retain current exact completed source receipt/hash and fixed SSH/scp
argv, retry same immutable object only, current error/exit contract. Scheduler
only transports an existing completed backup, never unlocks/creates backup.

Receiver must verify fixed expected receipt and streamed artifact SHA on opened
nofollow regular single-link current-user private files within owned0700 real
directories. Retain actual root/stage/target and file identity through bounded
read/publication checks; symlink/hardlink/path substitution is an error, never
VERIFIED. Receipt JSON <=64KiB at receiver boundary; artifact streaming memory
bound remains. No proof/key/token/env/log changes or generic file framework.

Actual artifact and receipt fsync, stage directory fsync, publish then parent
directory fsync must finish before VERIFIED. Existing identical completed target
must undergo the same real file/directory/parent sync before VERIFIED on retry;
existing different/partial/unsafe target is rejected and never overwritten.
Concurrent normal receiver transfers acquire flock on the held root directory
FD, then check absent destination and publish the verified nonempty stage with
stdlib rename under that same lock. All participating receivers retain the lock
through parent fsync and VERIFIED. Reject every observed existing partial/different/
unsafe target; identical completed target is reverified/synced. Python stdlib has
no cross-platform exclusive directory rename; this guarantee is explicitly for
normal transfers participating in the root lock. A malicious same-UID filesystem
writer ignoring the lock is outside this G1 no-overwrite claim; identity swap
checks can reject detected changes but cannot establish hostile same-UID fencing.
No handwritten ABI/syscall, reservation directory, new lock service or alternative
protocol is added. This smallest alternative was frozen after actual API review
and before receiver code; it is not an atomic no-overwrite primitive claim. Failure after a
rename may leave complete artifact, but failed fsync/unknown ACK is not durable
success. A later same-object retry revalidates+syncs; no replay of backup/business.

Meaningful real filesystem/subprocess tests invoke exact receiver code locally:
positive new publish and identical retry, failed artifact/receipt/stage/parent
fsync (including after publication), wrong receipt/hash, existing different and
partial target, links/path swap, interruption/lost ACK and concurrent same/different
object. Keep old four source export/receiver tests. Synthetic encrypted-looking
bytes and public receipt only; no real SSH credentials/network/provider calls.
These are local receiver contracts, not remote SSH/fencing/promotion/RPO/RTO.
All-targets Cargo check/AST/diff and exact owned source SHA/patch are required.
Source full workspace/socket gate remains unpassed; no commit/publish.

Next serial H2 must add actual same Worker snapshot cut (audit max sequence,
optional persisted policy version/bundle SHA) and offline restore evidence;
whole artifact SHA binds workload replay/lease journal without duplicate digests
or counts,
not reconstruct createdAt as commit cut. It overlaps C2 Domain/Broker files and
therefore waits for C2 stable integration. Real two-node fencing/traffic switch
requires a selected external facility; no local flag/manual fence-ok receipt can
prove old primary unable to execute HTTP or restart. See accepted external-
capabilities spec and evidence/ha-plan.md. No new HA maturity claim from H1.
