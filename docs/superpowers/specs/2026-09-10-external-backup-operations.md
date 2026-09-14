# External backup operations (BAK-06)

Status: external transfer operations implemented and installed. Local, remote
and actual launchd-invoked transfer/restore drills passed. Destination authorized: `apple:/Users/apple/Documents/rekey-backups`.
User delegated deployment choices. Use the default `~/.rekey` state (currently
not initialized), `~/.local/share/rekey-backups/outbox` for exports, and a user
launchd task at login and every 3600 seconds for transfers.

## Scope

Reuse `rekey backup` and `rekey restore`. The operator creates each new backup
with an explicit step-up proof in the trusted terminal. An external scheduler
may transfer an already completed encrypted backup and its receipt. It cannot
unlock Rekey or create new snapshots unattended. No password, recovery key,
signing key or capability is stored in scheduler configuration.

The first deployment needs one operator-selected source state directory, one
local export directory, one SSH host alias and remote directory, and a transfer
schedule. Those values are not inferred from other projects. Retention starts
as keep-all; automatic deletion is outside this slice.

## Export and transfer

1. Create a new owner-only export directory for this backup. Use a nonexistent
   artifact path outside the live state directory. Run the existing backup
   command with its hidden step-up prompt.
2. Capture stdout as a temporary receipt. Only a successful process exit plus
   a valid receipt makes the export eligible. Independently hash the artifact
   and compare with `sha256_hex`. Keep the original binary version, vault ID,
   format version and receipt alongside the encrypted artifact.
3. Publish the receipt only after the local check succeeds. A file left behind
   after a failed backup, or an empty receipt from shell redirection, is never
   eligible for transfer or restoration.
4. The external job transfers one immutable export directory using the
   operator's existing SSH identity and host-key verification. It must not
   overwrite an existing remote backup, copy the live SQLite database/WAL, or
   transmit unlock material. The destination independently verifies the
   artifact hash before recording transfer success. Transport exit zero alone
   is not remote verification.
5. Missing receipt, mismatch, SSH failure or remote verification failure exits
   nonzero and leaves an operator-visible job log. No empty fallback backup,
   silent skip or destructive synchronization. Retrying the immutable transfer
   is separate from asking the operator to create another snapshot.

## Restore drill

Use a disposable empty state directory and the matching Rekey binary. Verify
the artifact against the saved receipt, restore with the historical proof,
start locked, unlock, and compare the credential/Action IDs. Issue a new
session and externally authorize the disposable Action before execution;
capabilities are not recovered from backups. A bad hash, wrong proof or
nonempty target must fail. Never stop or overwrite a production authority for
the rehearsal.

Local and remote completion are separate. Local acceptance does not prove a
remote copy or recurring schedule. BAK-06 remains incomplete until the selected
destination passes a scheduled transfer, remote digest verification, failure
visibility and a restore drill using the remotely retrieved copy.

## Existing verification

`cargo test -p rekey-vault --test backup_restore` covers ciphertext-only output,
receipt hashes, wrapper generations, bad proof/hash, nonempty destinations,
corruption, audit failure and no-overwrite. `scripts/p0-durability.sh` is the
existing broader crash/fault gate; no replacement backup engine is introduced.

## Local evidence (2026-09-10)

`outputs/rekey-backup-20260910/local-receipt.json` records the real CLI/broker
drill on source commit `358b3a5`: encrypted mode-0600 backup, independently
matching SHA-256, plaintext canary absence, no-overwrite rejection and bad-hash
restore rejection. The restored broker reported exactly `locked` with zero
active sessions, retained the credential and Action IDs, and returned 200 from
a fixed anonymous GitHub read after a new session and external policy signing.
This read used a synthetic header canary, not a GitHub credential. Both temporary
authorities and test secrets were removed. The script and final command output
are saved alongside the receipt. This establishes the local prerequisite. The remote drill below extends it.


## Remote evidence (2026-09-10)

`outputs/rekey-backup-20260910/remote-receipt.json` records an independent real
backup uploaded through the existing `ssh apple` identity to
`/Users/apple/Documents/rekey-backups/drill-20260910T080208Z-3eacda59`.
The remote SHA-256 matched the local receipt; directory mode was 0700 and the
archive and receipt modes were 0600. The downloaded remote archive was hashed
again and used for the full restore/locked-state/ID-preservation/new-session
fixed read drill, which returned 200. No unlock material was transferred.
The remote ciphertext and non-secret receipt remain as acceptance evidence;
the disposable local states and test unlock material were destroyed, so this
retained test artifact is not intended for future restoration.

The user selected the destination and delegated remaining settings. The transfer
job scans completed export directories only; it never opens the live authority.
Pending exports use hidden directories and are published by rename only after
CLI success and digest verification. A remote staging directory is likewise
published only after remote verification. Existing completed copies must match
the full receipt and digest; retries never overwrite them. Failed staging data
is retained for diagnosis, not treated as a completed backup. Each invocation
logs success, no work, or a nonzero visible failure. No automatic retention.
The first real snapshot remains pending initialization and an operator proof.


## Installed schedule acceptance (2026-09-10)

`scripts/rekey-backup-sync.py` implements interactive `export` and noninteractive
`sync`. The installed copy is under `~/Library/Application Support/Rekey/`.
The launch agent `io.github.majiayu000.rekey.backup-sync` runs at login and every
3600 seconds. Outbox is `~/.local/share/rekey-backups/outbox`; source defaults
to `~/.rekey` for future manual exports. There is no initialized real state on
this machine yet, so no claim is made that real credentials are backed up.

The original Documents outbox failed under macOS TCC when invoked by launchd;
its nonzero error remains in `launchd-stderr.log`. Relocating the local outbox
resolved that restriction without granting broader permissions. The remote
Documents destination was unchanged. `scheduled-receipt.json` proves a fresh
backup transferred by the actual installed launch agent (manually kickstarted),
remote verification and recovery from the downloaded archive, followed by a
new session and fixed read returning 200. The configured hourly timer was
inspected; the drill did not wait one hour. `sync-tests.log` covers failed CLI
publication, missing receipt, local hash mismatch and remote mismatch without
overwriting a completed copy. `deployment.json` records the non-secret setup
and installed script hash. Acceptance test entries were removed from the local
outbox; encrypted remote drill artifacts remain. The external scheduling slice
is complete; creating the first real snapshot still requires the operator.
