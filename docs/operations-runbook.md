# Operations runbook

Every command below assumes the exact state directory and service identity have
been confirmed first. Never delete, overwrite, or change ownership recursively
until a verified backup exists and the target path has been written down.

## Routine backup and restore drill

1. Unlock the broker and run `rekey backup --output NEW_PATH` where `NEW_PATH`
   does not exist.
2. Save the successful receipt and its SHA-256 separately from the backup.
3. Run `shasum -a 256 BACKUP` and compare the exact 64-character digest.
4. Stop the broker. Restore into a newly created empty mode-0700 directory.
5. Start the restored broker locked, unlock it, list credentials/actions, and
   execute a disposable fixed Action.
6. Shut it down and retain the drill record. Never replace production state
   merely to test restore.

Missing receipt/SHA-256 means restore is not authorized: locate the original
receipt or create a new backup. A wrong proof, bad digest, corrupt backup, or
nonempty destination must fail without producing a servable vault.

## Interrupted restore or init

`.restore-incomplete` and `.init-incomplete` are safety markers, not files to
delete casually. Keep the broker stopped. Re-run the same restore against the
same directory only when the marker is a regular file created by Rekey and the
same trusted backup/digest/proof are available; Rekey cleans only its known
partial artifacts before retry. For an interrupted init, run init again and
complete recovery-key confirmation. A symlink or unexpected file type is a
security incident; preserve the directory for inspection.

## Database, worker, and audit faults

- `STORAGE_INTEGRITY_FAILED`, unsupported/unknown format, or malformed crypto
  metadata: stop immediately, preserve state, logs, binary version, and a
  filesystem copy. Restore the last verified backup into an empty directory.
- `AUDIT_COMMIT_FAILED` or `FAULTED`: the worker fails closed. Do not continue
  mutations or execution. Resolve disk/filesystem failure, restart locked, and
  verify audit reconciliation before service restoration.
- `AUDIT_COMMIT_FAILED_AFTER_EXECUTION` or another indeterminate result: a
  remote effect may already exist. Check the upstream system and request ID
  before retrying.

Never edit SQLite rows, WAL files, crypto discriminators, or audit records.

For incident triage, prefer `rekey audit list` over opening SQLite. Preserve a
stable traversal by carrying both returned sequence cursors between pages. Use
`rekey audit export --output NEW_PATH` for a complete JSONL snapshot; the path
must not exist and a receipt is success evidence only after file and parent
directory sync. Treat a retained partial file as failure evidence, choose a new
path for retry, and do not append or resume it. Exports are redacted but still
sensitive operational metadata and are not encrypted Credential backups.

Local rows are append-only for the vault lifetime. There is no supported audit
deletion, TTL, pruning, legal hold, WORM sink, SIEM delivery, or remote durability.

## ENOSPC and filesystem errors

Stop new requests, retain all files, and inspect free bytes and inodes with
`df -h` and `df -i`. Free space outside the Rekey state directory. Do not
remove `vault.sqlite3-wal`, temporary backup artifacts, or incomplete markers
by hand. After storage is healthy, restart locked and perform status, backup,
and restore verification. A backup without a successful receipt is not a
completed backup even if a file exists.

## Permissions and sockets

The default state/runtime directories are owner-only mode 0700; SQLite,
broker lock, Admin socket, and default Agent socket are mode 0600. Confirm the
service account owns them with `ls -ld` and `ls -l`. Stop the service before
repairing a known Rekey path. Do not make the Admin socket or state tree
group/world accessible.

`IPC_UNAVAILABLE` may mean the broker is stopped, the socket is stale, its
parent is writable, a symlink is present, ownership differs, or the client is
the wrong user. Fix the exact cause; do not relax the client checks.

## Service startup and logs

- launchd: `launchctl print gui/$(id -u)/io.github.majiayu000.rekey`; logs are
  `~/.rekey/rekeyd.stdout.log` and `~/.rekey/rekeyd.stderr.log`.
- systemd: `systemctl status rekey.service` and
  `journalctl -u rekey.service --since today`.

Expected boot state is locked. `SIGTERM` drains accepted work before exit;
Admin shutdown requires step-up while unlocked. A crash restart also starts
locked and reconciles unterminated `execution.started` audit rows.

## DNS, network, and Clash/TUN Fake-IP

Resolve the exact Action host with `dig +short HOST`. Private/reserved answers,
including `198.18.0.0/15`, are rejected. For Clash, add the exact host to the
DNS fake-IP filter so the host resolver returns real public addresses. Rekey
does not follow redirects or honor HTTP proxy environment variables.

## Upgrade, rollback, and rejected state

Follow [installation.md](installation.md). v1 state and any non-v5/unknown
layout are intentionally rejected and never migrated or overwritten. Preserve
the old directory and initialize v2 separately. Rollback requires the prior
binaries plus their matching pre-upgrade backup restored into an empty path.

## Lost keys

- Password lost, recovery key available: unlock with recovery, then run
  `rekey password change --recovery`; optionally rotate recovery afterward
  using the new password.
- Recovery key lost, password available: run `rekey recovery rotate` and save
  the newly displayed key offline.
- New recovery-key output lost, password available: rotate recovery again.
  Only the latest successfully displayed key is active.
- Both lost: encrypted credentials and backups are permanently inaccessible.
  Rekey has no backdoor, escrow, reset, or export operation.

Factor changes are not retroactive. A backup made before replacement still
requires its historical password or recovery key; a later backup uses the
wrapper generation active when it was created. Never delete historical factor
material while a retained backup still depends on it; otherwise that backup is
permanently unrecoverable.
