# Operations runbook

Every command below assumes the exact state directory and service identity have
been confirmed first. Never delete, overwrite, or change ownership recursively
until a verified backup exists and the target path has been written down.

## Routine backup and restore drill

For BAK-06's external scheduling boundary and transfer acceptance, see
[External backup operations](superpowers/specs/2026-09-10-external-backup-operations.md).
Creating a new snapshot still requires operator step-up. A scheduler may only
transfer an already completed backup and receipt; it does not hold the unlock
proof.

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

## Installed personal backup transfer

On this workstation, use `~/.rekey` as the future default source state and
`~/.local/share/rekey-backups/outbox` as the export queue. The hourly user launch
agent uploads completed exports to `apple:/Users/apple/Documents/rekey-backups`
and also runs at login. No real authority is initialized yet; the installed
job only transfers snapshots after the operator exports them. Retention is
keep-all. Desktop/Documents are not used for the local queue because macOS
TCC denied access from the background process.

After initializing and starting your authority, create a snapshot in a trusted
terminal using the existing hidden step-up prompt:

```sh
/usr/bin/python3 "$HOME/Library/Application Support/Rekey/backup-sync.py" \
  --outbox "$HOME/.local/share/rekey-backups/outbox" export \
  --state-dir "$HOME/.rekey" \
  --rekey /Users/lifcc/Desktop/code/AI/tools/rekey/target/debug/rekey
```

The `--rekey` path must refer to the binary matching your running authority.
Failed exports remain hidden `.pending-*` directories and are not uploaded.
Do not rename them into the queue. Retry export into a new directory.

Inspect or trigger the installed transfer job:

```sh
launchctl print "gui/$(id -u)/io.github.majiayu000.rekey.backup-sync"
launchctl kickstart "gui/$(id -u)/io.github.majiayu000.rekey.backup-sync"
tail -n 30 "$HOME/Library/Application Support/Rekey/backup-sync.stdout.log"
tail -n 30 "$HOME/Library/Application Support/Rekey/backup-sync.stderr.log"
```

Check the latest exit code and timestamps: old failure lines remain in the log.
`SYNC OK exports=0` means there was nothing to transfer, not that a snapshot
was created. `VERIFIED` means the remote digest and receipt matched. Missing
receipts, digest conflicts and SSH errors fail nonzero. Failed remote uploads
remain hidden `.upload-*` directories for diagnosis; they are not completed
backups. No unlock material is stored in the job or sent over SSH. To disable:
`launchctl bootout "gui/$(id -u)/io.github.majiayu000.rekey.backup-sync"`, then
remove only its named plist if disabling across future logins as well.

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
- `POLICY_INVALID`, `POLICY_VERSION_CONFLICT`, or `POLICY_VERSION_EXHAUSTED`:
  retain the rejected artifact, current status, and signer identity. Do not edit
  SQLite or retry with an unsigned snapshot. Reissue the intended contents as
  the next consecutive signed version; the terminal version is reserved.
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
locked and reconciles unterminated `execution.started` audit rows. A persisted
policy reports `unavailable` until the first successful unlock reverifies and
loads its signed bundle. `expired` is terminal for that loaded bundle; clock
rollback does not revive it.

## Policy and approval operations

Keep policy-signing and approver private keys outside Rekey state, processes,
and backups. Rekey stores only the immutable policy trust public key,
VRK-authenticated signed bundles, and redacted approval audit identifiers. It never signs policy
or approval artifacts.

Install the trust root once with `rekey policy trust install --file TRUST.json
--step-up-stdin`. Exact retries are idempotent; a different signer or key is a
replacement attempt and is refused. Activate only a verified next-version
bundle with `rekey policy activate --file BUNDLE.json --step-up-stdin`, then
confirm signer, version, expiry, digest, and `active` status.

For an approval incident, preserve the challenge, grant, policy status, and
redacted `approval.requested`, `approval.accepted`, or `approval.rejected`
events. Do not retry an uncertain upstream write merely by issuing a new grant.
Locking or restarting intentionally revokes every capability, challenge, and
in-memory approval use record; create a new session and challenge afterward.
There is no remote approval availability fallback or offline bypass.

The source-only `rekey-approval-sign` binary is a local one-person, one-time
review/sign tool. Use operator-owned policy, trust, Action, and PKCS8 files;
obtain the challenge from this host's `rekey approval prepare`; wrap the original
request text into `approval-request.json`; review the displayed digest; sign
only that digest; execute within 60 seconds with the same request. Do not take
trusted inputs from an Agent directory. Exported challenges are not
source-authenticated. Operator steps are in
[the user guide](user-guide.md#local-independent-approval-endpoint).

For workload identity, keep issuer private keys outside Rekey and place only
the intended static Ed25519 or RS256 public keys in the signed policy. The
source-only [WID-09 extension](superpowers/specs/2026-09-10-github-actions-jwks.md)
alternatively accepts `keys: []` and `online_key_source: "github-actions-jwks"`
for the exact GitHub issuer. Every mint fetches the fixed public HTTPS JWKS;
outage or invalid keys deny admission, with no stale-key fallback. Remote key
rotation does not alter the policy digest or reset consumed JWT replay records.
There is no discovery, introspection, SPIRE or Kubernetes integration.
For static identities, rotate verification keys by signing the next
consecutive policy version with the replacement key set, activate it, and
confirm status before issuing new workload tokens. A new-version activation
revokes all workload-minted sessions while preserving Admin-minted sessions.
Retrying the exact active bundle preserves both kinds of session.

`WORKLOAD_IDENTITY_INVALID` deliberately covers malformed, expired, replayed,
wrong-issuer, wrong-subject, wrong-audience, wrong-key, and otherwise
unverifiable workload tokens without exposing the failed check. An unauthorized
Action returns `REQUEST_DENIED` before replay consumption, so the same valid
token may be retried with an authorized Action. Once durable admission is
attempted, do not retry an uncertain token: successful consumption stores its
`jti` digest atomically with the redacted `session.created` audit event, and
replay denial survives token expiry, wall-clock rollback, restart, and restore
of a backup that already contains the consumption record until a successful
new-version policy activation. A pre-consumption backup cannot preserve that
later record and remains subject to the documented G1 complete-vault rollback
limit. Policy roll-forward atomically clears replay rows scoped to the prior
policy digest; an exact activation retry does not clear them.
`AUDIT_COMMIT_FAILED` or a durable-admission timeout faults the broker; preserve
state and follow the database/audit fault procedure. A definite pre-mutation
`AUTHORITY_BUSY` response is retryable.
Audit output must never contain the JWT, `jti`, external subject, signing key,
or capability token.

## DNS, network, and Clash/TUN Fake-IP

Resolve the exact Action host with `dig +short HOST`. Private/reserved answers,
including `198.18.0.0/15`, are rejected. For Clash, add the exact host to the
DNS fake-IP filter so the host resolver returns real public addresses. Rekey
does not follow redirects or honor HTTP proxy environment variables.

## Upgrade, rollback, and rejected state

Follow [installation.md](installation.md). This Alpha (`v2.0.0-alpha.2`)
initializes vault schema **v9**. The historical `v2.0.0-alpha.1` archive
initialized schema **v5**. There is no reader or migration for any other format,
including v1 and v4–v8. Unknown or mismatched layouts are rejected and never overwritten.

A backup made with an older binary restores only with that same generation of
binaries into an empty directory. It is not an import path into v9. Rollback
means the preserved old binaries plus their matching backup; never point those
binaries at a directory a v9 process has opened, and never point a v9 binary at
older state.

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
- Policy-signing private key lost: the current signed policy can continue until
  expiry, but no next version can be issued. The immutable trust root cannot be
  replaced; initialize a new vault and recreate state through supported Admin
  operations.
- Approver private key lost: remove that approver in the next signed policy
  version using the policy signer. Rekey cannot recover, rotate, or impersonate
  an external approver.

Factor changes are not retroactive. A backup made before replacement still
requires its historical password or recovery key; a later backup uses the
wrapper generation active when it was created. Never delete historical factor
material while a retained backup still depends on it; otherwise that backup is
permanently unrecoverable.


## Fixed Keycloak exchange (source only)

Use an owner-only profile with the fixed issuer origin/realm, confidential
client, subject access token, audience and GET target described in
`superpowers/specs/2026-09-10-keycloak-token-exchange-oau02.md`. The typed
`credential add-keycloak` and `rotate-keycloak` commands retain per-call step-up;
generic rotate rejects this kind. No provider token is returned to the Agent.
Exchange/revoke uncertainty is nonretryable. Inspect the request-linked
`oauth.token.issued`, `oauth.token.revoked` and terminal audit events before
operator recovery; no background renewal or crash-time cleanup is promised.
Resource servers using only offline JWT verification may continue accepting a
revoked JWT until expiry; immediate rejection requires their own online check.

Current source storage format is 10; old state/backups are rejected without
migration. The format-9 backup drill receipts remain historical evidence for
the recorded binaries and are not format-10 restore evidence.

## Local Agent tools and operator repair

MCP-03's owner-only manifest and Codex launch instructions are in
[Local MCP stdio](superpowers/specs/2026-09-10-local-mcp-stdio.md). The schema in
each manifest entry must match its reviewed policy binding. The adapter cannot
create a session, install trust, activate policies or approve a write.

For a policy draft produced by onboarding, build `rekey-policy-sign` and follow
[External policy signer](superpowers/specs/2026-09-10-external-policy-signer.md).
Review the complete draft before supplying its digest and an operator-held key.
Signing and activation remain separate trusted-terminal steps; retain the key
outside the Agent workspace and never hand it to a Broker or MCP configuration.

After an opaque credential fails upstream, run the trusted terminal repair helper
from [Operator credential repair](superpowers/specs/2026-09-10-operator-credential-repair.md).
It displays the registered Action and credential scope, asks provide/decline,
and delegates hidden entry to `rekey credential rotate`. Rotation affects all
Actions sharing that credential. The result alone does not repeat the request;
the operator or Agent must explicitly choose another execution after inspecting
any possible earlier write effect. Revoked and provider-specific credentials
remain outside this ordinary-token repair flow.
