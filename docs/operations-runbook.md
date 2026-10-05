# Operations runbook

Scope: **3.0.0-alpha.2 unpublished candidate**, vault/backup 25 and policy 6.
These durable formats are frozen across all v3 prereleases and GA. Local checks are not signed-device,
provider or release acceptance. Enterprise references below require a source
build with `--features lab`; they are not installed personal services.

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
4. Stop the broker. In a new mode-0700 destination, run `restore --inspect`
   with the input, receipt SHA and source password/recovery proof. Review the
   returned vault ID, source generation, high-water and missing-history flag.
5. Submit the exact reviewed JSON with `restore --expected-context`, the same
   input/SHA and a fresh proof. Record the new receipt generation; a stale
   context requires a new preview and human decision, not automatic retry.
6. Start the restored broker locked, unlock it, list credentials/actions, and
   execute a disposable allowed Action. See the [commands](user-guide.md#backup-and-restore).
7. Shut it down with fresh proof and retain the drill record. Never replace production state
   merely to test restore.

Missing receipt/SHA-256 means restore is not authorized: locate the original
receipt or create a new backup. A wrong proof, bad digest, corrupt backup, or
nonempty destination must fail without producing a servable vault.

## Disposable Docker primary/standby drill (source checkout)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Use a local Docker daemon and a new output directory. No existing vault or cloud
account is used; all credentials and keys are generated for this run.

```bash
docker build -f scripts/Dockerfile.dr -t rekey-dr-reference .
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-docker-dr-drill.py
python3 scripts/rekey-docker-dr-drill.py --image rekey-dr-reference --output /tmp/rekey-dr-new
```

The host controller refuses promotion while the partitioned primary exists,
fences its immutable ID through the external daemon, restores the encrypted
snapshot into a separate volume, rejects old authorization and issues a new
capability for a successful standby request. The private `report.json` records
image/source identity, measured recovery, one deliberately unreplicated write,
and verified resource cleanup. Any missing evidence exits nonzero. A daemon or
host failure, continuous replication, automatic routing and production RPO/RTO
are outside this [reference contract](superpowers/specs/2026-10-02-docker-dr-reference.md).
Only resources labeled for this invocation are removed.

## Operator-managed backup transfer (lab reference)

The pkg does not install a backup transfer job, destination or retention policy.
The retained `scripts/rekey-backup-sync.py` helper can export a new snapshot
through the matching CLI, or transfer completed encrypted exports and receipts.
An operator must explicitly choose private local/remote destinations, service
identity and schedule. Never reuse another workstation's path or SSH host.

Use the helper's `--help` and the [external backup contract](superpowers/specs/2026-09-10-external-backup-operations.md).
No scheduler receives an unlock proof. Hidden `.pending-*` exports or
`.upload-*` transfers are incomplete; do not rename them into successful backup
queues. `SYNC OK exports=0` means no transfer was needed, not that a backup was
created. Verify the remote digest and receipt. Removing a transfer job must not
delete vault state, generation anchors, keys or retained backups.

## Interrupted restore or init

`.restore-incomplete` and `.init-incomplete` are durable safety markers. Stop the
broker and preserve them with the database, wrappers and generation history.
A failed operation may already have reserved a higher external generation; the
absence of a success receipt does not authorize deleting or decrementing it.

For interrupted restore, authenticate the intended backup again with
`restore --inspect`, review the actual current high-water context, then explicitly
supply that context to the write call. Only the supported restore path may clean
its own verified partial files. A stale context or uncertain result requires a
new inspection and deliberate decision, never an automatic retry. A symlink or
unexpected file type is a security incident.

Interrupted init is not a restartable cleanup command. If it has reserved
history, rerunning init must not delete its database or marker. Preserve the
attempt and recovery material; use the supported authenticated restore flow
when a valid backup exists, or deliberately select a different new workspace.
Do not remove history to make the original directory appear empty.

`ROLLBACK_SUSPECTED` is a separate state with no usable root key. Review the
`rollback` object in `rekey status`; confirm it only through
`rollback-confirm --expected-context` with password or recovery proof. Presence
cannot confirm a rollback. The actual history is reread; a changed context
rejects without treating an ordinary unlock as consent. Confirmation leaves the
vault locked. Locking a suspected vault preserves its context; after restart,
unlock must detect the condition again. See [the exact CLI flow](user-guide.md#backup-and-restore).

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

Current source supports completed-execution pruning and authenticated
unlocked-only retention. Usage history is a separate authenticated ledger and
is not reset by pruning display audit rows. Delivery/archival below are lab
tools; their field acceptance is separate.

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

- Installed macOS pkg: use the App service controls. Its opt-in SMAppService
  job is `com.rekey.rekeyd`; `launchctl print gui/$(id -u)/com.rekey.rekeyd`
  is read-only diagnosis. Do not register a second generated LaunchAgent.
- Linux personal service: `systemctl --user status rekey.service` and
  `journalctl --user -u rekey.service --since today`. This unit uses
  `default.target` and no `User=`. A deliberately configured dedicated-account
  system service instead uses system-level commands. See [installation](installation.md).

Expected boot state is locked. `SIGTERM` drains accepted work before exit;
Admin shutdown requires fresh step-up in every state, including locked. A crash restart also starts
locked and reconciles unterminated `execution.started` audit rows. A persisted
policy reports `unavailable` until the first successful unlock reverifies and
loads its signed bundle. `expired` is terminal for that loaded bundle; clock
rollback does not revive it.

## Policy and approval operations

In team mode, keep external Ed25519 policy/approver private keys outside Rekey
state and backups. Personal mode instead uses a per-vault Secure Enclave P-256
key through explicit App authentication; there is no software fallback. The
Broker stores the immutable typed public trust root and authenticated signed
bundles, not the private policy key. Local Presence approval is a one-time
context-bound decision, not an external signature or background Agent prompt.

Install the trust root once with `rekey policy trust install --file TRUST.json
--step-up-stdin`. Exact retries are idempotent; a different signer or key is a
replacement attempt and is refused. Activate only a verified next-version
bundle with `rekey policy activate --file BUNDLE.json
--expected-vault-id VAULT_ID --expected-trust-sha256 TRUST_SHA256 --step-up-stdin`, then
confirm signer, version, expiry, digest, and `active` status. Read the public
vault/root target from `rekey policy status` after installing trust; the root
digest covers its canonical four-field trust document, with no trailing newline.
Activation status now exposes real vault/tenant IDs and persistent activation
time; exact retry preserves that time. Audit reason binds version and bundle SHA.

For an approval incident, preserve the challenge, grant, policy status, and
redacted `approval.requested`, `approval.accepted`, or `approval.rejected`
events. Do not retry an uncertain upstream write merely by issuing a new grant.
Locking or restarting intentionally revokes every capability, challenge, and
in-memory approval use record; create a new session and challenge afterward.
There is no remote approval availability fallback or offline bypass.

The packaged `rekey-approval-sign` binary is a local one-person, one-time
review/sign tool. Pin `rekey approval origin` on the Broker host; obtain the
origin-signed envelope from this host's `rekey approval prepare` or from
`rekey approval pending` / `rekey approval get`; wrap the
original request text into `approval-request.json`; review the displayed digest
with `--origin-key`; sign only that digest; execute within 60 seconds with the
same request. Do not take trusted inputs from an Agent directory. This is not a
hosted approval service. Operator steps are in
[the user guide](user-guide.md#local-independent-approval-endpoint).

For lab workload identity, keep issuer private keys outside Rekey and place only
the intended static Ed25519 or RS256 public keys in the signed policy. The
source-only [WID-09 extension](superpowers/specs/2026-09-10-github-actions-jwks.md)
alternatively accepts `keys: []` and `online_key_source: "github-actions-jwks"`
for the exact GitHub issuer. Every mint fetches the fixed public HTTPS JWKS;
outage or invalid keys deny admission, with no stale-key fallback. Remote key
rotation does not alter the policy digest or reset consumed JWT replay records.
There is no discovery, introspection, SPIRE or Kubernetes integration.
For static identities, rotate verification keys by signing the next
consecutive policy version with the replacement key set, activate it, and
confirm status before issuing new workload tokens. Replacing an active policy revokes all existing sessions. A first activation
without an active predecessor preserves manually issued sessions but revokes
workload-issued ones. Retrying the exact active bundle preserves both kinds.

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
including `198.18.0.0/15`, are rejected by default. Rekey does not silently send
queries to a public resolver. It does not follow redirects or honor HTTP proxy
environment variables.
When rejected for fake-IP, the daemon records `upstream.dns_configuration_required`
with the system-DNS/explicit-DoH remedies; inspect this event before retrying.

For a TUN network that returns only fake-IP answers, an administrator may
explicitly choose a trusted HTTPS JSON DoH service in the daemon's environment:

```bash
REKEY_DOH_URL=https://1.1.1.1/dns-query rekey serve
```

This is an optional example, not a default or a required provider. The service
must support JSON A/AAAA queries with `name` and `type` parameters. Its URL must
use HTTPS without userinfo, query or fragment; its own system-resolved addresses
and every returned provider address must be public. If the resolver hostname is
also fake-IP, use a reachable HTTPS IP URL whose certificate validates that IP,
or configure real system DNS. No hardcoded bootstrap addresses are used.

The chosen service receives each queried provider hostname. Provider credentials
are never included. Unset `REKEY_DOH_URL` to disable it; restart the daemon for
an environment change. A terminal setting applies to a daemon launched from
that terminal, not an already-running App or SMAppService. Existing Actions must
allow `retry-after` to forward that header; new App LLM onboarding includes it.

DoH resolves addresses; it does not supply a proxy exit. The provider URL, Host
and TLS SNI retain the original hostname while connecting to the screened IP.
TUN domain rules may rely on DNS mapping or SNI sniffing, so test the actual
provider and route on your network. Unreachable DoH/provider endpoints fail
closed; no retry through fake-IP or alternate resolver is attempted. The JSON
schema follows the [documented DNS JSON response](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/).

## Upgrade, rollback, and rejected state

Follow [installation](installation.md). The target is **3.0.0-alpha.2, unpublished**,
with vault/backup 25 and policy 6. These formats are frozen across all v3 releases.
Incompatible state and backups are always rejected: no migration, backfill or
legacy reader will be added. All v3 prereleases, GA and minor/patch releases must keep
the durable format; a breaking format needs a new major version.

Keep historical binaries, state and backups together. A historical backup is
not an import path to this candidate. The App's unsupported-format message is
read-only guidance; it does not migrate, inspect secret payloads or delete the
old workspace. Create a separate workspace intentionally. Do not switch an old
binary onto a directory touched by a newer format, and never erase external
generation history to force a software downgrade.

## Lost keys

- Password lost, recovery key available: unlock with recovery, then run
  `rekey password change --recovery`; optionally rotate recovery afterward
  using the new password.
- Recovery key lost, password available: run `rekey recovery rotate` and save
  the newly displayed key offline.
- New recovery-key output lost, password available: rotate recovery again.
  Only the latest successfully displayed key is active.
- Both lost: encrypted credentials and backups are permanently inaccessible.
  Rekey has no backdoor, escrow or factor-reset bypass.
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

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

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

Current source uses vault/backup 25 and policy 6, without migration. Older
backup drill receipts remain evidence only for their recorded binaries; they
do not establish current restore or provider acceptance.

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

## Audit delivery (development source)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

The [bounded audit delivery helper](superpowers/specs/2026-09-30-audit-delivery.md)
ships in the unreleased candidate archive. First obtain a trusted BackupReceipt
for the intended vault, choose a new UUID for this source instance, and create
an outbox under an existing private directory. Use the same explicit source
and vault IDs for every command:

```bash
python3 rekey-audit-delivery.py --outbox /secure/audit-outbox \
  --source-instance-id SOURCE_UUID --vault-id VAULT_UUID \
  init --vault-receipt /secure/receipt.json --endpoint https://SIEM_HOST/audit
rekey audit export --output /secure/audit.jsonl
python3 rekey-audit-delivery.py --outbox /secure/audit-outbox \
  --source-instance-id SOURCE_UUID --vault-id VAULT_UUID \
  enqueue --export /secure/audit.jsonl
python3 rekey-audit-delivery.py --outbox /secure/audit-outbox \
  --source-instance-id SOURCE_UUID --vault-id VAULT_UUID send
```

The last command reads the delivery token through hidden terminal input.
Explicit `--token-stdin` is available for a protected input pipe; neither token
nor unlock proof belongs in arguments, environment variables or outbox files.
The receiver must persist the batch and return the exact durable ACK described
in the specification. HTTP 200 alone does not advance the cursor. After a
lost response, resend the pending batch; its ID and digest remain unchanged.

Retain unacknowledged local audit events before pruning. A sequence gap,
partial outbox, permanent failure journal or identity mismatch requires
operator review; the helper does not skip the batch or reset its cursor.
Restore or clone uses a new source UUID and new outbox. Real SIEM storage,
permissions, deduplication and capacity must be validated at that receiver.

## Vault Transit approval signing (development source)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

For the fixed [Transit approval signer](superpowers/specs/2026-09-30-vault-transit-approval-signer.md),
the operator supplies one private profile containing the token, its absolute
expiry, the public HTTPS origin/mount/key, explicit key version and pinned
Ed25519 public key. The public key must match the approver in the independently
verified policy. Keep this profile outside the Agent workspace, owned by the
operator with mode 0600. Provider administrators must validate the key's
non-derived configuration and signing-only token permissions at Vault.

Use `--vault-transit-profile /secure/transit.json` in both the existing
`rekey-approval-sign review` and `sign` commands in place of `--key-file`.
Review binds the public target and key into the digest. Sign sends one request,
verifies the returned signature locally, and creates the usual exclusive
approval file; submission and live Broker authorization remain separate steps.
Changing target, key version, public key or reviewed request requires a new
review. Renewing the token for the same target does not change that digest.

The production signer uses built-in WebPKI roots and rejects non-public DNS
results. It has no private-address or custom-CA command option. An uncertain
remote response returns exit 1 without automatically retrying or selecting a
software key. Verify provider ACL and revocation at the real deployment before
claiming remote key custody or hardware protection.

## Independent HTTPS approval-file relay (source checkout)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Build `rekey-approval-relay` or use a future archive that contains it. Create
an operator-owned mode-0700 state directory. Configure one organization,
Broker origin public key, uploader subject, subject-to-ApproverId transport
access list and independently confirmed directory links. Relay configuration 3
and store 2 reject incompatible older inputs without migration; use an empty private state directory
for this breaking development version. Directory tombstones persist, changed
mapping/configuration does not clear them. A stop/restart does not revoke
downloaded grants or update a Broker policy.

The mode-0600 configuration has the following exact fields. Replace the
public placeholders and file paths with independently trusted values:

```json
{
  "formatVersion": 3,
  "instanceId": "<INSTANCE_UUID>",
  "endpoint": "https://approval.example.com/v1",
  "listenAddress": "127.0.0.1:8443",
  "stateDir": "/secure/relay-state",
  "tlsCertificateFile": "/secure/relay-cert.pem",
  "tlsKeyFile": "/secure/relay-key.pem",
  "idpIssuer": "https://idp.example.com/realms/rekey",
  "introspectionUrl": "https://idp.example.com/realms/rekey/protocol/openid-connect/token/introspect",
  "idpCaCertificateFile": "/secure/idp-ca.pem",
  "introspectionClientId": "relay-introspection",
  "introspectionClientSecretFile": "/secure/introspection-secret",
  "personnelClientId": "personnel-login",
  "audience": "rekey-relay",
  "tenantId": "<TENANT_UUID>",
  "originPublicKey": "<INDEPENDENTLY_PINNED_HEX_PUBLIC_KEY>",
  "uploaderSubject": "<STABLE_OPERATOR_SUBJECT>",
  "approvers": [{"subject": "<STABLE_APPROVER_SUBJECT>", "approverId": "<APPROVER_UUID>", "publicKey": "<LOWERCASE_HEX_ED25519_PUBLIC_KEY>"}],
  "directory": {
    "baseUrl": "https://directory.example.com/scim/v2",
    "caCertificateFile": "/secure/scim-ca.pem",
    "accessTokenFile": "/secure/scim-token.json",
    "mappingVersion": 1,
    "nodes": [
      {
        "nodeId": "<NODE_A_UUID>",
        "vaultId": "<ACTUAL_VAULT_A_UUID>"
      },
      {
        "nodeId": "<NODE_B_UUID>",
        "vaultId": "<ACTUAL_VAULT_B_UUID>"
      }
    ],
    "links": [
      {
        "sourceUserId": "<SCIM_OPERATOR_RESOURCE_ID>",
        "externalId": "<CONFIRMED_OPERATOR_EXTERNAL_ID>",
        "issuer": "https://idp.example.com/realms/rekey",
        "subject": "<STABLE_OPERATOR_SUBJECT>",
        "adminAllowed": true,
        "principalId": "<CONFIRMED_OPERATOR_PRINCIPAL_UUID>",
        "confirmedBy": "<CONFIRMING_ADMIN_STABLE_ID>",
        "confirmedAtMs": 1790726400000
      },
      {
        "sourceUserId": "<SCIM_APPROVER_RESOURCE_ID>",
        "externalId": "<CONFIRMED_APPROVER_EXTERNAL_ID>",
        "issuer": "https://idp.example.com/realms/rekey",
        "subject": "<STABLE_APPROVER_SUBJECT>",
        "adminAllowed": false,
        "principalId": "<CONFIRMED_APPROVER_PRINCIPAL_UUID>",
        "approverId": "<APPROVER_UUID>",
        "publicKeySha256": "<REVIEWED_POLICY_KEY_BYTES_SHA256>",
        "confirmedBy": "<CONFIRMING_ADMIN_STABLE_ID>",
        "confirmedAtMs": 1790726400000
      }
    ]
  }
}
```

Replace sample confirmation times with the actual independently verified UNIX-ms
confirmation instant. Resource/external IDs must be confirmed against the exact
issuer+subject; names and email addresses cannot establish this relationship.
`publicKeySha256` hashes the exact decoded32-byte Ed25519 public key reviewed in
the signed policy. The directory cannot install or replace approval keys.

TLS files, both explicit CA files, confidential-client secret and source token
must be regular owner-only mode-0600 files. The private SCIM token file is a JSON
object with only `accessToken` and integer `expiresAtMs`; write its actual secret
through a protected file editor, never argv/env/logs. It does not auto-refresh.
Fixed registered Users GETs poll every30s with3s per-request/10s batch deadlines,
at most4 concurrent requests and64KiB bodies. Unknown results immediately close
that member's remote gate; successful observations expire after60s, independently
for each member. Restart requires fresh observations. A source404 or false is a
permanent local tombstone; later true does not restore access.

Fresh authenticated configured uploader can GET `/v1/directory/revocations` for
bounded nonsecret receipts. Persisted affected request IDs may be truncated in
output with an explicit count. Each registered node remains pending until actual
signed policy application is independently reconciled; this directory slice has
no node-ACK write endpoint. A true signed policy roll-forward revokes all existing
Admin/Workload sessions and pending approvals locally, requiring unaffected roles
to create new sessions too; first activation and exact retry keep prior behavior.
Node OIDC login and managed admission now have local implementation evidence;
full TLS login execution, directory-to-signed-node rollout and manual identity
restoration remain incomplete. Neither relay denial nor this receipt
proves the two nodes have applied the change. Actual IdP/latency/VM acceptance and
strict TLS listener/PTY gates are unvalidated in this restricted environment. The service accepts only the fixed IdP
introspection profile in the [relay specification](superpowers/specs/2026-09-30-remote-approval-relay.md),
including issuer, audience, personnel client and access-token lifetime.
Use the customer's existing human login client to obtain transport tokens.
Store the bearer header in a private mode-0600 curl configuration; keep its
contents out of argv, environment variables, terminal output and logs.

```bash
rekey-approval-relay serve --config /secure/relay-config.json
```

The uploader exports the origin-signed challenge using the existing Admin
prepare/get entry. Upload only that envelope, with the public ApproverId:

```bash
umask 077
receipt_file="$(mktemp /secure/upload-receipt.XXXXXX)"
curl -q --config /secure/operator-transport.conf \
  --proxy '' --noproxy '*' --proto '=https' --max-time 10 --fail \
  --request PUT --header 'Content-Type: application/json' \
  --header 'X-Rekey-Approver-Id: <APPROVER_UUID>' \
  --data-binary @/secure/challenge-envelope.json --output "$receipt_file" \
  'https://approval.example.com/v1/requests/<REQUEST_UUID>/challenge'
```

The approver uses their own transport configuration to GET the same challenge
route into a new private temporary file. Independently pin origin, Action,
policy and trust; send the raw body/headers/content type through a separately
chosen protected channel. Run the existing signer review/sign on the full
request, then PUT the exact grant file to the `/grant` route. The uploader
GETs that route, checks its SHA256 against `/receipt`, and submits the same
request through `rekey execute --approval FILE`. All downloads use fresh
temporary files, normal TLS validation and the same curl restrictions above.

The immutable receipt means stored transport bytes. Broker lock, restart,
session revocation, policy changes or expiry can make those bytes unusable.
On an unknown upload result, GET `/receipt` or re-upload the same file; a
different file conflicts. An expired challenge requires a new prepare and
human review; transport delay does not extend the signing window. The relay
does not hold origin/approver private keys or call the signer. Client login,
real IdP revocation propagation, public deployment and independent devices
require separate field acceptance.

## Authenticated remote approval inbox (source checkout)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Use the same protected personnel curl configuration as the relay. Query the
fixed endpoint; the response contains public source labels, request IDs and
transport states, with authenticated relative detail/receipt paths.

```bash
curl -q --config /secure/personnel-curl.conf --proxy '' --noproxy '*' \
  --proto '=https' --max-time 10 --fail 'https://FIXED_ENDPOINT/v1/inbox'
```

Compare each source label with the independently obtained Admin origin pin.
Download the exact challenge through the original authenticated route and
review the complete body, headers, Action, policy and trust with the independent
signer. `grant-stored` only reports transported bytes; the Broker still checks
all authorization at execution. A failed transport requires explicit review,
never automatic approval or a replacement approver.

For a next page, use the same endpoint with `--get --data-urlencode
'cursor=RETURNED_CURSOR'`. Refresh from the first page for concurrent earlier
insertions or clock rollback and merge by request ID. Expired retained snapshots
require explicit `includeExpired=true`. Do not follow arbitrary returned origins.
See the [inbox contract](superpowers/specs/2026-09-30-remote-approval-inbox.md)
for the bounded statuses and cursor contract. This is a protected terminal
interface; a complete graphical review and signing flow is still separate work.

## Fixed S3 audit archive and Legal Hold (source checkout)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Use a sealed `batch-N.json` from the independent AUD-07 outbox. Choose the
actual bucket owner, commercial region, prefix, retention mode/UTC deadline
and hold status with the storage operator. The archive tool creates no bucket
and changes no bucket policy, retention setting or object version.

Store short-lived STS access key, secret and session token in a current-user
mode-0600 profile. Its exact fields are listed in the
[archive specification](superpowers/specs/2026-09-30-s3-audit-archive.md).
Pin the same source/vault UUIDs as the batch. Keep the archive and Legal Hold
management profiles separate with `purpose:archive` and `purpose:legal-hold`.
The operator label is a declared local label; actual IAM identities, permissions
and role separation need AWS evidence.

Run these commands from the unpacked archive root. In a source checkout,
use `scripts/rekey-audit-archive.py` instead.

```bash
python3 rekey-audit-archive.py archive --profile /secure/s3-archive.json \
  --batch /secure/audit-outbox/batch-N.json --state /secure/archive-one-batch \
  --mode GOVERNANCE --retain-until '<UTC_RETAIN_UNTIL>' --legal-hold ON
python3 rekey-audit-archive.py verify --profile /secure/s3-archive.json \
  --state /secure/archive-one-batch
python3 rekey-audit-archive.py legal-hold --profile /secure/s3-hold-manager.json \
  --state /secure/archive-one-batch --operation-id '<NEW_OPERATION_UUID>' --status OFF
```

Each state directory holds one frozen batch, upload intent, exact version and
readback receipts. Repeating the same archive command recovers pending work
with the same target/content/retention. A recovered version is synced before
further readback, and all later reads target that version. Hold operations
record before/after and use an immutable operation ID; unknown results require
explicit same-intent recovery. Neither operation deletes objects, shortens
retention or sends governance bypass. A partial journal requires inspection.

Network work has a shared 30-second budget with at most 8 seconds per child
request; local fsync can take additional time. The tool has no Vault unlock
permission. Protocol receipts and synthetic TLS tests do not prove AWS WORM,
customer IAM or legal compliance. Verify rewrite/delete/retention/Hold behavior
against the real test bucket and then the intended production configuration.

## 开发版持久租约与显式恢复

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

格式 15 的动态 Vault 源先持久登记 acquire intent，再请求远端；取得 exact ID 后
必须完成 issued 提交才能执行业务。重启后先保持 Locked，无后台清理请求。
首次显式 unlock 使用登记时的历史凭证版本清理最多 8 条已知 ID，总预算 8 秒；
清理请求服从绝对截止。Running 时重复 unlock 不清理正在执行的租约。

检查 Admin status 的 `lease_journal` 与 unlock 返回的 `lease_recovery`。Locked
或 Faulted 下计数为未验证诊断，不能据此认定恢复完成。Authority 在清理过程中
进入 Faulted 时，最终快照拒绝恢复，运行入口保持关闭。审计或完整性故障需先
处理其根因；不能用重新登记当前凭证替代登记时的历史 profile。

unknown 表示 acquire 请求可能已发出但 exact ID 尚未提交；恢复不猜 ID，不重放
业务，相关来源继续隔离。unconfirmed/deferred 也不证明远端账户已删除。请在
Vault 管理面核对对应角色、token 权限和自然到期；当前代码没有自动解除未知
来源隔离或扫描远端账户的入口。备份不能揭示备份之后产生的租约；主备切换仍
需独立 fencing。真实 Vault 权限、账户删除和恢复时间需要现场验收。

当前沙箱禁止 TCP/Unix socket 监听；已记录的旧进程验收与新增无监听回归分别
保留，完整新整合版本尚不能声明通过运行验收。详见
[租约规格](superpowers/specs/2026-09-30-vault-lease-journal.md)。

## 开发版 GCP 固定 SecretVersion 源

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

使用 `credential add-gcp-secret-manager LABEL --file PRIVATE_PROFILE` 注册，
使用 `credential rotate-gcp-secret-manager ID --file PRIVATE_PROFILE` 轮换；
每次都按现有隐藏 TTY 或 `--password-stdin` 完成 Admin step-up。profile 须为
当前用户拥有的私有常规文件，token 仅在文件/IPC body 中传递。具体闭合字段见
[GCP 合同](superpowers/specs/2026-09-30-gcp-secret-source.md)。

固定 global HTTPS origin、完整数值版本引用和短期 access token。优先登记
canonical 数字 project number；返回 name 必须精确匹配，不查别名，不使用 latest。
声明的到期不是 Google 签发或 IAM 证明；短 token 过期后须显式更新 profile。
一次读取得到完整非空 UTF-8 值，仅注入当前固定 Action，不选择 JSON 子字段、
缓存、自动刷新或向 Agent 返回凭证。需要独立 IAM 最小权限与真实 provider 验收。

当前候选使用 vault25 / policy6，旧 state/backup 拒绝恢复且永久不迁移。
解析、Authority、轮换/备份与 CLI 的合成证据仅支持对应本地边界；
真实 Google IAM、token 到期与撤权仍需实际 provider 验收。

## 开发版指标调度与规则

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

使用现有 `rekey-service-unit.py systemd-metrics-service` 输出 oneshot，传入实际安装的 `--rekey`、`--state-dir` 与 Broker 所属 `--run-as-user`；`systemd-metrics-timer` 输出固定 30 秒 timer。此生成器只输出文件，不安装或启动服务。先按[部署合同](superpowers/specs/2026-09-30-metrics-deployment.md)预置专用 `rekey-metrics` 只读组与 `/var/lib/rekey-metrics` 目录，collector 使用独立 UID，不能访问 Broker state/admin.sock。

`deploy/prometheus/` 中提供固定 textfile 路径的 scrape 示例、规则和 22 个官方 promtool 向量。过期、缺失、未来时间、解析错误、失联或时钟不可信时，不输出业务 rate 为零，转为 freshness 告警。生成器/静态检查不替代部署环境的 promtool、systemd 用户 bus、调度与告警交付验收。上线前需在实际目标完成权限、时钟、网络检查。

## 开发版原生策略与审批文件流程

策略页可预览并私密导出原始 UTF-8 草稿，再交给独立 `rekey-policy-sign` review/sign；既有信任与激活仍需显式 step-up。审批详情中选择原始 JSON 正文并导出 REQUEST，交给独立审批 signer 检查绑定、签名；选回一或两个签名 grant 后，以隐藏 capability 显式执行固定 `action@version`。界面不保管签名私钥，也不自动重试。

草稿最多 64KiB，每个 grant 最多 4KiB，正文遵守实际 Action 大小限制。导出为新建私密文件；执行采用受控快照，capability 仅走匿名 stdin。失焦、锁定、断开、切换 vault 或关闭表单会清空界面敏感状态并忽略迟到回调；这不会撤销已发生的远程效果。HTTP 状态与正文供人工核对，未知响应应查审计，勿自动重试。合成边界检查不能替代实际 GUI 与独立 signer 的设备验收，详见[原生流程合同](superpowers/specs/2026-09-30-native-policy-approval-flow.md)。

## 开发版 AWS 固定版本源

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

使用 `rekey credential add-aws-secrets-manager LABEL --file PRIVATE_PROFILE` 或
`rekey credential rotate-aws-secrets-manager ID --file PRIVATE_PROFILE`，按既有
隐藏 TTY 或明确 `--password-stdin` 提供 step-up。profile 为新建私密普通文件；
明示固定 regional HTTPS origin、完整 ARN、VersionId、短期 access key/secret/
session token 和声明到期，不能放 argv、env 或公开日志。

仅取完整 SecretString 作为本次固定 Action 的值，拒绝二进制、标签/latest、
错误 ARN/version、过期、反射和不合法 header；不执行 SDK discovery、refresh、
缓存、写入或 Agent KMS。SigV4 用原始配置签名，并对签名规范化后的 token
表示一并封口。当前候选使用 vault25 / policy6，旧状态/备份拒绝且永久不迁移。具体九字段和时间边界见[AWS 合同](superpowers/specs/2026-09-30-aws-secret-source.md)。

本地 Actor、加密和签名检查不证明真实 IAM/KMS/STS 撤权或 CloudTrail；
不要把合成测试或历史检查记录视为当前发布及现场验收。


### Fixed Azure Key Vault source (local source implementation)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Use a private regular profile file (closed azure-key-vault-source-v1 contract)
with one commercial vault origin/name/explicit version and imported token/use
expiry. Register with `rekey credential add-azure-key-vault LABEL --file PRIVATE_PROFILE`
and rotate with `rekey credential rotate-azure-key-vault ID --file PRIVATE_PROFILE`.
Both require a current per-call proof via hidden TTY or explicit `--password-stdin`.
The Agent executes only its registered Action. Source GET uses2025-07-01; disabled,
not-yet-valid, expired or mismatched SecretBundle blocks business dispatch.
Full token/value bytes remain unchanged; standard HTTP parsed representations
are also sealed. The current vault25 / policy6 candidate rejects incompatible older formats
without migration. Local fixtures/static review do not establish actual
Entra/RBAC/firewall/revocation acceptance.
See [the fixed Azure contract](superpowers/specs/2026-09-30-azure-secret-source.md).

## Fixed 1Password Connect field source (EXT-04, local verification pending)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Prepare the closed eight-field private onepassword-connect-source-v1 profile
from `2026-09-30-onepassword-secret-source.md`. The declared
local_use_expires_at_ms is Rekey's import-use deadline, not the provider token
expiry. Register with `rekey credential add-onepassword-connect LABEL --file
PRIVATE_PROFILE`; rotate with `rekey credential rotate-onepassword-connect
CREDENTIAL_ID --file PRIVATE_PROFILE`. Use hidden TTY or the existing explicit
--password-stdin proof. No token/value is permitted in argv or environment.
The Broker reads one fixed current item and one exact field with expected item
version, then uses its complete value only for the registered Action.
An item update needs explicit re-registration; matching Connect version does
not prove the synchronized item is cloud-latest. Private Connect, real TLS/READ
permissions/token revocation and synchronization acceptance remain pending.
Current vault/backup format25 rejects incompatible older layouts; no migration
or overwrite is attempted.

## Fixed two-node policy file box (ENT-01/02 local slice)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

`scripts/rekey-controlplane.py` uses one administrator-owned version1 registration
profile for exactly two nodes. Register real vault/node/signer IDs, canonical
trust document SHA, approval public-key SHA, absolute CLI/state/runtime paths,
admin UID, platform, audit/backup destinations and policy lifetime (at most5min).
The approval pin hashes the32 decoded key bytes; it does not hash pretty JSON.
Full closed fields and path/file ownership rules are in
[the fixed controlplane contract](superpowers/specs/2026-09-30-controlplane.md).

Use the independently reviewed signer artifacts without reformatting. Profile,
policy and trust files must be owner-only single-link regular files. A private
file box carries fixed node/command IDs and public receipts:

```bash
python3 scripts/rekey-controlplane.py publish --profile PROFILE.json --node NODE_UUID \
  --command-id COMMAND_UUID --policy policy.json --trust trust.json
python3 scripts/rekey-controlplane.py apply --profile PROFILE.json --node NODE_UUID \
  --command-id COMMAND_UUID
python3 scripts/rekey-controlplane.py status --profile PROFILE.json --node NODE_UUID \
  --command-id COMMAND_UUID
python3 scripts/rekey-controlplane.py reconcile --profile PROFILE.json --node NODE_UUID \
  --command-id COMMAND_UUID
```

For an OIDC-enabled node, add `--admin-session-file /private/path/session.token`
to apply/status/reconcile after completing that node login. The helper passes the
path to every CLI call; it never reads or records the token. Publish stays offline.
This caller wiring is locally tested. The complete TLS/loopback/UDS login and
node activation chain still requires real execution.

Apply locally under the registered node admin UID. Its pure CLI asks for hidden
step-up; the helper does not handle proof bytes. Publish is uploaded/unconfirmed.
Applied requires actual vault/root/version/bundle SHA/activation time and exact
committed activation audit. Readback is capped at25rows/page and10pages with one
fixed snapshot, plus64KiB per child output stream. Failed/absent readback, timeout
or receipt fsync stays unknown; preserve intent and use read-only reconciliation.
Do not resend an unknown command. CLI exit/code and activation confirmation are
reported separately: a CLI error can still accompany a verified commit.

Controlling TTY metadata is saved and restored after the owned activation child
exits or is killed. A synthetic PTY check does not prove terminal
restoration on the deployment host. Kernel filesystem stalls have no proven
hard45s wall limit. Actual hidden input and two-node/VM/UID/network/backup
isolation require separate field acceptance. No commit or release readiness is
claimed from fake CLI fixtures.


## OIDC node administrator login

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Register a public PKCE client on the exact issuer, with the exact fixed loopback
redirect URI on the same machine as rekeyd. Obtain the reviewed directory mapping
SHA from `rekey-approval-relay directory-registration --config PRIVATE_CONFIG`.
The subject/principal/node/vault below must match that reviewed registration and
the existing actual vault; these example UUIDs and hash are placeholders.
No discovery, confidential client, token refresh or remote browser callback exists.

Create an owner-only profile and explicit CA files (mode0600, regular files):

```json
{
  "format_version": 1,
  "issuer": "https://idp.example.test/realms/personnel",
  "client_id": "rekey-local-admin",
  "authorization_url": "https://idp.example.test/realms/personnel/protocol/openid-connect/auth",
  "token_url": "https://idp.example.test/realms/personnel/protocol/openid-connect/token",
  "jwks_url": "https://idp.example.test/realms/personnel/protocol/openid-connect/certs",
  "redirect_uri": "http://127.0.0.1:41745/oidc/callback",
  "ca_certificate_file": "/private/path/idp-ca.pem",
  "directory_identity_url": "https://directory.example.test/v1/directory/admin-identity",
  "directory_ca_certificate_file": "/private/path/directory-ca.pem",
  "directory_mapping_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "node_id": "11111111-1111-4111-8111-111111111111",
  "vault_id": "22222222-2222-4222-8222-222222222222",
  "administrators": [{
    "subject": "reviewed-idp-subject",
    "principal_id": "33333333-3333-4333-8333-333333333333"
  }]
}
```

Authorization/token/JWKS use the issuer's fixed HTTPS origin. Directory identity
uses its explicit CA and mapping pin; it must confirm the current subject's
explicit adminAllowed eligibility. Configure no proxy, redirect or ambient trust.
The directory's independently registered two nodes are eligibility bindings, not
hardware attestation or proof that both have applied policy.

```sh
rekeyd serve --state-dir /private/path/state --oidc-admin-profile /private/path/oidc.json
# In another trusted operator terminal, unlock using hidden proof:
rekey --state-dir /private/path/state unlock
rekey --state-dir /private/path/state oidc-login begin
# Open the returned HTTPS authorization_url manually on this same machine.
# Use the returned public flow_id; choose a NEW file in an owner-only parent:
rekey --state-dir /private/path/state oidc-login finish --flow-id FLOW_ID --session-file /private/path/admin.session
rekey --state-dir /private/path/state --admin-session-file /private/path/admin.session action list
rekey --state-dir /private/path/state oidc-login logout --session-file /private/path/admin.session
```

Cancel an unfinished login with `oidc-login cancel --flow-id FLOW_ID`. The original
login flow expires after120s. Finish writes the management token only to an
exclusive mode0600 file; stdout contains public principal/expiry/mapping fields.
Never print, copy into handoff files, or place its contents in argv/env.
Management validity is bounded by ID/access expiry and300s. Mutations still ask
for hidden step-up on every call, and every protected admission checks fresh
directory eligibility. Lock/drain/logout revoke local identity state.

Quickstart `prepare`, credential-repair and backup-sync `export` accept the same
`--admin-session-file` path. Agent `execute` and completed backup `sync` do not.
Service-unit `launchd`/`systemd` accept `--oidc-admin-profile`; this changes only
the generated serve arguments. Installing or restarting units is a separate
operator action. The metrics service/timer has no unattended OIDC refresh path;
its protected metrics operation cannot use a permanently stored short-lived login.

The current local test receipts do not prove full TLS/loopback/UDS or real IdP
login. See the canonical all-capabilities tracker for review and execution gates.


## PKCS#11 approval signing (development source)

Lab reference: use a source build with `--features lab`; this is not a default personal installation.

Use `rekey-approval-sign review` and `sign` with `--pkcs11-profile PRIVATE.json`
in place of the software key or Transit profile. Review the fixed module,
token and public-key identity, then sign with the exact reviewed digest.
The signer prompts for the token PIN on a hidden controlling terminal;
keep it out of arguments, environment variables and profile JSON.

The profile pins one module digest, token, key ID and Ed25519 public key.
A cancelled, expired or unknown device result produces no grant and is never
automatically retried. Follow the [fixed signer contract](superpowers/specs/2026-10-01-pkcs11-approval-signer.md)
for profile fields and private file requirements. Successful local contract
tests do not prove token compatibility, hardware nonexportability or driver
cleanup; validate those on the intended HSM before production use.


## Automatic audit retention (current source)

Choose an explicit age, inspect the current policy, or disable it:

```bash
rekey audit retention set --days 30
rekey audit retention status
rekey audit retention set --disable
```

Unlock explicitly before inspecting the authenticated policy. Setting and
disabling require the existing step-up prompt on every call.
For proof-only automation use `--password-stdin`; add `--recovery` for a
recovery-key proof. The background worker stores neither proof nor password
and never unlocks the vault. It checks the sealed policy about once a minute
while unlocked, preserves the original idle lock, and removes only eligible
complete execution groups older than the cutoff. Setting the policy does
not immediately delete rows.

The policy survives restart, backup/restore and VRK rotation. Disabled or
locked state pauses cleanup. Unknown replies or integrity failures stop the
broker; inspect the committed audit markers before taking further action.
One SQLite or OS call can exceed the cooperative deadline, so this is not
a strict maximum retention guarantee. Management and incomplete records,
old backups and physical remnants are retained. Older vault formats are
rejected without migration. See the [retention contract](superpowers/specs/2026-10-01-unlocked-audit-retention.md)
for deletion eligibility and local versus field acceptance.
