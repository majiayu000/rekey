# ENT-01/02 Fixed two-node policy distribution and target binding

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

Implementation contract frozen2026-09-30; Rust target/status, existing producers
and private file helper implemented locally. Strict PTY recovery remains unpassed
(66/67 root tests pass; actual setter EPERM); real two-node field acceptance is
unvalidated. Three new files total:
this specification, scripts/rekey-controlplane.py and scripts/test-controlplane.py.
Use existing typed policy IPC, Authority records/audit and independent signer;
no new opcode/schema, daemon, network transport, signature implementation,
remote unlock, shared-tenant Authority, automatic policy renewal or HA fencing.
A registered private file box transports two nodes' signed policies and receipts.
Physical VM/UID/network/backup isolation remains separately field-unvalidated.

## Minimal immutable target and status contract

POLICY_ACTIVATE metadata becomes the closed PolicyActivateMeta object:
expected_vault_id: VaultId, expected_trust_sha256: lower-case64hex,
bundle_json: raw signed policy JSON object preserved until the existing signed-
bundle unique-key parser. Do not first deserialize nested content into ordinary
serde_json::Value in CLI or Broker: that would silently remove duplicate keys
and break the existing rejection contract. Use the existing serde_json raw_value
feature/Box<RawValue> in the pure wire DTO (same JSON object on wire), with
closed outer typed fields and existing policy parser for nested uniqueness. This
adds no resolved dependency or crypto to CLI. CLI policy activate requires nonsecret
--expected-vault-id and --expected-trust-sha256 with --file; preserve each-call
hidden TTY/explicit --step-up-stdin proof. Reject naked old bundle frames without
a fallback. Update all existing producers/fixtures and native file flow.
Keep wire metadata<=64KiB; helper signed canonical bundle<=60KiB.

Expected trust digest uniquely means SHA256 of the canonical installed trust
DOCUMENT, not raw key bytes, RKPT seal material, timestamp or an optional
canonical buffer. Reconstruct existing PolicyTrustFile's exact four fields:
format_version=1, signer_id (canonical UUID), algorithm="ed25519", public_key
(lower-case64hex); existing serde_jcs encoding, no LF, then existing SHA256.
Fresh and restored roots derive it identically from immutable signer/key.
Add one pure rekey-policy helper and the existing workspace dependency edge
rekey-vault -> rekey-policy; no new resolved third-party dependency/cycle.
ValidatedPolicyTrust::from_parts currently has an empty canonical buffer and
must never use SHA(empty) as the target's trust digest.

Authority PolicyBundleInput carries expected target and checks actual header
vault ID plus immutable installed trust digest after step-up and before the
policy/audit transaction, including exact retry. Broker/CLI preflight alone
cannot prevent socket-target replacement. Keep existing signature verification,
strict first1/next+1/version mismatch, expiry, fault and cancellation contracts.
No caller-provided tenant string selects an Authority. Tenant is derived by
existing actual-vault UUID-byte mapping.

PolicyStatusResponse additionally exposes required vault_id and tenant_id from
the real Authority header, plus optional trust_sha256 and activated_at_ms from
verified immutable trust and persisted PolicyBundleRecord. Tenant uses the same
16 UUID bytes as the vault; it is not a hash/KDF or client-selected label.
Locked/faulted/unavailable state exposes actual public vault/tenant identity but
no root or activation details. Unlocked installed trust without an active bundle
exposes trust_sha256 (needed for first activation), with bundle details absent.
Active/expired
status requires the complete verified persisted details; expired never becomes
active on clock changes. Activation time survives restart/backup and exact
retry does not change it. policy.activated reason_code becomes
policy-activated:<version>:<canonical64hex_bundle_sha256> in the same transaction.
No additional audit table/credential field abuse or second signing algorithm.

## Fixed private registration and transport

Closed version1 profile: customer_id, registration_expires_at_ms, box_dir,
cli_path and nodes (exactly two). Each node includes node_id, vault_id,
state_dir, runtime_dir, admin_uid, platform, responsibility_domain, signer_id,
trust_sha256, approval_origin_sha256, audit_destination, backup_destination,
policy_max_lifetime_ms (positive and<=300000). Paths are absolute canonical
administrator registrations, no credentials. Root/vault/signer/node identities
are distinct between nodes; destinations/labels record administrator choices,
not permission/virtualization attestation. Target tenant is derived from vault,
not redundantly selected by the customer label.

BOX/nodes/N/commands/C/{command.json,policy.json} and receipts/C.json transport
one fixed UUID C per node. Each command binds profile/customer/node/vault,
registered signer/root, C, target version, canonical signed-bundle SHA and expiry.
Optional directory-event/mapping links remain unimplemented until ENT-03.
Approval origin pin means SHA256 of the exact 32-byte public key decoded from
the existing approval origin response lower-case hex; not JSON/file text.
The original independent signer supplies canonical policy and trust files;
this helper does not implement Ed25519/JCS or normalize arbitrary bundles.
No command chooses a new executable/state/node/socket/root. Profile authority
is the local administrator and protected box ownership, not self-reported JSON.

0700 directories, owner-checked0600 single-link regular files, component-by-
component no-follow/inode checks, exclusive lock, create-new immutable commands
and fsync publication. Bound profile/command/receipt<=64KiB, per-node journal
<=100commands/20MiB; capacity refuses new work. Preserve intent on receipt/fsync
failure. Reuse existing audit-delivery file patterns without creating a shared
transport framework or importing archive credentials/permissions.

## Commands and acknowledgment

Only publish/apply/status/reconcile, explicit --profile/--node/--command-id.
publish pins canonical signed artifact and reports uploaded/unconfirmed.
apply runs only at the registered local node under its admin UID; queries real
policy status and approval origin, checks pinned public target, persists intent
before mutation, then invokes fixed CLI with expected target. CLI itself prompts
for step-up; helper never reads, stores or forwards proof. One child at a time,
whole operation<=45s, stdout/stderr<=64KiB each, absolute executable, no shell,
ambient config, automatic retry or network implementation. Executable ancestors
must be root/admin-owned and prevent another UID from renaming path components
or the checked executable before launch. Non-sticky group/other-writable parents
are refused before child creation; a root-owned sticky system directory is
acceptable only with the remaining existing trusted-component/inode checks.
This is the fixed executable path boundary, not a new permission platform.
Preserve controlling
TTY for hidden step-up; terminate only this owned pure-CLI child on timeout.
For the activation child, open its controlling TTY read-only for termios
metadata (no proof byte read/write), preserve that metadata before launch and restore it after exit/kill+wait, including timeout while rpassword
is in raw/no-echo mode. Restore with unread terminal input discarded, without
reading, storing or forwarding proof bytes. A genuinely absent controlling TTY
cannot have been modified; other terminal capture/restoration failures must be
reported and cannot become activation confirmation. A proof-free synthetic PTY
checks actual raw-mode timeout restoration; it does not prove real user proof
entry or authorize touching the user terminal during tests.
Child timeout cannot prove Authority did not commit.
The45s budget is enforced at monotonic checkpoints and owned CLI waits; kernel
filesystem/fsync stalls are not proven to have a hard wall-time limit. The local
helper is not a claim of such field behavior.

After mutation, query actual status and existing paged audit list (fixed25rows
per page, <=10pages/250rows, fixed snapshot/cursor, same total deadline). This
keeps ordinary complete22-field pretty CLI audit pages within the unchanged
64KiB stdout cap. A larger record/page or missing matching event stays unknown;
do not enlarge output/deadline bounds or silently confirm without exact evidence. applied requires matching real
vault/tenant/root, target version/canonical bundle digest, persistent activation
instant and exact policy.activated event; receipt contains those public values,
C/node, policy digest, observed time and current active/expired status. Merely
receiving a success frame/upload/receipt file does not establish activation.
Known local predispatch rejection is rejected; any unconfirmed dispatched error,
child kill, missing/corrupt receipt or failed receipt fsync is unknown while
preserving original CLI exit/code. No closed provider/error-code rule engine.
reconcile only reads the same actual target/status/audit; it never resends mutation
or obtains a proof. Exact confirmed retry remains Authority's existing idempotence.
If current status no longer proves the requested version, report unknown unless
a prior verified durable receipt supplies historical confirmation; never infer
success from version>=target. Receipt readback may fsync that existing, verified
regular file descriptor and its verified parent before historical confirmation;
this changes no bytes, retries no mutation and obtains no proof. Failure remains
unknown with intent preserved. A merely visible receipt after failed fsync is not
a durable confirmation. Reusing C with different content rejects.

Independent nodes can be applied/unknown separately. Offline nodes retain only
still-valid old policy; expiry defaults deny. No directory ACL change or uploaded
file is a claim of Broker session revocation, all-node ACK, isolation or RPO/RTO.

## Local verification and field limits

Pure/actual Authority SQLite tests: wrong target/root before transaction, no
new audit on rejection; fresh/restored root digest equality; activation timestamp,
precise audit/backup, sequential version/idempotence and expiry; body-only proof.
Helper tests: wrong registration/target/root/origin, expiration, duplicate UUID,
ordering/partial failures, owner/symlink/hardlink/inode paths, capacity/fsync,
bounded child/output/timeout, commit-after-error, receipt loss/reconcile and no
second mutation. Fake CLI fixtures are test-only and do not prove real activation.
Compile all strict UDS/CLI/TLS and update existing native/signer tests; current
listener EPERM remains a real unpassed runtime gate. Full workspace required
before commit. Two real isolated nodes and customer ACL/VM/disk/network/backup
attack matrix are deferred; the local mapping contract is not field isolation.

Primary serialization reference: [serde_json RawValue](https://docs.rs/serde_json/latest/serde_json/value/struct.RawValue.html), inspected2026-09-30 for verbatim nested JSON transfer and raw_value feature. Use the existing locked serde_json version; no library upgrade.

Terminal metadata reference: [POSIX tcsetattr](https://pubs.opengroup.org/onlinepubs/009696799/functions/tcsetattr.html) and [Apple tcgetattr/tcsetattr](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/tcgetattr.3.html) describe terminal attributes on an open terminal descriptor, with no proof input/output. The local metadata restoration ioctl remains independently runtime-unvalidated when the host denies it.


## OIDC managed caller amendment (2026-10-01 before helper changes)

Existing apply/status/reconcile accept one explicit optional --admin-session-file
absolute path for the selected local node. Pass only that path to every invoked
rekey --admin-session-file argument; never open/read the management token in this
helper, infer a file, write it into registration/intent/receipt/journal, or change
profile format. Node/CLI remain the single trusted token-file and fresh identity
validation boundary. Publish is offline and has no login/file argument. Existing
step-up, deadline, target/root, immutable receipt and terminal cleanup contracts
remain. An unconfigured G1 invocation may omit the flag; an OIDC node then denies
managed operations. Actual child argv/no secret/no ambient environment regression
must pass; full protected Broker activation remains strict/field-unvalidated.
