# ENT-03 / APR-10 fixed SCIM consumer and signed roll-forward revocation

Frozen 2026-09-30 before implementation. This slice is not full OIDC administrator
login, a SCIM provisioning server, automatic policy signing/unlock, or verified
customer offboarding. Existing fixed introspection remains the relay identity
boundary. The minimal addition is one relay directory block, one existing-store
extension and one new Rust module; this spec is the only other new file. No new
crate/package versions, Vault schema/AAD, policy/grant signature format, daemon,
provider abstraction, group permission logic or recovery mechanism.

## A. Fixed directory consumer

Relay config and private SQLite store become format 2, breaking: reject nonempty
v1 state, never migrate or reset it. Required camelCase directory block:
baseUrl (fixed HTTPS SCIM base, no credentials/query/fragment), caCertificateFile,
accessTokenFile (private JSON accessToken + expiresAtMs), mappingVersion (positive
integer), nodes (exact two distinct canonical nodeId/vaultId pairs), links (1..32).
Each link: sourceUserId (one safe resource path segment), externalId, issuer,
subject, principalId (canonical UUID), optional approverId and publicKeySha256
(both or neither, lower64hex), confirmedBy (stable ID), confirmedAtMs.
For the subsequent OIDC self-proof prerequisite, the unreleased format2 Link
adds mandatory adminAllowed as frozen in 2026-09-30-oidc-admin.md C3; A-only
initial fixtures do not constitute complete administrator login.
Single issuer equals existing idpIssuer. Issuer+subject, sourceUserId, externalId,
principal and approver IDs are unique. Every configured uploader/approver has one
confirmed link; approver ID matches existing ACL. No email/name inference or keys
from SCIM. Configuration approval binds this fingerprint; actual policy-key
matching and node policy rollout remain independently reviewable work.

GET only baseUrl/Users/{registered sourceUserId}; explicit private CA, no proxy,
redirects, ambient token or refresh. Token is secret and never logged/returned;
explicit expiry checked before and after IO. 30s polls, <=4 concurrent requests,
3s per request, 10s original batch deadline, <=64KiB response, no retries. Startup
must perform the first batch before accepting admissions; uncertain members
remain closed, no successful member refreshes another. Every polling result
updates that member: exact id/externalId and User schema plus explicit bool active
required; duplicate JSON keys reject, unrelated SCIM fields ignored, no value/body
logging. active=false or authenticated source 404 creates durable one-way
tombstone. 401/403, timeouts, mismatched identity, invalid JSON or 5xx mean unknown,
not confirmed deletion. Later true never restores a tombstone. No automatic
restore/config replacement revival. Existing exact config binding rejects changed
mapping on the same store. Authoritative references: [SCIM resource IDs and active](https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.1),
[fixed resource retrieval](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.1).
This is a stricter registered-resource consumption contract, not full SCIM support.

Keep subjects and revocations in existing single SQLite owner, STRICT/FULL/WAL.
Confirmed mapping digest and tombstones persist; volatile monotonic per-member
freshness does not survive restart. Successful active result <=60s and unexpired
source token required at admission. Unknown result immediately closes that member
until a new valid result. Poll IO outside store lock; commit rechecks configured
mapping/source. Any directory apply/audit/commit failure sets the relay fault
while the same Store mutex is STILL held, before another admission can acquire
it; no old fresh cache may cross that failure-to-fault interval. GET/PUT/inbox admissions recheck
member gate in the SAME transaction that reads/updates/commits returned bytes,
including relevant configured uploader/recipient for transferred files. Never
check only before awaiting introspection or request body.

Tombstone, source-resource/body SHA (404 uses fixed absent marker), received/applied
wall time, stable identity, mapping version, affected existing request IDs, two
node pending records and nonsecret directory audit commit in one transaction.
Repeated false is idempotent (no new event/reset timestamps); don't prune tombstone
with 24h transport retention. Bound durable directory events by registered members
(<=32 events; affected requests bounded by existing4096). Storage error ->503+
relay fault, no successful offboarding receipt. No host-root/wholeDB rollback claim.

GET /v1/directory/revocations uses existing fresh introspection and exact configured
uploader authorization, but must remain available to that operator to inspect
revocations only while THEIR directory gate is active. <=32 metadata receipts,
<=64KiB response, no SCIM body/token; IDs may be capped with explicit truncated
count to preserve output bound while durable event retains affected IDs. Other
subjects get403 without enumeration. Each node starts pending; never claim local
Broker policy/session revocation from directory state or this transport receipt.
No ACK-write endpoint yet. Node reconciliation/signing integration follows.

## B. Existing Broker policy roll-forward

When a signed policy truly changes an existing active policy to its next version,
revoke_all in-memory Admin and Workload sessions plus pending approval state via
existing SessionRegistry semantics. First activation retains current behavior
(revoke Workload only); exact retry retains every session and original activation
instant/audit. Capture whether an existing policy was present before Authority
mutation; use the same distinction on timeout reconciliation when the exact
target is actually active. Wrong target, step-up/verification failure or failed
Authority transaction must not revoke healthy sessions. Preserve typed error and
fault behavior. No new personnel session inference (ordinary Admin principals
remain random), no new IPC/session table or cancellation of already-started
upstream effects. Conservative revocation affects other roles too; new sessions
must be re-created under current policy. This is the required node prerequisite,
not evidence that SCIM changes have been signed and applied to both nodes.

## Ownership and verification

A owns relay src/main.rs,auth.rs,relay.rs,new directory.rs and existing
relay_contract.rs. B owns broker runtime/admin.rs and its inline tests, and only
if needed existing session.rs/session/approval.rs and approval_contract.rs.
Separate frozen copies/targets; no shared writes, manifests or spec edits. Root
owns docs, caller configs, CI, archive and final source SHA integration.

A parser/config/store tests must run without listeners and cover exact mapping,
false->true, repeated false, restart freshness, transaction race, wrong/missing
identity, failed audit/commit, per-subject uncertainty, bounded receipts and no
secret output. Existing real TLS harness extends SCIM source and exercises fixed
CA/path/status/timeout/no redirect/token expiry; compile these strict cases when
host listeners are denied, retain actual gate as unpassed, never skip/weaken it.
B uses real Authority SQLite/signature and actual sessions to prove first install,
roll-forward, exact retry, failure and timeout reconciliation, old pending/grants
rejected and expiry latch retained. Full workspace gate remains required before
commit; current host bind/ioctl denials are not a pass or bypass authorization.

Remaining: signed offboarding-material/node apply+precise receipt chain, full OIDC
admin state/nonce/PKCE/login/logout, explicit manual mapping restoration, actual
IdP and two isolated nodes, observed latency/offline policy window. Claims stay
bounded until those are implemented and verified separately.
