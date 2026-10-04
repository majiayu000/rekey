# ENT-03 fixed OIDC node administrator login

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

Frozen minimum 2026-09-30 before implementation. Directory A and signed-policy
session revocation B are prerequisites, not a complete login. Pure ID-token
verification C1 below is the first serial implementation; C2 full authorization
flow/node session and C3 directory proof must follow before ENT-03 is complete.
No IAM platform, discovery, federation/groups, remote unlock, provider credential
export, automatic policy signing, ambient client secrets or backward migration.
At most four new files across C: this spec, policy/oidc_admin.rs,
broker/oidc_admin.rs, one existing-host contract test file if required. Reuse
current locked cached dependency versions and existing modules for wiring.

## C1 pure ID Token boundary (implement first)

New rekey-policy::oidc_admin narrow API verifies compact ID Token + fixed-source
JWKS bytes against a trusted issuer/client/expected nonce/current time and the
access token from the SAME completed code response (for at_hash when present).
It returns only verified issuer, stable subject and issued/expiry times; no token,
code, key material or capability. Use existing typed PolicyError variants and
unique JSON parser. No IO, provider adapters or configurable algorithm registry.
Public trusted context is explicit; do not treat a WorkloadIdentity/JWT or access
token introspection as an OIDC login result. Configuration validation belongs at
the trusted node profile boundary, not duplicated throughout helpers.

Compact JWS max16KiB, exactly3 nonempty canonical base64url-no-padding segments;
unique object keys (including duplicate unknown fields) reject. alg exact RS256,
kid required bounded nonempty; typ if present exact JWT. Reject none/HS/JWE,
crit/b64 extensions and jku/x5u overrides; no token-controlled key URLs.
JWKS <=64KiB,1..8 public keys, unique nonempty bounded kids; selected kid must be
one RSA public signing key, no private parameters, valid n/e,>=2048-bit verified
with existing aws-lc RSA/SHA256 primitives. Optional use must sig, alg RS256,
key_ops only verify when supplied. Unselected legitimate other-alg rotation keys
may be ignored, but duplicate/ambiguous kids reject. Unknown kid fails; no fetch
or key refresh in this pure API. Reuse existing low-level helpers narrowly if
necessary without renaming/rewriting unrelated Workload contracts.

Signature verification is mandatory before identity is returned. iss exact fixed
issuer; sub nonempty stable <=512 UTF8 bytes/no controls; aud string or unique
1..8 string list contains fixed client. Multi-aud requires azp=client; present azp
always equals client. exp and iat required integer seconds with checked ms
conversion, iat<=now<exp and exp>iat; token age<=300s. Optional nbf integer<=now
and nbf<exp. Nonce required exact expected nonempty flow nonce. If at_hash present,
verify canonical base64url of leftmost16 SHA256(access-token) bytes, matching
RS256. No refresh, clock-skew/claim-alias settings or permission inference.
Session lifetime later is min(ID/access expiry,300s) and separately monotonic;
this validator never mints a management identity or Node session.

Actual synthetic RSA signed tests must prove positive single/multi audience,
key rotation on newly supplied JWKS, at_hash, changed signing input/signature,
wrong issuer/aud/azp/nonce/kid/algorithm/keys, duplicate keys/claims, missing or
wrong typed time/nonce/sub, age/expiry/nbf/overflow, segments and byte/key caps.
No unsigned fixtures counted as verification. Pure tests need no listeners,
credentials or network; retain RED/GREEN and exact source hashes. Existing
Workload/JWKS verification regressions run if low-level helpers are touched.

## C2/C3 full node login contract (still pending)

Broker owns public-client authorization code+state/nonce/PKCE S256 and at most8
single-use120s flows bound to actual UID/node/vault/config. CLI remains pure IPC,
prints authorization URL for manual browser use and persists returned opaque
management token to an explicit0600 nofollow private file, never argv/env/metadata.
Fixed same-host127.0.0.1 port and /oidc/callback only, exact Host/path/method/state,
bind before URL, <=8KiB callback, no port/address fallback. Code exchange/JWKS
fixed explicit HTTPS endpoints/CA, no proxies/redirect/retry, one original deadline;
flow is consumed before token IO. Cancel/lock/drain clears secrets and no late
management token may appear. This local callback doesn't support headless remote
nodes with a browser on another machine; HTTPS relay code handoff is separately
unimplemented, never implicit alternate mode.

OIDC-enabled node needs one strict protected profile containing fixed issuer/
client/authorize/token/JWKS/redirect+CA, actual node/vault, pinned directory
mapping digest and explicit confirmed admin issuer+subject->principal mapping.
Keep ordinary G1 deployment distinct from enabling this identity gate. Public
client PKCE only; confidential-client registration is not silently supported.
Returned management session <=32 opaque hash-only tokens, bound UID/principal/
vault/mapping, min(ID/access expiry,300s)+monotonic. Token frame-body envelope
protects managed Admin dispatch; SESSION_CREATE uses verified principal. Local
init/serve/restore, unlock/lock, minimal passive health and begin/finish/cancel
remain OS-boundary operations; exact operation IDs/body envelope/audit wiring
will be frozen before C2 implementation. No Agent operation or Vault format change.

Directory must explicitly grant administrator eligibility (not infer from
approver/uploader). One fixed fresh authenticated self-only HTTPS identity proof
from the existing relay Store transaction binds issuer/subject/principal,
confirmed mapping digest and registered node/vault. Node fetches that trusted
source on login and every managed admission, not CLI-supplied JSON, and polls
active management identities within30s under bounded IO. Unknown/stale/offboard
closes admission and revokes managed/explicitly-bound sessions/pending; no inferred
random Admin principal ownership, no already-started-effect cancellation. Logout
is local Rekey logout, not IdP global logout. Authority commits nonsecret identity
result/audit before returning token; audit failure fails closed. Node receipt must
reflect actual apply/revocation counts; directory pending is not automatically ACK.

Protocol sources: [OIDC ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[PKCE S256](https://www.rfc-editor.org/rfc/rfc7636.html#section-4),
[OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1),
[native loopback](https://www.rfc-editor.org/rfc/rfc8252.html#section-7.3).
Actual IdP registration, browser callback reachability, two isolated node
revocation latency/offline windows, strict TLS/UDS/PTY and full workspace gates
remain unvalidated. C1 unit success must never be presented as complete ENT-03.

## C3 relay self-proof prerequisite (parallel with pure C1)

Directory config/store stays unreleased format2. Each existing confirmed Link gains
required boolean adminAllowed (no default/backfill); true is explicitly approved
node administrator eligibility, never inferred from uploader/approver, SCIM roles,
names, domains or groups. Include this flag in the existing directory mapping
digest/private store binding. All mapped subjects with adminAllowed may use fresh
introspection, but ordinary upload/inbox/recipient ACLs do not widen. At least one
explicit admin link; <=32 members total, stable issuer/sub and principal unchanged.
Admin subject can be distinct from uploader/approver and then has ONLY self-proof
access, unless separately configured in an existing transport role.

GET /v1/directory/admin-identity (no query/body or arbitrary subject selector) uses
fresh existing token introspection, exact adminAllowed mapping, SAME Store mutex
and SQL transaction directory gate, token/deadline recheck and nonsecret audit
commit before bytes. Active nonadmin403, disabled403/uncertain503 as current gate;
never return another user's identity. Bounded closed camelCase proof fields:
formatVersion=1,issuer,subject,principalId,mappingVersion,mappingSha256,nodes (two
registered nodeId/vaultId objects), observedAtMs (actual source result received
wall instant). Source freshness remains monotonic on relay, not recreated from
this timestamp by nodes. No token/fingerprint replacement/private keys or node
ACK. Proof is only current eligibility; each node still requires its trusted
profile/mapping pin, actual UID/vault and actual C2 token/session gate.

Add one offline existing relay CLI entry directory-registration --config FILE:
validate owner-protected profile and emit only public formatVersion,mappingVersion,
mappingSha256,nodes; read no source token/TLS private key, open no store/listener,
perform no network. This gives operator a reviewable mapping pin before node
registration; it is not a running source-freshness or administrator proof. No new
secret/profile store or mode-selection engine. Existing source fixture/caller and
operator profile examples receive mandatory adminAllowed explicitly.

Tests preserve13 A units plus real store role separation/own identity/uncertainty,
false tombstone/restart, auditfailure failclosed, bounds and digest-role binding.
Extend existing strict TLS fixture; compilation only under known bindEPERM,
no repeated permission bypass or fake runtime-pass. C1 and C3 own disjoint files;
full C2 depends on their stable API/actual source SHA integration.


## C2 frozen wire, admission and owner contract (2026-10-01 before code)

One new protected Node profile, enabled explicitly by rekeyd/rekey serve
--oidc-admin-profile FILE; no environment/discovery/client-secret registration.
Closed snake_case fields: format_version=1, issuer, client_id,
authorization_url, token_url, jwks_url, redirect_uri, ca_certificate_file,
directory_identity_url, directory_ca_certificate_file,
directory_mapping_sha256 (lowercase64hex), node_id, vault_id,
administrators (1..32 unique subject/principal_id pairs). issuer exact HTTPS;
three IdP endpoints same issuer origin with fixed nonempty paths, no userinfo,
query or fragment. Directory endpoint exact /v1/directory/admin-identity, HTTPS,
no query/fragment/userinfo. Explicit configured CA only, no ambient roots,
proxies, redirects or retries; fixed host/port under bounded original deadline,
resolve once per request and pin the resolved addresses, with no token-controlled
URL. Registered private HTTPS is allowed because these are trusted control-plane
endpoints with explicit CA, not Agent Action egress. Redirect exact
http://127.0.0.1:nonzero-configured-port/oidc/callback. Profile and CA reads follow
current private owner/nofollow/bounded file contracts. At startup compare actual
Authority vault_id before exposing sockets. node_id is the administrator-assigned
registration in the protected profile, not a hardware identity attestation.

New admin message IDs: 45 OIDC_LOGIN_BEGIN,46 OIDC_LOGIN_FINISH,
47 OIDC_LOGIN_CANCEL,48 OIDC_LOGOUT. Begin empty request returns public flow_id,
authorization_url,expires_at_ms (URL necessarily carries OAuth state/nonce/PKCE
challenge; never log it). Finish/Cancel metadata only flow_id; no supplied code,
redirect, issuer or identity. Finish waits only remaining original120s; successful
response metadata has stable principal/expiry/mapping, body only management token.
Logout body only management token, no directory IO needed to close own identity.
The fixed loopback listener is owned by the manager, with at most8 pending flows
on one configured listener and no fallback; bind must finish before Begin returns.
Callbacks accept one GET with exact Host/path, no body, <=8KiB headers+target,
unique query parameters, required state/code or fixed error handling, optional
iss exact issuer; unrecognized unique OAuth parameters ignored. Consume flow
before exchange. Reply generic text, no code/issuer/token echo. Total callback,
exchange, JWKS, directory proof and audit uses original flow deadline. Exchange
one bounded form POST code+client_id+redirect_uri+verifier; parse unique closed
required access_token,id_token,token_type=Bearer,positive integer expires_in,
allow standard unrelated response fields. Maximum64KiB response, IDtoken16KiB,
access token <=8KiB/no control bytes. No refresh token retained or used.

Managed Admin request body: ASCII RKAU followed by byte0x01, big-endian u16
management-token byte length (exact43 canonical base64url-no-pad bytes decoding
32bytes), those token bytes, then original operation body unchanged. Maximum
additional50bytes; validate in Domain codec, parse once at trusted dispatch gate,
then original typed proof/secret decoder. Token never metadata/argv/env/log.
Configured Node requires this envelope for every existing managed operation.
Explicit OS-boundary exceptions ONLY IDs1,2,3,15,16,31,34,36 and new45..48:
status/passive status, password/recovery unlock, lock/shutdown, desktop
login/resume (local unlock/bootstrap only, never mint OIDC management identity),
and the four login lifecycle messages. Existing shutdown/local proof semantics
remain. All remaining IDs including Metrics, PolicyStatus, credential/action
lists, approvals, desktop reveal/add/remember, policy/audit/key/source operations
are protected. Unknown operation remains typed invalid input. Without enabled
profile ordinary current G1 remains; management envelope on unconfigured node
is rejected rather than stripped. No mutation bypass based on CLI visibility.

CLI global --admin-session-file FILE passes only a private file path, applies
body wrapping centrally only to managed Admin messages; Agent channel unaffected.
OIDC login begin/finish/cancel/logout commands are explicit, finish --session-file
NEWFILE writes create_new+nofollow0600 in existing private parent, fsync before
success and never print token. Logout reads explicit private session file and
returns nonsecret outcome; no automatic file overwrite/relogin/refresh. Finish
response timeout honors original flow lifetime rather than ordinary30s CLI IO.
CLI dependency graph must remain pure IPC; no HTTP/crypto/SQLite added.

At login C1 verifies real RS256 IDtoken against this flow nonce/client/issuer and
same access token; fetch current fixed JWKS once. Profile exact subject/principal
and fresh C3 HTTPS self-proof must all agree with issuer/sub/principal/mapping pin
and both node registrations, including own configured node_id/actual vault_id.
Self-proof <=4096bytes unique closed JSON, format1, positive mappingVersion,
valid observedAtMs; that wall timestamp is never used as a new freshness lease.
Session <=32, random32byte opaque token stored SHA256-only; access token separately
Zeroizing Node-memory for directory checks, no persistence. Bound current owner
UID, principal, actual vault, profile/mapping and monotonic+wall expiry=min(IDtoken,
code-response access expiry,300s). Restart/config replacement clears all state.

Every managed operation first performs fresh fixed C3 lookup within original25s
operation budget, <=3s per proof; no cached CLI identity. A successful lookup then
atomically rechecks current session generation/deadlines/manager lifecycle at
admission before dispatch, so logout/poll/lock during IO cannot admit late work.
Already admitted effects retain existing termination semantics. For minting,
recheck identity when publishing the new capability under manager ownership; a
closed generation must revoke an unpublished mint and never return its token.
SESSION_CREATE uses verified principal instead of random principal and clamps
capability expiry to remaining management lifetime. Logout/unknown/offboard/
expiry closes all local management identities of the explicit mapped principal
before revoking its capability/pending entries; return actual revoke counts,
never cancel already-started upstream. Workload principal binding exists ONLY
when signed policy explicitly has the configured exact OIDC issuer/sub/principal;
nonhuman unrelated principals remain unchanged. For such explicitly bound humans,
Workload mint requires a live fresh managed identity and clamps expiry likewise;
no active identity means deny, not revival after offboarding. If shared principal
exists it is the explicit authorization identity, not guessed ownership from a
random Admin principal. No automatic policy signing/application or relay node ACK.

Background check active identities every<=30s, at most32 principals, <=4 concurrent
fixed proof IO, <=3s per request/10s batch; incomplete/unknown closes affected
identity. Lock/drain/shutdown/fault clears flows/listener/source access tokens and
management identities before admission may reopen. Cancellation/generation checks
prevent late exchange/audit completion from resurrecting state. No timing claims
about actual two-node offboarding until strict real topology tests pass.

Use existing Authority commit_audit_before/AuditDraft, no new VaultCommand/schema.
Nonsecret login success/failure, logout/offboard/expiry outcomes use truthful
stable principal/profile mapping/node/count reason fields; no fake policy/rule
AuthorizationEvidence to satisfy SQL checks before first policy installation.
A bare principal audit column is not populated without genuine policy evidence;
stable public identity registration is linked in reason_code. Success audit must
commit before management token is installed/returned. Audit failure faults/closes
manager and existing Broker admission; preserve Authority typed errors. No code,
ID/access/management token, nonce/verifier, raw upstream error or credentials in
logs/audit/output. Strict full-chain TLS/loopback/UDS remains compile-only on this
host; pure codec/state/proof/real-Authority audit tests must execute meaningfully.

C2 writer owns only necessary Broker module/runtime/bin/IPC/session/lifecycle,
Domain IPC DTO/body codec, pure signed-policy human binding method if required,
CLI main/commands/client and necessary existing test constructor updates. One new
Broker oidc_admin.rs plus at most one contract test; total C new files<=4. Root
alone owns docs, helper/native callers/release wiring and integration. No new
dependencies, store format, provider adapters, SDK/framework or speculative knobs.


## Existing macOS caller wiring (root ownership, frozen before edits)

Reuse CLI subprocess boundary, existing model/settings/test files, no new files,
Keychain reads or native HTTP client. Optional administrator-selected protected
Node profile path is passed to serve. Optional explicit management session file
path is passed centrally to CLI; app never reads/stores/displays token bytes.
Settings exposes Begin (manual open HTTPS authorization URL), Finish with explicit
new protected output file, Cancel, local Logout and selecting an existing session
file. Existing CLI flow_id/public expiry/profile mapping response is decoded; no
raw code/token handling or browser automation. Runtime generation/workspace/flow
revision recheck suppresses late completion after cancel/workspace/lock; captured
old-node result cannot change current workspace. Full clicks/TLS/UDS/IdP remain
unpassed. Socketless real child argv/no token/environment and stale-completion
checks plus full App compile are required; no Keychain test run. Existing desktop
remember is skipped until managed login when the explicitly selected profile is
enabled, because it is itself a protected operation. Local unlock remains separate.


### 2026-10-01 C2 review corrections (before fix implementation)

Begin must hold the existing lifecycle coordination ownership from its Running
check through manager flow insertion. Lock/drain/shutdown use the same existing
ownership; a Begin suspended before ownership cannot insert across a completed
lock. Do not add a new lifecycle layer.

Retain the monotonic access-token expiry from exchange-start Instant plus the
validated expires_in. Installation clamps to that original deadline, the ID-token
monotonic bound and the existing 300-second bound; wall-clock rollback during
exchange/JWKS/proof must never extend access validity.

The original flow/batch budget still bounds IO and successful admission. Before
terminal failure audit, consume the failed flow or atomically close affected poll
identities. Terminal failure audit then gets a separate bounded three-second
budget, including ordinary deadline expiry. Never skip its audit: real audit
commit/timeout failure retains the existing whole-Broker fail-closed contract.
No success or admission receives a renewed budget.

Successful identity publication and removal of its exchanging flow are one
manager-owner decision. Cancel either wins before publication and prevents it,
or loses after completion and returns the existing typed denial; it cannot
report cancellation while leaving an installed identity live.


### 2026-10-01 existing operator caller propagation (before implementation)

The existing quickstart prepare, credential-repair and backup-export operator
entry points accept an optional --admin-session-file path and prepend that public
path to each relevant CLI invocation. They never open/read/copy the token file.
Agent execute, handoff files and backup transport never receive this argument.
Keep each caller's existing proof/TTY/error behavior; let the CLI enforce the
private-file boundary without resolving the token path through symlinks.

The existing launchd/systemd daemon generator accepts --oidc-admin-profile and
emits that public path as one quoted argument to rekeyd serve. Preserve the
literal profile path for the Node's nofollow boundary. Metrics service/timer
reject this daemon-only option. Configured OIDC protects metrics opcode37; its
short-lived interactive management identity does not authorize an unattended
metrics daemon or refresh mechanism. No additional auth abstraction or files.
