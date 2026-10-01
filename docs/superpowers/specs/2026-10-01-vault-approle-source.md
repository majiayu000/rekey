# VEX-02: one execution-scoped Vault AppRole login

Status: local implementation and focused acceptance complete; independent source review collected. Full workspace and provider acceptance remain unpassed. This is the VEX-02 slice in `2026-09-16-external-capabilities.md`, after VEX-01 and EXT-06. Provider acceptance remains deferred by the user.

## Minimal scope

Reuse `VaultKvV2Source`, its existing protected add/typed-rotate IPC and current format20. Select one closed profile marker `vault-approle-kv-v2-source-v1`; it is an explicit alternative to the existing static-token marker, never an authentication fallback. No new credential kind, opcode, format, dependency, database table, global auth engine, endpoint discovery or token journal. Expected changes are about five existing production modules plus existing focused tests; no new production layer/config surface.

Required fields: `credential_type`, fixed `origin`, `auth_mount`, `role_id`, `secret_id`, `secret_id_expires_at_ms`, and existing `mount`, `path`, `key`, `version` (positive exact integer or literal `latest`). Optional `source_endpoint` has the VEX-01 closed exact IP/CA contract. Reject unknown/duplicate fields, explicit null, empty or unsafe mount/path/header values, mixed static-token fields and expired SecretID before sending login. RoleID/SecretID remain encrypted profile/body data; Rekey-owned copies and login JSON are Zeroizing. No argv/env/metadata/Debug/audit disclosure. RoleID/SecretID bounds reuse existing bounded source/header/profile conventions.

Fixed login: POST `/v1/auth/{auth_mount}/login` to the profile origin, body containing only `role_id` and `secret_id`. Use a harmless static accept header in the existing mandatory auth-header slot; do not change global UpstreamRequest to optional auth. Login/read/revoke all use the same public or VEX-01 private source transport; target business Action keeps its existing public restrictions.

Protocol references: [AppRole login](https://developer.hashicorp.com/vault/api-docs/auth/approle#login-with-approle), [revoke-self](https://developer.hashicorp.com/vault/api-docs/auth/token#revoke-a-token-self). No renew-self, Kubernetes/OIDC login, Namespace or extra engine is selected here.

## Effect, acquisition and ownership

Persist execution.started before decrypting; commit login.started before login IO. Recheck original absolute Action deadline and SecretID expiry at the actual first-poll send gate. Once login IO is admitted, SecretID uses/token creation may have happened. Do not retry login automatically, including response loss.

Capture all valid bounded complete `auth.client_token` candidates from an available bounded response before status/schema/TTL/reflection validation or any result-audit await. Duplicate/malformed complete responses cannot proceed, but known candidates must still be revoked at the fixed origin. No ad hoc substring token guessing. A truncated/unavailable body or transport timeout without a complete token is explicitly login-unknown/cleanup-unconfirmed; the existing buffered transport does not prove retention of partial chunks. Do not enlarge the global response contract or claim cleanup of an unknown identity. If a complete response is available after a late await, retain known candidates before converting the stage to timeout.

Accept only a single nonempty header-safe service token and finite positive, checked actual lease_duration. Calculate conservative token expiry from login request start + returned TTL; token lifetime must cover the remaining original Action deadline including the cleanup reserve. Reject missing/zero/overflow TTL, wrong token type or inadequate remaining life before KV/business. SecretID expiry governs admission, not renewal of the acquired token. Rekey does not configure periodic tokens or renew this token. Provider role policy/ACL and truly bounded natural expiry require field acceptance.

Login result audit is deferred until token candidates are owned, including for the private source wrapper. Preserve typed audit errors: real audit faults remain fail-closed, healthy deadline timeout must not be relabeled an audit commit fault. Safe audit data only includes stage/outcome, actual Authority credential ID/version, source binding/selected IP, finite expiry evidence and request/Action identity; never token/accessor/raw provider response.

## One read, one business Action, cleanup

Use the token for one fixed KV read, retaining existing exact/latest metadata validation and actual Vault-version audit. Seal RoleID/SecretID/token and their decoded representations across source errors, business headers/body and cleanup; the expected client_token field is consumed internally, never forwarded to the Agent. The selected KV value is consumed once by the existing fixed-header/sealing path.

Hold the sealed business response until known token(s) are cleaned up. POST `/v1/auth/token/revoke-self` with each exact known token, fixed origin/source binding and original remaining cleanup deadline. Only an explicit valid empty successful revoke response and successful cleanup/terminal audits confirm cleanup. Failure/timeout/403/reflection/ambiguous response or audit failure cannot release cached business success.

Track cleanup ownership separately from the ordinary HTTP remote-effect marker. Revoking the login token does not undo a business request or invalidate the fetched long-lived KV secret. On cancel/lock/drain, stop local business IO, await bounded known-token cleanup and preserve whether ordinary business IO was admitted. A sent business request without complete response remains indeterminate even when revoke succeeds. Login unknown is nonretryable indeterminate; denied-before-login preserves existing safe pre-effect errors. Cleanup failure after business admission is nonretryable indeterminate, never retryable upstream failure. Existing static KV error behavior remains unchanged.

No acquired token persistence/restart revocation promise: process death may leave a provider token, bounded by actual provider TTL/parent/ACL. Unknown login has no observed TTL; record uncertainty and require provider inspection rather than fabricate expiry.

## Local acceptance

Closed profiles, expiry/checked TTL, exact/latest single read, one login, duplicate token cleanup, reflection, invalid/missing/service-type TTL, rejection, response-loss/no retry, every acquisition/result/cleanup audit gate and typed errors. Deterministic fake transport + real Authority/SQLite cover ordering, cancellation before/during business and cleanup success/failure. Root rechecks integrated sources; independent reviewer verifies code and frozen SHA. Strict public/private TLS, UDS/TTY, real Vault minimal ACL/SecretID uses/natural expiry/revoke remain separate unpassed field gates. No full workspace/release/HA claim follows from focused tests.

## SDK lifecycle declaration supplement (before SDK edits)

The existing `vault-kv-v2-source@1` contract declares the union of its two closed profile capabilities, ordered `[Exchange, Lease, Resolve, Inject, Revoke]`, ProviderDefined exchange and revoke-before-success for acquired temporary tokens. A static-token profile acquires no temporary token and has an empty cleanup obligation; its existing execution/error behavior remains unchanged. No new kind/connector/opcode/contract schema/lifetime field, profile discovery or generalized runtime stage enforcement. Other cloud sources keep their existing shared Resolve/Inject declaration. Broker selection uses only kind/action and does not consume these fields; testkit verifies lease/revoke ordering and exchange metadata. One existing SDK source file plus its existing contract test is coordinated by root separately from the worker7files; total five production modules, zero new files. Current registry has ten built-ins including macOS Keychain, so the stale integration-test count9 must be corrected.

Current acceptance (2026-10-01): worker69 qualified unique IDs and root executor188/SDK19 PASS; independent9SHA review no confirmed P0/P1/P2. Root broader targeted266 PASS/one runtime Unix socket bind EPERM FAIL, not a full-suite PASS. Initial parallel raw failure was overwritten by the worker; actual excerpts remain and requests1vs2 root cause is unconfirmed. Root corrected two separate provider test-only stale format19 assertions, with independent supplemental review. See `approle-integrated-final-acceptance.json`.
