# OAU-02 fixed Keycloak standard token exchange

This source contract adds one built-in `keycloak-token-exchange@1`. It is not
arbitrary OAuth, GitHub ID-token federation, refresh, discovery, or a signer.
The Agent keeps ExecuteFixedHttpAction and never receives a provider token.

## Stored profile and Admin boundary

`credential_type=keycloak-token-exchange-v1`, `origin`, `realm`, `client_id`,
`client_secret`, `subject_token`, `audience`, `target_origin`, `target_path`
are the only fields of one encrypted profile. Both origins are canonical HTTPS;
realm is a 1..100 ASCII path segment (letters, digits, dash, underscore).
Client ID and audience are 1..128 ASCII letters/digits/dash/underscore/dot.
Client secret and subject token are 16..16384 non-whitespace printable ASCII bytes, including JSON-escaped quotes
and backslashes. Whole
profile is bounded by the existing 64 KiB Admin limit. No secret in argv/env,
metadata, logs, audit, or Agent output. Add/rotate use an owner regular profile
file and existing hidden-TTY/explicit password-stdin step-up. Generic rotation
rejects this typed credential; only typed rotation accepts a validated replacement. Operator supplies a fresh subject
token when it expires; issued tokens are never persisted or refreshed.

Credential kind `keycloak-token-exchange` uses AAD numeric code 5. Database
format changes from 9 to 10, including its kind CHECK and schema digest.
Old state and backups are rejected, never migrated or overwritten. Existing
AAD codes and binary AAD format stay unchanged.

## Fixed execution

Action must exactly equal the profile target origin/path, GET with no body,
content type or extra headers, and authorization prefix `Bearer `. Its timeout
is at least 2000 ms. Policy/schema authorization and execution.started commit
before credential preparation. Profile mismatch fails before remote IO.

Broker POSTs `/realms/{realm}/protocol/openid-connect/token` with confidential
Basic client authentication (form-encode client ID and secret separately before
Base64 per RFC6749 section 2.3.1) and RFC8693 form fields: fixed grant type,
subject_token, access_token subject/requested type, and one fixed audience.
Only Keycloak Standard V2 same-realm exchange is supported. No user-supplied
endpoint/form fields, actors, refresh tokens, scopes, or resource parameter.
Origins use the existing public-IP screened HTTPS transport: no redirects,
proxy environment or local-address exceptions. Source response cap is 64 KiB.

Require HTTP 200, one unescaped printable access_token of 16..16384 bytes,
`token_type=Bearer`, `issued_token_type=urn:ietf:params:oauth:token-type:access_token`,
integer expires_in in 1..300, and no refresh_token. Reject duplicate known
fields. Other Keycloak public fields are discarded. TTL bounds resource IO;
500 ms of the absolute Action deadline is reserved for cleanup. A real provider
must be configured for the fixed audience, short lifespan and no default scope
widening. The resource server validates its audience; Broker does not treat
unverified JWT decoding as cryptographic validation.

Reject source-response body or headers reflecting the client secret, subject token,
or existing Basic/sealing transforms before any resource IO, while still cleaning
up captured candidates. Subject and issued tokens must be independent.
Use the issued token for the one fixed GET. Capture issued tokens before status
and schema checks; on malformed responses attempt cleanup for up to four unique
plain ASCII `access_token` values, even on non-200. Escaped token strings,
unreadable/truncated bodies, more than four candidates and process crashes are
outside guaranteed cleanup; fail indeterminate and provider expiry is the bound.

Directly POST every captured issued token to the fixed realm `/revoke` endpoint,
same client authentication, `token_type_hint=access_token`. Require HTTP 200 and
empty body. No automatic retry of any network operation. Exchange, transport,
resource, cleanup or post-effect audit uncertainty returns nonretryable failure;
no successful Agent result unless cleanup and audit have committed.

All profile secret values, Basic authentication, issued token candidates and
their existing sealing transforms protect resource and revoke responses.
For client secret and subject token, sealing additionally matches standard JSON
string contents (quote/backslash escaping, with optional slash escaping), even
inside a string with a prefix/suffix, and their existing percent/base64 variants.
Arbitrary per-character Unicode escaping, custom or repeated re-encoding is not
part of this bounded direct-reflection guarantee.
Events are execution.started, oauth.token.issued, oauth.token.revoked, then one
terminal event; they share request/session/action context. Invalid pre-IO
profiles are blocked. Failures after exchange are conservatively indeterminate.

## Provider verification and limits

Keycloak 26.7.3 provider probe proves standard exchange, exact target audience,
active introspection, direct revoke, then inactive while 19.9 seconds remained.
Introspection authenticates the target client (Keycloak requires audience
membership), not the requester. Expired subject exchange returns HTTP 400
`invalid_request`. Source-token revocation does not imply revocation of issued
tokens; each issued token must be revoked directly.
Revocation success is an online provider-state guarantee. A resource validating
only a self-contained JWT signature can continue accepting it until expiry.
Acceptance uses a target that introspects with its own confidential client,
and checks active-before/inactive-after while the issued JWT is unexpired.

Tests must prove fixed profile/action, malformed exchange cleanup, expiry,
revoke failure, secret reflection, no retries and no IO after invalid input.
Real loopback/provider fixtures are not public HTTPS Broker field evidence.

References: https://www.rfc-editor.org/rfc/rfc8693.html,
https://www.keycloak.org/securing-apps/token-exchange,
https://www.keycloak.org/securing-apps/oidc-layers.

## Integrated source acceptance

`scripts/test-keycloak-live.py` and the test-only
`oau02_keycloak_fixture` run real Broker/CLI/Authority against Keycloak 26.7.3
through injected local TLS transport. The root-workspace run recorded in
`outputs/rekey-oau02-20260910/live/integrated/` passed protected add/rotate,
fixed-audience resource 200, direct revoke with inactive introspection before
expiry, a second explicit execution using the same subject, reflected-token
denial with revoke, and expired-subject rejection without a resource request.
Same-subject reuse is proven only for that provider configuration. The target
uses introspection, so revocation is checked independently of HTTP 200.
Audit/output/log secret scans and cleanup passed; source/binary hashes are in
`source.json`. This is not public production-transport or release evidence.

Six Broker contract tests include JSON-escaped source/profile-secret and
resource reflection regressions; these were reproduced before the local
sealing fix and passed afterward. Two local unit tests cover parsing and JSON
string representations, including optional slash escaping. Human security
review is still required before merge.
