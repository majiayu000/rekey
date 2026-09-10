# WID-09: fixed GitHub Actions online JWKS

A signed workload identity may opt into `"online_key_source":"github-actions-jwks"`
with `"keys":[]`. The issuer must be exactly
`https://token.actions.githubusercontent.com`. Omitting the optional field keeps
existing static non-empty keys. Static keys and an online source are mutually
exclusive. Subject, audiences, principal, age limits and permitted actions remain
explicit signed-policy constraints.

The Broker retrieves the fixed
`https://token.actions.githubusercontent.com/.well-known/jwks` for each online mint.
There is no cache, discovery URL, background refresh, introspection or JWT-provided
network address. Static identities retain offline verification. JWT `jku`/`x5u`
remain rejected; bounded RS256 `x5t` remains accepted metadata, never key authority.
GitHub's public endpoint and OIDC reference were checked on 2026-09-10:
https://docs.github.com/en/actions/reference/security/oidc
and https://token.actions.githubusercontent.com/.well-known/jwks .

Fetch uses the existing screened HTTPS transport (public DNS/IP checks, TLS,
no environment proxy, no redirects), a 64 KiB body bound and the workload admission
25-second absolute deadline. The GET contains only fixed public headers; JWTs and
credentials never leave the broker in this fetch. The existing transport's header
slot carries a public Accept value, not an authorization credential.

The pure policy layer routes bounded untrusted identity claims only to the
signed source choice; this is not verification. The fetched document must contain
1..8 unique RSA signing keys with explicit `kid`, `kty=RSA`, `alg=RS256`, `use=sig`,
canonical base64url `n/e` and valid RSA material. Existing key validation is reused
once when compiling each fetched key. Duplicate JSON members/kids, malformed,
unsupported and oversized documents fail closed. Ancillary JWKS metadata such as
x5c/x5t is ignored and is never a trust input.

Network IO and public-key parsing happen before acquiring the lifecycle mutation
coordinator. After acquiring it, the Broker confirms the exact same active policy
instance is still installed and checks current expiry before verification and
session admission. A policy replacement, lock, deadline, unknown kid, key mismatch,
rotation mismatch or unavailable endpoint rejects the mint. Each new mint fetches
again, including when a key rotates under an unchanged kid. No stale key fallback
is allowed. Remote keys are transient verifier inputs; the signed snapshot,
canonical digest and durable replay binding are never rewritten. Static and
online identities cannot borrow each other's keys, even under the same issuer/kid.

Focused tests cover opt-in/schema constraints, strict JWK parsing, remote/static
key isolation, fixed fetch request, fresh same-kid rotation, endpoint failure,
unknown/wrong keys, expiry, replay and policy replacement during a blocked fetch.
GitHub Actions run `34459644320` passed real online acceptance: no inline policy
keys, Broker-owned fixed JWKS fetch, real JWT mint and fixed read 200, replay,
wrong-audience and natural-expiry denial. A fresh same-audience JWT minted after
the expiry negative still succeeds, ruling out an endpoint outage as that result.
`outputs/rekey-wid09-20260910/online/` contains the public receipt, source/binary
hashes and run log. The dedicated private test repository was deleted after all
runs completed; API 404 is recorded in `cleanup.json`. This remains source-only
fixed-GitHub evidence, not general discovery/introspection or a release claim.
