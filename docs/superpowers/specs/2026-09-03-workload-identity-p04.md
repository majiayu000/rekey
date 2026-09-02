# Rekey v2 P-04 Workload Identity

**Date:** 2026-09-03
**Status:** Accepted for implementation
**Depends on:** Credential Authority v2 Foundation, P-03
**Scope:** offline-verifiable workload JWTs that mint bounded local capability sessions

## 1. Goal

P-04 lets a workload prove a policy-registered identity on the Agent socket and
receive a short-lived capability without an Admin step-up proof. The active
signed policy maps one exact external identity to one Rekey `PrincipalId`.
Every minted capability remains bounded by the token, policy, requested Action
versions, session TTL, use count, lock/restart lifecycle, and the existing
default-deny evaluator.

The first slice supports four explicit JWT profiles:

- generic OIDC workload tokens;
- SPIFFE/SPIRE JWT-SVIDs;
- Kubernetes service-account TokenRequest JWTs;
- CI/cloud OIDC workload tokens.

All verifier configuration is carried inside the existing signed policy
snapshot. Rekey does not discover issuers, fetch JWKS, call token introspection,
hold issuer private keys, or become an identity provider.

## 2. User-visible flow

The existing Admin path remains unchanged:

```text
rekey session create --action ACTION_ID@VERSION --step-up-stdin
```

The workload path is explicit and reads the bearer token only from stdin:

```text
printf '%s\n' "$TOKEN" | rekey session create \
  --action ACTION_ID@VERSION \
  --ttl 15m \
  --max-uses 20 \
  --workload-token-stdin
```

`--workload-token-stdin` is mutually exclusive with `--recovery` and
`--password-stdin`. It uses `agent.sock`, not `admin.sock`. The token is sent in
the Agent frame body and must never enter argv, environment, metadata, logs,
audit rows, or a state file.

The success response reuses `SessionCreatedResponse` and prints the capability
token exactly once. No response echoes the workload JWT, its `jti`, or its
external subject.

## 3. Signed policy format

P-04 raises the policy snapshot format from v2 to v3. The durable SQLite format
becomes v7 because replay consumption must survive broker restarts. There is no
v6 reader or migration; earlier binaries remain the only reader for earlier
vaults.

Snapshot v3 adds a required `workload_identities` array. It may be empty. At
most 64 entries are accepted.

```json
{
  "format_version": 3,
  "version": 2,
  "expires_at_ms": 4102444800000,
  "approvers": [],
  "workload_identities": [
    {
      "principal_id": "UUID",
      "issuer": "https://issuer.example",
      "audiences": ["rekey://vault/example"],
      "max_token_age_ms": 900000,
      "profile": {
        "kind": "oidc",
        "subject": "service:build"
      },
      "keys": [
        {
          "algorithm": "rs256",
          "kid": "key-1",
          "n": "BASE64URL_NO_PAD",
          "e": "AQAB"
        }
      ]
    }
  ],
  "bindings": [],
  "rules": []
}
```

Common entry rules:

- `principal_id` must be unique and must be referenced by at least one
  `permit` or `require-approval` rule.
- `issuer` is an exact, nonempty HTTPS URL without userinfo, query, fragment,
  whitespace, or control characters.
- `audiences` contains 1 through 8 unique nonempty strings and is canonical
  lexicographic order after validation.
- `max_token_age_ms` is positive and at most one hour.
- `keys` contains 1 through 8 unique `kid` values and unique key material.
- `kid`, issuer, subject, audience, namespace, service-account name, and SPIFFE
  ID are each at most 512 UTF-8 bytes and contain no control characters.

Profiles are closed and deny unknown fields:

```json
{"kind":"oidc","subject":"exact-sub"}
{"kind":"spiffe-jwt-svid","spiffe_id":"spiffe://example.org/workload/api"}
{"kind":"kubernetes-service-account","namespace":"prod","service_account":"api"}
{"kind":"ci-cloud","subject":"repo:owner/name:ref:refs/heads/main"}
```

For Kubernetes the expected subject is exactly
`system:serviceaccount:{namespace}:{service_account}`. Namespace and service
account components use Kubernetes DNS-label syntax. For SPIFFE the subject is
the exact canonical `spiffe://` ID and its trust domain must equal the hostname
of the configured issuer. Generic OIDC and CI/cloud use the exact configured
subject; no glob, regex, prefix, repository wildcard, or claim expression is
supported.

Verification keys are a closed tagged union:

- `ed25519`: `kid` plus a canonical 32-byte base64url-no-pad `x` value;
- `rs256`: `kid` plus canonical base64url-no-pad `n` and `e`; modulus size is
  2048 through 4096 bits and exponent is an odd value of at least 3.

No `none`, HMAC, algorithm fallback, key without `kid`, duplicate key, remote
key URL, `x5c`, or issuer-selected algorithm is accepted.

## 4. Agent IPC

Add `WORKLOAD_SESSION_CREATE` to the Agent channel. Metadata is strict JSON:

```json
{
  "actions": [{"action_id":"UUID","version":1}],
  "ttl_ms": 900000,
  "max_uses": 20
}
```

The body is one compact JWT followed by an optional single newline. The maximum
body is 16 KiB. Empty bodies, embedded newlines, invalid UTF-8, NUL, leading or
trailing whitespace, and more than one line are rejected before JWT parsing.

The Admin channel rejects this message type. The Agent channel continues to
reject all Admin session messages. Agent connection and metadata/body limits
remain bounded under the existing frame reader.

## 5. JWT validation

Validation is total and fail-closed:

1. Split into exactly three nonempty compact-JWS segments before decoding.
2. Decode header and claims with base64url without padding and reject duplicate
   JSON keys or trailing data.
3. Header permits only `alg`, `kid`, and optional `typ`. `typ`, when present,
   must be `JWT` or `at+jwt`. `kid` is required.
4. Select exactly one active policy entry by exact issuer and exactly one key
   by exact `kid` plus `alg`.
5. Verify the compact signing input before trusting subject, audience, time, or
   replay data.
6. Require string `iss`, string `sub`, string `jti`, integer `iat`, optional
   integer `nbf`, integer `exp`, and `aud` as one string or a nonempty string
   array. Standard claim types outside these forms are invalid.
7. Require exact issuer and profile subject. The token audience set must equal
   the configured audience set after duplicate rejection and sorting.
8. Require `iat <= now`, `nbf <= now` when present, `now < exp`,
   `exp > iat`, and `exp - iat <= max_token_age_ms`.
9. The active policy must not be expired. Token `exp` and requested session
   lifetime must not exceed the active policy expiry.
10. Compute replay key as SHA-256 over a domain-separated canonical tuple of
    policy digest, issuer, subject, and `jti`. Raw claims and JWT bytes are
    zeroized after the request.

Unknown top-level claims are ignored only after signature verification. They do
not participate in identity mapping. Duplicate claims are always rejected.

## 6. Capability admission

Admission runs under the lifecycle coordinator and one absolute 25-second
deadline:

1. Broker must be Running and have one non-expired active policy.
2. Verify the workload JWT against that pinned policy.
3. Every requested Action version must be Active, present in the pinned policy,
   and have at least one `permit` or `require-approval` rule for the resolved
   `principal_id`. Forbid-only or unrelated rules do not authorize session
   minting.
4. Mint a random `SessionId`; set tenant to the vault-derived tenant and bind
   the resolved principal plus the new session.
5. Effective TTL is the minimum of requested TTL, token expiry, policy expiry,
   and the existing 24-hour hard maximum. It must remain positive.
6. Admit the in-memory capability, then atomically insert the replay digest and
   `session.created` audit row in the Authority before returning success. A
   uniqueness conflict is replay denial and revokes the losing in-memory
   session.
7. Any replay/audit failure revokes the new session. After a successful durable
   consume, response loss leaves the replay key consumed and the bounded session
   live until its ordinary expiry or revocation. This is deliberately
   fail-closed and matches the existing session-create response-loss contract.

Policy activation revokes all workload-minted sessions before publishing the
new snapshot. Admin-minted sessions keep their current behavior. Lock,
shutdown, process restart, explicit session revoke, Action disable, Credential
revoke, expiry, max-use exhaustion, and concurrency caps continue to revoke or
deny workload capabilities through existing paths.

## 7. Durable replay records

Schema v7 adds:

```sql
CREATE TABLE workload_token_uses (
    replay_digest BLOB PRIMARY KEY CHECK (length(replay_digest) = 32),
    expires_at_ms INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;
```

The insert and success audit share one SQLite transaction. Raw issuer, subject,
audience, `jti`, signature, claims, and JWT are never stored. Replay rows are
bounded to 65,536. Expired rows may be deleted only inside a successful insert
transaction; if the cap is still reached, admission fails closed. A wall-clock
rollback may retain rows longer but cannot make an already stored replay key
usable again.

Restore validates every replay digest length and time field through schema and
integrity checks. Backup naturally includes ciphertext-independent replay
digests but no raw identity token.

## 8. Audit and errors

Successful workload mint writes `session.created` with reason
`workload-attested`; Admin mint remains reason `admin`. Rejected tokens do not
write untrusted issuer, subject, `kid`, `jti`, or JWT data. Replay and malformed
tokens return the same non-retryable Agent error `WORKLOAD_IDENTITY_INVALID` so
the Agent cannot probe registered issuers, keys, or prior use.

Authority/audit/storage uncertainty returns the existing fail-stop error and
must not mint a usable capability. Broker logs contain only stable event names
and error classes.

## 9. Implementation map

- `rekey-domain`: strict IPC metadata and workload/session provenance model.
- `rekey-policy`: snapshot v3 workload catalog, key validation, compact JWT
  parsing, signature/claim verification, and principal/action admission query.
- `rekey-vault`: schema v7 replay table and atomic consume-plus-audit command.
- `rekey-broker`: Agent dispatch, lifecycle coordination, session provenance,
  policy-change revocation, and bounded error mapping.
- `rekey-cli`: mutually exclusive stdin workload session flow over Agent IPC.
- tests/scripts/docs: domain/policy/store/broker/CLI contracts, real black-box,
  canaries, threat model, runbook, guide, Matrix, and closeout evidence.

No new service, daemon, network listener, config file, plugin registry, generic
identity trait, or remote cache is introduced.

## 10. Required verification

P-04 is complete only when all are fresh and passing:

1. Policy tests cover all four profiles, RS256 and Ed25519, exact issuer,
   subject and audience, duplicate keys/claims/audiences, bad `kid`/`alg`/`typ`,
   malformed compact input, signature tampering, time boundaries, token age,
   unknown fields in policy entries, and principal/action admission.
2. Broker tests prove valid workload mint and execution, no-step-up Agent flow,
   Admin/Agent channel separation, replay including a concurrent race, policy
   activation revocation, lock/restart/revoke/expiry/use exhaustion, inactive or
   unauthorized Actions, and audit failure before capability release.
3. Store tests prove atomic replay/audit commit, duplicate denial, cap behavior,
   expired cleanup, ENOSPC/commit rollback, backup/restore, schema tamper, and
   v6/unknown-version refusal.
4. CLI black-box covers stdin-only token input, one success response, malformed
   Broker responses, body/metadata bounds, and all mutual exclusions.
5. A real `rekeyd` plus `rekey` acceptance script activates a signed policy,
   mints through each profile, executes one fixed Action, rejects replay and
   claim/signature/time tampering, rotates policy, and queries the redacted
   audit trail.
6. Canary scans prove JWT, `jti`, signature, external subject, capability,
   credentials, password, and recovery key do not escape their defined
   boundaries.
7. `cargo fmt --all --check`, `cargo check --workspace --all-targets`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, repository mechanical contracts, P-04 black-box,
   exact-head CI, self-review, signed squash tree/DCO, and post-merge main CI
   pass.
8. README, user guide, operations runbook, threat model, closeout plan, and
   Feature Truth Matrix retain the G1/bounded-G2 and verifier-only claims.

## 11. Non-goals

- OIDC discovery, remote JWKS refresh, introspection, userinfo, revocation
  endpoints, or outbound identity-provider calls.
- X.509-SVID, mTLS workload API, SPIRE Agent socket integration, TPM, hardware
  attestation, cloud instance metadata, or node identity.
- SAML, SCIM, human login, groups, roles, organization hierarchy, break-glass,
  browser login, device code, or control plane.
- Wildcard subjects, claim expressions, CEL/Rego/Cedar, arbitrary custom claim
  mapping, or policy-generated capabilities.
- Refresh tokens, token exchange, delegated credentials, token persistence, or
  session survival across broker restart.
- More signature algorithms, remote key URLs, compatibility readers, or in-place
  migration from schema v6 or policy snapshot v2.
- Any increase to the default G1 claim, bounded Linux G2 claim, Connector
  maturity, enterprise readiness, or inclusion in `v2.0.0-alpha.1`.
