# P-06 GitHub App bounded extension specification

**Status:** Accepted implementation contract

**Date:** 2026-09-03

**Tracking:** [Issue #29](https://github.com/majiayu000/rekey/issues/29)

**Depends on:** P-05 connector contract SDK, P2.1 closed GitHub App profile

## 1. Goal

P-06 extends the built-in GitHub App connector with a bounded write path,
exact multi-repository selection, typed credential rotation, authenticated
installation-repository changes, and safe retry behavior. It does not turn
Rekey into an arbitrary GitHub proxy.

The Broker remains the sole owner of decrypted credentials, JWT signing,
installation-token exchange, upstream IO, deadlines, response sealing, audit,
retry decisions, and token revocation. The Agent still invokes only
`ExecuteFixedHttpAction` with a capability and never sees provider credentials.

## 2. Provider facts and chosen bounds

GitHub installation tokens may be restricted by `repository_ids` and
`permissions`, cannot exceed the installation grants, and expire after one
hour. GitHub permits up to 500 selected repositories; Rekey deliberately limits
one credential to 16. The create-issue endpoint accepts an installation token
with repository `issues: write` permission.

GitHub recommends `X-Hub-Signature-256` HMAC-SHA256 over the exact delivery
bytes and `X-GitHub-Delivery` uniqueness for replay protection. P-06 has no
public listener. An operator forwards one bounded delivery over the owner-only
Admin UDS with the current expected credential version.

GitHub permits multiple active App keys for no-downtime rotation. Rekey models
rotation as its existing transactional credential version change. It does not
manage keys in GitHub or retain multiple private keys in one profile.

## 3. Frozen non-goals

P-06 does not add:

- arbitrary GitHub origins, REST paths, methods, headers, permissions, or
  response forwarding;
- more than one installation in a credential;
- user access tokens, OAuth user flows, GraphQL, enterprise installation
  tokens, GitHub Enterprise Server hosts, or Git operations;
- a public webhook server, IP updater, queue, background polling, redelivery
  client, or automatic repository discovery;
- automatic retry of exchange, create-issue, revoke, transport-uncertain, or
  any other mutative or indeterminate effect;
- dynamic connectors, external CredentialSource, new Agent operations, wider
  G1/G2 claims, or inclusion in `v2.0.0-alpha.1`.

## 4. Credential profile v2

P-06 replaces the development payload with
`github-app-installation-v2`. No v1 migration, fallback, or dual parser is
added. A profile is one encrypted JSON object:

```json
{
  "credential_type": "github-app-installation-v2",
  "client_id": "Iv1.example",
  "app_id": 123,
  "installation_id": 456,
  "repositories": [
    {"id": 11, "owner": "octo-org", "name": "alpha"},
    {"id": 12, "owner": "octo-org", "name": "beta"}
  ],
  "permissions": {"metadata": "read", "issues": "write"},
  "webhook_secret": "a high entropy operator-provided value",
  "private_key_pkcs1_der_base64": "..."
}
```

The closed parser rejects unknown fields and duplicate semantic entries:

- `client_id` keeps the existing 1..=128 safe-character contract;
- App and installation IDs are non-zero;
- there are 1..=16 repositories, sorted by numeric ID after parsing, with
  unique IDs and unique case-insensitive `owner/name` pairs;
- owner and repository names use a bounded GitHub path-safe subset and are
  1..=100 bytes each;
- exact permissions are `metadata=read` and optional `issues=write`;
- webhook secret is 32..=256 bytes with no control character;
- PKCS#1 DER remains bounded and is validated before persistence.

The secret-free commitment binds client ID, App ID, installation ID, ordered
repositories, permissions, and a SHA-256 digest of the webhook secret. It never
contains private-key or webhook-secret bytes.

## 5. Closed action profiles

The registry entry remains `github-app-installation@1`; P-06 expands only its
Broker-owned profiles.

### 5.1 List repositories

- exact `GET https://api.github.com/installation/repositories`;
- exact `authorization: Bearer `, no Agent body/content type/extra header;
- exchange requests every configured repository ID and only `metadata=read`;
- exchange and resource responses must identify exactly those IDs;
- Agent output is canonical JSON containing only repository IDs, owner/name
  pairs, and count.

### 5.2 Create issue

- exact `POST https://api.github.com/repos/{owner}/{repo}/issues`, with the
  owner/repository present in the current profile;
- profile declares `issues=write`;
- exchange requests only that repository ID and exact
  `metadata=read,issues=write`;
- content type is `application/json`, extra headers are empty, and the closed
  body has `title` (1..=256 UTF-8 bytes) plus optional `body` (at most 32 KiB);
- success is 201 with positive `id` and `number`, the configured repository API
  URL, and an HTTPS issue URL under `github.com/{owner}/{repo}/issues/`;
- Agent output contains only canonical `id`, `number`, and `html_url`.

Every profile mismatch is rejected after `execution.started` but before JWT
signing or upstream IO. The existing absolute deadline and 500 ms cleanup
reservation remain in force.

## 6. Exchange and revoke

Every exchange supplies explicit repository IDs and permissions. A 201 response
succeeds only when exactly one token is observed, repository selection is
`selected`, returned permissions exactly match the request, and returned
repository IDs exactly match the request.

JWTs and all observed token candidates remain sealing needles. Every observed
installation token is revoked through the existing bounded
`DELETE /installation/token` path before Agent success. Failure, cancellation,
disconnect and shutdown preserve the current indeterminate/fail-closed rules.

## 7. Retry contract

P-06 performs at most one retry, only for the read-only repository-list request
when GitHub returns 403 or 429 with one canonical integer `Retry-After` header
between 1 and 30 seconds. The delay and retry must fit before the business
deadline. Missing, conflicting, malformed, zero, oversized or unaffordable
values fail without retry and proceed to revoke.

Exchange, create-issue, revoke, 5xx, transport failures, and every response for
which a remote mutation may have happened are never retried. A create-issue
transport failure is indeterminate, not a denial that invites automatic retry.
Such post-write upstream uncertainty returns `UPSTREAM_INDETERMINATE` with
`retryable=false` (CLI exit 8).

## 8. Typed rotation

`rekey credential rotate-github-app CREDENTIAL_ID --file PROFILE` uses the
existing regular-file and 64 KiB bounds, validates the v2 marker locally, and
sends secret bytes only in the Admin frame body. The Broker looks up the current
credential kind and validates every GitHub rotation before the Authority
commits its existing atomic encrypted version and audit row. Generic rotate can
therefore not replace a GitHub credential with malformed or opaque bytes.

Rotation may change the key, installation, repositories, permissions and
webhook secret together. Capabilities are not reminted. Later executions use
the new current profile, so removed-repository actions fail before upstream IO.

## 9. Installation-repositories webhook apply

The Admin-only command is:

```text
rekey credential apply-github-webhook CREDENTIAL_ID \
  --expected-version N \
  --event installation_repositories \
  --delivery UUID \
  --signature sha256=<64 lowercase hex> \
  --file PAYLOAD.json \
  --password-stdin
```

The exact payload is bounded to 64 KiB. Delivery UUID, event and signature are
public metadata; proof and payload use the frame body. The Broker:

1. coordinates the mutation and verifies step-up;
2. prepares the current GitHub credential and requires the expected version;
3. verifies HMAC-SHA256 in constant time over unmodified payload bytes;
4. accepts only `installation_repositories`, action `added` or `removed`, the
   exact installation ID, and one non-empty bounded repository delta;
5. rejects already-present additions, missing removals, mixed deltas,
   duplicates, and an empty or oversized result;
6. serializes the updated profile in a zeroizing buffer and commits it through
   the existing atomic credential rotation path.

Success increments the credential version, so the same expected-version
command cannot apply twice. A whole-vault restore before the event retains the
documented G1 rollback limitation; P-06 does not claim replay resistance across
that rollback. No Agent webhook surface or HTTP listener exists. Any signature,
event, installation, version, delta, audit or storage failure commits no change.

## 10. Audit and error contract

`execution.started`, `connector.github.authorized`,
`connector.github.token_revoked`, and one terminal event remain ordered. Typed
rotation and webhook apply use the existing atomic `credential.rotated` audit
event and return the new version. Audit metadata remains secret free.

Agent failures stay coarse. Admin/CLI may distinguish invalid profile, stale
version, invalid signature, unsupported event, invalid delta and storage failure
without returning payload or secret content.

## 11. Verification

Focused tests must cover:

1. v1 rejection, permission/name/repository bounds and invalid RSA material;
2. exact two-repository list scope and sanitized output;
3. create-issue path, permission, body and response binding;
4. removed repository and malformed write failure before signing or IO;
5. valid typed installation/key/scope rotation and rejected malformed generic
   rotation without mutation;
6. webhook golden HMAC, tamper, wrong installation/event/action/version,
   add/remove, replay/no-op and audit failure;
7. one bounded list retry and malformed/conflicting/oversized/deadline cases,
   plus zero retry for exchange, write and revoke;
8. two independent local CA/TLS provider scenarios with different installation
   and repository sets through release binaries, dual UDS and SQLite;
9. canary scans for key, webhook secret, JWT, token, capability, issue body and
   signature across Agent output, state, logs and audit.

Required commands:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/p2-github-app.sh
scripts/p6-github-app-extension.sh
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo +nightly check --manifest-path fuzz/Cargo.toml --all-targets
```

Existing mechanical secret/API and CLI dependency scans remain required. P-06
closes only after exact-head CI, resolved findings, squash merge, and green
post-main security, fuzz and performance workflows.

## 12. Primary references

- [Generating an installation access token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [REST API endpoints for issues](https://docs.github.com/en/rest/issues/issues)
- [Managing private keys for GitHub Apps](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
- [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [Best practices for using webhooks](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
- [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
