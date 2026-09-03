# P-07A Vault KV v2 CredentialSource

> Status: locally verified; exact-head CI and merge pending
>
> Date: 2026-09-03
>
> Tracking: [Issue #32](https://github.com/majiayu000/rekey/issues/32), parent [#31](https://github.com/majiayu000/rekey/issues/31)
>
> Depends on: P-05 Connector SDK, P-06 GitHub App extension

## 1. Goal

P-07A adds one closed external CredentialSource: an administrator registers a
HashiCorp Vault KV v2 location and bootstrap token, and the Broker resolves one
exact versioned string immediately before executing an existing fixed HTTPS
action. The Agent receives only the fixed action response and never receives
the Vault token or resolved value.

This is the first P-07 increment. It does not complete dynamic leases, cloud
Secrets/KMS, 1Password, PKCS#11, HSM, or OS keychain support.

The provider protocol follows Vault's documented KV v2 versioned read endpoint:
`GET /v1/:mount/data/:path?version=:version`. KV v2 static secrets do not issue
dynamic leases. See the official [KV v2 HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
and [lease semantics](https://developer.hashicorp.com/vault/docs/concepts/lease).

## 2. Scope and invariants

- Add the durable credential kind `vault-kv-v2-source` with AAD code 3.
- Add a built-in connector contract for source-resolved fixed HTTP header
  injection.
- Add Admin-only typed add and rotate commands.
- Resolve one exact string field from one exact KV v2 secret version.
- Reuse the existing screened HTTPS transport, action deadline, fixed action,
  policy, capability, response sealing, and terminal audit contracts.
- Keep the Agent wire surface unchanged.
- Keep default G1 and the bounded Linux G2 reference unchanged.

The new kind requires schema v8. Existing v7 state is rejected as an
unsupported layout; P-07A adds no migration or compatibility path.

## 3. Closed credential profile

The encrypted credential payload is canonical JSON with this exact shape:

```json
{
  "credential_type": "vault-kv-v2-source-v1",
  "origin": "https://vault.example.com",
  "mount": "secret",
  "path": "agents/github",
  "key": "token",
  "version": 7,
  "vault_token": "hvs.example"
}
```

Validation rules:

- `credential_type` is exactly `vault-kv-v2-source-v1`;
- `origin` uses HTTPS, contains no userinfo/query/fragment/path, and uses the
  existing canonical host/port validation;
- `mount` is one safe path segment;
- `path` is 1 through 16 safe non-empty segments;
- `key` is 1 through 128 printable non-control characters and is matched as one
  exact JSON object key, not JSONPath;
- `version` is a non-zero positive integer and is always sent explicitly;
- `vault_token` is 1 through 4,096 visible ASCII bytes and is used only as the
  `X-Vault-Token` request header;
- unknown fields, malformed JSON, invalid UTF-8, and oversized profiles fail
  before durable mutation.

The profile has no arbitrary method, URL, header, query, response expression,
namespace, TLS option, retry option, or environment lookup.

## 4. Admin lifecycle

The CLI adds:

```text
rekey credential add-vault-kv LABEL --file PROFILE --password-stdin
rekey credential rotate-vault-kv CREDENTIAL_ID --file PROFILE --password-stdin
```

The existing regular-file, no-follow, 64 KiB bound and Admin step-up ordering
apply. Secret bytes travel only in the Admin frame body. The Broker validates
the profile before the Authority commits the encrypted version and audit row.
Generic credential rotation remains limited to `opaque-token`.

Rotation is atomic and replaces the complete source profile. Revoking the
Rekey credential prevents future resolution. P-07A does not revoke or mutate
the static KV value at Vault.

## 5. Connector selection

`vault-kv-v2-source` may select only the built-in source-resolved fixed HTTP
connector. It is rejected for every reserved GitHub App action so it can never
bypass the closed GitHub profile.

The connector contract declares `Resolve` followed by `Inject`. Registry
selection remains compile-time and IO-free. P-07A does not add dynamic plugins,
provider discovery, configuration loading, or Agent-selected sources.

## 6. Resolution request

After capability/policy authorization, durable `execution.started`, credential
eligibility, and profile validation, the Broker sends exactly:

```text
GET https://<origin>/v1/<mount>/data/<path>?version=<version>
Accept: application/json
X-Vault-Token: <vault_token>
```

The request has an empty body, redirects disabled, proxy environment ignored,
the existing public-address DNS/IP screen, and a 64 KiB response limit. The
same absolute action deadline covers source DNS/TLS/HTTP, final action
DNS/TLS/HTTP, sealing, and terminal audit. P-07A performs no automatic retry.

Private, loopback, link-local, documentation, multicast, or mixed public/private
answers are rejected. Private Vault network support requires a later bounded
egress design and is not inferred from administrator registration.

## 7. Exact response contract

Success requires status 200 and this bounded semantic shape:

```json
{
  "data": {
    "data": {"token": "resolved-value"},
    "metadata": {
      "version": 7,
      "deletion_time": "",
      "destroyed": false
    }
  }
}
```

`data.data` must contain exactly the selected field, whose value is a string
with 1 through 8,192 visible ASCII bytes. The returned metadata version must exactly equal the configured version,
`destroyed` must be false, and `deletion_time` must be empty. Missing, null,
binary, nested, oversized, deleted, destroyed, wrong-version, malformed, or
non-200 responses fail closed before final action IO.

Provider envelope fields outside the required path are ignored only after the
bounded body is read; they never enter Agent output or audit. If any response
body/header reflects the Vault token, resolution fails as a security violation.

## 8. Secret lifecycle and final action

The resolved value exists only in a zeroizing Broker buffer. It is combined
with the fixed action's already-registered auth prefix/header and sent through
the existing fixed HTTPS executor. The Vault token, complete source profile,
resolved value, and final auth header are all response-sealing needles.

No resolved value is persisted, cached, returned over IPC, placed in metadata,
printed, or exposed through connector projections. Each execution resolves the
configured version once and consumes the result once.

## 9. Failure and audit semantics

- Profile, source/action mismatch, and malformed request state are definite
  pre-source denials.
- Source DNS/TLS/transport/timeout/status/schema/version failures are explicit,
  retryable upstream failures because KV read is non-mutating and final action
  has not begun.
- Source response overflow maps to the existing bounded response failure.
- Final fixed-action failures retain the current pre/post-effect and
  indeterminate behavior.
- Every admitted request still has exactly one started and one terminal event.
- Audit reasons identify the source failure class but contain no origin path,
  key, token, resolved value, body, or provider error text.
- Audit commit failure remains fail-stop and never falls through to final
  action execution.

## 10. Required verification

Implementation tests must cover:

1. profile success and every field boundary, unknown fields, wrong marker, and
   v7 layout rejection;
2. exact connector selection and reserved GitHub action denial before IO;
3. exact request method/path/query/headers, version binding, and one resolution
   per execution;
4. status, malformed JSON, missing/nested/wrong-type value, wrong version,
   deleted/destroyed, overflow, timeout, redirect, and private-address failure;
5. source-token reflection, resolved-secret reflection, encoded reflection,
   and provider-extra-field sanitization;
6. typed add/rotate, wrong kind, stale version, revoke, lock, bad step-up,
   mutation audit failure, and atomic rollback;
7. real release `rekeyd` + `rekey`, dual UDS, SQLite, local CA/TLS provider and
   final upstream fixture, rotation, restart, and backup/restore black-box flow;
8. canary scans across argv, environment, stdout/stderr, audit export, database,
   backup, and Agent-visible output;
9. workspace fmt/check/clippy/tests, P0/P1/P2/P3/P4/P5/P6 regressions, root/fuzz
   audit, nightly fuzz build, mechanical forbidden APIs, and CLI negative
   dependency tree;
10. exact-head CI, resolved self-review findings, signed squash merge, and
    post-main CI.

## 11. Public capability statement

After completion, documentation may say: "Rekey supports a closed HashiCorp
Vault KV v2 fixed-version CredentialSource for existing fixed HTTPS actions."

It may not say: "general external Vault support", "dynamic credentials",
"private Vault networks", "cloud KMS", "HSM-backed", "G3", "enterprise
ready", or "P-07 complete".

## 12. Explicit non-goals

- latest/alias resolution, KV v1, writes, deletes, list, metadata list, or CAS;
- Vault namespaces, AppRole, Kubernetes/OIDC auth, token renewal, response
  wrapping, dynamic secrets, lease renewal, or lease revocation;
- private CA configuration, insecure TLS, private address exceptions, proxies,
  redirects, retries, caching, prefetch, background refresh, or offline fallback;
- AWS, GCP, Azure, 1Password, Infisical, OpenBao-specific compatibility,
  PKCS#11, HSM, TPM, Secure Enclave, or OS keychain;
- arbitrary URL/header/JSONPath templates, plugin loading, provider registry,
  Agent source selection, or any Secret read/export API;
- migration of v7 state or inclusion in the published `v2.0.0-alpha.1` archive.
