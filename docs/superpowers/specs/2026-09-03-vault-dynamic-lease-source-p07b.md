# P-07B One-shot Vault Dynamic Lease CredentialSource

> Status: implemented and locally verified; exact-head CI, merge, and post-main evidence pending
>
> Date: 2026-09-03
>
> Tracking: [Issue #34](https://github.com/majiayu000/rekey/issues/34), parent [#31](https://github.com/majiayu000/rekey/issues/31)
>
> Depends on: P-07A Vault KV v2 fixed-version CredentialSource

## 1. Goal

P-07B adds one closed dynamic source flow. An administrator registers one
public HTTPS Vault origin, one `creds` role, one selected string field, and one
bootstrap token. For each admitted execution, Rekey obtains exactly one
dynamic value, uses it once in an existing fixed HTTPS action, and synchronously
revokes the exact Vault lease before returning success.

The Agent receives only the fixed action response. It never receives the Vault
token, source response, selected value, lease identifier, or revoke response.

This protocol follows Vault's documented dynamic credential and lease APIs:

- `GET /v1/:mount/creds/:role` creates dynamic credentials and a lease;
- the response binds the secret to `lease_id` and `lease_duration`;
- `POST /v1/sys/leases/revoke` with `sync: true` revokes one exact lease.

References: [database credential generation](https://developer.hashicorp.com/vault/api-docs/secret/databases),
[lease semantics](https://developer.hashicorp.com/vault/docs/concepts/lease), and
[exact lease revocation](https://developer.hashicorp.com/vault/api-docs/system/leases).

## 2. Scope and invariants

- Add durable credential kind `vault-dynamic-source` with the next unused AAD
  kind code.
- Add one compile-time built-in connector with effects `Resolve -> Lease ->
  Inject -> Revoke`.
- Add Admin-only typed add and rotate commands.
- Acquire no more than one dynamic lease for each execution attempt.
- Use one selected string field once in the existing fixed HTTP auth header.
- Hold the final upstream response until synchronous lease revocation succeeds.
- Keep the Agent wire protocol and fixed Action schema unchanged.
- Keep default G1 and the bounded Linux G2 reference unchanged.

The new credential kind requires schema v9. Existing v8 and earlier state is
rejected as an unsupported layout. P-07B adds no migration, compatibility
reader, backfill, or old-data repair path.

## 3. Closed credential profile

The encrypted credential payload is canonical JSON with exactly this shape:

```json
{
  "credential_type": "vault-dynamic-source-v1",
  "origin": "https://vault.example.com",
  "mount": "database",
  "role": "agent-api-token",
  "key": "token",
  "vault_token": "hvs.example"
}
```

Validation rules:

- `credential_type` is exactly `vault-dynamic-source-v1`;
- `origin` is a canonical HTTPS origin with no userinfo, path, query, or
  fragment and uses the existing host and port validation;
- `mount` and `role` are each one safe segment of 1 through 128 bytes;
- `key` is 1 through 128 visible ASCII bytes and is matched as one exact JSON
  object key, never as JSONPath;
- `vault_token` is 1 through 4,096 visible ASCII bytes and is used only in the
  `X-Vault-Token` header;
- unknown fields, duplicate fields, malformed JSON, invalid UTF-8, wrong marker,
  and oversized input fail before durable mutation.

The profile cannot choose a method, arbitrary path, request body, query,
headers, TLS behavior, retry policy, lease endpoint, response expression, or
environment credential.

## 4. Admin lifecycle

The CLI adds:

```text
rekey credential add-vault-dynamic LABEL --file PROFILE --password-stdin
rekey credential rotate-vault-dynamic CREDENTIAL_ID --file PROFILE --password-stdin
```

The P-07A regular-file, no-follow, 64 KiB input boundary and step-up ordering
apply. The complete profile travels only in an Admin frame body and remains
encrypted at rest. The Broker validates the closed profile before the Authority
commits the new credential version and mutation audit.

Rotation atomically replaces the full source profile. Rekey credential revoke
prevents future lease acquisition. Neither rotation nor Rekey credential revoke
operates on a lease from a completed historical execution.

## 5. Connector selection

`vault-dynamic-source` may select only the built-in one-shot dynamic source
connector and is rejected for all reserved GitHub App actions. Selection is
compile-time and performs no IO or credential parsing.

The connector contract reports `revoke_before_success: true`. It does not add a
dynamic library, subprocess, WASM runtime, provider registry, download path, or
Agent-selected connector.

## 6. Lease acquisition request

After capability and policy authorization, durable `execution.started`,
credential eligibility, and profile validation, the Broker sends exactly:

```text
GET https://<origin>/v1/<mount>/creds/<role>
Accept: application/json
X-Vault-Token: <vault_token>
```

The request body is empty. Redirects are disabled, proxy environment is
ignored, DNS answers pass the existing public-address screen, and the complete
response is bounded to 64 KiB. P-07B performs no retry.

This GET is a remote effect because Vault may create a credential and lease.
The Broker must pass remote-effect admission immediately before sending it and
must keep the execution supervisor alive through cleanup if drain or lock
begins afterward. Timeout, disconnect, truncated response, and transport
uncertainty after send are indeterminate even when no response body arrived.

## 7. Exact issued response contract

A usable response requires status 200 and these fields:

```json
{
  "lease_id": "database/creds/agent-api-token/example",
  "lease_duration": 60,
  "renewable": true,
  "data": {
    "token": "resolved-value"
  }
}
```

Rules:

- `lease_id` is exactly one non-empty visible ASCII string of at most 1,024
  bytes;
- duplicate `lease_id`, `lease_duration`, `renewable`, or `data` fields fail;
- `lease_duration` is an integer from 5 through 300 seconds;
- `renewable` is a boolean; either value is accepted but Rekey never renews;
- `data` contains the configured key as a string of 1 through 8,192 visible
  ASCII bytes;
- other `data` fields may be ignored while parsing but are never copied,
  persisted, audited, logged, or returned;
- top-level provider metadata may be ignored only inside the already bounded
  zeroizing response buffer;
- null, nested, binary, malformed, missing, wrong-type, duplicate, reflected,
  or oversized required values fail closed.

The parser borrows strings from the zeroizing source response or copies them
immediately into zeroizing buffers. It must not leave an ordinary allocated
`String` containing a provider secret on any success or error path.

The Broker performs a bounded raw probe for candidate `lease_id` strings before
semantic validation. If later validation fails, every captured valid candidate
is synchronously revoked within the remaining cleanup budget. A successful
issuance response without one unambiguous revocable lease ID is indeterminate.

## 8. Lease and action deadlines

One absolute Action deadline covers acquisition, parsing, audit, final action,
sealing, revocation, and terminal audit. Dynamic source execution requires an
Action timeout of at least 2 seconds.

After acquisition, the Broker derives a monotonic lease deadline from
`lease_duration`. Final action IO is bounded by the earlier of:

- the Action deadline minus a fixed 500 millisecond cleanup reserve; and
- the lease deadline minus the same cleanup reserve.

If no positive business window remains, the Broker skips the final action,
attempts exact revoke, and returns a definite upstream failure only after
successful revoke. The provider's `renewable` flag never extends either
deadline.

The accepted 300-second maximum is also the declared upper bound on provider
credential exposure after a Rekey process crash. P-07B does not claim that a
crashed process completed revocation.

## 9. Final action and secret sealing

The selected value is combined with the registered fixed action auth prefix and
header in a zeroizing buffer. The final request still uses the existing fixed
origin, method, path, request-body, response-size, redirect, proxy, DNS/IP, and
header contracts.

The complete source profile, Vault token, selected value, final auth value, and
captured lease IDs are sealing inputs. Source response token reflection is
detected before final action IO. Final response secret reflection is detected
before filtering or return. A reflected or malformed response does not skip
lease cleanup.

No source bytes are cached, returned over IPC, placed in metadata, serialized
to audit, or retained after the one execution.

## 10. Exact synchronous revocation

After lease acquisition, every terminal path attempts cleanup when at least one
valid candidate lease ID is available. The Broker sends one request per bounded
candidate:

```text
POST https://<origin>/v1/sys/leases/revoke
Content-Type: application/json
Accept: application/json
X-Vault-Token: <vault_token>

{"lease_id":"<exact-id>","sync":true}
```

Success requires status 204 and an empty body. Redirect, timeout, non-204,
non-empty response, transport uncertainty, or exhausted cleanup budget is a
revoke failure. Prefix and force revocation endpoints are never used.

The final Action response remains private until all required revocations
succeed. Any revoke failure returns `UPSTREAM_INDETERMINATE`, even when the
fixed action itself succeeded or was read-only.

## 11. Audit and failure semantics

- Invalid profile, connector mismatch, policy denial, and closed admission are
  definite failures before lease acquisition.
- Lease acquisition send uncertainty is indeterminate because a credential may
  exist without a received lease ID.
- A non-200 response is definite only when the response proves no lease was
  issued; otherwise it is indeterminate and cleanup is attempted for all
  captured candidates.
- After a valid lease is captured, schema, TTL, sealing, deadline, final action,
  cancellation, and terminal preparation failures attempt revoke first.
- Revoke failure or uncertainty is always indeterminate and never invites an
  automatic retry of the whole action.
- Each admitted execution still has exactly one `execution.started` and one
  terminal event.
- Redacted `vault.lease.issued` and `vault.lease.revoked` evidence records only
  outcome and a fixed reason class. Origin, mount, role, key, lease ID, Vault
  token, selected value, response body, and provider error text are forbidden.
- Audit commit failure remains fail-stop. It cannot fall through to final
  action success and cannot suppress the best-effort exact revoke attempt.

## 12. Restart, backup, and restore

No lease ID or resolved value is stored in SQLite, backup, or a background
registry. A clean execution revokes before success. Lock and shutdown drain
already-admitted revocable executions through cleanup.

A hard process or host crash can leave a lease active until Vault expires it.
The maximum accepted 300-second TTL bounds this exposure. Restart does not
claim to discover or revoke the abandoned lease. Backup and restore preserve
only the encrypted source profile; the next execution obtains a fresh lease.

Durable outstanding-lease cleanup, renewal, and crash-recovery revocation are a
separate future design and are not implied by P-07B.

## 13. Required verification

Implementation evidence must cover:

1. every profile field boundary, duplicate/unknown fields, no-follow input,
   typed add/rotate, wrong kind, bad proof, rollback, and schema v8 rejection;
2. exact connector selection, effect order, and reserved GitHub denial;
3. exact acquisition and revoke method/path/query/header/body contracts;
4. one issuance per execution and exact candidate lease cleanup;
5. status, malformed JSON, duplicate fields, missing/wrong-type selected value,
   TTL minimum/maximum, response overflow, timeout, redirect, and private IP;
6. issuance transport uncertainty, malformed response with and without a
   recoverable lease ID, and bounded multiple-candidate cleanup;
7. source/final/revoke reflection, raw and encoded selected-value sealing, and
   no source bytes in Agent output;
8. final action success/failure/timeout, revoke success/failure/timeout,
   cancellation, lock, drain, and audit failure ordering;
9. real release `rekeyd` and `rekey`, dual UDS, SQLite, local CA/TLS Vault and
   final fixtures, rotation, restart, backup/restore, and canary scans;
10. workspace fmt/check/clippy/tests, all existing acceptance regressions,
    root/fuzz audit, pinned fuzz smoke, mechanical boundaries, exact-head CI,
    resolved review findings, signed squash merge, and post-main CI.

## 14. Local verification

On 2026-09-03 the implementation passed workspace fmt, all-target check and
clippy, the complete workspace test suite, root and fuzz dependency audits,
the pinned `nightly-2026-09-01` build, and 2,000 runs for each of the five fuzz
targets. The complete macOS security-gate acceptance set passed, including the
release-binary dual-UDS/SQLite/local-CA P-07B harness, existing P0/P1/P2/P3/P4/
P5/P6/P7 regressions, durability, crash recovery, response sealing, and the
native launchd service-manager gate. Exact-head Ubuntu/macOS CI, review
closeout, signed squash merge, and post-main CI remain required before this
increment is complete.

## 15. Public capability statement

After completion, documentation may say: "Rekey supports one-shot Vault
dynamic source leases for existing fixed HTTPS actions and synchronously
revokes a captured lease before success."

It may not say: "general Vault support", "guaranteed crash-time revocation",
"lease renewal", "dynamic database integration", "private Vault networking",
"cloud KMS", "G3", "enterprise ready", or "P-07 complete".

## 16. Explicit non-goals

- lease renewal, lookup, prefix revoke, force revoke, tidy, list, or background
  lease management;
- durable lease journal, restart cleanup, HA lease ownership, or guaranteed
  cleanup after SIGKILL, process crash, host crash, or network partition;
- Vault namespaces, response wrapping, AppRole, Kubernetes/OIDC auth, token
  renewal, private CA, private address exceptions, proxies, redirects, retries,
  caching, prefetch, or offline fallback;
- arbitrary provider methods, endpoints, headers, response expressions, or
  multi-field composition;
- opening database connections, AWS request signing, cloud Secret Manager,
  1Password, PKCS#11, HSM, TPM, Secure Enclave, or OS keychain;
- plugin loading, provider registry, Agent source selection, Secret read/export
  APIs, schema v8 migration, or inclusion in `v2.0.0-alpha.1`.
