# EXT-02 Fixed GCP Secret Manager version source

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

Status: frozen implementation contract, 2026-09-30; implementation begins only
after the DYN-06 recovery correction and independent review gate. This extends
[the accepted external source scope](2026-09-16-external-capabilities.md#ext-02-gcp固定-secretversion-只读源).
It introduces one credential kind/compile-time connector and no new production
dependency, cloud SDK, credential discovery, refresh, local value cache or
Agent operation. The minimum is five new files: this specification, one broker
source module with its private unit tests, one real broker contract test, one
CLI black-box test, and one minimal broker TLS fixture if needed. Existing
workspace files are touched only to connect this source. Root owns shared docs,
release workflow, lockfile and full-suite verification.

## Protected input and version gates

The closed profile is `credential_type=gcp-secret-manager-source-v1`,
`origin=https://secretmanager.googleapis.com`, `secret_version`, `access_token`
and `access_token_expires_at_ms`. The origin is an explicit configuration field
but permits only the fixed global HTTPS authority/default port; regional or
arbitrary origins are not accepted. This makes the runtime URL an explicit
protected registration input. Token and resource are encrypted in the existing
Authority envelope. No token, raw profile or provider response enters metadata,
argv, environment, logs or audit rows. Existing private regular-file readers,
step-up proof and frame-body transport apply to add/typed rotate.

The resource is exactly `projects/P/secrets/S/versions/N`, at most 512 bytes.
P is a safe ASCII project ID or numeric project number, S is 1..255 ASCII letters,
numbers, underscore or hyphen, and N is canonical nonzero decimal u64. No leading
zero, alias/latest, locations, path/query escape or caller URL. The response name
must match the configured full string exactly; no project-ID/number alias lookup.
Operators should register the canonical numeric project number if the provider
normalizes names. Profile parsing rejects duplicate/unknown fields. The imported
opaque bearer token is nonempty, at most 16KiB, and must pass the existing outbound
header boundary. Its declared expiry must be in the future with at most 3600s
remaining; it does not prove Google's actual token expiry or IAM permissions.

Reserve CredentialKind `gcp-secret-manager-source` with AAD code 6, workspace
state/schema format 16, and Admin rotate opcode 41. Formats 15 and older state and
backups are rejected without migration/overwrite. Preserve all format-15 journal
integrity, backup and rotation invariants. The CLI remains a pure IPC client.

## One execution

Existing capability/Action/policy/approval checks and durable execution.started
precede the consume-once encrypted profile. Commit read-started evidence with
actual credential version and configured public resource before one GET to
`/v1/{secret_version}:access`. Use the existing public-IP-screened fixed HTTP
transport: no proxy environment, redirects, retries or custom production CA.
Request has no body and uses only the registered Bearer token; no business body
or headers travel to the source. Cap source response at 64KiB.

Bind source read, parsing and resolved-audit commit to the smaller of the original
Action absolute deadline and the imported token's remaining lifetime, anchored
before sending. Recheck declared expiry after parsing/audit and before business.
Do not restart a TTL at the response. A bootstrap token's expiry is not the TTL
of the separately fetched business value: subsequent business IO keeps the
original Action deadline and existing lifecycle gate.

Before parsing, seal reflected bootstrap token/raw profile/full Bearer value in
all upstream body/header bytes, including errors and disallowed headers. A 200
response must have unique closed `name` and `payload`, with payload `data` and
`dataCrc32c`. Check exact name, required decimal-string uint32 checksum, decode
ProtoJSON standard or URL-safe base64 with/without padding (select its alphabet
and padding once), and verify CRC32C over the complete decoded bytes. Reject bad
padding, mixed alphabets, whitespace, nonzero unused bits, malformed JSON,
overflow, missing checksum, invalid/empty UTF-8 or more than 8KiB of decoded data.
No field selection, trimming or rewriting. Existing header validation rejects
CR/LF/NUL when joining the complete value with the Action auth prefix.

Commit resolved evidence before business; failures at started/read-started/
resolved audit fail closed with zero business. Return the existing Broker-owned
PreparedExecution with the fetched value and complete bootstrap/value/auth
sealing needles. The consume-once Authority factory stays private. Existing
response sealing, terminal audit and indeterminate business semantics apply.
No dynamic lease cleanup, DYN journal entry, source writes or Agent secret read.
Provider 401/403/404, disabled/destroyed version, timeout, expiry, CRC/name mismatch
and reflection never fall back to another version/value or ambient identity.
Only fixed safe reasons enter errors/audit, never serde/provider raw text.

## Verification

Pure profile/JSON/base64/CRC32C tests include the independent `123456789`
CRC32C vector (0xe3069283), all four valid ProtoJSON encodings, boundary expiry,
resource injection, duplicates, wrong names/checksums and UTF-8/header limits.
Actual Broker/Authority/UDS contracts exercise typed add/rotate, single fixed
source read before business, all source/business reflection forms, audit failure,
lock/drain/deadline and fresh kind encryption/backup/DEK/VRK rotation. Real TLS
uses a test-only screened address/CA mapping and never opens production private
network or an arbitrary endpoint. CLI black-box checks protected profiles,
step-up error contracts, pure dependencies and no secret argv/env/output.

Current host denies TCP and Unix listener creation (EPERM). Strict runtime tests
must remain in source/CI and be reported blocked if they cannot run here; pure
checks and compilation are separate evidence, not substitutes. Do not weaken or
silently skip them. Full integration and field claims require later successful
checks. Real GCP IAM, exact canonical name, token issuance/expiry, disabled-version
propagation and actual cloud audit remain field-unvalidated without customer
inputs. No GCP account or real token is requested or created by local fixtures.

Protocol sources: [versions.access](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access),
[SecretPayload](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/SecretPayload),
[ProtoJSON bytes](https://protobuf.dev/programming-guides/json/#representation-of-each-type),
[canonical project identifiers](https://google.aip.dev/cloud/2510).

## Inherited response-header byte boundary

The production transport must not discard non-ASCII headers before sealing.
HeaderValue::from_bytes accepts valid UTF-8 token bytes while to_str rejects them;
this is not equivalent to malformed input. Extend only the existing wipe-owned
ResponseHeaders holder: valid UTF-8 values retain their exact bytes as strings;
unsupported non-UTF8 values remain owned raw wipe-on-drop bytes for sealing.
Each value belongs to exactly one representation, with no lossy conversion.
Inspect complete name/value bytes before any source resolution or business
response allowlist projection. Unsupported non-UTF8 values remain absent from
the existing String wire projection after sealing; clean such headers do not
turn otherwise valid requests into a new transport failure. Preserve all
existing HTTP/error/deadline/public-IP/proxy/redirect contracts and no new wire
fields, dependencies, validators or generic header abstraction.

Real reqwest HeaderValue/HeaderMap no-listener regressions must cover valid UTF-8
reflection and ASCII/UTF-8 secrets surrounded by nonUTF8 bytes, with clean body
and zero business effect for source reflections. Actual Authority/executor
regressions cover source and business sealing through this production conversion
boundary. Clean unsupported headers remain filtered only after full-byte checks.
Keep the previous frozen source patch/decoder receipts as history; header-stage
production deltas require fresh hash-bound integration checks and independent
static review. This closes a discovered transport prerequisite, not the existing
TLS/UDS EPERM or real-GCP acceptance gaps.

## 2026-09-30 HTTP Bearer edge-OWS sealing correction

A source profile token remains opaque/header-safe and its raw bytes are sent
unchanged. Both source and business sealing additionally retain the exact edge
SP/HTAB trimmed token and single-space Bearer representation when nonempty, with
the same supported encoded forms. This closes the standard HTTP/Bearer parsed
representation gap without token rewriting, JWT parsing, charset restriction,
retry or a generic transform layer. Test source value and source/business header
reflections independently with clean bodies; keep unreflected whitespace input
working, raw transmitted header exact, real HeaderMap and nonUTF8 cases.

Protocol basis: [HTTP field values, RFC9110 section5.5](https://httpwg.org/specs/rfc9110.html#field.values)
and [Bearer scheme, RFC6750 section2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1).

The complete resolved value also remains unchanged in the business request.
Business-response sealing additionally retains its nonempty edge SP/HTAB trimmed
representation and the auth bytes constructed with the existing fixed Action
prefix plus that representation, including standard encodings and header-edge
OWS removal. This is bounded representation sealing at the existing operation;
it does not trim the transmitted credential or claim arbitrary-provider DLP.
Regression probes use a clean independent bootstrap and clean body for header
cases, and separately cover normalized value and complete auth encodings.
