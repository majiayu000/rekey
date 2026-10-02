# EXT-03 Fixed Azure Key Vault Secret version source

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

Implementation contract, 2026-09-30. AWS final actual-source integration,
focused tests and independent review gates closed before assigning Azure
credential kind/AAD tag8, schema/format18 and typed rotate opcode43. Format17
and all older stores are rejected; no migration or compatibility layer. This implements the accepted
[EXT-03 scope](2026-09-16-external-capabilities.md#ext-03-azure固定版本-key-vault-secret-只读源).
The minimum is four new files: this specification, one private Broker module
with parser/Actor tests, one strict TLS/UDS contract and one CLI black-box test.
Zero new dependencies, SDK, source platform, ambient identity, login/discovery,
refresh, cache, managed identity, metadata endpoint, list/write, field selection,
private endpoint, sovereign cloud or Agent KMS operation.

## Protected profile and fixed request

Closed six-field profile: credential_type=azure-key-vault-source-v1, origin,
secret_name, secret_version, access_token, access_token_expires_at_ms. Use existing
private bounded regular-file reads, per-call step-up (hidden TTY or explicit
--password-stdin), body-only IPC and encrypted consume-once Authority storage.
Reject duplicate/unknown fields and any token/raw profile in public metadata,
argv/env/logs/audit. No JWT parsing or inferred token expiry/tenant identity.

Origin is exactly https://{vault}.vault.azure.net: canonical lowercase commercial
hostname, default443 without explicit port/userinfo/path/query/fragment. Vault is
3..24 ASCII lowercase letters/digits/hyphen without edge/consecutive hyphens.
Secret name is1..127 ASCII letters/digits/hyphen. Version is exactly32 ASCII
letters/digits; the provider documents an opaque identifier, not universally hex.
No empty/latest alias, URL escape, private/alternate suffix or endpoint catalogue.
Opaque token is nonempty<=16KiB, outbound-header safe, with explicit declared
future expiry and at most3600s remaining; this does not prove actual Entra validity.

One GET /secrets/{name}/{version}?api-version=2025-07-01, Accept application/json,
Bearer imported-token, no body/business input. Keep the accepted API version;
no7.4 compatibility path (its Learn view redirects to newer docs). Existing
public-IP-screened fixed TLS transport retains no proxy/redirect/retry/custom CA.
No extra401 tenant/challenge discovery or login. Cap source response64KiB and
complete nonempty UTF-8 value8KiB; no trimming/base64/contentType conversion.

## SecretBundle, time eligibility and effects

200 response requires unique value and id. Compare the returned ID to the entire
registered origin/secrets/name/version string with ASCII case-insensitivity,
which the provider specifies for object IDs. No URL decoding/normalization,
prefix match, redirect or alternate vault/version. Allow the known optional
attributes/contentType/kid/managed/previousVersion/tags using official types;
reject duplicate/unknown/mistyped fields. These metadata fields are not exposed
or used as header content. SecretBundle value is a string, not a certificate
conversion or configurable subfield selector.

Attributes absent means{}; enabled absent defaults true, nbf absent permits
immediate use, exp absent imposes no provider metadata expiry. These defaults do
not override source-token or Action limits. Explicit null attributes/enabled/
nbf/exp, noninteger security timestamps and seconds-to-ms overflow are rejected;
created/updated are informational and may be absent/null. Security timestamps
are signed integral Unix seconds converted with checked seconds-to-ms arithmetic;
a negative nbf is already in the past, while a negative exp is expired. Known
informational attributes recoveryLevel (string) and recoverableDays (int32) are
accepted when correctly typed; no deletion/recovery behavior is implemented.
Reject enabled=false,
nbf>now or exp<=now. GET can return expired or not-yet-valid values, so enforce
these local eligibility conditions after parse and again after resolved audit,
before business dispatch. This bounds admission; it cannot withdraw sent effects
or prove the business provider actually revoked a token at Key Vault metadata exp.

Durable execution.started precedes consume-once decrypt, then credential-version
bound azure.source.read_started precedes source IO. Anchor source deadline to
min(original absolute Action budget, token remaining lifetime) before sending.
Check complete raw body/header bytes for profile/token/fullBearer reflections
before status/parse, including unsupported nonUTF8/error/disallowed headers.
Use the existing wiped response-header byte boundary, not a second transport
abstraction. Parse and construct complete auth with existing CR/LF/NUL safety;
commit azure.source.resolved before business, then recheck token/source deadline,
secret eligibility and lifecycle. Bootstrap expiry only bounds the source phase;
resolved value has no inferred bootstrap TTL, and business retains the original
Action absolute deadline. Secret exp eligibility remains independent; no new
full timeout or source retry. No dynamic lease journal or provider cleanup.

Sealing also retains the raw profile, token/Bearer, resolved value and complete
business auth with existing supported JSON/encoded representations. Imported token bytes stay unchanged in the outbound header. In addition to
raw token/fullBearer, source and business sealing retain the exact edge SP/HTAB
trimmed token and its single-space Bearer representation (when nonempty). HTTP
field edge OWS and Bearer scheme separation can expose these standard parsed
representations; this is a fixed protocol representation, not a generic
transformation engine or a new token charset validator. No source retry, profile
input restriction or provider-token validity/expiry inference is introduced. Azure raw
message/request ID/error/header never enters audit/errors; use fixed reasons and
existing Rekey request correlation plus configured public reference/version.
Source403/429/disabled/mismatch/expiry/reflection/audit failure yields zero business.
Existing terminal audit and indeterminate business-effect contracts remain.
Do not claim opaque library allocations or Swift files are verifiably wiped.

## Verification and bounded claims

Private pure tests cover origin/path/version/expiry/header/profile rejection,
legitimate known optional metadata, case-only ID differences, wrong vault/name/
version, duplicate/unknown/null/types, value/body limits and attribute defaults/
boundaries/overflow. Actual Authority/SQLite/executor tests exercise durable
ordering, once-only source/business, audit failures, token expiry during source/
audit versus later business, secret exp before dispatch, original cumulative
budget, drain and raw UTF8/nonUTF8/reflected bootstrap/value bytes. Expand fresh
kind storage/backup/DEK/VRK/AAD/schema rejection, typed add/rotate and pure CLI
protected input tests. Strict TLS/UDS and CLI positive chains remain in source;
compile them without weakening/skipping for current listener EPERM. Root owns
shared docs/release/Cargo.lock and final actual-hash integration/independent review.

No current full workspace, GUI or real Azure tenant/firewall/RBAC/token-revocation
acceptance is claimed. Do not commit/publish without the required full suite.
Real credentials and customer environment remain deferred by user instruction.

Primary sources verified2026-09-30:
[Get Secret2025-07-01](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01),
[Secret attributes](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets),
[Object IDs](https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates),
[Authentication](https://learn.microsoft.com/en-us/azure/key-vault/general/authentication).

The complete resolved value also remains unchanged in the business request.
Business-response sealing additionally retains its nonempty edge SP/HTAB trimmed
representation and the auth bytes constructed with the existing fixed Action
prefix plus that representation, including standard encodings and header-edge
OWS removal. This is bounded representation sealing at the existing operation;
it does not trim the transmitted credential or claim arbitrary-provider DLP.
Regression probes use a clean independent bootstrap and clean body for header
cases, and separately cover normalized value and complete auth encodings.
