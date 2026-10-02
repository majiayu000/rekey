# EXT-04 Fixed 1Password Connect item field source

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

Implementation contract frozen after the completed Azure/GCP and Opaque/AWS
sealing gates, 2026-09-30: CredentialKind::OnePasswordConnectSource, wire name
onepassword-connect-source, stable AAD code9, state/backup format19,
CREDENTIAL_ROTATE_ONEPASSWORD_CONNECT=44. Reject formats1..18 without migration.
The implementation is integrated for local verification; source uses format19.
This implements the accepted EXT-04 fixed-item/one-field proposal, not a Connect
SDK, deployment, cloud-freshness proof or historical-version reader. Minimum:
this root specification, one private Broker parser/Actor module, one strict
TLS/UDS test file and one protected CLI black-box test; zero new dependencies.
No list/write/file fetch/reference following/OTP/password generation/cache,
refresh, login, ambient identity or private-network exception.

## Protected profile and one fixed request

Closed eight fields: credential_type=onepassword-connect-source-v1, origin,
vault_id, item_id, field_id, expected_item_version, access_token,
local_use_expires_at_ms. The last field is Rekey's declared import-use deadline,
not an asserted Connect token expiry; require future and at most3600s remaining.
Keep the token opaque/header-safe, nonempty and at most16KiB. Protection uses
existing private regular files, per-call step-up (hidden TTY or explicit
--password-stdin), encrypted consume-once Authority storage and body-only IPC;
no token/value/raw profile in argv, env, public metadata, logs or audit.

Origin is canonical fixed HTTPS DNS/default443 without explicit port, userinfo,
path, query, fragment or IP literal; use existing production public-IP screening,
TLS hostname/system trust, no proxy/redirect/retry/custom CA. Customer-hosted
public Connect is allowed. Private Connect remains a separate VEX-01 target-
binding capability, not a fixture-only production exception.

Vault/item IDs each match26 ASCII lowercase letters/digits, not hyphenated
RFC4122 UUIDs. Field ID is a nonempty exact string of at most128 UTF-8 bytes and
no control characters (local bound); username/password and custom IDs are legal.
Expected item version is a positive u32 local bound. CLI typed add-onepassword-connect/rotate-onepassword-connect use protected --file
profiles and existing --password-stdin proof; generic rotate cannot bypass this
kind. Builtin connector onepassword-connect-source@1 uses the existing
CredentialSource operation contract. Single GET
/v1/vaults/{vault_id}/items/{item_id}, Accept and Content-Type application/json,
Bearer imported-token, empty body and no query/version selector. Item version
only matches the current Connect response, not vault.contentVersion/server
version or a historical snapshot. An updated item needs administrator re-
registration; a stale synchronized copy can still match and must not be called
cloud-latest. Real expiry, revocation and vault-wide READ permission are enforced
by Connect; fixed item access does not create item-scoped upstream permissions.

## Closed item projection

Require200 with body<=64KiB; reject duplicate/unknown properties throughout the
known item shape. Require nonnull id, vault.id, category string, integer version,
fields array and every field's nonempty id; IDs/version match the profile exactly
and field IDs are unique. Select exactly the configured ID, never label/purpose/
section. Selected type must be STRING or CONCEALED, selected value a nonempty
UTF-8 string<=8KiB with existing outbound-header safety. No conversion, trimming,
reference following, inferred purpose/type or missing-field fallback.

Known item fields: id/title/category/lastEditedBy/state strings; vault={id};
version integer; urls/sections/fields/files arrays; favorite/trashed bool; tags
string array; createdAt/updatedAt informational strings (the provider models date-times; no
local time parser or admission decision uses them). If state is present only ACTIVE
admits use; ARCHIVED/DELETED/unknown state or trashed=true rejects. This is a
local conservative eligibility contract, not a claim every Connect version
returns these fields. Optional informational metadata can be absent/null;
nonnull values must have the documented type. State and trashed are security
eligibility markers: absent is permitted, explicit null is rejected; state must
be ACTIVE and trashed must be false when present. Security identity/version/core
fields and selected type/value never accept null. Check no new time/freshness
permission from metadata dates.

Known field fields: id/type/purpose/label/value/totp strings; section; generate
bool; recipe; entropy finite number; passwordDetails. Nonselected value/type
may be absent/null, and nonselected type strings are never executed. Section
shape is id/label strings. Recipe shape is length integer, characterSets string
array, excludeCharacters string. PasswordDetails shape is entropy finite number,
generated bool, strength string, history string array. URL shape is primary
bool, label/href strings. File shape is id/name/content_path/content strings,
size integer and section; content is merely an ignored JSON string, never
decoded or fetched. REFERENCE/OTP/FILE/SSHKEY are nonselected type values, not
an invented Reference object. Optional informational nested fields may be
absent/null; present objects remain closed and correctly typed. Do not export
or persist full items, nonselected values, history, titles or metadata; use wiped
owned buffers where controllable and do not claim opaque JSON/library allocations
are verifiably wiped.

## Audits, admission and sealing

execution.started commits before consume-once decrypt; credential-version-bound
onepassword.source.read_started commits before the single source effect. Anchor
source deadline to min(original absolute Action deadline, declared use-window
remaining). Inspect full raw source body and every UTF8/nonUTF8 header byte for
bootstrap reflections before status/parse, then inspect the parsed selected
value against the same bootstrap needles before auth construction/resolved
audit/business so JSON escaping cannot hide a selected bootstrap token; non200 or ErrorResponse/malformed
item fails with fixed public reasons and zero business, without sleeping/retry.
Provider message/request ID/synchronization error details never enter errors or
audit. Do not invent a closed provider-error code list or synchronization SLA.

After complete selection/auth construction, onepassword.source.resolved commits
before business; recheck lifecycle/source use deadline and eligibility. Resolved
business retains the original Action absolute budget, no fictitious secret TTL
from the bootstrap deadline. Audit contains configured public vault/item/field
reference and matched item version plus existing request/credential-version
correlation, never item data or token. Preserve terminal audit and indeterminate
business-effect contracts; an audit commit failure faults Authority and prevents
the next effect.

Sealing retains raw profile/token/fullBearer and selected complete value/full
Action auth plus existing supported encodings. Include the known HTTP parsed
edge SP/HTAB token/value representations and full fixed-prefix auth when nonempty,
while keeping all transmitted bytes unchanged. Independently test source value,
source headers and business headers with clean bodies, including nonUTF8 headers.
No general transformation engine or token charset validator.

## Verification and evidence boundaries

Pure checks cover fixed origin/IDs/profile/body/value limits, builtin/custom field
IDs, expected-version mismatch, all duplicate/null/unknown/type cases, known
metadata union, archived/trashed/missing/unsupported selected types. Actual
Authority/SQLite/executor tests cover one source/one business, durable ordering,
audit failures, use-window exhaustion in source/audit, later business under its
original deadline, cumulative budget/drain and independent reflected forms.
Extend actual kind/AAD/schema, protected typed add/rotate, backup/DEK/VRK and
recovered real source execution tests. Preserve strict TLS/UDS/CLI contracts;
compile them and retain actual listener EPERM failure, never skip/relax or claim
fixtures are TLS/real-cloud acceptance. Root owns shared docs/release/Cargo and
actual-SHA integration/independent review. No commit until required full workspace
passes; real account/token/network/Connect sync/revocation tests stay deferred.

Primary protocol evidence verified2026-09-30:
[Fixed item GET](https://www.1password.dev/connect/api-reference/get-vault-item-by-id),
[API reference and examples](https://www.1password.dev/connect/api-reference),
[Official Go item models](https://github.com/1Password/connect-sdk-go/blob/main/onepassword/items.go),
[Official Go file models](https://github.com/1Password/connect-sdk-go/blob/main/onepassword/files.go),
[Token management](https://www.1password.dev/connect/manage-connect),
[Connect security](https://www.1password.dev/connect/security),
[Synchronization architecture](https://www.1password.dev/connect/concepts).
Full OpenAPI download and exact model revision SHA were unavailable in this
host; the read official pages/models support this bounded local union, not every
server version. Unknown future fields fail closed pending separate review.
