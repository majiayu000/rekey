# EXT-01 Fixed AWS Secrets Manager version source

Frozen minimal implementation contract, 2026-09-30. This implements the accepted
[EXT-01 read-only source](2026-09-16-external-capabilities.md#ext-01-aws固定版本-secrets-manager-只读源)
after the GCP header/decoder integration and independent review gate. Four new
files maximum: this spec, one Broker source module with private parser/signing/
Actor tests, one real Broker contract test, and one CLI black-box test. Reuse the
existing source lifecycle, transport, Authority envelope and protected IPC input;
no SDK, discovery, refresh, cache, list/write/label selector or Agent KMS API.
Root owns docs/release/lockfile and dependency changes; one writer owns shared
CredentialKind/schema/IPC/executor source wiring.

## Protected registration

The closed nine-field profile is credential_type=aws-secrets-manager-source-v1,
origin, region, secret_arn, version_id, access_key_id, secret_access_key,
session_token, and credentials_expires_at_ms. Profile uses the existing <=64KiB
private regular-file input and per-call step-up; payload travels only in frame
body and encrypted storage. Reject duplicates/unknowns and derive no ambient
identity. CLI add-aws-secrets-manager/rotate-aws-secrets-manager use --file and
existing hidden TTY or explicit --password-stdin proof. No secret argv/env/metadata.

Only an explicit origin exactly equal to
https://secretsmanager.{region}.amazonaws.com is accepted. Region is a bounded
ASCII regional identifier (letters/digits/hyphen, no dot/control/escape, canonical
lowercase and terminal numeric component); cn-/us-gov-/us-iso variants are outside
this commercial arn:aws slice. No endpoint catalogue, arbitrary hostname,
FIPS/dualstack/private endpoint/port/query or custom CA. Full ARN must bind the
same region and one 12-digit account: arn:aws:secretsmanager:REGION:ACCOUNT:secret:
NAME-SUFFIX, with the full provider six-character suffix and its permitted ASCII
name characters; at most 2048 bytes. It is never sent as a URL/path. VersionId is
explicit 32..64 characters, bounded UTF-8 with no control characters; do not
assume every valid version is hexadecimal. Serialize exact SecretId/VersionId as
JSON, never a staging label or partial ARN. Exact response ARN/VersionId must match.

Access key ID is bounded safe ASCII suitable for the SigV4 Credential component,
secret access key is nonempty <=16KiB, and opaque session token is nonempty
<=16KiB and satisfies existing outbound header safety. A required session token
and declared future expiry with <=3600s remaining describe an imported temporary
credential; they do not prove actual STS validity/revocation or IAM permission.
Reserve kind aws-secrets-manager-source/AAD code 7, state/schema format 17 and
Admin rotate opcode 42. Reject every earlier state/backup without migration;
preserve all GCP and format-15 journal invariants. CLI remains pure IPC.

## One fixed source read

Existing Action/capability/policy/approval admission and durable execution.started
precede consume-once profile decryption. Commit source-read-started with actual
credential version and configured public ARN/version plus existing Rekey request
correlation before one signed POST / to the fixed origin. Request body contains
only SecretId and VersionId; headers include fixed application/x-amz-json-1.1,
x-amz-target secretsmanager.GetSecretValue, host, UTC x-amz-date, required
x-amz-security-token and AWS4-HMAC-SHA256 Authorization. Canonicalize/sign the
exact serialized bytes, sorted lowercase signed headers and empty query; no
proxy environment, redirects, retries, endpoint/user-agent discovery or business
input in source IO. Source response is capped at 64KiB, value at 8KiB nonempty
complete UTF-8, matching the fixed HTTP token contract rather than the cloud's
larger general SecretString limit.

Use existing aws-lc-rs 1.18 HMAC-SHA256 and sha2, with bounded zeroizing derived
key buffers; do not implement cryptographic primitives. UTC date conversion uses
cached locked time 0.3.55, the only new direct dependency (no new resolved package
or upgrades). No unsafe date ABI, shell AWS CLI or Python production subprocess.
Independent published SigV4 vector must test actual signing derivation in addition
to an independently verified fixed Secrets Manager request fixture.

Anchor the source absolute deadline before signing/sending to min(original Action
deadline, declared credential remaining lifetime). Parsing, audit and lifecycle
checks cannot restart it; recheck expiry/deadline after parse and resolved audit
and before business. Bootstrap expiry is not a TTL for SecretString: subsequent
business retains the original Action deadline. Seal full bootstrap/raw profile/
access-key/secret/session/Authorization representations in complete upstream
body/header bytes before response parsing, including non-UTF8/disallowed/error
headers. No provider request ID/error/raw bytes enter audit/errors: retain the
existing Rekey-generated request correlation, public resource/version and fixed
safe outcomes. A reflected provider ID is not an exception to sealing.

A 200 response requires unique ARN, VersionId, SecretString and permits the known
optional Name, CreatedDate and VersionStages fields with their actual API types;
reject duplicate/unknown fields, any SecretBinary (including null), mismatches,
empty/oversized value or invalid header auth composition. No field extraction,
trim, conversion or inferred latest version. Never log serde/provider raw errors.
Use zeroizing raw/parsing/derived-signing buffers where the existing source
contract permits; no verifiable wipe claim for opaque library contexts. Commit
resolved audit before preparing business. Existing full response sealing,
terminal audit, lock/drain and indeterminate effects remain unchanged. Source
failures/denial/expiry always yield zero business, without old-version fallback.

## Verification and current limits

Cover independent official SigV4 derivation, exact signed body/headers, declared
expiry/action deadline, malformed/duplicate fields, exact ARN/version, legitimate
optional metadata, binary rejection, full unchanged value, CR/LF/NUL denial,
full bootstrap and value reflection in real HeaderMap bytes, audit failure and
lock/drain with real Authority/SQLite/executor no-listener tests. Fresh-kind
AAD/encryption/typed rotation, schema rejection, backup, DEK/VRK rotations and
protected CLI rejection/dependency checks are required. Strict TLS/UDS positive
contracts remain in source and compile; the current EPERM listener restriction
must be reported if it prevents actual runs. No timeout weakening or silent skip.

Full current workspace is not green; no commit/publication follows until the
required full suite passes in a permitted environment. Real AWS IAM/KMS,
canonical ARN/version, STS expiry/revocation and CloudTrail evidence remain field
unvalidated. No account or real credential is created/requested for local fixtures.

Primary protocol sources verified 2026-09-30:
[GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html),
[SigV4 signing](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html),
[time OffsetDateTime](https://docs.rs/time/0.3.55/time/struct.OffsetDateTime.html).

## Imported session-token request copies

The existing UpstreamRequest header vector now carries the imported STS token in
x-amz-security-token. Add only a wipe-on-drop implementation for its Rekey-owned
header Strings and mark that fixed header sensitive at reqwest conversion;
retain request shape, transport/error/deadline contracts and existing auth/body
buffers. Minimal necessary existing-file adapters for Drop restrictions may use
mem::take, without changing effects or introducing a new header abstraction.

## SigV4 session-token header normalization sealing

The imported opaque token remains unchanged in protected input/outgoing header.
AWS canonical header signing trims edge SP/TAB and collapses their runs. Retain
both original and this exact signed canonical token representation in source and
business sealing needles, using the same normalization function as signing.
This is a known protocol representation, not a new whitespace validator or
arbitrary transform engine. Canonical-token reflection in response body or raw
headers must block source/business even if only the normalized value appears;
all existing bootstrap/material buffers remain wipe-owned as described above.
