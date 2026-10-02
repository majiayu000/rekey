# VEX-04: explicitly selected latest Vault KV v2 read

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

Frozen 2026-10-01 before code. Accepted local implementation scope is the latest
read slice in external-capabilities.md:186-195. No write/CAS, Namespace, engine,
private endpoint, login or token-renewal extension is part of this slice.

Minimal: existing encrypted profile and execution path, existing source tests,
public version audit using existing AuditDraft/commit_until. No new kind, schema,
AAD, IPC opcode, dependency, generic adapter or config surface.

## Input and execution

Existing vault-kv-v2-source-v1 profile version accepts either its existing exact
positive integer or the explicit literal "latest". Reject0, other strings,
negative/fraction/null/missing/compound values and unknown fields. Numeric exact
requests/metadata equality remain unchanged; do not add alias/default/fallback.
Administrator explicitly authorizes drift by importing a latest profile through
the same protected body and step-up add/rotate flow. Agent never selects version,
URL/path/key or bootstrap identity. Existing exact approvals remain exact.

Latest emits one fixed GET without the version query. Strictly validate the same
response metadata/version/deletion/destruction/key/value envelope; actual version
must be a positive integer. Freeze that returned version and Zeroizing value as
one local result. Use the value once for target authentication and reflected
response sealing; do not query latest again or fall back to older source data.
Numeric exact requires actual metadata.version equal its registered number.

Keep original absolute Action/effect/source deadlines, DNS/TLS/public-egress,
no redirects/proxy/retry, bounded bodies, full header/body/bootstrap sealing and
decoded-value sealing. No plaintext source response or decoded value reaches
Agent output, public errors, logs or audit. No cross-execution plaintext cache.

## Audit and error contract

Use existing connector_event and terminal commit_until for vault.source.read_started
before source IO and vault.source.resolved after strict resolution but before any
target effect. Real audit commit failure retains existing Authority fault and
prevents target preparation/effect. No new Vault command or audit row schema.
Include actual positive Vault version on resolved evidence in bounded nonsecret
reason_code, with fixed source-reference digest and exact/latest selector. Hash
only public origin/mount/path/key references, never bootstrap token or resolved
secret value. Existing audit credential_id/credential_version identify the
Authority payload version; never overwrite them with the external Vault version.
Unresolved/error source does not emit successful resolved evidence or target effect.
Keep existing typed errors and blocked terminal semantics.

## Verification limits

Meaningful socketless pure tests cover both exact and literal latest requests;
actual version mismatch/absence/zero/type, deleted/destroyed/key/empty, invalid
profile selectors and one-read frozen result/decoded-value/header sealing.
Exercise actual Authority/SQLite audit failure and version association using
existing test seams if possible; report precisely which execution phases were
actually exercised. Strict TLS/UDS contract must compile and include a counted
single-read/rotation/fail-closed audit case, but this host's listener gate remains
unpassed. Do not call pure parser or simulated response tests full roundtrip.
Fresh focused/workspace all-targets/Clippy/fmt/mechanical/CLI graph and exact
source-SHA independent review required. No field Vault rotation/IAM/private-CA
claim, commit or publication. Source format stays19 absent actual schema change.

Protocol reference verified 2026-10-01: [HashiCorp KV v2 read API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version)
specifies latest when version is omitted, with version-specific response metadata.


2026-10-01 review clarification before deadline fix: after read_started audit
await succeeds, re-evaluate the original source/effect deadline before entering
the source remote-effect gate. A ready audit result observed after the deadline
must not permit source send/DNS. Construct/recompute request timeout from the
remaining original deadline at this point; never renew it from a cached pre-audit
relative timeout. Guard entry at actual source future polling as needed; preserve
typed timeout/blocked terminal contracts. Do not change generic audit/other
sources or infer target-effect bypass: target already has its own fresh bound.
Add a real Authority ready-after-deadline regression with observed source phase
count, explicitly a socketless seam rather than claimed HTTP roundtrip.
