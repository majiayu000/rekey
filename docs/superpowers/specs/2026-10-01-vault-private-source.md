# VEX-01: one bound private Vault source

Frozen 2026-10-01 after VEX04 final independent closure and root17 tests.
Minimal version: optional encrypted-profile source_endpoint containing only
allowed_ips and ca_der_base64; four existing production modules and their tests,
no new credential kind/schema/opcode/dependency, service or global network option.
A limited Vault-source transport entry/trace is needed to apply fixed CA and
report selected endpoint. No shared pool, cache, generic CIDR policy, tenant
lookup service, backend platform, aliases or compatibility migrations.

## Binding and ownership
Both current KV and dynamic profile markers retain their closed shapes and may
explicitly include source_endpoint: {allowed_ips: [literal IP strings],
ca_der_base64: [base64 DER certificate strings]}. Omission keeps public source
semantics. Explicit null, duplicates, unknown fields, empty sets, invalid CA,
duplicate IP/cert, wildcards, CIDR and hostname entries deny import. Reuse
existing 64KiB credential/frame limits; no speculative profile-size modes.
Only RFC1918 IPv4 and IPv6 ULA literal targets are accepted in this private slice.
Reject unspecified, loopback, link-local/metadata, multicast, documentation,
IPv4-mapped/NAT64/6to4/other translated IPv6. Fixed origin supplies hostname/port
uniquely; require a valid DNS hostname for bound source, no IP-literal origin.

The binding belongs to the actual Authority through its existing vault-ID AAD
and immutable credential version. Existing tenant/node/actual-vault registration
is the deployment boundary. Principal ID is not tenant ID. No added profile
tenant/vault fields or status double probe. Trusted Admin independently checks
IP/CA/service ownership; this does not prevent plaintext mis-import by that Admin.
Rotate IP or CA only by explicit existing credential rotation, producing a new
credential version, which is also the public binding version.

## Request and audit boundary
Only fixed KV read and dynamic acquire/renew/exact-revoke source calls use this
binding. Business Action and other sources retain ordinary public transport.
Resolve every source request under the original absolute deadline, screen every
answer against the exact registered set and port, deny empty/mixed answers, then
pin one selected SocketAddr while retaining hostname URL/TLS/SNI verification.
Never reconnect to another address, re-resolve as fallback or retry a request.
Disable built-in TLS roots and add only fixed CA DER for this per-request client.
Keep redirect-none, no_proxy, bounded response and connect/absolute time limits.
Unsupported bound transport implementations deny; never fallback to send().
Existing test-only loopback injection must not become a production exception.

Retain existing durable source/effect intent before source IO. Bind the new
public attempt evidence to the actual credential ID/version and execution or
lease registration context: selected IP only when validated, phase and outcome.
Use existing Authority audit/TerminalAuditTracker; no new table or audit service.
Commit result/target evidence before accepting source result or starting business;
audit failure fails closed, acquired/uncertain effects still follow exact cleanup
and journal unknown semantics. Timeout/cancel must not fabricate successful
connection evidence. Do not log token/profile/lease ID/response or raw errors.

Historical journal cleanup reparses the exact historical encrypted profile,
including its old IP/CA set, not the current version. Old binding failure remains
unconfirmed; no alternate identity or new destination. No journal schema fields.

## Verification
Pure actual runtime cases cover closed profile, duplicate/null/malformed binding,
exact DNS set/port, RFC1918/ULA and translated-address rejection. Socketless fake
transport cases prove bound-source routing and ordinary target routing; real
Authority/SQLite cases prove credential-version/endpoint/phase audit and fail
closed on audit error, with unknown cleanup retained. These are not TLS roundtrips.
Add/compile strict TLS fixtures for fixed-CA-only, wrong CA/hostname, redirect,
DNS rebind/mixed answers, proxy ignored and no private permission in target.
Current host refuses listeners: do not run known-invalid listener checks again
or mark compilation as runtime acceptance. Offline/check/Clippy/fmt/mechanical
contracts and fresh independent actual-SHA review required, no commit/publication.
Real private DNS/routes/CA/ACL and cross-tenant VM egress remain deferred.

## Independent review clarification (2026-10-01)

Each dynamic exact-revoke attempt must carry the original absolute cleanup/effect
deadline through request construction and transport first poll. Never convert
to a cached Duration and restart it from a later now. Future construction before
the deadline and first poll after it must enter no source phase or transport.
This forbids deadline extension; it does not promise kernel realtime delivery.

Audit ACK wait timeout or ready-success observed after its original deadline is
a deadline failure, not proof of durable audit commit failure or Authority fault.
Preserve the existing typed operation error/retry contract. Only a real commit
failure may surface AUDIT_COMMIT_FAILED. Keep source/result/target fail-closed,
preserve exact cleanup/unknown effects and report actual audit error; do not
return source/business success on any expired audit wait. Real Actor/SQLite
delayed/late-ready tests must assert public code and actual healthy/faulted state,
besides checking target denied. Preserve the two P1 original reports/evidence.
