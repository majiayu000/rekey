# Fixed HTTP credential parsed-representation sealing

2026-09-30 bounded security completion of the credential-authority fixed-header
contract. Azure/GCP bootstrap and complete resolved-value actual Actor probes
showed raw-only response sealing allowed standard edge-OWS representations to
cross source/business boundaries. Those two private paths are now corrected.
Opaque credentials, Vault KV/dynamic resolved values, AWS resolved values and
Vault bootstrap token paths retain related raw-only patterns; they require actual
input/Actor verification before being reported as confirmed bugs or closed.

Minimum implementation uses the existing sealing module and existing source/
Actor test files, with zero new implementation files/config/dependencies/schema/
IPC operations. One small pure fixed-header representation helper may reuse
existing wiped needle construction at the existing response boundary; this is
not a source platform or generic credential-transformation engine. Keep existing
raw/standard encodings and every existing error/lifecycle/audit/deadline contract.

## Exact byte forms and ownership

Keep all registered raw token/complete value bytes and actual outbound auth bytes
unchanged, including meaningful whitespace. For a nonempty edge SP/HTAB trimmed
value additionally seal that exact value and the auth bytes made using the
already registered fixed Action prefix plus it, including the actual header-edge
OWS removal and existing encoded forms. Never add an empty needle or broad bare
scheme needle, change token charset/input eligibility, reset deadlines or retry.
For an already all-nonwhitespace value the raw bytes/ordinary auth behavior stay
unchanged. This covers fixed known representations, not arbitrary provider
normalization, substring extraction or DLP.

Apply at actual ordinary business preparation and each affected source business
resolver using that existing fixed prefix. Keep source raw-profile/token sealing;
when Vault bootstrap profiles actually accept edge OWS, add only the exact
trimmed X-Vault-Token representation to both source and carried business needles.
Do not change Vault login/namespace/private-network/engine semantics. Existing
AWS SigV4 canonical session-token and Azure/GCP Bearer bootstrap representations
remain intact, not replaced with a generic HTTP authorization parser.

## Required tests and closure

First preserve actual Actor RED evidence for each accepted affected family:
raw value/token accepted, source/business request count, exact raw outbound bytes,
normalized body reflection, normalized UTF8/nonUTF8 HeaderMap reflection with a
clean independent body, and supported encoded complete auth forms. A profile
that rejects edge OWS is documented as already closed at intake; never relax it
just to reproduce. Positive unreflected calls still send exact complete bytes.

GREEN must exercise real Authority/SQLite/consume-once/audit/executor admission
through existing fixtures; no plain helper assertion substitutes for actual
execution. Retain both boundaries for source bootstrap reflections: block before
business when the source reflects, and seal carried bootstrap on business reply.
Header/body paths must be independently clean/positive to avoid masking. Source
and business statuses/error/audit/lifecycle/absolute-budget contracts remain.
Reuse existing raw ResponseHeaders/wiped owned request buffers; no byte-to-lossy-
string gap, production loopback exception or weakened test.

Root freezes source hashes before/after integration; independent review verifies
helper and each actual caller. Preserve Azure/GCP47 and AWS20 source regressions
and other relevant existing source/sealing/ordinary-execution tests. Compile all
strict TLS/UDS cases and retain actual listener failures without skips. Current
full workspace/real provider acceptance remains incomplete, no commit/publish.
Any unverified path stays explicit pending rather than declaring workspace-wide
DLP or all credential models complete.

Protocol basis:
[HTTP field values, RFC9110 section5.5](https://httpwg.org/specs/rfc9110.html#field.values),
[Bearer header syntax, RFC6750 section2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1).
