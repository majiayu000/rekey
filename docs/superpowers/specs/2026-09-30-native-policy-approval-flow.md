# Native local policy and approval file flow

Status: frozen follow-up implementation contract, 2026-09-30. User authorization
to complete designed capabilities covers this bounded native file flow. It
extends POL-09/APR-09, with UX-04 as their summary. It supersedes only the prior
read-only review UI non-goal that excluded an execute entry; review/signature
verification and private signing material stay in the existing independent
signer/Broker chain. No policy engine, rule editor, remote login, new CLI/IPC,
source-kind wiring, state format or signing backend is added.

The minimum touches existing App.swift, Forms.swift, Model.swift and the native
bridge contract test, plus this one specification. Root owns shared baselines,
full-suite checks and future real native-click acceptance. Use a separate frozen
source snapshot with file ownership disjoint from other implementation writers.

## Three explicit local steps

Policy page accepts one operator-authored unsigned draft file, at most 64KiB.
Read regular nofollow/nonblocking bounded UTF-8 bytes, show the complete plain
text snapshot with an unsigned/unvalidated label, and export those exact bytes
to a new mode-0600 file. Do not rewrite JSON, generate/merge rules, infer policy
version or sign. Show fixed independent policy-sign review/sign handoff steps;
UI neither receives private key paths/bytes nor invokes the signer. Existing
trust installation and signed policy activation remain separate step-up calls.

From an existing pending challenge and its full read-only details, choose the
original UTF-8 JSON body. This slice uses application/json and no extra headers.
Display the full original snapshot; a digest does not reconstruct the body.
Export a new private REQUEST.json containing the displayed challenge envelope,
content_type, empty headers and original body for the existing independent
approval-sign tool. Explain that Action/policy/trust and independent origin pin
need the existing trusted channel. File export is not approval or authorization.
Keep existing origin/ID/version warnings and verifier ownership unchanged.

The selected challenge has a separate explicit execute form: original body,
one or two signed grant files, and capability in SecureField. Always use its
exact action_id@action_version; never substitute a later local Action version.
Show the matching Action target as local metadata and submit exactly once after
explicit user confirmation in the form. Do not prepare a new challenge, sign,
refresh a session, poll or retry automatically. Fixed argv is existing execute
with --capability -, --body-file, --content-type application/json and one/two
--approval paths. Capability goes only through the anonymous stdin pipe. It is
not an Admin step-up proof and never enters argv, environment, logs, preferences,
Keychain, export files or automatically created receipts.

## Snapshot, result and lifecycle boundaries

Read files by descriptor: regular, nofollow/nonblocking and bounded. Draft limit is 64KiB and each grant limit is 4KiB, matching the existing
CLI protected grant reader; body must meet the existing Agent/body and selected
Action limits. Preserve exact UTF-8 bytes including newline/whitespace. Before
reading a body, decode the registered Action's `request_policy.max_body_bytes`;
`request_max_bytes` belongs only to the creation input, not returned Action metadata.
Missing returned limits fail decoding rather than silently using a default. Before
submitting, create a private 0700 temporary directory and new synced 0600
body/grant snapshots from the displayed bytes; CLI reads these snapshots so a
changed operator file cannot silently alter what was previewed. Do not persist
the capability. Clean only these owned snapshots after success/failure; cleanup
failure is visible and is not secure erasure. Source files remain untouched.

Reuse the existing fixed argv/filtered environment/pipe/bounded-output Process
bridge and writePrivateNew. Preserve actual local NSError and CLI exit/stderr
contracts; never include file contents/token/provider raw data in diagnostics.
A failed new read clears old preview. File-dialog cancellation cancels only that
local step. Workspace switch, lock, disconnect, form close or loss of focus clear
capability, private previews and results. Async completion must match the same
workspace/form intent before updating visible state. Swift String memory does
not provide a verifiable zeroization claim. Closing a form does not undo a
remote effect; interruption/timeout remains unconfirmed and never auto-retries.

Execute stdout begins with the existing serde_json pretty-printed metadata
object, whose root closing brace is a standalone unindented line followed by LF.
Then come exactly body_len binary body bytes and, for a nonempty body, the
existing final LF. Parse this fixed CLI rendering boundary with the existing
output cap; the first LF is not the metadata boundary.
Do not decode the entire output as JSON or lossy UTF-8. Show Broker metadata and
actual HTTP status; CLI exit zero does not imply business HTTP success. Binary
body shows its length and offers explicit new-private-file saving. Broker alone
checks grant/signature/session/parameters/policy/expiry/use. No UI authorization
validator or mirrored digest/signature implementation is added.

## Verification

Synthetic native bridge/file tests cover exact argv/body/grant snapshots, token
absence from argv/env/files/errors, changed source files after preview, private
new-only exports, limits/symlink/nonregular errors, actual NSError/CLI failures,
empty/binary/malformed mixed responses and non-2xx HTTP, lifecycle stale-result
rejection and no automatic retry. Keep existing read-only detail/ID/version
contracts. Run strict Swift typecheck/compile and workspace check; actual
signer-to-Broker positive/parameter/session/replay contracts stay authoritative.

Current host denies TCP and Unix listeners. Full Broker/native bridge and click
acceptance remain blocked when their fixtures need a listener; compilation or
synthetic Process tests do not prove actual GUI interaction. Later use a unique
QA bundle ID and random synthetic state directory, no real ~/.rekey/preferences
or real Keychain entries, to click the complete file-review-sign-import-execute
flow and negative/replay path. Record actual checks separately. This slice is
not a graphical rule authoring tool or a remote IdP/inbox login client.

Read-only approval detail completion also captures the same native flow revision
and active-window intent. Success and error callbacks must not repopulate private
flow state or reopen its sheet after focus loss, clearing or workspace change.
Grant file boundary regressions include 4096 bytes accepted and 4097 rejected;
client previews do not silently permit inputs the existing CLI refuses.

The metadata renderer is the actual commands/mod.rs print_json path, not a
compact one-line fake CLI. Regression fixtures use its pretty-object shape and
include empty/binary/non2xx responses, escaped JSON newlines/nested header arrays,
and body bytes containing the same closing-line marker. No generic JSON stream
parser, CLI format switch or compatibility fallback is introduced.
