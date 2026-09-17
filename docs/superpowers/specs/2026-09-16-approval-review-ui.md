# Local approval challenge details in the macOS UI

This extends the APR-09 local inbox and the UX-04 native client with a read-only
challenge detail sheet. It supersedes only the inbox spec's GUI non-goal for
this local view. It does not complete an approval signing or full request review UI.

The bundled CLI remains the trusted IPC boundary. Opening an inbox item runs
`approval get ID` and `approval origin` on the selected local state directory.
The CLI already validates the envelope and origin response; the UI decodes the
required fields and rejects a returned challenge whose request ID differs from
the selected item. Either command or decoding failure shows an error and leaves
no old detail visible. No new IPC message or credential access is introduced.

The sheet shows the challenge's request, tenant, principal, session, action and
version, resource, schema, parameter digest, policy version/digest/rule, allowed
approver IDs, quorum, mode, use limit, creation time, and expiry. A matching
current Action can additionally show method/origin/path only when both ID and
version match. It is labeled as current local metadata, not envelope-signed
content. Unavailable versions are explicitly identified; no latest-version
substitution is made. The raw returned envelope is also available as plain text.

The origin public key is fetched from the local authority and shown for manual
comparison with an independently pinned key. This UI does not verify Ed25519
signatures, pin a key, or claim authenticated operator intent. Signature
verification and signing remain in the independent `rekey-approval-sign` flow.

The envelope contains only a parameter hash. It does not contain the body,
content type, extra headers, or HTTP target. The sheet explicitly states that
exact request parameters cannot be reviewed here and that the original request,
independently selected Action/policy/trust files, and pinned origin key remain
necessary in the signer. There is no approve/sign/execute button or key custody.

The displayed envelope can be exported byte-for-byte as a new 0600 file using
the existing private writer. Export is a snapshot and never claims the challenge
is still pending. Expiry remains visible and is refreshed while the sheet is open.
Lock, disconnection, or workspace switch clears the sheet with existing caches.
No persistence, remote listener, notifications, or background approval is added.

Verification uses the production CLI bridge with synthetic subprocess fixtures
for successful details, missing fields, wrong selected request, and failures in
either CLI command; the existing disposable-vault harness checks real origin
reads and unknown challenge errors. Native Swift compilation and workspace Cargo
check remain required. No GUI clicking or full signer workflow is claimed by
these focused tests.
