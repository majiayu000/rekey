# Unified experiment integration (development contract)

Status: implementation integrated; combined-head software verification is recorded in [the integration record](../plans/2026-10-09-experiment-integration.md). No release or existing-vault upgrade is authorized by this document.

This contract supersedes conflicting format and authorization clauses only for the next development line. The published 0.4 line remains vault26 / policy7. The 0.5.0-alpha.1 development line uses vault27 / policy8; non-current layouts are rejected with no migration, double reader, or backfill. Existing user vaults and the installed app are left untouched.

## Minimal integration

- Retain signed, tokenless Connections, OAuth, T1 derivation, and Worker-owned SSH keys from main. Existing HTTP/SSE optimizations already present in main are not duplicated; the remaining accepted direct JSON map, single-field SSE borrowing and boundary scanner changes are retained with their equivalence and split-frame security regressions. The implemented child-exit event watcher replaces periodic waits on macOS/Linux while preserving control-channel revocation and reaping ownership.
- Extend the existing Connection authentication declaration with an explicit mTLS alternative. mTLS is T0, fixed HTTPS only, with no header credential injection. Its credential kind is `mtls-identity`, AAD code 16. The Worker checks the current signed Connection digest and committed execution before releasing a consume-once TLS identity. The one-shot TLS/TCP owner is drained before mutation acknowledgement; no pool, resumption, redirects, ambient proxy, or private-address targets.
- Add administrator-only `pki-ca-signer`, AAD code 17. Import and version-checked rotation require fresh A2 proof and secret body input. Ordinary preparation/reveal and Agent binding reject CA keys. External CSR issuance, serial revocation, and full CRL publication remain Worker operations with the experiment's constrained certificate profile.
- Add only the certificate and CRL fact tables required by implemented PKI. Their complete collection digest is authenticated by the existing generation MAC; reservations, terminal facts and audit commit atomically. Backup, restore, DEK/VRK rotation and restart recovery use that same generation contract.
- Unowned reservations (owner decision 2026-11-17): a certificate or CRL is delivered only after its terminal commit, and the Worker runs each issuance or CRL from reservation to terminal commit inside one command. Full CRL publication refuses while any certificate reservation exists rather than silently omit a potentially signed leaf. A reservation present when the vault unlocks from Locked (the Worker starts Locked and returns to it after a lock or a confirmed rollback) by password, recovery or remembered-unlock resume has no running owner and was never delivered, for example after a Worker crash. Before that unlock publishes the unlocked state it finalizes every such certificate and CRL reservation to the existing Failed state (2) in one generation commit: the collection digest and MAC advance atomically with one `pki.certificate.finished` or `pki.crl.finished` audit per row, outcome `failure`, reason `abandoned-on-unlock`, carrying the reservation's request and credential IDs. Serial revocation and full CRL publication then proceed. A finalized serial was never issued, so it is not revocable, not listed and not reused; a finalized CRL number is not reused. A failed finalization fails that unlock under the ordinary generation rules (integrity and audit failures fault). A reservation seen while Unlocked, such as after a failed terminal commit, keeps the full-CRL refusal until the next unlock from Locked; re-authentication is not recovery. A confirmed rollback discards later facts, including any later completion of a reservation captured in the snapshot. No schema, format, audit kind or audit field changes.
- Preserve main SSH identity kinds 11/12/13 and Worker signing. Adapt the implemented pending-peer cancellation, live output checks, atomic approval/started audit, and completion ownership. Extend signed SSH policy for external one/two-approver grants and numeric session budgets using existing approval/quota machinery; no parallel SSH action database or exported signer. Each signed SSH key declares `approver` and `session_budget {max_signatures,max_seconds}`. The budget limits signatures on each agent socket from its first sign request and is separate from one-time approval use. External grants bind the complete existing challenge, with distinct allowed approvers and approval IDs; a quorum is submitted together through `approval submit` on stdin. Local-presence approval cannot satisfy an external-authority challenge. Pending EOF, extra pipelined bytes, shutdown or expiry cancels the challenge; once the Worker command is queued, its owner awaits terminal completion before releasing the lifecycle permit. Every response write polls under the current policy and lifecycle gate.
- Integrate accepted action-collection authentication only where the retained lab action API remains executable. Connection records already bind the complete signed snapshot; they do not acquire a second authorization ledger.

No new Agent PKI admission is included, and this contract adds no HA. The single-host Docker recovery controller was integrated later under its own [contract](2026-10-09-docker-ha-controller.md); multi-host HA remains out of scope. No historical green test count is a unified-head result.

## Personal desktop authentication correction (2026-10-23)

Decision: use the existing App review and system-authentication flow for interactive
`rekey add` on macOS when the App and default workspace are available. Explicit
stdin and custom-workspace CLI usage retain the existing basic-mode path. Public
connection options must survive the handoff; a launch receipt is not activation.
No secret or management proof is included in a URL.

The App checks signing availability before saving onboarding credentials. It uses
the authenticated installed signer ID from `policy status` even before the first
bundle is activated; locked/unavailable authority state does not expose it. It uses
the key matching the installed trust: either the existing Secure Enclave key or
the existing basic-mode software P-256 key through the bundled signer. It displays
which protection applies, never generates a replacement or switches the trust,
and fails before credential persistence when the key is unavailable or mismatched.
Software signing does not claim hardware isolation. The daemon still requires
fresh A2 proof for activation; an A1 desktop session cannot authorize it.

The password recheck interval (including 30 days) only controls the existing
system-authentication grant. Reviewed activation still requires fresh presence,
or the original password/recovery proof. Grant renewal, password changes, and
recovery-factor changes retain their original-factor requirements. The App handoff never reads `remembered-unlock.key` or uses it as a presence proof. Full vault lock and desktop privacy lock keep
their existing distinct behavior.

Draft metadata must project the canonical snapshot actually signed, including
connection ordering. The App keeps its exact review/signature equality check.
Saved credentials remain reusable after cancellation or later draft failure.

Acceptance: unsorted multi-connection requests round-trip and activate; missing
or mismatched signers fail before saving; software and hardware modes keep the
installed trust; cancellation never activates; CLI options round-trip without
secrets. With a valid system-authentication grant, add/review/activate requires
zero master-password entries, targeting one system-authentication prompt (up to
two if the OS separately protects the signing key). Hardware prompt counts need
device evidence. Stop if this requires trust replacement, format changes, or a
general authentication service; those are outside this correction.

## Verification

Run repository format/check/Clippy/test and mechanical dependency gates on the combined head. Exercise real TLS client authentication, PKI CSR/serial/CRL/restart/backup/rotation/tamper paths, native SSH approval and cancellation/owner drains, and the current Connection/OAuth/T1 contracts. Keep hardware/Touch ID/Secure Enclave and real deployment evidence separate from software fixtures. Preserve the native startup regression from the auto-connect fix.
## Shared control owner capacity (issue #70)

Keep seven short admin requests independently available at the full quota of
16 live native SSH/Profile owners. Accept at most 23 normal admin connections,
plus one bounded capacity responder. Profile registration consumes a short
request slot only until registration completes; an idle control does not hold it.
Admission uses immediate retryable `AUTHORITY_BUSY` on RKIP. Native OpenSSH
capacity refusal remains a bounded socket close under its existing protocol.
These are private constants, with no configuration, schema or opcode changes.

The shared owner permit belongs to the real socket, registration and admitted
execution. Profile registry entries retain only Weak references. Revocation
prevents further admission immediately, while queued Authority work and admitted
effects retain strong ownership until actual completion. EOF during registration
drains already queued work before releasing its owner; it never publishes a token
to a disconnected client. Registration deadlines prevent late admission, but
cleanup may outlive the deadline while the Worker finishes. Gateway replacement
cleanup is not established by this quota contract.
