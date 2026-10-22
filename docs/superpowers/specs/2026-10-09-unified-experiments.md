# Unified experiment integration (development contract)

Status: implementation integrated; combined-head software verification is recorded in [the integration record](../plans/2026-10-09-experiment-integration.md). No release is authorized by this document. Existing vaults change only through the explicit offline migration below, run by the owner.

This contract supersedes conflicting format and authorization clauses only for the next development line. The published 0.4 line remains vault26 / policy7. The 0.5.0-alpha.1 development line uses vault27 / policy8; open, unlock and restore reject non-current layouts with no in-place upgrade, runtime double reader, or backfill; the only cross-line path is [upgrade migration](#upgrade-migration) into a new vault. Existing user vaults and the installed app are left untouched.

## Minimal integration

- Retain signed, tokenless Connections, OAuth, T1 derivation, and Worker-owned SSH keys from main. Existing HTTP/SSE optimizations already present in main are not duplicated; the remaining accepted direct JSON map, single-field SSE borrowing and boundary scanner changes are retained with their equivalence and split-frame security regressions. The implemented child-exit event watcher replaces periodic waits on macOS/Linux while preserving control-channel revocation and reaping ownership.
- Extend the existing Connection authentication declaration with an explicit mTLS alternative. mTLS is T0, fixed HTTPS only, with no header credential injection. Its credential kind is `mtls-identity`, AAD code 16. The Worker checks the current signed Connection digest and committed execution before releasing a consume-once TLS identity. The one-shot TLS/TCP owner is drained before mutation acknowledgement; no pool, resumption, redirects, ambient proxy, or private-address targets.
- Add administrator-only `pki-ca-signer`, AAD code 17. Import and version-checked rotation require fresh A2 proof and secret body input. Ordinary preparation/reveal and Agent binding reject CA keys. External CSR issuance, serial revocation, and full CRL publication remain Worker operations with the experiment's constrained certificate profile.
- Add only the certificate and CRL fact tables required by implemented PKI. Their complete collection digest is authenticated by the existing generation MAC; reservations, terminal facts and audit commit atomically. Backup, restore, DEK/VRK rotation and restart recovery use that same generation contract.
- Preserve main SSH identity kinds 11/12/13 and Worker signing. Adapt the implemented pending-peer cancellation, live output checks, atomic approval/started audit, and completion ownership. Extend signed SSH policy for external one/two-approver grants and numeric session budgets using existing approval/quota machinery; no parallel SSH action database or exported signer. Each signed SSH key declares `approver` and `session_budget {max_signatures,max_seconds}`. The budget limits signatures on each agent socket from its first sign request and is separate from one-time approval use. External grants bind the complete existing challenge, with distinct allowed approvers and approval IDs; a quorum is submitted together through `approval submit` on stdin. Local-presence approval cannot satisfy an external-authority challenge. Pending EOF, extra pipelined bytes, shutdown or expiry cancels the challenge; once the Worker command is queued, its owner awaits terminal completion before releasing the lifecycle permit. Every response write polls under the current policy and lifecycle gate.
- Integrate accepted action-collection authentication only where the retained lab action API remains executable. Connection records already bind the complete signed snapshot; they do not acquire a second authorization ledger.

No new Agent PKI admission is included, and this contract adds no HA. The single-host Docker recovery controller was integrated later under its own [contract](2026-10-09-docker-ha-controller.md); multi-host HA remains out of scope. No historical green test count is a unified-head result.

## Upgrade migration

Owner decision 2026-10-22: user data may cross release lines through an in-Authority migration instead of forcing a new vault per release. This supersedes the "no migration" clauses of the 0.3/0.4 SPECs and the per-feature Lab SPECs for released formats 25 and later.

- `rekeyd migrate --from <old-state-dir> --to <new-empty-dir> --password-stdin` (`rekey migrate --from` delegates; the CLI links no crypto). Offline like restore: the source must not be in use (shared lock on its `broker.lock`), have no init/restore marker, and be at its own generation high-water.
- The source is never written. Its database (and WAL) is copied into a private 0700 scratch directory and read by a frozen reader that accepts only the released vault25, vault26 and vault27 layouts, pinned by `sqlite_schema` and header schema digests. Formats older than 25 stay rejected.
- The password unwraps the source VRK; the reader verifies the header MAC (v1 for 25/26, v2 for 27), integrity mark, every credential state seal, every version payload, policy state/trust/bundle seals and audit retention. Plaintext stays inside the process and is never exported or passed to an Agent.
- The target is a normal init (same password, new vault id, new VRK, new recovery key shown once) followed by one generation-advancing import transaction: credentials keep id, label, kind, state, version numbers and timestamps and are re-encrypted with fresh DEKs; policy trust and audit retention carry over; one `migration.completed` audit event names the source vault id, format and generation. The target is re-opened through the normal integrity path and its credential count, metadata and per-version payload digests must equal the source before the init is confirmed.
- Not carried: audit history, usage ledgers, workload replay digests, remembered/desktop unlock grants and `service.json` (re-established by normal flows). Migration refuses a non-empty lease journal, lab Actions and PKI issuance history rather than dropping them.
- The signed policy is not carried because its signature binds the old vault. Policy7/8 Connections, SSH keys and T1 permissions are converted mechanically (policy7 SSH keys get a local-presence approver and 100 signatures / 600 s budget, flagged for review) and written as an unsigned draft request `migrated-policy-request.json` (0600) for the owner to review and re-sign. Policy6 had no Connections. A basic-mode software signer key beside the source is copied so the carried trust stays usable.

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
