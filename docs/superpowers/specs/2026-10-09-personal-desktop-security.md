# Personal desktop privacy and remembered access

User-selected PR #61 scope, 2026-10-09: implement the personal desktop changes and
Docker HA separately. This document extends the 0.5 development contract only;
published vaults and the installed App are not changed.

Keep current PresenceKey/PresenceGrant, authenticated Keychain user presence and
same-ticket monotonic expiry. Password/recovery alone may issue a remembered
grant. Presence cannot renew it. Replacement durably revokes the old grant first
and fails closed. No old RememberedUnlock namespace or permissive Keychain ACL.

Settings: computer idle 1/5/15/30/60 minutes or disabled (default five minutes),
lock on sleep/display sleep/user switch/screen-lock signals (default on), password
recheck every unlock or after 1/7/30 days (default seven). Only non-secret choices
are persisted. DESKTOP_REMEMBER requires explicit lifetime_ms in the existing
1,000..=2,592,000,000 ms range, checked once by the Worker before effects. Existing
84-byte tickets bind original issue/expiry/vault identity; no format change,
migration or reader fallback. Resume never extends expiry. Seven days remains the
ordinary A1 desktop session maximum; remembering clamps that session to the
selected shorter grant deadline when applicable.

Add admin opcode 72 DESKTOP_LOCK with strict {forget_remembered: bool} metadata.
The current A1 desktop token travels in the body. Authenticate that exact session,
revoke it immediately, optionally durably forget PresenceGrant, and append a
non-secret audit before success. Invalid tokens cannot revoke another session.
This does not lock the vault, revoke Agent work or authorize credential use.
Full lock retains the existing Authority drain and grant deletion.

The UI starts/reopens private-locked even if the daemon is unlocked. Privacy lock
clears forms, results and caches immediately, invalidates
native completion revisions and requests server session revocation. Late login or
resume tokens are revoked when they arrive. Failed cleanup remains visible and
blocks another UI login until confirmed. Keychain is read only from an explicit
system-authentication operation. OS notifications may reduce access only; activation
never authenticates. Pending business operations are not retried or rolled back.

Preserve current personal Connection forms (they supersede the old Action form).
Extend the existing team unsigned-draft view with exact UTF-8 text editing and
explicit new-draft generation for the current policy8 fields; imported text must
not pass through a partial form. Draft export is new-only mode0600, max64KiB;
editing/generation never signs or activates it. Current source adapters, approval
inbox and signing boundaries remain the behavior sources, not stale PR61 code.

Validate real Worker/IPC expiry, invalid-token refusal, privacy-only revocation,
Agent continuity, shorter/longer remembered intervals, failed replacement,
cancelled/stale native completions and device/idle signals using synthetic data.
No automated OS sleep/lock or real Keychain authentication is authorized by these
tests; actual signed-device acceptance remains separate.

## Software acceptance

Eighteen Worker desktop contracts pass, including failed replacement, invalid
lifetime preservation, same-ticket monotonic caps, the seven-day A1 maximum,
audit-trigger failure and wall-clock expiry. Four real lab IPC cases pass,
including execution with an existing Agent capability after privacy lock; the
default build runs the three personal IPC cases. Lab policy test fixtures now
include the required policy8 derived_credentials collection.

Synthetic Swift contracts pass idle/device/disabled choices, immediate cache
clearing, stale login revocation, authentication cancellation, visible failed
cleanup, already-locked JSON errors, settings revocation before persistence,
every-unlock refusal without Keychain access and exact draft export. Current
Connection roundtrip/signing models, strict App bundle compilation/ad-hoc
signature, real Swift/CLI/Broker Connection/lifecycle/backup, automatic locked
startup and the human-vault mutation/failure harness pass. The independent Rust
signer accepts the generated empty policy8 draft. These use fresh synthetic
state and software signing; actual device events, protected Keychain/Touch ID
and installed App acceptance remain unverified.

PR61 disposition: retain current personal Connection/onboarding, source adapter
contracts and approval-notification implementation rather than its obsolete
Action/session/RememberedUnlock paths. The old broad source-import menu is not
part of the personal Connection flow; laboratory providers remain governed by
their existing lab CLI/contracts. Team raw draft editing preserves all current
fields and the independent review/sign/activate boundary. Docker HA has its own
controller specification and PR; it is not an acceptance dependency of this UI.

Follow-up cache review: a connection failure or rejected A1 closes sensitive
result/operation sheets as well as the main presentation; Root-owned action and
activity sheets close on privacy lock. Initially locked setup keeps its explicit
recovery-key saving result. Captured form revisions are checked before ordinary
password commands too, so a pre-lock form cannot start a late command. Synthetic
regressions cover these paths separately from actual device authentication.

CI harness correction: a fixed 100ms pause could request retry before the
synthetic failure callback completed. A controlled 200ms late failure reproduces
the exact timeout. The test now waits for the observable failure before retrying,
retaining the pending-cleanup, blocked-login and successful-retry assertions.
