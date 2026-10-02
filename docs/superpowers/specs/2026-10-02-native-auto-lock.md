# Native device-linked locking and remembered access

The user's 2026-10-02 request replaces the fixed seven-day-only desktop UX.
Separate local inactivity, device locking and the maximum remembered-password
interval. Reuse the native app, current Authority and protected IPC. No extra
service, policy engine, cloud integration or hardware-key migration.

## Product behavior

- Defaults: lock the desktop UI after five minutes without computer input;
  lock on screen lock, sleep, display sleep and user-session deactivation;
  retain the existing seven-day maximum remembered-password preference.
- Settings offer idle 1/5/15/30/60 minutes or disabled; one device-lock toggle;
  password recheck every unlock (no persistent grant), 1/7/30 days. Persist
  only these non-secret preferences in this app's UserDefaults.
- Automatic locking revokes the desktop session, clears visible secrets, owned
  clipboard contents, result/form state and pending UI completions. Existing
  Agent capabilities continue. Explicit "lock everything" keeps today's full
  Broker drain, session revocation and grant deletion.
- Start/reopen locked. Startup, activation and passive refresh MUST NOT read
  Keychain or automatically resume. The user either enters the vault proof or
  explicitly chooses Mac authentication, using LocalAuthentication's device
  owner policy before reading the remembered key. Cancellation, unavailable
  authentication, expired grant or failed IPC leaves the UI locked. Never
  infer authentication from an unlock notification or app activation.
- Remembered access retains its original expiry across UI locking and resume;
  only a fresh vault proof may issue a new interval. Changing preferences
  revokes the current desktop session and remembered grant first; a new manual
  login applies the selected interval. Settings must not silently extend a grant.

## Authority and IPC

`DESKTOP_REMEMBER` now requires strict metadata `{lifetime_ms: i64}`. Validate
1,000..=2,592,000,000 ms in Authority before effects. Its authenticated existing
84-byte wrapped-root record binds issued/expires/vault ID; resume validates the
bounded interval and original wall-clock expiry. No database format change.
Remember also clamps the active desktop session to that expiry. CLI
`desktop-remember --ttl 168h` retains the usual default but always sends metadata.

New admin message 52 (`DESKTOP_LOCK`) receives strict
`{forget_remembered: bool}` and the current desktop token only in the proof body.
It authenticates the session, optionally durably removes the remembered grant,
records an audit without secret data and revokes only that desktop session.
An invalid token cannot revoke another session. It does not extend activity or
grant Agent access; no OIDC management token is needed to reduce local authority.
Full Broker lock and its error behavior remain unchanged.

## Lifecycle and platform bounds

Observe NSWorkspace sleep/display/session notifications and the macOS distributed
`com.apple.screenIsLocked` notification. The latter is an observed system signal,
not a documented authentication API: it may only lock, never authorize unlocking.
Poll CoreGraphics elapsed input time even while the app is in the background;
recheck on activation. These are desktop UX controls in the existing G1 scope,
not a kernel isolation or independent user-presence proof for Broker clients.
LocalAuthentication verifies the human in the trusted app; this change does not
claim a Secure Enclave-bound, non-exportable remembered key.

Locking takes effect locally immediately, including during an operation. Pending
login/reveal results cannot reopen the UI or copy secrets after the lock. A token
issued by an in-flight login is revoked when its result arrives. A failed server
revocation stays visible, leaves the UI locked and requires a successful cleanup
before another UI login. No automatic business-request retry. OS lock/sleep will
not be triggered on the user's machine by automated tests.

Validation: actual Authority/IPC expiry and session revocation, Agent continuity,
invalid-token refusal, opt-out deletion, stale login/reveal completion, idle while
backgrounded, device signals, disabled controls and cancellation. Tests use
synthetic data and injected authentication; real Mac authentication is not
silently exercised. Existing full workspace and native contracts remain gates.

References: [1Password unlock settings](https://support.1password.com/unlock-auto-lock/),
[Apple event-source API](https://developer.apple.com/documentation/coregraphics/cgeventsource),
[Apple device-owner authentication](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication).
