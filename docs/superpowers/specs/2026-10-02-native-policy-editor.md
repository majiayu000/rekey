# Native policy draft authoring

Frozen before code, 2026-10-02. The user requests implementation first and
defers cloud/hardware/customer acceptance. Extend the existing native draft
sheet in place: a form for new unsigned policies and an exact UTF-8 text editor
for imported/generated drafts. No new service, dependency, IPC, database format,
signing backend or private-key access. This supersedes the earlier file-only
authoring boundary, preserving independent signing and step-up activation.

The form authors policy version/expiry, approver public IDs/keys and multiple
rules. Each rule selects an exact registered Action version, stable principal,
resource, parameter schema and any-validated/exact-hash scope. Effects are
permit, forbid and require-approval; the latter exposes approver IDs, quorum,
one-time/time-window, use limit and window duration. Rules for the same Action
share one identical binding; conflicting bindings are an authoring error.
New drafts have an empty workload identity list. The text editor can author the
complete existing format, including workload identities. Imported text never
round-trips through a partial form or silently discards fields.

Drafts remain unsigned and unvalidated until the independent signer reviews
them. UI does not duplicate policy semantics or signature validation. Form
strings are JSON-escaped; schema JSON remains verbatim for the existing
validator, including rejection of duplicate keys. Full generated output is
shown before new-only mode-0600 export. Text edits export exactly the visible
UTF-8 bytes, capped at 64 KiB. Editing never activates or signs anything.
Generating explicitly replaces the text; merely switching tabs does not.
Failed import clears old text. Workspace/lock/disconnect/focus/close clear all
draft state through the existing native-flow lifecycle. No draft/proof enters
preferences. Checks use the actual Rust signer, exact byte export/size bounds,
strict Swift compilation and existing native bridge regressions.

The same native completion also exposes the five already implemented source
types missing from the Add/Rotate pickers: GCP, AWS, Azure, 1Password Connect and
macOS Keychain. Use their existing protected-profile CLI commands and display
names; no new provider backend, profile parser or secret preview is introduced.

While unlocked, the existing active-window refresh also loads the pending inbox
on other pages. Display an in-app pending-count banner linking to the full
approval details. Reuse the current 15-second refresh and cache clearing; no
new background service, OS notification permission, external message, payload
preview or automatic approval. Locked/disconnected state clears the count.
